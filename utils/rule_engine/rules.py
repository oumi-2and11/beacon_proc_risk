"""规则基类、注册装饰器、5 个具体检测规则。"""

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from utils.rule_engine.context import RuleContext
from utils.common.constants import SUSPICIOUS_PARENT_CHILD, SUSPICIOUS_PATH_PATTERNS
from utils.common.validators import is_suspicious_path, is_system_path


# ---------------------------------------------------------------------------
# 规则命中结果
# ---------------------------------------------------------------------------
@dataclass
class RuleHitResult:
    rule_id: str
    title: str
    dimension: str          # "process" | "network" | "memory" | "other"
    score_delta: int
    evidence: Dict[str, Any]


# ---------------------------------------------------------------------------
# 规则基类 + 注册表
# ---------------------------------------------------------------------------
_RULE_REGISTRY: List[type] = []


class BaseRule(ABC):
    rule_id: str = ""
    title: str = ""
    dimension: str = "other"
    default_weight: int = 10

    @abstractmethod
    def check(self, context: RuleContext) -> Optional[RuleHitResult]:
        """规则命中返回 RuleHitResult，未命中返回 None。"""


def register_rule(cls):
    _RULE_REGISTRY.append(cls)
    return cls


# ---------------------------------------------------------------------------
# PROC-001: 异常父子进程关系
# ---------------------------------------------------------------------------
@register_rule
class AnomalousParentChildRule(BaseRule):
    rule_id = "PROC-001"
    title = "异常父子进程关系"
    dimension = "process"
    default_weight = 20

    def check(self, context: RuleContext) -> Optional[RuleHitResult]:
        proc = context.process
        parent_name = proc.parent_name.lower() if proc.parent_name else ""
        proc_name = proc.name.lower() if proc.name else ""

        if not parent_name or not proc_name:
            return None

        suspicious_children = SUSPICIOUS_PARENT_CHILD.get(parent_name, [])
        if not suspicious_children:
            return None

        if proc_name in [c.lower() for c in suspicious_children]:
            return RuleHitResult(
                rule_id=self.rule_id,
                title=self.title,
                dimension=self.dimension,
                score_delta=self.default_weight,
                evidence={
                    "parent": proc.parent_name,
                    "child": proc.name,
                    "detail": f"{proc.parent_name} -> {proc.name} 属于可疑父子组合",
                },
            )
        return None


# ---------------------------------------------------------------------------
# PROC-002: 可疑路径 + 未签名
# ---------------------------------------------------------------------------
@register_rule
class SuspiciousPathRule(BaseRule):
    rule_id = "PROC-002"
    title = "运行于可疑路径"
    dimension = "process"
    default_weight = 30

    def check(self, context: RuleContext) -> Optional[RuleHitResult]:
        proc = context.process
        if not is_suspicious_path(proc.exe_path):
            return None
        if proc.signed_status == "signed":
            return None

        matched = [p for p in SUSPICIOUS_PATH_PATTERNS if p.lower() in proc.exe_path.lower()]
        return RuleHitResult(
            rule_id=self.rule_id,
            title=self.title,
            dimension=self.dimension,
            score_delta=self.default_weight,
            evidence={
                "path": proc.exe_path,
                "matched_patterns": matched,
                "signed_status": proc.signed_status,
                "detail": f"路径包含 {matched[0]} 且签名状态为 {proc.signed_status}",
            },
        )


# ---------------------------------------------------------------------------
# PROC-003: 未签名非系统进程
# ---------------------------------------------------------------------------
@register_rule
class UnsignedProcessRule(BaseRule):
    rule_id = "PROC-003"
    title = "未签名的非系统进程"
    dimension = "process"
    default_weight = 15

    def check(self, context: RuleContext) -> Optional[RuleHitResult]:
        proc = context.process
        if proc.signed_status == "signed":
            return None
        if proc.is_system:
            return None

        return RuleHitResult(
            rule_id=self.rule_id,
            title=self.title,
            dimension=self.dimension,
            score_delta=self.default_weight,
            evidence={
                "name": proc.name,
                "path": proc.exe_path,
                "signed_status": proc.signed_status,
                "detail": f"签名状态为 {proc.signed_status}，非系统路径",
            },
        )


# ---------------------------------------------------------------------------
# PROC-004: 可疑进程名
# ---------------------------------------------------------------------------
# 已知恶意工具命名模式
_KNOWN_MALWARE_NAME_PATTERNS = [
    re.compile(r"^artifact", re.IGNORECASE),       # Cobalt Strike artifact
    re.compile(r"^beacon", re.IGNORECASE),          # beacon
    re.compile(r"^payload", re.IGNORECASE),         # payload
    re.compile(r"^shellcode", re.IGNORECASE),       # shellcode
    re.compile(r"^inject", re.IGNORECASE),          # injector
    re.compile(r"^mimikatz", re.IGNORECASE),        # mimikatz
    re.compile(r"^procdump", re.IGNORECASE),        # procdump
    re.compile(r"^lazagne", re.IGNORECASE),         # LaZagne
    re.compile(r"^nmap", re.IGNORECASE),            # nmap
    re.compile(r"^ncat", re.IGNORECASE),            # ncat
    re.compile(r"^psexec", re.IGNORECASE),          # PsExec
]

# 随机命名模式: 8+位纯字母/数字, 如 xjkdqwer.exe
_RANDOM_NAME_RE = re.compile(r"^[a-z0-9]{8,}\.exe$", re.IGNORECASE)


@register_rule
class SuspiciousNameRule(BaseRule):
    rule_id = "PROC-004"
    title = "可疑进程名"
    dimension = "process"
    default_weight = 20

    def check(self, context: RuleContext) -> Optional[RuleHitResult]:
        proc = context.process
        if not proc.name:
            return None
        # 系统路径进程跳过
        if proc.is_system:
            return None

        name = proc.name
        reasons = []

        # 检查已知恶意命名模式
        for pat in _KNOWN_MALWARE_NAME_PATTERNS:
            if pat.search(name):
                reasons.append(f"匹配已知恶意模式 {pat.pattern}")
                break

        # 检查随机命名
        if _RANDOM_NAME_RE.match(name):
            reasons.append("疑似随机命名(8+位字母数字)")

        if not reasons:
            return None

        return RuleHitResult(
            rule_id=self.rule_id,
            title=self.title,
            dimension=self.dimension,
            score_delta=self.default_weight,
            evidence={
                "name": name,
                "path": proc.exe_path,
                "reasons": reasons,
                "detail": f"进程名 {name}: {'; '.join(reasons)}",
            },
        )


# ---------------------------------------------------------------------------
# NET-101: 疑似 Beaconing 周期性通信
# ---------------------------------------------------------------------------
@register_rule
class BeaconingNetworkRule(BaseRule):
    rule_id = "NET-101"
    title = "疑似 Beaconing 周期性通信"
    dimension = "network"
    default_weight = 35

    def check(self, context: RuleContext) -> Optional[RuleHitResult]:
        if context.beacon_stats is None:
            return None
        if not context.beacon_stats.suspected:
            return None

        stats = context.beacon_stats
        return RuleHitResult(
            rule_id=self.rule_id,
            title=self.title,
            dimension=self.dimension,
            score_delta=self.default_weight,
            evidence={
                "sample_window": stats.sample_window,
                "interval_mean_ms": stats.interval_mean_ms,
                "interval_cv": stats.interval_cv,
                "jitter_like": stats.jitter_like,
                "detail": f"CV={stats.interval_cv:.3f}, 均值={stats.interval_mean_ms:.1f}ms"
                          if stats.interval_cv is not None else "疑似 Beaconing",
            },
        )
