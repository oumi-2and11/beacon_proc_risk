"""规则基类、注册装饰器、4 个具体检测规则。"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from utils.rule_engine.context import RuleContext
from utils.common.constants import SUSPICIOUS_PARENT_CHILD, SUSPICIOUS_PATH_PATTERNS
from utils.common.validators import is_suspicious_path


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
        if proc.signed_status not in ("unsigned", "invalid"):
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
