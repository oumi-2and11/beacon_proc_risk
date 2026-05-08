"""主检测器：编排完整的进程风险检测流水线。"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

from utils.process_collector.models import ProcessInfo
from utils.process_collector.collector import get_process_by_pid, get_connections_for_pid
from utils.rule_engine.engine import RuleEngine
from utils.rule_engine.context import RuleContext
from utils.rule_engine.rules import RuleHitResult
from utils.risk_detector.beacon import BeaconStats, detect_beaconing
from utils.risk_detector.scorer import ScoreResult, compute_score


@dataclass
class RemoteSummary:
    remote_ip: str
    remote_port: Optional[int]
    protocol: str = "TCP"
    conn_count: int = 0
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    risk_hint: Optional[str] = None


@dataclass
class ConnectionDetail:
    protocol: str
    local_ip: Optional[str]
    local_port: Optional[int]
    remote_ip: Optional[str]
    remote_port: Optional[int]
    state: Optional[str]
    seen_at: datetime


@dataclass
class DetectionResult:
    process_info: ProcessInfo
    hits: List[RuleHitResult] = field(default_factory=list)
    score: ScoreResult = field(default_factory=ScoreResult)
    beacon_stats: Optional[BeaconStats] = None
    remote_summaries: List[RemoteSummary] = field(default_factory=list)
    connections: List[ConnectionDetail] = field(default_factory=list)


def detect_process(pid: int, db_session, sample_window: int = 20) -> DetectionResult:
    """完整的风险检测流水线。

    步骤：
      1. 采集进程信息
      2. 采集网络连接
      3. 构建规则上下文
      4. 执行规则引擎检测
      5. Beaconing 检测
      6. 将 beacon_stats 注入上下文，触发 NET-101 规则
      7. 计算评分
      8. 聚合远端 IP 汇总
      9. 返回 DetectionResult

    Args:
        pid: 目标进程 PID
        db_session: SQLAlchemy session（用于加载白名单/规则配置）
        sample_window: Beaconing 检测滑动窗口

    Returns:
        DetectionResult

    Raises:
        ValueError: PID 不存在或无权限访问
    """
    # 1. 采集进程信息
    proc_info = get_process_by_pid(pid)
    if proc_info is None:
        raise ValueError(f"无法访问进程 PID={pid}")

    result = DetectionResult(process_info=proc_info)

    # 2. 采集网络连接
    raw_connections = get_connections_for_pid(pid)

    # 转换为 ConnectionDetail
    conn_details = []
    for c in raw_connections:
        conn_details.append(ConnectionDetail(
            protocol=c.get("protocol", "TCP"),
            local_ip=c.get("local_ip"),
            local_port=c.get("local_port"),
            remote_ip=c.get("remote_ip"),
            remote_port=c.get("remote_port"),
            state=c.get("state"),
            seen_at=c.get("seen_at", datetime.now()),
        ))
    result.connections = conn_details

    # 3. 加载白名单和 DB 规则配置
    from webapp.models import Allowlist
    allowlist_entries = Allowlist.query.filter_by(enabled=True).all()

    # 4. 构建规则上下文
    engine = RuleEngine()
    engine.load_db_config(db_session)

    ctx = RuleContext(
        process=proc_info,
        connections=raw_connections,
        allowlist=allowlist_entries,
    )

    # 5. 先执行非网络规则（不含 NET-101）
    hits = engine.evaluate(ctx)

    # 6. Beaconing 检测
    beacon = detect_beaconing(raw_connections, sample_window=sample_window)
    result.beacon_stats = beacon

    # 7. 注入 beacon_stats，再跑一遍触发 NET-101
    ctx.beacon_stats = beacon
    network_hits = engine.evaluate(ctx)
    # 只保留 NET-101 的命中（其他已记录）
    for h in network_hits:
        if h.rule_id.startswith("NET-") and h not in hits:
            hits.append(h)

    result.hits = hits

    # 8. 计算评分
    result.score = compute_score(hits)

    # 9. 聚合远端 IP 汇总
    ip_map: dict = {}
    for c in conn_details:
        if not c.remote_ip:
            continue
        key = (c.remote_ip, c.remote_port, c.protocol)
        if key not in ip_map:
            ip_map[key] = RemoteSummary(
                remote_ip=c.remote_ip,
                remote_port=c.remote_port,
                protocol=c.protocol,
                conn_count=1,
                first_seen_at=c.seen_at,
                last_seen_at=c.seen_at,
            )
        else:
            entry = ip_map[key]
            entry.conn_count += 1
            if c.seen_at:
                if entry.first_seen_at is None or c.seen_at < entry.first_seen_at:
                    entry.first_seen_at = c.seen_at
                if entry.last_seen_at is None or c.seen_at > entry.last_seen_at:
                    entry.last_seen_at = c.seen_at

    # 给高频连接加 risk_hint
    for summary in ip_map.values():
        if summary.conn_count >= 3:
            summary.risk_hint = f"高频连接({summary.conn_count}次)"

    result.remote_summaries = list(ip_map.values())

    return result
