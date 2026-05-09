"""主检测器：编排完整的进程风险检测流水线。"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

from utils.process_collector.models import ProcessInfo
from utils.process_collector.collector import get_process_by_pid, get_connections_for_pid
from utils.rule_engine.engine import RuleEngine
from utils.rule_engine.context import RuleContext
from utils.rule_engine.rules import RuleHitResult
from utils.risk_detector.beacon import BeaconStats, detect_beaconing, detect_beaconing_from_sampling
from utils.risk_detector.scorer import ScoreResult, compute_score
from utils.risk_detector.sampler import BeaconSampler, SamplingResult


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
    sampling_result: Optional[SamplingResult] = None


def detect_process(
    pid: int,
    db_session,
    sample_window: int = 20,
    beacon_sampling: bool = True,
    sampling_interval: float = 5,
    sampling_rounds: int = 12,
    on_sampling_progress=None,
) -> DetectionResult:
    """完整的风险检测流水线。

    步骤：
      1. 采集进程信息
      2. 采集网络连接
      3. Beaconing 多轮采样（默认启用）
      4. 构建规则上下文
      5. 执行规则引擎检测
      6. Beaconing 检测
      7. 将 beacon_stats 注入上下文，触发 NET-101 规则
      8. 计算评分
      9. 聚合远端 IP 汇总
     10. 返回 DetectionResult

    Args:
        pid: 目标进程 PID
        db_session: SQLAlchemy session
        sample_window: 旧版单次快照的窗口参数（保留兼容）
        beacon_sampling: 是否启用多轮采样（默认 True）
        sampling_interval: 采样间隔秒数（默认 5）
        sampling_rounds: 采样轮数（默认 12，共 60 秒）
        on_sampling_progress: 采样进度回调 fn(round, total)
    """
    # 1. 采集进程信息
    proc_info = get_process_by_pid(pid)
    if proc_info is None:
        raise ValueError(f"无法访问进程 PID={pid}")

    result = DetectionResult(process_info=proc_info)

    # 2. 采集网络连接（首轮快照）
    raw_connections = get_connections_for_pid(pid)

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

    # 3. Beaconing 多轮采样
    sampling_result = None
    if beacon_sampling and raw_connections:
        sampler = BeaconSampler(
            pid=pid,
            interval_sec=sampling_interval,
            total_rounds=sampling_rounds,
            on_progress=on_sampling_progress,
        )
        sampling_result = sampler.run()
        result.sampling_result = sampling_result

    # 4. 加载白名单和 DB 规则配置
    from webapp.models import Allowlist
    allowlist_entries = Allowlist.query.filter_by(enabled=True).all()

    # 5. 构建规则上下文
    engine = RuleEngine()
    engine.load_db_config(db_session)

    ctx = RuleContext(
        process=proc_info,
        connections=raw_connections,
        allowlist=allowlist_entries,
    )

    # 6. 先执行非网络规则
    hits = engine.evaluate(ctx)

    # 7. Beaconing 检测
    if sampling_result is not None:
        beacon = detect_beaconing_from_sampling(sampling_result)
    else:
        beacon = detect_beaconing(raw_connections, sample_window=sample_window)
    result.beacon_stats = beacon

    # 8. 注入 beacon_stats，触发 NET-101
    ctx.beacon_stats = beacon
    network_hits = engine.evaluate(ctx)
    for h in network_hits:
        if h.rule_id.startswith("NET-") and h not in hits:
            hits.append(h)

    result.hits = hits

    # 9. 计算评分
    result.score = compute_score(hits)

    # 10. 聚合远端 IP 汇总
    # 使用最后一轮的连接作为汇总（如果有多轮采样）
    final_conns = conn_details
    if sampling_result and sampling_result.snapshots:
        final_conns = []
        for c in sampling_result.snapshots[-1].connections:
            final_conns.append(ConnectionDetail(
                protocol=c.get("protocol", "TCP"),
                local_ip=c.get("local_ip"),
                local_port=c.get("local_port"),
                remote_ip=c.get("remote_ip"),
                remote_port=c.get("remote_port"),
                state=c.get("state"),
                seen_at=c.get("seen_at", datetime.now()),
            ))

    ip_map: dict = {}
    for c in final_conns:
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

    for summary in ip_map.values():
        if summary.conn_count >= 3:
            summary.risk_hint = f"高频连接({summary.conn_count}次)"
        # 标记持久连接
        if sampling_result:
            remote_key = (summary.remote_ip, summary.remote_port)
            if remote_key in sampling_result.persistent_remotes:
                summary.risk_hint = (summary.risk_hint + "; 持久连接"
                                     if summary.risk_hint else "持久连接")

    result.remote_summaries = list(ip_map.values())

    return result
