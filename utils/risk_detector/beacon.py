"""Beaconing 周期性通信检测。

两种模式：
  1. 多轮采样模式（推荐）：接收 BeaconSampler 的 SamplingResult，
     从 check-in 时间序列计算真实 CV，并检测持久连接模式。
  2. 单次快照回退：仅有一轮连接数据时，用启发式补充。
"""

from dataclasses import dataclass
from typing import List, Optional

from utils.common.constants import (
    BEACON_MIN_SAMPLES,
    BEACON_CV_THRESHOLD,
    BEACON_JITTER_CV_MIN,
)


@dataclass
class BeaconStats:
    sample_window: int = 0
    interval_mean_ms: Optional[float] = None
    interval_std_ms: Optional[float] = None
    interval_cv: Optional[float] = None
    suspected: bool = False
    jitter_like: bool = False
    notes: Optional[str] = None
    # 多轮采样专用字段
    checkin_count: int = 0
    persistent_remotes: Optional[list] = None
    sampling_rounds: int = 0


def _compute_cv(intervals: List[float]) -> Optional[dict]:
    """从间隔列表计算均值/标准差/CV，返回 dict 或 None。"""
    if len(intervals) < 2:
        return None
    mean = sum(intervals) / len(intervals)
    if mean <= 0:
        return None
    variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
    std = variance ** 0.5
    cv = std / mean
    return {"mean": mean, "std": std, "cv": cv}


def detect_beaconing_from_sampling(sampling_result) -> BeaconStats:
    """从多轮采样结果检测 Beaconing（主检测路径）。

    检测逻辑：
      1. 从 checkin_times 计算间隔 → CV
      2. CV < 阈值 → 疑似周期性通信
      3. 持久连接检测：远端连接在 80%+ 轮次中持续存在
      4. 两者任一命中 → suspected
    """
    from utils.risk_detector.sampler import SamplingResult

    sr = sampling_result
    stats = BeaconStats(
        sample_window=sr.total_rounds,
        sampling_rounds=sr.total_rounds,
        checkin_count=len(sr.checkin_times),
        persistent_remotes=list(sr.persistent_remotes),
    )

    reasons = []

    # ---- 1. Check-in 间隔 CV 分析 ----
    if len(sr.checkin_times) >= BEACON_MIN_SAMPLES:
        intervals = []
        for i in range(1, len(sr.checkin_times)):
            delta_ms = (sr.checkin_times[i] - sr.checkin_times[i - 1]) * 1000
            if delta_ms > 0:
                intervals.append(delta_ms)

        cv_result = _compute_cv(intervals)
        if cv_result:
            stats.interval_mean_ms = round(cv_result["mean"], 1)
            stats.interval_std_ms = round(cv_result["std"], 1)
            stats.interval_cv = round(cv_result["cv"], 4)

            if cv_result["cv"] < BEACON_CV_THRESHOLD:
                stats.suspected = True
                reasons.append(
                    f"CV={cv_result['cv']:.3f} < {BEACON_CV_THRESHOLD}，"
                    f"均值={cv_result['mean']:.0f}ms"
                )
            if BEACON_JITTER_CV_MIN < cv_result["cv"] < 0.15:
                stats.jitter_like = True
                reasons.append("含 jitter 特征")
    elif len(sr.checkin_times) >= 2:
        # 采样轮次不够 CV 阈值但有 check-in，给出弱信号
        reasons.append(
            f"检测到 {len(sr.checkin_times)} 次 check-in（样本不足 CV 阈值）"
        )
        # 如果 check-in 次数接近采样轮数，说明每次采样都有新连接 → 高频
        if len(sr.checkin_times) >= sr.total_rounds * 0.5:
            stats.suspected = True
            reasons.append("check-in 频率 ≥ 50% 采样轮次")

    # ---- 2. 持久连接检测 ----
    if sr.persistent_remotes:
        stats.suspected = True
        for remote in sr.persistent_remotes:
            ip, port = remote
            reasons.append(f"持久连接 {ip}:{port}（≥80% 轮次存在）")

    if reasons:
        if not stats.suspected:
            # 弱信号不算 suspected，但记录在 notes
            stats.notes = "弱信号: " + "; ".join(reasons[:3])
        else:
            stats.notes = "; ".join(reasons[:5])
    else:
        if len(sr.checkin_times) == 0 and not sr.persistent_remotes:
            stats.notes = f"{sr.total_rounds} 轮采样无 check-in 且无持久连接"
        else:
            stats.notes = "未发现 Beaconing 特征"

    return stats


def detect_beaconing(connections: List[dict], sample_window: int = 20) -> BeaconStats:
    """单次快照回退检测（兼容旧调用方式）。

    psutil 瞬时快照中所有 seen_at 相同，CV 无法计算。
    用多维度启发式补充。
    """
    stats = BeaconStats(sample_window=sample_window)

    if not connections:
        stats.notes = "无网络连接"
        return stats

    # 统计同 IP 连接数和远端端口
    ip_counts: dict = {}
    ip_ports: dict = {}
    for c in connections:
        rip = c.get("remote_ip")
        rport = c.get("remote_port")
        if rip:
            ip_counts[rip] = ip_counts.get(rip, 0) + 1
            if rip not in ip_ports:
                ip_ports[rip] = set()
            if rport:
                ip_ports[rip].add(rport)

    max_same_ip = max(ip_counts.values()) if ip_counts else 0

    # CV 算法（快照场景通常无法生效，但保留兼容）
    sorted_conns = sorted(connections, key=lambda c: c.get("seen_at"))
    intervals = []
    for i in range(1, len(sorted_conns)):
        t0 = sorted_conns[i - 1].get("seen_at")
        t1 = sorted_conns[i].get("seen_at")
        if t0 and t1:
            delta_ms = (t1 - t0).total_seconds() * 1000
            if delta_ms > 0:
                intervals.append(delta_ms)

    if len(intervals) >= BEACON_MIN_SAMPLES:
        cv_result = _compute_cv(intervals)
        if cv_result:
            stats.interval_mean_ms = round(cv_result["mean"], 1)
            stats.interval_std_ms = round(cv_result["std"], 1)
            stats.interval_cv = round(cv_result["cv"], 4)

            if cv_result["cv"] < BEACON_CV_THRESHOLD:
                stats.suspected = True
                stats.notes = f"CV={cv_result['cv']:.3f} < {BEACON_CV_THRESHOLD}，疑似周期性通信"
            elif BEACON_JITTER_CV_MIN < cv_result["cv"] < 0.15:
                stats.jitter_like = True
                stats.notes = f"CV={cv_result['cv']:.3f}，含 jitter 特征"
            return stats

    # 时序数据不足 → 启发式
    heuristic_reasons = []

    if max_same_ip >= 2:
        top_ip = max(ip_counts, key=ip_counts.get)
        heuristic_reasons.append(f"同 IP {top_ip} 有 {max_same_ip} 条连接")

    _WELL_KNOWN_PORTS = {20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443}
    for rip, ports in ip_ports.items():
        non_standard = ports - _WELL_KNOWN_PORTS
        for p in sorted(non_standard):
            heuristic_reasons.append(f"远端非标准端口 {rip}:{p}")

    if heuristic_reasons:
        stats.suspected = True
        stats.notes = "启发式: " + "; ".join(heuristic_reasons[:5])
        stats.interval_cv = 0.0
        stats.interval_mean_ms = 0.0
    else:
        stats.notes = "单次快照无时序数据，且无启发式命中（建议使用多轮采样模式）"

    return stats
