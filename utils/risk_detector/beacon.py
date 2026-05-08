"""Beaconing 周期性通信检测。

算法：
  1. 按 seen_at 排序连接
  2. 计算相邻连接间隔（ms）
  3. 不足 BEACON_MIN_SAMPLES → 不标记
  4. 计算 mean / std / cv = std / mean
  5. cv < BEACON_CV_THRESHOLD → suspected
  6. cv > BEACON_JITTER_CV_MIN 且 cv < 0.15 → jitter_like

单次快照局限：psutil 是瞬时快照，所有 seen_at 相同。
MVP 中以连接数启发式补充（同 IP 多连接 → 可疑），
CV 算法完整实现，后续支持时序采样后即可生效。
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


def detect_beaconing(connections: List[dict], sample_window: int = 20) -> BeaconStats:
    """检测进程网络连接是否存在 Beaconing 周期性通信特征。

    Args:
        connections: 网络连接列表，每项含 seen_at (datetime) 和 remote_ip
        sample_window: 滑动窗口大小

    Returns:
        BeaconStats 检测结果
    """
    stats = BeaconStats(sample_window=sample_window)

    if not connections:
        stats.notes = "无网络连接"
        return stats

    # ---- 启发式：同 IP 多连接 → 可疑 ----
    ip_counts: dict = {}
    for c in connections:
        rip = c.get("remote_ip")
        if rip:
            ip_counts[rip] = ip_counts.get(rip, 0) + 1

    total_conns = len(connections)
    max_same_ip = max(ip_counts.values()) if ip_counts else 0

    # ---- CV 算法（需时序采样数据才能真正生效） ----
    # 按 seen_at 排序
    sorted_conns = sorted(connections, key=lambda c: c.get("seen_at"))
    intervals = []
    for i in range(1, len(sorted_conns)):
        t0 = sorted_conns[i - 1].get("seen_at")
        t1 = sorted_conns[i].get("seen_at")
        if t0 and t1:
            delta_ms = (t1 - t0).total_seconds() * 1000
            if delta_ms > 0:
                intervals.append(delta_ms)

    # CV 计算
    if len(intervals) >= BEACON_MIN_SAMPLES:
        mean_ms = sum(intervals) / len(intervals)
        if mean_ms > 0:
            variance = sum((x - mean_ms) ** 2 for x in intervals) / len(intervals)
            std_ms = variance ** 0.5
            cv = std_ms / mean_ms

            stats.interval_mean_ms = round(mean_ms, 1)
            stats.interval_std_ms = round(std_ms, 1)
            stats.interval_cv = round(cv, 4)

            if cv < BEACON_CV_THRESHOLD:
                stats.suspected = True
                stats.notes = f"CV={cv:.3f} < {BEACON_CV_THRESHOLD}，疑似周期性通信"
            elif BEACON_JITTER_CV_MIN < cv < 0.15:
                stats.jitter_like = True
                stats.notes = f"CV={cv:.3f}，含 jitter 特征"
    elif total_conns == 0:
        stats.notes = "无远端连接"
    else:
        # 时序数据不足（psutil 快照场景），用启发式补充
        if max_same_ip >= 3:
            stats.suspected = True
            top_ip = max(ip_counts, key=ip_counts.get)
            stats.notes = f"同 IP {top_ip} 有 {max_same_ip} 条连接（启发式）"
            stats.interval_cv = 0.0   # 标记为低 CV
            stats.interval_mean_ms = 0.0
        else:
            stats.notes = f"连接数不足 {BEACON_MIN_SAMPLES}，CV 无法计算"

    return stats
