"""Beaconing 检测多轮网络连接采样器。

单次 psutil 快照所有连接 seen_at 相同，无法计算 CV。
本模块以固定间隔多次采集连接快照，积累时间序列，
使 Beaconing 的 CV 算法真正生效。

用法：
    sampler = BeaconSampler(pid=1234, interval=5, rounds=12)
    samples = sampler.run()   # 阻塞 ~60 秒
"""

import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from utils.process_collector.collector import get_connections_for_pid


@dataclass
class ConnectionSnapshot:
    """单轮采样的连接快照。"""
    round_idx: int
    timestamp: float                    # time.time() 秒
    connections: List[dict] = field(default_factory=list)


@dataclass
class SamplingResult:
    """多轮采样汇总结果。"""
    pid: int
    interval_sec: float
    total_rounds: int
    snapshots: List[ConnectionSnapshot] = field(default_factory=list)
    # 每轮新增的 check-in 事件时间戳
    checkin_times: List[float] = field(default_factory=list)
    # 持久连接: 在所有轮次中都存在的 (remote_ip, remote_port) 集合
    persistent_remotes: set = field(default_factory=set)


class BeaconSampler:
    """多轮网络连接采样器。

    Args:
        pid: 目标进程 PID
        interval_sec: 采样间隔（秒），默认 5
        total_rounds: 采样轮数，默认 12（共 60 秒）
        on_progress: 可选进度回调 fn(round_idx, total_rounds)
    """

    def __init__(
        self,
        pid: int,
        interval_sec: float = 5,
        total_rounds: int = 12,
        on_progress: Optional[Callable[[int, int], None]] = None,
    ):
        self.pid = pid
        self.interval_sec = interval_sec
        self.total_rounds = total_rounds
        self.on_progress = on_progress

    def run(self) -> SamplingResult:
        """执行多轮采样，返回 SamplingResult。

        每轮调用 get_connections_for_pid() 获取当前连接快照，
        然后睡眠等待下一轮。首轮立即采集，末轮不睡眠。
        """
        result = SamplingResult(
            pid=self.pid,
            interval_sec=self.interval_sec,
            total_rounds=self.total_rounds,
        )

        # 上一轮的 (remote_ip, remote_port) 集合，用于检测新增连接
        prev_remote_set: set = set()
        # 跟踪每对远端出现的轮次
        remote_round_presence: dict = {}  # (ip, port) -> set of round indices

        for i in range(self.total_rounds):
            if self.on_progress:
                self.on_progress(i + 1, self.total_rounds)

            now = time.time()
            conns = get_connections_for_pid(self.pid)

            snapshot = ConnectionSnapshot(round_idx=i, timestamp=now, connections=conns)
            result.snapshots.append(snapshot)

            # 提取本轮远端 (ip, port) 集合
            curr_remote_set: set = set()
            for c in conns:
                rip = c.get("remote_ip")
                rport = c.get("remote_port")
                if rip and rport:
                    key = (rip, rport)
                    curr_remote_set.add(key)
                    if key not in remote_round_presence:
                        remote_round_presence[key] = set()
                    remote_round_presence[key].add(i)

            # 检测 check-in: 本轮有、上一轮没有的远端连接视为一次 check-in
            new_remotes = curr_remote_set - prev_remote_set
            for _ in new_remotes:
                result.checkin_times.append(now)

            prev_remote_set = curr_remote_set

            # 末轮不睡眠
            if i < self.total_rounds - 1:
                time.sleep(self.interval_sec)

        # 检测持久连接: 在所有轮次中都出现的远端
        for key, rounds_seen in remote_round_presence.items():
            if len(rounds_seen) >= self.total_rounds * 0.8:
                result.persistent_remotes.add(key)

        return result
