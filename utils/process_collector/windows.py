"""Windows 平台进程采集，基于 psutil。"""

import psutil,socket
from datetime import datetime
from typing import Optional, List, Dict

from utils.process_collector.models import ProcessInfo
from utils.common.helpers import generate_process_key
from utils.common.validators import is_system_path, is_suspicious_path
from utils.common.constants import SUSPICIOUS_PARENT_CHILD


def collect_single_process(
    proc: psutil.Process, parent_cache: Optional[Dict[int, str]] = None
) -> Optional[ProcessInfo]:
    """从单个 psutil.Process 采集信息。

    Args:
        proc: psutil.Process 实例
        parent_cache: pid→name 映射缓存，避免重复查询父进程名

    Returns:
        ProcessInfo 或 None（权限拒绝/进程已退出）
    """
    try:
        pid = proc.pid
        name = proc.name()
        exe_path = ""
        cmdline = ""
        username = ""
        ppid = 0
        parent_name = ""
        create_time = None
        cpu_percent = 0.0
        memory_rss = 0

        try:
            exe_path = proc.exe() or ""
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        try:
            cl = proc.cmdline()
            cmdline = " ".join(cl) if cl else ""
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        try:
            username = proc.username() or ""
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        try:
            ppid = proc.ppid() or 0
            if parent_cache and ppid in parent_cache:
                parent_name = parent_cache[ppid]
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            ppid = 0

        try:
            create_time = datetime.fromtimestamp(proc.create_time())
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            pass

        try:
            cpu_percent = proc.cpu_percent(interval=0)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        try:
            mem = proc.memory_info()
            memory_rss = mem.rss if mem else 0
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        is_system = is_system_path(exe_path)
        path_suspicious = is_suspicious_path(exe_path)

        parent_child_suspicious = False
        if parent_name and name:
            suspicious_children = SUSPICIOUS_PARENT_CHILD.get(parent_name.lower(), [])
            if suspicious_children and name.lower() in [c.lower() for c in suspicious_children]:
                parent_child_suspicious = True

        signed_status = "signed" if is_system else "unknown"

        proc_key = ""
        if create_time:
            try:
                epoch = proc.create_time()
                proc_key = generate_process_key(pid, epoch)
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                pass

        return ProcessInfo(
            pid=pid,
            name=name,
            exe_path=exe_path,
            cmdline=cmdline,
            username=username,
            ppid=ppid,
            parent_name=parent_name,
            create_time=create_time,
            is_system=is_system,
            signed_status=signed_status,
            process_key=proc_key,
            cpu_percent=cpu_percent,
            memory_rss=memory_rss,
            path_suspicious=path_suspicious,
            parent_child_suspicious=parent_child_suspicious,
        )
    except psutil.NoSuchProcess:
        return None
    except psutil.AccessDenied:
        return None
    except psutil.ZombieProcess:
        return ProcessInfo(pid=proc.pid, name=getattr(proc, "_name", "") or "zombie")


def collect_process_list(max_processes: int = 5000) -> List[ProcessInfo]:
    """枚举所有运行进程。

    两轮采集：第一轮建 parent_cache，第二轮采集完整信息。
    最多返回 max_processes 个进程，按 PID 排序。
    """
    # 第一轮：构建 pid→name 缓存
    parent_cache: Dict[int, str] = {}
    try:
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                parent_cache[proc.pid] = proc.info["name"] or ""
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception:
        pass

    # 第二轮：完整采集
    results: List[ProcessInfo] = []
    try:
        for proc in psutil.process_iter(["pid"]):
            if len(results) >= max_processes:
                break
            info = collect_single_process(proc, parent_cache)
            if info is not None:
                results.append(info)
    except Exception:
        pass

    results.sort(key=lambda p: p.pid)
    return results


def _get_proc_connections(proc: psutil.Process):
    """兼容不同 psutil 版本获取进程连接。"""
    if hasattr(proc, "net_connections"):
        return proc.net_connections(kind="inet")
    return proc.connections(kind="inet")


def collect_connections_for_pid(pid: int) -> List[dict]:
    """采集指定进程的网络连接。

    返回 [{protocol, local_ip, local_port, remote_ip, remote_port, state, seen_at}]
    """
    try:
        proc = psutil.Process(pid)
        conns = _get_proc_connections(proc)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return []

    now = datetime.now()
    results = []
    for c in conns:
        proto = "UDP" if c.type == socket.SOCK_DGRAM else "TCP"
        results.append({
            "protocol": proto,
            "local_ip": c.laddr.ip if c.laddr else None,
            "local_port": c.laddr.port if c.laddr else None,
            "remote_ip": c.raddr.ip if c.raddr else None,
            "remote_port": c.raddr.port if c.raddr else None,
            "state": c.status if proto == "TCP" else "STATELESS",
            "seen_at": now,
        })
    return results


def find_proxy_connections(local_ip: str, local_port: int) -> List[dict]:
    """当远端是本地回环地址时，追踪代理进程的真实远端连接。

    场景：目标进程连接 127.0.0.1:7897（Clash 代理），
    实际 C2 地址由代理进程的远端连接决定。

    逻辑：找到监听 (local_ip, local_port) 的进程，获取其远端非回环连接。
    """
    import psutil as _ps

    _LOOPBACK = {"127.0.0.1", "0.0.0.0", "::1", "::"}

    # 查找监听该端口的进程
    proxy_pid = None
    proxy_name = None
    try:
        for conn in _ps.net_connections(kind="inet"):
            if (conn.status == "LISTEN" and
                conn.laddr and
                conn.laddr.port == local_port and
                conn.laddr.ip in _LOOPBACK):
                try:
                    proxy_pid = conn.pid
                    if proxy_pid:
                        proxy_name = _ps.Process(proxy_pid).name()
                except (_ps.NoSuchProcess, _ps.AccessDenied):
                    pass
                break
    except _ps.AccessDenied:
        pass

    if proxy_pid is None:
        return []

    # 获取代理进程的远端连接（排除回环），去重并限制数量
    proxy_conns = collect_connections_for_pid(proxy_pid)
    seen_keys: set = set()
    real_remotes = []
    proxy_label = f"{proxy_name}(PID {proxy_pid})"
    for c in proxy_conns:
        rip = c.get("remote_ip", "")
        rport = c.get("remote_port")
        if rip and rip not in _LOOPBACK and not rip.startswith("127."):
            key = (rip, rport)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            c["_proxy_via"] = proxy_label
            c["_proxy_local"] = f"{local_ip}:{local_port}"
            real_remotes.append(c)
            if len(real_remotes) >= 10:
                break

    return real_remotes
