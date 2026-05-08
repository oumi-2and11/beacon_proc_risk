"""统一采集接口，供 Flask 视图调用。"""

from typing import List, Optional

from utils.process_collector.models import ProcessInfo
from utils.process_collector.windows import (
    collect_process_list as _collect_list,
    collect_connections_for_pid as _collect_connections,
    collect_single_process,
)
import psutil


def get_process_list(max_processes: int = 5000, query: str = "") -> List[ProcessInfo]:
    """获取所有进程列表，支持按名称或 PID 搜索。"""
    processes = _collect_list(max_processes=max_processes)
    if query:
        q = query.strip().lower()
        processes = [
            p for p in processes
            if q in p.name.lower() or q == str(p.pid)
        ]
    return processes


def get_process_by_pid(pid: int) -> Optional[ProcessInfo]:
    """获取单个进程信息，不存在或无权限返回 None。"""
    try:
        proc = psutil.Process(pid)
        # 构建 parent_cache 仅用于查父进程名
        parent_cache = {}
        try:
            ppid = proc.ppid()
            if ppid:
                parent = psutil.Process(ppid)
                parent_cache[ppid] = parent.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return collect_single_process(proc, parent_cache)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def get_connections_for_pid(pid: int) -> List[dict]:
    """获取进程网络连接。"""
    return _collect_connections(pid)


def sync_process_catalog(process_info: ProcessInfo, db_session) -> "ProcessCatalog":
    """Upsert ProcessInfo 到 process_catalog 表。

    按 process_key 查找：存在则更新 last_seen_at，不存在则 INSERT。
    返回 ProcessCatalog ORM 实例。
    """
    from webapp.models import ProcessCatalog

    proc_key = process_info.process_key
    if not proc_key:
        # fallback：用 PID + 时间戳生成唯一 key
        from datetime import datetime
        import uuid
        proc_key = f"{process_info.pid}:{datetime.now().strftime('%Y%m%d%H%M%S%f')}:{uuid.uuid4().hex[:6]}"
        process_info.process_key = proc_key

    existing = ProcessCatalog.query.filter_by(process_key=proc_key).first()
    if existing:
        from datetime import datetime
        existing.last_seen_at = datetime.now()
        if process_info.name:
            existing.name = process_info.name
        if process_info.exe_path:
            existing.exe_path = process_info.exe_path
        existing.path_suspicious = process_info.path_suspicious
        existing.parent_child_suspicious = process_info.parent_child_suspicious
        return existing

    record = ProcessCatalog(
        pid=process_info.pid,
        start_time=process_info.create_time,
        process_key=proc_key,
        name=process_info.name or f"process_{process_info.pid}",
        exe_path=process_info.exe_path,
        cmdline=process_info.cmdline,
        username=process_info.username,
        ppid=process_info.ppid,
        parent_name=process_info.parent_name,
        is_system=process_info.is_system,
        signed_status=process_info.signed_status,
        path_suspicious=process_info.path_suspicious,
        parent_child_suspicious=process_info.parent_child_suspicious,
    )
    db_session.add(record)
    db_session.flush()
    return record
