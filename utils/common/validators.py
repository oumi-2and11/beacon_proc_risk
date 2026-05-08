"""数据验证函数。"""

from utils.common.constants import WINDOWS_SYSTEM_PATHS, SUSPICIOUS_PATH_PATTERNS


def is_valid_pid(pid: int) -> bool:
    return isinstance(pid, int) and pid > 0


def is_allowed(process_info: dict, allowlist_entries: list) -> bool:
    """检查进程是否在白名单中（应跳过）。

    process_info 需含 'name', 'exe_path'，可选 'remote_ips' 列表。
    allowlist_entries 为 Allowlist ORM 对象列表，含 type/value 字段。
    """
    proc_name = process_info.get("name", "").lower()
    proc_path = process_info.get("exe_path", "")
    remote_ips = process_info.get("remote_ips", [])

    for entry in allowlist_entries:
        if not getattr(entry, "enabled", True):
            continue
        etype = entry.type
        value = entry.value.lower() if isinstance(entry.value, str) else entry.value

        if etype == "process_name" and value == proc_name:
            return True
        if etype == "process_path" and value and proc_path.lower().startswith(value):
            return True
        if etype == "remote_ip" and value in remote_ips:
            return True
        if etype == "rule_id":
            pass  # rule_id 白名单在规则引擎中处理
    return False


def is_suspicious_path(exe_path: str) -> bool:
    if not exe_path:
        return False
    lower = exe_path.lower()
    return any(p.lower() in lower for p in SUSPICIOUS_PATH_PATTERNS)


def is_system_path(exe_path: str) -> bool:
    if not exe_path:
        return False
    lower = exe_path.lower()
    return any(lower.startswith(sp.lower()) for sp in WINDOWS_SYSTEM_PATHS)
