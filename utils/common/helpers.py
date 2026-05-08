"""辅助函数，供所有 utils 模块共用。"""

import json
import platform
from datetime import datetime

from utils.common.constants import RISK_THRESHOLD_MID, RISK_THRESHOLD_HIGH


def generate_process_key(pid: int, start_time_epoch: float) -> str:
    return f"{pid}:{int(start_time_epoch)}"


def determine_risk_level(score: int) -> str:
    if score >= RISK_THRESHOLD_HIGH:
        return "HIGH"
    if score >= RISK_THRESHOLD_MID:
        return "MID"
    return "LOW"


def format_datetime(dt) -> str:
    if dt is None:
        return ""
    if isinstance(dt, str):
        return dt
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def safe_json_serialize(obj) -> str:
    def _default(o):
        if isinstance(o, datetime):
            return o.isoformat()
        if isinstance(o, set):
            return list(o)
        if isinstance(o, bytes):
            return o.decode("utf-8", errors="replace")
        raise TypeError(f"Object of type {type(o)} is not JSON serializable")
    return json.dumps(obj, default=_default, ensure_ascii=False)


def get_hostname() -> str:
    return platform.node()


def get_os_info() -> str:
    return f"{platform.system()} {platform.version()}"


def truncate_string(s: str, max_len: int = 255) -> str:
    if len(s) <= max_len:
        return s
    if max_len <= 3:
        return s[:max_len]
    return s[: max_len - 3] + "..."
