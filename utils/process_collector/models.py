"""进程数据模型，所有模块的进程信息中间表示。"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List


@dataclass
class ProcessInfo:
    """单个进程快照的规范数据结构。

    to_dict() 返回 processes.html 模板所需格式: {pid, name, user, path, ppid}
    """

    pid: int
    name: str = ""
    exe_path: str = ""
    cmdline: str = ""
    username: str = ""
    ppid: int = 0
    parent_name: str = ""
    create_time: Optional[datetime] = None
    is_system: bool = False
    signed_status: str = "unknown"
    process_key: str = ""
    connections: List[dict] = field(default_factory=list)
    cpu_percent: float = 0.0
    memory_rss: int = 0

    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "name": self.name,
            "user": self.username,
            "path": self.exe_path,
            "ppid": self.ppid,
        }

    def to_detail_dict(self) -> dict:
        return self.to_dict()
