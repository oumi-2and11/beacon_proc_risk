"""规则上下文，传递给每条规则的检测环境信息。"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from utils.process_collector.models import ProcessInfo


@dataclass
class RuleContext:
    """单次规则检测的上下文。"""

    process: ProcessInfo
    connections: List[dict] = field(default_factory=list)
    allowlist: List[Dict[str, Any]] = field(default_factory=list)
    db_rules: List[Dict[str, Any]] = field(default_factory=list)
    parent_process: Optional[ProcessInfo] = None
    beacon_stats: Optional[Any] = None
