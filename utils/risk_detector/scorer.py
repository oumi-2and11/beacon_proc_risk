"""评分计算：从规则命中结果汇总为风险分数。"""

from dataclasses import dataclass
from typing import List

from utils.common.helpers import determine_risk_level, truncate_string
from utils.rule_engine.rules import RuleHitResult


@dataclass
class ScoreResult:
    total_score: int = 0
    level: str = "LOW"
    score_process: int = 0
    score_network: int = 0
    score_memory: int = 0
    score_other: int = 0
    summary_reason: str = ""


def compute_score(hits: List[RuleHitResult]) -> ScoreResult:
    """从规则命中列表计算评分。

    算法：
      1. 按 dimension 分组求和 score_delta
      2. total_score = 所有 score_delta 之和，上限 100
      3. level = determine_risk_level(total_score)
      4. summary_reason = 主要命中规则标题，截断至 255 字符
    """
    result = ScoreResult()

    if not hits:
        result.level = "LOW"
        result.summary_reason = "无风险命中"
        return result

    dim_map = {"process", "network", "memory", "other"}
    for hit in hits:
        dim = hit.dimension if hit.dimension in dim_map else "other"
        if dim == "process":
            result.score_process += hit.score_delta
        elif dim == "network":
            result.score_network += hit.score_delta
        elif dim == "memory":
            result.score_memory += hit.score_delta
        else:
            result.score_other += hit.score_delta

    total = result.score_process + result.score_network + result.score_memory + result.score_other
    result.total_score = min(total, 100)
    result.level = determine_risk_level(result.total_score)

    # 摘要：按分数降序列出命中规则标题
    sorted_hits = sorted(hits, key=lambda h: h.score_delta, reverse=True)
    titles = [h.title for h in sorted_hits]
    result.summary_reason = truncate_string(" + ".join(titles), 255)

    return result
