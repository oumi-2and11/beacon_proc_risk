"""规则引擎核心：加载规则、执行检测、白名单过滤。"""

from typing import List, Optional

from utils.rule_engine.context import RuleContext
from utils.rule_engine.rules import BaseRule, RuleHitResult, _RULE_REGISTRY
from utils.common.validators import is_allowed


class RuleEngine:
    """规则引擎：管理规则生命周期并执行检测。"""

    def __init__(self):
        self.rules: List[BaseRule] = []
        self._init_default_rules()

    def _init_default_rules(self):
        """实例化所有 @register_rule 注册的规则。"""
        for cls in _RULE_REGISTRY:
            self.rules.append(cls())

    def load_db_config(self, db_session):
        """从 DB Rule 表加载配置：enabled=False 则移除，default_weight 不同则覆盖。"""
        from webapp.models import Rule as RuleModel

        db_rules = RuleModel.query.all()
        db_map = {r.rule_id: r for r in db_rules}

        # 更新已有规则的权重和启用状态
        active_rules = []
        for rule in self.rules:
            db_rule = db_map.get(rule.rule_id)
            if db_rule:
                if not db_rule.enabled:
                    continue
                rule.default_weight = db_rule.default_weight
            active_rules.append(rule)

        # 添加 DB 中有但代码中未注册的规则（占位，check 永远返回 None）
        registered_ids = {r.rule_id for r in active_rules}
        for db_rule in db_rules:
            if db_rule.enabled and db_rule.rule_id not in registered_ids:
                placeholder = _PlaceholderRule(
                    rule_id=db_rule.rule_id,
                    title=db_rule.title,
                    dimension=db_rule.dimension,
                    default_weight=db_rule.default_weight,
                )
                active_rules.append(placeholder)

        self.rules = active_rules

    def evaluate(self, context: RuleContext) -> List[RuleHitResult]:
        """执行全部启用规则：先白名单过滤 → rule.check(ctx) → 收集命中。"""
        # 白名单过滤：rule_id 类型白名单暂不在此处理
        process_info = {
            "name": context.process.name,
            "exe_path": context.process.exe_path or "",
        }
        if is_allowed(process_info, context.allowlist):
            return []

        hits = []
        for rule in self.rules:
            result = rule.check(context)
            if result is not None:
                # 用规则实际权重覆盖 check 中的 score_delta
                result.score_delta = rule.default_weight
                hits.append(result)
        return hits

    def get_rule_by_id(self, rule_id: str) -> Optional[BaseRule]:
        """按 rule_id 查找规则实例。"""
        for rule in self.rules:
            if rule.rule_id == rule_id:
                return rule
        return None


class _PlaceholderRule(BaseRule):
    """DB 中有但代码未实现的规则占位，check 永远返回 None。"""

    def __init__(self, rule_id, title, dimension, default_weight):
        self.rule_id = rule_id
        self.title = title
        self.dimension = dimension
        self.default_weight = default_weight

    def check(self, context: RuleContext) -> Optional[RuleHitResult]:
        return None
