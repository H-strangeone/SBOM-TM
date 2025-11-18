from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from packaging.version import InvalidVersion, Version

from .context_loader import ServiceContext

@dataclass(slots=True)
class Rule:
    id: str
    description: str
    conditions: List[Dict[str, Any]]
    result: Dict[str, Any]
    score_factors: Dict[str, float]
    severity: Optional[str] = None
    last_updated: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class RuleEngine:
    def __init__(self, rules: List[Rule]):
        self.rules = rules

    @classmethod
    def from_directory(cls, directory: Path) -> "RuleEngine":
        rules: List[Rule] = []
        for path in sorted(directory.glob("*.json")):
            try:
                with path.open("r", encoding="utf-8") as fh:
                    payload = json.load(fh)
                if isinstance(payload, dict):
                    payload = [payload]
                for entry in payload:
                    rule = _build_rule_from_entry(entry)
                    if rule is not None:
                        rules.append(rule)
            except (OSError, json.JSONDecodeError) as exc:
                print(f" Error loading {path.name}: {exc}")
        return cls(rules)

    def evaluate(
        self,
        component: Dict[str, Any],
        vulnerability: Dict[str, Any],
        service: Optional[ServiceContext],
        threatintel: Optional[Dict[str, Any]] = None,
    ) -> Iterable[Dict[str, Any]]:
        context = {
            "component": component,
            "vuln": vulnerability,
            "context": asdict(service) if service else {},
            "threatintel": threatintel or {},
        }

        for rule in self.rules:
            if all(_condition_matches(condition, context) for condition in rule.conditions):
                yield {
                    "rule_id": rule.id,
                    "description": rule.description,
                    "pattern": rule.result.get("pattern", []),
                    "objective": rule.result.get("objective", []),
                    "recommendations": rule.result.get("recommendations", []),
                    "pattern_multiplier": rule.result.get("pattern_multiplier", 1.0),
                    "score_factors": rule.score_factors,
                    "rule_severity": rule.severity,
                    "rule_metadata": rule.metadata,
                    "last_updated": rule.last_updated,
                }


def _condition_matches(condition: Dict[str, Any], context: Dict[str, Any]) -> bool:
    if not condition:
        return True
    if "match_type" in condition:
        return _evaluate_complex_condition(condition, context)
    field, value = next(iter(condition.items()))
    actual = _dig_value(context, field)
    if isinstance(value, dict):
        for operator, expected in value.items():
            if not _compare(operator, actual, expected):
                return False
        return True
    return actual == value


def _dig_value(payload: Dict[str, Any], field: str) -> Any:
    if field.startswith("vulnerability."):
        field = "vuln." + field.split(".", 1)[1]
    elif field.startswith("package."):
        field = "component." + field.split(".", 1)[1]
    current: Any = payload
    for token in field.split("."):
        if isinstance(current, dict):
            current = current.get(token)
        else:
            return None
    return current


def _compare(operator: str, actual: Any, expected: Any) -> bool:
    if operator == "eq":
        return actual == expected
    if operator == "neq":
        return actual != expected
    if operator == "gte":
        return actual is not None and actual >= expected
    if operator == "lte":
        return actual is not None and actual <= expected
    if operator == "gt":
        return actual is not None and actual > expected
    if operator == "lt":
        return actual is not None and actual < expected
    if operator == "in":
        return actual in expected if isinstance(expected, (list, set, tuple)) else False
    if operator == "contains":
        if isinstance(actual, (list, set, tuple)):
            return expected in actual
        if isinstance(actual, str):
            return str(expected) in actual
        return False
    if operator == "exists":
        return actual is not None
    return False


def _evaluate_complex_condition(condition: Dict[str, Any], context: Dict[str, Any]) -> bool:
    match_type = str(condition.get("match_type", "")).lower()

    if match_type in {"regex", "regex_any"}:
        pattern = condition.get("pattern")
        if not pattern:
            return False
        flags_value = condition.get("flags", "")
        regex_flags = 0
        if isinstance(flags_value, str) and "i" in flags_value.lower():
            regex_flags |= re.IGNORECASE
        field_list = condition.get("fields") if match_type == "regex_any" else [condition.get("field")]
        if not field_list:
            return False
        for field in field_list:
            if not field:
                continue
            actual = _dig_value(context, str(field))
            if actual is not None and re.search(str(pattern), str(actual), regex_flags):
                return True
        return False

    if match_type in {"any_of", "in_list"}:
        field = condition.get("field")
        values = condition.get("values", [])
        if not field:
            return False
        actual = _dig_value(context, str(field))
        if actual is None:
            return False
        normalized_values = {str(value) for value in values}
        return str(actual) in normalized_values

    if match_type == "version_lt_field":
        field = condition.get("field")
        compare_to = condition.get("compare_to")
        if not field or not compare_to:
            return False
        left = _dig_value(context, str(field))
        right = _dig_value(context, str(compare_to))
        if left is None or right is None:
            return False
        try:
            return Version(str(left)) < Version(str(right))
        except InvalidVersion:
            return False

    if match_type == "missing_fields":
        fields = condition.get("fields", [])
        for field in fields:
            value = _dig_value(context, str(field))
            if value in (None, "", [], {}):
                return True
        return False

    if match_type == "and":
        subconditions = condition.get("subconditions", [])
        return all(_condition_matches(subcondition, context) for subcondition in subconditions)

    if match_type == "exists":
        field = condition.get("field")
        if not field:
            return False
        return _dig_value(context, str(field)) not in (None, "")

    if match_type == "not_exists":
        field = condition.get("field")
        if not field:
            return False
        return _dig_value(context, str(field)) in (None, "")

    return False


def _build_rule_from_entry(entry: Dict[str, Any]) -> Optional[Rule]:
    rule_id = entry.get("id") or entry.get("rule_id")
    if not rule_id:
        return None

    if entry.get("enabled") is False:
        return None

    title = entry.get("title")
    description = entry.get("description")
    if title and description:
        rule_description = f"{title}: {description}"
    else:
        rule_description = title or description or ""

    raw_conditions = entry.get("conditions")
    if not raw_conditions and entry.get("condition"):
        raw_conditions = [entry["condition"]]
    if not raw_conditions:
        return None

    result = entry.get("result") or {}
    if not result:
        tags = entry.get("tags") or []
        remediation = entry.get("remediation")
        recommendations: List[Dict[str, Any]] = []
        if remediation:
            recommendations.append({"type": "remediation", "detail": remediation})
        result = {
            "pattern": tags or [rule_id],
            "objective": entry.get("objective", []),
            "recommendations": recommendations,
            "pattern_multiplier": entry.get("pattern_multiplier", 1.0),
        }

    return Rule(
        id=str(rule_id),
        description=rule_description,
        conditions=list(raw_conditions),
        result=result,
        score_factors=entry.get("score_factors", {}),
        severity=entry.get("severity"),
        last_updated=entry.get("last_updated"),
        metadata={
            "scope": entry.get("scope"),
            "tags": entry.get("tags"),
            "remediation": entry.get("remediation"),
        },
    )
