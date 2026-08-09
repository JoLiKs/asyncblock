"""Tests for built-in rule catalog."""

from __future__ import annotations

from asyncblock.models import RuleInfo
from asyncblock.rules import RULES, list_rules


def test_list_rules_returns_grouped_catalog() -> None:
    catalog = list_rules()

    assert catalog
    assert all(isinstance(rule, RuleInfo) for rule in catalog)
    assert {rule.rule_id for rule in catalog} == {rule.rule_id for rule in RULES}


def test_list_rules_groups_http_methods() -> None:
    catalog = list_rules()
    http = next(rule for rule in catalog if rule.rule_id == "BLOCK_HTTP")

    assert "requests.get()" in http.patterns
    assert "requests.post()" in http.patterns
    assert http.severity == "error"
    assert "httpx" in http.suggestion


def test_rule_info_to_dict() -> None:
    rule = RuleInfo(
        rule_id="BLOCK_SLEEP",
        patterns=("time.sleep()",),
        suggestion="Use asyncio.sleep()",
        severity="error",
    )
    data = rule.to_dict()

    assert data["rule_id"] == "BLOCK_SLEEP"
    assert data["patterns"] == ["time.sleep()"]
    assert data["severity"] == "error"
