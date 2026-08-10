"""Built-in detection rules for blocking synchronous calls."""

from __future__ import annotations

from dataclasses import dataclass

from asyncblock.models import RuleInfo, Severity


@dataclass(frozen=True, slots=True)
class Rule:
    """A rule that matches a blocking call pattern."""

    rule_id: str
    message: str
    suggestion: str
    severity: Severity = "error"
    module: str | None = None
    attr: str | None = None
    builtin: str | None = None


def _module_attr_rule(
    rule_id: str,
    module: str,
    attr: str,
    *,
    suggestion: str,
    severity: Severity = "error",
) -> Rule:
    """Build a rule for a ``module.attr()`` blocking call."""
    return Rule(
        rule_id=rule_id,
        module=module,
        attr=attr,
        message=f"Blocking {module}.{attr}() inside async code",
        suggestion=suggestion,
        severity=severity,
    )


_HTTP_SUGGESTION = "Use httpx.AsyncClient or aiohttp.ClientSession"
_SUBPROCESS_SUGGESTION = (
    "Use asyncio.create_subprocess_exec() or asyncio.create_subprocess_shell()"
)
_SOCKET_SUGGESTION = "Use asyncio.open_connection() or asyncio streams"

RULES: tuple[Rule, ...] = (
    _module_attr_rule(
        "BLOCK_SLEEP",
        "time",
        "sleep",
        suggestion="Use asyncio.sleep() or anyio.sleep()",
    ),
    *(
        _module_attr_rule("BLOCK_HTTP", "requests", method, suggestion=_HTTP_SUGGESTION)
        for method in ("get", "post", "put", "patch", "delete", "head", "options", "request")
    ),
    Rule(
        rule_id="BLOCK_FILE",
        builtin="open",
        message="Blocking open() inside async code",
        suggestion="Use aiofiles.open()",
    ),
    *(
        _module_attr_rule("BLOCK_SUBPROCESS", "subprocess", attr, suggestion=_SUBPROCESS_SUGGESTION)
        for attr in ("run", "call", "check_call", "check_output", "Popen")
    ),
    *(
        _module_attr_rule("BLOCK_SOCKET", "socket", attr, suggestion=_SOCKET_SUGGESTION)
        for attr in ("socket", "create_connection")
    ),
    _module_attr_rule(
        "BLOCK_DB",
        "sqlite3",
        "connect",
        suggestion="Use aiosqlite.connect() or an async ORM driver",
    ),
    _module_attr_rule(
        "BLOCK_DB",
        "psycopg2",
        "connect",
        suggestion="Use asyncpg.connect() or psycopg (v3) async API",
    ),
)


def _rule_pattern(rule: Rule) -> str:
    if rule.builtin:
        return f"{rule.builtin}()"
    return f"{rule.module}.{rule.attr}()"


def list_rules() -> tuple[RuleInfo, ...]:
    """Return built-in rules grouped by ``rule_id`` with matched call patterns."""
    patterns_by_id: dict[str, list[str]] = {}
    details_by_id: dict[str, tuple[str, Severity]] = {}

    for rule in RULES:
        patterns_by_id.setdefault(rule.rule_id, []).append(_rule_pattern(rule))
        details_by_id[rule.rule_id] = (rule.suggestion, rule.severity)

    return tuple(
        RuleInfo(
            rule_id=rule_id,
            patterns=tuple(patterns),
            suggestion=details_by_id[rule_id][0],
            severity=details_by_id[rule_id][1],
        )
        for rule_id, patterns in patterns_by_id.items()
    )
