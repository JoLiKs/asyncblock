"""Tests for the AsyncBlock analyzer."""

from __future__ import annotations

from pathlib import Path

from asyncblock.analyzer import analyze_file, analyze_tree
from asyncblock.models import Finding
from asyncblock.rules import Rule

FIXTURES = Path(__file__).parent / "fixtures"


def _fixture(name: str) -> Path:
    return FIXTURES / name


def test_detects_time_sleep_in_async() -> None:
    findings = analyze_file(_fixture("block_sleep.py"))
    assert len(findings) == 1
    assert findings[0].rule_id == "BLOCK_SLEEP"
    assert findings[0].line == 5


def test_ignores_time_sleep_in_sync_function() -> None:
    findings = analyze_file(_fixture("sync_sleep_ok.py"))
    sleep_findings = [f for f in findings if f.rule_id == "BLOCK_SLEEP"]
    assert sleep_findings == []


def test_detects_aliased_import_time_sleep() -> None:
    findings = analyze_file(_fixture("alias_import.py"))
    assert len(findings) == 1
    assert findings[0].rule_id == "BLOCK_SLEEP"


def test_detects_requests_get_in_async() -> None:
    findings = analyze_file(_fixture("block_http.py"))
    assert len(findings) == 1
    assert findings[0].rule_id == "BLOCK_HTTP"


def test_detects_open_in_async() -> None:
    findings = analyze_file(_fixture("block_file.py"))
    assert len(findings) == 1
    assert findings[0].rule_id == "BLOCK_FILE"
    assert "aiofiles" in findings[0].suggestion


def test_detects_blocking_call_in_nested_sync_function() -> None:
    findings = analyze_file(_fixture("nested_sync_in_async.py"))
    assert len(findings) == 1
    assert findings[0].rule_id == "BLOCK_SLEEP"


def test_ignores_asyncio_sleep() -> None:
    findings = analyze_file(_fixture("async_sleep_ok.py"))
    assert findings == []


def test_detects_subprocess_run() -> None:
    findings = analyze_file(_fixture("block_subprocess.py"))
    assert len(findings) == 1
    assert findings[0].rule_id == "BLOCK_SUBPROCESS"


def test_detects_sqlite3_connect() -> None:
    findings = analyze_file(_fixture("block_db.py"))
    assert len(findings) == 1
    assert findings[0].rule_id == "BLOCK_DB"


def test_detects_socket_create_connection() -> None:
    findings = analyze_file(_fixture("block_socket.py"))
    assert len(findings) == 1
    assert findings[0].rule_id == "BLOCK_SOCKET"


def test_analyze_tree_excludes_glob_pattern() -> None:
    findings = analyze_tree(FIXTURES, exclude=["block_*.py"])
    files = {finding.file for finding in findings}
    assert all("block_" not in Path(f).name for f in files)


def test_analyze_tree_severity_filter() -> None:
    custom_rules = (
        Rule(
            rule_id="CUSTOM_WARN",
            module="time",
            attr="sleep",
            message="warn",
            suggestion="fix",
            severity="warning",
        ),
    )
    findings = analyze_file(_fixture("block_sleep.py"), rules=custom_rules)
    assert len(findings) == 1
    assert findings[0].severity == "warning"


def test_analyze_tree_rule_filter() -> None:
    findings = analyze_tree(FIXTURES, rule_ids=["BLOCK_SLEEP"])

    assert findings
    assert all(finding.rule_id == "BLOCK_SLEEP" for finding in findings)
    assert not any(finding.rule_id == "BLOCK_HTTP" for finding in findings)


def test_analyze_tree_rule_filter_empty_for_unknown_rule() -> None:
    findings = analyze_tree(FIXTURES, rule_ids=["NONEXISTENT_RULE"])

    assert findings == []


def test_finding_to_dict() -> None:
    finding = Finding(
        file="app.py",
        line=10,
        col=4,
        rule_id="BLOCK_SLEEP",
        message="Blocking sleep",
        suggestion="Use asyncio.sleep",
    )
    data = finding.to_dict()
    assert data["file"] == "app.py"
    assert data["rule_id"] == "BLOCK_SLEEP"
