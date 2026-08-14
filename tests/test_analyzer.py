"""Tests for the AsyncBlock analyzer."""

from __future__ import annotations

from pathlib import Path

from asyncblock.analyzer import (
    analyze_file,
    analyze_source,
    analyze_tree,
    load_ignore_patterns,
    summarize_findings,
)
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


def test_inline_ignore_same_line() -> None:
    findings = analyze_file(_fixture("ignore_same_line.py"))

    assert findings == []


def test_inline_ignore_next_line() -> None:
    findings = analyze_file(_fixture("ignore_next_line.py"))

    assert findings == []


def test_inline_ignore_specific_rule_only() -> None:
    findings = analyze_file(_fixture("ignore_specific_rule.py"))

    assert len(findings) == 1
    assert findings[0].rule_id == "BLOCK_SLEEP"


def test_analyze_source_inline_ignore() -> None:
    source = """import time

async def handler():
    time.sleep(1)  # asyncblock: ignore
"""
    findings = analyze_source(source)

    assert findings == []


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


def test_analyze_tree_include_glob_pattern() -> None:
    findings = analyze_tree(FIXTURES, include=["block_sleep.py"])

    assert findings
    assert all(Path(finding.file).name == "block_sleep.py" for finding in findings)
    assert all(finding.rule_id == "BLOCK_SLEEP" for finding in findings)


def test_analyze_tree_include_multiple_patterns() -> None:
    findings = analyze_tree(FIXTURES, include=["block_sleep.py", "block_http.py"])

    files = {Path(finding.file).name for finding in findings}
    assert files == {"block_sleep.py", "block_http.py"}


def test_analyze_tree_include_empty_when_no_match() -> None:
    findings = analyze_tree(FIXTURES, include=["nonexistent/*.py"])

    assert findings == []


def test_load_ignore_patterns_reads_file(tmp_path: Path) -> None:
    scan_root = tmp_path / "project"
    ignored = scan_root / "ignored"
    ignored.mkdir(parents=True)
    (ignored / "bad.py").write_text(
        "import time\n\nasync def handler():\n    time.sleep(1)\n",
        encoding="utf-8",
    )
    (scan_root / "ok.py").write_text(
        "import time\n\nasync def handler():\n    time.sleep(1)\n",
        encoding="utf-8",
    )
    (scan_root / ".asyncblockignore").write_text(
        "ignored/**\n# comment line\n\nlegacy/*.py\n",
        encoding="utf-8",
    )

    assert load_ignore_patterns(scan_root) == ["ignored/**", "legacy/*.py"]


def test_analyze_tree_respects_asyncblockignore(tmp_path: Path) -> None:
    scan_root = tmp_path / "project"
    ignored = scan_root / "ignored"
    ignored.mkdir(parents=True)
    (ignored / "bad.py").write_text(
        "import time\n\nasync def handler():\n    time.sleep(1)\n",
        encoding="utf-8",
    )
    (scan_root / "bad.py").write_text(
        "import time\n\nasync def handler():\n    time.sleep(1)\n",
        encoding="utf-8",
    )
    (scan_root / ".asyncblockignore").write_text("ignored/**\n", encoding="utf-8")

    findings = analyze_tree(scan_root)

    files = {Path(finding.file).name for finding in findings}
    assert files == {"bad.py"}


def test_analyze_tree_merges_cli_exclude_with_asyncblockignore(tmp_path: Path) -> None:
    scan_root = tmp_path / "project"
    ignored = scan_root / "ignored"
    ignored.mkdir(parents=True)
    (ignored / "bad.py").write_text(
        "import time\n\nasync def handler():\n    time.sleep(1)\n",
        encoding="utf-8",
    )
    (scan_root / "bad.py").write_text(
        "import time\n\nasync def handler():\n    time.sleep(1)\n",
        encoding="utf-8",
    )
    (scan_root / ".asyncblockignore").write_text("ignored/**\n", encoding="utf-8")

    findings = analyze_tree(scan_root, exclude=["bad.py"])

    assert findings == []


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


def test_analyze_source_detects_blocking_call() -> None:
    source = """import time

async def handler():
    time.sleep(1)
"""
    findings = analyze_source(source)

    assert len(findings) == 1
    assert findings[0].rule_id == "BLOCK_SLEEP"
    assert findings[0].file == "<string>"
    assert findings[0].line == 4


def test_analyze_source_custom_filename() -> None:
    source = """async def handler():
    open("x")
"""
    findings = analyze_source(source, filename="handlers.py")

    assert len(findings) == 1
    assert findings[0].file == "handlers.py"


def test_analyze_source_invalid_syntax_returns_empty() -> None:
    findings = analyze_source("async def oops(:")

    assert findings == []


def test_summarize_findings_counts_by_rule_and_file() -> None:
    findings = analyze_tree(FIXTURES)
    summary = summarize_findings(findings)

    assert summary.total == len(findings)
    assert summary.files >= 1
    assert summary.errors == summary.total
    assert summary.warnings == 0
    assert dict(summary.by_rule)
    assert all(count > 0 for _, count in summary.by_rule)


def test_summarize_findings_empty() -> None:
    summary = summarize_findings([])

    assert summary.total == 0
    assert summary.files == 0
    assert summary.errors == 0
    assert summary.warnings == 0
    assert summary.by_rule == ()


def test_scan_summary_to_dict() -> None:
    findings = analyze_file(_fixture("block_sleep.py"))
    data = summarize_findings(findings).to_dict()

    assert data["total"] == 1
    assert data["files"] == 1
    assert data["by_rule"] == {"BLOCK_SLEEP": 1}


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
