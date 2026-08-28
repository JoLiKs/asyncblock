"""Tests for the AsyncBlock CLI."""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

from asyncblock.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_rules_command_prints_catalog(capsys) -> None:
    exit_code = main(["rules"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "BLOCK_SLEEP" in captured.out
    assert "time.sleep()" in captured.out
    assert "BLOCK_HTTP" in captured.out


def test_rules_command_json_output(capsys) -> None:
    exit_code = main(["rules", "--json"])

    captured = capsys.readouterr()
    assert exit_code == 0

    payload = json.loads(captured.out)
    assert isinstance(payload, list)
    assert payload[0]["rule_id"]
    assert isinstance(payload[0]["patterns"], list)


def test_scan_command_missing_path_returns_error(capsys) -> None:
    exit_code = main(["scan", "/path/that/does/not/exist"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "does not exist" in captured.err


def test_scan_command_rule_filter(capsys) -> None:
    exit_code = main(["scan", str(FIXTURES), "--rule", "BLOCK_SLEEP", "--json"])

    captured = capsys.readouterr()
    assert exit_code == 1

    payload = json.loads(captured.out)
    assert payload
    assert all(item["rule_id"] == "BLOCK_SLEEP" for item in payload)
    assert not any(item["rule_id"] == "BLOCK_HTTP" for item in payload)


def test_scan_command_include_filter(capsys) -> None:
    exit_code = main(["scan", str(FIXTURES), "--include", "block_sleep.py", "--json"])

    captured = capsys.readouterr()
    assert exit_code == 1

    payload = json.loads(captured.out)
    assert payload
    assert all(item["file"].endswith("block_sleep.py") for item in payload)


def test_scan_command_stdin(capsys, monkeypatch) -> None:
    source = """import time

async def handler():
    time.sleep(1)
"""
    monkeypatch.setattr("sys.stdin", StringIO(source))

    exit_code = main(["scan", "-", "--json"])

    captured = capsys.readouterr()
    assert exit_code == 1

    payload = json.loads(captured.out)
    assert len(payload) == 1
    assert payload[0]["rule_id"] == "BLOCK_SLEEP"
    assert payload[0]["file"] == "<stdin>"


def test_scan_command_summary_text_output(capsys) -> None:
    exit_code = main(["scan", str(FIXTURES), "--summary"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Summary:" in captured.out
    assert "scanned" in captured.out.lower()
    assert "BLOCK_SLEEP" in captured.out
    assert captured.err == ""


def test_scan_command_summary_json_output_on_stderr(capsys) -> None:
    exit_code = main(["scan", str(FIXTURES), "--json", "--summary"])

    captured = capsys.readouterr()
    assert exit_code == 1

    findings = json.loads(captured.out)
    assert isinstance(findings, list)
    assert findings

    summary = json.loads(captured.err.strip())
    assert summary["total"] == len(findings)
    assert summary["files"] >= 1
    assert summary["files_scanned"] >= 1
    assert isinstance(summary["by_rule"], dict)


def test_scan_command_summary_empty_scan(capsys) -> None:
    exit_code = main(["scan", str(FIXTURES / "async_sleep_ok.py"), "--summary"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "no blocking calls found" in captured.out.lower()
    assert "1 file scanned" in captured.out.lower()


def test_scan_command_unix_format(capsys) -> None:
    exit_code = main(["scan", str(FIXTURES / "block_sleep.py"), "--format", "unix"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out.strip() == (
        f"{FIXTURES / 'block_sleep.py'}:5:5: BLOCK_SLEEP: "
        "Blocking time.sleep() inside async code"
    )


def test_scan_command_unix_format_empty(capsys) -> None:
    exit_code = main(["scan", str(FIXTURES / "async_sleep_ok.py"), "--format", "unix"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "no blocking calls found" in captured.out.lower()


def test_scan_command_github_format(capsys) -> None:
    exit_code = main(["scan", str(FIXTURES / "block_sleep.py"), "--format", "github"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out.strip() == (
        f"::error file={FIXTURES / 'block_sleep.py'},line=5,col=5,title=BLOCK_SLEEP::"
        "Blocking time.sleep() inside async code — Use asyncio.sleep() or anyio.sleep()"
    )


def test_scan_command_github_format_empty(capsys) -> None:
    exit_code = main(["scan", str(FIXTURES / "async_sleep_ok.py"), "--format", "github"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "no blocking calls found" in captured.out.lower()
