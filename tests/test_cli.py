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
