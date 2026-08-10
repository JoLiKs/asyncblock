"""Command-line interface for AsyncBlock."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, cast

from asyncblock import __version__
from asyncblock.analyzer import analyze_tree
from asyncblock.models import Finding, RuleInfo, Severity
from asyncblock.rules import list_rules


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="asyncblock",
        description="Find blocking synchronous calls inside async def functions",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan a file or directory for blocking calls")
    scan.add_argument(
        "path",
        nargs="?",
        default=".",
        help="File or directory to scan (default: current directory)",
    )
    scan.add_argument(
        "--json",
        action="store_true",
        help="Output findings as JSON",
    )
    scan.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="Exclude paths matching a glob pattern (repeatable)",
    )
    scan.add_argument(
        "--severity",
        choices=("warning", "error"),
        default="warning",
        help="Minimum severity to report (default: warning)",
    )
    scan.add_argument(
        "--rule",
        action="append",
        default=[],
        metavar="RULE_ID",
        help="Report only findings for these rule IDs (repeatable, see `asyncblock rules`)",
    )

    rules = subparsers.add_parser("rules", help="List built-in detection rules")
    rules.add_argument(
        "--json",
        action="store_true",
        help="Output rules as JSON",
    )
    return parser


def _render_table(
    columns: list[tuple[str, dict[str, Any]]],
    rows: list[tuple[str, ...]],
) -> str:
    """Render a table with rich when available, otherwise tab-separated text."""
    try:
        from rich.console import Console
        from rich.table import Table

        table = Table(show_header=True, header_style="bold")
        for title, options in columns:
            table.add_column(title, **options)
        for row in rows:
            table.add_row(*row)

        console = Console()
        with console.capture() as capture:
            console.print(table)
        return capture.get()
    except ImportError:
        header = "\t".join(title for title, _ in columns)
        body = ["\t".join(row) for row in rows]
        return "\n".join([header, *body])


def _format_text(findings: list[Finding]) -> str:
    if not findings:
        return "No blocking calls found in async contexts."

    columns: list[tuple[str, dict[str, Any]]] = [
        ("Location", {"style": "cyan", "no_wrap": True}),
        ("Rule", {"style": "magenta"}),
        ("Message", {}),
        ("Suggestion", {"style": "green"}),
    ]
    rows = [
        (finding.location, finding.rule_id, finding.message, finding.suggestion)
        for finding in findings
    ]
    return _render_table(columns, rows)


def _format_rules_text(rules: tuple[RuleInfo, ...]) -> str:
    if not rules:
        return "No built-in rules configured."

    columns: list[tuple[str, dict[str, Any]]] = [
        ("Rule", {"style": "magenta", "no_wrap": True}),
        ("Patterns", {}),
        ("Severity", {}),
        ("Suggestion", {"style": "green"}),
    ]
    rows = [
        (rule.rule_id, ", ".join(rule.patterns), rule.severity, rule.suggestion)
        for rule in rules
    ]
    return _render_table(columns, rows)


def _run_rules(args: argparse.Namespace) -> int:
    rules = list_rules()

    if args.json:
        payload = [rule.to_dict() for rule in rules]
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(_format_rules_text(rules))

    return 0


def _run_scan(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if not path.exists():
        print(f"Error: path does not exist: {path}", file=sys.stderr)
        return 2

    rule_ids = args.rule or None
    findings = analyze_tree(
        path,
        exclude=args.exclude,
        min_severity=cast(Severity, args.severity),
        rule_ids=rule_ids,
    )

    if args.json:
        payload = [finding.to_dict() for finding in findings]
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(_format_text(findings))

    has_errors = any(finding.severity == "error" for finding in findings)
    return 1 if has_errors else 0


def main(argv: list[str] | None = None) -> int:
    """Entry point for the asyncblock CLI."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _run_scan(args)
    if args.command == "rules":
        return _run_rules(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
