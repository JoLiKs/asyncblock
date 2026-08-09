"""Command-line interface for AsyncBlock."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import cast

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

    rules = subparsers.add_parser("rules", help="List built-in detection rules")
    rules.add_argument(
        "--json",
        action="store_true",
        help="Output rules as JSON",
    )
    return parser


def _format_text(findings: list[Finding]) -> str:
    if not findings:
        return "No blocking calls found in async contexts."

    try:
        from rich.console import Console
        from rich.table import Table

        table = Table(show_header=True, header_style="bold")
        table.add_column("Location", style="cyan", no_wrap=True)
        table.add_column("Rule", style="magenta")
        table.add_column("Message")
        table.add_column("Suggestion", style="green")

        for finding in findings:
            table.add_row(finding.location, finding.rule_id, finding.message, finding.suggestion)

        console = Console()
        with console.capture() as capture:
            console.print(table)
        return capture.get()
    except ImportError:
        lines = ["Location\tRule\tMessage\tSuggestion"]
        for finding in findings:
            lines.append(
                f"{finding.location}\t{finding.rule_id}\t{finding.message}\t{finding.suggestion}"
            )
        return "\n".join(lines)


def _format_rules_text(rules: tuple[RuleInfo, ...]) -> str:
    if not rules:
        return "No built-in rules configured."

    try:
        from rich.console import Console
        from rich.table import Table

        table = Table(show_header=True, header_style="bold")
        table.add_column("Rule", style="magenta", no_wrap=True)
        table.add_column("Patterns")
        table.add_column("Severity")
        table.add_column("Suggestion", style="green")

        for rule in rules:
            table.add_row(
                rule.rule_id,
                ", ".join(rule.patterns),
                rule.severity,
                rule.suggestion,
            )

        console = Console()
        with console.capture() as capture:
            console.print(table)
        return capture.get()
    except ImportError:
        lines = ["Rule\tPatterns\tSeverity\tSuggestion"]
        for rule in rules:
            lines.append(
                f"{rule.rule_id}\t{', '.join(rule.patterns)}\t{rule.severity}\t{rule.suggestion}"
            )
        return "\n".join(lines)


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

    findings = analyze_tree(
        path,
        exclude=args.exclude,
        min_severity=cast(Severity, args.severity),
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
