"""Command-line interface for AsyncBlock."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Literal, cast

from asyncblock import __version__
from asyncblock.analyzer import analyze_source, analyze_tree, filter_findings, summarize_findings
from asyncblock.models import Finding, RuleInfo, ScanSummary, Serializable, Severity
from asyncblock.rules import list_rules

_NO_FINDINGS_MESSAGE = "No blocking calls found in async contexts."
OutputFormat = Literal["table", "unix", "github"]
CommandHandler = Callable[[argparse.Namespace], int]


def _parse_scan_filters(args: argparse.Namespace) -> tuple[Severity, list[str] | None]:
    return cast(Severity, args.severity), args.rule or None


def _print_json(items: Sequence[Serializable]) -> None:
    payload = [item.to_dict() for item in items]
    print(json.dumps(payload, ensure_ascii=False, indent=2))


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
        help="File or directory to scan, or '-' for stdin (default: current directory)",
    )
    scan.add_argument(
        "--json",
        action="store_true",
        help="Output findings as JSON",
    )
    scan.add_argument(
        "--format",
        choices=("table", "unix", "github"),
        default="table",
        help="Human-readable output format: table, unix, or github (default: table; ignored with --json)",
    )
    scan.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="Exclude paths matching a glob pattern (repeatable)",
    )
    scan.add_argument(
        "--include",
        action="append",
        default=[],
        metavar="GLOB",
        help="Include only paths matching a glob pattern (repeatable)",
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
    scan.add_argument(
        "--summary",
        action="store_true",
        help="Print a short summary of findings (counts by rule and severity)",
    )

    rules = subparsers.add_parser("rules", help="List built-in detection rules")
    rules.add_argument(
        "--json",
        action="store_true",
        help="Output rules as JSON",
    )
    return parser


def _pluralize(count: int, singular: str) -> str:
    suffix = "" if count == 1 else "s"
    return f"{count} {singular}{suffix}"


def _render_table(
    columns: list[tuple[str, dict[str, Any]]],
    rows: list[tuple[str, ...]],
    *,
    empty_message: str,
) -> str:
    """Render a table with rich when available, otherwise tab-separated text."""
    if not rows:
        return empty_message

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


def _format_findings_unix(findings: list[Finding]) -> str:
    if not findings:
        return _NO_FINDINGS_MESSAGE
    return "\n".join(finding.format_unix() for finding in findings)


def _format_findings_github(findings: list[Finding]) -> str:
    if not findings:
        return _NO_FINDINGS_MESSAGE
    return "\n".join(finding.format_github() for finding in findings)


def _format_findings_table(findings: list[Finding]) -> str:
    return _render_table(
        [
            ("Location", {"style": "cyan", "no_wrap": True}),
            ("Rule", {"style": "magenta"}),
            ("Message", {}),
            ("Suggestion", {"style": "green"}),
        ],
        [
            (finding.location, finding.rule_id, finding.message, finding.suggestion)
            for finding in findings
        ],
        empty_message=_NO_FINDINGS_MESSAGE,
    )


def _format_summary(summary: ScanSummary) -> str:
    if summary.total == 0:
        return "Summary: no blocking calls found."

    parts = [_pluralize(summary.total, "finding"), f"in {_pluralize(summary.files, 'file')}"]
    severity_parts: list[str] = []
    if summary.errors:
        severity_parts.append(_pluralize(summary.errors, "error"))
    if summary.warnings:
        severity_parts.append(_pluralize(summary.warnings, "warning"))
    lines = [f"Summary: {', '.join(parts)} ({', '.join(severity_parts)})"]
    for rule_id, count in summary.by_rule:
        lines.append(f"  {rule_id}: {count}")
    return "\n".join(lines)


def _format_rules_table(rules: tuple[RuleInfo, ...]) -> str:
    return _render_table(
        [
            ("Rule", {"style": "magenta", "no_wrap": True}),
            ("Patterns", {}),
            ("Severity", {}),
            ("Suggestion", {"style": "green"}),
        ],
        [
            (rule.rule_id, ", ".join(rule.patterns), rule.severity, rule.suggestion)
            for rule in rules
        ],
        empty_message="No built-in rules configured.",
    )


def _run_rules(args: argparse.Namespace) -> int:
    rules = list_rules()

    if args.json:
        _print_json(list(rules))
    else:
        print(_format_rules_table(rules))

    return 0


def _scan_stdin(
    *,
    min_severity: Severity,
    rule_ids: list[str] | None,
) -> list[Finding]:
    """Read Python source from stdin and return filtered findings."""
    source = sys.stdin.read()
    findings = analyze_source(source, filename="<stdin>")
    return filter_findings(findings, min_severity=min_severity, rule_ids=rule_ids)


def _write_scan_output(
    findings: list[Finding],
    *,
    as_json: bool,
    output_format: OutputFormat,
    summary: ScanSummary | None,
) -> None:
    """Print scan findings and an optional summary."""
    if as_json:
        _print_json(findings)
        if summary is not None:
            summary_json = json.dumps(summary.to_dict(), ensure_ascii=False)
            print(summary_json, file=sys.stderr)
        return

    if output_format == "unix":
        print(_format_findings_unix(findings))
    elif output_format == "github":
        print(_format_findings_github(findings))
    else:
        print(_format_findings_table(findings))
    if summary is not None:
        print()
        print(_format_summary(summary))


def _run_scan(args: argparse.Namespace) -> int:
    min_severity, rule_ids = _parse_scan_filters(args)

    if args.path == "-":
        findings = _scan_stdin(min_severity=min_severity, rule_ids=rule_ids)
    else:
        path = Path(args.path)
        if not path.exists():
            print(f"Error: path does not exist: {path}", file=sys.stderr)
            return 2

        findings = analyze_tree(
            path,
            exclude=args.exclude,
            include=args.include,
            min_severity=min_severity,
            rule_ids=rule_ids,
        )

    summary = summarize_findings(findings) if args.summary else None
    _write_scan_output(
        findings,
        as_json=args.json,
        output_format=cast(OutputFormat, args.format),
        summary=summary,
    )

    return 1 if any(finding.severity == "error" for finding in findings) else 0


_COMMAND_HANDLERS: dict[str, CommandHandler] = {
    "scan": _run_scan,
    "rules": _run_rules,
}


def main(argv: list[str] | None = None) -> int:
    """Entry point for the asyncblock CLI."""
    args = _build_parser().parse_args(argv)
    handler = _COMMAND_HANDLERS.get(args.command)
    return handler(args) if handler is not None else 0


if __name__ == "__main__":
    raise SystemExit(main())
