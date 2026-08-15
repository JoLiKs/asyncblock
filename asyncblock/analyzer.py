"""AST-based analyzer for blocking calls inside async contexts."""

from __future__ import annotations

import ast
import fnmatch
import re
import tokenize
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from io import StringIO
from pathlib import Path

from asyncblock.models import Finding, ScanSummary, Severity, meets_min_severity
from asyncblock.rules import RULES, Rule


def _top_level_module_name(qualified_name: str) -> str:
    """Return the top-level package from a dotted import path."""
    return qualified_name.split(".", maxsplit=1)[0]


_IGNORE_DIRECTIVE_RE = re.compile(
    r"asyncblock:\s*ignore(?P<next_line>-next-line)?"
    r"(?:\s+(?P<rule_ids>[A-Z][A-Z0-9_]*(?:\s+[A-Z][A-Z0-9_]*)*))?",
    re.IGNORECASE,
)


@dataclass
class _LineSuppression:
    """Rules suppressed on a specific source line."""

    ignore_all: bool = False
    rule_ids: set[str] = field(default_factory=set)


def _parse_suppressions(source: str) -> dict[int, _LineSuppression]:
    """Parse ``# asyncblock: ignore`` directives from source comments."""
    suppressions: dict[int, _LineSuppression] = {}

    try:
        tokens = tokenize.generate_tokens(StringIO(source).readline)
    except tokenize.TokenError:
        return suppressions

    for token in tokens:
        if token.type != tokenize.COMMENT:
            continue

        match = _IGNORE_DIRECTIVE_RE.search(token.string)
        if match is None:
            continue

        target_line = token.start[0] + (1 if match.group("next_line") else 0)
        rule_ids = match.group("rule_ids")
        suppression = suppressions.setdefault(target_line, _LineSuppression())

        if rule_ids is None:
            suppression.ignore_all = True
            continue

        suppression.rule_ids.update(rule_ids.split())

    return suppressions


def _is_finding_suppressed(
    finding: Finding,
    suppression: _LineSuppression | None,
) -> bool:
    """Return whether an inline ignore directive suppresses *finding*."""
    if suppression is None:
        return False
    return suppression.ignore_all or finding.rule_id in suppression.rule_ids


def _apply_suppressions(
    findings: list[Finding],
    suppressions: dict[int, _LineSuppression],
) -> list[Finding]:
    """Drop findings suppressed by inline ``asyncblock: ignore`` comments."""
    if not suppressions:
        return findings

    return [
        finding
        for finding in findings
        if not _is_finding_suppressed(finding, suppressions.get(finding.line))
    ]


def _read_text(path: Path) -> str | None:
    """Read UTF-8 text from *path*, returning ``None`` on I/O errors."""
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


class _DepthCounter:
    """Tracks nesting depth for async or nested-sync scopes."""

    __slots__ = ("_depth",)

    def __init__(self) -> None:
        self._depth = 0

    @property
    def active(self) -> bool:
        return self._depth > 0

    @contextmanager
    def scope(self) -> Iterator[None]:
        self._depth += 1
        try:
            yield
        finally:
            self._depth -= 1


class _ImportMap:
    """Tracks import aliases for resolving call targets."""

    def __init__(self) -> None:
        self.module_aliases: dict[str, str] = {}
        self.imported_symbols: dict[str, tuple[str, str]] = {}

    def register_imports(self, node: ast.AST) -> None:
        for child in ast.walk(node):
            if isinstance(child, ast.Import):
                for alias in child.names:
                    local = alias.asname or _top_level_module_name(alias.name)
                    self.module_aliases[local] = _top_level_module_name(alias.name)
            elif isinstance(child, ast.ImportFrom) and child.module:
                module = _top_level_module_name(child.module)
                for alias in child.names:
                    if alias.name == "*":
                        continue
                    local = alias.asname or alias.name
                    self.imported_symbols[local] = (module, alias.name)


class _AsyncBlockingVisitor(ast.NodeVisitor):
    """Walks AST and collects blocking calls inside async contexts."""

    def __init__(self, filename: str, rules: tuple[Rule, ...]) -> None:
        self.filename = filename
        self.rules = rules
        self.findings: list[Finding] = []
        self.imports = _ImportMap()
        self._async_depth = _DepthCounter()
        self._nested_sync_depth = _DepthCounter()

    def visit_Module(self, node: ast.Module) -> None:
        self.imports.register_imports(node)
        self.generic_visit(node)

    @property
    def _in_async_context(self) -> bool:
        return self._async_depth.active or self._nested_sync_depth.active

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        with self._async_depth.scope():
            self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if self._in_async_context:
            with self._nested_sync_depth.scope():
                self.generic_visit(node)
            return
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if self._in_async_context:
            rule = _match_call(node.func, self.imports, self.rules)
            if rule is not None:
                self.findings.append(_make_finding(node, rule, self.filename))
        self.generic_visit(node)


def _match_name_call(
    name: str,
    imports: _ImportMap,
    rules: tuple[Rule, ...],
) -> Rule | None:
    """Return the first rule matching a bare name call such as ``open()`` or ``sleep()``."""
    for rule in rules:
        if rule.builtin and name == rule.builtin:
            return rule
    if name in imports.imported_symbols:
        module, attr = imports.imported_symbols[name]
        return _match_module_attr(module, attr, rules)
    return None


def _match_call(
    func: ast.expr,
    imports: _ImportMap,
    rules: tuple[Rule, ...],
) -> Rule | None:
    """Return the first rule matching the given call expression."""
    if isinstance(func, ast.Name):
        return _match_name_call(func.id, imports, rules)

    if isinstance(func, ast.Attribute):
        module, attr = _resolve_attribute(func, imports)
        if module is not None and attr is not None:
            return _match_module_attr(module, attr, rules)

    return None


def _resolve_attribute(node: ast.Attribute, imports: _ImportMap) -> tuple[str | None, str | None]:
    """Resolve `module.attr` from an Attribute node, following one level of alias."""
    attr = node.attr
    value = node.value
    if isinstance(value, ast.Name):
        if value.id in imports.module_aliases:
            return imports.module_aliases[value.id], attr
        if value.id in imports.imported_symbols:
            module, _ = imports.imported_symbols[value.id]
            return module, attr
    return None, None


def _match_module_attr(module: str, attr: str, rules: tuple[Rule, ...]) -> Rule | None:
    for rule in rules:
        if rule.module == module and rule.attr == attr:
            return rule
    return None


def _make_finding(node: ast.Call, rule: Rule, filename: str) -> Finding:
    """Build a finding record for a matched blocking call."""
    return Finding(
        file=filename,
        line=node.lineno,
        col=node.col_offset + 1,
        rule_id=rule.rule_id,
        message=rule.message,
        suggestion=rule.suggestion,
        severity=rule.severity,
    )


def analyze_source(
    source: str,
    *,
    filename: str = "<string>",
    rules: tuple[Rule, ...] | None = None,
) -> list[Finding]:
    """Analyze Python source text and return findings for blocking calls in async code."""
    active_rules = rules if rules is not None else RULES

    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError:
        return []

    visitor = _AsyncBlockingVisitor(filename, active_rules)
    visitor.visit(tree)
    return _apply_suppressions(visitor.findings, _parse_suppressions(source))


def analyze_file(path: str | Path, rules: tuple[Rule, ...] | None = None) -> list[Finding]:
    """Analyze a single Python file and return findings for blocking calls in async code."""
    source_path = Path(path)
    source = _read_text(source_path)
    if source is None:
        return []

    return analyze_source(source, filename=str(source_path), rules=rules)


def _parse_ignore_file(path: Path) -> list[str]:
    """Parse glob patterns from a ``.asyncblockignore`` file."""
    content = _read_text(path)
    if content is None:
        return []

    patterns: list[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            patterns.append(stripped)
    return patterns


def load_ignore_patterns(root: str | Path) -> list[str]:
    """Load exclude globs from ``.asyncblockignore`` files along the path to root."""
    root_path = Path(root).resolve()
    directory = root_path.parent if root_path.is_file() else root_path

    patterns: list[str] = []
    for path in (directory, *directory.parents):
        ignore_file = path / ".asyncblockignore"
        if ignore_file.is_file():
            patterns.extend(_parse_ignore_file(ignore_file))
    return patterns


def _matches_glob_patterns(relative_path: str, patterns: list[str]) -> bool:
    normalized_path = relative_path.replace("\\", "/")
    return any(fnmatch.fnmatch(normalized_path, pattern) for pattern in patterns)


def _should_scan_file(
    relative_path: str,
    *,
    include_patterns: list[str],
    exclude_patterns: list[str],
) -> bool:
    if exclude_patterns and _matches_glob_patterns(relative_path, exclude_patterns):
        return False
    return not include_patterns or _matches_glob_patterns(relative_path, include_patterns)


def _collect_python_files(root_path: Path) -> list[tuple[Path, str]]:
    """Return ``(absolute_path, relative_path)`` pairs for scannable Python files."""
    if root_path.is_file():
        if root_path.suffix != ".py":
            return []
        return [(root_path, root_path.name)]

    return [
        (file_path, str(file_path.relative_to(root_path)))
        for file_path in sorted(root_path.rglob("*.py"))
    ]


def summarize_findings(findings: list[Finding]) -> ScanSummary:
    """Aggregate finding counts by file and rule."""
    files = {finding.file for finding in findings}
    by_rule = Counter(finding.rule_id for finding in findings)
    by_severity = Counter(finding.severity for finding in findings)

    ranked_rules = tuple(sorted(by_rule.items(), key=lambda item: (-item[1], item[0])))
    return ScanSummary(
        total=len(findings),
        files=len(files),
        errors=by_severity["error"],
        warnings=by_severity["warning"],
        by_rule=ranked_rules,
    )


def filter_findings(
    findings: list[Finding],
    *,
    min_severity: Severity = "warning",
    rule_ids: list[str] | None = None,
) -> list[Finding]:
    """Return findings that meet the minimum severity and optional rule filter."""
    allowed_rule_ids = set(rule_ids) if rule_ids else None
    return [
        finding
        for finding in findings
        if meets_min_severity(finding.severity, min_severity)
        and (allowed_rule_ids is None or finding.rule_id in allowed_rule_ids)
    ]


def analyze_tree(
    root: str | Path,
    *,
    exclude: list[str] | None = None,
    include: list[str] | None = None,
    min_severity: Severity = "warning",
    rule_ids: list[str] | None = None,
) -> list[Finding]:
    """Recursively analyze Python files under *root* and return aggregated findings."""
    root_path = Path(root)
    exclude_patterns = [*(exclude or []), *load_ignore_patterns(root_path)]
    include_patterns = include or []
    findings: list[Finding] = []

    for file_path, relative_path in _collect_python_files(root_path):
        if not _should_scan_file(
            relative_path,
            include_patterns=include_patterns,
            exclude_patterns=exclude_patterns,
        ):
            continue
        findings.extend(analyze_file(file_path))

    return filter_findings(findings, min_severity=min_severity, rule_ids=rule_ids)
