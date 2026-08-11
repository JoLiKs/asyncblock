"""AST-based analyzer for blocking calls inside async contexts."""

from __future__ import annotations

import ast
import fnmatch
from pathlib import Path

from asyncblock.models import Finding, Severity
from asyncblock.rules import RULES, Rule


def _module_root(qualified_name: str) -> str:
    """Return the top-level package from a dotted import path."""
    return qualified_name.split(".", maxsplit=1)[0]


class _ImportMap:
    """Tracks import aliases for resolving call targets."""

    def __init__(self) -> None:
        self.module_aliases: dict[str, str] = {}
        self.imported_symbols: dict[str, tuple[str, str]] = {}

    def collect_from(self, node: ast.AST) -> None:
        for child in ast.walk(node):
            if isinstance(child, ast.Import):
                for alias in child.names:
                    local = alias.asname or _module_root(alias.name)
                    self.module_aliases[local] = _module_root(alias.name)
            elif isinstance(child, ast.ImportFrom) and child.module:
                module = _module_root(child.module)
                for alias in child.names:
                    if alias.name == "*":
                        continue
                    local = alias.asname or alias.name
                    self.imported_symbols[local] = (module, alias.name)


class _AsyncBlockingVisitor(ast.NodeVisitor):
    """Walks AST and collects blocking calls inside async contexts."""

    def __init__(self, source_path: str, rules: tuple[Rule, ...]) -> None:
        self.source_path = source_path
        self.rules = rules
        self.findings: list[Finding] = []
        self.imports = _ImportMap()
        self._async_depth = 0
        self._nested_sync_depth = 0

    def visit_Module(self, node: ast.Module) -> None:
        self.imports.collect_from(node)
        self.generic_visit(node)

    @property
    def _in_async_context(self) -> bool:
        return self._async_depth > 0 or self._nested_sync_depth > 0

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._async_depth += 1
        self.generic_visit(node)
        self._async_depth -= 1

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        inside_async = self._async_depth > 0
        if inside_async:
            self._nested_sync_depth += 1
        self.generic_visit(node)
        if inside_async:
            self._nested_sync_depth -= 1

    def visit_Call(self, node: ast.Call) -> None:
        if self._in_async_context:
            rule = _match_call(node.func, self.imports, self.rules)
            if rule is not None:
                self.findings.append(_finding_from_call(node, rule, self.source_path))
        self.generic_visit(node)


def _match_call(
    func: ast.expr,
    imports: _ImportMap,
    rules: tuple[Rule, ...],
) -> Rule | None:
    """Return the first rule matching the given call expression."""
    if isinstance(func, ast.Name):
        for rule in rules:
            if rule.builtin and func.id == rule.builtin:
                return rule
        if func.id in imports.imported_symbols:
            module, attr = imports.imported_symbols[func.id]
            return _match_module_attr(module, attr, rules)
        return None

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


def _finding_from_call(node: ast.Call, rule: Rule, source_path: str) -> Finding:
    """Build a finding record for a matched blocking call."""
    return Finding(
        file=source_path,
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
    return visitor.findings


def analyze_file(path: str | Path, rules: tuple[Rule, ...] | None = None) -> list[Finding]:
    """Analyze a single Python file and return findings for blocking calls in async code."""
    source_path = Path(path)

    try:
        source = source_path.read_text(encoding="utf-8")
    except OSError:
        return []

    return analyze_source(source, filename=str(source_path), rules=rules)


def _normalize_relative_path(relative_path: str) -> str:
    return relative_path.replace("\\", "/")


def _matches_glob_patterns(relative_path: str, patterns: list[str]) -> bool:
    normalized = _normalize_relative_path(relative_path)
    return any(fnmatch.fnmatch(normalized, pattern) for pattern in patterns)


def _should_scan_file(
    relative_path: str,
    *,
    include_patterns: list[str],
    exclude_patterns: list[str],
) -> bool:
    if exclude_patterns and _matches_glob_patterns(relative_path, exclude_patterns):
        return False
    return not include_patterns or _matches_glob_patterns(relative_path, include_patterns)


def _iter_python_files(root_path: Path) -> list[tuple[Path, str]]:
    """Return ``(absolute_path, relative_path)`` pairs for scannable Python files."""
    if root_path.is_file():
        if root_path.suffix != ".py":
            return []
        return [(root_path, root_path.name)]

    return [
        (file_path, str(file_path.relative_to(root_path)))
        for file_path in sorted(root_path.rglob("*.py"))
    ]


def filter_findings(
    findings: list[Finding],
    *,
    min_severity: Severity = "warning",
    rule_ids: list[str] | None = None,
) -> list[Finding]:
    """Return findings that meet the minimum severity and optional rule filter."""
    return _filter_findings(findings, min_severity=min_severity, rule_ids=rule_ids)


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
    exclude_patterns = exclude or []
    include_patterns = include or []
    findings: list[Finding] = []

    for file_path, relative_path in _iter_python_files(root_path):
        if not _should_scan_file(
            relative_path,
            include_patterns=include_patterns,
            exclude_patterns=exclude_patterns,
        ):
            continue
        findings.extend(analyze_file(file_path))

    return _filter_findings(findings, min_severity=min_severity, rule_ids=rule_ids)


_SEVERITY_RANK: dict[Severity, int] = {"warning": 0, "error": 1}


def _meets_min_severity(severity: Severity, min_severity: Severity) -> bool:
    return _SEVERITY_RANK[severity] >= _SEVERITY_RANK[min_severity]


def _filter_findings(
    findings: list[Finding],
    *,
    min_severity: Severity,
    rule_ids: list[str] | None,
) -> list[Finding]:
    allowed_rule_ids = set(rule_ids) if rule_ids else None
    return [
        finding
        for finding in findings
        if _meets_min_severity(finding.severity, min_severity)
        and (allowed_rule_ids is None or finding.rule_id in allowed_rule_ids)
    ]
