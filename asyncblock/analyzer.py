"""AST-based analyzer for blocking calls inside async contexts."""

from __future__ import annotations

import ast
import fnmatch
from pathlib import Path

from asyncblock.models import Finding, Severity
from asyncblock.rules import RULES, Rule


class _ImportMap:
    """Tracks import aliases for resolving call targets."""

    def __init__(self) -> None:
        self.module_aliases: dict[str, str] = {}
        self.imported_symbols: dict[str, tuple[str, str]] = {}

    def collect_from(self, node: ast.AST) -> None:
        for child in ast.walk(node):
            if isinstance(child, ast.Import):
                for alias in child.names:
                    local = alias.asname or alias.name.split(".")[0]
                    root = alias.name.split(".")[0]
                    self.module_aliases[local] = root
            elif isinstance(child, ast.ImportFrom) and child.module:
                for alias in child.names:
                    if alias.name == "*":
                        continue
                    local = alias.asname or alias.name
                    self.imported_symbols[local] = (child.module.split(".")[0], alias.name)


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
                self.findings.append(
                    Finding(
                        file=self.source_path,
                        line=node.lineno,
                        col=node.col_offset + 1,
                        rule_id=rule.rule_id,
                        message=rule.message,
                        suggestion=rule.suggestion,
                        severity=rule.severity,
                    )
                )
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


def analyze_file(path: str | Path, rules: tuple[Rule, ...] | None = None) -> list[Finding]:
    """Analyze a single Python file and return findings for blocking calls in async code."""
    source_path = Path(path)
    active_rules = rules if rules is not None else RULES

    try:
        source = source_path.read_text(encoding="utf-8")
    except OSError:
        return []

    try:
        tree = ast.parse(source, filename=str(source_path))
    except SyntaxError:
        return []

    visitor = _AsyncBlockingVisitor(str(source_path), active_rules)
    visitor.visit(tree)
    return visitor.findings


def _should_exclude(relative_path: str, exclude_patterns: list[str]) -> bool:
    normalized = relative_path.replace("\\", "/")
    return any(fnmatch.fnmatch(normalized, pattern) for pattern in exclude_patterns)


def analyze_tree(
    root: str | Path,
    *,
    exclude: list[str] | None = None,
    min_severity: Severity = "warning",
    rule_ids: list[str] | None = None,
) -> list[Finding]:
    """Recursively analyze Python files under *root* and return aggregated findings."""
    root_path = Path(root)
    exclude_patterns = exclude or []
    findings: list[Finding] = []

    if root_path.is_file():
        if root_path.suffix == ".py":
            findings.extend(analyze_file(root_path))
        return _filter_findings(findings, min_severity=min_severity, rule_ids=rule_ids)

    for file_path in sorted(root_path.rglob("*.py")):
        relative = str(file_path.relative_to(root_path))
        if _should_exclude(relative, exclude_patterns):
            continue
        findings.extend(analyze_file(file_path))

    return _filter_findings(findings, min_severity=min_severity, rule_ids=rule_ids)


def _filter_findings(
    findings: list[Finding],
    *,
    min_severity: Severity,
    rule_ids: list[str] | None,
) -> list[Finding]:
    result = findings
    if min_severity == "error":
        result = [finding for finding in result if finding.severity == "error"]
    if rule_ids:
        allowed = set(rule_ids)
        result = [finding for finding in result if finding.rule_id in allowed]
    return result
