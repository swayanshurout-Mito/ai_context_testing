"""
call_graph.py — Lightweight call graph builder.

For a given function in a file, finds:
  1. What functions it CALLS (callees)
  2. What functions CALL it (callers) across the repo
  3. Import chain for the file

Uses AST for Python, regex for JS/TS/Go/Java/YAML.
Designed to run in CI with no external dependencies.
"""

from __future__ import annotations

import ast
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CallGraphResult:
    function_name: str
    file_path: str
    callees: list[str] = field(default_factory=list)
    callers: list[CallerInfo] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    related_definitions: list[str] = field(default_factory=list)


@dataclass
class CallerInfo:
    file_path: str
    function_name: str
    line: int
    snippet: str


SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx",
    ".go", ".java", ".rb", ".php",
    ".yml", ".yaml", ".tf", ".hcl",
}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", ".terraform", "vendor", ".tox",
}


def _should_scan(path: str) -> bool:
    p = Path(path)
    if any(skip in p.parts for skip in SKIP_DIRS):
        return False
    return p.suffix in SCAN_EXTENSIONS


def _extract_function_name_at_line(file_path: str, line_no: int) -> str | None:
    """Extract the function/method name at or near the given line."""
    try:
        with open(file_path, encoding="utf-8", errors="replace") as f:
            source = f.read()
    except (FileNotFoundError, PermissionError):
        return None

    if file_path.endswith(".py"):
        return _py_function_at_line(source, line_no)

    return _regex_function_at_line(source, line_no)


def _py_function_at_line(source: str, line_no: int) -> str | None:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return _regex_function_at_line(source, line_no)

    best = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.lineno <= line_no <= node.end_lineno:
                if best is None or node.lineno >= best.lineno:
                    best = node

    return best.name if best else None


_FUNC_PATTERNS = [
    re.compile(r"(?:async\s+)?(?:def|function)\s+(\w+)\s*\("),
    re.compile(r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(?"),
    re.compile(r"(?:public|private|protected)?\s*(?:static\s+)?(\w+)\s*\("),
    re.compile(r"func\s+(\w+)\s*\("),
]


def _regex_function_at_line(source: str, line_no: int) -> str | None:
    lines = source.splitlines()
    search_range = range(max(0, line_no - 10), min(len(lines), line_no + 1))

    for i in reversed(list(search_range)):
        for pat in _FUNC_PATTERNS:
            m = pat.search(lines[i])
            if m:
                return m.group(1)
    return None


def _py_extract_callees(source: str, func_name: str) -> list[str]:
    """Extract all function calls made inside the given function."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    func_node = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == func_name:
                func_node = node
                break

    if not func_node:
        return []

    callees = []
    for node in ast.walk(func_node):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                callees.append(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                callees.append(node.func.attr)

    return list(dict.fromkeys(callees))


def _py_extract_imports(source: str) -> list[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(f"import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            names = ", ".join(a.name for a in node.names)
            imports.append(f"from {module} import {names}")

    return imports


def _regex_extract_callees(source: str, func_name: str) -> list[str]:
    lines = source.splitlines()
    in_func = False
    depth = 0
    callees = []

    func_start = re.compile(
        rf"(?:def|function|func|const|let|var)\s+{re.escape(func_name)}\s*[\(=]"
    )
    call_pat = re.compile(r"\b(\w+)\s*\(")

    for line in lines:
        if func_start.search(line):
            in_func = True
            depth = 0

        if in_func:
            depth += line.count("{") + line.count("(") - line.count("}") - line.count(")")
            for m in call_pat.finditer(line):
                name = m.group(1)
                if name not in ("if", "for", "while", "return", "print",
                                "switch", "catch", "else", func_name):
                    callees.append(name)

            if depth <= 0 and in_func and len(callees) > 0:
                break

    return list(dict.fromkeys(callees))


def find_callers(func_name: str, repo_root: str, source_file: str) -> list[CallerInfo]:
    """Find all files/functions that call the given function name."""
    callers = []

    try:
        result = subprocess.run(
            ["grep", "-rn", "--include=*.py", "--include=*.js", "--include=*.ts",
             "--include=*.tsx", "--include=*.go", "--include=*.java",
             rf"\b{func_name}\s*(",
             repo_root],
            capture_output=True, text=True, timeout=30,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return callers

    for line in result.stdout.splitlines()[:50]:
        parts = line.split(":", 2)
        if len(parts) < 3:
            continue

        file_path, line_no_str, snippet = parts
        rel_path = os.path.relpath(file_path, repo_root)

        if rel_path == source_file:
            continue
        if any(skip in rel_path for skip in SKIP_DIRS):
            continue

        try:
            line_no = int(line_no_str)
        except ValueError:
            continue

        caller_func = _extract_function_name_at_line(file_path, line_no)

        callers.append(CallerInfo(
            file_path=rel_path,
            function_name=caller_func or "(module-level)",
            line=line_no,
            snippet=snippet.strip()[:200],
        ))

    return callers


def find_definitions(names: list[str], repo_root: str, exclude_file: str) -> list[str]:
    """Find definitions of given function/class names across the repo."""
    definitions = []

    for name in names[:15]:
        try:
            result = subprocess.run(
                ["grep", "-rn", "--include=*.py", "--include=*.js", "--include=*.ts",
                 rf"^\s*(?:def|class|function|const|let|var|func)\s+{name}\b",
                 repo_root],
                capture_output=True, text=True, timeout=10,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue

        for line in result.stdout.splitlines()[:3]:
            parts = line.split(":", 2)
            if len(parts) < 3:
                continue
            file_path = os.path.relpath(parts[0], repo_root)
            if file_path == exclude_file:
                continue
            definitions.append(f"{file_path}:{parts[1]}: {parts[2].strip()[:150]}")

    return definitions[:20]


def build_call_graph(
    file_path: str,
    line_no: int,
    repo_root: str,
) -> CallGraphResult:
    """Build a lightweight call graph for the function at the given location."""
    abs_path = os.path.join(repo_root, file_path)

    try:
        with open(abs_path, encoding="utf-8", errors="replace") as f:
            source = f.read()
    except FileNotFoundError:
        return CallGraphResult(function_name="?", file_path=file_path)

    func_name = _extract_function_name_at_line(abs_path, line_no)
    if not func_name:
        return CallGraphResult(function_name="?", file_path=file_path)

    if file_path.endswith(".py"):
        callees = _py_extract_callees(source, func_name)
        imports = _py_extract_imports(source)
    else:
        callees = _regex_extract_callees(source, func_name)
        imports = [l.strip() for l in source.splitlines()[:30]
                   if re.match(r"^\s*(import|from|require|use)\b", l)]

    callers = find_callers(func_name, repo_root, file_path)
    related = find_definitions(callees[:10], repo_root, file_path)

    return CallGraphResult(
        function_name=func_name,
        file_path=file_path,
        callees=callees,
        callers=callers,
        imports=imports,
        related_definitions=related,
    )
