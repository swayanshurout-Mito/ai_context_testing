"""
context_builder.py — Builds rich context bundles for ALL findings.

Every finding gets deep context (call graph + embeddings) so the LLM
can decide whether the flagged code is an actual bug or an intentional
pattern that should be left alone.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from call_graph import build_call_graph, CallGraphResult
from embedder import CodeChunk, SearchResult, search_for_finding


@dataclass
class ContextBundle:
    mode: str
    vulnerable_code: str
    imports: str
    call_graph_summary: str
    related_code: str
    full_prompt_context: str
    token_estimate: int


def classify_finding(rule_id: str, message: str) -> str:
    """All findings go through deep context."""
    return "deep"


def _read_file_lines(file_path: str, repo_root: str) -> list[str]:
    abs_path = os.path.join(repo_root, file_path)
    try:
        with open(abs_path, encoding="utf-8", errors="replace") as f:
            return f.readlines()
    except FileNotFoundError:
        return []


def _extract_vulnerable_block(
    lines: list[str],
    start_line: int,
    end_line: int,
    padding: int = 5,
) -> str:
    """Extract the vulnerable code with some surrounding context."""
    begin = max(0, start_line - 1 - padding)
    end = min(len(lines), end_line + padding)
    block = []
    for i in range(begin, end):
        marker = ">>>" if start_line - 1 <= i < end_line else "   "
        block.append(f"{marker} {i + 1:4d} | {lines[i].rstrip()}")
    return "\n".join(block)


def _extract_imports(lines: list[str], file_path: str) -> str:
    """Extract import statements from the file."""
    imports = []
    for line in lines[:50]:
        stripped = line.strip()
        if re.match(r"^(import |from .+ import |require\(|const .+ = require|use |#include)", stripped):
            imports.append(stripped)
    return "\n".join(imports) if imports else "(no imports found)"


def _format_call_graph(cg: CallGraphResult) -> str:
    """Format call graph into readable text."""
    parts = []
    parts.append(f"Function: {cg.function_name} in {cg.file_path}")

    if cg.callees:
        parts.append(f"\nCalls these functions: {', '.join(cg.callees[:15])}")

    if cg.callers:
        parts.append(f"\nCalled by ({len(cg.callers)} locations):")
        for c in cg.callers[:8]:
            parts.append(f"  - {c.file_path}:{c.line} in {c.function_name}")
            parts.append(f"    {c.snippet}")

    if cg.related_definitions:
        parts.append(f"\nRelated definitions:")
        for d in cg.related_definitions[:10]:
            parts.append(f"  - {d}")

    return "\n".join(parts)


def _format_related_code(results: list[SearchResult]) -> str:
    """Format embedding search results into readable context."""
    if not results:
        return "(no related code found via semantic search)"

    parts = []
    for i, r in enumerate(results, 1):
        parts.append(
            f"--- Related Code #{i} (similarity: {r.score:.3f}) ---\n"
            f"File: {r.chunk.file_path} (lines {r.chunk.start_line}-{r.chunk.end_line})\n"
            f"{r.chunk.content[:1500]}\n"
        )
    return "\n".join(parts)


def build_deep_context(
    finding: dict,
    repo_root: str,
    embedded_chunks: list[CodeChunk],
    api_key: str,
) -> ContextBundle:
    """Build rich context for logic findings (deep track).

    Includes: vulnerable code + imports + call graph + semantic search results.
    """
    file_path = finding.get("path", "")
    start_line = finding.get("start", {}).get("line", 0)
    end_line = finding.get("end", {}).get("line", 0)
    message = finding.get("extra", {}).get("message", "")

    lines = _read_file_lines(file_path, repo_root)
    vuln_code = _extract_vulnerable_block(lines, start_line, end_line, padding=10)
    imports = _extract_imports(lines, file_path)

    cg = build_call_graph(file_path, start_line, repo_root)
    cg_summary = _format_call_graph(cg)

    source_code = "".join(lines[max(0, start_line - 5):end_line + 5])
    related_results = search_for_finding(
        finding_description=message,
        finding_file=file_path,
        finding_code=source_code,
        chunks=embedded_chunks,
        api_key=api_key,
        top_k=5,
    )
    related_code = _format_related_code(related_results)

    prompt = (
        f"FILE: {file_path}\n\n"
        f"IMPORTS:\n{imports}\n\n"
        f"VULNERABLE CODE (with surrounding context):\n{vuln_code}\n\n"
        f"CALL GRAPH:\n{cg_summary}\n\n"
        f"RELATED CODE FROM CODEBASE:\n{related_code}\n"
    )

    if len(prompt) > 16000:
        prompt = prompt[:16000] + "\n... (truncated for token limit)"

    return ContextBundle(
        mode="deep",
        vulnerable_code=vuln_code,
        imports=imports,
        call_graph_summary=cg_summary,
        related_code=related_code,
        full_prompt_context=prompt,
        token_estimate=len(prompt) // 4,
    )
