"""
embedder.py — In-memory code embedder + vector search.

Uses OpenAI's text-embedding-3-small for embedding code chunks,
then cosine similarity for retrieval. No external vector DB needed —
everything runs in-memory during the CI job.

Flow:
  1. Chunk the repo's relevant files into blocks (~50-100 lines each)
  2. Embed each chunk via OpenAI embeddings API
  3. For a given query (vulnerability description), find top-K similar chunks
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
from openai import OpenAI

EMBEDDING_MODEL = "text-embedding-3-small"
CHUNK_SIZE_LINES = 60
CHUNK_OVERLAP_LINES = 10
MAX_CHUNKS = 500
MAX_FILES = 200
TOP_K = 5

SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx",
    ".go", ".java", ".rb", ".php",
    ".yml", ".yaml", ".tf", ".hcl",
    ".json", ".toml", ".cfg", ".ini",
}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", ".terraform", "vendor", ".tox",
    ".mypy_cache", ".pytest_cache", "egg-info",
}

SKIP_FILES = {"package-lock.json", "yarn.lock", "uv.lock", "poetry.lock"}


@dataclass
class CodeChunk:
    file_path: str
    start_line: int
    end_line: int
    content: str
    embedding: list[float] = field(default_factory=list)


@dataclass
class SearchResult:
    chunk: CodeChunk
    score: float


def _should_index(path: Path) -> bool:
    if path.name in SKIP_FILES:
        return False
    if any(skip in path.parts for skip in SKIP_DIRS):
        return False
    if path.suffix not in SCAN_EXTENSIONS:
        return False
    try:
        if path.stat().st_size > 500_000:
            return False
    except OSError:
        return False
    return True


def _chunk_file(file_path: str, repo_root: str) -> list[CodeChunk]:
    """Split a file into overlapping chunks."""
    abs_path = os.path.join(repo_root, file_path)
    try:
        with open(abs_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except (FileNotFoundError, PermissionError):
        return []

    if len(lines) <= CHUNK_SIZE_LINES:
        content = "".join(lines).strip()
        if content:
            return [CodeChunk(
                file_path=file_path,
                start_line=1,
                end_line=len(lines),
                content=content,
            )]
        return []

    chunks = []
    i = 0
    while i < len(lines):
        end = min(i + CHUNK_SIZE_LINES, len(lines))
        content = "".join(lines[i:end]).strip()
        if content:
            chunks.append(CodeChunk(
                file_path=file_path,
                start_line=i + 1,
                end_line=end,
                content=content,
            ))
        i += CHUNK_SIZE_LINES - CHUNK_OVERLAP_LINES

    return chunks


def collect_chunks(repo_root: str, focus_files: list[str] | None = None) -> list[CodeChunk]:
    """Collect code chunks from the repo.

    If focus_files is provided, chunks those first (guaranteed included),
    then fills remaining budget with other repo files.
    """
    chunks: list[CodeChunk] = []

    if focus_files:
        for fp in focus_files:
            chunks.extend(_chunk_file(fp, repo_root))

    file_count = 0
    for root, dirs, files in os.walk(repo_root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            if file_count >= MAX_FILES:
                break
            full = Path(root) / fname
            if not _should_index(full):
                continue
            rel = str(full.relative_to(repo_root))
            if focus_files and rel in focus_files:
                continue
            new_chunks = _chunk_file(rel, repo_root)
            chunks.extend(new_chunks)
            file_count += 1
            if len(chunks) >= MAX_CHUNKS:
                break
        if len(chunks) >= MAX_CHUNKS:
            break

    return chunks[:MAX_CHUNKS]


def embed_chunks(chunks: list[CodeChunk], api_key: str) -> list[CodeChunk]:
    """Embed all chunks using OpenAI embeddings API (batched)."""
    if not chunks:
        return chunks

    client = OpenAI(api_key=api_key)
    batch_size = 100

    for i in range(0, len(chunks), batch_size):
        batch = chunks[i:i + batch_size]
        texts = [
            f"# {c.file_path}:{c.start_line}-{c.end_line}\n{c.content[:2000]}"
            for c in batch
        ]

        try:
            resp = client.embeddings.create(
                model=EMBEDDING_MODEL,
                input=texts,
            )
            for j, item in enumerate(resp.data):
                batch[j].embedding = item.embedding
        except Exception as e:
            print(f"  [!] Embedding batch {i // batch_size} failed: {e}")

    return [c for c in chunks if c.embedding]


def search(
    query: str,
    chunks: list[CodeChunk],
    api_key: str,
    top_k: int = TOP_K,
    exclude_file: str | None = None,
) -> list[SearchResult]:
    """Find the top-K most relevant chunks for a query."""
    if not chunks:
        return []

    client = OpenAI(api_key=api_key)
    try:
        resp = client.embeddings.create(
            model=EMBEDDING_MODEL,
            input=[query],
        )
        query_emb = np.array(resp.data[0].embedding)
    except Exception as e:
        print(f"  [!] Query embedding failed: {e}")
        return []

    results = []
    for chunk in chunks:
        if not chunk.embedding:
            continue
        if exclude_file and chunk.file_path == exclude_file:
            continue

        chunk_emb = np.array(chunk.embedding)
        score = float(np.dot(query_emb, chunk_emb) / (
            np.linalg.norm(query_emb) * np.linalg.norm(chunk_emb) + 1e-10
        ))
        results.append(SearchResult(chunk=chunk, score=score))

    results.sort(key=lambda r: r.score, reverse=True)
    return results[:top_k]


def search_for_finding(
    finding_description: str,
    finding_file: str,
    finding_code: str,
    chunks: list[CodeChunk],
    api_key: str,
    top_k: int = TOP_K,
) -> list[SearchResult]:
    """Semantic search tailored for a vulnerability finding."""
    query = (
        f"Code related to: {finding_description}\n"
        f"In file: {finding_file}\n"
        f"Code:\n{finding_code[:500]}"
    )
    return search(query, chunks, api_key, top_k, exclude_file=finding_file)
