#!/usr/bin/env python3
"""
ai_sec_review.py — Context-aware CI reviewer.

ALL findings get deep context (call graph + embeddings).
The LLM decides whether to fix or skip based on the full picture.

Usage (called by GitHub Action):
    python3 .github/scripts/ai_sec_review.py semgrep_results.json

Environment variables:
    OPENAI_API_KEY   — required
    GITHUB_TOKEN     — auto-provided by GitHub Actions
    PR_NUMBER        — set by workflow for PR events
    SCAN_MODE        — "pr" or "push"
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

from openai import OpenAI

from context_builder import ContextBundle, build_deep_context
from embedder import collect_chunks, embed_chunks, CodeChunk

# ── Config ────────────────────────────────────────────────────────────

MAX_FINDINGS = 30
MAX_RETRIES = 2
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
OPENAI_MAX_TOKENS = 3000
OPENAI_TEMPERATURE = 0.1

SEVERITY_EMOJI = {"ERROR": "🔴", "WARNING": "🟡", "INFO": "🔵"}
SEVERITY_LABEL = {"ERROR": "High", "WARNING": "Medium", "INFO": "Low"}

SYSTEM_PROMPT = """\
You are a context-aware code security reviewer running in CI.
You receive the flagged code AND its full context: call graph, related code, imports.

CRITICAL RULES:
1. FIRST analyze the call graph and related code to understand WHY the flagged
   code is written this way. Look at who calls this function and what it calls.
2. If the context shows the pattern is INTENTIONAL and SAFE, respond with
   exactly: INTENTIONAL_SKIP: <one-line reason>
   Examples of intentional patterns:
   - JWT decoded without verification because a downstream function does the real verification
   - Dynamic import validated against a whitelist before execution
   - subprocess with shell=True but commands come from a hardcoded internal set
   - pickle used for IPC over Unix sockets, not user input
   - yaml.load with custom tag constructors for internal config, not user input
3. If the code IS a real vulnerability (e.g., user input flows into SQL, eval,
   subprocess, pickle, etc. with NO upstream validation), provide the fix.
4. When fixing: return ONLY the fixed code — no markdown fences, no explanation.
5. Preserve exact indentation, style, and function signatures.
6. The output must be a drop-in replacement for the vulnerable lines.
7. Do NOT refactor, rename, or change unrelated code.
"""

USER_TEMPLATE = """\
VULNERABILITY
  Type     : {vuln_type}
  Severity : {severity}
  CWE      : {cwe}
  File     : {file_path}
  Lines    : {start_line}–{end_line}

DESCRIPTION
{message}

FULL CONTEXT (call graph + related code from codebase):
{context}

INSTRUCTIONS:
- Study the CALL GRAPH to see who calls this function and what it calls.
- Study the RELATED CODE to understand if this pattern is intentional.
- If the pattern is justified by context, respond: INTENTIONAL_SKIP: <reason>
- If it's a real bug, return ONLY the patched code.
"""

# ── Helpers ───────────────────────────────────────────────────────────

def load_findings(json_path: str) -> list[dict]:
    with open(json_path, encoding="utf-8") as f:
        data = json.load(f)
    results = data.get("results", [])
    results.sort(key=lambda r: (
        {"ERROR": 0, "WARNING": 1, "INFO": 2}.get(
            r.get("extra", {}).get("severity", "INFO").upper(), 3
        ),
        r.get("path", ""),
        r.get("start", {}).get("line", 0),
    ))
    return results[:MAX_FINDINGS]


def read_source_lines(file_path: str, start: int, end: int) -> str:
    try:
        with open(file_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        return "".join(lines[start - 1 : end])
    except FileNotFoundError:
        return ""


def get_vuln_type(rule_id: str) -> str:
    parts = rule_id.split(".")
    return parts[-1].replace("-", " ").title() if parts else rule_id


INTENTIONAL_SKIP_PREFIX = "INTENTIONAL_SKIP:"


def generate_fix(
    finding: dict,
    context: ContextBundle,
) -> tuple[str | None, bool]:
    """Returns (fix_text, was_intentional_skip).

    If the LLM decides the pattern is intentional, fix_text is None and
    was_intentional_skip is True (with the reason).
    """
    api_key = os.getenv("OPENAI_API_KEY", "")
    if not api_key:
        print("  [!] OPENAI_API_KEY not set — skipping")
        return None, False

    extra = finding.get("extra", {})
    meta = extra.get("metadata", {})
    cwes = meta.get("cwe", [])
    if isinstance(cwes, str):
        cwes = [cwes]

    prompt = USER_TEMPLATE.format(
        vuln_type=get_vuln_type(finding.get("check_id", "")),
        severity=extra.get("severity", "UNKNOWN"),
        cwe=", ".join(cwes) or "N/A",
        file_path=finding.get("path", ""),
        start_line=finding.get("start", {}).get("line", 0),
        end_line=finding.get("end", {}).get("line", 0),
        message=extra.get("message", ""),
        context=context.full_prompt_context,
    )

    client = OpenAI(api_key=api_key)

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = client.chat.completions.create(
                model=OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=OPENAI_MAX_TOKENS,
                temperature=OPENAI_TEMPERATURE,
            )
            raw = resp.choices[0].message.content or ""
            stripped = raw.strip()

            if stripped.upper().startswith(INTENTIONAL_SKIP_PREFIX.upper()):
                reason = stripped[len(INTENTIONAL_SKIP_PREFIX):].strip()
                return reason, True

            lines = stripped.splitlines()
            if lines and lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            patched = "\n".join(lines)
            if patched.strip():
                return patched, False
        except Exception as e:
            print(f"  [!] LLM attempt {attempt} failed: {e}")
            if attempt < MAX_RETRIES:
                time.sleep(2 ** attempt)

    return None, False


def post_pr_review(
    owner: str, repo: str, pr_number: int,
    commit_sha: str, comments: list[dict], summary: str,
) -> bool:
    review_body = {
        "commit_id": commit_sha,
        "body": summary,
        "event": "COMMENT",
        "comments": comments,
    }

    cmd = [
        "gh", "api", "-X", "POST",
        f"/repos/{owner}/{repo}/pulls/{pr_number}/reviews",
        "--input", "-",
    ]

    result = subprocess.run(
        cmd, input=json.dumps(review_body),
        capture_output=True, text=True,
    )

    if result.returncode != 0:
        print(f"  [!] Review post failed: {result.stderr[:300]}")
        return False

    print(f"  [+] Posted review with {len(comments)} suggestion(s)")
    return True


def post_push_comment(owner: str, repo: str, sha: str, body: str) -> bool:
    cmd = [
        "gh", "api", "-X", "POST",
        f"/repos/{owner}/{repo}/commits/{sha}/comments",
        "--input", "-",
    ]
    result = subprocess.run(
        cmd, input=json.dumps({"body": body}),
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"  [!] Commit comment failed: {result.stderr[:200]}")
        return False
    return True


def build_suggestion_body(
    finding: dict,
    fix: str | None,
    context: ContextBundle,
    was_intentional: bool = False,
    skip_reason: str = "",
) -> str:
    extra = finding.get("extra", {})
    meta = extra.get("metadata", {})
    severity = extra.get("severity", "UNKNOWN").upper()
    emoji = SEVERITY_EMOJI.get(severity, "⚪")
    rule_id = finding.get("check_id", "unknown")
    short_rule = rule_id.rsplit(".", 1)[-1]

    cwes = meta.get("cwe", [])
    if isinstance(cwes, str):
        cwes = [cwes]

    message = extra.get("message", "")
    if len(message) > 300:
        message = message[:297] + "..."

    body = f"### {emoji} {short_rule}\n\n"
    body += f"**Track:** 🧠 Context-aware (deep)\n"
    body += f"**Severity:** {SEVERITY_LABEL.get(severity, severity)} | "
    body += f"**CWE:** {', '.join(cwes) or 'N/A'}\n\n"
    body += f"{message}\n\n"

    body += "<details><summary>📊 Context used for this analysis</summary>\n\n"
    body += f"**Call Graph:**\n```\n{context.call_graph_summary[:800]}\n```\n\n"
    if context.related_code and "no related code" not in context.related_code:
        related_count = len([l for l in context.related_code.split("---") if l.strip()])
        body += f"**Related Code Found:** {related_count} chunks\n"
    body += f"\n**Context tokens:** ~{context.token_estimate}\n"
    body += "</details>\n\n"

    if was_intentional:
        body += f"✅ **Intentional pattern — no fix needed**\n\n"
        body += f"> {skip_reason}\n\n"
        body += "*The LLM analysed the call graph and related code and determined this "
        body += "is an intentional design pattern, not a vulnerability.*\n"
    elif fix:
        body += "**Suggested fix:**\n"
        body += f"```suggestion\n{fix}\n```\n"
    else:
        body += "⚠️ *Could not auto-generate a fix. Manual review required.*\n"

    refs = meta.get("references", [])
    if isinstance(refs, str):
        refs = [refs]
    if refs:
        body += "\n**References:** " + " | ".join(f"[link]({r})" for r in refs[:3])

    return body


# ── Main ──────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 ai_sec_review.py <semgrep_results.json>")
        sys.exit(1)

    json_path = sys.argv[1]
    findings = load_findings(json_path)

    if not findings:
        print("[*] No findings to process.")
        sys.exit(0)

    api_key = os.getenv("OPENAI_API_KEY", "")
    mode = os.getenv("SCAN_MODE", "push")
    pr_number = os.getenv("PR_NUMBER", "")
    repo_full = os.getenv("GITHUB_REPOSITORY", "")
    commit_sha = os.getenv("GITHUB_SHA", "")
    owner, repo = repo_full.split("/") if "/" in repo_full else ("", "")
    repo_root = os.getcwd()

    print(f"[*] {len(findings)} findings — ALL go through deep context (call graph + embeddings)")

    # Pre-compute embeddings for all findings
    embedded_chunks: list[CodeChunk] = []
    if findings and api_key:
        print("[*] Building code embeddings for deep context...")
        changed_files = list({f.get("path", "") for f in findings})
        chunks = collect_chunks(repo_root, focus_files=changed_files)
        print(f"  Collected {len(chunks)} chunks from {len(set(c.file_path for c in chunks))} files")
        embedded_chunks = embed_chunks(chunks, api_key)
        print(f"  Embedded {len(embedded_chunks)} chunks")

    stats = {"total": len(findings), "fixed": 0, "intentional": 0, "failed": 0}
    review_comments = []
    summary_lines = []

    for i, finding in enumerate(findings, 1):
        extra = finding.get("extra", {})
        severity = extra.get("severity", "UNKNOWN").upper()
        rule_id = finding.get("check_id", "")
        file_path = finding.get("path", "")
        start_line = finding.get("start", {}).get("line", 0)
        end_line = finding.get("end", {}).get("line", 0)
        short_rule = rule_id.rsplit(".", 1)[-1]

        emoji = SEVERITY_EMOJI.get(severity, "⚪")
        print(f"\n[{i}/{len(findings)}] {emoji} 🧠 {short_rule}  "
              f"{file_path}:{start_line}-{end_line}")

        context = build_deep_context(
            finding, repo_root, embedded_chunks, api_key,
        )
        print(f"  [deep] Context: ~{context.token_estimate} tokens "
              f"(call graph + {len(embedded_chunks)} embedded chunks)")

        source = read_source_lines(file_path, start_line, end_line)
        if not source.strip():
            source = extra.get("lines", "")
        if not source.strip():
            print("  [!] No source available — skipping")
            summary_lines.append(
                f"| {emoji} | 🧠 | `{short_rule}` | `{file_path}:{start_line}` | ⏭️ Skipped |"
            )
            continue

        print("  [*] Generating context-aware AI analysis...")
        fix_or_reason, was_intentional = generate_fix(finding, context)

        if was_intentional:
            stats["intentional"] += 1
            print(f"  [=] INTENTIONAL SKIP: {fix_or_reason}")
            status = "✅ Intentional"
        elif fix_or_reason:
            stats["fixed"] += 1
            print(f"  [+] Fix generated ({len(fix_or_reason)} chars)")
            status = "🔧 Fix suggested"
        else:
            stats["failed"] += 1
            print("  [-] No fix generated")
            status = "⚠️ Manual"

        summary_lines.append(
            f"| {emoji} | 🧠 | `{short_rule}` | `{file_path}:{start_line}` | {status} |"
        )

        if mode == "pr" and pr_number:
            comment_body = build_suggestion_body(
                finding,
                fix=fix_or_reason if not was_intentional else None,
                context=context,
                was_intentional=was_intentional,
                skip_reason=fix_or_reason if was_intentional else "",
            )

            if start_line == end_line:
                review_comments.append({
                    "path": file_path,
                    "line": end_line,
                    "side": "RIGHT",
                    "body": comment_body,
                })
            else:
                review_comments.append({
                    "path": file_path,
                    "start_line": start_line,
                    "line": end_line,
                    "start_side": "RIGHT",
                    "side": "RIGHT",
                    "body": comment_body,
                })

    # Build summary
    summary = "## 🛡️ AI Context-Aware Security Review\n\n"
    summary += f"**{stats['total']}** finding(s) scanned — ALL with deep context (call graph + embeddings)\n\n"
    summary += f"- 🔧 **{stats['fixed']}** fix suggestions\n"
    summary += f"- ✅ **{stats['intentional']}** marked as intentional (no fix needed)\n"
    summary += f"- ⚠️ **{stats['failed']}** need manual review\n\n"
    summary += "| Sev | Track | Rule | Location | Status |\n"
    summary += "|-----|-------|------|----------|--------|\n"
    summary += "\n".join(summary_lines) + "\n"
    summary += f"\n*Model: {OPENAI_MODEL} · "
    summary += f"Deep context for all {stats['total']} finding(s) · "
    summary += f"Max {MAX_FINDINGS}*"

    print(f"\n{'='*60}")
    print(f"  Fixed: {stats['fixed']}  Intentional: {stats['intentional']}  "
          f"Manual: {stats['failed']}")
    print(f"{'='*60}")

    if mode == "pr" and pr_number and owner and repo:
        pr_info_cmd = ["gh", "api", f"/repos/{owner}/{repo}/pulls/{pr_number}"]
        pr_result = subprocess.run(pr_info_cmd, capture_output=True, text=True)
        head_sha = commit_sha
        if pr_result.returncode == 0:
            try:
                head_sha = json.loads(pr_result.stdout).get("head", {}).get("sha", commit_sha)
            except json.JSONDecodeError:
                pass

        if review_comments:
            post_pr_review(owner, repo, int(pr_number), head_sha, review_comments, summary)
        else:
            cmd = [
                "gh", "api", "-X", "POST",
                f"/repos/{owner}/{repo}/issues/{pr_number}/comments",
                "--input", "-",
            ]
            subprocess.run(cmd, input=json.dumps({"body": summary}),
                           capture_output=True, text=True)
            print("  [+] Posted summary comment")

    elif mode == "push" and owner and repo and commit_sha:
        post_push_comment(owner, repo, commit_sha, summary)
        print("  [+] Posted commit comment")
    else:
        print("\n" + summary)


if __name__ == "__main__":
    main()
