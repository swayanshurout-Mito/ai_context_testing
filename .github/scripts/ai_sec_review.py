#!/usr/bin/env python3
"""
ai_sec_review.py — CI script that reads Semgrep JSON results,
generates AI-powered fix suggestions, and posts them as inline
PR review comments (GitHub suggestion blocks).

On push (non-PR), posts a summary issue comment instead.

Usage (called by the GitHub Action):
    python3 .github/scripts/ai_sec_review.py semgrep_results.json

Environment variables:
    OPENAI_API_KEY   — required
    GITHUB_TOKEN     — auto-provided by GitHub Actions
    PR_NUMBER        — set by the workflow for PR events
    SCAN_MODE        — "pr" or "push"
    GITHUB_REPOSITORY, GITHUB_SHA — auto-set by Actions
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import time

from openai import OpenAI

# ── Config ────────────────────────────────────────────────────────────

MAX_FINDINGS = 25
MAX_RETRIES = 2
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
OPENAI_MAX_TOKENS = 2048
OPENAI_TEMPERATURE = 0.1

SEVERITY_EMOJI = {"ERROR": "🔴", "WARNING": "🟡", "INFO": "🔵"}
SEVERITY_LABEL = {"ERROR": "High", "WARNING": "Medium", "INFO": "Low"}

SYSTEM_PROMPT = """\
You are a secure-code remediation assistant running in CI.

RULES:
1. Fix ONLY the security vulnerability described.
2. Do NOT change business logic, calculations, or decision flows.
3. Do NOT add explanatory comments.
4. Do NOT refactor or rename.
5. Only add: validation, sanitization, encoding, safe APIs, config hardening.
6. Return ONLY the fixed code — no markdown fences, no explanation.
7. Preserve exact indentation and style.
8. The output must be a drop-in replacement for the input code.
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

VULNERABLE CODE (lines {start_line}–{end_line}):
```
{code}
```

Return ONLY the patched replacement code.
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


def generate_fix(finding: dict, source_code: str) -> str | None:
    api_key = os.getenv("OPENAI_API_KEY", "")
    if not api_key:
        print("  [!] OPENAI_API_KEY not set — skipping fix generation")
        return None

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
        code=source_code,
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
            lines = raw.strip().splitlines()
            if lines and lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            patched = "\n".join(lines)
            if patched.strip():
                return patched
        except Exception as e:
            print(f"  [!] LLM attempt {attempt} failed: {e}")
            if attempt < MAX_RETRIES:
                time.sleep(2 ** attempt)

    return None


def gh_api(method: str, endpoint: str, data: dict | None = None) -> dict | None:
    cmd = ["gh", "api", "-X", method, endpoint]
    if data:
        cmd += ["-f" if isinstance(v, str) else "-F" for k, v in data.items() for _ in [None]]
        input_json = json.dumps(data)
        cmd = ["gh", "api", "-X", method, endpoint, "--input", "-"]
        result = subprocess.run(cmd, input=input_json, capture_output=True, text=True)
    else:
        result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"  [!] gh api error: {result.stderr[:200]}")
        return None
    try:
        return json.loads(result.stdout) if result.stdout.strip() else {}
    except json.JSONDecodeError:
        return {}


def post_pr_review(
    owner: str,
    repo: str,
    pr_number: int,
    commit_sha: str,
    comments: list[dict],
    summary: str,
) -> bool:
    """Post a batch PR review with inline suggestions."""
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
    """Post a commit comment for push events (no PR)."""
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


def build_suggestion_body(finding: dict, fix: str | None) -> str:
    """Build the markdown body for a single inline comment."""
    extra = finding.get("extra", {})
    meta = extra.get("metadata", {})
    severity = extra.get("severity", "UNKNOWN").upper()
    emoji = SEVERITY_EMOJI.get(severity, "⚪")
    rule_id = finding.get("check_id", "unknown")
    short_rule = rule_id.rsplit(".", 1)[-1]

    cwes = meta.get("cwe", [])
    if isinstance(cwes, str):
        cwes = [cwes]
    cwe_str = ", ".join(cwes) or "N/A"

    message = extra.get("message", "")
    if len(message) > 300:
        message = message[:297] + "…"

    body = f"### {emoji} {short_rule}\n\n"
    body += f"**Severity:** {SEVERITY_LABEL.get(severity, severity)} | "
    body += f"**CWE:** {cwe_str}\n\n"
    body += f"{message}\n\n"

    if fix:
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

    mode = os.getenv("SCAN_MODE", "push")
    pr_number = os.getenv("PR_NUMBER", "")
    repo_full = os.getenv("GITHUB_REPOSITORY", "")
    commit_sha = os.getenv("GITHUB_SHA", "")

    owner, repo = repo_full.split("/") if "/" in repo_full else ("", "")

    print(f"[*] Processing {len(findings)} finding(s) [mode={mode}]")

    # Track stats
    stats = {"total": len(findings), "fixed": 0, "skipped": 0, "failed": 0}
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
        print(f"\n[{i}/{len(findings)}] {emoji} {short_rule}  {file_path}:{start_line}-{end_line}")

        source = read_source_lines(file_path, start_line, end_line)
        if not source.strip():
            source = extra.get("lines", "")

        if not source.strip():
            print("  [!] No source code available — skipping")
            stats["skipped"] += 1
            summary_lines.append(f"| {emoji} | `{short_rule}` | `{file_path}:{start_line}` | ⏭️ Skipped (no source) |")
            continue

        print("  [*] Generating AI fix…")
        fix = generate_fix(finding, source)

        if fix:
            stats["fixed"] += 1
            print(f"  [+] Fix generated ({len(fix)} chars)")
            status = "✅ Suggested"
        else:
            stats["failed"] += 1
            print("  [-] No fix generated")
            status = "⚠️ Manual review"

        summary_lines.append(f"| {emoji} | `{short_rule}` | `{file_path}:{start_line}` | {status} |")

        if mode == "pr" and pr_number:
            comment_body = build_suggestion_body(finding, fix)

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
    summary = "## 🛡️ AI Security Review\n\n"
    summary += f"**{stats['total']}** finding(s) scanned"
    summary += f" · **{stats['fixed']}** fix suggestions"
    summary += f" · **{stats['failed']}** need manual review"
    summary += f" · **{stats['skipped']}** skipped\n\n"
    summary += "| Sev | Rule | Location | Status |\n"
    summary += "|-----|------|----------|--------|\n"
    summary += "\n".join(summary_lines) + "\n"
    summary += f"\n*Model: {OPENAI_MODEL} · "
    summary += f"Scanned {stats['total']}/{MAX_FINDINGS} max findings*"

    print(f"\n{'='*60}")
    print(f"  Fixed: {stats['fixed']}  Manual: {stats['failed']}  Skipped: {stats['skipped']}")
    print(f"{'='*60}")

    if mode == "pr" and pr_number and owner and repo:
        # Get the latest commit SHA on the PR head
        pr_info = gh_api("GET", f"/repos/{owner}/{repo}/pulls/{pr_number}")
        head_sha = pr_info.get("head", {}).get("sha", commit_sha) if pr_info else commit_sha

        if review_comments:
            post_pr_review(owner, repo, int(pr_number), head_sha, review_comments, summary)
        else:
            # No inline comments, just post summary
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
