"""
semgrep_test_bad.py — Intentionally vulnerable code for CI / AI Security Review testing.
Do not use in production. Add this file via PR to trigger Semgrep + AI fix suggestions.
"""

import hashlib
import sqlite3
import subprocess
from flask import request


# ── Hardcoded secret (Semgrep: generic hardcoded secret / flask secret)
SECRET_KEY = "dev-secret-key-change-in-production-12345"
API_KEY = "test-api-key-do-not-commit"


# ── SQL injection (Semgrep: sql-injection / formatted query)
def get_user_by_id(user_id: str):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()


def search_by_name(name: str):
    conn = sqlite3.connect("app.db")
    return conn.execute(f"SELECT * FROM users WHERE name LIKE '%{name}%'").fetchall()


# ── Command injection (Semgrep: subprocess-shell-true / command-injection)
def run_report(report_name: str):
    cmd = f"python3 scripts/report.py --name {report_name}"
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


# ── Weak crypto (Semgrep: weak hash / md5)
def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


# ── XSS (Semgrep: reflected XSS — unsanitized user input in response)
def render_greeting():
    name = request.args.get("name", "Guest")
    return f"<html><body><h1>Hello, {name}!</h1></body></html>"
