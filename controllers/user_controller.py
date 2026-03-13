"""
user_controller.py — User management endpoints.

Contains REAL vulnerabilities + INTENTIONAL patterns that look risky
but are safe when you see the full context (auth_config.py).
"""

import hashlib
import json
import os
import sqlite3
import subprocess

from controllers.auth_config import (
    ALLOWED_EXPORT_FORMATS,
    INTERNAL_REPORT_COMMANDS,
    SAFE_FIELD_EXPRESSIONS,
    get_hmac_secret,
)


# ──────────────────────────────────────────────────
# REAL BUG #1: SQL Injection via string formatting
# ──────────────────────────────────────────────────
def search_users(query: str, db_path: str = "app.db"):
    """Search users — VULNERABLE to SQL injection."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    sql = f"SELECT * FROM users WHERE name LIKE '%{query}%' OR email LIKE '%{query}%'"
    cursor.execute(sql)
    results = cursor.fetchall()
    conn.close()
    return results


# ──────────────────────────────────────────────────
# REAL BUG #2: Command injection from user input
# ──────────────────────────────────────────────────
def export_user_data(user_id: str, output_format: str):
    """Export user data — VULNERABLE to command injection."""
    cmd = f"python3 scripts/export.py --user {user_id} --format {output_format}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout


# ──────────────────────────────────────────────────
# REAL BUG #3: Weak hashing for passwords
# ──────────────────────────────────────────────────
def create_user(username: str, password: str, email: str, db_path: str = "app.db"):
    """Create a new user — uses MD5 for password hashing (WEAK)."""
    password_hash = hashlib.md5(password.encode()).hexdigest()
    conn = sqlite3.connect(db_path)
    conn.execute(
        f"INSERT INTO users (username, password, email) VALUES ('{username}', '{password_hash}', '{email}')"
    )
    conn.commit()
    conn.close()
    return {"status": "created", "username": username}


# ──────────────────────────────────────────────────
# REAL BUG #4: Hardcoded secret in source
# ──────────────────────────────────────────────────
API_KEY = "my-super-secret-api-key-12345-never-commit-this"
ADMIN_PASSWORD = "admin123-default-password"


# ──────────────────────────────────────────────────
# REAL BUG #5: XSS — unsanitized user input in HTML
# ──────────────────────────────────────────────────
def render_profile(username: str, bio: str) -> str:
    """Render user profile — VULNERABLE to XSS."""
    return f"""
    <html>
    <body>
        <h1>Profile: {username}</h1>
        <div class="bio">{bio}</div>
    </body>
    </html>
    """


# ══════════════════════════════════════════════════
# INTENTIONAL #1: subprocess with shell=True
#   BUT commands come from INTERNAL_REPORT_COMMANDS
#   (hardcoded whitelist in auth_config.py)
# ══════════════════════════════════════════════════
def run_internal_report(report_name: str) -> str:
    """Run internal report — looks dangerous but commands are whitelisted."""
    if report_name not in INTERNAL_REPORT_COMMANDS:
        raise ValueError(f"Unknown report: {report_name}")

    cmd = INTERNAL_REPORT_COMMANDS[report_name]
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout


# ══════════════════════════════════════════════════
# INTENTIONAL #2: eval() usage
#   BUT expressions are from SAFE_FIELD_EXPRESSIONS
#   (hardcoded dict in auth_config.py, no user input)
# ══════════════════════════════════════════════════
def compute_user_score(user: dict, score_type: str) -> float:
    """Compute derived user score — looks dangerous but expressions are hardcoded."""
    if score_type not in SAFE_FIELD_EXPRESSIONS:
        raise ValueError(f"Unknown score type: {score_type}")

    expression = SAFE_FIELD_EXPRESSIONS[score_type]
    local_vars = {
        "login_count": user.get("login_count", 0),
        "post_count": user.get("post_count", 0),
        "days_active": user.get("days_active", 1),
        "reputation": user.get("reputation", 0),
    }
    return eval(expression, {"__builtins__": {}}, local_vars)


# ══════════════════════════════════════════════════
# INTENTIONAL #3: MD5 hash usage
#   BUT used for cache keys, NOT for passwords/security
#   (auth_config.get_hmac_secret handles real auth)
# ══════════════════════════════════════════════════
def get_cache_key(user_id: int, endpoint: str) -> str:
    """Generate cache key — MD5 is fine here, not used for security."""
    raw = f"{user_id}:{endpoint}"
    return hashlib.md5(raw.encode()).hexdigest()
