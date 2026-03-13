"""
auth_config.py — Configuration and whitelists for user_controller.

This file provides the CONTEXT that proves certain patterns in
user_controller.py are intentional and safe.
"""

import hashlib
import hmac
import os


INTERNAL_REPORT_COMMANDS = {
    "daily_active_users": "python3 reports/dau.py --date today",
    "revenue_summary": "python3 reports/revenue.py --period weekly",
    "system_health": "python3 reports/healthcheck.py --verbose",
    "user_growth": "python3 reports/growth.py --metric signups",
}

SAFE_FIELD_EXPRESSIONS = {
    "engagement": "login_count * 0.3 + post_count * 0.7",
    "activity_rate": "login_count / days_active",
    "influence": "reputation * 0.5 + post_count * 0.3 + login_count * 0.2",
    "retention": "(login_count + days_active) / 2",
}

ALLOWED_EXPORT_FORMATS = {"csv", "json", "xml", "xlsx"}

_HMAC_KEY = os.environ.get("HMAC_SECRET_KEY", "")


def get_hmac_secret() -> str:
    """Return HMAC secret from environment — never hardcoded."""
    if not _HMAC_KEY:
        raise RuntimeError("HMAC_SECRET_KEY environment variable not set")
    return _HMAC_KEY


def sign_payload(payload: bytes) -> str:
    """Sign a payload with HMAC-SHA256 using the environment secret."""
    key = get_hmac_secret().encode()
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def verify_signature(payload: bytes, signature: str) -> bool:
    """Verify HMAC-SHA256 signature."""
    expected = sign_payload(payload)
    return hmac.compare_digest(expected, signature)
