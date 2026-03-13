"""
token_service.py — JWT token pre-parser.

Semgrep WILL flag: unverified-jwt-decode (jwt.decode with verify=False)

WITHOUT CONTEXT — LLM would:
  Add full signature verification with a secret key,
  breaking the flow because this service doesn't HAVE the signing key.

WITH CONTEXT — LLM should see (via call graph to auth_middleware.py):
  This is a PRE-PARSER. It extracts claims (org_id, user_id) so we can
  route the token to the correct external auth service. The REAL
  verification happens in auth_middleware.validate_with_provider().
  The fix should NOT add signature verification here.
"""

import jwt
import requests
from flask import request


# ┌─────────────────────────────────────────────────────┐
# │ Semgrep flags this: unverified-jwt-decode            │
# │ But it's INTENTIONAL — see auth_middleware.py         │
# └─────────────────────────────────────────────────────┘

def extract_token_claims(token: str) -> dict:
    """Pre-parse JWT to extract routing claims WITHOUT verification.

    We decode without verification because:
    1. We need org_id to determine WHICH auth provider to verify against
    2. Each org uses a different identity provider (Okta, Auth0, Azure AD)
    3. We don't have the signing key yet — the provider has it
    4. Full verification happens in auth_middleware.validate_with_provider()
    """
    claims = jwt.decode(token, options={"verify_signature": False})
    return {
        "org_id": claims.get("org"),
        "user_id": claims.get("sub"),
        "provider": claims.get("iss"),
        "roles": claims.get("roles", []),
    }


def get_token_from_request() -> str | None:
    """Extract bearer token from Authorization header."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return None


# ┌─────────────────────────────────────────────────────┐
# │ REAL BUG: SQL injection — this SHOULD be fixed       │
# └─────────────────────────────────────────────────────┘

def lookup_org_config(org_id: str) -> dict:
    """Fetch org auth configuration. HAS A REAL SQL INJECTION BUG."""
    import sqlite3
    conn = sqlite3.connect("auth.db")
    row = conn.execute(
        "SELECT * FROM org_configs WHERE org_id = '" + org_id + "'"
    ).fetchone()
    return dict(row) if row else {}
# trigger CI
