"""
auth_middleware.py — Full authentication middleware.

This file provides the CONTEXT that explains why token_service.py
decodes JWT without verification. The call graph should find this file
and show the LLM that validate_with_provider() does the real verification.
"""

import jwt
import requests
from flask import request, g, jsonify

from services.token_service import extract_token_claims, get_token_from_request, lookup_org_config


AUTH_PROVIDERS = {
    "okta": "https://{domain}/oauth2/v1/introspect",
    "auth0": "https://{domain}/userinfo",
    "azure": "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
}


def authenticate():
    """Full auth flow:
    1. Extract token (token_service)
    2. Pre-parse claims WITHOUT verification (token_service) — to get org_id
    3. Look up which auth provider this org uses
    4. Verify the token with the ACTUAL provider (this function)
    """
    token = get_token_from_request()
    if not token:
        return jsonify({"error": "No token provided"}), 401

    claims = extract_token_claims(token)

    org_config = lookup_org_config(claims["org_id"])
    if not org_config:
        return jsonify({"error": "Unknown organization"}), 403

    verified_claims = validate_with_provider(
        token=token,
        provider=org_config["provider"],
        domain=org_config["domain"],
        client_id=org_config["client_id"],
        client_secret=org_config["client_secret"],
    )

    if not verified_claims:
        return jsonify({"error": "Token verification failed"}), 401

    g.user = verified_claims
    g.org_id = claims["org_id"]
    return None


def validate_with_provider(
    token: str,
    provider: str,
    domain: str,
    client_id: str,
    client_secret: str,
) -> dict | None:
    """Verify the JWT with the org's actual identity provider.

    THIS is where real verification happens — not in token_service.
    """
    url_template = AUTH_PROVIDERS.get(provider)
    if not url_template:
        return None

    if provider == "okta":
        url = url_template.format(domain=domain)
        resp = requests.post(url, data={
            "token": token,
            "token_type_hint": "access_token",
            "client_id": client_id,
            "client_secret": client_secret,
        })
        if resp.status_code == 200 and resp.json().get("active"):
            return resp.json()

    elif provider == "auth0":
        url = url_template.format(domain=domain)
        resp = requests.get(url, headers={"Authorization": f"Bearer {token}"})
        if resp.status_code == 200:
            return resp.json()

    elif provider == "azure":
        jwks_url = f"https://login.microsoftonline.com/{domain}/discovery/v2.0/keys"
        jwks = requests.get(jwks_url).json()
        try:
            return jwt.decode(
                token,
                jwt.PyJWKClient(jwks_url).get_signing_key_from_jwt(token).key,
                algorithms=["RS256"],
                audience=client_id,
            )
        except jwt.InvalidTokenError:
            return None

    return None
