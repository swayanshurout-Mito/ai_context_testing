"""
request_validator.py — Request validation middleware.

Contains REAL vulnerabilities + INTENTIONAL patterns that look risky
but are safe when you see the full context (sanitizer_config.py).
"""

import json
import os
import pickle
import re
import tempfile
import xml.etree.ElementTree as ET
import yaml

from middleware.sanitizer_config import (
    ALLOWED_CONTENT_TYPES,
    IPC_SOCKET_PATH,
    TRUSTED_YAML_TAGS,
    get_yaml_loader,
)


# ──────────────────────────────────────────────────
# REAL BUG #1: XML External Entity (XXE) attack
# ──────────────────────────────────────────────────
def parse_xml_request(xml_string: str) -> dict:
    """Parse XML from user request — VULNERABLE to XXE."""
    tree = ET.fromstring(xml_string)
    return {child.tag: child.text for child in tree}


# ──────────────────────────────────────────────────
# REAL BUG #2: Arbitrary file read via path traversal
# ──────────────────────────────────────────────────
def read_uploaded_config(filename: str) -> str:
    """Read user-uploaded config file — VULNERABLE to path traversal."""
    config_dir = "/app/configs"
    filepath = os.path.join(config_dir, filename)
    with open(filepath, "r") as f:
        return f.read()


# ──────────────────────────────────────────────────
# REAL BUG #3: Unsafe deserialization of user input
# ──────────────────────────────────────────────────
def load_user_session(session_data: bytes) -> dict:
    """Restore session from cookie — VULNERABLE to pickle RCE."""
    return pickle.loads(session_data)


# ──────────────────────────────────────────────────
# REAL BUG #4: Unsafe YAML load from user input
# ──────────────────────────────────────────────────
def parse_user_yaml(yaml_string: str) -> dict:
    """Parse YAML from user-submitted form — VULNERABLE to code execution."""
    return yaml.load(yaml_string, Loader=yaml.FullLoader)


# ──────────────────────────────────────────────────
# REAL BUG #5: SSRF — fetching arbitrary URLs
# ──────────────────────────────────────────────────
def fetch_webhook_url(url: str) -> str:
    """Fetch user-provided webhook URL — VULNERABLE to SSRF."""
    import urllib.request
    response = urllib.request.urlopen(url)
    return response.read().decode("utf-8")


# ──────────────────────────────────────────────────
# REAL BUG #6: Regex denial of service (ReDoS)
# ──────────────────────────────────────────────────
def validate_email(email: str) -> bool:
    """Validate email — VULNERABLE to ReDoS with evil input."""
    pattern = r"^([a-zA-Z0-9_.+-]+)*@([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


# ══════════════════════════════════════════════════
# INTENTIONAL #1: pickle.loads
#   BUT data comes from UNIX domain socket IPC only
#   (IPC_SOCKET_PATH in sanitizer_config.py)
#   Never exposed to user input.
# ══════════════════════════════════════════════════
def receive_ipc_message() -> dict:
    """Receive message from internal worker via Unix socket IPC."""
    import socket
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(IPC_SOCKET_PATH)
    data = sock.recv(65536)
    sock.close()
    return pickle.loads(data)


# ══════════════════════════════════════════════════
# INTENTIONAL #2: yaml.load (unsafe loader)
#   BUT uses custom loader from sanitizer_config
#   that only allows TRUSTED_YAML_TAGS for internal
#   config files, never user input.
# ══════════════════════════════════════════════════
def load_internal_config(config_path: str) -> dict:
    """Load internal YAML config — custom loader with restricted tags."""
    if not config_path.startswith("/etc/app/"):
        raise ValueError("Config must be in /etc/app/")

    loader = get_yaml_loader()
    with open(config_path, "r") as f:
        return yaml.load(f, Loader=loader)


# ══════════════════════════════════════════════════
# INTENTIONAL #3: tempfile without explicit cleanup
#   BUT used with NamedTemporaryFile(delete=True)
#   which auto-cleans on close. Safe pattern.
# ══════════════════════════════════════════════════
def process_upload(content: bytes, suffix: str = ".tmp") -> str:
    """Process upload via temp file — auto-deleted on close."""
    allowed_suffixes = {".tmp", ".csv", ".json", ".xml"}
    if suffix not in allowed_suffixes:
        raise ValueError(f"Invalid suffix: {suffix}")

    with tempfile.NamedTemporaryFile(delete=True, suffix=suffix) as tmp:
        tmp.write(content)
        tmp.flush()
        return _validate_content(tmp.name)


def _validate_content(filepath: str) -> str:
    """Validate file content and return summary."""
    with open(filepath, "r") as f:
        data = f.read()
    return f"Validated {len(data)} bytes"
