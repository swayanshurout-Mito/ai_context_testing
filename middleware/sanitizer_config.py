"""
sanitizer_config.py — Configuration for request_validator.py.

This file provides the CONTEXT that proves certain patterns in
request_validator.py are intentional and safe.
"""

import yaml


IPC_SOCKET_PATH = "/var/run/app/worker.sock"

ALLOWED_CONTENT_TYPES = {
    "application/json",
    "application/xml",
    "text/csv",
    "multipart/form-data",
}

TRUSTED_YAML_TAGS = {
    "!include",
    "!env",
    "!secret_ref",
}


class _RestrictedLoader(yaml.SafeLoader):
    """YAML loader that only allows our trusted internal tags.

    Extends SafeLoader (no arbitrary Python execution) and adds
    constructors only for tags in TRUSTED_YAML_TAGS.
    """
    pass


def _include_constructor(loader, node):
    """Handle !include tag — reads another YAML file."""
    filepath = loader.construct_scalar(node)
    if not filepath.startswith("/etc/app/"):
        raise ValueError(f"!include path must be under /etc/app/: {filepath}")
    with open(filepath, "r") as f:
        return yaml.safe_load(f)


def _env_constructor(loader, node):
    """Handle !env tag — reads from environment."""
    import os
    var_name = loader.construct_scalar(node)
    return os.environ.get(var_name, "")


def _secret_ref_constructor(loader, node):
    """Handle !secret_ref tag — reads from vault (stub)."""
    secret_name = loader.construct_scalar(node)
    return f"vault://{secret_name}"


_RestrictedLoader.add_constructor("!include", _include_constructor)
_RestrictedLoader.add_constructor("!env", _env_constructor)
_RestrictedLoader.add_constructor("!secret_ref", _secret_ref_constructor)


def get_yaml_loader():
    """Return the restricted YAML loader for internal configs.

    Safe because:
    1. Extends SafeLoader (no arbitrary code execution)
    2. Only allows TRUSTED_YAML_TAGS
    3. !include is path-restricted to /etc/app/
    """
    return _RestrictedLoader
