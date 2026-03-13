"""
plugin_registry.py — Plugin whitelist and registration.

This file provides CONTEXT for plugin_loader.py.
The call graph should find this and show the LLM that
dynamic imports in load_plugin() are safe because they're
validated against this whitelist.
"""

import logging

logger = logging.getLogger(__name__)

APPROVED_PLUGINS = {
    "csv_exporter",
    "pdf_generator",
    "slack_notifier",
    "email_sender",
    "s3_uploader",
    "audit_logger",
    "webhook_dispatcher",
}


def is_plugin_allowed(plugin_name: str) -> bool:
    """Check if a plugin is in the approved whitelist."""
    allowed = plugin_name in APPROVED_PLUGINS
    if not allowed:
        logger.warning("Blocked unapproved plugin: %s", plugin_name)
    return allowed


def get_registered_plugins() -> list[str]:
    """Return list of all approved plugin names."""
    return sorted(APPROVED_PLUGINS)


def register_plugin(name: str) -> bool:
    """Add a plugin to the approved list (admin only)."""
    if not name.isidentifier():
        raise ValueError(f"Invalid plugin name: {name}")
    APPROVED_PLUGINS.add(name)
    logger.info("Registered new plugin: %s", name)
    return True
