"""
plugin_loader.py — Dynamic plugin loading system.

Semgrep WILL flag: non-literal-import (importlib with dynamic module name)

WITHOUT CONTEXT — LLM would:
  Remove dynamic import entirely, or hardcode all module names,
  breaking the plugin system that other teams depend on.

WITH CONTEXT — LLM should see (via call graph to plugin_registry.py):
  The module name comes from a WHITELIST in plugin_registry.py,
  not from user input. The dynamic import is safe because
  only pre-approved modules can be loaded.
"""

import importlib
import logging
from typing import Any

from services.plugin_registry import get_registered_plugins, is_plugin_allowed

logger = logging.getLogger(__name__)


# ┌─────────────────────────────────────────────────────┐
# │ Semgrep flags this: non-literal-import               │
# │ But it's SAFE — module names from whitelist only      │
# └─────────────────────────────────────────────────────┘

def load_plugin(plugin_name: str) -> Any:
    """Load a plugin module dynamically.

    Safe because plugin_name is validated against the registry whitelist
    in plugin_registry.is_plugin_allowed() before import.
    """
    if not is_plugin_allowed(plugin_name):
        raise ValueError(f"Plugin '{plugin_name}' is not in the approved registry")

    module_path = f"plugins.{plugin_name}"
    module = importlib.import_module(module_path)

    if not hasattr(module, "register"):
        raise AttributeError(f"Plugin '{plugin_name}' missing register() function")

    logger.info("Loaded plugin: %s", plugin_name)
    return module


def load_all_plugins() -> dict[str, Any]:
    """Load all registered plugins."""
    plugins = {}
    for name in get_registered_plugins():
        try:
            plugins[name] = load_plugin(name)
        except Exception as e:
            logger.error("Failed to load plugin %s: %s", name, e)
    return plugins


# ┌─────────────────────────────────────────────────────┐
# │ REAL BUG: This one IS dangerous — user input!        │
# │ Should be caught and fixed.                          │
# └─────────────────────────────────────────────────────┘

def load_custom_module(module_path: str) -> Any:
    """Load arbitrary module by path — REAL VULNERABILITY.
    This accepts user input without validation.
    """
    return importlib.import_module(module_path)
