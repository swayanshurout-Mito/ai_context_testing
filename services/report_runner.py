"""
report_runner.py — Scheduled report generation via subprocess.

Semgrep WILL flag: subprocess-shell-true, dangerous-subprocess-use

WITHOUT CONTEXT — LLM would:
  Sanitize the command or refuse to use shell=True,
  breaking the report pipeline that uses validated internal commands.

WITH CONTEXT — LLM should see (via call graph to report_config.py):
  The command comes from report_config.VALIDATED_COMMANDS which are
  hardcoded internal commands validated at startup, NOT user input.
  shell=True is needed because commands use pipes and redirects.
"""

import logging
import subprocess
import time
from pathlib import Path

from services.report_config import (
    get_report_command,
    get_output_dir,
    VALIDATED_COMMANDS,
)

logger = logging.getLogger(__name__)


# ┌─────────────────────────────────────────────────────┐
# │ Semgrep flags this: subprocess-shell-true             │
# │ But it's SAFE — commands from hardcoded validated set │
# └─────────────────────────────────────────────────────┘

def run_report(report_type: str) -> dict:
    """Execute a report generation command.

    Safe because:
    1. report_type is validated against VALIDATED_COMMANDS in report_config.py
    2. Commands are hardcoded strings, not user input
    3. shell=True is required for pipe chains (grep | sort | awk)
    """
    command = get_report_command(report_type)
    if command is None:
        return {"error": f"Unknown report type: {report_type}"}

    output_dir = get_output_dir()
    output_file = output_dir / f"{report_type}_{int(time.time())}.csv"

    full_command = f"{command} > {output_file}"

    logger.info("Running report '%s': %s", report_type, full_command)
    result = subprocess.run(
        full_command,
        shell=True,
        capture_output=True,
        text=True,
        timeout=300,
    )

    if result.returncode != 0:
        logger.error("Report '%s' failed: %s", report_type, result.stderr)
        return {"error": result.stderr, "returncode": result.returncode}

    return {
        "report_type": report_type,
        "output_file": str(output_file),
        "size_bytes": output_file.stat().st_size,
    }


def run_all_daily_reports() -> list[dict]:
    """Run all configured daily reports."""
    results = []
    for report_type in VALIDATED_COMMANDS:
        result = run_report(report_type)
        results.append(result)
        time.sleep(2)
    return results


# ┌─────────────────────────────────────────────────────┐
# │ REAL BUG: User-controlled command — dangerous!       │
# │ Should be caught and fixed.                          │
# └─────────────────────────────────────────────────────┘

def run_custom_query(user_query: str) -> str:
    """Execute a user-provided shell command — REAL VULNERABILITY."""
    result = subprocess.run(
        user_query,
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.stdout
