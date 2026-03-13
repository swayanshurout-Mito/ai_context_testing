"""
report_config.py — Report command configuration.

This file provides CONTEXT for report_runner.py.
The call graph should find this and show the LLM that
subprocess commands come from this hardcoded, validated set —
NOT from user input.
"""

import os
from pathlib import Path

VALIDATED_COMMANDS = {
    "daily_users": (
        "psql -h localhost -U readonly -d analytics -c "
        "\"SELECT date, count(*) FROM logins GROUP BY date ORDER BY date DESC LIMIT 30\" "
        "| grep -v rows | sort"
    ),
    "revenue_summary": (
        "psql -h localhost -U readonly -d analytics -c "
        "\"SELECT month, sum(amount) FROM payments GROUP BY month\" "
        "| tail -n +3 | head -n -2"
    ),
    "error_log": (
        "cat /var/log/app/error.log | grep -i 'error\\|fatal' "
        "| awk '{print $1, $2, $NF}' | sort | uniq -c | sort -rn | head -50"
    ),
    "disk_usage": "df -h | grep -v tmpfs | sort -k5 -rn",
    "active_connections": "netstat -an | grep ESTABLISHED | wc -l",
}


def get_report_command(report_type: str) -> str | None:
    """Return the command for a report type, or None if not in whitelist."""
    return VALIDATED_COMMANDS.get(report_type)


def get_output_dir() -> Path:
    """Get or create the report output directory."""
    output_dir = Path(os.getenv("REPORT_OUTPUT_DIR", "/tmp/reports"))
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def validate_all_commands() -> bool:
    """Startup validation — ensure all commands are safe."""
    for name, cmd in VALIDATED_COMMANDS.items():
        if any(dangerous in cmd for dangerous in ["rm ", "dd ", "mkfs", "> /dev/"]):
            raise ValueError(f"Dangerous command detected in '{name}': {cmd}")
    return True
