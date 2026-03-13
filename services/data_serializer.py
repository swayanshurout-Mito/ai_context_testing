"""
data_serializer.py — YAML/Pickle serialization for internal data.

Semgrep WILL flag: yaml-load, insecure-deserialization

WITHOUT CONTEXT — LLM would:
  Change yaml.load(Loader=yaml.Loader) to yaml.safe_load(),
  breaking deserialization of custom Python objects used internally.
  Remove pickle entirely.

WITH CONTEXT — LLM should see (via call graph to data_pipeline.py):
  yaml.load() is used for INTERNAL config that contains custom tag
  constructors (e.g., !env, !include). safe_load can't handle these.
  pickle is used for inter-process communication via a Unix socket,
  not for user-facing data.
"""

import pickle
import socket
import yaml
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


# ┌─────────────────────────────────────────────────────┐
# │ Semgrep flags: yaml-load (unsafe Loader)              │
# │ But it's INTENTIONAL — custom tag constructors needed │
# └─────────────────────────────────────────────────────┘

def _env_constructor(loader, node):
    """Custom YAML tag: !env VAR_NAME resolves to os.getenv(VAR_NAME)."""
    import os
    return os.getenv(loader.construct_scalar(node), "")


def _include_constructor(loader, node):
    """Custom YAML tag: !include path loads another YAML file."""
    path = Path(loader.construct_scalar(node))
    with open(path) as f:
        return yaml.load(f, Loader=yaml.Loader)


yaml.add_constructor("!env", _env_constructor, Loader=yaml.Loader)
yaml.add_constructor("!include", _include_constructor, Loader=yaml.Loader)


def load_pipeline_config(config_path: str) -> dict:
    """Load pipeline config with custom YAML tags.

    Uses yaml.Loader (not safe_load) because config files use:
      - !env DATABASE_URL  → resolves environment variable
      - !include base.yml  → includes another config file

    Config files are from the INTERNAL config directory, not user input.
    """
    with open(config_path) as f:
        return yaml.load(f, Loader=yaml.Loader)


# ┌─────────────────────────────────────────────────────┐
# │ Semgrep flags: insecure-deserialization (pickle)      │
# │ But it's SAFE — IPC via Unix socket, not user input  │
# └─────────────────────────────────────────────────────┘

IPC_SOCKET_PATH = "/var/run/app/worker.sock"


def send_to_worker(task: dict) -> None:
    """Send task to background worker via Unix socket using pickle.

    Safe because:
    1. Unix socket is local-only (not network accessible)
    2. Socket permissions are 0o600 (owner only)
    3. Both sender and receiver are our own processes
    """
    data = pickle.dumps(task)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(IPC_SOCKET_PATH)
    sock.sendall(len(data).to_bytes(4, "big") + data)
    sock.close()


def receive_from_socket(conn: socket.socket) -> dict:
    """Receive pickled task from Unix socket."""
    length = int.from_bytes(conn.recv(4), "big")
    data = b""
    while len(data) < length:
        data += conn.recv(length - len(data))
    return pickle.loads(data)


# ┌─────────────────────────────────────────────────────┐
# │ REAL BUG: Deserializing user-uploaded data — danger! │
# │ Should be caught and fixed.                          │
# └─────────────────────────────────────────────────────┘

def import_user_upload(file_data: bytes) -> list:
    """Parse user-uploaded data file — REAL VULNERABILITY.
    Uses pickle on untrusted input.
    """
    return pickle.loads(file_data)
