"""Application configuration read from environment variables."""

from __future__ import annotations

import os
from pathlib import Path


def database_path() -> str:
    """Return the SQLite database path (env var DATABASE_PATH overrides default)."""
    return os.environ.get("DATABASE_PATH", str(Path(__file__).resolve().parent.parent / "data" / "events.db"))


def server_port() -> int:
    try:
        return int(os.environ.get("APP_PORT", "8000"))
    except ValueError:
        return 8000


def lease_duration_seconds() -> int:
    """Lifetime of a claim lease (env var LEASE_DURATION_SECONDS overrides default)."""
    try:
        value = int(os.environ.get("LEASE_DURATION_SECONDS", "30"))
    except ValueError:
        return 30
    return value if value > 0 else 30


# Development-only default so `docker compose up` works with zero configuration.
# Deployments must override it with SNAPSHOT_CURSOR_SECRET: rotating/changing the
# secret invalidates every snapshot cursor signed with the previous value.
DEFAULT_SNAPSHOT_CURSOR_SECRET = "dev-only-snapshot-cursor-secret-change-me"


def snapshot_cursor_secret() -> bytes:
    """Return the HMAC key for snapshot cursors as UTF-8 bytes.

    Reads ``SNAPSHOT_CURSOR_SECRET``; an unset or empty value falls back to a
    built-in development default so the service stays one-command startable.
    """
    secret = os.environ.get("SNAPSHOT_CURSOR_SECRET", "").strip()
    return (secret or DEFAULT_SNAPSHOT_CURSOR_SECRET).encode("utf-8")
