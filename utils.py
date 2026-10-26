"""Shared helpers: formatting, safe filenames, and path validation."""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from config import CAPTURES_DIR, DATA_DIR

_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]")


def human_bytes(num: float) -> str:
    """Format a byte count as a human-readable string (e.g. '1.4 MB')."""
    step = 1024.0
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(num) < step:
            return f"{num:.1f} {unit}" if unit != "B" else f"{int(num)} B"
        num /= step
    return f"{num:.1f} PB"


def human_rate(num: float, suffix: str = "B/s") -> str:
    """Format a per-second rate."""
    step = 1024.0
    for unit in ["", "K", "M", "G", "T"]:
        if abs(num) < step:
            return f"{num:.1f} {unit}{suffix}"
        num /= step
    return f"{num:.1f} P{suffix}"


def sanitize_filename(name: str) -> str:
    """Strip path components and unsafe characters from a user-supplied name.

    Prevents path traversal (``../``) and keeps only a safe basename. Always
    returns a non-empty string.
    """
    base = Path(name).name  # drop any directory component
    cleaned = _SAFE_NAME_RE.sub("_", base).strip("._")
    return cleaned or "unnamed"


def safe_output_path(filename: str, directory: Path = CAPTURES_DIR) -> Path:
    """Resolve a user-supplied filename to a path confined to ``directory``.

    Raises ValueError if the resolved path would escape the directory.
    """
    directory = directory.resolve()
    candidate = (directory / sanitize_filename(filename)).resolve()
    if directory not in candidate.parents and candidate != directory:
        raise ValueError("Resolved path escapes the allowed directory.")
    return candidate


def timestamp_slug(dt: datetime | None = None) -> str:
    """Return a filename-friendly timestamp like '20260109-143501'."""
    return (dt or datetime.now()).strftime("%Y%m%d-%H%M%S")


__all__ = [
    "human_bytes",
    "human_rate",
    "sanitize_filename",
    "safe_output_path",
    "timestamp_slug",
    "DATA_DIR",
    "CAPTURES_DIR",
]
