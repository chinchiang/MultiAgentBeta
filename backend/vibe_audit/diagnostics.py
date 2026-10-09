"""Local diagnostics for failures the API and reports deliberately describe in fixed words.

What the operator sees stays fixed text, so an exception from a provider, a target or the host never reaches a run
record. What is lost that way is the reason a run failed on this machine. This log keeps it, on the operator's
machine only: the exception type and the code locations it passed through, never its message or values, since those
can carry credentials, provider bodies, target responses or repository text.
"""
from __future__ import annotations

import logging
import os
import traceback
from pathlib import Path

LOG_NAME = "vibe-audit.log"
log = logging.getLogger("vibe_audit")


def note_failure(context: str, exc: BaseException) -> None:
    """Record where a swallowed exception came from: its type and the last code locations, nothing it carried."""
    frames = traceback.extract_tb(exc.__traceback__)[-4:]
    where = " <- ".join(f"{Path(frame.filename).name}:{frame.lineno} {frame.name}" for frame in reversed(frames))
    log.warning("%s: %s at %s", context, type(exc).__name__, where or "unknown location")


def configure(data_dir: Path) -> Path:
    """Write the log inside the owner-only data directory; the file is readable by the operator alone."""
    path = Path(data_dir) / LOG_NAME
    path.touch(mode=0o600, exist_ok=True)
    os.chmod(path, 0o600)
    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    log.info("workbench started")
    return path
