"""The backend process's own configuration: every VIBEAUDIT_* setting the environment provides, read in one place.

Settings.from_environ() reads and checks them once for the API process; the module-level readers serve the modules
that look a setting up when they need it (catalog root, fixture registry, runtime profile), so a test can point them
elsewhere. Credential references are not settings: adapters, providers and the supervisor read model keys, test
identities and the lease database URL a runtime profile names, by the names a run or profile gives and under their
own rules, and the supervisor loads adapters.py on its own, so nothing here is used from there.
"""
from __future__ import annotations

import math
import os
import re
import secrets
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .adapters import format_origin, parse_origin

ROOT = Path(__file__).resolve().parents[2]
# The origins the console answers on when none is configured; the launcher adds the port it listens on.
DEFAULT_CONSOLE_ORIGINS = frozenset({"http://127.0.0.1:8000", "http://localhost:8000", "http://[::1]:8000"})
_TOKEN = re.compile(r"[A-Za-z0-9_-]{32,256}")


def startup_token_strong(token):
    """At least 96 bits by the token's own character frequencies, eight distinct characters and no repeating pattern.

    A length and character-set check alone accepts 32 copies of one letter."""
    counts = Counter(token)
    bits = -sum(count * math.log2(count / len(token)) for count in counts.values())
    periodic = any(token == (token[:k] * (len(token) // k + 1))[:len(token)] for k in range(1, len(token) // 2 + 1))
    return len(counts) >= 8 and bits >= 96 and not periodic


def checked_token(token):
    """The startup token as given, or the ValueError that names what is wrong with it."""
    if not isinstance(token, str) or not _TOKEN.fullmatch(token):
        raise ValueError("VIBEAUDIT_SESSION_TOKEN must be 32-256 URL-safe characters (A-Z a-z 0-9 _ -)")
    if not startup_token_strong(token):
        raise ValueError("VIBEAUDIT_SESSION_TOKEN is too predictable; generate one with: python -c \"import secrets; print(secrets.token_urlsafe(32))\"")
    return token


def _environ(environ):
    return os.environ if environ is None else environ


def catalog_root(environ=None) -> Path:
    """VIBEAUDIT_CATALOG_ROOT, or the checkout's catalogs/ beside the package."""
    configured = _environ(environ).get("VIBEAUDIT_CATALOG_ROOT")
    return Path(configured) if configured else ROOT / "catalogs"


def fixture_config(environ=None) -> Path | None:
    """VIBEAUDIT_FIXTURE_CONFIG: the administrator's registry of trusted fixture profiles, when there is one."""
    configured = _environ(environ).get("VIBEAUDIT_FIXTURE_CONFIG")
    return Path(configured) if configured else None


def runtime_config(environ=None) -> Path | None:
    """VIBEAUDIT_RUNTIME_CONFIG: the trusted runtime profiles (worker images, lease database), when provisioned."""
    configured = _environ(environ).get("VIBEAUDIT_RUNTIME_CONFIG")
    return Path(configured) if configured else None


def source_roots(environ=None) -> tuple[Path, ...]:
    """VIBEAUDIT_SOURCE_ROOTS (os.pathsep-separated), or the checkout's fixtures/: where a live run's source may live."""
    configured = _environ(environ).get("VIBEAUDIT_SOURCE_ROOTS", str(ROOT / "fixtures"))
    return tuple(Path(item).resolve() for item in configured.split(os.pathsep) if item)


def console_origins(environ=None, extra=()) -> frozenset[str]:
    """The origins the console trusts: VIBEAUDIT_UI_ORIGINS plus extra, each read as one exact origin and written the way
    a browser sends it (lowercase host, no default port), or the :8000 defaults when none is configured.

    Configured origins replace the defaults, so another local service on :8000 is not a trusted origin while the
    console runs on a different port. An entry that is not an origin stops the console from starting.
    """
    configured = [item for item in _environ(environ).get("VIBEAUDIT_UI_ORIGINS", "").split(",") if item.strip()] + list(extra)
    origins = set()
    for item in configured:
        try:
            origins.add(format_origin(*parse_origin(item.strip().rstrip("/")), omit_default_port=True))
        except ValueError:
            raise ValueError("VIBEAUDIT_UI_ORIGINS entries must be scheme://host[:port]") from None
    return frozenset(origins or DEFAULT_CONSOLE_ORIGINS)


@dataclass(frozen=True)
class Settings:
    """What the API process was started with. Arguments win over the environment; the token is generated when neither
    gives one, and fixed_token records that the operator chose it (so a logout of every session may not replace it)."""
    session_token: str
    fixed_token: bool
    data_dir: Path
    database_url: str | None
    console_origins: frozenset[str]
    source_roots: tuple[Path, ...]
    catalog_root: Path
    fixture_config: Path | None
    runtime_config: Path | None

    @classmethod
    def from_environ(cls, environ=None, *, data_dir=None, database_url=None, session_token=None, console_origins_extra=()):
        env = _environ(environ)
        given = session_token or env.get("VIBEAUDIT_SESSION_TOKEN")
        return cls(
            session_token=checked_token(given or secrets.token_urlsafe(32)),
            fixed_token=bool(given),
            data_dir=Path(data_dir or env.get("VIBEAUDIT_DATA_DIR") or ROOT / ".data"),
            database_url=database_url or env.get("VIBEAUDIT_DATABASE_URL") or None,
            console_origins=console_origins(env, console_origins_extra),
            source_roots=source_roots(env),
            catalog_root=catalog_root(env),
            fixture_config=fixture_config(env),
            runtime_config=runtime_config(env),
        )
