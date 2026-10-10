"""The backend process's settings: read from the environment it is given, checked once, arguments winning."""
import os
from pathlib import Path

import pytest

from vibe_audit import settings
from vibe_audit.settings import DEFAULT_CONSOLE_ORIGINS, ROOT, Settings, checked_token, console_origins, startup_token_strong

STRONG = "ab3-F9_kQ7zLm2XpV0cR8tYwN4sH6jD1gE5uB"


def test_defaults_come_from_the_checkout_and_a_generated_token():
    made = Settings.from_environ({})
    assert startup_token_strong(made.session_token) and not made.fixed_token
    assert made.data_dir == ROOT / ".data" and made.database_url is None
    assert made.console_origins == DEFAULT_CONSOLE_ORIGINS
    assert made.source_roots == ((ROOT / "fixtures").resolve(),)
    assert made.catalog_root == ROOT / "catalogs" and (made.catalog_root / "manifest.json").is_file()
    assert made.fixture_config is None and made.runtime_config is None
    assert Settings.from_environ({}).session_token != made.session_token


def test_the_environment_is_read_and_arguments_win_over_it(tmp_path):
    environ = {"VIBEAUDIT_SESSION_TOKEN": STRONG, "VIBEAUDIT_DATA_DIR": str(tmp_path / "env"), "VIBEAUDIT_DATABASE_URL": "postgresql://x",
               "VIBEAUDIT_UI_ORIGINS": "http://127.0.0.1:9000/,HTTP://Localhost:80", "VIBEAUDIT_SOURCE_ROOTS": os.pathsep.join([str(tmp_path / "a"), "", str(tmp_path / "b")]),
               "VIBEAUDIT_CATALOG_ROOT": str(tmp_path / "catalogs"), "VIBEAUDIT_FIXTURE_CONFIG": str(tmp_path / "fixtures.json"), "VIBEAUDIT_RUNTIME_CONFIG": str(tmp_path / "runtime.json")}
    made = Settings.from_environ(environ)
    assert made.session_token == STRONG and made.fixed_token
    assert made.data_dir == tmp_path / "env" and made.database_url == "postgresql://x"
    # Origins read as origins and written as a browser sends them: lowercase host, no default port, no trailing slash.
    assert made.console_origins == {"http://127.0.0.1:9000", "http://localhost"}
    assert made.source_roots == ((tmp_path / "a").resolve(), (tmp_path / "b").resolve())
    assert (made.catalog_root, made.fixture_config, made.runtime_config) == (tmp_path / "catalogs", tmp_path / "fixtures.json", tmp_path / "runtime.json")
    other = Settings.from_environ(environ, data_dir=tmp_path / "arg", database_url="sqlite", session_token=STRONG[::-1], console_origins_extra=["http://[::1]:8123"])
    assert (other.data_dir, other.database_url, other.session_token) == (tmp_path / "arg", "sqlite", STRONG[::-1])
    assert other.console_origins == {"http://127.0.0.1:9000", "http://localhost", "http://[::1]:8123"}
    # The launcher's own port is added to the defaults only when nothing is configured.
    assert console_origins({}, ["http://127.0.0.1:8123"]) == {"http://127.0.0.1:8123"}


@pytest.mark.parametrize("token,reason", [
    ("short", "32-256 URL-safe"), ("x" * 32, "too predictable"), ("abcdefgh" * 4, "too predictable"), ("a b" + "c" * 30, "32-256 URL-safe"),
    ("é" + "a" * 31, "32-256 URL-safe"), (5, "32-256 URL-safe"),
])
def test_a_weak_or_malformed_startup_token_stops_the_start(token, reason):
    with pytest.raises(ValueError, match=reason):
        checked_token(token)
    with pytest.raises(ValueError, match=reason):
        Settings.from_environ({"VIBEAUDIT_SESSION_TOKEN": token} if isinstance(token, str) else {}, session_token=token)
    assert checked_token(STRONG) == STRONG


@pytest.mark.parametrize("raw", ["127.0.0.1:9000", "http://user@127.0.0.1:9000", "http://127.0.0.1:9000/console", "http://127.0.0.1:0", "ftp://127.0.0.1", "http://"])
def test_a_console_origin_that_is_not_an_origin_stops_the_start(raw):
    with pytest.raises(ValueError, match="^VIBEAUDIT_UI_ORIGINS entries must be scheme://host\\[:port\\]$"):
        console_origins({"VIBEAUDIT_UI_ORIGINS": raw})
    with pytest.raises(ValueError, match="VIBEAUDIT_UI_ORIGINS"):
        Settings.from_environ({"VIBEAUDIT_UI_ORIGINS": f"http://127.0.0.1:9000,{raw}"})


def test_the_lazy_readers_follow_the_process_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("VIBEAUDIT_CATALOG_ROOT", str(tmp_path))
    monkeypatch.setenv("VIBEAUDIT_FIXTURE_CONFIG", str(tmp_path / "f.json"))
    monkeypatch.setenv("VIBEAUDIT_RUNTIME_CONFIG", str(tmp_path / "r.json"))
    assert (settings.catalog_root(), settings.fixture_config(), settings.runtime_config()) == (tmp_path, tmp_path / "f.json", tmp_path / "r.json")
    for name in ("VIBEAUDIT_CATALOG_ROOT", "VIBEAUDIT_FIXTURE_CONFIG", "VIBEAUDIT_RUNTIME_CONFIG"):
        monkeypatch.setenv(name, "")
    assert (settings.catalog_root(), settings.fixture_config(), settings.runtime_config()) == (ROOT / "catalogs", None, None)
    assert settings.source_roots({"VIBEAUDIT_SOURCE_ROOTS": ""}) == ()
    assert isinstance(settings.source_roots()[0], Path)
