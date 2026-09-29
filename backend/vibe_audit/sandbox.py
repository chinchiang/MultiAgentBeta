"""Optional Docker isolation for three fixed, offline white-box scanners.

Image digests must be provisioned in trusted harness configuration. This module
does not pull/build images, execute repository scripts, install dependencies,
mount the Docker socket, or return scanner output containing source snippets.

Integration is deliberately unverified until run against a real local Docker
daemon and provisioned images. Unit tests inject a process runner and test only
the control plane. Never describe those tests as a successful security scan.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shutil
import stat
import time
import uuid
from pathlib import Path
from typing import Mapping

MAX_OUTPUT_BYTES = 256 * 1024
MAX_FILES = 20_000
MAX_SOURCE_BYTES = 128 * 1024 * 1024
CONTROL_TIMEOUT_SECONDS = 5.0
_REPOSITORIES = {"semgrep": "semgrep/semgrep", "osv": "ghcr.io/google/osv-scanner", "gitleaks": "ghcr.io/gitleaks/gitleaks"}
_RULES = Path(__file__).resolve().parents[2] / "fixtures" / "semgrep-rules.yml"
_GITLEAKS_CONFIG = Path(__file__).resolve().parents[2] / "fixtures" / "gitleaks.toml"
_OSV_CONFIG = Path(__file__).resolve().parents[2] / "fixtures" / "osv-scanner.toml"


class SandboxBlocked(ValueError):
    pass


def _reply(scanner_id, status, reason, **fields):
    return {"scanner_id": scanner_id, "status": status, "reason": reason,
            "findings": [], "gaps": [], "cleanup_confirmed": True,
            "simulated": False, **fields}


def _is_link(path):
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _safe_path(value, *, directory=True):
    path = Path(value).absolute()
    if any(c in str(path) for c in [",", "\r", "\n", "\x00"]):
        raise SandboxBlocked("Mount path contains unsupported characters.")
    if path == Path(path.anchor):
        raise SandboxBlocked("Filesystem roots cannot be scanner mounts.")
    for part in (path, *path.parents):
        if _is_link(part):
            raise SandboxBlocked("Symlinks and Windows reparse points cannot be scanner mounts.")
    if (directory and not path.is_dir()) or (not directory and not path.is_file()):
        raise SandboxBlocked("Required scanner input path is missing or has the wrong type.")
    return path.resolve(strict=True)


def _check_source(path, *, max_bytes=MAX_SOURCE_BYTES):
    count, size, files_count = 0, 0, 0
    def inaccessible(_error):
        raise SandboxBlocked("Source contains an inaccessible directory; scan coverage cannot be established.")
    for base, dirs, files in os.walk(path, followlinks=False, onerror=inaccessible):
        for name in dirs + files:
            item = Path(base) / name
            info = item.lstat()
            count += 1
            if count > MAX_FILES:
                raise SandboxBlocked("Source tree exceeds the entry limit; provide a bounded staging snapshot.")
            if _is_link(item) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise SandboxBlocked("Source must contain only regular files and directories, with no links, sockets or devices.")
            size += info.st_size if stat.S_ISREG(info.st_mode) else 0
            files_count += int(stat.S_ISREG(info.st_mode))
            if size > max_bytes:
                raise SandboxBlocked("Source tree exceeds the byte limit; provide a bounded staging snapshot.")
            if name == ".semgrepignore":
                raise SandboxBlocked("Untrusted Semgrep ignore files must be removed from a separate scanner staging snapshot.")
    if not files_count:
        raise SandboxBlocked("Empty source snapshot cannot establish scan coverage.")
    return files_count


def _image(scanner_id, image_pins):
    repository = _REPOSITORIES.get(scanner_id)
    if repository is None:
        raise SandboxBlocked("This sandbox only supports Semgrep, OSV and Gitleaks; dynamic scanners remain blocked.")
    image = image_pins.get(scanner_id, "")
    if not isinstance(image, str) or not re.fullmatch(re.escape(repository) + r"@sha256:[a-f0-9]{64}", image):
        raise SandboxBlocked("A trusted official-repository image pinned by SHA-256 digest is required; tags are not accepted.")
    return image


def _client_env():
    # Docker client sees no cloud/model credentials and no remote Docker context
    # overrides. Only OS process/bootstrap essentials are retained.
    keys = {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA"}
    return {k: v for k, v in os.environ.items() if k.upper() in keys}


def build_scanner_command(scanner_id: str, source_dir: str, *, image_pins: Mapping[str, str],
                          container_name: str, docker_binary="docker", offline_db_dir=None) -> list[str]:
    """Compile an immutable command from a scanner id; no arbitrary argv input."""
    if not re.fullmatch(r"vibeaudit-[a-f0-9]{32}", container_name):
        raise SandboxBlocked("Invalid generated container name.")
    image = _image(scanner_id, image_pins)
    source = _safe_path(source_dir)
    _check_source(source)
    argv = [docker_binary, "--host", "npipe:////./pipe/docker_engine" if os.name == "nt" else "unix:///var/run/docker.sock",
            "run", "--name", container_name, "--pull", "never", "--network", "none",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
            "--user", "65534:65534", "--pids-limit", "128", "--memory", "512m", "--memory-swap", "512m",
            "--cpus", "1", "--ulimit", "nofile=256:256", "--log-driver", "none",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777", "--workdir", "/tmp",
            "--env", "HOME=/tmp", "--env", "TMPDIR=/tmp",
            "--mount", f"type=bind,source={source},target=/src,readonly,bind-recursive=readonly"]
    if scanner_id == "semgrep":
        rules = _safe_path(_RULES, directory=False)
        argv += ["--mount", f"type=bind,source={rules},target=/trusted/semgrep-rules.yml,readonly",
                 "--env", "SEMGREP_SEND_METRICS=off", "--env", "SEMGREP_ENABLE_VERSION_CHECK=0",
                 image, "semgrep", "scan", "--config", "/trusted/semgrep-rules.yml", "--metrics", "off",
                 "--disable-version-check", "--disable-nosem", "--no-git-ignore", "--no-autofix", "--json",
                 "--jobs", "1", "--timeout", "5", "--max-memory", "256", "/src"]
    elif scanner_id == "gitleaks":
        config = _safe_path(_GITLEAKS_CONFIG, directory=False)
        argv += ["--mount", f"type=bind,source={config},target=/trusted/gitleaks.toml,readonly", image,
                 "dir", "/src", "--config", "/trusted/gitleaks.toml", "--gitleaks-ignore-path", "/dev/null",
                 "--redact", "--report-format", "json", "--report-path", "/dev/stdout", "--timeout", "60", "--no-banner"]
    else:
        if not offline_db_dir:
            raise SandboxBlocked("OSV requires a provisioned offline database snapshot; online database access is disabled.")
        db = _safe_path(offline_db_dir)
        _check_source(db, max_bytes=2 * 1024 * 1024 * 1024)
        if not (db / "osv-scanner").is_dir():
            raise SandboxBlocked("OSV database must use the documented osv-scanner/<ecosystem>/all.zip directory layout.")
        config = _safe_path(_OSV_CONFIG, directory=False)
        argv += ["--mount", f"type=bind,source={db},target=/db,readonly,bind-recursive=readonly",
                 "--mount", f"type=bind,source={config},target=/trusted/osv-scanner.toml,readonly",
                 "--env", "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/db", image,
                 "scan", "source", "--recursive", "--offline", "--config", "/trusted/osv-scanner.toml", "--format", "json", "/src"]
    return argv


async def _default_runner(argv, *, env, cwd):
    kwargs = {"stdout": asyncio.subprocess.PIPE, "stderr": asyncio.subprocess.PIPE, "stdin": asyncio.subprocess.DEVNULL,
              "env": env, "cwd": cwd}
    if os.name == "nt":
        kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
    return await asyncio.create_subprocess_exec(*argv, **kwargs)


async def _collect(stream, output, budget, exceeded):
    while True:
        chunk = await stream.read(8192)
        if not chunk:
            return
        available = max(0, MAX_OUTPUT_BYTES - budget[0])
        output.extend(chunk[:available])
        budget[0] += len(chunk)
        if budget[0] > MAX_OUTPUT_BYTES:
            exceeded.set()


async def _bounded_control(runner, argv, env):
    """Run Docker lifecycle commands, killing and reaping the CLI on failure."""
    proc = None
    readers = []
    try:
        proc = await asyncio.wait_for(runner(argv, env=env, cwd=str(Path(__file__).parent)), CONTROL_TIMEOUT_SECONDS)
        exceeded = asyncio.Event()
        budget = [0]
        readers = [asyncio.create_task(_collect(stream, bytearray(), budget, exceeded)) for stream in (proc.stdout, proc.stderr)]
        code = await asyncio.wait_for(proc.wait(), CONTROL_TIMEOUT_SECONDS)
        await asyncio.wait_for(asyncio.gather(*readers), CONTROL_TIMEOUT_SECONDS)
        return code == 0 and not exceeded.is_set()
    except (Exception, asyncio.CancelledError):
        if proc is not None:
            try:
                proc.kill()
            except (ProcessLookupError, OSError):
                pass
            try:
                await asyncio.wait_for(proc.wait(), CONTROL_TIMEOUT_SECONDS)
            except (Exception, asyncio.CancelledError):
                pass
        return False
    finally:
        for reader in readers:
            if not reader.done():
                reader.cancel()
        if readers:
            await asyncio.gather(*readers, return_exceptions=True)


async def _cleanup(runner, docker_prefix, name, env, *, force):
    if force:
        await _bounded_control(runner, [*docker_prefix, "kill", name], env)
        # A kill racing with normal completion may fail, but wait and removal
        # still establish termination without relying on the attached client.
    waited = await _bounded_control(runner, [*docker_prefix, "wait", name], env)
    removed = await _bounded_control(runner, [*docker_prefix, "rm", "--force", name], env)
    return waited and removed


def _safe_text(value, limit=240):
    value = str(value)[:limit]
    value = re.sub(r"[\x00-\x1f\x7f]", "?", value)
    for key, secret in os.environ.items():
        if key.startswith("VIBEAUDIT_") and len(secret) >= 6:
            value = value.replace(secret, "[REDACTED]")
    return value


def _finding(scanner_id, rule, path, line, title):
    safe_path = _safe_text(path)
    if safe_path.startswith("/src/"):
        safe_path = safe_path[5:]
    return {"scanner_id": scanner_id, "rule_id": _safe_text(rule), "file": safe_path,
            "line": line if type(line) is int and line > 0 else None,
            "title": _safe_text(title), "state": "corroborated_static"}


def _parse(scanner_id, output, exit_code):
    if exit_code not in {0, 1}:
        raise ValueError("scanner exit failure")
    data = json.loads(output)
    findings, gaps = [], []
    if scanner_id == "semgrep":
        if not isinstance(data, dict) or not isinstance(data.get("results"), list):
            raise ValueError("schema")
        for row in data["results"][:1000]:
            findings.append(_finding(scanner_id, row["check_id"], row["path"], row.get("start", {}).get("line"), row.get("extra", {}).get("message", "Semgrep candidate finding")))
        if data.get("errors"):
            gaps.append("Semgrep reported analysis errors; affected coverage is incomplete.")
        if not data.get("paths", {}).get("scanned"):
            gaps.append("Semgrep did not provide a non-empty scanned path list.")
    elif scanner_id == "gitleaks":
        if not isinstance(data, list):
            raise ValueError("schema")
        for row in data[:1000]:
            # Secret, Match, Entropy, Commit content and source snippets are
            # deliberately discarded even when upstream --redact is enabled.
            findings.append(_finding(scanner_id, row["RuleID"], row["File"], row.get("StartLine"), row.get("Description", "Potential secret exposure")))
    else:
        if not isinstance(data, dict) or not isinstance(data.get("results"), list):
            raise ValueError("schema")
        for source in data["results"][:1000]:
            path = source.get("source", {}).get("path", "")
            for package in source.get("packages", [])[:1000]:
                for vuln in package.get("vulnerabilities", [])[:1000]:
                    findings.append(_finding(scanner_id, vuln["id"], path, None, "Dependency vulnerability reported by the provisioned offline database"))
                    if len(findings) >= 1000:
                        break
                if len(findings) >= 1000:
                    break
            if len(findings) >= 1000:
                break
        gaps.append("Offline OSV results depend on the supplied database age and ecosystem coverage; commit-level matching is unsupported offline.")
    if len(findings) >= 1000:
        gaps.append("Finding import reached its bounded limit; the full result was not imported.")
    if exit_code == 1 and not findings:
        raise ValueError("nonzero exit with no parsed findings")
    return findings, gaps


async def run_scanner(scanner_id: str, source_dir: str, *, image_pins: Mapping[str, str], cancel_event,
                      lease_hook=None, process_runner=None, timeout_seconds=120, offline_db_dir=None) -> dict:
    """Run one fixed scanner. Injected runners are for control-plane tests only.

    ``process_runner(argv, *, env, cwd)`` is async and returns an object with
    ``stdout``/``stderr`` async readers, ``wait()`` and synchronous ``kill()``.
    The lease hook is called before spawn and repeatedly during execution.
    It must raise on lease expiry. Callers must pass a private staging snapshot
    consistent with the white-box source digest; this runner cannot freeze a
    concurrently modified working tree for them.
    """
    docker = shutil.which("docker") if process_runner is None else "docker"
    if not docker:
        return _reply(scanner_id, "blocked", "Docker CLI is unavailable; no scanner was executed on the host.")
    if lease_hook is None:
        return _reply(scanner_id, "blocked", "A live run lease hook is required before starting a scanner sandbox.")
    if not isinstance(timeout_seconds, (int, float)) or not 0.05 <= timeout_seconds <= 300:
        return _reply(scanner_id, "blocked", "Scanner timeout must be between 0.05 and 300 seconds.")
    if cancel_event is not None and cancel_event.is_set():
        return _reply(scanner_id, "cancelled", "Scanner was cancelled before container creation.")
    name = "vibeaudit-" + uuid.uuid4().hex
    try:
        argv = build_scanner_command(scanner_id, source_dir, image_pins=image_pins, container_name=name,
                                     docker_binary=docker, offline_db_dir=offline_db_dir)
        await asyncio.wait_for(lease_hook(), timeout=min(timeout_seconds, CONTROL_TIMEOUT_SECONDS))
    except (Exception, asyncio.CancelledError):
        return _reply(scanner_id, "blocked", "Scanner prerequisites or run lease were not satisfied; no container was created.")
    if cancel_event is not None and cancel_event.is_set():
        return _reply(scanner_id, "cancelled", "Scanner was cancelled before container creation.")
    runner = process_runner or _default_runner
    env = _client_env()
    docker_prefix = argv[:3]
    proc, readers, wait_task = None, [], None
    stdout, stderr, budget = bytearray(), bytearray(), [0]
    exceeded = asyncio.Event()
    status, reason, code = "execution_error", "Scanner did not complete.", None
    deadline = time.monotonic() + timeout_seconds
    try:
        proc = await asyncio.wait_for(runner(argv, env=env, cwd=str(Path(__file__).parent)), timeout=min(timeout_seconds, CONTROL_TIMEOUT_SECONDS))
        readers = [asyncio.create_task(_collect(stream, output, budget, exceeded))
                   for stream, output in [(proc.stdout, stdout), (proc.stderr, stderr)]]
        wait_task = asyncio.create_task(proc.wait())
        while True:
            if cancel_event is not None and cancel_event.is_set():
                status, reason = "cancelled", "Scanner cancelled; container termination was requested."
                break
            if exceeded.is_set():
                status, reason = "incomplete", "Scanner output exceeded the bounded byte limit; partial output was not accepted."
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                status, reason = "incomplete", "Scanner exceeded its wall-clock deadline."
                break
            try:
                await asyncio.wait_for(lease_hook(), timeout=min(remaining, 0.5))
            except Exception:
                status, reason = "cancelled", "Run lease expired; scanner termination was requested."
                break
            if wait_task.done():
                code = wait_task.result()
                await asyncio.wait_for(asyncio.gather(*readers), timeout=max(0.001, deadline - time.monotonic()))
                if exceeded.is_set():
                    status, reason = "incomplete", "Scanner output exceeded the bounded byte limit; partial output was not accepted."
                else:
                    status, reason = "completed", "Scanner process completed; this does not establish application security."
                break
            await asyncio.wait({wait_task}, timeout=min(0.05, remaining))
    except asyncio.CancelledError:
        status, reason = "cancelled", "Scanner task cancelled; container termination was requested."
    except Exception:
        status, reason = "execution_error", "Scanner process failed; raw stderr was withheld because it may contain source data."
    finally:
        # Docker run's client can disappear while its container continues. Kill,
        # wait and remove the named container independently before reaping CLI.
        cleanup_task = asyncio.create_task(_cleanup(runner, docker_prefix, name, env, force=status != "completed"))
        try:
            cleanup_confirmed = await asyncio.shield(cleanup_task)
        except asyncio.CancelledError:
            cleanup_confirmed = await cleanup_task
        if proc is not None:
            if wait_task is None or not wait_task.done():
                try:
                    proc.kill()
                except (ProcessLookupError, OSError):
                    pass
            try:
                await asyncio.wait_for(proc.wait(), CONTROL_TIMEOUT_SECONDS)
            except (Exception, asyncio.CancelledError):
                cleanup_confirmed = False
        for task in readers + ([wait_task] if wait_task is not None else []):
            if not task.done():
                task.cancel()
        await asyncio.gather(*readers, *([wait_task] if wait_task is not None else []), return_exceptions=True)
    if not cleanup_confirmed:
        return _reply(scanner_id, "outcome_unknown", "Container termination/removal could not be confirmed; do not resume automatically.", cleanup_confirmed=False, container_name=name)
    fields = {"exit_code": code, "output_bytes": budget[0], "image": image_pins.get(scanner_id),
              "output_sha256": hashlib.sha256(bytes(stdout)).hexdigest(), "control_plane_test": process_runner is not None,
              "simulated": process_runner is not None}
    if status != "completed":
        return _reply(scanner_id, status, reason, **fields)
    try:
        findings, gaps = _parse(scanner_id, bytes(stdout), code)
    except Exception:
        return _reply(scanner_id, "execution_error", "Scanner exit status or output schema was invalid; raw output was withheld.", **fields)
    status = "incomplete" if scanner_id == "semgrep" and gaps else "completed"
    return _reply(scanner_id, status, reason, findings=findings, gaps=gaps, **fields)


def sandbox_capabilities(image_pins=None):
    pins = image_pins or {}
    detected = shutil.which("docker") is not None
    result = []
    for scanner_id in _REPOSITORIES:
        try:
            _image(scanner_id, pins)
            pinned = True
        except SandboxBlocked:
            pinned = False
        result.append({"id": scanner_id, "available": False, "sandbox_implemented": True,
                       "docker_cli_detected": detected, "image_digest_configured": pinned,
                       "integration_verified": False, "status": "blocked_missing_prerequisites" if not detected or not pinned else "configured_unverified",
                       "detail": "Optional offline Docker executor implemented; real image/daemon execution has not been validated on this host."})
    return result
