"""Bounded, read-only source intake. Repository content is data, never instructions.

This is a best-effort local snapshot, not a filesystem sandbox or an exhaustive
secret scanner. Concurrent hostile filesystem mutation needs OS isolation.
"""
from __future__ import annotations

import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import stat

MAX_FILES = 120
MAX_FILE_BYTES = 64 * 1024
MAX_TOTAL_BYTES = 384 * 1024
MAX_ENTRIES = 5000
MAX_DEPTH = 12
MAX_GAPS = 256
_SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", "dist", "build", ".next", ".cache", "__pycache__", ".idea", ".vscode", ".ssh", ".aws", ".azure", ".config", ".docker", ".kube", ".gnupg", ".terraform"}
_TEXT_SUFFIXES = {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".json", ".yaml", ".yml", ".toml", ".md", ".html", ".css", ".sql", ".txt", ".go", ".rs", ".java", ".cs", ".php", ".rb", ".tf", ".sh", ".ps1"}
_SECRET_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".kdbx", ".crt", ".cer"}
_SECRET_NAMES = {"credentials", "credentials.json", "credential.json", "secrets.json", "secrets.yaml", "secrets.yml", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", ".npmrc", ".pypirc", ".netrc", "service-account.json", "service_account.json"}
_PRIVATE_KEY = re.compile(r"-----BEGIN [^-\r\n]*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END [^-\r\n]*PRIVATE KEY(?: BLOCK)?-----|\Z)", re.S)
_SECRET_WORDS = r"api[_-]?key|password|passwd|secret|access[_-]?token|auth[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key"
# SECRET_KEY / SECRET_KEY_BASE style names; password_hash and similar code stay readable for reviewers.
_KEY_SUFFIX = r"(?:[_-]?key(?:[_-]?base)?)?"
# Every pattern stays linear in the snapshot size; hostile sources can be megabytes of one token.
# A name starts at a word start, or the lazy name scan would restart at every letter of a long word.
_SECRET_ASSIGNMENT = re.compile(rf'''(?im)(["']?(?:(?<![A-Za-z0-9_])[A-Za-z0-9_]*?(?:{_SECRET_WORDS}|token){_KEY_SUFFIX})["']?\s*[:=]\s*)(["'])([^\r\n]*?)(\2)''')
# Leading whitespace stays on the key's own line, or every blank line would rescan the rest of the run.
_UNQUOTED_SECRET = re.compile(rf"(?im)^([^\S\n]*[A-Za-z0-9_.-]*?(?:{_SECRET_WORDS}){_KEY_SUFFIX}\s*[:=]\s*)([^\r\n#]+)")
# Shell, Dockerfile and batch declarations hold literal values, so any secret-like name counts.
# The lookahead finds the word once; the name is then consumed without backtracking.
_ENV_DECLARATION = re.compile(rf"(?im)^([^\S\n]*(?:export|ENV|ARG|set|setx)\s+(?=[A-Za-z0-9_.-]*?(?:{_SECRET_WORDS}|token))[A-Za-z0-9_.-]*+\s*=\s*)([^\r\n#]+)")
_DEFINE_SECRET = re.compile(rf'''(?i)(\bdefine\(\s*(["'])(?=[A-Za-z0-9_-]*?(?:{_SECRET_WORDS}|token))[A-Za-z0-9_-]*+\2\s*,\s*)(["'])([^\r\n]*?)(\3)''')
_CONNECTION_PASSWORD = re.compile(r'''(?im)((?:^|[;"'])[^\S\n]*(?:password|pwd)\s*=\s*)([^;"'\r\n]+)''')
_AUTH_FIELD = re.compile(r'''(?i)(["'](?:auth|identitytoken|registrytoken)["']\s*:\s*)(["'])([^"'\r\n]*)(\2)''')
_KNOWN_SECRET = re.compile(r"\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}|[sr]k_(?:live|test)_[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|xox[abposr]-[A-Za-z0-9-]{10,}|AKIA[A-Z0-9]{16}|AIza[0-9A-Za-z_-]{35}|npm_[A-Za-z0-9]{36}|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b")
_BEARER = re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}")
# Any scheme: postgres://, mongodb+srv://, redis://:password@ and so on. The bounded scheme
# keeps runs like a.a.a.a from being rescanned after every dot.
_URL_AUTH = re.compile(r"(?i)\b([a-z][a-z0-9+.-]{0,63}://)[^/\s:@]*:[^/\s@]+@")


def redact_text(text: str) -> str:
    """Conservative literal redaction; does not promise to find every secret."""
    text = _PRIVATE_KEY.sub("[REDACTED_PRIVATE_KEY]", text)
    text = _SECRET_ASSIGNMENT.sub(lambda m: m[1] + m[2] + "[REDACTED]" + m[4], text)
    text = _UNQUOTED_SECRET.sub(lambda m: m[1] + "[REDACTED]", text)
    text = _ENV_DECLARATION.sub(lambda m: m[1] + "[REDACTED]", text)
    text = _DEFINE_SECRET.sub(lambda m: m[1] + m[3] + "[REDACTED]" + m[5], text)
    text = _CONNECTION_PASSWORD.sub(lambda m: m[1] + "[REDACTED]", text)
    text = _AUTH_FIELD.sub(lambda m: m[1] + m[2] + "[REDACTED]" + m[4], text)
    text = _KNOWN_SECRET.sub("[REDACTED_TOKEN]", text)
    text = _BEARER.sub(lambda m: m[1] + "[REDACTED]", text)
    return _URL_AUTH.sub(lambda m: m[1] + "[REDACTED]@", text)


def _linklike(path: Path) -> bool:
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _safe_ancestors(path: Path) -> bool:
    return all(not _linklike(item) for item in (path, *path.parents))


def _secret_path(path: Path) -> bool:
    name = path.name.lower()
    return (name.startswith(".env") or name in _SECRET_NAMES
            or path.suffix.lower() in _SECRET_SUFFIXES
            or any(word in name for word in ("credentials", "service-account", "service_account", "private-key", "private_key"))
            or name.startswith(("secret.", "secrets.")))


def _routes(path: str, content: str) -> list[dict]:
    found: list[dict] = []
    # Deliberately heuristic: decorators and literal Express-style routes only.
    patterns = [
        re.compile(r"@\w+(?:\.\w+)*\.(get|post|put|patch|delete|head|options|route)\(\s*['\"]([^'\"]{1,256})['\"]", re.I),
        re.compile(r"\b(?:app|router|server)\.(get|post|put|patch|delete|head|options|all)\(\s*['\"]([^'\"]{1,256})['\"]", re.I),
    ]
    for pattern in patterns:
        for match in pattern.finditer(content):
            method = match[1].upper()
            found.append({"method": method if method not in {"ROUTE", "ALL"} else "UNKNOWN", "path": match[2], "file": path, "line": content.count("\n", 0, match.start()) + 1, "confidence": "heuristic"})
    if path.endswith(("route.ts", "route.js")) and "/app/" in "/" + path:
        route_parts = path.split("app/", 1)[1].split("/")[:-1]
        route = "/" + "/".join(route_parts)
        for match in re.finditer(r"export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b", content):
            found.append({"method": match[1], "path": route, "file": path, "line": content.count("\n", 0, match.start()) + 1, "confidence": "heuristic"})
    return found[:200]


def snapshot_source(path: str) -> dict:
    if not path or not isinstance(path, str):
        raise ValueError("source_path must identify an existing source directory")
    root = Path(os.path.abspath(path))
    try:
        if not root.is_dir() or not _safe_ancestors(root):
            raise ValueError("Source root must be a real directory without symlink/reparse ancestors")
    except OSError:
        raise ValueError("Source directory is not accessible") from None
    files: list[dict] = []
    gaps: list[str] = []
    routes: list[dict] = []
    total_bytes = 0
    entries_seen = 0
    stack = [(root, 0)]

    def gap(message: str) -> None:
        if len(gaps) < MAX_GAPS:
            gaps.append(message)
        elif len(gaps) == MAX_GAPS:
            gaps.append("Additional omitted-file gaps suppressed at bounded gap limit.")

    while stack:
        directory, depth = stack.pop()
        if entries_seen >= MAX_ENTRIES or len(files) >= MAX_FILES or total_bytes >= MAX_TOTAL_BYTES:
            gap("Snapshot limit reached; remaining source was not inspected.")
            break
        try:
            if not _safe_ancestors(directory):
                gap("Skipped linked/reparse directory.")
                continue
            with os.scandir(directory) as iterator:
                entries = list(itertools.islice(iterator, MAX_ENTRIES - entries_seen + 1))
            if entries_seen + len(entries) > MAX_ENTRIES:
                gap("Directory entry limit reached; directory truncated.")
                entries = entries[:MAX_ENTRIES - entries_seen]
            entries_seen += len(entries)
        except OSError:
            gap("Unreadable directory omitted.")
            continue
        for entry in sorted(entries, key=lambda e: e.name):
            candidate = Path(entry.path)
            relative = candidate.relative_to(root).as_posix()
            try:
                if _linklike(candidate):
                    gap(f"Skipped symlink/reparse path: {relative}")
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if entry.name.lower() in _SKIP_DIRS or _secret_path(candidate):
                        gap(f"Excluded directory: {relative}")
                    elif depth >= MAX_DEPTH:
                        gap(f"Depth limit: {relative}")
                    else:
                        stack.append((candidate, depth + 1))
                    continue
                if _secret_path(candidate):
                    gap(f"Secret-designated file excluded without reading: {relative}")
                    continue
                if candidate.suffix.lower() not in _TEXT_SUFFIXES and candidate.name.lower() not in {"dockerfile", "makefile"}:
                    continue
                info = candidate.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink > 1:
                    gap(f"Non-regular or hardlinked file omitted: {relative}")
                    continue
                if len(files) >= MAX_FILES or info.st_size > MAX_FILE_BYTES or total_bytes + info.st_size > MAX_TOTAL_BYTES:
                    gap(f"File/byte limit omitted: {relative}")
                    continue
                if not _safe_ancestors(candidate):
                    gap(f"Path changed before read: {relative}")
                    continue
                flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(candidate, flags)
                with os.fdopen(descriptor, "rb") as handle:
                    before = os.fstat(handle.fileno())
                    if (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino) or before.st_nlink > 1:
                        gap(f"File changed before read: {relative}")
                        continue
                    raw = handle.read(MAX_FILE_BYTES + 1)
                    after = os.fstat(handle.fileno())
                if len(raw) > MAX_FILE_BYTES or total_bytes + len(raw) > MAX_TOTAL_BYTES:
                    gap(f"Growing/oversized file omitted: {relative}")
                    continue
                if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                    gap(f"File changed during read: {relative}")
                    continue
                if b"\0" in raw:
                    gap(f"Binary content omitted: {relative}")
                    continue
                try:
                    original = raw.decode("utf-8-sig")
                except UnicodeDecodeError:
                    gap(f"Non-UTF-8 file omitted: {relative}")
                    continue
                content = redact_text(original)
                if content != original:
                    gap(f"Secret-like literals redacted: {relative}")
                files.append({"path": relative, "content": content, "sha256": hashlib.sha256(raw).hexdigest(), "redacted": content != original, "content_sha256": hashlib.sha256(content.encode()).hexdigest()})
                total_bytes += len(raw)
                routes.extend(_routes(relative, content))
            except OSError:
                gap(f"Unreadable file omitted: {relative}")
    files.sort(key=lambda item: item["path"])
    material = [{"path": f["path"], "sha256": f["sha256"], "content_sha256": f["content_sha256"]} for f in files]
    digest = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if not files:
        gap("No eligible source files were included.")
    return {"digest": digest, "files": files, "gaps": gaps, "routes": routes[:500], "bytes_read": total_bytes,
            "limitations": ["Snapshot is bounded; route extraction and secret redaction are heuristic, not exhaustive. Repository code was not executed."]}
