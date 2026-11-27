"""Bounded, read-only source intake. Repository content is data, never instructions.

This is a best-effort local snapshot, not a filesystem sandbox or an exhaustive
secret scanner. Concurrent hostile filesystem mutation needs OS isolation.
"""
from __future__ import annotations

import errno
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
# Every snapshot's first capability limit, after the operator's notice when literals were left unredacted.
BOUNDED = "Snapshot is bounded; route extraction and secret redaction are heuristic, not exhaustive. Repository code was not executed."
_TEXT_SUFFIXES = {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".json", ".yaml", ".yml", ".toml", ".md", ".html", ".css", ".sql", ".txt", ".go", ".rs", ".java", ".cs", ".php", ".rb", ".tf", ".sh", ".ps1"}
_SECRET_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".kdbx", ".crt", ".cer"}
_SECRET_NAMES = {"credentials", "credentials.json", "credential.json", "secrets.json", "secrets.yaml", "secrets.yml", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", ".npmrc", ".pypirc", ".netrc", "service-account.json", "service_account.json"}
_PRIVATE_KEY = re.compile(r"-----BEGIN [^-\r\n]*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END [^-\r\n]*PRIVATE KEY(?: BLOCK)?-----|\Z)", re.S)
# Short forms count only as a whole name segment (DB_PASS, smtp-pwd), so bypass or compass stay readable.
_SECRET_WORDS = (r"api[_-]?key|password|passwd|secret|access[_-]?token|auth[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key"
                 r"|(?<![a-z])(?:pass(?:[_-]?phrase)?|pwd)(?![a-z])|(?:signing|encryption|hmac|master|webhook|access)[_-]?key")
# SECRET_KEY / SECRET_KEY_BASE style names; password_hash and similar code stay readable for reviewers.
_KEY_SUFFIX = r"(?:[_-]?key(?:[_-]?base)?)?"
# Every pattern stays linear in the snapshot size; hostile sources can be megabytes of one token.
# A name starts at a word start, or the lazy name scan would restart at every letter of a long word.
_SECRET_ASSIGNMENT = re.compile(rf'''(?im)(["']?(?:(?<![A-Za-z0-9_])[A-Za-z0-9_]*?(?:{_SECRET_WORDS}|token){_KEY_SUFFIX})["']?\s*[:=]\s*)(["'])([^\r\n]*?)(\2)''')
# Leading whitespace stays on the key's own line, or every blank line would rescan the rest of the run.
# A YAML list item (docker-compose "- DB_PASSWORD=x", or quoted "- 'DB_PASSWORD=x'") counts as a line start, but only
# with "=": "- password: at least 8 characters" is a Markdown list about one. Only the quote opened before the name
# closes the value, and a # inside the quotes is part of it. Group 2 is the list marker, group 3 that quote.
_LINE_KEY = r"""^([^\S\n]*(?:(-)[^\S\n]+)?(["'])?[A-Za-z0-9_.-]*?"""
_SEPARATOR = r"""(?(2)\s*=|\s*[:=])\s*"""
_UNQUOTED_SECRET = re.compile(rf"""(?im){_LINE_KEY}(?:{_SECRET_WORDS}){_KEY_SUFFIX}{_SEPARATOR})((?(3)(?:(?!\3)[^\r\n])+|[^\r\n#]+))""")
# A bare token name is also code ("token: string", "token = None", "token = req.token") and configuration
# ("token: 2024-01-01", "token: 1.2.3-rc1"), so its unquoted value counts only when it reads as a credential: one run
# of token characters holding both a letter and a digit, not a version number, ending the line or the quote.
_UNQUOTED_TOKEN = re.compile(rf"""(?im){_LINE_KEY}token{_SEPARATOR})(?=[A-Za-z0-9._~+/=-]*[0-9])(?=[A-Za-z0-9._~+/=-]*[A-Za-z])"""
                             r"""(?!v?[0-9]+(?:\.[0-9]+)+(?:[-+][A-Za-z0-9.]*)?(?![A-Za-z0-9._~+/=-]))"""
                             r"""([A-Za-z0-9._~+/=-]{8,})(?=(?(3)\3|[^\S\r\n]*(?:#|\r?$)))""")
# Shell, Dockerfile and batch declarations hold literal values, so any secret-like name counts.
# The lookahead finds the word once; the name is then consumed without backtracking.
_ENV_DECLARATION = re.compile(rf"(?im)^([^\S\n]*(?:export|ENV|ARG|set|setx)\s+(?=[A-Za-z0-9_.-]*?(?:{_SECRET_WORDS}|token))[A-Za-z0-9_.-]*+\s*=\s*)([^\r\n#]+)")
_DEFINE_SECRET = re.compile(rf'''(?i)(\bdefine\(\s*(["'])(?=[A-Za-z0-9_-]*?(?:{_SECRET_WORDS}|token))[A-Za-z0-9_-]*+\2\s*,\s*)(["'])([^\r\n]*?)(\3)''')
_CONNECTION_PASSWORD = re.compile(r'''(?im)((?:^|[;"'])[^\S\n]*(?:password|pwd|accountkey|sharedaccesskey)\s*=\s*)([^;"'\r\n]+)''')
_AUTH_FIELD = re.compile(r'''(?i)(["'](?:auth|identitytoken|registrytoken)["']\s*:\s*)(["'])([^"'\r\n]*)(\2)''')
# A token character before the match is ruled out first, so a long run of them is scanned once,
# not once per "eyJ" or "sk-" inside it.
_KNOWN_SECRET = re.compile(r"(?<![A-Za-z0-9_-])(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}|[sr]k_(?:live|test)_[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|xox[abposr]-[A-Za-z0-9-]{10,}|AKIA[A-Z0-9]{16}|AIza[0-9A-Za-z_-]{35}|npm_[A-Za-z0-9]{36}|hf_[A-Za-z0-9]{30,}|ASIA[A-Z0-9]{16}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|ya29\.[A-Za-z0-9_-]{20,}|shp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}|dop_v1_[a-f0-9]{64}|pypi-[A-Za-z0-9_-]{50,}|hooks\.slack\.com/services/[A-Za-z0-9_/-]{20,}|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b")
_BEARER = re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}")
# Other Authorization schemes ("Basic dXNlcjpwYXNz", "Token abc") only next to the header name: alone, "Basic" is prose.
# The name may carry a Proxy-, X- or HTTP_ (CGI and Django's META) prefix; another word glued to it is a different name.
_AUTH_HEADER = re.compile(r"""(?i)((?<![A-Za-z0-9_-])(?:proxy[_-]|x[_-]|http_)?authorization["']?\s*[:=,]\s*["']?[^\S\r\n]*(?:basic|token|apikey)[^\S\r\n]+)[A-Za-z0-9._~+/=-]{4,}""")
# Digest carries its secrets as parameters (username="a", response="<hash>"), so all of them go: to the end of the
# line, or of the quoted value the header sits in (group 2), skipping escaped quotes inside it.
_AUTH_DIGEST = re.compile(r"""(?i)((?<![A-Za-z0-9_-])(?:proxy[_-]|x[_-]|http_)?authorization["']?\s*[:=,]\s*(["'])?[^\S\r\n]*digest[^\S\r\n]+)"""
                          r"""((?(2)(?:\\.|(?!\2)[^\\\r\n])+|[^\r\n]+))""")
# Any scheme: postgres://, mongodb+srv://, redis://:password@ and so on. The bounded scheme
# keeps runs like a.a.a.a from being rescanned after every dot.
_URL_AUTH = re.compile(r"(?i)\b([a-z][a-z0-9+.-]{0,63}://)[^/\s:@]*:[^/\s@]+@")


def redact_text(text: str, keep: frozenset[str] = frozenset()) -> str:
    """Conservative literal redaction; does not promise to find every secret.

    keep holds values the operator declared synthetic test credentials: a match whose whole value is one of them
    stays readable. A value that only contains one is still redacted. A blank value has nothing to hide: the
    connection-string form otherwise matches just the space before a kept, quoted value."""
    def kept(value: str, replacement: str, original: str) -> str:
        return original if not value.strip() or value.strip().strip("'\";,") in keep else replacement

    text = _PRIVATE_KEY.sub("[REDACTED_PRIVATE_KEY]", text)
    text = _SECRET_ASSIGNMENT.sub(lambda m: kept(m[3], m[1] + m[2] + "[REDACTED]" + m[4], m[0]), text)
    text = _UNQUOTED_SECRET.sub(lambda m: kept(m[4], m[1] + "[REDACTED]", m[0]), text)
    text = _UNQUOTED_TOKEN.sub(lambda m: kept(m[4], m[1] + "[REDACTED]", m[0]), text)
    text = _ENV_DECLARATION.sub(lambda m: kept(m[2], m[1] + "[REDACTED]", m[0]), text)
    text = _DEFINE_SECRET.sub(lambda m: kept(m[4], m[1] + m[3] + "[REDACTED]" + m[5], m[0]), text)
    text = _CONNECTION_PASSWORD.sub(lambda m: kept(m[2], m[1] + "[REDACTED]", m[0]), text)
    text = _AUTH_FIELD.sub(lambda m: kept(m[3], m[1] + m[2] + "[REDACTED]" + m[4], m[0]), text)
    text = _KNOWN_SECRET.sub(lambda m: kept(m[0], "[REDACTED_TOKEN]", m[0]), text)
    text = _BEARER.sub(lambda m: kept(m[0][len(m[1]):], m[1] + "[REDACTED]", m[0]), text)
    text = _AUTH_HEADER.sub(lambda m: kept(m[0][len(m[1]):], m[1] + "[REDACTED]", m[0]), text)
    text = _AUTH_DIGEST.sub(lambda m: kept(m[3], m[1] + "[REDACTED]", m[0]), text)
    return _URL_AUTH.sub(lambda m: m[1] + "[REDACTED]@", text)


def _linklike(path: Path) -> bool:
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


# The stat failures that mean "nothing is there": Path.is_dir answered False for these and raised any other until
# Python 3.14, which answers False for every OSError.
_MISSING_ERRNOS = frozenset({errno.ENOENT, errno.ENOTDIR, errno.EBADF, errno.ELOOP})
# ERROR_NOT_READY, ERROR_INVALID_NAME, ERROR_CANT_RESOLVE_FILENAME.
_MISSING_WINERRORS = frozenset({21, 123, 1921})


def _is_directory(path: Path) -> bool:
    """Whether path is a directory, False when nothing is there; a path that cannot be examined raises OSError."""
    try:
        return stat.S_ISDIR(path.stat().st_mode)
    except OSError as exc:
        if exc.errno in _MISSING_ERRNOS or getattr(exc, "winerror", None) in _MISSING_WINERRORS:
            return False
        raise


def _safe_ancestors(path: Path) -> bool:
    return all(not _linklike(item) for item in (path, *path.parents))


def _source_name(path: Path) -> bool:
    """Whether the snapshot reads a file of this name: a text suffix, or a build file named by convention."""
    return path.suffix.lower() in _TEXT_SUFFIXES or path.name.lower() in {"dockerfile", "makefile"}


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


def snapshot_source(path: str, keep: frozenset[str] = frozenset()) -> dict:
    if not path or not isinstance(path, str):
        raise ValueError("source_path must identify an existing source directory")
    root = Path(os.path.abspath(path))
    try:
        if not _is_directory(root) or not _safe_ancestors(root):
            raise ValueError("Source root must be a real directory without symlink/reparse ancestors")
    except OSError:
        raise ValueError("Source directory is not accessible") from None
    files: list[dict] = []
    gaps: list[str] = []
    routes: list[dict] = []
    total_bytes = 0
    entries_seen = 0
    stack = [(root, 0)]

    # Source the snapshot could not read is a gap: the review did not cover it, and that includes a file named as source
    # that is a link or is not UTF-8 text. What it leaves out by design (other links, excluded and secret paths,
    # redacted literals) is left out, a limitation.
    noted: list[str] = []

    def gap(message: str) -> None:
        if len(gaps) < MAX_GAPS:
            gaps.append(message)
        elif len(gaps) == MAX_GAPS:
            gaps.append("Additional omitted-file gaps suppressed at bounded gap limit.")

    def left_out(message: str) -> None:
        if len(noted) < MAX_GAPS:
            noted.append(message)
        elif len(noted) == MAX_GAPS:
            noted.append("Additional exclusions suppressed at bounded limit.")

    while stack:
        directory, depth = stack.pop()
        if entries_seen >= MAX_ENTRIES or len(files) >= MAX_FILES or total_bytes >= MAX_TOTAL_BYTES:
            gap("Snapshot limit reached; remaining source was not inspected.")
            break
        try:
            if not _safe_ancestors(directory):
                # Found safe when listed, it is not now: it changed during the walk and was not read, a gap.
                gap("Skipped linked/reparse directory.")
                continue
            with os.scandir(directory) as iterator:
                entries = list(itertools.islice(iterator, MAX_ENTRIES - entries_seen + 1))  # pragma: no mutate (one entry past the limit only detects truncation)
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
                    # A link named as source stands for source nobody read, a gap; any other link is left out by design.
                    if _source_name(candidate):
                        gap(f"Skipped symlink/reparse path: {relative}")
                    else:
                        left_out(f"Skipped symlink/reparse path: {relative}")
                    continue
                if entry.is_dir(follow_symlinks=False):  # pragma: no mutate (a symlink was refused just above)
                    if entry.name.lower() in _SKIP_DIRS or _secret_path(candidate):
                        left_out(f"Excluded directory: {relative}")
                    elif depth >= MAX_DEPTH:
                        gap(f"Depth limit: {relative}")
                    else:
                        stack.append((candidate, depth + 1))
                    continue
                if _secret_path(candidate):
                    left_out(f"Secret-designated file excluded without reading: {relative}")
                    continue
                if not _source_name(candidate):
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
                    raw = handle.read(MAX_FILE_BYTES + 1)  # pragma: no mutate (one byte past the limit detects growth; reading more changes nothing)
                    after = os.fstat(handle.fileno())
                if len(raw) > MAX_FILE_BYTES or total_bytes + len(raw) > MAX_TOTAL_BYTES:
                    gap(f"Growing/oversized file omitted: {relative}")
                    continue
                if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                    gap(f"File changed during read: {relative}")
                    continue
                # Named as source but not readable as UTF-8 text (UTF-16 carries NUL bytes): source nobody read, a gap.
                if b"\0" in raw:
                    gap(f"Binary content omitted: {relative}")
                    continue
                try:
                    original = raw.decode("utf-8-sig")  # pragma: no mutate (codec names are case-insensitive)
                except UnicodeDecodeError:
                    gap(f"Non-UTF-8 file omitted: {relative}")
                    continue
                content = redact_text(original, keep)
                if content != original:
                    left_out(f"Secret-like literals redacted: {relative}")
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
    limitations = [BOUNDED, *noted]
    if keep:
        found = sum(any(item in f["content"] for f in files) for item in keep)
        # The operator's own choice, so no gap; but first and outside the limit: the readers of the report must see
        # that redaction was relaxed.
        limitations.insert(0, f"Operator-declared test literals left unredacted: {found} of {len(keep)} appear in the snapshot")
    return {"digest": digest, "files": files, "gaps": gaps, "routes": routes[:500], "bytes_read": total_bytes, "limitations": limitations}
