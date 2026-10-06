"""Create bounded private scanner inputs without running repository code."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import uuid

from .snapshot import _safe_ancestors, _linklike

_SKIP = {".git", "node_modules", ".venv", "venv", "__pycache__", ".npm-cache", ".pytest_cache", "dist", "build"}


def _open_regular(path: Path):
    """Anchor each POSIX path component with O_NOFOLLOW, including directories."""
    if os.name!="posix":
        return os.open(path,os.O_RDONLY|getattr(os,"O_BINARY",0)|getattr(os,"O_NOFOLLOW",0))
    parts=path.absolute().parts
    directory=os.open(parts[0],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for component in parts[1:-1]:
            child=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
            os.close(directory)
            directory=child
        return os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory)
    finally:
        os.close(directory)


def stage_source(source_path: str, private_root: str | Path, *, expected_snapshot: dict | None = None,
                 max_files: int = 20000, max_bytes: int = 128 * 1024 * 1024) -> dict:
    source = Path(source_path).absolute()
    private = Path(private_root).absolute()
    if not source.is_dir() or not _safe_ancestors(source):
        raise ValueError("Scanner source must be a real directory without link ancestors")
    private.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not _safe_ancestors(private) or private == source or private.is_relative_to(source):
        raise ValueError("Private scanner staging must be outside the source tree")
    # mkdir's mode is ignored for an existing directory, and it holds every staged secret file.
    os.chmod(private, 0o700)
    target = private / uuid.uuid4().hex
    # 0755 is deliberate: the whitebox worker container (UID 65532) bind-mounts this
    # directory and must traverse it, so host-side privacy rests on the 0700 parent
    # above, not on this copy's own mode. Do not tighten it here.
    target.mkdir(mode=0o755)
    try:
        return _copy_source(source, target, expected_snapshot, max_files, max_bytes)
    except BaseException:
        # A partial copy can already hold secret files; it must not outlive the failed intake.
        remove_private_tree(target)
        raise


def _copy_source(source: Path, target: Path, expected_snapshot: dict | None, max_files: int, max_bytes: int) -> dict:
    entries, total = [], 0
    omitted = []
    for base, dirs, files in os.walk(source, followlinks=False):
        kept = []
        for name in sorted(dirs):
            # Neither scanners nor models see a skipped directory, so the record has to say so.
            if name in _SKIP or _linklike(Path(base) / name):
                omitted.append((Path(base) / name).relative_to(source).as_posix() + "/")
            else:
                kept.append(name)
        dirs[:] = kept
        for name in sorted(files):
            item = Path(base) / name
            relative = item.relative_to(source).as_posix()
            if name in {".semgrepignore", ".gitleaksignore", ".gitleaks.toml", "osv-scanner.toml"}:
                omitted.append(relative)
                continue
            if _linklike(item) or not _safe_ancestors(item):
                omitted.append(relative)
                continue
            info = item.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink > 1:
                omitted.append(relative)
                continue
            if len(entries) >= max_files or total + info.st_size > max_bytes:
                raise ValueError("Scanner source exceeds bounded snapshot limits")
            fd = _open_regular(item)
            with os.fdopen(fd, "rb") as handle:
                before = os.fstat(handle.fileno())
                if (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_size) != (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_size) or before.st_nlink > 1:
                    raise ValueError("Scanner input changed before read")
                content = handle.read(max_bytes - total + 1)
                after = os.fstat(handle.fileno())
            if len(content) + total > max_bytes or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise ValueError("Scanner input changed during read")
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            with destination.open("xb") as output:
                output.write(content)
            destination.chmod(0o444)
            total += len(content)
            entries.append({"path": relative, "sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content)})
    if not entries:
        raise ValueError("Empty scanner staging snapshot")
    entries.sort(key=lambda value: value["path"])
    by_path = {entry["path"]: entry["sha256"] for entry in entries}
    if expected_snapshot:
        for item in expected_snapshot["files"]:
            if by_path.get(item["path"]) != item["sha256"]:
                raise ValueError("Source changed between model intake and scanner snapshot")
    checksum = hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"path": str(target), "digest": checksum, "files": entries, "omitted": omitted, "bytes": total}


def remove_private_tree(path: str | Path) -> bool:
    """Delete a private working copy, including its read-only files; report rather than raise on failure."""
    def writable(function, target, error):
        # Already gone is the outcome we want.
        if isinstance(error, FileNotFoundError):
            return
        os.chmod(target, stat.S_IWRITE)
        function(target)
    try:
        shutil.rmtree(path, onexc=writable)
    except OSError:
        return False
    return True


def discard_staging(record: dict, private_root: str | Path) -> bool:
    """A staged copy holds the repository's secret files for the scanners, so it must not outlive them."""
    root = Path(record["path"])
    if root.parent != Path(private_root).absolute() or not re.fullmatch(r"[0-9a-f]{32}", root.name) or _linklike(root):
        raise ValueError("Refusing to delete a path outside private scanner staging")
    return remove_private_tree(root)


def staged_line_count(record: dict, path: str) -> int | None:
    """Line count of one file of a verified staging copy; None when the record does not list it or it changed."""
    entry = next((item for item in record["files"] if item["path"] == path), None)
    if entry is None:
        return None
    try:
        with os.fdopen(_open_regular(Path(record["path"]) / path), "rb") as handle:
            content = handle.read(entry["bytes"] + 1)
    except OSError:
        return None
    if hashlib.sha256(content).hexdigest() != entry["sha256"]:
        return None
    # A last line without a newline is still a line; one past a trailing newline is allowed too, as editors number it.
    return content.count(b"\n") + 1


def verify_staging(record: dict) -> bool:
    root = Path(record["path"])
    if not _safe_ancestors(root):
        return False
    expected={item["path"] for item in record["files"]}
    actual=set()
    for base, dirs, files in os.walk(root,followlinks=False):
        if any(_linklike(Path(base)/d) for d in dirs):
            return False
        actual.update((Path(base)/name).relative_to(root).as_posix() for name in files)
    if expected!=actual:
        return False
    for item in record["files"]:
        p = root / item["path"]
        if not p.resolve().is_relative_to(root.resolve()) or not _safe_ancestors(p) or not p.is_file() or p.stat().st_nlink>1:
            return False
        if hashlib.sha256(p.read_bytes()).hexdigest() != item["sha256"]:
            return False
    return True
