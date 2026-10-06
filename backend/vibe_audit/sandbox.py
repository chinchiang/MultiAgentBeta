"""Path, bound and result-parsing helpers for the isolated white-box scanner path.

Scanner execution itself lives in the isolated worker (WorkerRuntime.run_scanner
→ execute_tool → worker_entry); this module never spawns processes or talks to
Docker. Image digests must be provisioned in trusted harness configuration, and
scanner output is parsed into bounded findings without source snippets.
"""
from __future__ import annotations

import functools
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath

MAX_FILES = 20_000
MAX_SOURCE_BYTES = 128 * 1024 * 1024


class SandboxBlocked(ValueError):
    """A scanner prerequisite or input is outside the trusted bounds."""


def _is_link(path):
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _safe_path(value, *, directory=True):
    # An empty string would silently resolve to the process working directory.
    if not isinstance(value, str) or not value:
        raise SandboxBlocked("A non-empty scanner path is required.")
    path = Path(value).absolute()
    if any(c in str(path) for c in [",", "\r", "\n", "\x00"]):
        raise SandboxBlocked("Mount path contains unsupported characters.")
    if path == Path(path.anchor):
        raise SandboxBlocked("Filesystem roots cannot be scanner mounts.")
    # Existence and type first: the link walk below lstats every ancestor and
    # must not crash on a missing path with the wrong exception type.
    if (directory and not path.is_dir()) or (not directory and not path.is_file()):
        raise SandboxBlocked("Required scanner input path is missing or has the wrong type.")
    for part in (path, *path.parents):
        if _is_link(part):
            raise SandboxBlocked("Symlinks and Windows reparse points cannot be scanner mounts.")
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


def _safe_text(value, limit=240):
    value = str(value)[:limit]
    value = re.sub(r"[\x00-\x1f\x7f]", "?", value)
    for key, secret in os.environ.items():
        if key.startswith("VIBEAUDIT_") and len(secret) >= 6:
            value = value.replace(secret, "[REDACTED]")
    return value


# The scanner runs on hostile source with the raw staging copy (secret files included) mounted. Its JSON is a claim,
# like a black-box worker's: a rule ID is imported only when the harness can name it from a list it owns (its Semgrep
# rule file, the pinned gitleaks default rules, the provisioned OSV database), and titles come from the harness, not
# from the container, so code running inside the container cannot pass file contents on as finding text or rule IDs.
_FIXED_TITLES = {"gitleaks": "Potential secret exposure",
                 "osv": "Dependency vulnerability reported by the provisioned offline database"}
UNRECOGNIZED = "unrecognized-rule"
_FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


def _semgrep_messages():
    """Rule ID -> message from the harness's own rule file (fixtures/semgrep-rules.yml)."""
    text = (_FIXTURES / "semgrep-rules.yml").read_text(encoding="utf-8")
    messages, current = {}, None
    for line in text.splitlines():
        match = re.match(r"\s*-\s+id:\s*(\S+)\s*$", line)
        if match:
            current = match[1]
            continue
        match = re.match(r"\s+message:\s*(.+?)\s*$", line)
        if match and current:
            messages[current] = match[1]
    return messages


def gitleaks_rule_ids():
    """The pinned image's default rule IDs plus any rule the harness's own gitleaks.toml adds."""
    listed = (_FIXTURES / "gitleaks-default-rule-ids.txt").read_text(encoding="utf-8").splitlines()
    added = re.findall(r'(?m)^\s*id\s*=\s*"([^"]+)"\s*$', (_FIXTURES / "gitleaks.toml").read_text(encoding="utf-8"))
    return frozenset(line.strip() for line in listed if line.strip() and not line.startswith("#")) | frozenset(added)


def osv_database_ids(offline_db_dir):
    """Vulnerability IDs in the provisioned offline databases: each all.zip holds one <ID>.json per record."""
    ids = frozenset()
    for archive in sorted(Path(offline_db_dir).glob("osv-scanner/*/all.zip")):
        info = archive.stat()
        ids |= _archive_ids(str(archive), info.st_size, info.st_mtime_ns)
    return ids


@functools.lru_cache(maxsize=8)
def _archive_ids(path, size, mtime_ns):
    import zipfile
    with zipfile.ZipFile(path) as bundle:
        return frozenset(PurePosixPath(name).name[:-5] for name in bundle.namelist() if name.endswith(".json"))


def _trusted_rule(scanner_id, rule, known):
    """The rule ID the harness recognizes and the title it writes for it, ignoring any text the scanner returned."""
    rule = str(rule)
    if scanner_id == "semgrep":
        # Semgrep prefixes a local rule's ID with its config path (for example inputs.rules.<id>).
        match = next((rid for rid in known if rule == rid or rule.endswith("." + rid)), None)
        return (match, known[match]) if match else (UNRECOGNIZED, "Semgrep finding from a rule outside the harness rule set")
    return (rule if rule in known else UNRECOGNIZED), _FIXED_TITLES[scanner_id]


def _finding(scanner_id, rule, path, line, known=()):
    from .snapshot import redact_text
    safe_path = _safe_text(path)
    if safe_path.startswith("/src/"):
        safe_path = safe_path[5:]
    rule_id, title = _trusted_rule(scanner_id, rule, known)
    # The upper bound on line is the staged file's length, which only the controller can check (service._scan_source).
    return {"scanner_id": scanner_id, "rule_id": rule_id, "file": redact_text(safe_path),
            "line": line if type(line) is int and line > 0 else None,
            "title": title, "state": "corroborated_static"}


def _parse(scanner_id, output, exit_code, osv_ids=frozenset()):
    """Import one scanner's JSON. osv_ids are the provisioned database's IDs; an OSV ID outside them is unrecognized."""
    if exit_code not in {0, 1}:
        raise ValueError("scanner exit failure")
    data = json.loads(output)
    findings, gaps = [], []
    if scanner_id == "semgrep":
        if not isinstance(data, dict) or not isinstance(data.get("results"), list):
            raise ValueError("schema")
        messages = _semgrep_messages()
        for row in data["results"][:1000]:
            findings.append(_finding(scanner_id, row["check_id"], row["path"], row.get("start", {}).get("line"), messages))
        if data.get("errors"):
            gaps.append("Semgrep reported analysis errors; affected coverage is incomplete.")
        if not data.get("paths", {}).get("scanned"):
            gaps.append("Semgrep did not provide a non-empty scanned path list.")
    elif scanner_id == "gitleaks":
        if not isinstance(data, list):
            raise ValueError("schema")
        rules = gitleaks_rule_ids()
        for row in data[:1000]:
            # Secret, Match, Entropy, Commit content and source snippets are
            # deliberately discarded even when upstream --redact is enabled.
            findings.append(_finding(scanner_id, row["RuleID"], row["File"], row.get("StartLine"), rules))
    else:
        if not isinstance(data, dict) or not isinstance(data.get("results"), list):
            raise ValueError("schema")
        for source in data["results"][:1000]:
            path = source.get("source", {}).get("path", "")
            for package in source.get("packages", [])[:1000]:
                for vuln in package.get("vulnerabilities", [])[:1000]:
                    findings.append(_finding(scanner_id, vuln["id"], path, None, osv_ids))
                    if len(findings) >= 1000:
                        break
                if len(findings) >= 1000:
                    break
            if len(findings) >= 1000:
                break
        gaps.append("Offline OSV results depend on the supplied database age and ecosystem coverage; commit-level matching is unsupported offline.")
    if len(findings) >= 1000:
        gaps.append("Finding import reached its bounded limit; the full result was not imported.")
    # A finding is a (rule, file, line) fact: the order and repetition the scanner chose carry nothing a reader needs,
    # so neither reaches the run record.
    findings = sorted({json.dumps(f, sort_keys=True): f for f in findings}.values(),
                      key=lambda f: (f["file"], f["line"] or 0, f["rule_id"]))
    unrecognized = sum(f["rule_id"] == UNRECOGNIZED for f in findings)
    if unrecognized:
        gaps.append(f"{unrecognized} {scanner_id} finding(s) named a rule the harness does not recognize; their rule text was not imported.")
    if exit_code == 1 and not findings:
        raise ValueError("nonzero exit with no parsed findings")
    return findings, gaps
