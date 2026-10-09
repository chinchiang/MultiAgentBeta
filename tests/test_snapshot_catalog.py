"""The exact limits, gap texts and digests of the source snapshot, and the integrity checks of the catalog registry."""
import hashlib
import json
import os
import shutil
import types

import pytest

from vibe_audit import snapshot
from vibe_audit.catalog import CatalogError, CatalogRegistry, default_catalog_root, load_catalogs
from vibe_audit.messages import zh
from vibe_audit.snapshot import _linklike, _routes, _secret_path, redact_text, snapshot_source

LIMITATIONS = ["Snapshot is bounded; route extraction and secret redaction are heuristic, not exhaustive. Repository code was not executed."]


def write(root, relative, content="print('ok')\n"):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    return path


def digest_of(files):
    material = [{"path": f["path"], "sha256": f["sha256"], "content_sha256": f["content_sha256"]} for f in files]
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def gaps_read_in_chinese(result):
    assert all(zh(gap) is not None for gap in result["gaps"]), result["gaps"]


def test_snapshot_is_sorted_hashed_and_summed_exactly(tmp_path):
    write(tmp_path, "b.py", "b = 1\n")
    write(tmp_path, "a/x.py", "x = 1\n")
    result = snapshot_source(str(tmp_path))
    assert [f["path"] for f in result["files"]] == ["a/x.py", "b.py"]
    assert result["files"][1] == {"path": "b.py", "content": "b = 1\n", "sha256": hashlib.sha256(b"b = 1\n").hexdigest(),
                                  "redacted": False, "content_sha256": hashlib.sha256(b"b = 1\n").hexdigest()}
    assert result["digest"] == digest_of(result["files"])
    assert result["routes"] == [] and result["gaps"] == [] and result["bytes_read"] == 12 and result["limitations"] == LIMITATIONS
    (tmp_path / "a" / "nothing").mkdir()
    empty = snapshot_source(str(tmp_path / "a" / "nothing"))
    assert empty["gaps"] == ["No eligible source files were included."] and empty["digest"] == hashlib.sha256(b"[]").hexdigest()
    gaps_read_in_chinese(empty)


def test_snapshot_refusals_name_their_cause(tmp_path):
    for path in ["", None, 5]:
        with pytest.raises(ValueError, match="^source_path must identify an existing source directory$"):
            snapshot_source(path)
    with pytest.raises(ValueError, match="^Source root must be a real directory without symlink/reparse ancestors$"):
        snapshot_source(str(tmp_path / "missing"))
    write(tmp_path, "file.py")
    with pytest.raises(ValueError, match="^Source root must be a real directory without symlink/reparse ancestors$"):
        snapshot_source(str(tmp_path / "file.py"))
    with pytest.raises(ValueError, match="^Source directory is not accessible$"):
        snapshot_source("x" * 5000)


def test_gap_list_is_bounded_with_one_closing_note(tmp_path, monkeypatch):
    monkeypatch.setattr(snapshot, "MAX_GAPS", 3)
    for index in range(5):
        write(tmp_path, f".env.{index}", "NEVER_READ")
    result = snapshot_source(str(tmp_path))
    assert result["gaps"] == [f"Secret-designated file excluded without reading: .env.{index}" for index in range(3)] + \
        ["Additional omitted-file gaps suppressed at bounded gap limit."]
    gaps_read_in_chinese(result)


@pytest.mark.parametrize("limit,value", [("MAX_FILES", 1), ("MAX_TOTAL_BYTES", 12), ("MAX_ENTRIES", 2)])
def test_each_exhausted_limit_stops_the_walk_with_a_gap(tmp_path, monkeypatch, limit, value):
    monkeypatch.setattr(snapshot, limit, value)
    write(tmp_path, "a.py", "a = 1\n" * 2)
    write(tmp_path, "sub/b.py", "b = 1\n")
    result = snapshot_source(str(tmp_path))
    assert [f["path"] for f in result["files"]] == ["a.py"]
    assert result["gaps"] == ["Snapshot limit reached; remaining source was not inspected."]
    gaps_read_in_chinese(result)


def test_directory_entries_are_truncated_only_past_the_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(snapshot, "MAX_ENTRIES", 3)
    for name in "abc":
        write(tmp_path, f"{name}.py")
    assert snapshot_source(str(tmp_path))["gaps"] == []
    for name in "de":
        write(tmp_path, f"{name}.py")
    result = snapshot_source(str(tmp_path))
    assert len(result["files"]) == 3 and result["gaps"] == ["Directory entry limit reached; directory truncated."]
    gaps_read_in_chinese(result)


def test_depth_limit_and_excluded_directories(tmp_path, monkeypatch):
    monkeypatch.setattr(snapshot, "MAX_DEPTH", 1)
    write(tmp_path, "d1/a.py")
    write(tmp_path, "d1/d2/deep.py")
    write(tmp_path, "credentials/c.py", "NEVER_READ")
    write(tmp_path, "node_modules/m.js", "NEVER_READ")
    result = snapshot_source(str(tmp_path))
    assert [f["path"] for f in result["files"]] == ["d1/a.py"]
    assert result["gaps"] == ["Excluded directory: credentials", "Excluded directory: node_modules", "Depth limit: d1/d2"]
    gaps_read_in_chinese(result)


def test_text_files_are_chosen_by_suffix_or_build_file_name(tmp_path):
    write(tmp_path, "Dockerfile", "FROM scratch\n")
    write(tmp_path, "MAKEFILE", "all:\n")
    write(tmp_path, "README.rst", "not text for the snapshot\n")
    write(tmp_path, "zapp.PY", "z = 1\n")
    result = snapshot_source(str(tmp_path))
    assert [f["path"] for f in result["files"]] == ["Dockerfile", "MAKEFILE", "zapp.PY"] and result["gaps"] == []


def test_non_regular_and_hardlinked_files_are_named_not_read(tmp_path):
    write(tmp_path, "a.py", "a = 1\n")
    os.link(tmp_path / "a.py", tmp_path / "b.py")
    os.mkfifo(tmp_path / "pipe.py")
    write(tmp_path, "z.py", "z = 1\n")
    result = snapshot_source(str(tmp_path))
    assert [f["path"] for f in result["files"]] == ["z.py"]
    assert result["gaps"] == [f"Non-regular or hardlinked file omitted: {name}" for name in ["a.py", "b.py", "pipe.py"]]
    gaps_read_in_chinese(result)


def test_file_and_total_byte_limits_are_inclusive(tmp_path, monkeypatch):
    monkeypatch.setattr(snapshot, "MAX_FILE_BYTES", 10)
    monkeypatch.setattr(snapshot, "MAX_TOTAL_BYTES", 15)
    write(tmp_path, "a.py", "x" * 10)
    write(tmp_path, "b.py", "y" * 5)
    result = snapshot_source(str(tmp_path))
    assert [(f["path"], f["content"]) for f in result["files"]] == [("a.py", "x" * 10), ("b.py", "y" * 5)]
    assert result["bytes_read"] == 15 and result["gaps"] == []
    write(tmp_path, "b.py", "y" * 6)
    write(tmp_path, "c.py", "z" * 11)
    result = snapshot_source(str(tmp_path))
    assert [f["path"] for f in result["files"]] == ["a.py"]
    assert result["gaps"] == ["File/byte limit omitted: b.py", "File/byte limit omitted: c.py"]
    gaps_read_in_chinese(result)


def test_binary_non_utf8_bom_and_redacted_files(tmp_path):
    write(tmp_path, "bin.py", b"x = 1\0")
    write(tmp_path, "latin.py", b"caf\xe9 = 1\n")
    write(tmp_path, "bom.py", b"\xef\xbb\xbfbom = 1\n")
    write(tmp_path, "config.py", '{"password": "hunter2"}\n')
    result = snapshot_source(str(tmp_path))
    assert [(f["path"], f["content"], f["redacted"]) for f in result["files"]] == [
        ("bom.py", "bom = 1\n", False), ("config.py", '{"password": "[REDACTED]"}\n', True)]
    assert result["files"][1]["sha256"] == hashlib.sha256(b'{"password": "hunter2"}\n').hexdigest()
    assert result["files"][1]["content_sha256"] == hashlib.sha256(b'{"password": "[REDACTED]"}\n').hexdigest()
    assert result["gaps"] == ["Binary content omitted: bin.py", "Secret-like literals redacted: config.py", "Non-UTF-8 file omitted: latin.py"]
    gaps_read_in_chinese(result)


def test_routes_are_capped_per_file_and_per_snapshot(tmp_path):
    for name in "abc":
        write(tmp_path, f"{name}.js", "\n".join(f'app.get("/{name}{index}", handler);' for index in range(250)))
    result = snapshot_source(str(tmp_path))
    assert len(result["routes"]) == 500
    assert len(_routes("a.js", "\n".join(f'app.get("/{index}")' for index in range(250)))) == 200


def test_route_lines_methods_and_next_app_prefix():
    assert _routes("x.js", "\n\nAPP.GET('/upper')\n\n") == [{"method": "GET", "path": "/upper", "file": "x.js", "line": 3, "confidence": "heuristic"}]
    assert _routes("x.py", "@Api.Post('/p')\n") == [{"method": "POST", "path": "/p", "file": "x.py", "line": 1, "confidence": "heuristic"}]
    assert [r["method"] for r in _routes("x.js", "app.all('/a'); router.route('/b')")] == ["UNKNOWN"]
    assert _routes("app/app/x/route.ts", "\n\nexport function GET() {}\n\n") == [
        {"method": "GET", "path": "/app/x", "file": "app/app/x/route.ts", "line": 3, "confidence": "heuristic"}]
    assert _routes("x/app/route.ts", "export function get() {}") == []


def test_linklike_reads_the_windows_reparse_bit(monkeypatch):
    from pathlib import Path
    def fake(attributes):
        info = types.SimpleNamespace(st_mode=0o100644)
        if attributes is not None:
            info.st_file_attributes = attributes
        return info
    for attributes, linked in [(None, False), (0, False), (0x1, False), (0x400, True), (0x420, True)]:
        monkeypatch.setattr(Path, "lstat", lambda self, attributes=attributes: fake(attributes))
        assert _linklike(Path("/repo/x")) is linked, attributes


@pytest.mark.parametrize("name", ["prod-service-account.yaml", "prod_service_account.yaml", "team-private-key.txt", "ENV.private_key.txt", ".envrc"])
def test_secret_path_words_match_anywhere_in_the_name(name):
    from pathlib import Path
    assert _secret_path(Path("/repo") / name) is True


def test_redaction_marker_is_exact():
    # A quoted key is only the assignment form's business, so its marker and the value's quotes are seen as they are.
    assert redact_text('{"password": "hunter2"}') == '{"password": "[REDACTED]"}'
    assert redact_text("token: 'abc'\nname = 'kept'") == "token: '[REDACTED]'\nname = 'kept'"


# --- catalog ---------------------------------------------------------------------------------------------------------


def test_default_catalog_root_is_the_environment_or_the_checkout(monkeypatch):
    monkeypatch.setenv("VIBEAUDIT_CATALOG_ROOT", "/configured/catalogs")
    assert str(default_catalog_root()) == os.path.normpath("/configured/catalogs")
    monkeypatch.delenv("VIBEAUDIT_CATALOG_ROOT")
    root = default_catalog_root()
    assert root.name == "catalogs" and (root / "manifest.json").is_file()
    # The checkout keeps the package in backend/; a mutation run copies it to src/ beside a copy of the catalogs.
    assert any((root.parent / package / "vibe_audit" / "catalog.py").is_file() for package in ("backend", "src"))


class Catalogs:
    """A writable copy of the shipped catalogs whose manifest is re-pinned after each change."""

    def __init__(self, tmp_path):
        self.root = tmp_path / "catalogs"
        shutil.copytree(default_catalog_root(), self.root)
        self.manifest = json.loads((self.root / "manifest.json").read_text(encoding="utf-8"))

    def collection(self, index=0):
        return self.manifest["collections"][index]

    def entries(self, index=0):
        return json.loads((self.root / self.collection(index)["file"]).read_text(encoding="utf-8"))

    def rewrite(self, entries, index=0):
        data = json.dumps(entries).encode("utf-8")
        (self.root / self.collection(index)["file"]).write_bytes(data)
        self.collection(index).update(sha256=hashlib.sha256(data).hexdigest(), count=len(entries))

    def save(self, manifest=None):
        text = manifest if isinstance(manifest, str) else json.dumps(self.manifest if manifest is None else manifest)
        (self.root / "manifest.json").write_text(text, encoding="utf-8")
        return self.root

    def refused(self, message):
        with pytest.raises(CatalogError) as refused:
            CatalogRegistry(self.save())
        assert str(refused.value) == message


def test_registry_refusals_name_their_cause(tmp_path):
    catalogs = Catalogs(tmp_path)
    with pytest.raises(CatalogError, match="^Catalog manifest unavailable or invalid$"):
        CatalogRegistry(tmp_path / "missing")
    (tmp_path / "broken").mkdir()
    (tmp_path / "broken" / "manifest.json").write_text("{", encoding="utf-8")
    with pytest.raises(CatalogError, match="^Catalog manifest unavailable or invalid$"):
        CatalogRegistry(tmp_path / "broken")
    catalogs.manifest["schema_version"] = 2
    catalogs.refused("Unsupported catalog schema")
    catalogs.manifest["schema_version"] = 1
    collections = catalogs.manifest.pop("collections")
    catalogs.refused("Catalog registry is empty")
    catalogs.manifest["collections"] = collections
    entries = catalogs.entries()
    catalogs.collection()["count"] = len(entries) + 1
    catalogs.collection()["sha256"] = hashlib.sha256((catalogs.root / catalogs.collection()["file"]).read_bytes()).hexdigest()
    catalogs.refused("Catalog count mismatch")
    catalogs.rewrite(entries + [{"id": "X-1"}])
    catalogs.refused("Invalid catalog entry")
    catalogs.rewrite(entries + [entries[0]])
    catalogs.refused("Duplicate catalog identifier")
    catalogs.rewrite(entries[:-1] + [{**entries[-1], "version": "0.0.0"}])
    catalogs.refused("Catalog entry edition mismatch")
    catalogs.rewrite(entries[:-1] + [{**entries[-1], "standard": "OTHER"}])
    catalogs.refused("Catalog entry edition mismatch")
    catalogs.rewrite(entries)
    assert CatalogRegistry(catalogs.save()).resolve(entries[0]["id"]) == entries[0]


def test_catalog_files_must_sit_under_the_root_unlinked_and_present(tmp_path):
    catalogs = Catalogs(tmp_path)
    outside = tmp_path / "outside.json"
    shutil.copy(catalogs.root / catalogs.collection()["file"], outside)
    catalogs.collection()["file"] = "../outside.json"
    catalogs.refused("Catalog path escapes its configured root")
    try:
        (catalogs.root / "linked.json").symlink_to(outside)
    except OSError:
        pytest.skip("OS does not permit creating symlinks for this account")
    catalogs.collection()["file"] = "linked.json"
    catalogs.refused("Catalog path escapes its configured root")
    catalogs.collection()["file"] = "absent.json"
    catalogs.refused("Catalog file unavailable: absent.json")


def test_identifier_lookups_are_bounded_and_copied():
    registry = load_catalogs()
    first = registry.entries("LLM")[0]["id"]
    assert registry.validate_ids([first] * 1000)[0]["id"] == first
    for identifiers in [[first] * 1001, (first,), first, None]:
        with pytest.raises(CatalogError, match="^Standard IDs must be a bounded list$"):
            registry.validate_ids(identifiers)
    with pytest.raises(CatalogError, match="^Unknown or unversioned standard identifier: 5$"):
        registry.resolve(5)
    with pytest.raises(CatalogError, match="^Unknown or unversioned standard identifier: 'LLM99:2026'$"):
        registry.resolve("LLM99:2026")
    manifest = registry.manifest()
    manifest["collections"][0]["sources"].clear()
    assert registry.manifest()["collections"][0]["sources"]
