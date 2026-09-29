import json
import shutil

import pytest

from vibe_audit.catalog import CatalogError, default_catalog_root, load_catalogs


def test_all_versions_and_real_identifiers_are_loaded():
    registry = load_catalogs()
    counts = {c["standard"]: c["count"] for c in registry.manifest()["collections"]}
    assert counts["ASVS"] > 300
    assert counts["WSTG"] > 80
    assert counts["LLM"] == counts["AGENTIC"] == 10
    assert registry.resolve("LLM03:2026")["title"] == "Excessive Agency"
    assert registry.resolve("ASI10:2026")["official_id"] == "ASI10"
    assert registry.resolve("v5.0.0-8.2.2") == registry.resolve("ASVS-v5.0.0-8.2.2")
    assert registry.resolve("WSTG-v42-ATHZ-04")["official_id"] == "WSTG-ATHZ-04"
    assert counts["WSTG"] == 97
    assert "Format String" in registry.resolve("WSTG-v42-INPV-13")["title"]


@pytest.mark.parametrize("identifier", ["WSTG-ATHZ-04", "LLM11:2026", "LLM03:2025", "ASI01", "ASVS-v5.0.0-99.9.9", "v5.0.0-99.9.9", "../manifest.json"])
def test_unversioned_unknown_and_fabricated_ids_fail_closed(identifier):
    with pytest.raises(CatalogError):
        load_catalogs().resolve(identifier)


def test_local_source_tampering_is_detected(tmp_path):
    destination = tmp_path / "catalogs"
    shutil.copytree(default_catalog_root(), destination)
    manifest = json.loads((destination / "manifest.json").read_text(encoding="utf-8"))
    source = destination / manifest["collections"][0]["sources"][0]["file"]
    source.write_bytes(source.read_bytes() + b"modified")
    with pytest.raises(CatalogError, match="integrity"):
        load_catalogs(destination)


def test_registry_does_not_expose_mutable_internal_entries():
    registry = load_catalogs()
    result = registry.resolve("LLM01:2026")
    result["title"] = "corrupted"
    assert registry.resolve("LLM01:2026")["title"] == "Prompt Injection"


def test_manifest_records_pins_attribution_and_two_source_checks():
    registry = load_catalogs()
    for collection in registry.manifest()["collections"]:
        assert collection["license"] == "CC-BY-SA-4.0"
        assert len(collection["sources"]) >= 2
        assert collection["verification"]
        assert any(len(source.get("commit") or "") == 40 for source in collection["sources"])
        assert all(len(source["sha256"]) == 64 for source in collection["sources"])
