"""Offline, integrity-checked OWASP identifier registry. No model-supplied IDs are trusted."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

from .schemas import CATALOG_ENTRY_SCHEMA
from .settings import catalog_root

_ENTRY_VALIDATOR = Draft202012Validator(CATALOG_ENTRY_SCHEMA)


class CatalogError(ValueError):
    pass


def default_catalog_root() -> Path:
    return catalog_root()


def _read_checked(root: Path, relative: str, expected: str) -> bytes:
    unresolved = root / relative
    # resolve() follows links, so the link check has to look at the path as written.
    path = unresolved.resolve()
    if not path.is_relative_to(root.resolve()) or unresolved.is_symlink():
        raise CatalogError("Catalog path escapes its configured root")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise CatalogError(f"Catalog file unavailable: {relative}") from exc
    if len(data) > 30_000_000 or hashlib.sha256(data).hexdigest() != expected:
        if hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest() == expected:
            raise CatalogError(f"Catalog integrity mismatch: {relative} has converted line endings; check it out again with the repository .gitattributes")
        raise CatalogError(f"Catalog integrity mismatch: {relative}")
    return data


class CatalogRegistry:
    def __init__(self, root: Path):
        self.root = root.resolve()
        try:
            self._manifest = json.loads((self.root / "manifest.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise CatalogError("Catalog manifest unavailable or invalid") from exc
        if self._manifest.get("schema_version") != 1:
            raise CatalogError("Unsupported catalog schema")
        self._entries: dict[str, dict] = {}
        for collection in self._manifest.get("collections", []):
            for source in collection["sources"]:
                _read_checked(self.root, source["file"], source["sha256"])
            raw = _read_checked(self.root, collection["file"], collection["sha256"])
            entries = json.loads(raw)
            if len(entries) != collection["count"]:
                raise CatalogError("Catalog count mismatch")
            for entry in entries:
                try:
                    _ENTRY_VALIDATOR.validate(entry)
                except ValidationError as exc:
                    raise CatalogError("Invalid catalog entry") from exc
                if entry["id"] in self._entries:
                    raise CatalogError("Duplicate catalog identifier")
                if entry["standard"] != collection["standard"] or entry["version"] != collection["version"]:
                    raise CatalogError("Catalog entry edition mismatch")
                self._entries[entry["id"]] = entry
        if not self._entries:
            raise CatalogError("Catalog registry is empty")

    def resolve(self, identifier: str) -> dict:
        if isinstance(identifier, str) and identifier.startswith("v5.0.0-"):
            identifier = "ASVS-" + identifier
        if not isinstance(identifier, str) or identifier not in self._entries:
            raise CatalogError(f"Unknown or unversioned standard identifier: {identifier!r}")
        return copy.deepcopy(self._entries[identifier])

    def validate_ids(self, identifiers: list[str]) -> list[dict]:
        if not isinstance(identifiers, list) or len(identifiers) > 1000:
            raise CatalogError("Standard IDs must be a bounded list")
        return [self.resolve(identifier) for identifier in identifiers]

    def entries(self, standard: str | None = None) -> list[dict]:
        return [copy.deepcopy(e) for e in self._entries.values() if standard is None or e["standard"] == standard]

    def manifest(self) -> dict:
        return copy.deepcopy(self._manifest)


def load_catalogs(root: Path | str | None = None) -> CatalogRegistry:
    return CatalogRegistry(Path(root) if root is not None else default_catalog_root())
