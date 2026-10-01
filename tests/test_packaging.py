import ast
import re
import sys
import tomllib
from importlib.metadata import packages_distributions
from pathlib import Path

import pytest

import vibe_audit.__main__ as entry

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "backend" / "vibe_audit"


def test_every_direct_third_party_import_is_a_declared_dependency():
    declared = {re.split(r"[\[=<>~!]", spec, maxsplit=1)[0].lower()
                for spec in tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["dependencies"]}
    siblings = {path.stem for path in PACKAGE.glob("*.py")}
    distributions = packages_distributions()
    missing = {}
    for path in PACKAGE.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module]
            else:
                continue
            for name in names:
                top = name.split(".")[0]
                # The worker imports its sibling modules flat inside the container.
                if top in sys.stdlib_module_names or top == "vibe_audit" or top in siblings:
                    continue
                if not {d.lower() for d in distributions.get(top, [])} & declared:
                    missing.setdefault(top, set()).add(path.name)
    assert not missing


def test_entry_point_refuses_to_start_outside_a_source_checkout(tmp_path, monkeypatch, capsys):
    def started(*args, **kwargs):
        raise AssertionError("The workbench started without its catalogs")
    monkeypatch.setattr("vibe_audit.api.create_app", started)
    monkeypatch.setattr("uvicorn.run", started)
    monkeypatch.setattr(entry, "__file__", str(tmp_path / "site-packages" / "vibe_audit" / "__main__.py"))
    monkeypatch.setattr(sys, "argv", ["vibe-audit"])
    with pytest.raises(SystemExit) as stopped:
        entry.main()
    assert stopped.value.code == 2
    assert "source checkout" in capsys.readouterr().err


def test_entry_point_finds_resources_in_this_checkout():
    assert (Path(entry.__file__).resolve().parents[2] / "catalogs").is_dir()
