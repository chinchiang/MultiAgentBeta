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


def _release_script():
    import importlib.util
    spec = importlib.util.spec_from_file_location("package_release", ROOT / "scripts" / "package-release.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_release_ships_tracked_files_and_the_built_ui_only(tmp_path):
    import subprocess
    release = _release_script()
    for name, text in {"b.py": "b", "A/z.txt": "z", ".claude/settings.json": "{}", ".claude/hooks/start.sh": "x",
                       "CLAUDE.md": "notes", "docs/CLAUDE.md": "kept", "scratch.txt": "x",
                       "frontend/dist/index.html": "<html>", ".env.local": "SECRET=1"}.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text)
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "b.py", "A/z.txt", "docs/CLAUDE.md"], cwd=tmp_path, check=True)
    # Agent configuration stays out of a release even when it is committed for cloud sessions.
    subprocess.run(["git", "add", ".claude", "CLAUDE.md"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "-f", ".env.local"], cwd=tmp_path, check=True)
    names = release.deliverables(tmp_path)
    assert names == ["A/z.txt", "b.py", "docs/CLAUDE.md", "frontend/dist/index.html"]
    rendered = release.render(names, tmp_path)
    assert rendered.count(b"\r\n") == 4 and rendered.endswith(b"  frontend/dist/index.html\r\n")
    (tmp_path / release.MANIFEST).write_bytes(rendered)
    assert release.check(tmp_path) == []
    (tmp_path / "b.py").write_text("changed")
    assert release.check(tmp_path) == ["b.py"]


def test_committed_receipts_name_no_host_or_account():
    import subprocess
    done = subprocess.run([sys.executable, str(ROOT / "scripts" / "redact-receipts.py"), "--check"], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr


def test_receipt_redaction_changes_only_identifiers():
    import importlib.util
    spec = importlib.util.spec_from_file_location("redact_receipts", ROOT / "scripts" / "redact-receipts.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    raw = (b'<testsuite hostname="DESK-01" tests="1"><testcase name="t" time="0.1">'
           b'<skipped message="needs PG">C:\\Users\\alice\\repo\\tests\\t.py:3 /home/bob/repo /mnt/c/Users/alice/x</skipped></testcase></testsuite>')
    assert module.redact(raw) == (b'<testsuite hostname="redacted-host" tests="1"><testcase name="t" time="0.1">'
                                  b'<skipped message="needs PG">C:\\Users\\user\\repo\\tests\\t.py:3 /home/user/repo /mnt/c/Users/user/x</skipped></testcase></testsuite>')
    assert module.redact(module.redact(raw)) == module.redact(raw)


def _provision_script():
    import importlib.util
    spec = importlib.util.spec_from_file_location("provision_runtime", ROOT / "scripts" / "provision-runtime.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DIGEST = "python@sha256:" + "2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9"
NOT_PINNED = ["python:3.13-slim", "python", "python@sha256:" + "A" * 64, "python@sha256:" + "a" * 63,
              DIGEST + "0", DIGEST + " ", "@sha256:" + "a" * 64, DIGEST + "\npython:latest",
              DIGEST + "\n" + DIGEST, DIGEST + "\n", ""]


def test_worker_dockerfile_refuses_a_base_image_that_is_not_digest_pinned():
    import shutil
    import subprocess
    text = (ROOT / "deploy" / "worker" / "Dockerfile").read_text(encoding="utf-8")
    after_from = text.split("FROM ${BASE_IMAGE}", 1)[1]
    # ARG 要在 FROM 之後重新宣告，RUN 與 LABEL 才看得到值；檢查與 mkdir 同一個 RUN，失敗就不會產生映像
    assert after_from.lstrip().startswith("ARG BASE_IMAGE\n")
    assert 'LABEL org.opencontainers.image.base.name="${BASE_IMAGE}"' in after_from
    run = after_from.split("\nRUN ", 1)[1]
    guard, rest = run.split(" \\\n    || { echo ", 1)
    assert "exit 1; } \\\n    && mkdir -p" in rest
    if shutil.which("sh") is None or shutil.which("grep") is None:
        pytest.skip("sh/grep is not available")
    # 直接執行 Dockerfile 中的檢查本身（而不是另寫一份規則），BASE_IMAGE 以環境變數提供
    accepts = lambda value: subprocess.run(["sh", "-c", guard], env={"PATH": "/usr/bin:/bin", "BASE_IMAGE": value}).returncode == 0
    assert accepts(DIGEST) and accepts("public.ecr.aws/docker/library/" + DIGEST)
    assert not any(accepts(value) for value in NOT_PINNED)


def test_provisioning_records_only_a_worker_built_from_a_digest_pinned_base():
    provision = _provision_script()
    image = lambda labels: {"Id": "sha256:" + "b" * 64, "Config": {"Labels": labels}}
    assert provision.worker_base(image({provision.BASE_LABEL: DIGEST})) == DIGEST
    for labels in [None, {}, {provision.BASE_LABEL: None}, {provision.BASE_LABEL: ["x"]},
                   *({provision.BASE_LABEL: value} for value in NOT_PINNED)]:
        with pytest.raises(SystemExit, match="digest-pinned"):
            provision.worker_base(image(labels))
    with pytest.raises(SystemExit):
        provision.worker_base({"Id": "sha256:" + "b" * 64})


@pytest.mark.skipif(not __import__("os").getenv("VIBEAUDIT_TEST_WORKER_IMAGE"), reason="Real Linux Docker worker image not provisioned")
def test_provisioned_worker_image_carries_its_digest_pinned_base():
    import os
    from urllib.parse import quote
    from vibe_audit.worker_entry import docker_api
    status, data = docker_api("GET", "/images/" + quote(os.environ["VIBEAUDIT_TEST_WORKER_IMAGE"], safe="") + "/json", timeout=20)
    assert status == 200
    assert _provision_script().DIGEST_REFERENCE.fullmatch(_provision_script().worker_base(data))


@pytest.mark.skipif(__import__("os").name != "posix", reason="provision-runtime.py runs on local Linux only")
def test_provisioning_writes_nothing_for_a_worker_without_a_digest_pinned_base(tmp_path, monkeypatch):
    provision = _provision_script()
    labels = {"worker": {}, "semgrep": None}
    def fake_docker(method, path, timeout):
        tool = "worker" if "vibeaudit-worker" in path else "semgrep"
        return 200, {"Id": "sha256:" + "c" * 64, "RepoDigests": [], "Config": {"Labels": labels[tool]}}
    monkeypatch.setattr(provision, "docker_api", fake_docker)
    out = tmp_path / "runtime.json"
    monkeypatch.setattr(sys, "argv", ["provision-runtime.py", "--output", str(out), "--static-only"])
    with pytest.raises(SystemExit, match="digest-pinned"):
        provision.main()
    assert not out.exists() and not out.with_suffix(".images.json").exists()
    labels["worker"] = {provision.BASE_LABEL: DIGEST}
    provision.main()
    import json
    assert json.loads(out.with_suffix(".images.json").read_text())["worker"]["base_image_label"] == DIGEST
