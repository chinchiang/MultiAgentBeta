"""Opt-in real offline scanners; no model provider or arbitrary target is used."""
import asyncio
import json
import os
from pathlib import Path
import secrets
import string
import uuid

import pytest

from vibe_audit.worker_runtime import WorkerRuntime
from vibe_audit.staging import stage_source
from vibe_audit.resource_manifest import resource_manifest


@pytest.mark.skipif(not os.getenv("VIBEAUDIT_TEST_RUNTIME_CONFIG"),reason="Provisioned Linux scanner images and PostgreSQL required")
@pytest.mark.parametrize("tool",["semgrep","gitleaks","osv"])
async def test_real_offline_scanner_finds_seeded_issue_without_egress(tmp_path,tool):
    config=json.loads(Path(os.environ["VIBEAUDIT_TEST_RUNTIME_CONFIG"]).read_text())["profiles"]["default"]
    config["database_url"]=os.environ[config.pop("database_url_env")]
    config["work_root"]=str(tmp_path/"workers")
    source=tmp_path/"source"
    source.mkdir()
    (source/"app.py").write_text("def unsafe(value):\n    return eval(value)\n")
    # Generated per run so the repository holds no realistic-looking credential; it only has to match
    # gitleaks' GitHub token detector, which wants ghp_ followed by 36 high-entropy alphanumerics.
    canary="ghp_"+"".join(secrets.choice(string.ascii_letters+string.digits) for _ in range(36))
    (source/".env").write_text(f"GITHUB_TOKEN={canary}\n")
    (source/"requirements.txt").write_text("urllib3==1.26.4\n")
    staged=stage_source(str(source),tmp_path/"private")
    resource_manifest(config,[tool])
    runtime=WorkerRuntime(config)
    async def forbid(**kwargs):
        raise AssertionError("An offline scanner attempted a target request")
    manifest={"run_id":uuid.uuid4().hex,"mode":"live","source_digest":staged["digest"],
              "budget":{"max_seconds":600,"max_requests":1},"allowed_requests":[],"auth_profiles":[]}
    try:
        result=await runtime.run_scanner(tool,staged["path"],manifest=manifest,cancel_event=asyncio.Event(),request_hook=forbid)
        assert result["status"]=="completed",json.dumps(result,default=str)
        assert result["cleanup_confirmed"] is True and result["isolation"]=="docker_network_none"
        assert result.get("findings"),json.dumps(result,default=str)
        assert result.get("broker_observations",[])==[]
        assert canary not in json.dumps(result,default=str)
    finally:
        runtime.leases.close()
