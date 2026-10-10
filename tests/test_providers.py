import asyncio
import hashlib
import json
from types import SimpleNamespace

import httpx
import pytest

from vibe_audit import providers
from vibe_audit.snapshot import snapshot_source, redact_text


@pytest.fixture
def profile():
    return {"id": "reviewer-a", "provider": "openai_compatible", "model_id": "test-model", "family": "test", "endpoint": "http://127.0.0.1:11434/v1", "credential_env": "", "max_output_tokens": 256, "temperature": 0}


@pytest.fixture
def policy():
    return {"data_policy": "local_only", "allowed_model_origins": ["http://127.0.0.1:11434"], "max_tokens": 1000, "response_schema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"], "additionalProperties": False}}


def response(content='{"ok":true}', *, finish="stop", refusal=None, usage=True):
    return {"model": "test-model", "choices": [{"finish_reason": finish, "message": {"content": content, "refusal": refusal}}], "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15} if usage else None}


@pytest.fixture
def fake_provider(monkeypatch):
    calls = []
    answers = [response()]
    monkeypatch.setattr(providers, "_load_litellm", lambda: SimpleNamespace())
    async def invoke(*args):
        calls.append(args)
        value = answers[min(len(calls) - 1, len(answers) - 1)]
        if isinstance(value, Exception):
            raise value
        return value
    monkeypatch.setattr(providers, "_invoke", invoke)
    return calls, answers


@pytest.mark.asyncio
async def test_generation_uses_explicit_agent_and_metering(profile, policy, fake_provider):
    calls, _ = fake_provider
    result = await providers.generate_json(profile, "Review", {"source": "x"}, policy)
    assert result["data"] == {"ok": True}
    assert result["model_id"] == "test-model"
    assert result["usage"]["tokens"] == 15
    assert result["cost_usd"] is None
    assert len(calls) == 1
    assert calls[0][1]["id"] == "reviewer-a"
    assert calls[0][-1] == 30


@pytest.mark.parametrize("endpoint,allow", [("https://api.example.com/v1", ["https://api.example.com"]), ("http://localhost:11434/v1", ["http://localhost:11434"]), ("http://192.168.1.5/v1", ["http://192.168.1.5"]), ("http://localhost:11434/v1", []), ("http://0.0.0.0:11434/v1", [])])
@pytest.mark.asyncio
async def test_local_only_denies_nonliteral_loopback(profile, policy, fake_provider, endpoint, allow):
    profile["endpoint"] = endpoint
    policy["allowed_model_origins"] = allow
    with pytest.raises(providers.ProviderError, match="literal loopback"):
        await providers.generate_json(profile, "Review", {}, policy)
    assert not fake_provider[0]


@pytest.mark.parametrize("endpoint", ["http://user:secret@127.0.0.1:11434/v1", "http://127.0.0.1:11434/v1?key=secret", "http://127.0.0.1:11434/v1#fragment", "http://127.0.0.1:11434\\@evil.test/"],
                         ids=["userinfo", "query", "fragment", "backslash"])
@pytest.mark.asyncio
async def test_endpoint_ambiguity_rejected(profile, policy, fake_provider, endpoint):
    profile["endpoint"] = endpoint
    with pytest.raises(providers.ProviderError):
        await providers.generate_json(profile, "Review", {}, policy)
    assert not fake_provider[0]


@pytest.mark.asyncio
async def test_explicit_origin_and_credential_references(profile, policy, fake_provider, monkeypatch):
    policy["allowed_model_origins"] = ["http://127.0.0.1:9999"]
    with pytest.raises(providers.ProviderError) as err:
        await providers.generate_json(profile, "Review", {}, policy)
    assert err.value.code == "origin_denied"
    policy["data_policy"] = "cloud_allowed"
    policy["allowed_model_origins"] = []
    with pytest.raises(providers.ProviderError) as err:
        await providers.generate_json(profile, "Review", {}, policy)
    assert err.value.code == "origin_denied"
    policy["data_policy"] = "local_only"
    policy["allowed_model_origins"] = ["http://127.0.0.1:11434"]
    profile["credential_env"] = "OPENAI_API_KEY"
    with pytest.raises(providers.ProviderError) as err:
        await providers.generate_json(profile, "Review", {}, policy)
    assert err.value.code == "invalid_credential_reference"
    profile["credential_env"] = "VIBEAUDIT_TEST_KEY"
    monkeypatch.setenv("VIBEAUDIT_TEST_KEY", "synthetic-test-key")
    monkeypatch.setenv("VIBEAUDIT_MODEL_CREDENTIAL_ORIGINS", "VIBEAUDIT_TEST_KEY=http://127.0.0.1:11434")
    await providers.generate_json(profile, "Review", {}, policy)
    assert fake_provider[0][0][4] == "synthetic-test-key"


@pytest.mark.asyncio
async def test_model_key_goes_only_to_the_origin_the_operator_bound(profile, policy, fake_provider, monkeypatch):
    # The request body names the endpoint and its allowlist; only the environment binds a key to an origin.
    monkeypatch.setenv("VIBEAUDIT_TEST_KEY", "synthetic-test-key")
    monkeypatch.delenv("VIBEAUDIT_MODEL_CREDENTIAL_ORIGINS", raising=False)
    profile["credential_env"] = "VIBEAUDIT_TEST_KEY"
    for binding in [None, "VIBEAUDIT_TEST_KEY=http://127.0.0.1:11435", "VIBEAUDIT_OTHER_KEY=http://127.0.0.1:11434"]:
        if binding:
            monkeypatch.setenv("VIBEAUDIT_MODEL_CREDENTIAL_ORIGINS", binding)
        with pytest.raises(providers.ProviderError) as err:
            await providers.generate_json(profile, "Review", {}, policy)
        assert err.value.code == "credential_origin_denied" and "synthetic-test-key" not in str(err.value)
        assert err.value.usage["model_calls"] == 0
    assert fake_provider[0] == []
    monkeypatch.setenv("VIBEAUDIT_MODEL_CREDENTIAL_ORIGINS", "VIBEAUDIT_OTHER_KEY=https://api.example.com, VIBEAUDIT_TEST_KEY=http://127.0.0.1:11434/")
    await providers.generate_json(profile, "Review", {}, policy)
    assert fake_provider[0][0][4] == "synthetic-test-key"
    # A key-less local endpoint needs no binding.
    profile["credential_env"] = ""
    monkeypatch.delenv("VIBEAUDIT_MODEL_CREDENTIAL_ORIGINS")
    await providers.generate_json(profile, "Review", {}, policy)
    assert len(fake_provider[0]) == 2


def test_credential_origin_bindings_and_defaults(monkeypatch):
    monkeypatch.delenv("VIBEAUDIT_MODEL_CREDENTIAL_ORIGINS", raising=False)
    assert providers.credential_origins() == {"VIBEAUDIT_OPENAI_API_KEY": {"https://api.openai.com"},
                                              "VIBEAUDIT_ANTHROPIC_API_KEY": {"https://api.anthropic.com"}}
    # The operator can rebind a pre-filled name, e.g. to a gateway, and list several origins for one key.
    bound = providers.credential_origins({"VIBEAUDIT_MODEL_CREDENTIAL_ORIGINS":
        "VIBEAUDIT_OPENAI_API_KEY=https://gateway.example:8443,VIBEAUDIT_LOCAL_KEY=http://[::1]:8001,VIBEAUDIT_LOCAL_KEY=http://127.0.0.1:8001"})
    assert bound["VIBEAUDIT_OPENAI_API_KEY"] == {"https://gateway.example:8443"}
    assert bound["VIBEAUDIT_LOCAL_KEY"] == {"http://[::1]:8001", "http://127.0.0.1:8001"}
    for raw in ["VIBEAUDIT_KEY", "OPENAI_API_KEY=https://api.openai.com", "VIBEAUDIT_KEY=https://api.example.com/v1",
                "VIBEAUDIT_KEY=ftp://api.example.com", "VIBEAUDIT_KEY=https://user:pw@api.example.com"]:
        with pytest.raises(providers.ProviderError) as err:
            providers.credential_origins({"VIBEAUDIT_MODEL_CREDENTIAL_ORIGINS": raw})
        assert err.value.code == "invalid_credential_binding"
    from vibe_audit.adapters import credential_env_allowed
    assert not credential_env_allowed("VIBEAUDIT_MODEL_CREDENTIAL_ORIGINS", {})


@pytest.mark.parametrize("name,value", [
    ("VIBEAUDIT_DATABASE_URL", "postgresql://vibe:db-secret@127.0.0.1/vibeaudit"),
    ("VIBEAUDIT_SESSION_TOKEN", "s" * 40),
    ("VIBEAUDIT_LEASE_DB", "postgresql://vibe:db-secret@127.0.0.1/leases"),
    ("VIBEAUDIT_COPY", "s" * 40),
], ids=["database-url", "session-token", "lease-db", "copied-value"])
@pytest.mark.asyncio
async def test_credentials_never_name_the_tools_own_settings(profile, policy, fake_provider, monkeypatch, name, value):
    # The probe would send the value as a bearer token; the session token and database URLs never leave.
    monkeypatch.setenv("VIBEAUDIT_SESSION_TOKEN", "s" * 40)
    monkeypatch.setenv(name, value)
    policy["allowed_model_origins"] = ["http://127.0.0.1:11434"]
    profile["credential_env"] = name
    with pytest.raises(providers.ProviderError) as err:
        await providers.generate_json(profile, "Review", {}, policy)
    assert err.value.code == "invalid_credential_reference"
    assert fake_provider[0] == []


@pytest.mark.asyncio
async def test_failures_before_dispatch_cost_nothing_and_keep_usage_known(policy, monkeypatch):
    # Real LiteLLM: gpt-5 rejects temperature 0 before any request; nothing listens on port 9 either.
    profile = {"id": "reviewer-a", "provider": "openai", "model_id": "gpt-5", "family": "gpt",
               "endpoint": "http://127.0.0.1:9/v1", "credential_env": "", "max_output_tokens": 256, "temperature": 0}
    policy.update(allowed_model_origins=[], max_model_calls=1)
    with pytest.raises(providers.ProviderError) as err:
        await providers.generate_json(profile, "Review", {}, policy)
    assert err.value.code == "unsupported_parameter" and err.value.usage["tokens_known"] is True
    assert "temperature" in str(err.value) and "no request was sent" in str(err.value)
    # Leaving temperature empty uses the model default and gets as far as the (closed) endpoint.
    profile["temperature"] = None
    with pytest.raises(providers.ProviderError) as err:
        await providers.generate_json(profile, "Review", {}, policy)
    assert err.value.code == "endpoint_unavailable" and err.value.usage["tokens_known"] is True
    # A policy denial of the resolved address is not a billed attempt either.
    monkeypatch.setenv("VIBEAUDIT_TEST_KEY", "synthetic-test-key")
    monkeypatch.setenv("VIBEAUDIT_MODEL_CREDENTIAL_ORIGINS", "VIBEAUDIT_TEST_KEY=https://10.0.0.5")
    profile.update(endpoint="https://10.0.0.5/v1", temperature=0.2, credential_env="VIBEAUDIT_TEST_KEY")
    policy.update(data_policy="cloud_allowed", allowed_model_origins=["https://10.0.0.5"])
    with pytest.raises(providers.ProviderError) as err:
        await providers.generate_json(profile, "Review", {}, policy)
    assert err.value.code == "origin_denied" and err.value.usage["tokens_known"] is True


def test_run_input_rejects_reserved_credential_names():
    from vibe_audit.domain import AuthProfile, ModelProfile
    with pytest.raises(ValueError, match="Vibe Audit setting"):
        ModelProfile(id="a", role="reviewer", provider="openai", model_id="m", family="f", credential_env="VIBEAUDIT_DATABASE_URL")
    with pytest.raises(ValueError, match="Vibe Audit setting"):
        AuthProfile(id="alice", credential_env="VIBEAUDIT_SESSION_TOKEN")


def test_run_input_rejects_a_model_key_named_as_a_test_identity():
    from vibe_audit.domain import RunInput
    model = {"id": "a", "role": "reviewer", "provider": "openai", "model_id": "m", "family": "f", "credential_env": "VIBEAUDIT_OPENAI_API_KEY"}
    with pytest.raises(ValueError, match="both a model and a test identity"):
        RunInput(models=[model], auth_profiles=[{"id": "alice", "credential_env": "VIBEAUDIT_OPENAI_API_KEY"}])
    RunInput(models=[model], auth_profiles=[{"id": "alice", "credential_env": "VIBEAUDIT_ALICE_TOKEN"}])


@pytest.mark.parametrize("endpoint", ["http://127.0.0.1:11434/v1", "http://[::1]:11434/v1"])
@pytest.mark.asyncio
async def test_local_only_loopback_needs_no_origin_list(profile, policy, fake_provider, endpoint):
    # The workbench disables the origins field under local_only and sends [].
    profile["endpoint"] = endpoint
    policy["allowed_model_origins"] = []
    await providers.generate_json(profile, "Review", {}, policy)
    assert fake_provider[0]


@pytest.mark.parametrize("allow", [[], ["http://127.0.0.1:11434"]])
@pytest.mark.asyncio
async def test_missing_data_policy_is_denied(profile, policy, fake_provider, allow):
    del policy["data_policy"]
    policy["allowed_model_origins"] = allow
    with pytest.raises(providers.ProviderError) as err:
        await providers.generate_json(profile, "Review", {}, policy)
    assert err.value.code == "data_policy_denied"
    assert not fake_provider[0]


@pytest.mark.asyncio
async def test_schema_retry_is_bounded_and_each_attempt_reserved(profile, policy, fake_provider):
    calls, answers = fake_provider
    answers[:] = [response('{"wrong":true}'), response('{"ok":true}')]
    reservations = []
    async def reserve():
        reservations.append(1)
    policy["request_hook"] = reserve
    result = await providers.generate_json(profile, "Review", {}, policy)
    assert len(calls) == len(reservations) == 2
    assert result["usage"]["tokens"] == 30
    assert all(call[1]["model_id"] == "test-model" for call in calls)


@pytest.mark.parametrize("content", ['{"ok":1}', '{"ok":true,"ok":false}', '{"ok":NaN}', '```json\n{"ok":true}\n```', '[]'])
@pytest.mark.asyncio
async def test_invalid_json_never_accepted(profile, policy, fake_provider, content):
    calls, answers = fake_provider
    answers[:] = [response(content)]
    with pytest.raises(providers.ProviderError) as err:
        await providers.generate_json(profile, "Review", {}, policy)
    assert err.value.code == "schema_validation"
    assert err.value.usage["model_calls"] == 2
    assert len(calls) == 2


@pytest.mark.parametrize("answer,code", [(response(finish="length"), "truncated"), (response(refusal="Cannot comply"), "refusal"), (response(finish="tool_calls"), "unexpected_output"), (response(usage=False), "usage_unavailable")])
@pytest.mark.asyncio
async def test_refusal_truncation_usage_fail_closed(profile, policy, fake_provider, answer, code):
    calls, answers = fake_provider
    answers[:] = [answer]
    with pytest.raises(providers.ProviderError) as err:
        await providers.generate_json(profile, "Review", {}, policy)
    assert err.value.code == code
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_network_error_not_retried_and_secret_error_not_exposed(profile, policy, fake_provider):
    calls, answers = fake_provider
    answers[:] = [RuntimeError("authorization=synthetic-private-secret body=source-code")]
    with pytest.raises(providers.ProviderError) as err:
        await providers.generate_json(profile, "Review", {}, policy)
    assert "synthetic-private-secret" not in str(err.value)
    assert not err.value.usage["tokens_known"]
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_budget_stop_and_remote_schema_ref_no_network(profile, policy, fake_provider):
    policy["max_tokens"] = 14
    with pytest.raises(providers.ProviderError) as err:
        await providers.generate_json(profile, "Review", {}, policy)
    assert err.value.code == "budget_exhausted"
    assert err.value.usage["tokens"] == 15
    assert len(fake_provider[0]) == 1
    policy["response_schema"] = {"$ref": "https://evil.example/schema"}
    with pytest.raises(providers.ProviderError) as err:
        await providers.generate_json(profile, "Review", {}, policy)
    assert err.value.code == "invalid_schema"
    assert len(fake_provider[0]) == 1


@pytest.mark.asyncio
async def test_probe_does_not_claim_tool_support(profile, policy, fake_provider):
    fake_provider[1][:] = [response('{"probe":"vibeaudit","ok":true}')]
    result = await providers.probe_model(profile, policy)
    assert result["status"] == "verified"
    assert result["capabilities"]["tool_calling"] == "not_tested"
    assert result["simulated"] is False


@pytest.mark.asyncio
async def test_transport_pins_ip_preserves_host_and_blocks_redirect():
    captured = []
    def handler(request):
        captured.append(request)
        return httpx.Response(302, headers={"Location": "https://evil.example"}, stream=httpx.ByteStream(b""))
    transport = providers._OriginTransport("https://api.example.com", "93.184.216.34")
    await transport.inner.aclose()
    transport.inner = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(providers.ProviderError) as err:
            await client.post("https://api.example.com/v1/chat/completions", json={})
    assert err.value.code == "redirect_denied"
    assert captured[0].url.host == "93.184.216.34"
    assert captured[0].headers["host"] == "api.example.com"
    assert captured[0].extensions["sni_hostname"] == "api.example.com"


@pytest.mark.asyncio
async def test_transport_denies_wrong_origin_without_sending():
    transport = providers._OriginTransport("https://api.example.com", "93.184.216.34")
    await transport.inner.aclose()
    def never(_):
        pytest.fail("Unapproved origin reached transport")
    transport.inner = httpx.MockTransport(never)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(providers.ProviderError):
            await client.post("https://evil.example/v1", json={})


@pytest.mark.asyncio
async def test_dns_rejects_private_results(monkeypatch):
    async def answers(*_, **__):
        return [(2, 1, 6, "", ("127.0.0.1", 443))]
    monkeypatch.setattr(providers.asyncio.get_running_loop(), "getaddrinfo", answers)
    with pytest.raises(providers.ProviderError, match="globally routable"):
        await providers._resolve_model_ip("https://api.example.com/v1")


def test_snapshot_redacts_excludes_secret_files_and_hashes(tmp_path):
    raw = 'password = "literal-test-secret"\n@app.get("/health")\ndef health(): pass\n'
    (tmp_path / "app.py").write_text(raw, encoding="utf-8")
    (tmp_path / ".env").write_text("NEVER_READ=synthetic-secret", encoding="utf-8")
    (tmp_path / "private.key").write_text("NEVER_READ", encoding="utf-8")
    result = snapshot_source(str(tmp_path))
    assert len(result["files"]) == 1
    assert "literal-test-secret" not in result["files"][0]["content"]
    assert result["files"][0]["sha256"] == hashlib.sha256((tmp_path / "app.py").read_bytes()).hexdigest()
    assert result["routes"][0]["path"] == "/health"
    assert result["routes"][0]["confidence"] == "heuristic"
    assert snapshot_source(str(tmp_path))["digest"] == result["digest"]
    assert any("excluded without reading" in gap for gap in result["gaps"])


def test_snapshot_symlink_is_not_read(tmp_path):
    (tmp_path / "real.py").write_text("print('ok')", encoding="utf-8")
    try:
        (tmp_path / "link.py").symlink_to(tmp_path / "real.py")
    except OSError:
        pytest.skip("OS does not permit creating symlinks for this account")
    result = snapshot_source(str(tmp_path))
    assert [f["path"] for f in result["files"]] == ["real.py"]
    assert any("symlink" in gap for gap in result["gaps"])


def test_snapshot_limits_and_typescript_routes(tmp_path, monkeypatch):
    from vibe_audit import snapshot
    monkeypatch.setattr(snapshot, "MAX_FILE_BYTES", 80)
    (tmp_path / "huge.py").write_text("x" * 100, encoding="utf-8")
    (tmp_path / "web.ts").write_text('router.post("/api/audit", handler);', encoding="utf-8")
    result = snapshot_source(str(tmp_path))
    assert len(result["files"]) == 1
    assert result["routes"][0]["method"] == "POST"
    assert any("limit" in gap for gap in result["gaps"])


def test_redaction_known_token_private_key_bearer_and_url():
    content = "-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----\nBearer abcdefghijklmnop\nhttps://user:password@host/\nsk-proj-abcdefghijklmnopqrstuvw"
    redacted = redact_text(content)
    assert "synthetic" not in redacted
    assert "abcdefghijklmnop" not in redacted
    assert "user:password" not in redacted


@pytest.mark.asyncio
@pytest.mark.parametrize("response_status", [200, 302, 429, 503])
@pytest.mark.parametrize("provider,model", [("openai", "gpt-4o-mini"), ("openai_compatible", "test-model"), ("nvidia_nim", "nvidia/llama-3.1-nemotron-70b-instruct"), ("anthropic", "claude-3-7-sonnet-latest")])
async def test_installed_litellm_sdk_uses_guarded_http_transport(profile, policy, monkeypatch, provider, model, response_status):
    """Real installed SDK transforms, synthetic HTTP only; no paid/network call."""
    import socket
    captured = []
    stray_connections = []
    def reject_socket(*args, **kwargs):
        stray_connections.append(True)
        raise AssertionError("An unguarded socket connection was attempted")
    monkeypatch.setattr(socket.socket, "connect", reject_socket)
    monkeypatch.setattr(socket.socket, "connect_ex", reject_socket)
    def handler(request):
        captured.append(request)
        if response_status != 200:
            return httpx.Response(response_status, headers={"content-type": "application/json", "location": "https://unapproved.example"}, stream=httpx.ByteStream(b'{"error":{"message":"synthetic failure","type":"test_error"}}'))
        if provider == "anthropic":
            body = {"id": "synthetic", "type": "message", "role": "assistant", "model": model, "content": [{"type": "text", "text": '{"ok":true}'}], "stop_reason": "end_turn", "stop_sequence": None, "usage": {"input_tokens": 10, "output_tokens": 5}}
        else:
            body = {"id": "synthetic", "object": "chat.completion", "created": 1, **response()}
        return httpx.Response(200, headers={"content-type": "application/json"}, stream=httpx.ByteStream(json.dumps(body).encode()))
    def init(transport, origin, pinned_ip):
        transport.origin = origin
        transport.pinned_ip = pinned_ip
        transport.dispatched = False
        transport.inner = httpx.MockTransport(handler)
    monkeypatch.setattr(providers._OriginTransport, "__init__", init)
    invoke = providers._invoke
    async def diagnostic_invoke(*args):
        try:
            return await invoke(*args)
        except Exception as exc:
            if response_status != 200:
                raise
            # All inputs in this test are synthetic; expose SDK regressions to
            # pytest while production error responses remain deliberately safe.
            pytest.fail(f"Synthetic SDK integration failed: {type(exc).__name__}: {str(exc)[:1500]}")
    monkeypatch.setattr(providers, "_invoke", diagnostic_invoke)
    profile["provider"] = provider
    profile["model_id"] = model
    if response_status == 200:
        result = await providers.generate_json(profile, "Return JSON.", {}, policy)
        assert result["data"] == {"ok": True}
        assert result["usage"]["tokens"] == 15
    else:
        with pytest.raises(providers.ProviderError) as error:
            await providers.generate_json(profile, "Return JSON.", {}, policy)
        assert error.value.usage["tokens_known"] is False
    assert len(captured) == 1
    assert not stray_connections
    assert captured[0].url.host == "127.0.0.1"
    assert captured[0].headers["host"] == "127.0.0.1:11434"
    outbound = json.loads(captured[0].content)
    assert outbound["model"] == model


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["refused", "connect_timeout", "dns"])
@pytest.mark.parametrize("provider", ["openai_compatible", "anthropic"])
async def test_unreachable_endpoint_is_known_zero_usage(profile, policy, monkeypatch, provider, failure):
    # Nothing reached the provider, so the run may keep calling instead of latching unknown usage.
    def handler(request):
        if failure == "refused":
            raise httpx.ConnectError("synthetic connection refused", request=request)
        raise httpx.ConnectTimeout("synthetic connect timeout", request=request)
    def init(transport, origin, pinned_ip):
        transport.origin, transport.pinned_ip, transport.dispatched = origin, pinned_ip, False
        transport.inner = httpx.MockTransport(handler)
    monkeypatch.setattr(providers._OriginTransport, "__init__", init)
    if failure == "dns":
        async def no_dns(*args, **kwargs):
            raise OSError("synthetic name resolution failure")
        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", no_dns)
        monkeypatch.setenv("VIBEAUDIT_TEST_KEY", "synthetic")
        monkeypatch.setenv("VIBEAUDIT_MODEL_CREDENTIAL_ORIGINS", "VIBEAUDIT_TEST_KEY=https://model.example.invalid")
        profile.update(endpoint="https://model.example.invalid/v1", credential_env="VIBEAUDIT_TEST_KEY")
        policy.update(data_policy="cloud_allowed", allowed_model_origins=["https://model.example.invalid"])
    profile["provider"] = provider
    with pytest.raises(providers.ProviderError) as error:
        await providers.generate_json(profile, "Return JSON.", {}, policy)
    assert error.value.code == "endpoint_unavailable"
    assert error.value.usage["tokens_known"] is True and error.value.usage["tokens"] == 0


@pytest.mark.asyncio
async def test_failure_after_dispatch_keeps_usage_unknown(profile, policy, monkeypatch):
    def handler(request):
        raise httpx.ReadTimeout("synthetic read timeout", request=request)
    def init(transport, origin, pinned_ip):
        transport.origin, transport.pinned_ip, transport.dispatched = origin, pinned_ip, False
        transport.inner = httpx.MockTransport(handler)
    monkeypatch.setattr(providers._OriginTransport, "__init__", init)
    with pytest.raises(providers.ProviderError) as error:
        await providers.generate_json(profile, "Return JSON.", {}, policy)
    assert error.value.usage["tokens_known"] is False


@pytest.mark.asyncio
async def test_retry_policy_denial_retains_previous_billed_usage(profile, policy, fake_provider):
    calls, answers = fake_provider
    answers[:] = [response('{"wrong":true}')]
    count = 0
    async def reserve():
        nonlocal count
        count += 1
        if count == 2:
            raise ValueError("Budget exhausted")
    policy["request_hook"] = reserve
    with pytest.raises(providers.ProviderError) as error:
        await providers.generate_json(profile, "Review", {}, policy)
    assert error.value.code == "request_denied"
    assert error.value.usage["tokens"] == 15
    assert error.value.usage["model_calls"] == len(calls) == 1


# Explicit ids keep test receipts (JUnit names) from spelling out a synthetic credential;
# the same applies to every parametrize below and in test_engine.py whose values look like credentials.
SECRET_FORMATS = [
    "DATABASE_URL = postgres://app:synthetic-secret@db:5432/app",
    'uri = "mongodb+srv://app:synthetic-secret@cluster0.example.net/db"',
    "redis://:synthetic-secret@cache:6379/0",
    "export PASSWORD=synthetic-secret",
    "ENV SECRET_KEY=synthetic-secret",
    "export GITLAB_TOKEN=synthetic-secret",
    "define('DB_PASSWORD', 'synthetic-secret');",
    '"Server=db;User Id=sa;Password=synthetic-secret;"',
    'token = "synthetic-secret"',
    "SECRET_KEY = 'synthetic-secret'",
    "secret_key_base: synthetic-secret",
    '{"auths": {"registry.example": {"auth": "synthetic-secret"}}}',
    "-----BEGIN PGP PRIVATE KEY BLOCK-----\nsynthetic-secret\n-----END PGP PRIVATE KEY BLOCK-----",
    "stripe = sk_live_" + "s" * 24, "slack = xoxb-" + "1" * 12, "maps = AIza" + "s" * 35,
    "jwt = eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeW50aGV0aWMifQ.c3ludGhldGljLXNpZ25hdHVyZQ",
    # Keys after blank lines or on the line after a separator, and schemes behind a dotted prefix.
    "\n\n   password: synthetic-secret", "Server=db;\r\nPassword=synthetic-secret",
    "url = svc.db.postgres://app:synthetic-secret@db/app", "define('my-secret', 'synthetic-secret')",
    # Short password names, signing keys and cloud connection-string keys.
    "DB_PASS=synthetic-secret", "  smtp_pwd: synthetic-secret", 'GPG_PASSPHRASE = "synthetic-secret"',
    'signing_key = "synthetic-secret"', "export WEBHOOK_KEY=synthetic-secret",
    "DefaultEndpointsProtocol=https;AccountName=demo;AccountKey=synthetic-secret;EndpointSuffix=core.windows.net",
    "hf = hf_" + "s" * 34, "aws = ASIA" + "S" * 16, "mail = SG." + "s" * 22 + "." + "s" * 43, "google = ya29." + "s" * 30,
    "hook = https://hooks.slack.com/services/T0000/B0000/" + "s" * 24,
]


@pytest.mark.parametrize("content", SECRET_FORMATS, ids=[f"format-{i}" for i in range(len(SECRET_FORMATS))])
def test_redaction_covers_common_secret_formats(content):
    redacted = redact_text(content)
    assert "synthetic-secret" not in redacted
    assert "REDACTED" in redacted


@pytest.mark.parametrize("content", ["password_hash = bcrypt.hashpw(password, salt)", "login(user, password=password)",
                                     'tokenizer = load("cl100k")', '<input type="password" name="password">',
                                     'bypass = "cache"', "compass: north", "passthrough = True", "for item in items: pass"])
def test_redaction_keeps_security_relevant_code_readable(content):
    # Reviewers must still see how credentials are handled, not only that they exist.
    assert redact_text(content) == content


@pytest.mark.parametrize("unit", ["a", "token", "secret_", "\n", " \n", "a.", "a+", "define('token", "export token_",
                                  "eyJ-", "sk-a", "xoxb-", "glpat-", "pass", "_pass", "DB_PASS=", "export pwd_",
                                  "SG.", "hf_", "ASIA", "ya29.", "hooks.slack.com/services/", ";AccountKey="])
def test_redaction_stays_linear_on_hostile_single_token_files(unit):
    # Each of these took minutes at the per-file limit with backtracking name scans.
    import time
    from vibe_audit.snapshot import MAX_FILE_BYTES
    content = (unit * (MAX_FILE_BYTES // len(unit) + 1))[:MAX_FILE_BYTES]
    started = time.perf_counter()
    redact_text(content)
    assert time.perf_counter() - started < 2


def test_snapshot_skips_container_and_cluster_credential_dirs(tmp_path):
    for name in [".docker", ".kube"]:
        (tmp_path / name).mkdir()
        (tmp_path / name / "config.json").write_text('{"note": "NEVER_READ"}', encoding="utf-8")
    (tmp_path / "app.py").write_text("print('ok')", encoding="utf-8")
    result = snapshot_source(str(tmp_path))
    assert [f["path"] for f in result["files"]] == ["app.py"]
    assert {"Excluded directory: .docker", "Excluded directory: .kube"} <= set(result["gaps"])


def test_next_root_route_is_slash():
    from vibe_audit.snapshot import _routes
    assert _routes("app/route.ts", "export async function GET() {};")[0]["path"] == "/"


def test_tokenizer_loader_rejects_unknown_network_assets():
    import tiktoken.load
    providers._install_offline_tokenizer_loader()
    with pytest.raises(providers.ProviderError) as error:
        tiktoken.load.read_file_cached("https://unapproved.example/tokenizer", "abc")
    assert error.value.code == "tokenizer_unavailable"


@pytest.mark.asyncio
async def test_contract_rules_beyond_the_schema_get_the_same_bounded_retry(profile, policy, fake_provider):
    calls, answers = fake_provider
    answers[:] = [response('{"ok":true}'), response('{"ok":true}')]
    seen = []
    def check(data):
        seen.append(data)
        if len(seen) == 1:
            raise ValueError("A challenge needs counterevidence or missing evidence")
    policy["contract_check"] = check
    result = await providers.generate_json(profile, "Review", {}, policy)
    assert len(calls) == len(seen) == 2 and result["data"] == {"ok": True}


@pytest.mark.asyncio
async def test_cancel_between_attempts_still_reports_the_billed_attempt(profile, policy, fake_provider):
    calls, answers = fake_provider
    answers[:] = [response('{"wrong":true}')]
    count = 0
    async def reserve():
        nonlocal count
        count += 1
        if count == 2:
            raise asyncio.CancelledError()
    policy["request_hook"] = reserve
    with pytest.raises(providers.ProviderError) as error:
        await providers.generate_json(profile, "Review", {}, policy)
    assert error.value.code == "cancelled" and error.value.usage["tokens"] == 15
