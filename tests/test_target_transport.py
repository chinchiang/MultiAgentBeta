"""Public seams of target_transport: IP pinning, single-hop HTTP(S) transport and credential redaction."""
import importlib.util
import ipaddress
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from vibe_audit import target_transport
from vibe_audit.target_transport import (
    CREDENTIAL_ORIGINS_ENV,
    DEFAULT_CREDENTIAL_ORIGINS,
    MAX_RESPONSE_BYTES,
    REQUEST_TIMEOUT_SECONDS,
    RESERVED_ENV,
    TransportRefused,
    bound_model_credentials,
    credential_env_allowed,
    redact_credentials,
    resolve_pinned_ip,
    secret_forms,
    send_pinned_request,
    target_ip_refused,
    unmapped_ip,
)

MODULE_PATH = Path(target_transport.__file__)


def test_module_loads_flat_without_vibe_audit_package():
    spec = importlib.util.spec_from_file_location("target_transport_flat", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    flat = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"vibe_audit": None}):
        spec.loader.exec_module(flat)
    assert flat.resolve_pinned_ip("127.0.0.1", 8080, ["127.0.0.1"]) == "127.0.0.1"


def test_unmapped_and_refused_ips_cover_ipv4_ipv6_and_translations():
    assert unmapped_ip(ipaddress.ip_address("127.0.0.1")) == ipaddress.ip_address("127.0.0.1")
    assert unmapped_ip(ipaddress.ip_address("::1")) == ipaddress.ip_address("::1")
    assert unmapped_ip(ipaddress.ip_address("::ffff:169.254.169.254")) == ipaddress.ip_address("169.254.169.254")
    assert unmapped_ip(ipaddress.ip_address("2002:a9fe:a9fe::1")) == ipaddress.ip_address("169.254.169.254")
    assert unmapped_ip(ipaddress.ip_address("64:ff9b::169.254.169.254")) == ipaddress.ip_address("169.254.169.254")
    assert unmapped_ip(ipaddress.ip_address("64:ff9b:1::100.100.100.200")) == ipaddress.ip_address("100.100.100.200")

    for allowed in ("127.0.0.1", "::1", "10.0.0.5", "192.168.1.2", "fd12:3456::1", "93.184.216.34"):
        assert target_ip_refused(ipaddress.ip_address(allowed)) is False, allowed

    for refused in (
        "169.254.169.254",
        "169.254.1.2",
        "100.100.100.200",
        "fd00:ec2::254",
        "::ffff:169.254.169.254",
        "2002:a9fe:0102::1",
        "64:ff9b::169.254.169.254",
        "64:ff9b:1::100.100.100.200",
        "0.0.0.0",
        "::",
        "224.0.0.1",
        "ff02::1",
        "fec0::1",
        "240.0.0.1",
        "255.255.255.255",
        "fe80::1",
    ):
        assert target_ip_refused(ipaddress.ip_address(refused)) is True, refused


def test_resolve_pinned_ip_validates_allowlist_and_sorts_deterministically():
    for bad in (None, "127.0.0.1", ("127.0.0.1",), [123], ["example.test"], ["127.0.0.0/24"]):
        with pytest.raises(TransportRefused) as exc_info:
            resolve_pinned_ip("127.0.0.1", 80, bad)  # type: ignore[arg-type]
        assert (exc_info.value.rule, exc_info.value.delivered, exc_info.value.status_code) == ("invalid_allowed_ips", False, None)
        assert str(exc_info.value) == "invalid_allowed_ips"

    with pytest.raises(TransportRefused) as exc_info:
        resolve_pinned_ip("127.0.0.1", 80, [])
    assert (exc_info.value.rule, exc_info.value.delivered, exc_info.value.status_code) == ("no_allowed_ips", False, None)

    with pytest.raises(TransportRefused) as exc_info:
        resolve_pinned_ip("127.0.0.1", 80, ["127.0.0.1", "169.254.169.254"])
    assert (exc_info.value.rule, exc_info.value.delivered, exc_info.value.status_code) == ("refused_ip", False, None)

    with patch.object(socket, "getaddrinfo", side_effect=AssertionError("literal IP host needs no DNS")):
        assert resolve_pinned_ip("127.0.0.1", 80, ["127.0.0.1"]) == "127.0.0.1"
        with pytest.raises(TransportRefused) as exc_info:
            resolve_pinned_ip("127.0.0.2", 80, ["127.0.0.1"])
        assert (exc_info.value.rule, exc_info.value.delivered) == ("unlisted_ip", False)

    rows = [
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 8443, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.9", 8443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.2", 8443)),
    ]
    with patch.object(target_transport.socket, "getaddrinfo", return_value=rows) as lookup:
        assert resolve_pinned_ip("app.internal", 8443, ["::1", "10.0.0.2", "10.0.0.9"]) == "10.0.0.2"
        lookup.assert_called_once_with("app.internal", 8443, type=socket.SOCK_STREAM)
        with pytest.raises(TransportRefused) as exc_info:
            resolve_pinned_ip("app.internal", 8443, ["10.0.0.2", "10.0.0.9"])
        assert (exc_info.value.rule, exc_info.value.delivered) == ("unlisted_ip", False)

    with patch.object(target_transport.socket, "getaddrinfo", return_value=[]):
        with pytest.raises(TransportRefused) as exc_info:
            resolve_pinned_ip("app.internal", 8443, ["10.0.0.2"])
        assert (exc_info.value.rule, exc_info.value.delivered) == ("unlisted_ip", False)

    with patch.object(target_transport.socket, "getaddrinfo", side_effect=socket.gaierror("nxdomain")):
        with pytest.raises(TransportRefused) as exc_info:
            resolve_pinned_ip("missing.internal", 8443, ["10.0.0.2"])
        assert (exc_info.value.rule, exc_info.value.delivered, exc_info.value.status_code) == ("dns_failed", False, None)


def test_credential_helpers_enforce_prefix_reserved_names_url_values_and_bound_models():
    assert "VIBEAUDIT_DATABASE_URL" in RESERVED_ENV and "VIBEAUDIT_SESSION_TOKEN" in RESERVED_ENV
    assert CREDENTIAL_ORIGINS_ENV == "VIBEAUDIT_MODEL_CREDENTIAL_ORIGINS"
    assert DEFAULT_CREDENTIAL_ORIGINS == {
        "VIBEAUDIT_OPENAI_API_KEY": "https://api.openai.com",
        "VIBEAUDIT_ANTHROPIC_API_KEY": "https://api.anthropic.com",
    }

    env = {
        "VIBEAUDIT_OK": "tok-123",
        "VIBEAUDIT_URL_LIKE": "postgres://user:pw@db:5432/app",
        "VIBEAUDIT_SESSION_TOKEN": "ui-session-secret",
        "VIBEAUDIT_ALIAS": "ui-session-secret",
        CREDENTIAL_ORIGINS_ENV: " VIBEAUDIT_CUSTOM_MODEL = https://llm.example , bad=1, VIBEAUDIT_SECOND=https://m2.example ",
    }
    assert credential_env_allowed("VIBEAUDIT_OK", env) is True
    assert credential_env_allowed("VIBEAUDIT_UNSET", env) is True
    assert credential_env_allowed("VIBEAUDIT_URL_LIKE", env) is False
    assert credential_env_allowed("VIBEAUDIT_SESSION_TOKEN", env) is False
    assert credential_env_allowed("VIBEAUDIT_ALIAS", env) is False
    for bad_name in (None, 12, "", "OPENAI_API_KEY", "vibeaudit_lower", "VIBEAUDIT_BAD-DASH"):
        assert credential_env_allowed(bad_name, env) is False

    assert bound_model_credentials(env) == {
        "VIBEAUDIT_OPENAI_API_KEY",
        "VIBEAUDIT_ANTHROPIC_API_KEY",
        "VIBEAUDIT_CUSTOM_MODEL",
        "VIBEAUDIT_SECOND",
    }
    assert secret_forms('a/b"c') == {'a/b"c', 'a/b\\"c', 'a\\/b\\"c', "a%2Fb%22c"}
    assert secret_forms("") == set()

    # Default environ=None reads os.environ directly.
    with patch.dict(
        os.environ,
        {
            "VIBEAUDIT_PROC_KEY": "proc-secret-val",
            CREDENTIAL_ORIGINS_ENV: "VIBEAUDIT_PROC_MODEL=https://llm.proc",
        },
        clear=False,
    ):
        assert credential_env_allowed("VIBEAUDIT_PROC_KEY") is True
        assert "VIBEAUDIT_PROC_MODEL" in bound_model_credentials()
        assert redact_credentials(
            "leak proc-secret-val",
            {"auth_profiles": [{"id": "p", "credential_env": "VIBEAUDIT_PROC_KEY"}]},
        ) == "leak [REDACTED_CREDENTIAL]"


def test_redact_credentials_recursively_scrubs_longest_first_and_skips_reserved_settings():
    manifest = {
        "auth_profiles": [
            {"id": "alice", "credential_env": "VIBEAUDIT_ALICE"},
            {"id": "reserved", "credential_env": "VIBEAUDIT_DATA_DIR"},
            {"id": "missing_env_field"},
            "not-a-dict",
        ],
        "models": [
            {"id": "m1", "credential_env": "VIBEAUDIT_MODEL_ONE"},
            {"id": "url", "credential_env": "VIBEAUDIT_URL_SECRET"},
        ],
    }
    env = {
        "VIBEAUDIT_ALICE": "zz-short",
        "VIBEAUDIT_MODEL_ONE": 'aa-zz-short/with"quote',
        "VIBEAUDIT_OPENAI_API_KEY": "sk-default-bound",
        "VIBEAUDIT_EXTRA_MODEL": "nim-bound-key",
        "VIBEAUDIT_DATA_DIR": "/var/lib/vibeaudit",
        "VIBEAUDIT_DATABASE_URL": "secret-db-setting",
        "VIBEAUDIT_SAME_AS_RESERVED": "secret-db-setting",
        "VIBEAUDIT_URL_SECRET": "https://internal.example/key",
        CREDENTIAL_ORIGINS_ENV: "VIBEAUDIT_EXTRA_MODEL=https://integrate.api.nvidia.com,VIBEAUDIT_DATABASE_URL=https://x",
    }
    payload = {
        "longest_first": 'prefix aa-zz-short/with"quote and zz-short suffix',
        "escaped_json": 'aa-zz-short\\/with\\"quote',
        "url_encoded": "aa-zz-short%2Fwith%22quote",
        "bound_models": ["sk-default-bound", b"raw nim-bound-key bytes"],
        "transient": "session/tok+1 and session%2Ftok%2B1",
        "untouched_settings": "/var/lib/vibeaudit and secret-db-setting and https://internal.example/key",
        "numbers": [42, True, None],
    }
    redacted = redact_credentials(payload, manifest, extra_secrets=["", "session/tok+1"], environ=env)
    assert redacted == {
        "longest_first": "prefix [REDACTED_CREDENTIAL] and [REDACTED_CREDENTIAL] suffix",
        "escaped_json": "[REDACTED_CREDENTIAL]",
        "url_encoded": "[REDACTED_CREDENTIAL]",
        "bound_models": ["[REDACTED_CREDENTIAL]", b"raw [REDACTED_CREDENTIAL] bytes"],
        "transient": "[REDACTED_CREDENTIAL] and [REDACTED_CREDENTIAL]",
        "untouched_settings": "/var/lib/vibeaudit and secret-db-setting and https://internal.example/key",
        "numbers": [42, True, None],
    }
    # Original input is not mutated in place, and an empty secret set returns the value untouched.
    assert payload["bound_models"][0] == "sk-default-bound"
    plain = {"ok": "nothing-to-redact"}
    assert redact_credentials(plain, None, environ={}) == {"ok": "nothing-to-redact"}


class LoopbackServer:
    """Single-shot or multi-shot raw TCP (or TLS) listener on loopback."""

    def __init__(self, reply, host="127.0.0.1", family=socket.AF_INET, ssl_context: ssl.SSLContext | None = None):
        self.reply = reply
        self.requests: list[bytes] = []
        self.ssl_context = ssl_context
        self.socket = socket.socket(family, socket.SOCK_STREAM)
        self.socket.bind((host, 0))
        self.socket.listen()
        self.port = self.socket.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                raw_conn, _ = self.socket.accept()
            except OSError:
                return
            with raw_conn:
                raw_conn.settimeout(2)
                try:
                    conn = self.ssl_context.wrap_socket(raw_conn, server_side=True) if self.ssl_context else raw_conn
                except OSError:
                    continue
                with conn:
                    raw = b""
                    while b"\r\n\r\n" not in raw:
                        try:
                            chunk = conn.recv(65536)
                        except OSError:
                            break
                        if not chunk:
                            break
                        raw += chunk
                    head, sep, rest = raw.partition(b"\r\n\r\n")
                    if sep:
                        declared = [
                            line.split(b":", 1)[1].strip()
                            for line in head.split(b"\r\n")
                            if line.lower().startswith(b"content-length:")
                        ]
                        while declared and len(rest) < int(declared[0]):
                            more = conn.recv(65536)
                            if not more:
                                break
                            rest += more
                        self.requests.append(head + sep + rest)
                    try:
                        self.reply(conn, raw) if callable(self.reply) else conn.sendall(self.reply)
                    except OSError:
                        pass

    def close(self):
        self.socket.close()


def wire_response(status=200, body=b"", headers=()):
    has_length = any(h.lower().startswith("content-length:") for h in headers)
    base = [f"HTTP/1.1 {status} OK", "Connection: close"]
    if not has_length:
        base.append(f"Content-Length: {len(body)}")
    base.extend(headers)
    return "\r\n".join(base).encode() + b"\r\n\r\n" + body


@pytest.fixture
def serve():
    servers = []

    def start(reply, host="127.0.0.1", family=socket.AF_INET, ssl_context: ssl.SSLContext | None = None):
        servers.append(LoopbackServer(reply, host=host, family=family, ssl_context=ssl_context))
        return servers[-1]

    yield start
    for item in servers:
        item.close()


@pytest.fixture(scope="module")
def tls_pair(tmp_path_factory):
    cert_dir = tmp_path_factory.mktemp("tls")
    cert_file = cert_dir / "cert.pem"
    key_file = cert_dir / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key_file),
            "-out",
            str(cert_file),
            "-days",
            "1",
            "-subj",
            "/CN=secure.fixture",
            "-addext",
            "subjectAltName=DNS:secure.fixture",
        ],
        check=True,
        capture_output=True,
    )
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
    return server_ctx, cert_file


def test_send_pinned_request_defense_in_depth_and_http_https_dial(serve, tls_pair):
    assert MAX_RESPONSE_BYTES == 256 * 1024
    assert REQUEST_TIMEOUT_SECONDS == 10.0

    for bad_ip in (None, 123, "", "fixture.invalid", "127.0.0.0/8"):
        with pytest.raises(TransportRefused) as exc_info:
            send_pinned_request("http", "fixture.invalid", 80, bad_ip)  # type: ignore[arg-type]
        assert (exc_info.value.rule, exc_info.value.delivered) == ("invalid_allowed_ips", False)

    for refused in ("169.254.169.254", "::ffff:169.254.169.254", "0.0.0.0"):
        with pytest.raises(TransportRefused) as exc_info:
            send_pinned_request("http", "fixture.invalid", 80, refused)
        assert (exc_info.value.rule, exc_info.value.delivered) == ("refused_ip", False)

    server = serve(wire_response(201, b'{"ok":true}', ["Content-Type: text/plain; charset=utf-8"]))
    with patch.object(socket, "getaddrinfo", side_effect=AssertionError("pinned_ip must dial without DNS")):
        result = send_pinned_request(
            "http",
            "fixture.invalid",
            server.port,
            "127.0.0.1",
            "POST",
            "/items?x=1",
            {"X-Test": "yes", "Connection": "close"},
            b'{"n":1}',
            timeout=2.0,
        )
    assert result == {
        "status_code": 201,
        "body": '{"ok":true}',
        "bytes": 11,
        "peer_ip": "127.0.0.1",
        "content_type": "text/plain; charset=utf-8",
    }
    sent = server.requests[0]
    assert sent.startswith(b"POST /items?x=1 HTTP/1.1\r\n")
    assert f"Host: fixture.invalid:{server.port}\r\n".encode() in sent
    assert b"X-Test: yes\r\n" in sent and sent.endswith(b'\r\n\r\n{"n":1}')

    # Default method="GET" and path="/", plus HTTP default-port 80 omission vs port 443 retention.
    plain_default = serve(wire_response(200, b"d1"))
    real_connect = socket.socket.connect

    def redirect_ports(sock, addr):
        ip, port = addr[0], addr[1]
        if port in (80, 443):
            return real_connect(sock, (ip, plain_default.port))
        return real_connect(sock, addr)

    with patch.object(socket.socket, "connect", redirect_ports):
        send_pinned_request("http", "plain.fixture", 80, "127.0.0.1", timeout=2.0)
        send_pinned_request("http", "plain.fixture", 443, "127.0.0.1", timeout=2.0)
    assert plain_default.requests[0].startswith(b"GET / HTTP/1.1\r\n")
    assert b"Host: plain.fixture\r\n" in plain_default.requests[0]
    assert b"Host: plain.fixture:443\r\n" in plain_default.requests[1]

    # Real TLS over loopback pinned IP: verifies SNI/SAN against host and omits :443 in Host header.
    server_ctx, cert_file = tls_pair
    tls_server = serve(wire_response(200, b"plain"), ssl_context=server_ctx)
    real_default_ctx = ssl.create_default_context

    def redirect_443_to_loopback(sock, addr):
        ip, port = addr[0], addr[1]
        return real_connect(sock, (ip, tls_server.port if port == 443 else port))

    handshake_timeouts = []
    real_wrap = ssl.SSLContext.wrap_socket

    def record_wrap_timeout(self, sock, *args, **kwargs):
        if not kwargs.get("server_side"):
            handshake_timeouts.append((sock.gettimeout(), kwargs))
        return real_wrap(self, sock, *args, **kwargs)

    # Clock ticks: deadline=100.8 -> pre-connect remaining=0.7 -> pre-TLS remaining=0.5 (0 < remaining <= 1) -> pre-request=0.3 -> body read=0.2
    ticks = iter([100.0, 100.1, 100.3, 100.5, 100.6, 100.7])
    with patch.object(
        target_transport.ssl, "create_default_context", lambda: real_default_ctx(cafile=str(cert_file))
    ), patch.object(socket.socket, "connect", redirect_443_to_loopback), patch.object(
        ssl.SSLContext, "wrap_socket", record_wrap_timeout
    ), patch.object(target_transport.time, "monotonic", lambda: next(ticks)):
        https_res = send_pinned_request("https", "secure.fixture", 443, "127.0.0.1", timeout=0.8)
    assert https_res == {
        "status_code": 200,
        "body": "plain",
        "bytes": 5,
        "peer_ip": "127.0.0.1",
        "content_type": "application/json",
    }
    assert len(handshake_timeouts) == 1
    assert handshake_timeouts[0][0] == pytest.approx(0.5)
    assert handshake_timeouts[0][1] == {"server_hostname": "secure.fixture", "do_handshake_on_connect": False}
    assert b"Host: secure.fixture\r\n" in tls_server.requests[0]

    # IPv6 literal dial uses AF_INET6 when available.
    try:
        v6 = serve(wire_response(200, b"v6"), host="::1", family=socket.AF_INET6)
    except OSError:
        pytest.skip("IPv6 loopback is not available here")
    v6_res = send_pinned_request("http", "::1", v6.port, "::1", timeout=2.0)
    assert v6_res["peer_ip"] == "::1" and v6_res["body"] == "v6"
    assert f"Host: [::1]:{v6.port}\r\n".encode() in v6.requests[0]


def test_bodiless_head_and_204_ignore_declared_content_length_while_304_is_refused_as_3xx(serve):
    head_server = serve(b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\nConnection: close\r\n\r\n")
    assert send_pinned_request("http", "127.0.0.1", head_server.port, "127.0.0.1", "HEAD", "/") == {
        "status_code": 200,
        "body": "",
        "bytes": 0,
        "peer_ip": "127.0.0.1",
        "content_type": "application/json",
    }
    s204 = serve(b"HTTP/1.1 204 No Content\r\nContent-Length: 42\r\nConnection: close\r\n\r\n")
    res = send_pinned_request("http", "127.0.0.1", s204.port, "127.0.0.1", "GET", "/")
    assert (res["status_code"], res["body"], res["bytes"]) == (204, "", 0)

    s304 = serve(b"HTTP/1.1 304 Not Modified\r\nContent-Length: 42\r\nConnection: close\r\n\r\n")
    with pytest.raises(TransportRefused) as exc_info:
        send_pinned_request("http", "127.0.0.1", s304.port, "127.0.0.1", "GET", "/")
    assert (exc_info.value.rule, exc_info.value.delivered, exc_info.value.status_code) == ("redirect", True, 304)


def test_pre_send_failures_never_mark_delivered_and_clean_up_egress_sockets(serve, tls_pair):
    # Pre-revoked egress stops before opening a connection.
    sockets: set[socket.socket] = set()
    lock = threading.Lock()
    revoked = threading.Event()
    revoked.set()
    with pytest.raises(TransportRefused) as exc_info:
        send_pinned_request("http", "127.0.0.1", 9, "127.0.0.1", egress=(sockets, lock, revoked))
    assert (exc_info.value.rule, exc_info.value.delivered, exc_info.value.status_code) == ("revoked", False, None)
    assert sockets == set()

    # Non-positive timeout expires before sending anything.
    fresh_egress = (sockets, lock, threading.Event())
    for non_positive in (0.0, -0.5):
        with pytest.raises(TransportRefused) as exc_info:
            send_pinned_request("http", "127.0.0.1", 9, "127.0.0.1", timeout=non_positive, egress=fresh_egress)
        assert (exc_info.value.rule, exc_info.value.delivered, exc_info.value.status_code) == ("connect_timeout", False, None)
        assert sockets == set()

    # Refused TCP port fails pre-send with connect_failed.
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
    with pytest.raises(TransportRefused) as exc_info:
        send_pinned_request("http", "127.0.0.1", closed_port, "127.0.0.1", timeout=1.0, egress=fresh_egress)
    assert (exc_info.value.rule, exc_info.value.delivered, exc_info.value.status_code) == ("connect_failed", False, None)
    assert sockets == set()

    # TLS hostname mismatch fails during handshake (pre-send: delivered=False).
    server_ctx, cert_file = tls_pair
    tls_server = serve(wire_response(200, b"secret"), ssl_context=server_ctx)
    real_default_ctx = ssl.create_default_context
    with patch.object(target_transport.ssl, "create_default_context", lambda: real_default_ctx(cafile=str(cert_file))):
        with pytest.raises(TransportRefused) as exc_info:
            send_pinned_request(
                "https", "wrong.fixture", tls_server.port, "127.0.0.1", timeout=2.0, egress=fresh_egress
            )
    assert (exc_info.value.rule, exc_info.value.delivered, exc_info.value.status_code) == ("connect_failed", False, None)
    assert tls_server.requests == []
    assert sockets == set()

    # Exact zero remaining clock boundaries before connect, before TLS handshake, and right after HTTP connect.
    plain_ok = serve(wire_response(200, b"ok"))
    with patch.object(target_transport.time, "monotonic", side_effect=[100.0, 101.0]), patch.object(
        socket.socket, "connect", side_effect=AssertionError("zero remaining before connect must not dial")
    ):
        with pytest.raises(TransportRefused) as exc_info:
            send_pinned_request("http", "127.0.0.1", plain_ok.port, "127.0.0.1", timeout=1.0, egress=fresh_egress)
        assert (exc_info.value.rule, exc_info.value.delivered) == ("connect_timeout", False)
    for tls_clock in ([100.0, 100.5, 102.0], [100.0, 100.5, 102.5]):
        with patch.object(target_transport.time, "monotonic", side_effect=tls_clock):
            with pytest.raises(TransportRefused) as exc_info:
                send_pinned_request("https", "secure.fixture", plain_ok.port, "127.0.0.1", timeout=2.0, egress=fresh_egress)
            assert (exc_info.value.rule, exc_info.value.delivered) == ("connect_timeout", False)
    for post_conn_clock in ([100.0, 100.5, 101.0], [100.0, 100.5, 101.5]):
        with patch.object(target_transport.time, "monotonic", side_effect=post_conn_clock):
            with pytest.raises(TransportRefused) as exc_info:
                send_pinned_request("http", "127.0.0.1", plain_ok.port, "127.0.0.1", timeout=1.0, egress=fresh_egress)
            assert (exc_info.value.rule, exc_info.value.delivered) == ("connect_timeout", False)
    assert plain_ok.requests == []

    # Revocation set during plain HTTP connect aborts before sending anything.
    revoke_http = threading.Event()
    real_sock_connect = socket.socket.connect

    def connect_then_revoke(sock, addr):
        out = real_sock_connect(sock, addr)
        revoke_http.set()
        return out

    with patch.object(socket.socket, "connect", connect_then_revoke):
        with pytest.raises(TransportRefused) as exc_info:
            send_pinned_request(
                "http", "127.0.0.1", plain_ok.port, "127.0.0.1", timeout=2.0, egress=(sockets, lock, revoke_http)
            )
    assert (exc_info.value.rule, exc_info.value.delivered) == ("revoked", False)
    assert plain_ok.requests == [] and sockets == set()

    # TLS handshake timeout AND live concurrent egress revocation during a blocked TLS handshake.
    stalled_raw = socket.socket()
    stalled_raw.bind(("127.0.0.1", 0))
    stalled_raw.listen()
    stalled_port = stalled_raw.getsockname()[1]
    accepted = []
    accepted_event = threading.Event()

    def hold_tcp():
        while True:
            try:
                conn, _ = stalled_raw.accept()
            except OSError:
                return
            accepted.append(conn)
            accepted_event.set()

    threading.Thread(target=hold_tcp, daemon=True).start()
    try:
        with pytest.raises(TransportRefused) as exc_info:
            send_pinned_request("https", "secure.fixture", stalled_port, "127.0.0.1", timeout=0.15, egress=fresh_egress)
        assert (exc_info.value.rule, exc_info.value.delivered, exc_info.value.status_code) == ("connect_timeout", False, None)
        assert sockets == set()

        # Now block in do_handshake() with a long timeout, and revoke egress concurrently (shutting down active sockets).
        accepted_event.clear()
        live_revoke = threading.Event()

        def revoke_stalled_handshake():
            accepted_event.wait(timeout=2.0)
            time.sleep(0.05)
            with lock:
                live_revoke.set()
                for active in list(sockets):
                    try:
                        active.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    try:
                        active.close()
                    except OSError:
                        pass
                sockets.clear()

        threading.Thread(target=revoke_stalled_handshake, daemon=True).start()
        started_revoke = time.monotonic()
        with pytest.raises(TransportRefused) as exc_info:
            send_pinned_request(
                "https", "secure.fixture", stalled_port, "127.0.0.1", timeout=3.0, egress=(sockets, lock, live_revoke)
            )
        assert time.monotonic() - started_revoke < 1.5
        assert (exc_info.value.rule, exc_info.value.delivered, exc_info.value.status_code) == ("revoked", False, None)
        assert sockets == set()
    finally:
        stalled_raw.close()
        for c in accepted:
            c.close()

    # Revocation set right after TCP connect (before TLS handshake) aborts with revoked (delivered=False).
    revoke_mid = threading.Event()
    real_wrap = ssl.SSLContext.wrap_socket

    def revoke_on_wrap(self, sock, *args, **kwargs):
        revoke_mid.set()
        return real_wrap(self, sock, *args, **kwargs)

    with patch.object(target_transport.ssl, "create_default_context", lambda: real_default_ctx(cafile=str(cert_file))), patch.object(
        ssl.SSLContext, "wrap_socket", revoke_on_wrap
    ):
        with pytest.raises(TransportRefused) as exc_info:
            send_pinned_request(
                "https", "secure.fixture", tls_server.port, "127.0.0.1", timeout=2.0, egress=(sockets, lock, revoke_mid)
            )
    assert (exc_info.value.rule, exc_info.value.delivered, exc_info.value.status_code) == ("revoked", False, None)
    assert sockets == set()


def test_post_send_policy_and_framing_refusals_report_delivered_and_status(serve):
    # Deployment identity check runs before redirect/encoding/body checks.
    dep_ok = serve(wire_response(200, b"ok", ["X-Deploy: v1"]))
    assert (
        send_pinned_request(
            "http", "127.0.0.1", dep_ok.port, "127.0.0.1", deployment_header="X-Deploy", deployment_id="v1"
        )["body"]
        == "ok"
    )
    for hdrs, status in (([], 200), (["X-Deploy: v2"], 302)):
        dep_bad = serve(wire_response(status, b"moved", ["Location: http://evil.invalid/", *hdrs]))
        with pytest.raises(TransportRefused) as exc_info:
            send_pinned_request(
                "http", "127.0.0.1", dep_bad.port, "127.0.0.1", deployment_header="X-Deploy", deployment_id="v1"
            )
        assert (exc_info.value.rule, exc_info.value.delivered, exc_info.value.status_code) == (
            "deployment_changed",
            True,
            status,
        )

    # Every 3xx status is refused with redirect; 299 and 400 are allowed.
    for status in (300, 301, 302, 307, 308, 399):
        redir = serve(wire_response(status, b"go", ["Location: http://elsewhere.invalid/"]))
        with pytest.raises(TransportRefused) as exc_info:
            send_pinned_request("http", "127.0.0.1", redir.port, "127.0.0.1")
        assert (exc_info.value.rule, exc_info.value.delivered, exc_info.value.status_code) == ("redirect", True, status)
    for status in (299, 400, 500):
        ok_s = serve(wire_response(status, b"x"))
        assert send_pinned_request("http", "127.0.0.1", ok_s.port, "127.0.0.1")["status_code"] == status

    # Compression: empty and identity (case-insensitive) pass; anything else is compressed.
    for enc in ("", "identity", "IDENTITY"):
        enc_ok = serve(wire_response(200, b"hi", [f"Content-Encoding: {enc}"]))
        assert send_pinned_request("http", "127.0.0.1", enc_ok.port, "127.0.0.1")["body"] == "hi"
    for enc in ("gzip", "br", "deflate"):
        enc_bad = serve(wire_response(206, b"hi", [f"Content-Encoding: {enc}"]))
        with pytest.raises(TransportRefused) as exc_info:
            send_pinned_request("http", "127.0.0.1", enc_bad.port, "127.0.0.1")
        assert (exc_info.value.rule, exc_info.value.delivered, exc_info.value.status_code) == ("compressed", True, 206)

    # Strict ASCII Content-Length (including Latin-1 superscript digit \xb2 where str.isdigit() is True),
    # negative/oversized declared length, oversized streamed body, incomplete body, invalid UTF-8.
    for bad_len_bytes in (b"abc", b"", b"-", b"+5", b"5+1", "۱۲".encode(), b"\xb2", b"-\xb2"):
        bad_s = serve(b"HTTP/1.1 200 OK\r\nContent-Length: " + bad_len_bytes + b"\r\nConnection: close\r\n\r\nhello")
        with pytest.raises(TransportRefused) as exc_info:
            send_pinned_request("http", "127.0.0.1", bad_s.port, "127.0.0.1", max_response_bytes=32)
        assert (exc_info.value.rule, exc_info.value.delivered, exc_info.value.status_code) == (
            "invalid_length",
            True,
            200,
        )

    for over_len in ("33", "-1"):
        over_s = serve(f"HTTP/1.1 201 OK\r\nContent-Length: {over_len}\r\nConnection: close\r\n\r\n".encode() + b"A" * 40)
        with pytest.raises(TransportRefused) as exc_info:
            send_pinned_request("http", "127.0.0.1", over_s.port, "127.0.0.1", max_response_bytes=32)
        assert (exc_info.value.rule, exc_info.value.delivered, exc_info.value.status_code) == (
            "declared_too_large",
            True,
            201,
        )

    exact_s = serve(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + b"B" * 32)
    assert send_pinned_request("http", "127.0.0.1", exact_s.port, "127.0.0.1", max_response_bytes=32)["bytes"] == 32

    stream_over = serve(b"HTTP/1.1 202 OK\r\nConnection: close\r\n\r\n" + b"B" * 33)
    with pytest.raises(TransportRefused) as exc_info:
        send_pinned_request("http", "127.0.0.1", stream_over.port, "127.0.0.1", max_response_bytes=32)
    assert (exc_info.value.rule, exc_info.value.delivered, exc_info.value.status_code) == ("body_too_large", True, 202)

    short_s = serve(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nhello")
    with pytest.raises(TransportRefused) as exc_info:
        send_pinned_request("http", "127.0.0.1", short_s.port, "127.0.0.1", max_response_bytes=32)
    assert (exc_info.value.rule, exc_info.value.delivered, exc_info.value.status_code) == ("incomplete_body", True, 200)

    bad_utf8 = serve(wire_response(200, b"\xff\xfe"))
    with pytest.raises(TransportRefused) as exc_info:
        send_pinned_request("http", "127.0.0.1", bad_utf8.port, "127.0.0.1")
    assert (exc_info.value.rule, exc_info.value.delivered, exc_info.value.status_code) == ("invalid_utf8", True, 200)


def test_chunked_reads_watchdog_timeouts_and_protocol_errors(serve):
    import http.client

    chunked = serve(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n"
    )
    assert send_pinned_request("http", "127.0.0.1", chunked.port, "127.0.0.1")["body"] == "abcdef"

    # Per-chunk read1 bounds size to min(8192, max_response_bytes + 1 - size) and updates remaining timeout.
    timeouts, sizes = [], []
    real_settimeout, real_read1 = socket.socket.settimeout, http.client.HTTPResponse.read1

    def spy_read1(self, size=-1):
        chunk = real_read1(self, size)
        sizes.append((size, len(chunk)))
        return chunk

    big_limit = 8192 * 2 + 5
    big_server = serve(wire_response(200, b"C" * big_limit))
    with patch.object(socket.socket, "settimeout", lambda s, v: timeouts.append(v) or real_settimeout(s, v)), patch.object(
        http.client.HTTPResponse, "read1", spy_read1
    ):
        got = send_pinned_request(
            "http", "127.0.0.1", big_server.port, "127.0.0.1", timeout=2.5, max_response_bytes=big_limit
        )
    assert got["bytes"] == big_limit
    body_timeouts = [v for v in timeouts if v != 2]
    assert len(body_timeouts) >= 4 and all(0 < v <= 2.5 for v in body_timeouts)
    seen_bytes = 0
    for ask, n in sizes:
        assert ask == min(8192, big_limit + 1 - seen_bytes)
        seen_bytes += n
    assert sizes[-1] == (1, 0)

    # Slow trickled headers are interrupted by the daemon watchdog and reported as post-send timeout (delivered=True).
    def slow_headers(conn, _req):
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n")
        for idx in range(40):
            time.sleep(0.05)
            conn.sendall(f"X-Slow-{idx}: 1\r\n".encode())
        conn.sendall(b"\r\n")

    timers = []
    real_timer = threading.Timer
    started = time.monotonic()
    with patch.object(
        target_transport.threading, "Timer", lambda *a, **k: timers.append(real_timer(*a, **k)) or timers[-1]
    ):
        with pytest.raises(TransportRefused) as exc_info:
            send_pinned_request("http", "127.0.0.1", serve(slow_headers).port, "127.0.0.1", timeout=0.25)
    assert time.monotonic() - started < 0.8
    assert len(timers) == 1 and timers[0].daemon is True
    assert (exc_info.value.rule, exc_info.value.delivered, exc_info.value.status_code) == ("timeout", True, None)

    # Slow trickled body is also reported as post-send timeout (delivered=True).
    def slow_body(conn, _req):
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\npart1")
        for _ in range(20):
            time.sleep(0.05)
            conn.sendall(b"x")

    with pytest.raises(TransportRefused) as exc_info:
        send_pinned_request("http", "127.0.0.1", serve(slow_body).port, "127.0.0.1", timeout=0.2)
    assert (exc_info.value.rule, exc_info.value.delivered, exc_info.value.status_code) == ("timeout", True, None)

    # Pure socket TimeoutError post-send (even if watchdog has not fired yet) is also timeout (delivered=True).
    class InertTimer:
        daemon = False

        def start(self):
            pass

        def cancel(self):
            pass

    def silent_peer(conn, _req):
        time.sleep(0.35)

    with patch.object(target_transport.threading, "Timer", lambda *_a, **_k: InertTimer()):
        with pytest.raises(TransportRefused) as exc_info:
            send_pinned_request("http", "127.0.0.1", serve(silent_peer).port, "127.0.0.1", timeout=0.1)
    assert (exc_info.value.rule, exc_info.value.delivered, exc_info.value.status_code) == ("timeout", True, None)

    # Malformed or empty post-send HTTP reply is protocol_error (delivered=True).
    for garbage in (b"", b"NOT-HTTP\r\n\r\n"):
        bad_proto = serve(garbage)
        with pytest.raises(TransportRefused) as exc_info:
            send_pinned_request("http", "127.0.0.1", bad_proto.port, "127.0.0.1", timeout=1.0)
        assert (exc_info.value.rule, exc_info.value.delivered, exc_info.value.status_code) == (
            "protocol_error",
            True,
            None,
        )




