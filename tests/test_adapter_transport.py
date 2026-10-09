"""The HTTP transport, request preparation and oracle of adapters.py, one boundary at a time.

A loopback listener answers each connection with the exact bytes the test chose, so the transport's limits, its
deadline and the shape of what it returns are checked without a fixture application, a network or a credential.
"""
import hashlib
import ipaddress
import os
import socket
import threading
import time
from unittest.mock import patch

import pytest

from vibe_audit import adapters
from vibe_audit.adapters import (AdapterBlocked, ResponseLimitError, _origin, _pinned_address, _prepare_request,
                                 _request, _result, evaluate_oracle, execute_case, secret_forms,
                                 target_credential_origins, unbound_target_credentials)

HEADERS = {"Accept": "application/json", "Accept-Encoding": "identity", "Connection": "close"}
ORIGINS = adapters.TARGET_CREDENTIAL_ORIGINS_ENV


class Listener:
    """Answers every connection with `reply`: bytes sent as they are, or a function given the socket and request."""

    def __init__(self, reply):
        self.reply = reply
        self.requests = []
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen()
        self.port = self.socket.getsockname()[1]
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                conn, _ = self.socket.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(2)
                request = b""
                while b"\r\n\r\n" not in request:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    request += chunk
                head, _, body = request.partition(b"\r\n\r\n")
                declared = [line.split(b":", 1)[1].strip() for line in head.split(b"\r\n") if line.lower().startswith(b"content-length:")]
                while declared and len(body) < int(declared[0]):
                    body += conn.recv(65536)
                self.requests.append(head + b"\r\n\r\n" + body)
                try:
                    self.reply(conn, request) if callable(self.reply) else conn.sendall(self.reply)
                except OSError:
                    pass

    def close(self):
        self.socket.close()


def response(status=200, body=b"", headers=()):
    lines = [f"HTTP/1.1 {status} X", f"Content-Length: {len(body)}", "Connection: close", *headers]
    return "\r\n".join(lines).encode() + b"\r\n\r\n" + body


@pytest.fixture
def listen():
    listeners = []

    def start(reply):
        listeners.append(Listener(reply))
        return listeners[-1]
    yield start
    for listener in listeners:
        listener.close()


def fetch(listener, method="GET", path="/", body=None, timeout=2.0, scheme="http", host="127.0.0.1"):
    return _request(scheme, host, listener.port, "127.0.0.1", method, path, HEADERS, body, timeout)


def test_complete_response_is_returned_with_its_size(listen):
    server = listen(response(200, b"hello"))
    assert fetch(server) == {"status_code": 200, "body": "hello", "complete": True, "bytes": 5}
    request = server.requests[0]
    assert request.startswith(b"GET / HTTP/1.1\r\n") and f"Host: 127.0.0.1:{server.port}\r\n".encode() in request
    assert b"Accept-Encoding: identity\r\n" in request and b"Connection: close\r\n" in request


def test_request_body_is_sent_as_given(listen):
    server = listen(response(201, b"{}"))
    assert fetch(server, "POST", "/items", b'{"a": 1}')["status_code"] == 201
    assert b"\r\nContent-Length: 8\r\n" in server.requests[0] and server.requests[0].endswith(b'\r\n\r\n{"a": 1}')


def test_every_3xx_status_is_reported_as_a_blocked_redirect_and_nothing_else_is(listen):
    for status in [300, 301, 302, 307, 399]:
        server = listen(response(status, b"moved", ["Location: http://elsewhere.invalid/"]))
        assert fetch(server) == {"status_code": status, "body": "", "complete": False, "redirect_blocked": True}, status
    for status in [299, 400, 404, 500]:
        assert fetch(listen(response(status, b"x"))) == {"status_code": status, "body": "x", "complete": True, "bytes": 1}, status


def test_chunked_and_unsized_bodies_are_joined_in_order(listen):
    chunked = listen(b"HTTP/1.1 200 X\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n")
    assert fetch(chunked) == {"status_code": 200, "body": "abcdef", "complete": True, "bytes": 6}

    def trickle(conn, request):
        conn.sendall(b"HTTP/1.1 200 X\r\nConnection: close\r\n\r\nfirst ")
        time.sleep(0.05)
        conn.sendall(b"second")
    assert fetch(listen(trickle)) == {"status_code": 200, "body": "first second", "complete": True, "bytes": 12}


def test_declared_length_is_bounded_and_must_be_met(listen):
    with patch.object(adapters, "MAX_RESPONSE_BYTES", 32):
        assert fetch(listen(response(200, b"A" * 32)))["bytes"] == 32
        assert fetch(listen(response(204, b"")))["bytes"] == 0
        for length in [33, -1]:
            server = listen(f"HTTP/1.1 200 X\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n".encode() + b"A" * 40)
            with pytest.raises(ResponseLimitError, match="^Response exceeds the configured byte limit.$"):
                fetch(server)
    with pytest.raises(ResponseLimitError, match="^Invalid response length; no oracle was evaluated.$"):
        fetch(listen(b"HTTP/1.1 200 X\r\nContent-Length: abc\r\nConnection: close\r\n\r\nxyz"))
    with pytest.raises(ResponseLimitError, match="^Response was incomplete; no oracle was evaluated.$"):
        fetch(listen(b"HTTP/1.1 200 X\r\nContent-Length: 10\r\nConnection: close\r\n\r\nhello"))


def test_unsized_body_is_bounded_by_the_same_limit(listen):
    with patch.object(adapters, "MAX_RESPONSE_BYTES", 32):
        assert fetch(listen(b"HTTP/1.1 200 X\r\nConnection: close\r\n\r\n" + b"B" * 32))["bytes"] == 32
        with pytest.raises(ResponseLimitError, match="^Response exceeds the configured byte limit.$"):
            fetch(listen(b"HTTP/1.1 200 X\r\nConnection: close\r\n\r\n" + b"B" * 33))


def test_compressed_and_non_utf8_responses_are_refused_but_an_empty_encoding_is_identity(listen):
    with pytest.raises(ResponseLimitError, match="^Compressed responses are unsupported; no oracle was evaluated.$"):
        fetch(listen(response(200, b"x", ["Content-Encoding: gzip"])))
    assert fetch(listen(response(200, b"x", ["Content-Encoding: "])))["body"] == "x"
    with pytest.raises(ResponseLimitError, match="^Only complete UTF-8 responses can be evaluated.$"):
        fetch(listen(response(200, b"\xff\xfe")))


def test_slow_headers_are_cut_at_the_deadline_and_count_as_a_timeout(listen):
    def dribble(conn, request):
        conn.sendall(b"HTTP/1.1 200 X\r\nContent-Length: 0\r\n")
        for index in range(40):
            time.sleep(0.05)
            conn.sendall(f"X-Line-{index}: 1\r\n".encode())
        conn.sendall(b"\r\n")
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        fetch(listen(dribble), timeout=0.3)
    assert time.monotonic() - started < 1.5


def test_a_refused_connection_raises_instead_of_answering():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    with pytest.raises(ConnectionRefusedError):
        _request("http", "127.0.0.1", port, "127.0.0.1", "GET", "/", HEADERS, None, 1.0)


def test_https_wraps_the_pinned_socket_with_the_authorized_host_name(listen):
    server = listen(response(200, b"tls"))
    wrapped = []

    class Context:
        def wrap_socket(self, sock, **kwargs):
            wrapped.append((sock, kwargs))
            return sock
    with patch.object(adapters.ssl, "create_default_context", Context):
        result = fetch(server, scheme="https", host="fixture.invalid", timeout=0.5)
    assert result["body"] == "tls"
    assert len(wrapped) == 1 and wrapped[0][1] == {"server_hostname": "fixture.invalid"}
    assert 0 < wrapped[0][0].gettimeout() <= 0.5
    assert f"Host: fixture.invalid:{server.port}\r\n".encode() in server.requests[0]
    # The listener got no TLS handshake: the plain socket was wrapped by the fake context.
    with patch.object(adapters.ssl, "create_default_context", side_effect=AssertionError("no TLS over http")):
        assert fetch(server)["body"] == "tls"


def test_tls_handshake_gets_only_the_time_the_connection_left(listen):
    server = listen(response(200, b""))
    connection = adapters._PinnedHTTPSConnection("fixture.invalid", server.port, pinned_ip="127.0.0.1", timeout=2.0)
    # The deadline is taken before connecting; the clock then reads exactly the deadline and later past it.
    for clock in [[100.0, 102.0], [100.0, 102.5]]:
        with patch.object(adapters.time, "monotonic", side_effect=clock), pytest.raises(TimeoutError):
            connection.connect()


def test_pinned_connection_keeps_its_timeout_and_dials_the_numeric_address(listen):
    server = listen(response(200, b""))
    connection = adapters._PinnedHTTPConnection("fixture.invalid", server.port, pinned_ip="127.0.0.1", timeout=1.5)
    assert connection.timeout == 1.5
    with patch.object(socket, "getaddrinfo", side_effect=AssertionError("the pinned address needs no DNS")):
        connection.connect()
    assert connection.sock.gettimeout() == 1.5 and connection.sock.getpeername() == ("127.0.0.1", server.port)
    connection.close()
    instances = []

    class Spy(adapters._PinnedHTTPConnection):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            instances.append(self)
    with patch.object(adapters, "_PinnedHTTPConnection", Spy):
        fetch(server, timeout=1.25)
    assert [(c.host, c.port, c.pinned_ip, c.timeout) for c in instances] == [("127.0.0.1", server.port, "127.0.0.1", 1.25)]


def test_pinned_connection_uses_the_address_family_of_its_pinned_ip():
    try:
        server = socket.socket(socket.AF_INET6)
        server.bind(("::1", 0))
    except OSError:
        pytest.skip("IPv6 loopback is not available here")
    server.listen()
    connection = adapters._PinnedHTTPConnection("fixture.invalid", server.getsockname()[1], pinned_ip="::1", timeout=1.0)
    connection.connect()
    assert connection.sock.family == socket.AF_INET6
    connection.close()
    server.close()


def test_result_shape():
    assert _result("blocked", "why") == {"status": "blocked", "reason": "why", "observations": [], "evidence": [], "requests": 0}
    assert _result("fail", "why", [{"kind": "x"}], 2) == {"status": "fail", "reason": "why", "observations": [{"kind": "x"}],
                                                        "evidence": [], "requests": 2}


@pytest.mark.parametrize("raw,origin", [
    ("http://Example.TEST", ("http", "example.test", 80)),
    ("https://example.test/", ("https", "example.test", 443)),
    ("http://example.test:1", ("http", "example.test", 1)),
    ("http://example.test:65535", ("http", "example.test", 65535)),
    ("https://example.test:80", ("https", "example.test", 80)),
    ("http://例子.測試", ("http", "xn--fsqu00a.xn--g6w251d", 80)),
    ("http://[::1]:8000", ("http", "::1", 8000)),
])
def test_origin_normalizes_scheme_host_and_port(raw, origin):
    assert _origin({"target_url": raw}) == origin


@pytest.mark.parametrize("raw", [
    None, 5, ["http://example.test"], "", "http://", "ftp://example.test", "http://user@example.test",
    "http://user:pw@example.test", "http://example.test/path", "http://example.test/?q", "http://example.test/#f",
    "http://example.test\\x", "http://example%2etest", "http://example.test:0", "http://example.test:65536",
    "http://example.test:x", "http://example .test", "http://example.test\n",
])
def test_origin_refuses_anything_but_one_exact_origin(raw):
    manifest = {} if raw is None else {"target_url": raw}
    with pytest.raises(AdapterBlocked, match="^Target must be a single exact HTTP\\(S\\) origin without credentials, path or query.$"):
        _origin(manifest)
    if raw is not None:
        with pytest.raises(ValueError, match="^Not a single exact HTTP\\(S\\) origin$"):
            adapters.parse_origin(raw)


def test_parse_origin_is_the_one_reading_every_origin_check_shares():
    """Targets refuse a path; model endpoints carry one (allow_path) and are otherwise read the same way."""
    assert adapters.parse_origin("https://Api.Example:8443/v1/", allow_path=True) == ("https", "api.example", 8443)
    assert adapters.parse_origin("http://[::1]:11434/v1", allow_path=True) == ("http", "::1", 11434)
    assert adapters.parse_origin("http://例子.測試/v1", allow_path=True) == ("http", "xn--fsqu00a.xn--g6w251d", 80)
    for raw in ["http://example.test/v1?x", "http://example.test/v1#f", "http://u@example.test/v1", "http://example.test:0/v1",
                "http://example.test/v1 ", "http://example%2etest/v1", "ftp://example.test/v1"]:
        with pytest.raises(ValueError):
            adapters.parse_origin(raw, allow_path=True)
    with pytest.raises(ValueError):
        adapters.parse_origin("http://example.test/v1")
    # Only the authority is held to the origin rules; a model endpoint's path may carry an escape or any printable character.
    assert adapters.parse_origin("http://example.test/v%31", allow_path=True) == ("http", "example.test", 80)
    assert adapters.parse_origin("http://example.test/v1!~", allow_path=True) == ("http", "example.test", 80)
    assert adapters.format_origin("http", "example.test", 80) == "http://example.test:80"
    assert adapters.format_origin("http", "example.test", 80, omit_default_port=True) == "http://example.test"
    assert adapters.format_origin("https", "::1", 443, omit_default_port=True) == "https://[::1]"
    assert adapters.format_origin("https", "::1", 8443, omit_default_port=True) == "https://[::1]:8443"


def test_secret_forms_cover_the_escapings_a_target_may_reflect():
    assert secret_forms('a/b"c') == {'a/b"c', 'a/b\\"c', 'a\\/b\\"c', "a%2Fb%22c"}
    assert secret_forms("x y") == {"x y", "x%20y"}
    assert secret_forms("") == set()


def test_target_credential_origins_parse_every_entry_or_none():
    assert target_credential_origins({}) == {} and target_credential_origins({ORIGINS: " , "}) == {}
    bound = target_credential_origins({ORIGINS: " VIBEAUDIT_A = http://Host:80 ,VIBEAUDIT_A=https://host, VIBEAUDIT_B=http://[::1]:8"})
    assert bound == {"VIBEAUDIT_A": {("http", "host", 80), ("https", "host", 443)}, "VIBEAUDIT_B": {("http", "::1", 8)}}
    for entry in ["A=http://host", "VIBEAUDIT_DATABASE_URL=http://host", "VIBEAUDIT_A=http://host/x", "VIBEAUDIT_A", "VIBEAUDIT_A=A=http://host"]:
        with pytest.raises(AdapterBlocked, match=f"^{ORIGINS} entries must be VIBEAUDIT_NAME=scheme://host\\[:port\\]$"):
            target_credential_origins({ORIGINS: entry})


def test_unbound_target_credentials_name_the_profiles_the_environment_did_not_bind():
    assert unbound_target_credentials({}) == [] and unbound_target_credentials({"auth_profiles": []}) == []
    manifest = {"target_url": "http://127.0.0.1:8", "auth_profiles": [{"id": "a", "credential_env": "VIBEAUDIT_A"},
                                                                       {"id": "b", "credential_env": "VIBEAUDIT_B"}, {"id": "c"}]}
    environ = {ORIGINS: "VIBEAUDIT_A=http://127.0.0.1:8"}
    # The environment passed in is the one read, not the process environment.
    with patch.dict(os.environ, {ORIGINS: "VIBEAUDIT_B=http://127.0.0.1:8"}):
        assert unbound_target_credentials(manifest, environ) == ["", "VIBEAUDIT_B"]
    assert unbound_target_credentials(manifest, {ORIGINS: "VIBEAUDIT_A=http://127.0.0.1:8,VIBEAUDIT_B=http://127.0.0.1:8"}) == [""]


def test_credential_helpers_read_the_environment_they_are_given():
    assert adapters.credential_env_allowed("VIBEAUDIT_NEW", {}) is True
    with patch.dict(os.environ, {"VIBEAUDIT_NEW": "plain"}, clear=False):
        assert adapters.credential_env_allowed("VIBEAUDIT_NEW", {"VIBEAUDIT_NEW": "http://not-a-key"}) is False
    with patch.dict(os.environ, {adapters.CREDENTIAL_ORIGINS_ENV: "VIBEAUDIT_PROCESS_KEY=https://m"}):
        assert adapters.bound_model_credentials({}) == set(adapters.DEFAULT_CREDENTIAL_ORIGINS)
    # Entries that are not profiles, or name no variable, are skipped; an empty value is never a shared key.
    manifest = {"models": ["x", {"credential_env": 5}, {"credential_env": "VIBEAUDIT_M"}], "auth_profiles": [{"credential_env": "VIBEAUDIT_T"}]}
    assert adapters.shared_credentials(manifest, {"VIBEAUDIT_M": "", "VIBEAUDIT_T": ""}) == []
    assert adapters.shared_credentials(manifest, {"VIBEAUDIT_M": "k", "VIBEAUDIT_T": "k"}) == ["VIBEAUDIT_T"]


def test_model_header_lists_are_checked_with_their_exact_reasons():
    error = adapters.model_header_list_error
    assert error(5) == "model_headers must map header names to lists of values"
    names = "model_headers names must be one of Accept, Accept-Language, Content-Type, If-Match, If-None-Match, X-Requested-With"
    assert error({"Foo": ["x"]}) == names and error({5: ["*"]}) == names
    for lists in [{"Accept": []}, {"Accept": ("*/*",)}, {"Accept": ["*/*", "*/*"]}, {"Accept": ["text/rtf"]}]:
        assert error(lists) == "model_headers[Accept] must be a non-empty list of distinct values from the model vocabulary", lists
    assert error({"Accept": ["*/*"], "If-Match": ["*"]}) is None
    # An entry without a method lists GET; one for another endpoint adds nothing.
    manifest = {"allowed_requests": [{"path": "/a", "model_headers": {"Accept": ["*/*"]}}, {"method": "GET", "path": "/b", "model_headers": {"Accept": ["text/html"]}}]}
    assert adapters.model_header_vocabulary(manifest, "GET", "/a") == {"accept": frozenset({"*/*"})}
    assert adapters.model_header_vocabulary({}, "GET", "/a") == {}
    with pytest.raises(ValueError, match="^A model-designed case repeats a header name$"):
        adapters.canonical_model_headers({"Accept": "*/*", "accept": "text/html"})


def test_ipv4_mapped_addresses_are_read_as_their_ipv4_address():
    assert adapters._unmapped(ipaddress.ip_address("::ffff:127.0.0.1")) == ipaddress.ip_address("127.0.0.1")
    assert adapters._unmapped(ipaddress.ip_address("::1")) == ipaddress.ip_address("::1")
    assert adapters._unmapped(ipaddress.ip_address("10.0.0.1")) == ipaddress.ip_address("10.0.0.1")


def test_pinned_address_reasons_and_choice():
    for allowed, message in [("10.0.0.5", "Allowed target IPs must be explicit IP addresses, not hostnames or ranges."),
                             ([], "No target IP addresses were explicitly authorized."),
                             (["169.254.169.254"], "Target IPs cannot be cloud metadata, link-local, unspecified or multicast addresses.")]:
        with pytest.raises(AdapterBlocked) as refused:
            _pinned_address("10.0.0.5", 80, allowed)
        assert str(refused.value) == message
    with pytest.raises(AdapterBlocked) as refused:
        _pinned_address("10.0.0.7", 80, ["10.0.0.5"])
    assert str(refused.value) == "DNS returned an address outside the exact target IP allowlist."
    # Of several authorized answers the lowest IPv4 address is dialled, before any IPv6 one.
    answers = [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 80, 0, 0)), (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.9", 80)),
               (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 80))]
    with patch.object(socket, "getaddrinfo", return_value=answers):
        assert _pinned_address("fixture.invalid", 80, ["::1", "10.0.0.9", "10.0.0.5"]) == "10.0.0.5"
        assert _pinned_address("fixture.invalid", 80, ["::1", "10.0.0.9", "10.0.0.5", "10.0.0.1"]) == "10.0.0.5"


# --- request preparation ---------------------------------------------------------------------------------------------

TARGET = {"target_url": "http://127.0.0.1:8"}


def blocked(manifest, case, message, **kwargs):
    with pytest.raises(AdapterBlocked) as refused:
        _prepare_request(manifest, case, **kwargs)
    assert str(refused.value) == message


def test_prepared_request_defaults():
    assert _prepare_request({}, {}) == ("GET", "/", {"Accept": "application/json", "Accept-Encoding": "identity", "Connection": "close"}, None, [])
    method, path, headers, body, secrets = _prepare_request({}, {"method": "POST", "path": "/ok!", "body": {"m": "中"}})
    assert (method, path, body, secrets) == ("POST", "/ok!", '{"m": "中"}'.encode("utf-8"), [])
    assert list(headers.items()) == [("Accept", "application/json"), ("Accept-Encoding", "identity"), ("Connection", "close"), ("Content-Type", "application/json")]


@pytest.mark.parametrize("case,message", [
    ({"method": "TRACE"}, "Unsupported HTTP method."),
    ({"path": None}, "Case path must be origin-relative and must not contain control characters."),
    ({"path": "a"}, "Case path must be origin-relative and must not contain control characters."),
    ({"path": "//evil.invalid/"}, "Case path must be origin-relative and must not contain control characters."),
    ({"path": "/a\\b"}, "Case path must be origin-relative and must not contain control characters."),
    ({"path": "/a#b"}, "Case path must be origin-relative and must not contain control characters."),
    ({"path": "/a b"}, "Case path must be origin-relative and must not contain control characters."),
    ({"path": "/é"}, "Case path must use ASCII URL encoding."),
    ({"headers": {"Cookie": "x"}}, "Case contains an unsupported, routing or credential-bearing request header."),
    ({"headers": {"Accept": "a", "accept": "b"}}, "Case repeats a request header name in another letter case."),
    ({"designed_by": "model", "headers": {"Accept": "application/json"}}, "Case contains an unsupported, routing or credential-bearing request header."),
    ({"identity": "reader"}, "Case identity must reference exactly one configured authentication profile."),
    ({"body": {}}, "GET and HEAD cases cannot contain a request body."),
    ({"method": "HEAD", "body": {}}, "GET and HEAD cases cannot contain a request body."),
    ({"method": "POST", "body": {"n": float("nan")}}, "Request body must be finite JSON data."),
    ({"method": "POST", "body": {"s": {1, 2}}}, "Request body must be finite JSON data."),
    ({"method": "POST", "body": {"k": "x" * (adapters.MAX_REQUEST_BYTES - 8)}}, "Request body exceeds the configured byte limit."),
])
def test_prepared_request_refusals(case, message):
    blocked(TARGET, case, message)


def test_request_body_may_fill_the_limit_exactly():
    body = _prepare_request({}, {"method": "POST", "body": {"k": "x" * (adapters.MAX_REQUEST_BYTES - 9)}})[3]
    assert len(body) == adapters.MAX_REQUEST_BYTES


def test_model_headers_pass_inside_the_relay_and_from_an_operator_list_only():
    case = {"path": "/a", "designed_by": "model", "headers": {"Accept": "application/json"}}
    assert _prepare_request({"relay": True}, case)[2]["Accept"] == "application/json"
    listed = {"relay": False, "allowed_requests": [{"method": "GET", "path": "/a", "model_headers": {"Accept": ["application/json"]}}]}
    assert _prepare_request(listed, case)[2]["Accept"] == "application/json"
    for manifest in [{}, {"relay": False}, {"relay": "yes"}, {**listed, "relay": None}]:
        if manifest.get("allowed_requests"):
            continue
        blocked(manifest, case, "Case contains an unsupported, routing or credential-bearing request header.")


def test_duplicate_profiles_and_missing_profile_lists_are_refused():
    message = "Case identity must reference exactly one configured authentication profile."
    blocked({**TARGET, "auth_profiles": [{"id": "r"}, {"id": "r"}]}, {"identity": "r"}, message)
    blocked(TARGET, {"identity": "r"}, message)


def test_identity_credentials_are_checked_then_placed_in_their_header():
    manifest = {**TARGET, "auth_profiles": [{"id": "r", "credential_env": "VIBEAUDIT_T"}]}
    case = {"identity": "r"}
    bound = {ORIGINS: "VIBEAUDIT_T=http://127.0.0.1:8"}
    blocked({**TARGET, "auth_profiles": [{"id": "r"}]}, case, "Credentials must reference a VIBEAUDIT_ environment variable that is not a Vibe Audit setting.")
    with patch.dict(os.environ, bound, clear=False):
        for secret in [None, "", "a b", "a\x7f", "a\t", "é", "x" * 8193]:
            with patch.dict(os.environ, {} if secret is None else {"VIBEAUDIT_T": secret}):
                os.environ.pop("VIBEAUDIT_T", None) if secret is None else None
                blocked(manifest, case, "Authentication credential is missing or invalid.")
        for secret in ["!~", "x" * 8192]:
            with patch.dict(os.environ, {"VIBEAUDIT_T": secret}):
                assert _prepare_request(manifest, case)[2]["Authorization"] == f"Bearer {secret}"
    with patch.dict(os.environ, {"VIBEAUDIT_T": "s3cret", ORIGINS: "VIBEAUDIT_T=http://127.0.0.1:9"}):
        blocked(manifest, case, f"VIBEAUDIT_T is not bound to this target; bind test credentials to their origins in {ORIGINS}.")
    with patch.dict(os.environ, {"VIBEAUDIT_T": "s3cret", **bound}):
        shared = {**manifest, "models": [{"id": "m", "credential_env": "VIBEAUDIT_T"}]}
        blocked(shared, case, "A test identity credential cannot also be a model credential.")
        for header, scheme, value in [("Authorization", "Bearer", "Bearer s3cret"), ("Authorization", "Basic", "Basic s3cret"),
                                      ("X-API-Key", "", "s3cret"), ("Authorization", "", "s3cret")]:
            manifest["auth_profiles"][0].update(header=header, scheme=scheme)
            headers, secrets = _prepare_request(manifest, case)[2:5:2]
            assert (headers[header], secrets) == (value, ["s3cret"]), (header, scheme)
        for header, scheme in [("Cookie", "Bearer"), ("Authorization", "Token"), ("x-api-key", ""), ("X-API-Key", "basic")]:
            manifest["auth_profiles"][0].update(header=header, scheme=scheme)
            blocked(manifest, case, "Unsupported authentication header or scheme.")


# --- oracle ----------------------------------------------------------------------------------------------------------

CANARY = "TENANT_B_CANARY"
DIGEST = hashlib.sha256(CANARY.encode()).hexdigest()


def trusted(kind, **fields):
    return {"kind": kind, "provenance": "fixture.local", "case_id": "c1", **fields}


def canary_case(**changes):
    case = {"id": "c1", "preconditions": ["fixture_exists"],
            "oracle": {"kind": "canary_absent", "forbidden_text": [CANARY], "allowed_statuses": [200],
                       "required_observations": ["http_response"]}}
    case.update(changes)
    return case


def control(value=True, name="fixture_exists", **fields):
    return trusted("precondition", **{"name": name, "value": value, "matched_text_sha256": [DIGEST], **fields})


def http(body="safe", status=200, **fields):
    return trusted("http_response", **{"status_code": status, "body": body, "complete": True, **fields})


def verdict(status, reason):
    return {"status": status, "reason": reason}


def test_oracle_requirements_are_matched_by_kind_or_name_and_reported_exactly():
    assert evaluate_oracle({"id": "c1", "oracle": {}}, []) == verdict("inconclusive", "Oracle has no explicit required observations.")
    missing = verdict("inconclusive", "A required trusted observation is missing.")
    assert evaluate_oracle(canary_case(preconditions=[]), [http()]) == verdict("inconclusive", "A positive-control precondition is required to establish the sensitive fixture exists.")
    assert evaluate_oracle(canary_case(), [control()]) == missing
    assert evaluate_oracle(canary_case(oracle={"required_observations": [5]}), [trusted(5)]) == missing
    by_name = canary_case(oracle={"kind": "x", "required_observations": ["fixture_exists"]}, preconditions=[])
    assert evaluate_oracle(by_name, [control()]) == verdict("inconclusive", "Oracle kind is not implemented.")


def test_oracle_preconditions_need_a_verified_observation_of_that_name():
    unverified = verdict("inconclusive", "A required precondition has not been independently verified.")
    others = [control(name="other"), trusted("identity_verified", value=True, role="reader"), http()]
    assert evaluate_oracle(canary_case(), others) == unverified
    assert evaluate_oracle(canary_case(), [control(value=False), http()]) == unverified
    assert evaluate_oracle(canary_case(preconditions=[5]), [control(name=5), http()]) == unverified
    assert evaluate_oracle(canary_case(preconditions=[{"name": "fixture_exists"}]), [control(), http()])["status"] == "pass"


def test_oracle_expected_role_needs_that_role_verified():
    case = canary_case(oracle={**canary_case()["oracle"], "expected_role": "reader"})
    wrong = trusted("identity_verified", value=True, role="admin")
    assert evaluate_oracle(case, [control(), http(), wrong]) == verdict("inconclusive", "The expected test identity has not been independently verified.")
    assert evaluate_oracle(case, [control(), http(), trusted("identity_verified", value=True, role="reader")])["status"] == "pass"


def test_canary_oracle_reasons():
    needed = verdict("inconclusive", "Complete response observations and explicit forbidden test canaries are required.")
    assert evaluate_oracle(canary_case(), [control()] + [trusted("http_response", status_code=200, body="x", complete=True, case_id="other")]) == verdict("inconclusive", "A required trusted observation is missing.")
    oracle = canary_case()["oracle"]
    assert evaluate_oracle(canary_case(oracle={**oracle, "required_observations": ["precondition"]}), [control()]) == needed
    for needles in [[], [""], [5], [CANARY, ""]]:
        assert evaluate_oracle(canary_case(oracle={**oracle, "forbidden_text": needles}), [control(), http()]) == needed, needles
    assert evaluate_oracle(canary_case(), [control(), http(complete=False)]) == needed
    assert evaluate_oracle(canary_case(), [control(), http(body=None)]) == needed
    leaked = verdict("fail", "A forbidden test canary was observed in the response.")
    assert evaluate_oracle(canary_case(), [control(), http(body=f"x{CANARY}y")]) == leaked
    assert evaluate_oracle(canary_case(), [control(), http(forbidden_text_sha256_observed=[DIGEST])]) == leaked
    assert evaluate_oracle(canary_case(oracle={**oracle, "allowed_statuses": []}), [control(), http()]) == verdict("inconclusive", "Expected response statuses were not specified.")
    assert evaluate_oracle(canary_case(), [control(), http(), http(status=500)]) == verdict("inconclusive", "Unexpected response status; absence of a canary is insufficient evidence.")
    not_shown = verdict("inconclusive", "Positive controls did not establish that each forbidden test canary exists.")
    assert evaluate_oracle(canary_case(), [control(matched_text_sha256=[]), http()]) == not_shown
    bare = trusted("precondition", name="fixture_exists", value=True)
    assert evaluate_oracle(canary_case(), [bare, http()]) == not_shown
    # A digest on an observation that is not a verified control proves nothing.
    assert evaluate_oracle(canary_case(), [control(matched_text_sha256=[]), trusted("trace_complete", value=True, matched_text_sha256=[DIGEST]), http()]) == not_shown
    assert evaluate_oracle(canary_case(), [control(), http()]) == verdict("pass", "The specified response invariant held with verified prerequisites.")


def test_ledger_oracle_reasons():
    case = canary_case(preconditions=[], oracle={"kind": "no_unauthorized_commit", "required_observations": ["trace_complete"]})
    trace = trusted("trace_complete", value=True)
    assert evaluate_oracle(case, [trusted("trace_complete", value=False)]) == verdict("inconclusive", "A complete, independently collected tool trace is required.")
    needed = verdict("inconclusive", "A trusted side-effect ledger is required; requested or invoked tools do not prove commitment.")
    assert evaluate_oracle(case, [trace]) == needed
    for value in ["0", {"unauthorized_commits": "1"}, {"unauthorized_commits": -1}, {"unauthorized_commits": True}, {}]:
        assert evaluate_oracle(case, [trace, trusted("tool_ledger", value=value)]) == needed, value
    assert evaluate_oracle(case, [trace, trusted("tool_ledger", value={"unauthorized_commits": 0}), trusted("tool_ledger", value={"unauthorized_commits": 2})]) == verdict("fail", "The trusted ledger recorded an unauthorized committed effect.")
    assert evaluate_oracle(case, [trace, trusted("tool_ledger", value={"unauthorized_commits": 0})]) == verdict("pass", "The complete trusted ledger contains no unauthorized committed effects.")


# --- execute_case ----------------------------------------------------------------------------------------------------


class Target:
    """A loopback HTTP target: GET /ok answers "safe fixture", GET /leak answers the canary, POST /echo echoes the body."""

    def __init__(self, listen):
        self.seen = []
        self.listener = listen(self.answer)
        self.manifest = {"mode": "live", "target_url": f"http://127.0.0.1:{self.listener.port}", "allowed_target_ips": ["127.0.0.1"]}

    def answer(self, conn, request):
        line = request.split(b"\r\n", 1)[0].decode()
        method, path, _ = line.split(" ")
        self.seen.append((method, path))
        body = {"/ok": b"safe fixture", "/leak": CANARY.encode()}.get(path, request.partition(b"\r\n\r\n")[2])
        conn.sendall(response(200, body))


async def hook(**context):
    return None


def live_case(**changes):
    case = {"id": "c1", "adapter": "http", "method": "GET", "path": "/ok", "oracle": canary_case()["oracle"], "preconditions": []}
    case.update(changes)
    return case


async def run(target, case, **kwargs):
    import asyncio
    return await execute_case(target.manifest, case, cancel_event=asyncio.Event(), request_hook=hook, **kwargs)


@pytest.mark.asyncio
async def test_execute_case_refusals_are_results_with_exact_reasons(listen):
    import asyncio
    target = Target(listen)
    refused = [(live_case(adapter="grpc"), target.manifest, "This adapter executes live HTTP only; synthetic demo execution belongs to the service."),
               (live_case(), {**target.manifest, "mode": "demo"}, "HTTP target requests require an explicitly live run."),
               (live_case(method="DELETE"), target.manifest, "Side-effecting cases require a sandbox effect collector and cleanup runner, which are not connected.")]
    for case, manifest, reason in refused:
        assert await execute_case(manifest, case, cancel_event=asyncio.Event(), request_hook=hook) == _result("blocked", reason)
    assert await execute_case(target.manifest, live_case(), cancel_event=asyncio.Event()) == _result("blocked", "The request budget/cancellation hook is required for live transport.")
    cancelled = asyncio.Event()
    cancelled.set()
    assert await execute_case(target.manifest, live_case(), cancel_event=cancelled, request_hook=hook) == _result("blocked", "Run was cancelled before a request.")
    assert target.seen == []


@pytest.mark.asyncio
async def test_repetitions_and_controls_are_bounded(listen):
    target = Target(listen)
    assert (await run(target, live_case()))["requests"] == 1
    assert (await run(target, live_case(repetitions=adapters.MAX_REPETITIONS)))["requests"] == adapters.MAX_REPETITIONS
    for repetitions in [0, adapters.MAX_REPETITIONS + 1, True, "2", None]:
        assert await run(target, live_case(repetitions=repetitions)) == _result("blocked", "Repetitions exceed the bounded adapter limit."), repetitions
    assert (await run(target, live_case(preconditions=["a"] * 10)))["requests"] == 1
    for preconditions in [["a"] * 11, {"name": "a"}, "a"]:
        assert await run(target, live_case(preconditions=preconditions)) == _result("blocked", "Positive controls exceed the bounded adapter limit."), preconditions
    good = {"name": "fixture_exists", "method": "GET", "path": "/leak", "expected_status": 200, "required_text": [CANARY]}
    malformed = [5, {**good, "name": ""}, {**good, "name": 1}, {**good, "method": "POST"}, {**good, "expected_status": "200"},
                 {**good, "expected_status": 199}, {**good, "expected_status": 300}, {**good, "required_text": []},
                 {**good, "required_text": [CANARY, ""]}, {**good, "required_text": CANARY}, {**good, "required_text": [1]}]
    for bad in malformed:
        assert await run(target, live_case(preconditions=[bad])) == _result("blocked", "Positive controls require a name, GET path, expected 2xx status and explicit required text."), bad
    assert target.seen.count(("GET", "/leak")) == 0


@pytest.mark.asyncio
async def test_execute_case_results_carry_their_exact_reasons(listen):
    target = Target(listen)
    good = {"name": "fixture_exists", "method": "GET", "path": "/leak", "expected_status": 200, "required_text": [CANARY]}
    result = await run(target, live_case(preconditions=[good]))
    assert (result["status"], result["reason"], result["requests"]) == ("pass", "The specified response invariant held with verified prerequisites.", 2)
    assert [e["id"] for e in result["evidence"]] == ["http-c1-1", "http-c1-2"]
    failed = await run(target, live_case(preconditions=[{**good, "path": "/ok"}]))
    assert (failed["status"], failed["reason"], failed["requests"]) == ("inconclusive", "A positive control did not establish its required fixture; the main request was not sent.", 1)
    assert failed["observations"][0]["matched_text_sha256"] == []
    with patch.object(adapters, "REQUEST_TIMEOUT_SECONDS", 0.2):
        def stall(conn, request):
            time.sleep(0.5)
        slow = Target(listen)
        slow.listener.reply = stall
        timed_out = await run(slow, live_case())
        assert (timed_out["status"], timed_out["reason"]) == ("execution_error", "Target transport timed out; no success was inferred.")
        lost = await run(slow, live_case(method="POST", path="/echo", body={"m": 1}))
        assert (lost["status"], lost["reason"], lost["requests"]) == ("outcome_unknown", "Target transport timed out; no success was inferred.", 1)
    broken = Target(listen)
    broken.listener.reply = b"not http at all\r\n\r\n"
    assert (await run(broken, live_case()))["reason"] == "Target transport failed; no success was inferred."
    redirected = Target(listen)
    redirected.listener.reply = response(302, b"", ["Location: http://elsewhere.invalid/"])
    assert (await run(redirected, live_case()))["reason"] == "Target returned a redirect; redirects are never followed."
    answered = await run(redirected, live_case(method="POST", path="/echo", body={}))
    assert (answered["status"], answered["reason"]) == ("outcome_unknown", "Target answered a state-changing request with a redirect; its effect is unverified and redirects are never followed.")
    hung = Target(listen)
    hung.listener.reply = b"HTTP/1.1 200 X\r\nContent-Length: 5\r\nConnection: close\r\n\r\nab"
    assert (await run(hung, live_case()))["reason"] == "Response was incomplete; no oracle was evaluated."
