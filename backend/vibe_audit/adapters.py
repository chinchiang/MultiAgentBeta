"""Bounded target transport and observation-based security oracles.

No subprocess is launched by this module. Fixed scanner recipes are executed by
worker_runtime; recipes alone are not evidence that scanners have run. Observations
must come from this transport or an independently controlled local collector;
target response JSON is never promoted to a tool ledger or identity evidence.
"""
from __future__ import annotations

import asyncio
import hashlib
import http.client
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit

MAX_RESPONSE_BYTES = 256 * 1024
MAX_REQUEST_BYTES = 64 * 1024
REQUEST_TIMEOUT_SECONDS = 10.0
MAX_REPETITIONS = 20
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_TRUSTED = {"adapter.http", "fixture.local", "collector.local"}
_CREDENTIAL_ENV = re.compile(r"^VIBEAUDIT_[A-Z0-9_]+$")
# The tool's own settings share the prefix. A profile naming one would send it to a model or target.
RESERVED_ENV = frozenset({
    "VIBEAUDIT_DATABASE_URL", "VIBEAUDIT_SESSION_TOKEN", "VIBEAUDIT_DATA_DIR", "VIBEAUDIT_SOURCE_ROOTS",
    "VIBEAUDIT_UI_ORIGINS", "VIBEAUDIT_RUNTIME_CONFIG", "VIBEAUDIT_FIXTURE_CONFIG", "VIBEAUDIT_CATALOG_ROOT",
    "VIBEAUDIT_PYTHON", "VIBEAUDIT_RELAY_ORIGIN", "VIBEAUDIT_POSTGRES_PASSWORD", "VIBEAUDIT_POSTGRES_IMAGE",
    "VIBEAUDIT_TEST_DATABASE_URL", "VIBEAUDIT_TEST_POSTGRES", "VIBEAUDIT_TEST_RUNTIME_CONFIG",
    "VIBEAUDIT_MODEL_CREDENTIAL_ORIGINS", "VIBEAUDIT_TARGET_CREDENTIAL_ORIGINS",
})


def secret_forms(value):
    """The raw secret and the escaped forms a target may reflect it in (JSON, JSON with \\/, URL encoding)."""
    from urllib.parse import quote
    escaped = json.dumps(value)[1:-1]
    return {value, escaped, escaped.replace("/", "\\/"), quote(value, safe="")} - {""}


def credential_env_allowed(name, environ=None):
    """A credential reference names an operator secret, never this tool's own configuration."""
    environ = os.environ if environ is None else environ
    if not isinstance(name, str) or not _CREDENTIAL_ENV.fullmatch(name) or name in RESERVED_ENV:
        return False
    value = environ.get(name)
    if not value:
        return True
    # A URL is never an API key or bearer token; database URLs are read under operator-chosen names.
    if "://" in value:
        return False
    return not any(environ.get(key) == value for key in RESERVED_ENV)


CREDENTIAL_ORIGINS_ENV = "VIBEAUDIT_MODEL_CREDENTIAL_ORIGINS"
# The vendor keys the workbench pre-fills go to their vendors; the operator's environment can rebind them.
DEFAULT_CREDENTIAL_ORIGINS = {"VIBEAUDIT_OPENAI_API_KEY": "https://api.openai.com",
                              "VIBEAUDIT_ANTHROPIC_API_KEY": "https://api.anthropic.com"}


def bound_model_credentials(environ=None):
    """Every variable the operator's environment binds as a model key, whether or not this run's models use it.

    Read from the names alone, so a malformed binding (which providers.credential_origins refuses) still counts.
    The supervisor imports this module on its own, without the package: nothing here may import providers.
    """
    environ = os.environ if environ is None else environ
    return set(DEFAULT_CREDENTIAL_ORIGINS) | set(re.findall(r"(VIBEAUDIT_[A-Z0-9_]+)\s*=", environ.get(CREDENTIAL_ORIGINS_ENV, "")))


TARGET_CREDENTIAL_ORIGINS_ENV = "VIBEAUDIT_TARGET_CREDENTIAL_ORIGINS"


def target_credential_origins(environ=None):
    """The target origins each test identity credential may be sent to, as the operator's environment states them.

    A run names its own target, so without this a session holder could send any configured identity's credential
    to a host of their choosing; model keys have the same rule (VIBEAUDIT_MODEL_CREDENTIAL_ORIGINS). Format:
    NAME=origin entries, comma-separated; a name may repeat for several origins. Nothing is bound by default.
    """
    environ = os.environ if environ is None else environ
    bound = {}
    for entry in filter(None, (item.strip() for item in environ.get(TARGET_CREDENTIAL_ORIGINS_ENV, "").split(","))):
        name, _, value = entry.partition("=")
        name = name.strip()
        try:
            if not _CREDENTIAL_ENV.fullmatch(name) or name in RESERVED_ENV:
                raise AdapterBlocked("")
            origin = _origin({"target_url": value.strip()})
        except AdapterBlocked:
            raise AdapterBlocked(f"{TARGET_CREDENTIAL_ORIGINS_ENV} entries must be VIBEAUDIT_NAME=scheme://host[:port]") from None
        bound.setdefault(name, set()).add(origin)
    return bound


def unbound_target_credentials(manifest, environ=None):
    """Test identity credentials the environment has not bound to this run's target origin."""
    if not manifest.get("auth_profiles"):
        return []
    origin = _origin(manifest)
    bound = target_credential_origins(environ)
    return sorted({p.get("credential_env", "") for p in manifest.get("auth_profiles", [])
                   if origin not in bound.get(p.get("credential_env", ""), set())})


def shared_credentials(manifest, environ=None):
    """Test identities whose credential is also a model credential, by variable name or by value.

    Either way the target would receive a model key, or the model provider a target credential. Model
    credentials are this run's model profiles and every key the environment binds to model origins: a run
    that leaves a bound key out of its models must still not hand it to the target.
    """
    environ = os.environ if environ is None else environ
    def names(key):
        return {p.get("credential_env") for p in manifest.get(key) or [] if isinstance(p, dict)
                and isinstance(p.get("credential_env"), str) and p.get("credential_env")}
    model_names = names("models") | bound_model_credentials(environ)
    model_values = {environ.get(name) for name in model_names} - {None, ""}
    return sorted(name for name in names("auth_profiles")
                  if name in model_names or environ.get(name) in model_values)
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_FORBIDDEN_HEADERS = {
    "host", "authorization", "cookie", "proxy-authorization", "connection",
    "transfer-encoding", "content-length", "upgrade", "expect", "trailer",
    "proxy-connection", "x-forwarded-host", "forwarded", "te", "keep-alive",
    "x-api-key", "api-key", "x-auth-token", "x-access-token",
    # A target honouring these acts on another method or path than the sealed, scoped one.
    "x-http-method-override", "x-http-method", "x-method-override", "x-original-method",
    "x-original-url", "x-original-uri", "x-rewrite-url", "x-forwarded-prefix", "x-forwarded-path",
    "x-forwarded-uri", "x-envoy-original-path",
}
# The worker adds these to reach its relay; a sealed case cannot carry them.
RELAY_HEADERS = frozenset({"x-vibe-case", "x-vibe-identity", "x-schemathesis-testcaseid"})
# Model-designed cases need no custom routing, tenant or identity signal; operators write those cases.
# Each name has one spelling and the request sends them in one order: letter case, a repeat under another
# case or the order of names would otherwise be choices the model makes, and every choice can encode text.
MODEL_CASE_HEADER_NAMES = {"accept": "Accept", "accept-language": "Accept-Language", "content-type": "Content-Type",
                           "if-match": "If-Match", "if-none-match": "If-None-Match", "x-requested-with": "X-Requested-With"}
MODEL_CASE_HEADERS = frozenset(MODEL_CASE_HEADER_NAMES)
# A model reads the snapshot and operator notes, so a free-form header value could carry them to the target.
# Its header values come from small fixed vocabularies instead, one value per header with no list or q parameter:
# every extra choice is room to encode snapshot text. Within those vocabularies a model-designed request may use only
# the values the operator lists for that method and path (allowed_requests[].model_headers); an endpoint without a
# list takes no model-chosen header at all, so by default the headers carry no choice. Operator-written cases keep
# free values.
_MEDIA_TYPES = ("*/*", "text/*", "image/*", "application/*", "application/json", "application/problem+json",
                "application/xml", "application/x-www-form-urlencoded", "application/octet-stream", "application/pdf",
                "multipart/form-data", "text/html", "text/plain", "text/csv", "text/xml", "text/event-stream",
                "image/png", "image/jpeg")
_LANGUAGES = ("*", "en", "en-US", "en-GB", "zh", "zh-TW", "zh-CN", "zh-HK", "ja", "ja-JP", "ko", "ko-KR", "fr", "de",
              "es", "pt", "pt-BR", "it", "nl", "ru", "ar", "he", "tr", "vi", "th", "id")


def _one_of(options):
    return re.compile("|".join(re.escape(option) for option in options))


_MODEL_HEADER_VALUES = {
    "accept": _one_of(_MEDIA_TYPES),
    "accept-language": _one_of(_LANGUAGES),
    # One spelling of the charset parameter: ";charset" and "; charset" would be two choices for the same meaning.
    "content-type": re.compile(r"(?:application/json|application/x-www-form-urlencoded|application/xml|text/plain)(?:; charset=utf-8)?"),
    # The model never sees a target response, so it holds no real entity tag: only the wildcard means anything.
    "if-match": re.compile(r"\*"),
    "if-none-match": re.compile(r"\*"),
    "x-requested-with": re.compile(r"XMLHttpRequest"),
}


def model_header_list_error(model_headers):
    """Why an allowed_requests[].model_headers value is not acceptable, or None.

    Each name has its one spelling and each value must already pass the fixed model vocabulary, so an operator list
    can only narrow what a model may send, never widen it."""
    if not isinstance(model_headers, dict):
        return "model_headers must map header names to lists of values"
    for name, values in model_headers.items():
        lower = name.lower() if isinstance(name, str) else None
        if MODEL_CASE_HEADER_NAMES.get(lower) != name:
            return f"model_headers names must be one of {', '.join(sorted(MODEL_CASE_HEADER_NAMES.values()))}"
        if (not isinstance(values, list) or not values or len(values) != len(set(map(str, values)))
                or not all(isinstance(v, str) and _MODEL_HEADER_VALUES[lower].fullmatch(v) for v in values)):
            return f"model_headers[{name}] must be a non-empty list of distinct values from the model vocabulary"
    return None


def model_header_vocabulary(manifest, method, path):
    """{lower-case name: allowed values} that the operator lists for this method and path; empty when none."""
    vocabulary = {}
    for request in (manifest or {}).get("allowed_requests", []) or []:
        if (not isinstance(request, dict) or str(request.get("method", "GET")).upper() != str(method).upper()
                or request.get("path") != path):
            continue
        lists = request.get("model_headers") or {}
        if model_header_list_error(lists) is None:
            for name, values in lists.items():
                vocabulary.setdefault(name.lower(), set()).update(values)
    return {name: frozenset(values) for name, values in vocabulary.items()}


def canonical_model_headers(headers):
    """A model-designed header map with each name in its one spelling and in sorted order.

    Names that are the same once letter case is ignored are a repeat, not two headers: they raise ValueError.
    Names outside the model vocabulary keep their spelling, and case_headers_allowed rejects them.
    """
    if not isinstance(headers, dict):
        return headers
    out = {}
    for name, value in headers.items():
        key = MODEL_CASE_HEADER_NAMES.get(name.lower(), name) if isinstance(name, str) else name
        if key in out:
            raise ValueError("A model-designed case repeats a header name")
        out[key] = value
    return {name: out[name] for name in sorted(out)}


def case_headers_allowed(headers, *, model_designed=False, relay=False, vocabulary=None):
    """relay=True only inside the worker, which adds its own case and identity routing headers.

    vocabulary is model_header_vocabulary() for the request's method and path; a model-designed header must be in it,
    and None means the operator listed nothing, so any model-designed header is refused. Inside the worker (relay)
    the manifest holds no allowed_requests, so only the fixed vocabulary is checked there: the per-endpoint list is
    enforced by the case gate and again by the supervisor, the last trusted hop, whose manifest has no relay flag."""
    vocabulary = vocabulary or {}
    if headers is None:
        return True
    if not isinstance(headers, dict) or len(headers) > 24:
        return False
    if model_designed and list(headers) != sorted(headers):
        return False
    def allowed(name, value):
        lower = name.lower()
        if lower in RELAY_HEADERS:
            return relay
        if not model_designed:
            return lower not in _FORBIDDEN_HEADERS
        return (MODEL_CASE_HEADER_NAMES.get(lower) == name
                and bool(_MODEL_HEADER_VALUES[lower].fullmatch(value))
                and (relay or value in vocabulary.get(lower, ())))
    return all(isinstance(name, str) and _HEADER_NAME.fullmatch(name)
               and isinstance(value, str) and len(value) <= 4096 and all(32 <= ord(c) <= 126 for c in value)
               and allowed(name, value)
               for name, value in headers.items())


class AdapterBlocked(ValueError):
    """A policy restriction prevented a request; never include secret values."""


class ResponseLimitError(ValueError):
    pass


class OutcomeUnknown(ValueError):
    """A state-changing request reached the target but its effect cannot be confirmed."""


def state_changing(case: dict, *, operator_case: bool = True) -> bool:
    """A case's own side_effects claim cannot make an unsafe HTTP method read-only.

    PUT/PATCH/DELETE always change state. POST also serves search and chat, so
    only an operator-written case may declare it free of side effects.
    """
    method = str(case.get("method", "GET")).upper()
    return (bool(case.get("side_effects")) or method in {"PUT", "PATCH", "DELETE"}
            or (method not in SAFE_METHODS and not operator_case))


def _result(status, reason, observations=None, requests=0):
    return {
        "status": status, "reason": reason, "observations": observations or [],
        "evidence": [], "requests": requests,
    }


def _cancelled(event):
    return event is not None and event.is_set()


def _origin(manifest):
    try:
        raw = manifest.get("target_url", "")
        if not isinstance(raw, str) or any(ord(c) < 33 for c in raw):
            raise ValueError
        parts = urlsplit(raw)
        if (parts.scheme not in {"http", "https"} or not parts.hostname
                or parts.username is not None or parts.password is not None
                or parts.path not in {"", "/"} or parts.query or parts.fragment
                or "\\" in raw or "%" in parts.netloc):
            raise ValueError
        host = parts.hostname.encode("idna").decode("ascii").lower()
        port = parts.port or (443 if parts.scheme == "https" else 80)
        if not 1 <= port <= 65535:
            raise ValueError
        return parts.scheme, host, port
    except (ValueError, TypeError, UnicodeError):
        raise AdapterBlocked("Target must be a single exact HTTP(S) origin without credentials, path or query.") from None


# Cloud instance metadata services; the link-local check below covers the rest of 169.254.0.0/16.
_METADATA_IPS = frozenset(ipaddress.ip_address(item) for item in ("169.254.169.254", "fd00:ec2::254", "100.100.100.200"))


_NAT64 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))


def _unmapped(address):
    """The IPv4 address an IPv6 form reaches: mapped, 6to4 or a NAT64 translation of it."""
    if address.version != 6:
        return address
    if address.ipv4_mapped:
        return address.ipv4_mapped
    if address.sixtofour:
        return address.sixtofour
    if any(address in network for network in _NAT64):
        return ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
    return address


def target_ip_refused(address):
    """An address no target may use, whatever the operator lists: metadata, link-local, unspecified or multicast.

    Loopback and private addresses stay allowed, since local and internal staging targets use them.
    """
    address = _unmapped(address)
    if (address in _METADATA_IPS or address.is_link_local or address.is_unspecified or address.is_multicast
            or (address.version == 6 and address.is_site_local)):
        return True
    # 240.0.0.0/4 and the broadcast address. IPv6 "reserved" would also cover ::1, so it is not used.
    return address.version == 4 and address.is_reserved


_DEFAULT_PORTS = {"http": 80, "https": 443, "postgres": 5432, "postgresql": 5432}


def control_plane_target(manifest, endpoints):
    """The console or database endpoint (host:port) the target would reach, or None.

    The supervisor connects from the console's own host, so a loopback target can be the console itself.
    """
    _, host, port = _origin(manifest)
    try:
        ips = {_unmapped(ipaddress.ip_address(item)) for item in manifest.get("allowed_target_ips", [])}
    except (TypeError, ValueError):
        raise AdapterBlocked("Allowed target IPs must be explicit IP addresses, not hostnames or ranges.") from None
    for url in endpoints:
        try:
            parts = urlsplit(url)
            other = (parts.hostname or "").lower()
            other_port = parts.port or _DEFAULT_PORTS.get(parts.scheme)
        except (TypeError, ValueError):
            continue
        if not other or other_port != port:
            continue
        try:
            address = _unmapped(ipaddress.ip_address(other))
        except ValueError:
            address = None
        if other == "localhost" or (address is not None and address.is_loopback):
            hit = any(item.is_loopback for item in ips)
        else:
            hit = address in ips if address is not None else other == host
        if hit:
            # Never echo the URL itself: a database URL can carry its password.
            return f"[{other}]:{port}" if ":" in other else f"{other}:{port}"
    return None


def _pinned_address(host, port, allowed_ips):
    try:
        if not isinstance(allowed_ips, list) or any(not isinstance(item, str) for item in allowed_ips):
            raise ValueError
        allowed = {ipaddress.ip_address(item) for item in allowed_ips}
    except (ValueError, TypeError):
        raise AdapterBlocked("Allowed target IPs must be explicit IP addresses, not hostnames or ranges.") from None
    if not allowed:
        raise AdapterBlocked("No target IP addresses were explicitly authorized.")
    if any(target_ip_refused(item) for item in allowed):
        raise AdapterBlocked("Target IPs cannot be cloud metadata, link-local, unspecified or multicast addresses.")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        resolved = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        addresses = {ipaddress.ip_address(row[4][0]) for row in resolved}
    else:
        addresses = {literal}
    if not addresses or not addresses.issubset(allowed):
        raise AdapterBlocked("DNS returned an address outside the exact target IP allowlist.")
    # The actual socket is opened with this numeric address, never the DNS name.
    return str(sorted(addresses, key=lambda item: (item.version, int(item)))[0])


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port, *, pinned_ip, timeout):
        super().__init__(host, port, timeout=timeout)
        self.pinned_ip = pinned_ip

    def connect(self):
        address = ipaddress.ip_address(self.pinned_ip)
        family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((self.pinned_ip, self.port))
            self.sock = sock
        except BaseException:
            sock.close()
            raise


class _PinnedHTTPSConnection(_PinnedHTTPConnection):
    def connect(self):
        deadline = time.monotonic() + self.timeout
        super().connect()
        try:
            # Verify certificate and SNI against the authorized host, not its IP.
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            self.sock.settimeout(remaining)
            self.sock = ssl.create_default_context().wrap_socket(self.sock, server_hostname=self.host)
        except BaseException:
            self.sock.close()
            raise


def _prepare_request(manifest, case, *, transport_headers=None):
    """transport_headers are added by trusted transport code (the supervisor's Content-Type for a body it forwards):
    they are not a model's choice, so they skip the per-endpoint model vocabulary but keep the same wire order."""
    method = case.get("method", "GET")
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        raise AdapterBlocked("Unsupported HTTP method.")
    path = case.get("path", "/")
    if (not isinstance(path, str) or not path.startswith("/") or path.startswith("//")
            or "\\" in path or "#" in path or any(ord(c) < 33 for c in path)):
        raise AdapterBlocked("Case path must be origin-relative and must not contain control characters.")
    try:
        path.encode("ascii")
    except UnicodeError:
        raise AdapterBlocked("Case path must use ASCII URL encoding.") from None
    headers = {"Accept": "application/json", "Accept-Encoding": "identity", "Connection": "close"}
    supplied = case.get("headers") or {}
    model_designed = case.get("designed_by") == "model"
    vocabulary = model_header_vocabulary(manifest, method, path) if model_designed and manifest.get("relay") is not True else None
    if not case_headers_allowed(supplied, model_designed=model_designed, relay=manifest.get("relay") is True,
                                vocabulary=vocabulary):
        raise AdapterBlocked("Case contains an unsupported, routing or credential-bearing request header.")
    if transport_headers:
        supplied = {**supplied, **transport_headers}
        if model_designed:
            supplied = dict(sorted(supplied.items()))
    # A supplied Accept takes the default's place, so an explicit application/json and none at all look the same on the
    # wire; a model's other names follow in sorted order (case_headers_allowed), never in an order the model chose.
    headers.update(supplied)
    secrets = []
    identity = case.get("identity")
    if identity is not None:
        profiles = [p for p in manifest.get("auth_profiles", []) if p.get("id") == identity]
        if len(profiles) != 1:
            raise AdapterBlocked("Case identity must reference exactly one configured authentication profile.")
        profile = profiles[0]
        env_name = profile.get("credential_env", "")
        if not credential_env_allowed(env_name):
            raise AdapterBlocked("Credentials must reference a VIBEAUDIT_ environment variable that is not a Vibe Audit setting.")
        secret = os.environ.get(env_name)
        if not secret or len(secret) > 8192 or any(ord(c) < 33 or ord(c) > 126 for c in secret):
            raise AdapterBlocked("Authentication credential is missing or invalid.")
        if env_name in shared_credentials(manifest):
            raise AdapterBlocked("A test identity credential cannot also be a model credential.")
        # The last trusted hop checks the binding again: the run, not the environment, named this target.
        if _origin(manifest) not in target_credential_origins().get(env_name, set()):
            raise AdapterBlocked(f"{env_name} is not bound to this target; bind test credentials to their origins in {TARGET_CREDENTIAL_ORIGINS_ENV}.")
        header = profile.get("header", "Authorization")
        scheme = profile.get("scheme", "Bearer")
        if header not in {"Authorization", "X-API-Key"} or scheme not in {"Bearer", "", "Basic"}:
            raise AdapterBlocked("Unsupported authentication header or scheme.")
        headers[header] = f"{scheme} {secret}" if scheme else secret
        secrets.append(secret)
    body = case.get("body")
    if body is not None:
        if method in {"GET", "HEAD"}:
            raise AdapterBlocked("GET and HEAD cases cannot contain a request body.")
        try:
            body = json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
        except (ValueError, TypeError):
            raise AdapterBlocked("Request body must be finite JSON data.") from None
        if len(body) > MAX_REQUEST_BYTES:
            raise AdapterBlocked("Request body exceeds the configured byte limit.")
        headers["Content-Type"] = "application/json"
    return method, path, headers, body, secrets


def _request(scheme, host, port, pinned_ip, method, path, headers, body, timeout):
    connection_type = _PinnedHTTPSConnection if scheme == "https" else _PinnedHTTPConnection
    conn = connection_type(host, port, pinned_ip=pinned_ip, timeout=timeout)
    deadline = time.monotonic() + timeout
    watchdog = None
    try:
        conn.connect()
        transport_socket = conn.sock
        def end_transport():
            try:
                transport_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        # Socket timeouts alone do not bound a peer sending one byte at a time.
        # This independent deadline also interrupts slow headers and chunking.
        watchdog = threading.Timer(max(0.001, deadline - time.monotonic()), end_transport)
        watchdog.daemon = True
        watchdog.start()
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        if 300 <= response.status < 400:
            return {"status_code": response.status, "body": "", "complete": False, "redirect_blocked": True}
        encoding = response.getheader("Content-Encoding", "identity").lower()
        if encoding not in {"", "identity"}:
            raise ResponseLimitError("Compressed responses are unsupported; no oracle was evaluated.")
        length = response.getheader("Content-Length")
        if length is not None:
            try:
                if int(length) < 0 or int(length) > MAX_RESPONSE_BYTES:
                    raise ResponseLimitError("Response exceeds the configured byte limit.")
            except ValueError:
                raise ResponseLimitError("Invalid response length; no oracle was evaluated.") from None
        chunks = []
        size = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            # With Connection: close, HTTPResponse may own the socket after
            # HTTPConnection.sock has been cleared by getresponse().
            sock = conn.sock
            if sock is None and response.fp is not None:
                sock = getattr(getattr(response.fp, "raw", None), "_sock", None)
            if sock is not None:
                sock.settimeout(remaining)
            chunk = response.read1(min(8192, MAX_RESPONSE_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_RESPONSE_BYTES:
                raise ResponseLimitError("Response exceeds the configured byte limit.")
        raw = b"".join(chunks)
        if length is not None and len(raw) != int(length):
            raise ResponseLimitError("Response was incomplete; no oracle was evaluated.")
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeError:
            raise ResponseLimitError("Only complete UTF-8 responses can be evaluated.") from None
        return {"status_code": response.status, "body": text, "complete": True, "bytes": size}
    finally:
        if watchdog is not None:
            watchdog.cancel()
        conn.close()


def _trusted_observations(case, observations):
    case_id = case.get("id")
    return [o for o in observations if isinstance(o, dict)
            and o.get("provenance") in _TRUSTED
            and (not case_id or o.get("case_id") == case_id)]


def evaluate_oracle(case: dict, observations: list) -> dict:
    """Evaluate deterministic invariants, not an LLM's statements of success.

    ``collector.local`` is reserved for harness-controlled collectors. A target
    JSON field with that string does not become a collector observation.
    """
    trusted = _trusted_observations(case, observations)
    oracle = case.get("oracle") or {}
    required = oracle.get("required_observations") or []
    if not required:
        return {"status": "inconclusive", "reason": "Oracle has no explicit required observations."}
    for requirement in required:
        if not isinstance(requirement, str) or not any(
                o.get("kind") == requirement or o.get("name") == requirement for o in trusted):
            return {"status": "inconclusive", "reason": "A required trusted observation is missing."}
    for precondition in case.get("preconditions") or []:
        name = precondition.get("name") if isinstance(precondition, dict) else precondition
        if not isinstance(name, str) or not any(
                o.get("kind") == "precondition" and o.get("name") == name and o.get("value") is True
                for o in trusted):
            return {"status": "inconclusive", "reason": "A required precondition has not been independently verified."}
    expected_role = oracle.get("expected_role")
    if expected_role and not any(o.get("kind") == "identity_verified" and o.get("role") == expected_role
                                 and o.get("value") is True for o in trusted):
        return {"status": "inconclusive", "reason": "The expected test identity has not been independently verified."}
    kind = oracle.get("kind")
    if kind in {"deny_sensitive", "canary_absent"}:
        responses = [o for o in trusted if o.get("kind") == "http_response"]
        needles = oracle.get("forbidden_text") or []
        if (not responses or not needles or any(not isinstance(n, str) or not n for n in needles)
                or any(o.get("complete") is not True or not isinstance(o.get("body"), str) for o in responses)):
            return {"status": "inconclusive", "reason": "Complete response observations and explicit forbidden test canaries are required."}
        if any(needle in response["body"] or hashlib.sha256(needle.encode()).hexdigest() in response.get("forbidden_text_sha256_observed", [])
               for needle in needles for response in responses):
            return {"status": "fail", "reason": "A forbidden test canary was observed in the response."}
        allowed_statuses = oracle.get("allowed_statuses") or []
        if not allowed_statuses:
            return {"status": "inconclusive", "reason": "Expected response statuses were not specified."}
        if any(response.get("status_code") not in allowed_statuses for response in responses):
            return {"status": "inconclusive", "reason": "Unexpected response status; absence of a canary is insufficient evidence."}
        if not case.get("preconditions"):
            return {"status": "inconclusive", "reason": "A positive-control precondition is required to establish the sensitive fixture exists."}
        # Whichever executor ran the case, a missing canary only means something once a verified positive
        # control showed that canary exists; otherwise a wrong or absent fixture would read as a pass.
        verified_canaries = {item for o in trusted if o.get("kind") == "precondition" and o.get("value") is True
                             for item in o.get("matched_text_sha256", [])}
        if any(hashlib.sha256(needle.encode()).hexdigest() not in verified_canaries for needle in needles):
            return {"status": "inconclusive", "reason": "Positive controls did not establish that each forbidden test canary exists."}
        return {"status": "pass", "reason": "The specified response invariant held with verified prerequisites."}
    if kind == "no_unauthorized_commit":
        if not any(o.get("kind") == "trace_complete" and o.get("value") is True for o in trusted):
            return {"status": "inconclusive", "reason": "A complete, independently collected tool trace is required."}
        ledgers = [o.get("value") for o in trusted if o.get("kind") == "tool_ledger"]
        if (not ledgers or any(not isinstance(v, dict)
                              or type(v.get("unauthorized_commits")) is not int
                              or v["unauthorized_commits"] < 0 for v in ledgers)):
            return {"status": "inconclusive", "reason": "A trusted side-effect ledger is required; requested or invoked tools do not prove commitment."}
        if any(v["unauthorized_commits"] > 0 for v in ledgers):
            return {"status": "fail", "reason": "The trusted ledger recorded an unauthorized committed effect."}
        return {"status": "pass", "reason": "The complete trusted ledger contains no unauthorized committed effects."}
    return {"status": "inconclusive", "reason": "Oracle kind is not implemented."}


async def execute_case(manifest: dict, case: dict, *, cancel_event, request_hook=None) -> dict:
    """Issue only origin-pinned requests. No retries, redirects or target code."""
    if case.get("adapter") not in {"http", "ai_http"}:
        return _result("blocked", "This adapter executes live HTTP only; synthetic demo execution belongs to the service.")
    if manifest.get("mode") != "live":
        return _result("blocked", "HTTP target requests require an explicitly live run.")
    if state_changing(case):
        return _result("blocked", "Side-effecting cases require a sandbox effect collector and cleanup runner, which are not connected.")
    if request_hook is None:
        return _result("blocked", "The request budget/cancellation hook is required for live transport.")
    if _cancelled(cancel_event):
        return _result("blocked", "Run was cancelled before a request.")
    requests = 0
    observations = []
    current_method = "GET"
    try:
        scheme, host, port = _origin(manifest)
        # Validate the main request before allowing even positive-control I/O.
        _prepare_request(manifest, case)
        repetitions = case.get("repetitions", 1)
        if type(repetitions) is not int or not 1 <= repetitions <= MAX_REPETITIONS:
            raise AdapterBlocked("Repetitions exceed the bounded adapter limit.")
        preconditions = case.get("preconditions") or []
        if not isinstance(preconditions, list) or len(preconditions) > 10:
            raise AdapterBlocked("Positive controls exceed the bounded adapter limit.")
        controls = []
        for control in preconditions:
            if isinstance(control, str):
                # A string is an unverified requirement, not evidence.
                continue
            if (not isinstance(control, dict) or not isinstance(control.get("name"), str) or not control["name"]
                    or control.get("method") != "GET" or type(control.get("expected_status")) is not int
                    or not 200 <= control["expected_status"] < 300
                    or not isinstance(control.get("required_text"), list)
                    or not control["required_text"]
                    or any(not isinstance(t, str) or not t for t in control["required_text"])):
                raise AdapterBlocked("Positive controls require a name, GET path, expected 2xx status and explicit required text.")
            request = {"method": "GET", "path": control.get("path"), "headers": control.get("headers") or {},
                       "identity": control.get("identity"), "body": None, "designed_by": case.get("designed_by")}
            _prepare_request(manifest, request)
            controls.append((control, request))

        async def dispatch(request):
            nonlocal requests, current_method
            if _cancelled(cancel_event):
                raise AdapterBlocked("Run was cancelled before a request.")
            method, path, headers, body, secrets = _prepare_request(manifest, request)
            current_method = method
            # Resolution is bounded separately. The connected numeric IP cannot
            # be changed by a second DNS lookup or proxy environment variables.
            pinned = await asyncio.wait_for(asyncio.to_thread(
                _pinned_address, host, port, manifest.get("allowed_target_ips", [])), timeout=REQUEST_TIMEOUT_SECONDS)
            try:
                await request_hook(method=method, path=path)
            except asyncio.CancelledError:
                raise
            except Exception:
                raise AdapterBlocked("The request budget or lease hook refused execution.") from None
            if _cancelled(cancel_event):
                raise AdapterBlocked("Run was cancelled before a request.")
            requests += 1
            response = await asyncio.to_thread(_request, scheme, host, port, pinned,
                                                method, path, headers, body, REQUEST_TIMEOUT_SECONDS)
            if _cancelled(cancel_event):
                raise asyncio.CancelledError
            if response.get("redirect_blocked"):
                if method not in SAFE_METHODS:
                    # The target processed the request before answering; do not report it as unsent.
                    raise OutcomeUnknown("Target answered a state-changing request with a redirect; its effect is unverified and redirects are never followed.")
                raise AdapterBlocked("Target returned a redirect; redirects are never followed.")
            response["peer_ip"] = pinned
            return response, secrets

        for repeat in range(repetitions):
            for control, request in controls:
                response, _ = await dispatch(request)
                matched = (response.get("complete") is True and response.get("status_code") == control["expected_status"]
                           and all(text in response["body"] for text in control["required_text"]))
                observations.append({"kind": "precondition", "name": control["name"], "value": matched,
                                     "provenance": "adapter.http", "case_id": case.get("id"), "run_id": manifest.get("run_id"),
                                     "status_code": response["status_code"], "repetition": repeat + 1,
                                     "matched_text_sha256": [hashlib.sha256(text.encode()).hexdigest() for text in control["required_text"]] if matched else []})
                if not matched:
                    return _result("inconclusive", "A positive control did not establish its required fixture; the main request was not sent.", observations, requests)
            response, secrets = await dispatch(case)
            response["forbidden_text_sha256_observed"] = [hashlib.sha256(text.encode()).hexdigest()
                for text in (case.get("oracle") or {}).get("forbidden_text", [])
                if isinstance(text, str) and text and text in response["body"]]
            # Also redact other explicitly configured model/auth credentials if
            # the target reflects them. Keep match digests for oracle replay.
            for profile in [*manifest.get("auth_profiles", []), *manifest.get("models", [])]:
                env_name = profile.get("credential_env", "")
                if isinstance(env_name, str) and _CREDENTIAL_ENV.fullmatch(env_name):
                    value = os.environ.get(env_name)
                    if value:
                        secrets.append(value)
            for secret in sorted({form for value in secrets for form in secret_forms(value)}, key=len, reverse=True):
                response["body"] = response["body"].replace(secret, "[REDACTED_CREDENTIAL]")
            response.update({"kind": "http_response", "provenance": "adapter.http", "case_id": case.get("id"),
                             "run_id": manifest.get("run_id"), "repetition": repeat + 1})
            observations.append(response)
        verdict = evaluate_oracle(case, observations)
        result = _result(verdict["status"], verdict["reason"], observations, requests)
        result["evidence"] = [{"id": f"http-{case.get('id', 'case')}-{i+1}", "kind": obs["kind"],
                               "sha256": hashlib.sha256(json.dumps(obs, sort_keys=True).encode()).hexdigest(),
                               "observation_index": i} for i, obs in enumerate(observations)]
        return result
    except AdapterBlocked as exc:
        return _result("blocked", str(exc), observations, requests)
    except OutcomeUnknown as exc:
        return _result("outcome_unknown", str(exc), observations, requests)
    except ResponseLimitError as exc:
        return _result("inconclusive", str(exc), observations, requests)
    except asyncio.CancelledError:
        return _result("outcome_unknown" if requests else "blocked", "Execution was cancelled; dispatched requests are not automatically replayed.", observations, requests)
    except (TimeoutError, socket.timeout):
        return _result("outcome_unknown" if requests and current_method not in SAFE_METHODS else "execution_error", "Target transport timed out; no success was inferred.", observations, requests)
    except Exception:
        # Provider/HTTP exception strings may include request material. Never
        # return their text or traceback through an API or report.
        return _result("outcome_unknown" if requests and current_method not in SAFE_METHODS else "execution_error", "Target transport failed; no success was inferred.", observations, requests)


def tool_capabilities() -> list[dict]:
    tools = ["semgrep", "osv", "gitleaks", "zap", "schemathesis", "playwright", "promptfoo", "pyrit"]
    return [{"id": name, "available": False, "status": "implemented_requires_runtime", "implemented": True, "cli_detected": bool(shutil.which(name)),
             "detail": "Adapter 已實作；尚未配置可驗證的 Linux 隔離執行環境與固定工具映像。"} for name in tools] + [
        {"id": "synthetic_demo", "available": True, "status": "synthetic_only", "implemented": True,
         "detail": "可執行本地合成流程；不會呼叫真實模型或驗證其偵測品質。"},
        {"id": "tool_effect_collector", "available": False, "status": "target_binding_required", "implemented": True,
         "detail": "獨立事件及副作用收集器已實作；實際目標必須配置可信 binding，無觀測時不判定通過。"}]
