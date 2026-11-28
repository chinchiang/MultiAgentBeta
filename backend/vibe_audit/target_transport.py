"""Pinned single-hop HTTP(S) target transport and credential redaction.

Standard-library only, with zero imports from vibe_audit, so both the backend
package and the isolated container / supervisor runtime can load it directly.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import threading
import time
from collections.abc import Iterable, Mapping
from typing import Any, TypeVar
from urllib.parse import quote

T = TypeVar("T")

MAX_RESPONSE_BYTES = 256 * 1024
REQUEST_TIMEOUT_SECONDS = 10.0

_CREDENTIAL_ENV = re.compile(r"^VIBEAUDIT_[A-Z0-9_]+$")
# The tool's own settings share the prefix. A profile naming one would send it to a model or target.
RESERVED_ENV = frozenset({
    "VIBEAUDIT_DATABASE_URL", "VIBEAUDIT_SESSION_TOKEN", "VIBEAUDIT_DATA_DIR", "VIBEAUDIT_SOURCE_ROOTS",
    "VIBEAUDIT_UI_ORIGINS", "VIBEAUDIT_RUNTIME_CONFIG", "VIBEAUDIT_FIXTURE_CONFIG", "VIBEAUDIT_CATALOG_ROOT",
    "VIBEAUDIT_PYTHON", "VIBEAUDIT_RELAY_ORIGIN", "VIBEAUDIT_POSTGRES_PASSWORD", "VIBEAUDIT_POSTGRES_IMAGE",
    "VIBEAUDIT_TEST_DATABASE_URL", "VIBEAUDIT_TEST_POSTGRES", "VIBEAUDIT_TEST_RUNTIME_CONFIG",
    "VIBEAUDIT_MODEL_CREDENTIAL_ORIGINS", "VIBEAUDIT_TARGET_CREDENTIAL_ORIGINS", "VIBEAUDIT_BEDROCK_PROFILES",
})
CREDENTIAL_ORIGINS_ENV = "VIBEAUDIT_MODEL_CREDENTIAL_ORIGINS"
# The vendor keys the workbench pre-fills go to their vendors; the operator's environment can rebind them.
DEFAULT_CREDENTIAL_ORIGINS = {
    "VIBEAUDIT_OPENAI_API_KEY": "https://api.openai.com",
    "VIBEAUDIT_ANTHROPIC_API_KEY": "https://api.anthropic.com",
}


class TransportRefused(Exception):
    """A target address or HTTP(S) exchange broke a deterministic transport rule."""

    def __init__(self, rule: str, *, delivered: bool, status_code: int | None = None) -> None:
        super().__init__(rule)
        self.rule = rule
        self.delivered = delivered
        self.status_code = status_code


# Cloud instance metadata services; the link-local check below covers the rest of 169.254.0.0/16.
_METADATA_IPS = frozenset(ipaddress.ip_address(item) for item in ("169.254.169.254", "fd00:ec2::254", "100.100.100.200"))

# RFC 6052 /96 prefixes, which embed the IPv4 address in the last 32 bits; other prefix lengths are not decoded.
_NAT64 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/96"))


def unmapped_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
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


def target_ip_refused(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """An address no target may use, whatever the operator lists: metadata, link-local, unspecified or multicast.

    Loopback and private addresses stay allowed, since local and internal staging targets use them.
    """
    address = unmapped_ip(address)
    if (address in _METADATA_IPS or address.is_link_local or address.is_unspecified or address.is_multicast
            or (address.version == 6 and address.is_site_local)):
        return True
    # 240.0.0.0/4 and the broadcast address. IPv6 "reserved" would also cover ::1, so it is not used.
    return address.version == 4 and address.is_reserved


def resolve_pinned_ip(host: str, port: int, allowed_ips: list[str]) -> str:
    """Validate allowed_ips and resolve host to one numeric IP address."""
    try:
        if not isinstance(allowed_ips, list) or any(not isinstance(item, str) for item in allowed_ips):
            raise ValueError
        allowed = {ipaddress.ip_address(item) for item in allowed_ips}
    except (ValueError, TypeError):
        raise TransportRefused("invalid_allowed_ips", delivered=False) from None
    if not allowed:
        raise TransportRefused("no_allowed_ips", delivered=False)
    if any(target_ip_refused(item) for item in allowed):
        raise TransportRefused("refused_ip", delivered=False)
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        try:
            resolved = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError:
            raise TransportRefused("dns_failed", delivered=False) from None
        addresses = {ipaddress.ip_address(row[4][0]) for row in resolved}
    else:
        addresses = {literal}
    if not addresses or not addresses.issubset(allowed):
        raise TransportRefused("unlisted_ip", delivered=False)
    # The actual socket is opened with this numeric address, never the DNS name.
    return str(sorted(addresses, key=lambda item: (item.version, int(item)))[0])


def secret_forms(value: str) -> set[str]:
    """The raw secret and the escaped forms a target may reflect it in (JSON, JSON with \\/, URL encoding)."""
    escaped = json.dumps(value)[1:-1]
    quoted = quote(value, safe="")  # pragma: no mutate (letters are always unescaped by quote)
    return {value, escaped, escaped.replace("/", "\\/"), quoted} - {""}


def credential_env_allowed(name: object, environ: Mapping[str, str] | None = None) -> bool:
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


def bound_model_credentials(environ: Mapping[str, str] | None = None) -> set[str]:
    """Every variable the operator's environment binds as a model key, whether or not this run's models use it."""
    environ = os.environ if environ is None else environ
    raw = environ.get(CREDENTIAL_ORIGINS_ENV)
    extra = re.findall(r"(VIBEAUDIT_[A-Z0-9_]+)\s*=", raw) if raw else ()
    return set(DEFAULT_CREDENTIAL_ORIGINS) | set(extra)


def redact_credentials(
    value: T,
    manifest: Mapping[str, Any] | None = None,
    *,
    extra_secrets: Iterable[str] = (),
    environ: Mapping[str, str] | None = None,
) -> T:
    """Remove every configured target/model credential, bound model key and extra secret from value."""
    environ = os.environ if environ is None else environ
    raw_secrets: set[str] = set()
    profiles = [*(manifest.get("auth_profiles") or []), *(manifest.get("models") or [])] if manifest else []
    names = {p.get("credential_env") for p in profiles if isinstance(p, dict)} | bound_model_credentials(environ)
    for name in names:
        if credential_env_allowed(name, environ):
            secret_val = environ.get(name)  # type: ignore[arg-type]
            if secret_val:
                raw_secrets.add(secret_val)
    for extra in extra_secrets:
        if extra:
            raw_secrets.add(extra)
    forms = sorted({form for item in raw_secrets for form in secret_forms(item)}, key=len, reverse=True)
    if not forms:
        return value
    encoded_forms = [form.encode() for form in forms]

    def _scrub(item: Any) -> Any:
        if isinstance(item, str):
            for form in forms:
                item = item.replace(form, "[REDACTED_CREDENTIAL]")
            return item
        if isinstance(item, bytes):
            for encoded in encoded_forms:
                item = item.replace(encoded, b"[REDACTED_CREDENTIAL]")
            return item
        if isinstance(item, list):
            return [_scrub(entry) for entry in item]
        if isinstance(item, dict):
            return {key: _scrub(entry) for key, entry in item.items()}
        return item

    return _scrub(value)


def send_pinned_request(
    scheme: str,
    host: str,
    port: int,
    pinned_ip: str,
    method: str = "GET",
    path: str = "/",
    headers: Mapping[str, str] | None = None,
    body: bytes | None = None,
    *,
    timeout: float = REQUEST_TIMEOUT_SECONDS,
    max_response_bytes: int = MAX_RESPONSE_BYTES,
    deployment_header: str | None = None,
    deployment_id: str | None = None,
    egress: tuple[set[socket.socket], threading.Lock, threading.Event] | None = None,
    trusted_ca: str | None = None,
) -> dict[str, Any]:
    """Send one origin-pinned HTTP(S) request without retries or redirect following.

    trusted_ca is PEM text of a CA the operator trusts for this target, on top of the system's: a target behind a
    private CA is reached only with it. A certificate no trusted CA signs for the host is refused as tls_untrusted."""
    try:
        if not isinstance(pinned_ip, str):
            raise ValueError
        address = ipaddress.ip_address(pinned_ip)
    except (TypeError, ValueError):
        raise TransportRefused("invalid_allowed_ips", delivered=False) from None
    if target_ip_refused(address):
        raise TransportRefused("refused_ip", delivered=False)

    sockets, lock, revoked = egress if egress is not None else (set(), threading.Lock(), threading.Event())
    deadline = time.monotonic() + timeout
    sock = socket.socket(socket.AF_INET6 if address.version == 6 else socket.AF_INET)
    with lock:
        if revoked.is_set():
            sock.close()
            raise TransportRefused("revoked", delivered=False)
        sockets.add(sock)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        with lock:
            sockets.discard(sock)
        sock.close()
        raise TransportRefused("connect_timeout", delivered=False)

    conn: http.client.HTTPConnection | None = None
    expired = threading.Event()

    def _expire() -> None:
        expired.set()
        with lock:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    watchdog = threading.Timer(remaining, _expire)
    watchdog.daemon = True
    watchdog.start()
    try:
        try:
            sock.settimeout(remaining)
            sock.connect((pinned_ip, port))
            if scheme == "https":
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                sock.settimeout(remaining)
                context = ssl.create_default_context()
                if trusted_ca:
                    context.load_verify_locations(cadata=trusted_ca)
                secure = context.wrap_socket(
                    sock, server_hostname=host, do_handshake_on_connect=False
                )
                with lock:
                    sockets.discard(sock)
                    sock = secure
                    if revoked.is_set():
                        sock.close()
                        raise TransportRefused("revoked", delivered=False)
                    sockets.add(sock)
                secure.do_handshake()
            if revoked.is_set():
                raise TransportRefused("revoked", delivered=False)
            remaining = deadline - time.monotonic()
            if remaining <= 0 or expired.is_set():
                raise TimeoutError
            sock.settimeout(remaining)
        except TransportRefused:
            raise
        except ssl.SSLCertVerificationError:
            # No trusted CA signs the certificate for this host: nothing was sent, and the operator can supply the
            # target's private CA rather than look for a network fault.
            raise TransportRefused("tls_untrusted", delivered=False) from None
        except OSError as exc:
            if isinstance(exc, TimeoutError) or expired.is_set():
                raise TransportRefused("connect_timeout", delivered=False) from None
            if revoked.is_set():
                raise TransportRefused("revoked", delivered=False) from None
            raise TransportRefused("connect_failed", delivered=False) from None
        conn = http.client.HTTPConnection(host, port)
        conn.default_port = 443 if scheme == "https" else 80
        conn.sock = sock
        try:
            conn.request(method, path, body=body or None, headers=dict(headers) if headers else {})
            response = conn.getresponse()
            if expired.is_set():
                raise TimeoutError
            if deployment_header:
                observed_deployment = response.getheader(deployment_header)
                if observed_deployment is None or observed_deployment != deployment_id:
                    raise TransportRefused("deployment_changed", delivered=True, status_code=response.status)
            if 300 <= response.status < 400:
                raise TransportRefused("redirect", delivered=True, status_code=response.status)
            encoding = response.getheader("Content-Encoding", "identity").lower()  # pragma: no mutate (header names and the default are compared case-insensitively)
            if encoding not in {"", "identity"}:
                raise TransportRefused("compressed", delivered=True, status_code=response.status)
            raw_length = response.getheader("Content-Length")  # pragma: no mutate (header names are case-insensitive)
            expected_length: int | None = None
            if raw_length is not None:
                if raw_length.startswith("-") and raw_length[1:].isascii() and raw_length[1:].isdigit():
                    raise TransportRefused("declared_too_large", delivered=True, status_code=response.status)
                if not (raw_length.isascii() and raw_length.isdigit()):
                    raise TransportRefused("invalid_length", delivered=True, status_code=response.status)
                expected_length = int(raw_length)
                if expected_length > max_response_bytes:
                    raise TransportRefused("declared_too_large", delivered=True, status_code=response.status)
            bodiless = method == "HEAD" or response.status == 204
            if bodiless:
                raw = b""
                size = 0
            else:
                chunks: list[bytes] = []
                size = 0
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:  # pragma: no mutate (the exact instant cannot be hit; the watchdog ends the transport then)
                        raise TimeoutError
                    if response.fp is not None:
                        sock.settimeout(remaining)
                    chunk = response.read1(min(8192, max_response_bytes + 1 - size))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > max_response_bytes:
                        raise TransportRefused("body_too_large", delivered=True, status_code=response.status)
                raw = b"".join(chunks)
                if expired.is_set():
                    raise TimeoutError
                if expected_length is not None and size != expected_length:
                    raise TransportRefused("incomplete_body", delivered=True, status_code=response.status)
            try:
                text = raw.decode()
            except UnicodeDecodeError:
                raise TransportRefused("invalid_utf8", delivered=True, status_code=response.status) from None
            content_type = response.getheader("Content-Type")  # pragma: no mutate (header names are case-insensitive)
            return {
                "status_code": response.status,
                "body": text,
                "bytes": size,
                "peer_ip": pinned_ip,
                "content_type": "application/json" if content_type is None else content_type,
            }
        except TransportRefused:
            raise
        except Exception as exc:
            if isinstance(exc, TimeoutError) or expired.is_set():
                raise TransportRefused("timeout", delivered=True) from None
            raise TransportRefused("protocol_error", delivered=True) from None
    finally:
        watchdog.cancel()
        if conn is not None:
            conn.close()
        with lock:
            sockets.discard(sock)
        sock.close()


