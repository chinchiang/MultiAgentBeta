"""Request rules: what a request to the target may look like, and whether it may be sent.

Every checkpoint that decides on a request (the case gate, the retest preflight, authorize, the supervisor and the
transport) asks this module instead of keeping its own copy of a rule. It depends on the standard library only: the
backend imports it as vibe_audit.request_rules, the supervisor inside the container as the flat module request_rules.
"""
from __future__ import annotations

import re

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


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


def state_changing(case: dict, *, operator_case: bool = True) -> bool:
    """A case's own side_effects claim cannot make an unsafe HTTP method read-only.

    PUT/PATCH/DELETE always change state. POST also serves search and chat, so
    only an operator-written case may declare it free of side effects.
    """
    method = str(case.get("method", "GET")).upper()
    return (bool(case.get("side_effects")) or method in {"PUT", "PATCH", "DELETE"}
            or (method not in SAFE_METHODS and not operator_case))


def request_path_problem(path):
    """Why the transport would never send this path, or None. The operator's scope is held to the same rule, so a scope
    entry is refused as input rather than listing a path no request can ever take."""
    if (not isinstance(path, str) or not path.startswith("/") or path.startswith("//")
            or "\\" in path or "#" in path or any(ord(c) < 33 for c in path)):
        return "Case path must be origin-relative and must not contain control characters."
    if not path.isascii():
        return "Case path must use ASCII URL encoding."
    return None
