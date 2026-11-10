"""Request rules: what a request to the target may look like, and whether it may be sent.

Every checkpoint that decides on a request (the case gate, the retest preflight, authorize, the supervisor and the
transport) asks this module instead of keeping its own copy of a rule. It depends on the standard library only: the
backend imports it as vibe_audit.request_rules, the supervisor inside the container as the flat module request_rules.
"""
from __future__ import annotations

import re

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# The method of a request or scope entry that names none.
DEFAULT_METHOD = "GET"  # pragma: no mutate (every comparison upper-cases it, so any spelling is the same method)


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


# The phases of the steps the case itself names: its own request and its positive controls. Every other step of a
# plan is the engine's lifecycle, which only a request sequence sends.
CASE_PHASES = frozenset({"case", "control"})


def own_step(case, manifest=None):
    """The step of the case's request plan that is the case's own request, or None without one.

    With the run's manifest, a case sealed before request plans has its plan rebuilt from its fields (as match_request
    does), unchecked and never written back."""
    plan = case.get("request_plan")
    if not isinstance(plan, dict):
        return None if manifest is None else _steps(manifest, case, lifecycle=None, live=True)[0][0]
    return next((s for s in plan.get("steps") or [] if s.get("phase") == "case"), None)


def read_only(case):
    """Whether the case's own request leaves the target's state as it was, as the case's request plan records it.

    The worker gets only that step of the plan; a step that does not say it reads is a write. A case sealed before
    request plans is read by the rule of its time: only a model-written POST is never read-only."""
    own = own_step(case)
    if own is not None:
        return own.get("read_only") is True
    return not state_changing(case, operator_case=case.get("designed_by") != "model")


def request_path_problem(path):
    """Why the transport would never send this path, or None. The operator's scope is held to the same rule, so a scope
    entry is refused as input rather than listing a path no request can ever take."""
    if (not isinstance(path, str) or not path.startswith("/") or path.startswith("//")
            or "\\" in path or "#" in path or any(ord(c) < 33 for c in path)):
        return "Case path must be origin-relative and must not contain control characters."
    if not path.isascii():
        return "Case path must use ASCII URL encoding."
    return None


class RequestRefused(ValueError):
    """A request rule a case breaks. rule is a stable code each caller maps to its own message and exception type;
    step is the id of the plan step that breaks it."""

    def __init__(self, rule, step=None):
        super().__init__(rule)
        self.rule = rule
        self.step = step


def _source(manifest, case):
    """Who wrote a case's requests: the model, the operator (a case of the operator's own list), or else the engine."""
    if case.get("designed_by") == "model":
        return "model"
    return "operator" if any(c.get("id") == case.get("id") for c in manifest.get("cases") or []) else "engine"


def _step(id, phase, source, request, *, side_effects=False):
    step = {"id": id, "phase": phase, "source": source, "method": request.get("method", "GET"), "path": request.get("path"),
            "identity": request.get("identity"), "headers": {} if request.get("headers") is None else request.get("headers"),
            "body": request.get("body")}
    step["read_only"] = not state_changing({**step, "side_effects": side_effects}, operator_case=source == "operator")
    return step


# Header names ignore letter case. Both sides of a comparison fold the same way, so any one folding will do.
_FOLD = str.lower


def _headers(headers):
    if not isinstance(headers, dict):
        return headers
    return {_FOLD(str(name)): value for name, value in headers.items()}


def _key(step):
    """What makes two steps the same step; the headers are spelled as text so the key can sit in a set."""
    headers = _headers(step["headers"])
    return step["method"], step["path"], step["identity"], repr(sorted(headers.items()) if isinstance(headers, dict) else headers)


def in_scope(manifest, method, path):
    """Whether the operator's run scope (allowed_requests) lists this method and exact path."""
    return (method, path) in {(str(r.get("method", DEFAULT_METHOD)).upper(), r.get("path")) for r in manifest.get("allowed_requests") or []}


def _steps(manifest, case, *, lifecycle, live):
    """The case's plan steps in their checking order, own request first, then controls, then lifecycle, and the
    order the plan lists them in; no rule is checked here, each step only records whether it may carry a body."""
    source = _source(manifest, case)
    own = _step("case", "case", source, case, side_effects=bool(case.get("side_effects")))
    controls = [_step("control:" + str(p.get("name")), "control", source, p)
                for p in case.get("preconditions", []) if isinstance(p, dict)]
    if lifecycle is None:
        # A sealed case carries its lifecycle in its request plan; one sealed before the plan existed carries it in
        # allowed_requests, beside the case's own requests.
        plan = case.get("request_plan")
        lifecycle = ([s for s in plan.get("steps", []) if s.get("phase") not in CASE_PHASES] if isinstance(plan, dict)
                     else case.get("allowed_requests") or [])
    # A step is the same step only with the same headers too: an engine probe of a control's request keeps its own source.
    seen = {_key(s) for s in [own, *controls]}
    engine = []
    for request in lifecycle:
        step = _step(request.get("id") or f"lifecycle:{len(engine) + 1}", request.get("phase", "lifecycle"), "engine", request)
        key = _key(step)
        if key not in seen:
            seen.add(key)
            engine.append(step)
    # The model wrote a body or a write after reading the untrusted snapshot: it goes only to an endpoint the operator
    # marked model_body, never to one that stores, publishes or forwards what it receives.
    marked = {(str(r.get("method", DEFAULT_METHOD)).upper(), r.get("path")) for r in manifest.get("allowed_requests") or []
              if r.get("model_body") is True}
    for step in [own, *controls, *engine]:
        payload = step["body"] is not None or str(step["method"]).upper() not in SAFE_METHODS
        step["body_permitted"] = not (live and step["source"] == "model" and payload) or (str(step["method"]).upper(), step["path"]) in marked
    return [own, *controls, *engine], [*controls, own, *engine]


def plan_case(manifest, case, *, live, lifecycle=None):
    """The case's request plan: every request it may send, in order, each with who wrote it.

    lifecycle is the engine's fixture lifecycle for the case (reset, setup, cleanup and the like); without it the
    lifecycle the case was sealed with is used. Each rule is checked over every step before the next rule, the case's
    own request first, then its controls, then its lifecycle: the order the case gate has always reported them in.
    A step that breaks a rule raises RequestRefused naming the rule and the step."""
    checked, planned = _steps(manifest, case, lifecycle=lifecycle, live=live)
    for step in checked:
        # The operator's per-endpoint list binds only what the model wrote; other headers ignore it.
        vocabulary = model_header_vocabulary(manifest, step["method"], step["path"])
        if not case_headers_allowed(step["headers"], model_designed=step["source"] == "model", vocabulary=vocabulary):
            raise RequestRefused("headers", step["id"])
    selectable = {p.get("id") for p in manifest.get("auth_profiles") or [] if p.get("model_selectable") is True}
    for step in checked:
        if step["source"] == "model" and step["identity"] is not None and step["identity"] not in selectable:
            raise RequestRefused("identity", step["id"])
    if live:
        for step in checked:
            if not in_scope(manifest, step["method"], step["path"]):
                raise RequestRefused("scope", step["id"])
    return {"version": 1, "steps": planned}


def match_request(manifest, case, request, *, expect=None):
    """The step of the case's request plan this request is: the one with its method, path and identity.

    Where more than one step has them, expect (the sealed step the caller is about to send) picks the one with its
    headers. Steps that are still alike, or no expect, give the first: the plan lists the case's own steps before the
    engine's, so a model's step is never read as the engine's."""
    method = str(request.get("method", DEFAULT_METHOD)).upper()
    if not in_scope(manifest, method, request.get("path")):
        raise RequestRefused("scope")
    plan = case.get("request_plan")
    # A case sealed before the plan existed passed the case gate then: its plan is rebuilt from its fields, unchecked
    # and never written back, so neither its hash nor the operator's approval changes.
    # Every caller matches requests of a live run, so the rebuilt plan holds a model's body to the live rule.
    steps = plan["steps"] if isinstance(plan, dict) else _steps(manifest, case, lifecycle=None, live=True)[1]
    named = [s for s in steps if (str(s["method"]).upper(), s["path"]) == (method, request.get("path"))]
    if not named:
        raise RequestRefused("step")
    # The identity is the named step's own, never another step's.
    steps = [s for s in named if s["identity"] == request.get("identity")]
    if not steps:
        raise RequestRefused("identity", named[0]["id"])
    if expect is not None:
        steps = [s for s in steps if _headers(s["headers"]) == _headers(expect.get("headers"))] or steps
    return steps[0]
