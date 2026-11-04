"""Properties of the pure functions, checked over generated inputs with Hypothesis (offline, no service or key)."""
import ipaddress
import json
import re
from urllib.parse import quote

import pytest
from hypothesis import example, given, settings, strategies as st

from vibe_audit import adapters, snapshot
from vibe_audit.adapters import AdapterBlocked, _one_of, _origin, _pinned_address, _unmapped, case_headers_allowed, format_origin, parse_origin, secret_forms, target_ip_refused
from vibe_audit.lease import canonical_hash
from vibe_audit.messages import PATTERNS, STATUS_ZH, ZH, zh
from vibe_audit.policy import sealed
from vibe_audit.snapshot import _routes, redact_text

settings.register_profile("ci", deadline=None, max_examples=200)
settings.load_profile("ci")

printable = st.text(st.characters(min_codepoint=33, max_codepoint=126), min_size=1, max_size=64)
labels = st.from_regex(r"[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?", fullmatch=True)
json_values = st.recursive(st.none() | st.booleans() | st.integers() | st.text(max_size=20),
                           lambda children: st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=8), children, max_size=4), max_leaves=12)


@given(printable)
def test_secret_forms_hold_the_value_and_its_escapings(value):
    forms = secret_forms(value)
    assert value in forms and quote(value, safe="") in forms
    escaped = json.dumps(value)[1:-1]
    assert escaped in forms and json.loads(f'"{escaped}"') == value
    assert all(forms) and len(forms) <= 4


@given(st.lists(labels, min_size=1, max_size=4), st.sampled_from(["http", "https"]), st.integers(1, 65535))
def test_origin_round_trips_a_plain_host_and_port(parts, scheme, port):
    host = ".".join(parts)
    assert _origin({"target_url": f"{scheme}://{host.upper()}:{port}/"}) == (scheme, host, port)
    with pytest.raises(AdapterBlocked):
        _origin({"target_url": f"{scheme}://{host}:{port}/path"})
    # A model endpoint reads the same origin through its path, and the text form reads back to the same parts.
    assert parse_origin(f"{scheme}://{host}:{port}/v1/chat", allow_path=True) == (scheme, host, port)
    for omit in (False, True):
        assert parse_origin(format_origin(scheme, host, port, omit_default_port=omit)) == (scheme, host, port)


@given(st.lists(printable, min_size=1, max_size=6, unique=True), printable)
def test_one_of_matches_whole_options_only(options, other):
    pattern = _one_of(options)
    assert all(pattern.fullmatch(option) for option in options)
    assert (pattern.fullmatch(other) is not None) == (other in options)


def same_json(a, b):
    """The same JSON value: Python's == also holds for False and 0 or True and 1, which JSON writes differently."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(same_json(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(same_json(x, y) for x, y in zip(a, b))
    return a == b


@given(st.dictionaries(st.text(max_size=8), json_values, max_size=6), st.text(max_size=8), json_values)
# Python counts False == 0 and True == 1; JSON does not, so neither may the hash.
@example(mapping={"": False}, key="", value=0)
@example(mapping={"a": [True]}, key="a", value=[1])
def test_canonical_hashes_ignore_key_order_and_notice_every_change(mapping, key, value):
    reordered = dict(reversed(list(mapping.items())))
    assert canonical_hash(mapping) == canonical_hash(reordered)
    assert sealed({**mapping, "hash": "ignored"}) == sealed(mapping)
    changed = {**mapping, key: value}
    assert (canonical_hash(changed) == canonical_hash(mapping)) == (key in mapping and same_json(mapping[key], value))


@given(st.ip_addresses())
def test_literal_targets_are_dialled_as_themselves_or_refused(address):
    text = str(address)
    assert _unmapped(_unmapped(address)) == _unmapped(address)
    if address.version == 4:
        assert target_ip_refused(ipaddress.ip_address(f"::ffff:{text}")) == target_ip_refused(address)
    if target_ip_refused(address):
        with pytest.raises(AdapterBlocked, match="metadata, link-local, unspecified or multicast"):
            _pinned_address(text, 80, [text])
    else:
        assert _pinned_address(text, 80, [text]) == text
        with pytest.raises(AdapterBlocked, match="outside the exact target IP allowlist"):
            _pinned_address(text, 80, ["203.0.113.254" if text != "203.0.113.254" else "203.0.113.253"])


@st.composite
def secret_bearing_text(draw):
    """Arbitrary text with a known-format token, a private key or a URL credential dropped into it."""
    token = draw(st.sampled_from([
        "AKIA" + draw(st.text(st.sampled_from("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"), min_size=16, max_size=16)),
        "sk-" + draw(st.text(st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789"), min_size=20, max_size=40)),
        "ghp_" + draw(st.text(st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789"), min_size=24, max_size=40)),
        "-----BEGIN PRIVATE KEY-----\n" + draw(st.text(max_size=40)) + "\n-----END PRIVATE KEY-----",
        "https://" + draw(labels) + ":" + draw(st.text(st.characters(min_codepoint=33, max_codepoint=126, blacklist_characters="/@:\\"), min_size=1, max_size=12)) + "@host/",
    ]))
    # The token stands alone, as it would in a file: a letter glued to it is a longer word, not a key.
    return draw(st.text(max_size=30)) + " " + token + " " + draw(st.text(max_size=30))


@given(secret_bearing_text())
def test_redaction_leaves_no_known_secret_form_and_is_stable(text):
    redacted = redact_text(text)
    assert "[REDACTED" in redacted
    for pattern in (snapshot._KNOWN_SECRET, snapshot._PRIVATE_KEY, snapshot._URL_AUTH):
        assert pattern.search(redacted) is None, pattern.pattern[:40]
    assert redact_text(redacted) == redacted


@given(st.text(max_size=200))
def test_redaction_never_fails_and_only_removes_secret_shapes(text):
    redacted = redact_text(text)
    assert isinstance(redacted, str)
    if not re.search(r"(?i)key|pass|pwd|secret|token|auth|bearer|://|-----BEGIN|AKIA|AIza|sk-|xox|gh[pousr]_|glpat|npm_|hf_|ASIA|SG\.|ya29|shp|dop_v1|pypi-|hooks\.slack|eyJ", text):
        assert redacted == text


@given(st.text(max_size=120))
def test_zh_answers_every_text_with_chinese_or_nothing(text):
    answer = zh(text)
    assert answer is None or (isinstance(answer, str) and answer)
    assert zh(None) is None


@given(st.sampled_from(sorted(ZH)), st.sampled_from(sorted(STATUS_ZH)))
def test_known_messages_and_labelled_statuses_read_in_chinese(message, status):
    assert zh(message) == ZH[message]
    # "<label>: <status>" splits at the first colon, so only a message without one is a label here.
    if ": " not in message:
        assert zh(f"{message}: {status}") == f"{ZH[message]}：{STATUS_ZH[status]}"


@given(st.sampled_from(PATTERNS), st.lists(st.text(st.characters(min_codepoint=48, max_codepoint=122, whitelist_categories=("L", "N")), min_size=1, max_size=6), min_size=1, max_size=4))
def test_every_pattern_template_renders_for_any_simple_values(pattern, values):
    regex, template = pattern
    groups = regex.count("(") - regex.count("(?") - regex.count("\\(")
    filled = template.format(*(values * groups)[:groups])
    assert isinstance(filled, str) and "{" not in filled


@given(st.text(max_size=400), st.from_regex(r"[a-z]{1,8}(/[a-z]{1,8}){0,3}\.(py|ts|js)", fullmatch=True))
def test_route_extraction_is_bounded_and_well_formed(content, path):
    routes = _routes(path, content)
    assert len(routes) <= 200
    for route in routes:
        assert set(route) == {"method", "path", "file", "line", "confidence"}
        assert route["file"] == path and route["confidence"] == "heuristic"
        assert 1 <= route["line"] <= content.count("\n") + 1
        assert route["method"] in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "UNKNOWN"}


@given(st.dictionaries(st.from_regex(r"[A-Za-z][A-Za-z0-9-]{0,15}", fullmatch=True), st.text(st.characters(min_codepoint=32, max_codepoint=126), max_size=64), max_size=6))
def test_operator_headers_pass_unless_forbidden(headers):
    allowed = case_headers_allowed(headers)
    forbidden = any(name.lower() in adapters._FORBIDDEN_HEADERS or name.lower() in adapters.RELAY_HEADERS for name in headers)
    assert allowed == (not forbidden)
    assert case_headers_allowed({**headers, "X-Flag": "a\tb"}) is False
