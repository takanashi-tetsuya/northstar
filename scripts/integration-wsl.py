#!/usr/bin/env python3
"""Dependency-free integration test for a locally running Northstar instance."""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import http.client
import json
import os
import re
import socket
import ssl
import struct
import time
import urllib.parse
import xml.etree.ElementTree as ET
import zlib


HTTP_HOST = os.environ.get("XMPP_TEST_HOST", "127.0.0.1")
HTTP_PORT = int(os.environ.get("XMPP_TEST_HTTP_PORT", "18080"))
METRICS_PORT = int(os.environ.get("XMPP_TEST_METRICS_PORT", str(HTTP_PORT)))
XMPP_PORT = int(os.environ.get("XMPP_TEST_CLIENT_PORT", "15222"))
XMPPS_PORT = int(os.environ.get("XMPP_TEST_XMPPS_PORT", "15223"))
DOMAIN = os.environ.get("XMPP_TEST_DOMAIN", "localhost")
ALICE = "alice_it"
BOB = "bob_it"
PASSWORD = "integration-password-123"
ADMIN = "admin_it"
ADMIN_PASSWORD = "integration-admin-password-123"
C2S_CLIENT_CERT = os.environ.get("XMPP_TEST_C2S_CLIENT_CERT")
C2S_CLIENT_KEY = os.environ.get("XMPP_TEST_C2S_CLIENT_KEY")
C2S_WRONG_DOMAIN_CERT = os.environ.get("XMPP_TEST_C2S_WRONG_DOMAIN_CERT")
C2S_WRONG_DOMAIN_KEY = os.environ.get("XMPP_TEST_C2S_WRONG_DOMAIN_KEY")
C2S_CN_ONLY_CERT = os.environ.get("XMPP_TEST_C2S_CN_ONLY_CERT")
C2S_CN_ONLY_KEY = os.environ.get("XMPP_TEST_C2S_CN_ONLY_KEY")
C2S_UNTRUSTED_CERT = os.environ.get("XMPP_TEST_C2S_UNTRUSTED_CERT")
C2S_UNTRUSTED_KEY = os.environ.get("XMPP_TEST_C2S_UNTRUSTED_KEY")


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def assert_carbon_shape(stanza: str, direction: str) -> None:
    """Validate the namespace structure a standards client actually sees."""
    check(direction in ("sent", "received"), f"invalid Carbon direction: {direction}")
    try:
        root = ET.fromstring(stanza)
    except ET.ParseError as error:
        raise AssertionError(f"Carbon is not standalone XML: {stanza}") from error
    check(root.tag == "{jabber:client}message", f"invalid Carbon message root: {stanza}")
    wrapper = root.find(f"{{urn:xmpp:carbons:2}}{direction}")
    check(wrapper is not None, f"missing {direction} Carbon wrapper: {stanza}")
    forwarded = wrapper.find("{urn:xmpp:forward:0}forwarded")
    check(forwarded is not None, f"missing Carbon forwarded element: {stanza}")
    children = list(forwarded)
    check(
        len(children) == 1 and children[0].tag == "{jabber:client}message",
        f"forwarded Carbon stanza is not a jabber:client message: {stanza}",
    )


def png_1x1_rgba(red: int, green: int, blue: int, alpha: int = 255) -> bytes:
    """Build a deterministic, standards-valid one-pixel RGBA PNG."""

    def chunk(kind: bytes, payload: bytes) -> bytes:
        checksum = zlib.crc32(kind + payload) & 0xFFFFFFFF
        return struct.pack("!I", len(payload)) + kind + payload + struct.pack("!I", checksum)

    signature = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack("!IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    scanline = bytes((0, red, green, blue, alpha))
    return signature + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(scanline)) + chunk(b"IEND", b"")


def omemo_payload_b64(marker: str) -> str:
    """Return a canonical opaque payload sentinel for server-only wire tests."""
    return base64.b64encode(marker.encode()).decode()


def omemo2_envelope(
    sender_device_id: int,
    recipients: list[tuple[str, list[int]]],
    payload_marker: str | None,
    *,
    kex: bool = False,
    store: bool = True,
) -> str:
    """Build a structurally valid OMEMO:2 outer envelope.

    The bytes are intentionally opaque rather than decryptable: real X3DH and
    Double Ratchet interoperability is exercised by the browser suite.  Wire
    fixtures use this helper to prove that the server treats the envelope as
    untrusted ciphertext and never needs private key material.
    """
    check(1 <= sender_device_id <= (1 << 31) - 1, "invalid OMEMO sender device id")
    check(recipients, "an OMEMO envelope needs at least one recipient")
    groups = []
    for jid, device_ids in recipients:
        check(device_ids, "an OMEMO recipient needs at least one device")
        keys = []
        for device_id in device_ids:
            check(1 <= device_id <= (1 << 31) - 1, "invalid OMEMO recipient device id")
            material = hashlib.sha256(
                f"northstar-wire-key:{jid}:{device_id}:{payload_marker or ''}".encode()
            ).digest()
            kex_attr = " kex='true'" if kex else ""
            keys.append(
                f"<key rid='{device_id}'{kex_attr}>"
                f"{base64.b64encode(material).decode()}</key>"
            )
        groups.append(f"<keys jid='{jid}'>" + "".join(keys) + "</keys>")
    payload = (
        f"<payload>{omemo_payload_b64(payload_marker)}</payload>"
        if payload_marker is not None
        else ""
    )
    hints = "<store xmlns='urn:xmpp:hints'/>" if payload_marker is not None and store else ""
    return (
        "<encrypted xmlns='urn:xmpp:omemo:2'>"
        f"<header sid='{sender_device_id}'>" + "".join(groups) + "</header>"
        f"{payload}</encrypted>"
        "<encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:omemo:2' name='OMEMO'/>"
        f"{hints}"
    )


def omemo2_bundle(prekey_count: int = 25, first_prekey_id: int = 1) -> str:
    """Build an exact-size public OMEMO:2 bundle for PEP protocol fixtures."""
    check(prekey_count >= 0, "negative OMEMO prekey count")
    public_key = base64.b64encode(bytes(range(32))).decode()
    signature = base64.b64encode(bytes(range(64))).decode()
    prekeys = "".join(
        f"<pk id='{first_prekey_id + offset}'>{public_key}</pk>"
        for offset in range(prekey_count)
    )
    return (
        "<bundle xmlns='urn:xmpp:omemo:2'>"
        f"<spk id='1'>{public_key}</spk><spks>{signature}</spks>"
        f"<ik>{public_key}</ik><prekeys>{prekeys}</prekeys></bundle>"
    )


def api(method: str, path: str, payload=None, token: str | None = None):
    connection = http.client.HTTPConnection(HTTP_HOST, HTTP_PORT, timeout=10)
    headers = {}
    body = None
    if payload is not None:
        body = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    raw = response.read()
    content_type = response.getheader("Content-Type", "")
    result = json.loads(raw) if raw and "json" in content_type else raw.decode()
    connection.close()
    return response.status, result


def metrics_api():
    connection = http.client.HTTPConnection(HTTP_HOST, METRICS_PORT, timeout=10)
    connection.request("GET", "/metrics")
    response = connection.getresponse()
    body = response.read().decode()
    status = response.status
    connection.close()
    return status, body


def raw_http(method: str, path: str, body: bytes | None = None, headers=None):
    connection = http.client.HTTPConnection(HTTP_HOST, HTTP_PORT, timeout=10)
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    result = response.read()
    status = response.status
    response_headers = {name.lower(): value for name, value in response.getheaders()}
    connection.close()
    return status, response_headers, result


def admin_operation_request(
    method: str,
    path: str,
    token: str,
    payload=None,
    idempotency_key: str | None = None,
    verify_replay: bool = False,
) -> tuple[dict, str, bytes]:
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    headers = {
        "Authorization": f"Bearer {token}",
        "Idempotency-Key": idempotency_key or f"integration-{time.time_ns()}",
    }
    if body is not None:
        headers["Content-Type"] = "application/json"
    status, response_headers, raw = raw_http(method, path, body, headers)
    check(status == 202, f"operation enqueue failed: {status} {raw!r}")
    result = json.loads(raw)
    operation_id = result.get("operation_id")
    location = response_headers.get("location")
    check(
        isinstance(operation_id, str)
        and location == f"/api/v1/admin/operations/{operation_id}"
        and result.get("status") == "pending",
        f"invalid asynchronous operation response: {response_headers} {result}",
    )
    if verify_replay:
        replay_status, replay_headers, replay_raw = raw_http(method, path, body, headers)
        check(
            replay_status == status
            and replay_headers.get("location") == location
            and replay_raw == raw,
            "Idempotency-Key replay was not byte-for-byte stable",
        )
    return result, location, raw


def wait_operation(token: str, location: str, expected: str = "succeeded") -> dict:
    deadline = time.monotonic() + 20
    last = None
    while time.monotonic() < deadline:
        status, last = api("GET", location, token=token)
        check(status == 200, f"operation lookup failed: {status} {last}")
        if last.get("status") in {"succeeded", "failed", "canceled", "indeterminate"}:
            check(last["status"] == expected, f"operation ended unexpectedly: {last}")
            return last
        time.sleep(0.1)
    raise AssertionError(f"operation did not terminate: {last}")


def pow_intent(method: str, path: str, body: object) -> dict[str, object]:
    if isinstance(body, str):
        encoded = body.encode()
    elif isinstance(body, bytes):
        encoded = body
    else:
        # Mirrors abuse::canonical_json_body_digest: recursive object-key
        # ordering, stable array order and no insignificant whitespace.
        encoded = json.dumps(
            body,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    return {
        "version": 2,
        "method": method,
        "path": path,
        "body_sha256": base64.urlsafe_b64encode(hashlib.sha256(encoded).digest())
        .decode()
        .rstrip("="),
    }


def solve_pow(
    token: str | None,
    action: str,
    intent: dict[str, object],
) -> dict[str, str]:
    status, challenge = api(
        "POST",
        "/api/v1/anti-abuse/challenge",
        {"action": action, "intent": intent},
        token=token,
    )
    check(status == 200, f"could not obtain {action} PoW challenge: {status} {challenge}")
    requirement = challenge["requirement"]
    wait_seconds = max(
        int(requirement.get("hard_wait_seconds", 0)),
        int(requirement.get("retry_after_seconds", 0)),
    )
    if wait_seconds:
        time.sleep(wait_seconds + 0.05)
    factor = max(1, int(requirement["work_factor"]))
    target = ((1 << 64) - 1) // factor
    prefix = challenge["prefix"].encode()
    nonce = 0
    while True:
        candidate = str(nonce).encode()
        value = int.from_bytes(hashlib.sha256(prefix + candidate).digest()[:8], "big")
        if value <= target:
            return {"challenge_id": challenge["challenge_id"], "nonce": str(nonce)}
        nonce += 1


def solve_pow_prefix(prefix: str, work_factor: int) -> str:
    target = ((1 << 64) - 1) // max(1, work_factor)
    prefix_bytes = prefix.encode()
    nonce = 0
    while True:
        candidate = str(nonce)
        value = int.from_bytes(
            hashlib.sha256(prefix_bytes + candidate.encode()).digest()[:8], "big"
        )
        if value <= target:
            return candidate
        nonce += 1


def xdata_value(xml: str, field: str) -> str:
    match = re.search(
        rf"<field\b[^>]*\bvar=['\"]{re.escape(field)}['\"][^>]*>.*?<value>(.*?)</value>",
        xml,
        re.DOTALL,
    )
    check(match is not None, f"registration form omitted {field}: {xml}")
    return html.unescape(match.group(1))


def xdata_optional_value(xml: str, field: str) -> str | None:
    """Return one XEP-0004 value, while allowing an empty/unvalued field."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as error:
        raise AssertionError(f"registration form was not standalone XML: {xml}") from error
    matching = [
        element
        for element in root.iter("{jabber:x:data}field")
        if element.get("var") == field
    ]
    check(len(matching) <= 1, f"registration form duplicated {field}: {xml}")
    if not matching:
        return None
    values = matching[0].findall("{jabber:x:data}value")
    check(len(values) <= 1, f"registration form gave multiple values for {field}: {xml}")
    if not values:
        return None
    return "".join(values[0].itertext())


def xmpp_registration_body_digest(
    username: str, password: str, invitation_token: str | None = None
) -> str:
    """Mirror PowIntent::xmpp_registration without retaining a wire body."""
    digest = hashlib.sha256()
    digest.update(b"northstar/xmpp-registration-intent/v1\0")

    def field(value: str | None) -> None:
        if value is None:
            digest.update(b"\0")
            return
        encoded = value.encode()
        digest.update(b"\1")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)

    field(username)
    field(password)
    field(invitation_token)
    return base64.urlsafe_b64encode(digest.digest()).decode().rstrip("=")


def starttls_registration_socket() -> tuple[ssl.SSLSocket, str]:
    sock = socket.create_connection((HTTP_HOST, XMPP_PORT), timeout=10)
    stream = (
        f"<stream:stream to='{DOMAIN}' version='1.0' xmlns='jabber:client' "
        "xmlns:stream='http://etherx.jabber.org/streams'>"
    ).encode()
    sock.sendall(stream)
    features = read_until(sock, b"</stream:features>")
    check(b"<starttls" in features, "registration connection did not require STARTTLS")
    sock.sendall(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
    check(b"<proceed" in read_until(sock, b"/>"), "registration STARTTLS failed")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    secure = context.wrap_socket(sock, server_hostname=DOMAIN)
    secure.sendall(stream)
    secure_features = read_until(secure, b"</stream:features>").decode()
    return secure, secure_features


def atomic_registration_wire_conformance() -> None:
    xep0077_username = "xep0077_atomic"
    secure, features = starttls_registration_socket()
    check(
        "http://jabber.org/features/iq-register" in features,
        "XEP-0077 was not advertised after STARTTLS",
    )
    secure.sendall(
        b"<iq xmlns='jabber:client' type='get' id='xep0077-form'>"
        b"<query xmlns='jabber:iq:register'/></iq>"
    )
    form = read_until(secure, b"</iq>").decode()
    check(
        xdata_optional_value(form, "urn:northstar:pow:challenge-id") in (None, ""),
        f"XEP-0077 initial form exposed an unbound PoW challenge: {form}",
    )
    secure.sendall(
        (
            "<iq xmlns='jabber:client' type='set' id='xep0077-create'>"
            "<query xmlns='jabber:iq:register'><x xmlns='jabber:x:data' type='submit'>"
            "<field var='FORM_TYPE' type='hidden'><value>jabber:iq:register</value></field>"
            f"<field var='username'><value>{xep0077_username}</value></field>"
            f"<field var='password'><value>{PASSWORD}</value></field>"
            "</x></query></iq>"
        ).encode()
    )
    result = read_until(secure, b"</iq>").decode()
    check("type='result'" in result, f"XEP-0077 atomic registration failed: {result}")
    secure.close()
    status, login = api(
        "POST", "/api/v1/login", {"username": xep0077_username, "password": PASSWORD}
    )
    check(status == 200 and login.get("token"), f"XEP-0077 account did not commit: {login}")

    xep0389_username = "xep0389_atomic"
    secure, features = starttls_registration_socket()
    check("urn:xmpp:register:0" in features, "XEP-0389 was not advertised after STARTTLS")
    secure.sendall(
        b"<register xmlns='urn:xmpp:register:0'><flow id='northstar'/></register>"
    )
    initial_form = read_until(secure, b"</challenge>").decode()
    check(
        xdata_optional_value(initial_form, "urn:northstar:pow:challenge-id")
        in (None, ""),
        f"XEP-0389 initial form exposed an unbound PoW challenge: {initial_form}",
    )
    ordinary_response = (
        "<response xmlns='urn:xmpp:register:0'><x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE' type='hidden'><value>urn:xmpp:register:0</value></field>"
        f"<field var='username'><value>{xep0389_username}</value></field>"
        f"<field var='password'><value>{PASSWORD}</value></field>"
        "</x></response>"
    )
    secure.sendall(ordinary_response.encode())
    # XEP-0077 above consumed the one ordinary registration allowance for
    # this source IP. The next exact body must therefore be challenged, which
    # gives this hermetic fixture a deterministic v2 metered-retry path.
    challenge = read_until(secure, b"</challenge>").decode()
    challenge_id = xdata_value(challenge, "urn:northstar:pow:challenge-id")
    version = int(xdata_value(challenge, "urn:northstar:pow:version"))
    prefix = xdata_value(challenge, "urn:northstar:pow:prefix")
    work_factor = int(xdata_value(challenge, "urn:northstar:pow:work-factor"))
    hard_wait = int(xdata_value(challenge, "urn:northstar:pow:hard-wait-seconds"))
    intent_digest = xdata_value(challenge, "urn:northstar:pow:intent-body-sha256")
    check(version == 2, f"XEP-0389 metered retry was not PoW v2: {challenge}")
    check(
        intent_digest
        == xmpp_registration_body_digest(xep0389_username, PASSWORD),
        f"XEP-0389 challenge was not bound to the submitted registration body: {challenge}",
    )
    if hard_wait:
        time.sleep(hard_wait + 0.05)
    nonce = solve_pow_prefix(prefix, work_factor)
    secure.sendall(
        (
            "<response xmlns='urn:xmpp:register:0'><x xmlns='jabber:x:data' type='submit'>"
            "<field var='FORM_TYPE' type='hidden'><value>urn:xmpp:register:0</value></field>"
            f"<field var='username'><value>{xep0389_username}</value></field>"
            f"<field var='password'><value>{PASSWORD}</value></field>"
            f"<field var='urn:northstar:pow:challenge-id'><value>{challenge_id}</value></field>"
            f"<field var='urn:northstar:pow:nonce'><value>{nonce}</value></field>"
            "</x></response>"
        ).encode()
    )
    success = read_until(secure, b"</success>").decode()
    check(
        f"<jid>{xep0389_username}@{DOMAIN}</jid>" in success,
        f"XEP-0389 atomic registration failed: {success}",
    )
    secure.close()
    status, login = api(
        "POST", "/api/v1/login", {"username": xep0389_username, "password": PASSWORD}
    )
    check(status == 200 and login.get("token"), f"XEP-0389 account did not commit: {login}")


def register_account(username: str, password: str) -> tuple[int, object]:
    request = {
        "username": username,
        "password": password,
        "invitation_token": None,
    }
    proof = solve_pow(
        None,
        "registration",
        pow_intent("POST", "/api/v1/register", request),
    )
    return api(
        "POST",
        "/api/v1/register",
        {**request, "pow": proof},
    )


def failed_login_idempotency_conformance() -> None:
    username = "login_idem_it"
    status, result = register_account(username, PASSWORD)
    check(status == 201, f"login idempotency account registration failed: {result}")

    request_body = json.dumps(
        {"username": username, "password": "deliberately-wrong-password"},
        separators=(",", ":"),
    ).encode()
    original_responses = []
    for attempt in range(5):
        headers = {
            "Content-Type": "application/json",
            "Idempotency-Key": f"failed-login-idempotency-{attempt:02d}",
        }
        response = raw_http("POST", "/api/v1/login", request_body, headers)
        status, response_headers, raw = response
        check(status == 401, f"invalid login did not return 401: {status} {raw!r}")
        parsed = json.loads(raw)
        check(
            parsed
            == {
                "error": {
                    "code": "unauthorized",
                    "message": "authentication required",
                }
            },
            f"invalid login returned a non-canonical error: {parsed}",
        )
        check(
            response_headers.get("www-authenticate") == 'Bearer realm="northstar"',
            f"invalid login omitted WWW-Authenticate: {response_headers}",
        )
        check("idempotency-replayed" not in response_headers, "first response was marked replayed")
        original_responses.append(response)

    status, first_challenge = api(
        "POST",
        "/api/v1/anti-abuse/challenge",
        {"action": "login", "username": username},
    )
    check(status == 200, f"could not inspect login PoW step: {first_challenge}")
    check(
        first_challenge["requirement"]["step"] == 1,
        f"five failed logins did not advance exactly one PoW step: {first_challenge}",
    )

    for attempt, original in enumerate(original_responses):
        headers = {
            "Content-Type": "application/json",
            "Idempotency-Key": f"failed-login-idempotency-{attempt:02d}",
        }
        replay_status, replay_headers, replay_raw = raw_http(
            "POST", "/api/v1/login", request_body, headers
        )
        check(
            replay_status == original[0]
            and replay_raw == original[2]
            and replay_headers.get("www-authenticate")
            == original[1].get("www-authenticate")
            and replay_headers.get("idempotency-replayed") == "true",
            f"failed-login replay was not stable: {replay_status} {replay_headers} {replay_raw!r}",
        )

    status, replay_challenge = api(
        "POST",
        "/api/v1/anti-abuse/challenge",
        {"action": "login", "username": username},
    )
    check(status == 200, f"could not inspect replayed login PoW step: {replay_challenge}")
    check(
        replay_challenge["requirement"]["step"] == 1,
        f"failed-login replay advanced the abuse counter: {replay_challenge}",
    )


def challenge_capacity_conformance() -> None:
    known_username = "capacityknown"
    status, result = register_account(known_username, PASSWORD)
    check(status == 201, f"challenge capacity account registration failed: {result}")

    for index in range(256):
        status, challenge = api(
            "POST",
            "/api/v1/anti-abuse/challenge",
            {"action": "login", "username": f"capacityunknown{index:03d}"},
        )
        check(status == 200, f"challenge capacity rejected slot {index}: {challenge}")

    denials = []
    for username in ("capacityunknownoverflow", known_username):
        body = json.dumps(
            {"action": "login", "username": username}, separators=(",", ":")
        ).encode()
        status, headers, raw = raw_http(
            "POST",
            "/api/v1/anti-abuse/challenge",
            body,
            {"Content-Type": "application/json"},
        )
        parsed = json.loads(raw)
        check(
            status == 429
            and parsed.get("error", {}).get("code") == "rate_limited"
            and parsed.get("error", {}).get("message")
            == "proof-of-work challenge capacity reached; try again later",
            f"challenge overflow was not a typed 429: {status} {headers} {parsed}",
        )
        retry_after = int(headers.get("retry-after", "0"))
        check(retry_after > 0, f"challenge overflow omitted Retry-After: {headers}")
        denials.append((parsed, retry_after))
    check(
        denials[0][0] == denials[1][0] and abs(denials[0][1] - denials[1][1]) <= 1,
        f"known and unknown login subjects leaked through capacity errors: {denials}",
    )


def assert_api_session(token: str, username: str, stage: str) -> None:
    """Assert bearer continuity without ever printing the bearer itself."""
    status, result = api("GET", "/api/v1/me", token=token)
    check(
        status == 200 and result.get("jid") == f"{username}@{DOMAIN}",
        f"{username} REST bearer became invalid at {stage}: {status} {result}",
    )


def wait_ready() -> None:
    deadline = time.monotonic() + 30
    last_error = None
    while time.monotonic() < deadline:
        try:
            status, body = api("GET", "/readyz")
            if status == 200 and body == "ready":
                return
        except OSError as error:
            last_error = error
        time.sleep(0.25)
    raise RuntimeError(f"server did not become ready: {last_error}")


def read_until(sock: socket.socket, marker: bytes, timeout: float = 10) -> bytes:
    sock.settimeout(timeout)
    data = bytearray()
    while marker not in data:
        chunk = sock.recv(8192)
        if not chunk:
            raise EOFError(f"connection ended before {marker!r}: {data!r}")
        data.extend(chunk)
    return bytes(data)


def tcp_starttls_login() -> None:
    sock = socket.create_connection((HTTP_HOST, XMPP_PORT), timeout=10)
    stream = (
        f"<stream:stream to='{DOMAIN}' version='1.0' xmlns='jabber:client' "
        "xmlns:stream='http://etherx.jabber.org/streams'>"
    ).encode()
    sock.sendall(stream)
    features = read_until(sock, b"</stream:features>")
    check(b"<starttls" in features and b"<required" in features, "STARTTLS was not required")
    sock.sendall(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
    proceed = read_until(sock, b"/>")
    check(b"<proceed" in proceed, "server did not accept STARTTLS")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    secure = context.wrap_socket(sock, server_hostname=DOMAIN)
    secure.sendall(stream)
    mechanisms = read_until(secure, b"</stream:features>")
    check(b"<mechanism>PLAIN</mechanism>" in mechanisms, "SASL PLAIN missing after TLS")
    encoded = base64.b64encode(f"\0{ALICE}\0{PASSWORD}".encode()).decode()
    secure.sendall(
        f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{encoded}</auth>".encode()
    )
    result = read_until(secure, b"/>")
    check(b"<success" in result, "TCP SASL authentication failed")
    secure.close()


def tcp_plaintext_registration_is_terminal() -> None:
    sock = socket.create_connection((HTTP_HOST, XMPP_PORT), timeout=10)
    sock.sendall(
        (
            f"<stream:stream to='{DOMAIN}' version='1.0' xmlns='jabber:client' "
            "xmlns:stream='http://etherx.jabber.org/streams'>"
        ).encode()
    )
    features = read_until(sock, b"</stream:features>")
    check(b"<starttls" in features and b"<required" in features, "plaintext stream did not require STARTTLS")
    sock.sendall(
        b"<iq type='get' id='plaintext-register'><query xmlns='jabber:iq:register'/></iq>"
    )
    terminal = read_until(sock, b"</stream:stream>")
    check(
        b"<stream:error" in terminal
        and b"<not-authorized" in terminal
        and b"</stream:stream>" in terminal,
        f"pre-STARTTLS registration was not terminated as mandatory negotiation requires: {terminal!r}",
    )
    sock.close()


def tcp_initial_header_error_opens_before_closing() -> None:
    for opening, condition in (
        (
            f"<stream:stream to='{DOMAIN}' version='1.0' xmlns='jabber:client' "
            "xmlns:stream='urn:invalid-stream-namespace'>",
            b"invalid-namespace",
        ),
        (
            f"<stream:stream to='{DOMAIN}' version='2.0' xmlns='jabber:client' "
            "xmlns:stream='http://etherx.jabber.org/streams'>",
            b"unsupported-version",
        ),
        (
            f"<stream:stream to='{DOMAIN}' xmlns='jabber:client' "
            "xmlns:stream='http://etherx.jabber.org/streams'>",
            b"unsupported-version",
        ),
        (
            f"<s:stream to='{DOMAIN}' version='1.0' xmlns='jabber:client' "
            "xmlns:s='http://etherx.jabber.org/streams'>",
            b"bad-namespace-prefix",
        ),
        (
            f"<s:stream to='{DOMAIN}' version='1.0' xmlns='jabber:client'>",
            b"bad-namespace-prefix",
        ),
        (
            "<stream:stream version='1.0' xmlns='jabber:client' "
            "xmlns:stream='http://etherx.jabber.org/streams'>",
            b"improper-addressing",
        ),
        (
            "<stream:stream to='unknown.invalid' version='1.0' xmlns='jabber:client' "
            "xmlns:stream='http://etherx.jabber.org/streams'>",
            b"host-unknown",
        ),
    ):
        sock = socket.create_connection((HTTP_HOST, XMPP_PORT), timeout=10)
        sock.sendall(opening.encode())
        terminal = read_until(sock, b"</stream:stream>")
        check(
            terminal.startswith(b"<stream:stream from=")
            and b"<stream:error" in terminal
            and condition in terminal
            and b"</stream:stream>" in terminal,
            f"initial TCP header error was not preceded by the server stream opening: {terminal!r}",
        )
        sock.close()

    for invalid, condition in (
        (b"\xff", b"unsupported-encoding"),
        (
            b"<?xml version='1.0' encoding='ISO-8859-1'?>"
            + (
                f"<stream:stream to='{DOMAIN}' version='1.0' xmlns='jabber:client' "
                "xmlns:stream='http://etherx.jabber.org/streams'>"
            ).encode(),
            b"unsupported-encoding",
        ),
    ):
        sock = socket.create_connection((HTTP_HOST, XMPP_PORT), timeout=10)
        sock.sendall(invalid)
        terminal = read_until(sock, b"</stream:stream>")
        check(
            terminal.startswith(b"<stream:stream from=")
            and condition in terminal
            and b"</stream:stream>" in terminal,
            f"initial encoding error was not reported safely: {terminal!r}",
        )
        sock.close()

    # The declaration state belongs to the complete XML entity, not one
    # socket read. A second declaration after the opening/features cannot be
    # reinterpreted as a new entity until STARTTLS or legacy SASL succeeds.
    sock = socket.create_connection((HTTP_HOST, XMPP_PORT), timeout=10)
    sock.sendall(
        (
            f"<?xml version='1.0'?><stream:stream to='{DOMAIN}' version='1.0' "
            "xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>"
        ).encode()
    )
    read_until(sock, b"</stream:features>")
    sock.sendall(b"<?xml version='1.0'?><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
    terminal = read_until(sock, b"</stream:stream>")
    check(
        b"<not-well-formed" in terminal and b"</stream:stream>" in terminal,
        f"second XML declaration in one C2S entity was accepted: {terminal!r}",
    )
    sock.close()

    for version in ("1.1", "1.01"):
        sock = socket.create_connection((HTTP_HOST, XMPP_PORT), timeout=10)
        sock.sendall(
            (
                f"<stream:stream to='{DOMAIN}' version='{version}' xmlns='jabber:client' "
                "xmlns:stream='http://etherx.jabber.org/streams'>"
            ).encode()
        )
        accepted = read_until(sock, b"</stream:features>")
        check(
            b"version='1.0'" in accepted and b"<starttls" in accepted,
            f"forward-compatible stream version {version} was rejected: {accepted!r}",
        )
        sock.close()


def tcp_direct_tls_login() -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["xmpp-client"])
    sock = socket.create_connection((HTTP_HOST, XMPPS_PORT), timeout=10)
    secure = context.wrap_socket(sock, server_hostname=DOMAIN)
    check(
        secure.selected_alpn_protocol() == "xmpp-client",
        "Direct TLS did not negotiate the xmpp-client ALPN identifier",
    )
    stream = (
        f"<stream:stream to='{DOMAIN}' version='1.0' xmlns='jabber:client' "
        "xmlns:stream='http://etherx.jabber.org/streams'>"
    ).encode()
    secure.sendall(stream)
    mechanisms = read_until(secure, b"</stream:features>")
    check(b"<starttls" not in mechanisms, "Direct TLS incorrectly advertised STARTTLS")
    check(b"<mechanism>PLAIN</mechanism>" in mechanisms, "Direct TLS SASL features missing")
    encoded = base64.b64encode(f"\0{ALICE}\0{PASSWORD}".encode()).decode()
    secure.sendall(
        f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{encoded}</auth>".encode()
    )
    result = read_until(secure, b"/>")
    check(b"<success" in result, "Direct TLS SASL authentication failed")
    secure.sendall(stream)
    post_auth = read_until(secure, b"</stream:features>")
    check(b"urn:ietf:params:xml:ns:xmpp-bind" in post_auth, "Direct TLS bind feature missing")
    secure.sendall(
        b"<iq type='set' id='direct-bind'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>"
        b"<resource>direct-tls-namespace-test</resource></bind></iq>"
    )
    bound = read_until(secure, b"direct-bind")
    check(b"type='result'" in bound, f"Direct TLS resource binding failed: {bound!r}")
    secure.sendall(
        b"<message xmlns='' type='chat' id='namespace-reset'><body>must not route</body></message>"
    )
    namespace_error = read_until(secure, b"</stream:stream>")
    check(
        b"<invalid-namespace" in namespace_error,
        f"explicit TCP default-namespace reset was accepted: {namespace_error!r}",
    )
    secure.close()


def tcp_c2s_external_conformance() -> None:
    check(
        all(
            value
            for value in (
                C2S_CLIENT_CERT,
                C2S_CLIENT_KEY,
                C2S_WRONG_DOMAIN_CERT,
                C2S_WRONG_DOMAIN_KEY,
                C2S_CN_ONLY_CERT,
                C2S_CN_ONLY_KEY,
                C2S_UNTRUSTED_CERT,
                C2S_UNTRUSTED_KEY,
            )
        ),
        "C2S EXTERNAL certificate fixture paths are missing",
    )

    def connect(certificate: str | None, key: str | None) -> tuple[socket.socket, bytes]:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(["xmpp-client"])
        if certificate is not None and key is not None:
            context.load_cert_chain(certificate, key)
        raw = socket.create_connection((HTTP_HOST, XMPPS_PORT), timeout=10)
        secure = context.wrap_socket(raw, server_hostname=DOMAIN)
        secure.sendall(
            (
                f"<stream:stream to='{DOMAIN}' version='1.0' xmlns='jabber:client' "
                "xmlns:stream='http://etherx.jabber.org/streams'>"
            ).encode()
        )
        return secure, read_until(secure, b"</stream:features>")

    anonymous, features = connect(None, None)
    check(
        b"<mechanism>EXTERNAL</mechanism>" not in features,
        "C2S EXTERNAL was advertised without a presented client identity",
    )
    anonymous.close()

    cn_only, features = connect(C2S_CN_ONLY_CERT, C2S_CN_ONLY_KEY)
    check(
        b"<mechanism>EXTERNAL</mechanism>" not in features,
        "a client-certificate commonName was accepted as an XMPP identity",
    )
    cn_only.close()

    wrong_domain, features = connect(C2S_WRONG_DOMAIN_CERT, C2S_WRONG_DOMAIN_KEY)
    check(
        b"<mechanism>EXTERNAL</mechanism>" not in features,
        "a trusted non-local id-on-xmppAddr was accepted as a C2S identity",
    )
    wrong_domain.close()

    # A matching id-on-xmppAddr never bypasses PKIX. The TLS handshake (or
    # its first attempted application write under TLS 1.3) must fail when the
    # leaf chains to a CA outside the dedicated C2S trust store.
    untrusted_rejected = False
    untrusted = None
    try:
        untrusted, _ = connect(C2S_UNTRUSTED_CERT, C2S_UNTRUSTED_KEY)
    except (ConnectionError, EOFError, OSError, ssl.SSLError):
        untrusted_rejected = True
    finally:
        if untrusted is not None:
            untrusted.close()
    check(
        untrusted_rejected,
        "an id-on-xmppAddr certificate outside the dedicated C2S PKIX roots was accepted",
    )

    secure, features = connect(C2S_CLIENT_CERT, C2S_CLIENT_KEY)
    check(
        b"<mechanism>EXTERNAL</mechanism>" in features,
        f"PKIX/id-on-xmppAddr C2S identity did not enable EXTERNAL: {features!r}",
    )
    secure.sendall(
        b"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL'>=</auth>"
    )
    external_result = read_until(secure, b"/>")
    check(
        b"<success" in external_result,
        f"implicit C2S SASL EXTERNAL authentication failed: {external_result!r}",
    )
    secure.sendall(
        (
            f"<stream:stream to='{DOMAIN}' from='{ALICE}@{DOMAIN}' version='1.0' "
            "xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>"
        ).encode()
    )
    post_auth = read_until(secure, b"</stream:features>")
    check(
        b"urn:ietf:params:xml:ns:xmpp-bind" in post_auth,
        f"EXTERNAL did not reach the authenticated restart: {post_auth!r}",
    )
    secure.sendall(
        b"<iq type='set' id='external-bind'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>"
        b"<resource>external-client-cert</resource></bind></iq>"
    )
    bound = read_until(secure, b"external-bind")
    check(
        b"type='result'" in bound and f"{ALICE}@{DOMAIN}/external-client-cert".encode() in bound,
        f"EXTERNAL identity was not bound to its certificate JID: {bound!r}",
    )
    secure.close()


def tcp_direct_tls_transport_boundaries() -> None:
    stream = (
        f"<stream:stream to='{DOMAIN}' version='1.0' xmlns='jabber:client' "
        "xmlns:stream='http://etherx.jabber.org/streams'>"
    ).encode()

    for expected_version, tls_version in (
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    ):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = tls_version
        context.maximum_version = tls_version
        context.set_alpn_protocols(["xmpp-client"])
        raw = socket.create_connection((HTTP_HOST, XMPPS_PORT), timeout=10)
        secure = context.wrap_socket(raw, server_hostname=DOMAIN)
        try:
            check(
                secure.version() == expected_version,
                f"Direct TLS negotiated {secure.version()!r}, expected {expected_version}",
            )
            check(
                secure.selected_alpn_protocol() == "xmpp-client",
                "Direct TLS did not negotiate xmpp-client for the pinned TLS version",
            )
            secure.sendall(stream)
            features = read_until(secure, b"</stream:features>")
            check(b"<starttls" not in features, "Direct TLS advertised STARTTLS")
        finally:
            secure.close()

    for server_hostname, label in ((None, "missing"), ("wrong.invalid", "wrong")):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(["xmpp-client"])
        raw = socket.create_connection((HTTP_HOST, XMPPS_PORT), timeout=10)
        secure = context.wrap_socket(raw, server_hostname=server_hostname)
        secure.settimeout(5)
        response = b""
        try:
            secure.sendall(stream)
            while len(response) <= 64 * 1024:
                chunk = secure.recv(8192)
                if not chunk:
                    break
                response += chunk
        except (ConnectionError, OSError, ssl.SSLError):
            pass
        finally:
            secure.close()
        check(
            b"<stream:features" not in response,
            f"Direct TLS accepted a {label} SNI: {response!r}",
        )


def tcp_direct_tls_auth_without_bind_times_out() -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["xmpp-client"])
    sock = socket.create_connection((HTTP_HOST, XMPPS_PORT), timeout=10)
    secure = context.wrap_socket(sock, server_hostname=DOMAIN)
    stream = (
        f"<stream:stream to='{DOMAIN}' version='1.0' xmlns='jabber:client' "
        "xmlns:stream='http://etherx.jabber.org/streams'>"
    ).encode()
    secure.sendall(stream)
    read_until(secure, b"</stream:features>")
    encoded = base64.b64encode(f"\0{ALICE}\0{PASSWORD}".encode()).decode()
    secure.sendall(
        f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{encoded}</auth>".encode()
    )
    check(b"<success" in read_until(secure, b"/>"), "deadline probe authentication failed")
    terminal = read_until(secure, b"</stream:stream>", timeout=8)
    check(
        b"<policy-violation" in terminal and b"</stream:stream>" in terminal,
        f"authenticated stream without a resource was not terminated: {terminal!r}",
    )
    secure.close()


def open_starttls_stream(stream_from: str | None = None) -> socket.socket:
    sock = socket.create_connection((HTTP_HOST, XMPP_PORT), timeout=10)
    from_attribute = f" from='{stream_from}'" if stream_from else ""
    stream = (
        f"<stream:stream to='{DOMAIN}'{from_attribute} version='1.0' xmlns='jabber:client' "
        "xmlns:stream='http://etherx.jabber.org/streams'>"
    ).encode()
    sock.sendall(stream)
    features = read_until(sock, b"</stream:features>")
    check(b"<starttls" in features and b"<required" in features, "STARTTLS was not required")
    sock.sendall(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
    check(b"<proceed" in read_until(sock, b"/>"), "server did not accept STARTTLS")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    secure = context.wrap_socket(sock, server_hostname=DOMAIN)
    secure.sendall(stream)
    post_tls = read_until(secure, b"</stream:features>")
    check(b"urn:xmpp:sasl:2" in post_tls, "SASL2 was not advertised after STARTTLS")
    return secure


def open_direct_tls_stream(stream_from: str | None = None) -> socket.socket:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["xmpp-client"])
    sock = socket.create_connection((HTTP_HOST, XMPPS_PORT), timeout=10)
    secure = context.wrap_socket(sock, server_hostname=DOMAIN)
    from_attribute = f" from='{stream_from}'" if stream_from else ""
    stream = (
        f"<stream:stream to='{DOMAIN}'{from_attribute} version='1.0' xmlns='jabber:client' "
        "xmlns:stream='http://etherx.jabber.org/streams'>"
    ).encode()
    secure.sendall(stream)
    features = read_until(secure, b"</stream:features>")
    check(b"<mechanism>PLAIN</mechanism>" in features, "SASL features missing")
    return secure


def sasl2_plain_bind(
    secure: socket.socket,
    tag: str,
    device_id: str,
    request_token: bool = False,
    authzid: str = "",
) -> tuple[bytes, str | None]:
    encoded = base64.b64encode(f"{authzid}\0{ALICE}\0{PASSWORD}".encode()).decode()
    token_request = (
        "<request-token xmlns='urn:xmpp:fast:0' mechanism='HT-SHA-256-NONE'/>"
        if request_token
        else ""
    )
    secure.sendall(
        (
            "<authenticate xmlns='urn:xmpp:sasl:2' mechanism='PLAIN'>"
            f"<initial-response>{encoded}</initial-response>"
            f"<user-agent id='{device_id}'><software>Northstar integration</software>"
            f"<device>{tag}</device></user-agent>"
            f"<bind xmlns='urn:xmpp:bind:0'><tag>{tag}</tag>"
            "<enable xmlns='urn:xmpp:carbons:2'/><enable xmlns='urn:xmpp:sm:3' resume='true'/>"
            "<inactive xmlns='urn:xmpp:csi:0'/></bind>"
            f"{token_request}</authenticate>"
        ).encode()
    )
    result = read_until(secure, b"</stream:features>")
    check(
        b"<success xmlns='urn:xmpp:sasl:2'>" in result
        and b"<bound xmlns='urn:xmpp:bind:0'>" in result
        and b"<enabled xmlns='urn:xmpp:sm:3'" in result,
        f"SASL2/Bind2 inline negotiation failed: {result!r}",
    )
    check(
        f"<authorization-identifier>{ALICE}@{DOMAIN}/{tag}/".encode() in result,
        f"Bind2 tag was not preserved in the generated resource: {result!r}",
    )
    token_match = re.search(rb"<token xmlns='urn:xmpp:fast:0'[^>]* token='([^']+)'", result)
    return result, token_match.group(1).decode() if token_match else None


def sasl2_fast_authenticate_xml(
    token: str,
    device_id: str,
    count: int,
    tag: str,
    invalidate: bool = False,
) -> str:
    initiator = hmac.new(token.encode(), b"Initiator", hashlib.sha256).digest()
    initial = base64.b64encode(ALICE.encode() + b"\0" + initiator).decode()
    invalidate_attribute = " invalidate='true'" if invalidate else ""
    return (
        "<authenticate xmlns='urn:xmpp:sasl:2' mechanism='HT-SHA-256-NONE'>"
        f"<initial-response>{initial}</initial-response>"
        f"<user-agent id='{device_id}'><software>Northstar integration</software></user-agent>"
        f"<fast xmlns='urn:xmpp:fast:0' count='{count}'{invalidate_attribute}/>"
        f"<bind xmlns='urn:xmpp:bind:0'><tag>{tag}</tag></bind>"
        "</authenticate>"
    )


def sasl2_fast_bind(
    secure: socket.socket,
    token: str,
    device_id: str,
    count: int,
    tag: str,
    invalidate: bool = False,
) -> bytes:
    secure.sendall(
        sasl2_fast_authenticate_xml(token, device_id, count, tag, invalidate).encode()
    )
    result = read_until(secure, b"</stream:features>")
    check(
        b"<success xmlns='urn:xmpp:sasl:2'>" in result
        and b"<bound xmlns='urn:xmpp:bind:0'>" in result,
        f"FAST/Bind2 authentication failed: {result!r}",
    )
    additional = re.search(rb"<additional-data>([^<]+)</additional-data>", result)
    check(additional is not None, f"FAST responder proof was missing: {result!r}")
    responder = base64.b64decode(additional.group(1))
    check(
        hmac.compare_digest(responder, hmac.new(token.encode(), b"Responder", hashlib.sha256).digest()),
        "FAST responder proof did not authenticate the server",
    )
    return result


def sasl2_scram_bind(secure: socket.socket, plus: bool) -> bytes:
    client_nonce = base64.urlsafe_b64encode(os.urandom(18)).decode().rstrip("=")
    mechanism = "SCRAM-SHA-256-PLUS" if plus else "SCRAM-SHA-256"
    flag = "p=tls-server-end-point" if plus else "n"
    gs2_header = f"{flag},a={ALICE}@{DOMAIN},"
    client_first_bare = f"n={ALICE},r={client_nonce}"
    initial = base64.b64encode(f"{gs2_header}{client_first_bare}".encode()).decode()
    secure.sendall(
        (
            f"<authenticate xmlns='urn:xmpp:sasl:2' mechanism='{mechanism}'>"
            f"<initial-response>{initial}</initial-response>"
            "<user-agent id='47d53b10-aeb5-46f8-a72d-5c6727724a31'/>"
            f"<bind xmlns='urn:xmpp:bind:0'><tag>{'Plus' if plus else 'Scram'}</tag></bind>"
            "</authenticate>"
        ).encode()
    )
    challenge_xml = read_until(secure, b"</challenge>")
    challenge_match = re.search(rb"<challenge[^>]*>([^<]+)</challenge>", challenge_xml)
    check(challenge_match is not None, f"SASL2 SCRAM challenge missing: {challenge_xml!r}")
    server_first = base64.b64decode(challenge_match.group(1)).decode()
    attributes = dict(part.split("=", 1) for part in server_first.split(","))
    nonce = attributes["r"]
    salted_password = hashlib.pbkdf2_hmac(
        "sha256", PASSWORD.encode(), base64.b64decode(attributes["s"]), int(attributes["i"])
    )
    if plus:
        endpoint = hashlib.sha256(secure.getpeercert(binary_form=True)).digest()
        channel_binding = gs2_header.encode() + endpoint
    else:
        channel_binding = gs2_header.encode()
    client_final_bare = f"c={base64.b64encode(channel_binding).decode()},r={nonce}"
    auth_message = f"{client_first_bare},{server_first},{client_final_bare}"
    client_key = hmac.new(salted_password, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    signature = hmac.new(stored_key, auth_message.encode(), hashlib.sha256).digest()
    proof = bytes(left ^ right for left, right in zip(client_key, signature))
    final = base64.b64encode(
        f"{client_final_bare},p={base64.b64encode(proof).decode()}".encode()
    ).decode()
    secure.sendall(f"<response xmlns='urn:xmpp:sasl:2'>{final}</response>".encode())
    result = read_until(secure, b"</stream:features>")
    check(
        b"<success xmlns='urn:xmpp:sasl:2'>" in result
        and b"<bound xmlns='urn:xmpp:bind:0'>" in result,
        f"SASL2 {mechanism} with authzid and Bind2 failed: {result!r}",
    )
    return result


def legacy_scram_exchange(
    username: str,
    password: str,
    mechanism: str,
) -> tuple[dict[str, str], bytes]:
    check(
        mechanism in {"SCRAM-SHA-256", "SCRAM-SHA-1"},
        f"unsupported SCRAM test mechanism: {mechanism}",
    )
    secure = open_direct_tls_stream()
    client_nonce = base64.urlsafe_b64encode(os.urandom(18)).decode().rstrip("=")
    client_first_bare = f"n={username},r={client_nonce}"
    initial = base64.b64encode(f"n,,{client_first_bare}".encode()).decode()
    secure.sendall(
        (
            f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='{mechanism}'>"
            f"{initial}</auth>"
        ).encode()
    )
    challenge_xml = read_until(secure, b"</challenge>")
    challenge_match = re.search(rb"<challenge[^>]*>([^<]+)</challenge>", challenge_xml)
    check(challenge_match is not None, f"{mechanism} did not emit server-first: {challenge_xml!r}")
    server_first = base64.b64decode(challenge_match.group(1)).decode()
    attributes = dict(part.split("=", 1) for part in server_first.split(","))
    check(
        set(attributes) == {"r", "s", "i"}
        and attributes["r"].startswith(client_nonce)
        and len(base64.b64decode(attributes["s"])) == 32,
        f"{mechanism} emitted an invalid server-first shape: {server_first!r}",
    )
    hash_name = "sha1" if mechanism == "SCRAM-SHA-1" else "sha256"
    digest = hashlib.sha1 if mechanism == "SCRAM-SHA-1" else hashlib.sha256
    salted_password = hashlib.pbkdf2_hmac(
        hash_name,
        password.encode(),
        base64.b64decode(attributes["s"]),
        int(attributes["i"]),
    )
    client_final_bare = f"c=biws,r={attributes['r']}"
    auth_message = f"{client_first_bare},{server_first},{client_final_bare}"
    client_key = hmac.new(salted_password, b"Client Key", digest).digest()
    stored_key = digest(client_key).digest()
    client_signature = hmac.new(stored_key, auth_message.encode(), digest).digest()
    proof = bytes(left ^ right for left, right in zip(client_key, client_signature))
    final = base64.b64encode(
        f"{client_final_bare},p={base64.b64encode(proof).decode()}".encode()
    ).decode()
    secure.sendall(
        f"<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>{final}</response>".encode()
    )
    secure.settimeout(10)
    terminal = bytearray()
    while b"</success>" not in terminal and b"</failure>" not in terminal:
        chunk = secure.recv(8192)
        if not chunk:
            break
        terminal.extend(chunk)
    result = bytes(terminal)
    if b"</success>" in result:
        success = re.search(rb"<success[^>]*>([^<]+)</success>", result)
        check(success is not None, f"{mechanism} success omitted server-final data: {result!r}")
        server_final = base64.b64decode(success.group(1)).decode()
        server_key = hmac.new(salted_password, b"Server Key", digest).digest()
        expected = base64.b64encode(
            hmac.new(server_key, auth_message.encode(), digest).digest()
        ).decode()
        check(
            server_final == f"v={expected}",
            f"{mechanism} server-final signature did not authenticate the server",
        )
    secure.close()
    return attributes, result


def tcp_sasl_core_conformance() -> None:
    # RFC 6120 section 6.3.10: legacy SASL must support the less-efficient
    # exchange where <auth/> omits its initial response.
    secure = open_direct_tls_stream()
    secure.sendall(b"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'/>")
    challenge = read_until(secure, b"</challenge>")
    check(b"<challenge" in challenge, "omitted PLAIN initial response was not challenged")
    encoded = base64.b64encode(f"\0{ALICE}\0{PASSWORD}".encode()).decode()
    secure.sendall(
        f"<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>{encoded}</response>".encode()
    )
    check(b"<success" in read_until(secure, b"/>"), "deferred PLAIN response failed")
    secure.close()

    secure = open_direct_tls_stream()
    secure.sendall(b"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='SCRAM-SHA-256'/>")
    challenge = read_until(secure, b"</challenge>")
    check(b"<challenge" in challenge, "omitted SCRAM initial response was not challenged")
    client_nonce = "northstar-integration-client-nonce"
    client_first_bare = f"n={ALICE},r={client_nonce}"
    client_first = base64.b64encode(f"n,,{client_first_bare}".encode()).decode()
    secure.sendall(
        f"<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>{client_first}</response>".encode()
    )
    server_challenge = read_until(secure, b"</challenge>").decode()
    match = re.search(r"<challenge[^>]*>([^<]+)</challenge>", server_challenge)
    check(match is not None, f"SCRAM server-first message missing: {server_challenge}")
    server_first = base64.b64decode(match.group(1)).decode()
    attributes = dict(part.split("=", 1) for part in server_first.split(","))
    nonce = attributes["r"]
    salt = base64.b64decode(attributes["s"])
    iterations = int(attributes["i"])
    client_final_bare = f"c=biws,r={nonce}"
    auth_message = f"{client_first_bare},{server_first},{client_final_bare}"
    salted_password = hashlib.pbkdf2_hmac("sha256", PASSWORD.encode(), salt, iterations)
    client_key = hmac.new(salted_password, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    client_signature = hmac.new(stored_key, auth_message.encode(), hashlib.sha256).digest()
    proof = bytes(left ^ right for left, right in zip(client_key, client_signature))
    client_final = base64.b64encode(
        f"{client_final_bare},p={base64.b64encode(proof).decode()}".encode()
    ).decode()
    secure.sendall(
        f"<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>{client_final}</response>".encode()
    )
    check(
        b"<success" in read_until(secure, b"</success>"),
        "deferred SCRAM-SHA-256 response failed",
    )
    secure.close()

    _, sha1_result = legacy_scram_exchange(ALICE, PASSWORD, "SCRAM-SHA-1")
    check(
        b"</success>" in sha1_result,
        f"explicitly enabled SCRAM-SHA-1 compatibility failed: {sha1_result!r}",
    )

    # Unknown and disabled users both complete the full server-first/final
    # exchange with account- and family-specific dummy material. Their public
    # round-trip count, salt/iteration syntax and terminal condition remain
    # indistinguishable. Iteration *values* are deliberately selected by a
    # deployment-keyed account mapping from every live profile, so two
    # different usernames need not receive the same value. Requiring equality
    # here made the fixture depend on the random dummy-SCRAM secret. Corrupt
    # stored verifiers are tested separately as a temporary backend failure in
    # the random-schema database suite.
    status, admin_login = api(
        "POST", "/api/v1/login", {"username": ADMIN, "password": ADMIN_PASSWORD}
    )
    check(status == 200, f"could not authenticate admin for disabled SCRAM probe: {admin_login}")
    status, user_page = api("GET", "/api/v1/admin/users", token=admin_login["token"])
    check(status == 200, f"could not list users for disabled SCRAM probe: {user_page}")
    bob_id = next(row["id"] for row in user_page["users"] if row["username"] == BOB)
    _, disable_location, _ = admin_operation_request(
        "PATCH",
        f"/api/v1/admin/users/{bob_id}",
        admin_login["token"],
        {"disabled": True},
    )
    wait_operation(admin_login["token"], disable_location)
    try:
        unknown_shape, unknown_result = legacy_scram_exchange(
            "unknown_scram_it", PASSWORD, "SCRAM-SHA-256"
        )
        disabled_shape, disabled_result = legacy_scram_exchange(
            BOB, PASSWORD, "SCRAM-SHA-256"
        )
        check(
            set(unknown_shape) == set(disabled_shape) == {"r", "s", "i"}
            and len(base64.b64decode(unknown_shape["s"]))
            == len(base64.b64decode(disabled_shape["s"]))
            == 32
            and 4096 <= int(unknown_shape["i"]) <= 10_000_000
            and 4096 <= int(disabled_shape["i"]) <= 10_000_000
            and unknown_shape["s"] != disabled_shape["s"],
            "unknown and disabled SCRAM server-first wire shapes diverged, used an invalid cost, or reused one salt",
        )
        check(
            b"<not-authorized" in unknown_result
            and b"<not-authorized" in disabled_result
            and b"unknown_scram_it" not in unknown_result
            and BOB.encode() not in disabled_result,
            "unknown/disabled SCRAM did not finish with one non-enumerating failure shape",
        )
    finally:
        status, reenabled = api(
            "PATCH",
            f"/api/v1/admin/users/{bob_id}",
            {"disabled": False},
            token=admin_login["token"],
        )
        check(status == 200, f"could not re-enable SCRAM probe account: {reenabled}")

    # A supplied authorization identity that is not authorized has its own
    # mandatory public condition; parser diagnostics must remain server-side.
    invalid_authzid = base64.b64encode(
        f"mallory@{DOMAIN}\0{ALICE}\0{PASSWORD}".encode()
    ).decode()
    secure = open_direct_tls_stream()
    secure.sendall(
        f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{invalid_authzid}</auth>".encode()
    )
    failure = read_until(secure, b"</failure>")
    check(
        b"<invalid-authzid" in failure and b"mallory" not in failure,
        f"legacy SASL leaked or misclassified authzid failure: {failure!r}",
    )
    secure.close()

    secure = open_direct_tls_stream()
    secure.sendall(
        (
            "<authenticate xmlns='urn:xmpp:sasl:2' mechanism='PLAIN'>"
            f"<initial-response>{invalid_authzid}</initial-response></authenticate>"
        ).encode()
    )
    failure = read_until(secure, b"</failure>")
    check(
        b"<invalid-authzid" in failure and b"mallory" not in failure,
        f"SASL2 leaked or misclassified authzid failure: {failure!r}",
    )
    secure.close()

    # A legacy stream `from` is not trusted before authentication, but if it
    # is supplied the server must bind the eventual success to that identity.
    # Perform the password work first and return the same public failure as a
    # bad credential, so this validation does not become an account oracle.
    secure = open_direct_tls_stream(f"{BOB}@{DOMAIN}")
    encoded = base64.b64encode(f"\0{ALICE}\0{PASSWORD}".encode()).decode()
    secure.sendall(
        f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{encoded}</auth>".encode()
    )
    failure = read_until(secure, b"</failure>")
    check(
        b"<not-authorized" in failure
        and ALICE.encode() not in failure
        and BOB.encode() not in failure,
        f"pre-SASL stream identity was not bound without disclosure: {failure!r}",
    )
    secure.close()

    # Once legacy SASL succeeds, a fresh XML entity is required.  Any `from`
    # on that restarted entity is authoritative and must still name the
    # authenticated bare JID.
    secure = open_direct_tls_stream(f"{ADMIN}@{DOMAIN}")
    admin_encoded = base64.b64encode(
        f"\0{ADMIN}\0{ADMIN_PASSWORD}".encode()
    ).decode()
    secure.sendall(
        f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{admin_encoded}</auth>".encode()
    )
    check(b"<success" in read_until(secure, b"/>"), "identity-bound PLAIN failed")
    secure.sendall(
        (
            f"<stream:stream to='{DOMAIN}' from='{BOB}@{DOMAIN}' version='1.0' "
            "xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>"
        ).encode()
    )
    restart_failure = read_until(secure, b"</stream:stream>")
    check(
        b"<invalid-from" in restart_failure and b"</stream:stream>" in restart_failure,
        f"post-SASL stream identity change was accepted: {restart_failure!r}",
    )
    secure.close()

    # Five retries are allowed on one XML stream; initiating a sixth closes
    # that stream with policy-violation instead of allowing an unbounded loop.
    secure = open_direct_tls_stream()
    for attempt in range(5):
        request = (
            f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='INVALID-{attempt}'/>"
            if attempt % 2 == 0
            else f"<authenticate xmlns='urn:xmpp:sasl:2' mechanism='INVALID-{attempt}'/>"
        )
        secure.sendall(request.encode())
        failure = read_until(secure, b"</failure>")
        check(b"<invalid-mechanism" in failure, f"SASL retry {attempt + 1} was misclassified")
    secure.sendall(b"<authenticate xmlns='urn:xmpp:sasl:2' mechanism='INVALID-6'/>")
    closing = read_until(secure, b"</stream:stream>")
    check(b"<policy-violation" in closing, "sixth SASL attempt did not close the stream")
    secure.close()


def tcp_sasl2_bind2_fast_conformance() -> None:
    device_id = "d24452b0-73f7-4ebc-9a28-68dbf446f23e"

    # Bind2 and its Carbons/SM/CSI inline features must be available over
    # both standardized TCP TLS profiles without a stream restart.
    secure = open_starttls_stream(f"{ALICE}@{DOMAIN}")
    sasl2_plain_bind(
        secure,
        "Starttls",
        "eb95df34-fb88-44dd-beba-1245592834f3",
        authzid=f"{ALICE}@{DOMAIN}",
    )
    secure.close()

    secure = open_direct_tls_stream(f"{ALICE}@{DOMAIN}")
    sasl2_scram_bind(secure, plus=False)
    secure.close()

    secure = open_direct_tls_stream(f"{ALICE}@{DOMAIN}")
    sasl2_scram_bind(secure, plus=True)
    secure.close()

    # A full credential authentication may issue a FAST token. The same
    # installation can use it with different generated Bind2 resources, but
    # a replayed counter succeeds at most once and explicit invalidation is
    # effective before another authentication can begin.
    secure = open_direct_tls_stream(f"{ALICE}@{DOMAIN}")
    _, token = sasl2_plain_bind(secure, "FastIssue", device_id, request_token=True)
    check(token is not None, "full SASL2 authentication did not issue a FAST token")
    secure.close()

    secure = open_direct_tls_stream(f"{ALICE}@{DOMAIN}")
    sasl2_fast_bind(secure, token, device_id, 1, "FastResourceA")
    secure.close()

    replay = open_direct_tls_stream(f"{ALICE}@{DOMAIN}")
    replay.sendall(sasl2_fast_authenticate_xml(token, device_id, 1, "Replay").encode())
    replay_failure = read_until(replay, b"</failure>")
    check(
        b"<not-authorized" in replay_failure,
        f"FAST replay was not rejected as an authentication failure: {replay_failure!r}",
    )
    replay.close()

    secure = open_direct_tls_stream(f"{ALICE}@{DOMAIN}")
    sasl2_fast_bind(secure, token, device_id, 2, "FastResourceB")
    secure.close()

    secure = open_direct_tls_stream(f"{ALICE}@{DOMAIN}")
    sasl2_fast_bind(secure, token, device_id, 3, "FastInvalidate", invalidate=True)
    secure.close()

    revoked = open_direct_tls_stream(f"{ALICE}@{DOMAIN}")
    revoked.sendall(sasl2_fast_authenticate_xml(token, device_id, 4, "Revoked").encode())
    revoked_failure = read_until(revoked, b"</failure>")
    check(
        b"<credentials-expired" in revoked_failure,
        f"invalidated FAST credential remained usable: {revoked_failure!r}",
    )
    revoked.close()

    # XEP-0388 deliberately does not inherit RFC 6120's legacy single '='
    # empty-response sentinel, and base SASL2 children cannot appear after an
    # inline extension.
    malformed = open_direct_tls_stream()
    malformed.sendall(
        b"<authenticate xmlns='urn:xmpp:sasl:2' mechanism='PLAIN'>"
        b"<initial-response>=</initial-response></authenticate>"
    )
    check(
        b"<incorrect-encoding" in read_until(malformed, b"</failure>"),
        "SASL2 accepted the legacy explicit-empty Base64 sentinel",
    )
    malformed.sendall(
        (
            "<authenticate xmlns='urn:xmpp:sasl:2' mechanism='PLAIN'>"
            "<bind xmlns='urn:xmpp:bind:0'/>"
            "<user-agent id='4cf1aa55-c1f8-472a-ab3a-431dbaa1a0ef'/></authenticate>"
        ).encode()
    )
    check(
        b"<malformed-request" in read_until(malformed, b"</failure>"),
        "SASL2 accepted an out-of-order base child after Bind2",
    )
    malformed.close()

    exclusive = open_direct_tls_stream()
    exclusive.sendall(b"<authenticate xmlns='urn:xmpp:sasl:2' mechanism='PLAIN'/>")
    check(b"<challenge" in read_until(exclusive, b"</challenge>"), "SASL2 challenge missing")
    exclusive.sendall(b"<message xmlns='jabber:client' type='chat'/>")
    terminal = read_until(exclusive, b"</stream:stream>")
    check(
        terminal.endswith(b"</stream:stream>"),
        f"non-SASL XML did not terminate an active SASL2 exchange: {terminal!r}",
    )
    exclusive.close()

    restart_file = os.environ.get("XMPP_TEST_FAST_RESTART_FILE")
    if restart_file:
        restart_device = "04ce4ba1-9203-491c-adf3-5d7d6e563f0b"
        restart_candidate = open_direct_tls_stream(f"{ALICE}@{DOMAIN}")
        _, restart_token = sasl2_plain_bind(
            restart_candidate,
            "RestartIssue",
            restart_device,
            request_token=True,
        )
        check(restart_token is not None, "restart probe did not issue a FAST token")
        restart_candidate.close()
        descriptor = os.open(restart_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump({"token": restart_token, "device_id": restart_device}, output)


def fast_after_process_restart_conformance() -> None:
    restart_file = os.environ.get("XMPP_TEST_FAST_RESTART_FILE")
    check(restart_file is not None, "restart verification requires a token state file")
    with open(restart_file, encoding="utf-8") as source:
        state = json.load(source)
    secure = open_direct_tls_stream(f"{ALICE}@{DOMAIN}")
    sasl2_fast_bind(secure, state["token"], state["device_id"], 1, "Restarted")
    secure.close()


def recv_exact(sock: socket.socket, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        chunk = sock.recv(length - len(result))
        if not chunk:
            raise EOFError("WebSocket connection closed")
        result.extend(chunk)
    return bytes(result)


class XmppWebSocket:
    def __init__(
        self,
        username: str,
        password: str,
        resource: str,
        resume=None,
        expect_bind_conflict: bool = False,
        sasl2: bool = False,
        sasl2_resume=None,
        initial_presence: bool = True,
    ):
        self.sock = socket.create_connection((HTTP_HOST, HTTP_PORT), timeout=10)
        self.sock.settimeout(10)
        key = base64.b64encode(os.urandom(16)).decode()
        request = (
            "GET /xmpp-websocket HTTP/1.1\r\n"
            f"Host: {HTTP_HOST}:{HTTP_PORT}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "Sec-WebSocket-Protocol: xmpp\r\n"
            "X-Forwarded-Proto: https\r\n\r\n"
        ).encode()
        self.sock.sendall(request)
        response = read_until(self.sock, b"\r\n\r\n")
        check(response.startswith(b"HTTP/1.1 101"), f"WebSocket upgrade failed: {response!r}")
        accept = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        )
        check(accept in response, "invalid WebSocket accept key")
        check(b"Sec-WebSocket-Protocol: xmpp".lower() in response.lower(), "xmpp subprotocol missing")
        self.username = username
        self.password = password
        self.resource = resource
        self.sasl2_resume_id = None
        if sasl2:
            check(resume is None and not expect_bind_conflict, "SASL2 test client has no legacy bind mode")
            self.login_sasl2(sasl2_resume, initial_presence)
        else:
            self.login(resume, expect_bind_conflict, initial_presence)

    def send(self, text: str, opcode: int = 1) -> None:
        payload = text.encode()
        mask = os.urandom(4)
        first = 0x80 | opcode
        if len(payload) < 126:
            header = bytes((first, 0x80 | len(payload)))
        elif len(payload) <= 65535:
            header = bytes((first, 0x80 | 126)) + struct.pack("!H", len(payload))
        else:
            header = bytes((first, 0x80 | 127)) + struct.pack("!Q", len(payload))
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self.sock.sendall(header + mask + masked)

    def send_with_pow(self, text: str, token: str) -> None:
        check(text.endswith("</message>"), "PoW can only be attached to a complete message")
        proof = solve_pow(
            token,
            "message",
            pow_intent("XMPP", "/xmpp/message", text),
        )
        pow_xml = (
            "<pow xmlns='urn:northstar:pow:1' "
            f"challenge='{proof['challenge_id']}' nonce='{proof['nonce']}'/>"
        )
        self.send(text[: -len("</message>")] + pow_xml + "</message>")

    def receive(self, timeout: float = 10) -> str:
        deadline = time.monotonic() + timeout
        fragments = bytearray()
        while time.monotonic() < deadline:
            self.sock.settimeout(max(0.1, deadline - time.monotonic()))
            first, second = recv_exact(self.sock, 2)
            opcode = first & 0x0F
            length = second & 0x7F
            if length == 126:
                length = struct.unpack("!H", recv_exact(self.sock, 2))[0]
            elif length == 127:
                length = struct.unpack("!Q", recv_exact(self.sock, 8))[0]
            if second & 0x80:
                mask = recv_exact(self.sock, 4)
                payload = bytes(
                    byte ^ mask[index % 4] for index, byte in enumerate(recv_exact(self.sock, length))
                )
            else:
                payload = recv_exact(self.sock, length)
            if opcode == 8:
                raise EOFError("WebSocket was closed")
            if opcode == 9:
                self.send(payload.decode(errors="ignore"), opcode=10)
                continue
            if opcode in (0, 1):
                fragments.extend(payload)
                if first & 0x80:
                    return fragments.decode()
        raise TimeoutError("timed out waiting for WebSocket frame")

    def receive_until(self, marker: str, timeout: float = 10) -> tuple[str, list[str]]:
        deadline = time.monotonic() + timeout
        frames = []
        while time.monotonic() < deadline:
            try:
                frame = self.receive(max(0.1, deadline - time.monotonic()))
            except TimeoutError as error:
                raise TimeoutError(
                    f"timed out waiting for {marker!r}; frames={frames!r}"
                ) from error
            except (EOFError, ConnectionError) as error:
                raise EOFError(
                    f"WebSocket closed while waiting for {marker!r}; frames={frames!r}"
                ) from error
            frames.append(frame)
            if marker in frame:
                return frame, frames
        raise TimeoutError(f"timed out waiting for {marker!r}; frames={frames!r}")

    def login(
        self,
        resume=None,
        expect_bind_conflict: bool = False,
        initial_presence: bool = True,
    ) -> None:
        self.send(f"<open xmlns='urn:ietf:params:xml:ns:xmpp-framing' to='{DOMAIN}' version='1.0'/>")
        self.receive_until("<open ")
        self.receive_until("<mechanisms")
        encoded = base64.b64encode(f"\0{self.username}\0{self.password}".encode()).decode()
        self.send(
            f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{encoded}</auth>"
        )
        self.receive_until("<success")
        self.send(f"<open xmlns='urn:ietf:params:xml:ns:xmpp-framing' to='{DOMAIN}' version='1.0'/>")
        self.receive_until("<open ")
        features, _ = self.receive_until("</stream:features>")
        check("urn:xmpp:sm:3" in features, "stream management was not advertised after SASL")
        check("urn:xmpp:csi:0" in features, "client state indication was not advertised after SASL")
        if resume:
            previous_id, handled = resume
            self.send(
                f"<resume xmlns='urn:xmpp:sm:3' previd='{previous_id}' h='{handled}'/>"
            )
            resumed, _ = self.receive_until("<resumed ")
            check(f"previd='{previous_id}'" in resumed, f"stream resumption failed: {resumed}")
            return
        bind_id = f"bind-{self.resource}"
        self.send(
            f"<iq xmlns='jabber:client' type='set' id='{bind_id}'>"
            f"<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>{self.resource}</resource></bind></iq>"
        )
        reply, _ = self.receive_until(bind_id)
        if expect_bind_conflict:
            check(
                "type='error'" in reply and "<conflict" in reply,
                f"expected resource conflict, received: {reply}",
            )
            return
        check("type='result'" in reply, f"resource binding failed: {reply}")
        if initial_presence:
            self.send("<presence xmlns='jabber:client'/>")

    def login_sasl2(self, resume=None, initial_presence: bool = True) -> None:
        self.send(
            f"<open xmlns='urn:ietf:params:xml:ns:xmpp-framing' to='{DOMAIN}' "
            f"from='{self.username}@{DOMAIN}' version='1.0'/>"
        )
        self.receive_until("<open ")
        _, feature_frames = self.receive_until("</stream:features>")
        features = "".join(feature_frames)
        check("urn:xmpp:sasl:2" in features, "WebSocket did not advertise SASL2")
        encoded = base64.b64encode(f"\0{self.username}\0{self.password}".encode()).decode()
        device_id = "ae2ac358-8626-43f8-94ce-c6a72d7fcbfa"
        resume_xml = ""
        if resume:
            previous_id, handled = resume
            resume_xml = (
                f"<resume xmlns='urn:xmpp:sm:3' previd='{previous_id}' h='{handled}'/>"
            )
        self.send(
            "<authenticate xmlns='urn:xmpp:sasl:2' mechanism='PLAIN'>"
            f"<initial-response>{encoded}</initial-response>"
            f"<user-agent id='{device_id}'><software>Northstar integration</software></user-agent>"
            f"{resume_xml}"
            f"<bind xmlns='urn:xmpp:bind:0'><tag>{self.resource}</tag>"
            "<enable xmlns='urn:xmpp:carbons:2'/><enable xmlns='urn:xmpp:sm:3' resume='true'/>"
            "<active xmlns='urn:xmpp:csi:0'/></bind></authenticate>"
        )
        _, outcome_frames = self.receive_until("</stream:features>")
        outcome = "".join(outcome_frames)
        if resume:
            check(
                "<success xmlns='urn:xmpp:sasl:2'>" in outcome
                and "<resumed xmlns='urn:xmpp:sm:3'" in outcome
                and "<bound xmlns='urn:xmpp:bind:0'>" not in outcome
                and "</stream:features>" in outcome,
                f"WebSocket SASL2 inline SM resume did not skip Bind2 or emit features: {outcome}",
            )
        else:
            check(
                "<success xmlns='urn:xmpp:sasl:2'>" in outcome
                and "<bound xmlns='urn:xmpp:bind:0'>" in outcome
                and "<enabled xmlns='urn:xmpp:sm:3'" in outcome,
                f"WebSocket SASL2/Bind2 inline negotiation failed: {outcome}",
            )
            enabled = re.search(r"<enabled xmlns='urn:xmpp:sm:3'[^>]* id='([^']+)'", outcome)
            check(enabled is not None, f"SASL2 inline SM enable returned no resume id: {outcome}")
            self.sasl2_resume_id = enabled.group(1)
        if initial_presence:
            self.send("<presence xmlns='jabber:client'/>")

    def abort(self) -> None:
        self.sock.close()

    def close(self) -> None:
        try:
            self.send("<close xmlns='urn:ietf:params:xml:ns:xmpp-framing'/>")
        except OSError:
            pass
        self.sock.close()


def expect_orderly_websocket_close(
    client: XmppWebSocket, reason: str, timeout: float = 3
) -> None:
    deadline = time.monotonic() + timeout
    frames = []
    closed = False
    while time.monotonic() < deadline:
        try:
            frames.append(client.receive(timeout=max(0.1, deadline - time.monotonic())))
        except (EOFError, ConnectionError):
            closed = True
            break
        except (TimeoutError, socket.timeout):
            break
    check(
        closed and any("<close " in frame for frame in frames),
        f"{reason} did not complete an orderly XMPP/WebSocket close: {frames}",
    )


def bosh_post_xml(body: str) -> bytes:
    status, _, response = raw_http(
        "POST",
        "/http-bind",
        body.encode(),
        {
            "Content-Type": "text/xml; charset=utf-8",
            "X-Forwarded-Proto": "https",
        },
    )
    check(status == 200, f"BOSH request failed with HTTP {status}: {response!r}")
    return response


def bosh_sasl2_bind_conformance() -> None:
    rid = int.from_bytes(os.urandom(6), "big")
    created = bosh_post_xml(
        "<body xmlns='http://jabber.org/protocol/httpbind' "
        "xmlns:xmpp='urn:xmpp:xbosh' "
        f"rid='{rid}' to='{DOMAIN}' wait='0' hold='0' ver='1.6' xmpp:version='1.0'/>"
    )
    sid_match = re.search(rb"\bsid='([^']+)'", created)
    check(sid_match is not None, f"BOSH session did not return a SID: {created!r}")
    check(b"urn:xmpp:sasl:2" in created, f"BOSH did not advertise SASL2: {created!r}")
    sid = sid_match.group(1).decode()
    encoded = base64.b64encode(f"\0{ALICE}\0{PASSWORD}".encode()).decode()
    authenticated = bosh_post_xml(
        "<body xmlns='http://jabber.org/protocol/httpbind' "
        f"rid='{rid + 1}' sid='{sid}'>"
        "<authenticate xmlns='urn:xmpp:sasl:2' mechanism='PLAIN'>"
        f"<initial-response>{encoded}</initial-response>"
        "<user-agent id='7c396fcc-8ce4-49c7-99d7-878371ed01a4'>"
        "<software>Northstar integration</software></user-agent>"
        "<bind xmlns='urn:xmpp:bind:0'><tag>Bosh</tag>"
        "<enable xmlns='urn:xmpp:carbons:2'/><inactive xmlns='urn:xmpp:csi:0'/>"
        "</bind></authenticate></body>"
    )
    check(
        b"<success xmlns='urn:xmpp:sasl:2'>" in authenticated
        and b"<bound xmlns='urn:xmpp:bind:0'>" in authenticated
        and b"</stream:features>" in authenticated,
        f"BOSH SASL2/Bind2 negotiation failed: {authenticated!r}",
    )
    terminated = bosh_post_xml(
        "<body xmlns='http://jabber.org/protocol/httpbind' "
        f"rid='{rid + 2}' sid='{sid}' type='terminate'/>"
    )
    check(b"type='terminate'" in terminated, f"BOSH did not terminate cleanly: {terminated!r}")


def websocket_sasl2_resume_conformance() -> None:
    original = XmppWebSocket(ALICE, PASSWORD, "Sasl2Web", sasl2=True)
    resume_id = original.sasl2_resume_id
    check(resume_id is not None, "WebSocket SASL2 session was not resumable")
    original.abort()
    time.sleep(0.25)
    resumed = XmppWebSocket(
        ALICE,
        PASSWORD,
        "IgnoredBindTag",
        sasl2=True,
        sasl2_resume=(resume_id, 0),
    )
    resumed.close()


def modern_message_profiles_conformance(
    alice: XmppWebSocket,
    bob: XmppWebSocket,
    alice_token: str,
) -> None:
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='modern-disco-server' to='{DOMAIN}'>"
        "<query xmlns='http://jabber.org/protocol/disco#info'/></iq>"
    )
    disco, _ = alice.receive_until("modern-disco-server")
    check(
        all(
            client_feature not in disco
            for client_feature in (
                "urn:xmpp:sce:1",
                "urn:xmpp:stickers:0",
                "urn:xmpp:tm:1",
                "urn:xmpp:atm:1",
                "urn:xmpp:omemo:2",
            )
        ),
        "server root falsely advertised endpoint encryption/trust/rendering capabilities",
    )

    alice.send_with_pow(
        f"<message xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='chat' id='sticker-valid'>"
        "<body>🙂</body><sticker xmlns='urn:xmpp:stickers:0' pack='integration-pack'/>"
        "<file-sharing xmlns='urn:xmpp:sfs:0'>"
        "<file xmlns='urn:xmpp:file:metadata:0'><media-type>image/png</media-type>"
        "<desc>🙂</desc><size>1</size></file>"
        "<sources><url-data xmlns='http://jabber.org/protocol/url-data' "
        "target='https://files.example.test/sticker.png'/></sources>"
        "</file-sharing></message>",
        alice_token,
    )
    sticker, _ = bob.receive_until("sticker-valid")
    check(
        "urn:xmpp:stickers:0" in sticker and "urn:xmpp:sfs:0" in sticker,
        f"XEP-0449 sticker payload was not routed intact: {sticker}",
    )

    trust_key = base64.b64encode(hashlib.sha256(b"integration-trust-key").digest()).decode()
    alice.send_with_pow(
        f"<message xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='chat' id='trust-message-valid'>"
        "<store xmlns='urn:xmpp:hints'/><trust-message xmlns='urn:xmpp:tm:1' "
        "usage='urn:xmpp:atm:1' encryption='urn:xmpp:omemo:2'>"
        f"<key-owner jid='{BOB}@{DOMAIN}'><trust>{trust_key}</trust></key-owner>"
        "</trust-message></message>",
        alice_token,
    )
    trust_message, _ = bob.receive_until("trust-message-valid")
    check(
        "urn:xmpp:tm:1" in trust_message
        and "urn:xmpp:atm:1" in trust_message
        and trust_key in trust_message,
        f"XEP-0434 trust message was not routed intact: {trust_message}",
    )

    rejected_modern_ids = ["sticker-invalid", "trust-message-invalid"]
    alice.send(
        f"<message xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='chat' id='sticker-invalid'>"
        "<sticker xmlns='urn:xmpp:stickers:0'/></message>"
    )
    sticker_error, _ = alice.receive_until("sticker-invalid")
    check(
        "type='error'" in sticker_error and "bad-request" in sticker_error,
        f"standalone XEP-0449 marker was not rejected: {sticker_error}",
    )
    alice.send(
        f"<message xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='chat' id='trust-message-invalid'>"
        "<trust-message xmlns='urn:xmpp:tm:1' usage='urn:xmpp:atm:1' "
        "encryption='urn:xmpp:omemo:2'>"
        f"<key-owner jid='{BOB}@{DOMAIN}/forbidden-resource'><trust>not-base64!</trust></key-owner>"
        "</trust-message></message>"
    )
    trust_error, _ = alice.receive_until("trust-message-invalid")
    check(
        "type='error'" in trust_error and "jid-malformed" in trust_error,
        f"malformed XEP-0434 trust message was not rejected: {trust_error}",
    )
    invalid_delivery_deadline = time.time() + 0.5
    while time.time() < invalid_delivery_deadline:
        try:
            unexpected = bob.receive(max(0.05, invalid_delivery_deadline - time.time()))
        except TimeoutError:
            break
        check(
            not any(message_id in unexpected for message_id in rejected_modern_ids),
            f"invalid modern message payload was forwarded: {unexpected}",
        )


def run() -> None:
    wait_ready()
    if os.environ.get("XMPP_TEST_ONLY_CHALLENGE_CAPACITY") == "true":
        challenge_capacity_conformance()
        print("PoW challenge hard capacity and account-enumeration resistance passed")
        return
    if os.environ.get("XMPP_TEST_ONLY_LOGIN_IDEMPOTENCY") == "true":
        failed_login_idempotency_conformance()
        print("REST failed-login counting and terminal idempotency replay passed")
        return
    if os.environ.get("XMPP_TEST_ONLY_MODERN_MESSAGES") == "true":
        for username in (ALICE, BOB):
            status, result = register_account(username, PASSWORD)
            check(status == 201, f"registration failed for {username}: {status} {result}")
        status, login = api(
            "POST", "/api/v1/login", {"username": ALICE, "password": PASSWORD}
        )
        check(status == 200, f"modern-message REST login failed: {login}")
        alice = XmppWebSocket(ALICE, PASSWORD, "alice-modern")
        bob = XmppWebSocket(BOB, PASSWORD, "bob-modern")
        modern_message_profiles_conformance(alice, bob, login["token"])
        alice.close()
        bob.close()
        print("XEP-0434/XEP-0449 visible message profiles passed")
        return
    if os.environ.get("XMPP_TEST_ONLY_ATOMIC_REGISTRATION") == "true":
        atomic_registration_wire_conformance()
        print("XEP-0077 and XEP-0389 atomic registration wire conformance passed")
        return
    if os.environ.get("XMPP_TEST_SASL_RESTART_VERIFY") == "true":
        fast_after_process_restart_conformance()
        print("integration: FAST credential survived a real process restart with the mounted key")
        return
    if os.environ.get("XMPP_TEST_ONLY_XEP0077") == "true":
        delete_username = "delete_it"
        status, result = register_account(delete_username, PASSWORD)
        check(status == 201, f"XEP-0077 deletion account registration failed: {result}")
        status, delete_login = api(
            "POST", "/api/v1/login", {"username": delete_username, "password": PASSWORD}
        )
        check(status == 200, f"XEP-0077 deletion account REST login failed: {delete_login}")
        delete_primary = XmppWebSocket(delete_username, PASSWORD, "delete-primary")
        delete_resumable = XmppWebSocket(delete_username, PASSWORD, "delete-resumable")
        delete_enable_racer = XmppWebSocket(delete_username, PASSWORD, "delete-enable-racer")
        delete_resumable.send("<enable xmlns='urn:xmpp:sm:3' resume='true'/>")
        enabled, _ = delete_resumable.receive_until("<enabled ")
        check("resume='true'" in enabled, "deletion test did not create resumable SM state")
        # Deliberately leave the enable response unread. The server may process
        # this just before or just after account quiesce; either ordering must
        # end with the stream revoked and no post-snapshot durable row.
        delete_enable_racer.send("<enable xmlns='urn:xmpp:sm:3' resume='true'/>")
        delete_primary.send(
            "<iq xmlns='jabber:client' type='set' id='account-remove'>"
            "<query xmlns='jabber:iq:register'><remove/></query></iq>"
        )
        removed, _ = delete_primary.receive_until("account-remove")
        check("type='result'" in removed, f"XEP-0077 removal failed: {removed}")
        expect_orderly_websocket_close(
            delete_resumable, "XEP-0077 sibling-session revocation"
        )
        expect_orderly_websocket_close(
            delete_enable_racer, "XEP-0077 concurrent-enable revocation"
        )
        status, _ = api("GET", "/api/v1/me", token=delete_login["token"])
        check(status == 401, "XEP-0077 removal retained REST access")
        status, _ = api(
            "POST", "/api/v1/login", {"username": delete_username, "password": PASSWORD}
        )
        check(status == 401, "XEP-0077 removed account could authenticate")
        print("XEP-0077 runtime deletion/session revocation passed")
        return
    if os.environ.get("XMPP_TEST_ONLY_SASL") == "true":
        for username in (ALICE, BOB):
            status, result = register_account(username, PASSWORD)
            check(status == 201, f"registration failed for {username}: {status} {result}")
        tcp_starttls_login()
        tcp_direct_tls_transport_boundaries()
        tcp_direct_tls_auth_without_bind_times_out()
        tcp_direct_tls_login()
        tcp_c2s_external_conformance()
        tcp_sasl_core_conformance()
        tcp_sasl2_bind2_fast_conformance()
        websocket_sasl2_resume_conformance()
        bosh_sasl2_bind_conformance()
        print(
            "integration: STARTTLS/Direct TLS, deferred PLAIN/SCRAM, "
            "SASL2/SCRAM-PLUS/Bind2/FAST over TCP, WebSocket and BOSH, "
            "invalid-authzid and SASL retry ceiling passed"
        )
        return
    status, config = api("GET", "/api/v1/config")
    check(status == 200 and config["domain"] == DOMAIN, "public config failed")
    check(config["archive_policy"] == "encrypted_only", "encrypted archive policy is not active")
    status, api_headers, _ = raw_http("GET", "/api/v1/config")
    check(
        status == 200 and api_headers.get("cache-control") == "no-store, max-age=0",
        "API responses were not protected against caching",
    )
    request_id = api_headers.get("x-request-id", "")
    check(
        re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            request_id,
        )
        is not None,
        f"API response did not carry a valid request id: {request_id!r}",
    )
    status, missing_headers, missing_body = raw_http("GET", "/api/v1/not-a-real-endpoint")
    missing = json.loads(missing_body)
    check(
        status == 404
        and missing_headers.get("content-type", "").startswith("application/json")
        and missing.get("error", {}).get("code") == "not_found",
        f"unknown API route did not use the JSON error envelope: {status} {missing}",
    )
    status, api_root_headers, api_root_body = raw_http("GET", "/api")
    api_root_error = json.loads(api_root_body)
    check(
        status == 404
        and api_root_headers.get("content-type", "").startswith("application/json")
        and api_root_headers.get("cache-control") == "no-store, max-age=0"
        and api_root_error.get("error", {}).get("code") == "not_found",
        f"exact API root escaped the JSON/no-store boundary: {status} {api_root_headers} {api_root_error}",
    )
    status, method_headers, method_body = raw_http("POST", "/api/v1/config")
    method_error = json.loads(method_body)
    check(
        status == 405
        and "GET" in method_headers.get("allow", "")
        and method_error.get("error", {}).get("code") == "method_not_allowed",
        f"API method rejection lost JSON or Allow: {status} {method_headers} {method_error}",
    )

    for username in (ALICE, BOB):
        status, result = register_account(username, PASSWORD)
        check(status == 201, f"registration failed for {username}: {status} {result}")

    tcp_direct_tls_auth_without_bind_times_out()

    status, alice_login = api("POST", "/api/v1/login", {"username": ALICE, "password": PASSWORD})
    check(status == 200, f"Alice REST login failed: {alice_login}")
    alice_token = alice_login["token"]
    status, bob_login = api("POST", "/api/v1/login", {"username": BOB, "password": PASSWORD})
    check(status == 200, f"Bob REST login failed: {bob_login}")
    bob_token = bob_login["token"]
    assert_api_session(bob_token, BOB, "immediately-after-login")
    status, me = api("GET", "/api/v1/me", token=alice_token)
    check(status == 200 and me["jid"] == f"{ALICE}@{DOMAIN}", "current-user endpoint failed")

    status, admin_login = api(
        "POST", "/api/v1/login", {"username": ADMIN, "password": ADMIN_PASSWORD}
    )
    check(status == 200 and admin_login["is_admin"], "bootstrap administrator login failed")
    admin_token = admin_login["token"]
    status, invalid_admin_auth = api(
        "GET", "/api/v1/admin/users", token="A" * 64
    )
    check(
        status == 401
        and invalid_admin_auth.get("error", {}).get("code") == "unauthorized",
        f"unknown administrator bearer was not treated as unauthenticated: {invalid_admin_auth}",
    )
    status, non_admin_auth = api("GET", "/api/v1/admin/users", token=alice_token)
    check(
        status == 403 and non_admin_auth.get("error", {}).get("code") == "forbidden",
        f"valid non-administrator bearer was not forbidden: {non_admin_auth}",
    )
    status, users = api("GET", "/api/v1/admin/users", token=admin_token)
    listed_usernames = {entry["username"] for entry in users.get("users", [])}
    check(
        status == 200
        and {ADMIN, ALICE, BOB}.issubset(listed_usernames),
        "administrator user listing failed",
    )

    tcp_initial_header_error_opens_before_closing()
    tcp_plaintext_registration_is_terminal()
    tcp_starttls_login()
    tcp_direct_tls_transport_boundaries()
    tcp_direct_tls_login()
    tcp_c2s_external_conformance()
    tcp_sasl_core_conformance()
    tcp_sasl2_bind2_fast_conformance()
    websocket_sasl2_resume_conformance()
    bosh_sasl2_bind_conformance()

    # The SASL core fixture deliberately disables and re-enables Bob while it
    # verifies dummy-SCRAM and account-state behavior. That security transition
    # must revoke every bearer minted under the previous auth generation.
    status, revoked_bob_session = api("GET", "/api/v1/me", token=bob_token)
    check(
        status == 401,
        f"Bob's pre-disable REST bearer survived the auth-generation change: "
        f"{status} {revoked_bob_session}",
    )
    status, bob_login = api(
        "POST", "/api/v1/login", {"username": BOB, "password": PASSWORD}
    )
    check(status == 200, f"Bob REST re-login failed after account re-enable: {bob_login}")
    bob_token = bob_login["token"]
    assert_api_session(bob_token, BOB, "after-sasl-account-state-conformance")

    alice = XmppWebSocket(ALICE, PASSWORD, "alice-web")

    alice.send("<enable xmlns='urn:xmpp:sm:3' resume='true'/>")
    enabled, _ = alice.receive_until("<enabled ")
    resume_id_match = re.search(r"id='([^']+)'", enabled)
    check(
        resume_id_match is not None and "resume='true'" in enabled,
        "stream resumption was not enabled",
    )
    resume_id = resume_id_match.group(1)
    alice.send(
        "<iq xmlns='jabber:client' type='get' id='sm-ping'>"
        "<ping xmlns='urn:xmpp:ping'/></iq>"
    )
    alice.receive_until("sm-ping")
    alice.send("<r xmlns='urn:xmpp:sm:3'/>")
    acknowledgement, _ = alice.receive_until("<a ")
    check("h='1'" in acknowledgement, f"incorrect handled count: {acknowledgement}")
    alice.abort()
    # Exercise the real takeover race: the replacement transport must be able
    # to claim the durable SM session before the aborted socket's async
    # teardown has finished.
    alice = XmppWebSocket(ALICE, PASSWORD, "ignored-on-resume", resume=(resume_id, 0))
    replayed, _ = alice.receive_until("sm-ping")
    check("type='result'" in replayed, "unacknowledged stanza was not replayed after resume")
    alice.send("<a xmlns='urn:xmpp:sm:3' h='1'/>")

    alice.send(
        "<iq xmlns='jabber:client' type='get' id='ping-1'>"
        "<ping xmlns='urn:xmpp:ping'/></iq>"
    )
    ping, _ = alice.receive_until("ping-1")
    check("type='result'" in ping, "XMPP ping failed")

    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='disco-pep' to='{ALICE}@{DOMAIN}'>"
        "<query xmlns='http://jabber.org/protocol/disco#info'/></iq>"
    )
    pep_disco, _ = alice.receive_until("disco-pep")
    check(
        "category='pubsub' type='pep'" in pep_disco,
        f"account PEP identity was not advertised: {pep_disco}",
    )
    check(
        "http://jabber.org/protocol/pubsub#multi-items" in pep_disco
        and "http://jabber.org/protocol/pubsub#persistent-items" in pep_disco
        and "http://jabber.org/protocol/pubsub#publish-options" in pep_disco
        and "http://jabber.org/protocol/pubsub#retract-items" in pep_disco
        and "http://jabber.org/protocol/pubsub#retrieve-items" in pep_disco
        and "urn:xmpp:bookmarks:1#compat" in pep_disco
        and "urn:xmpp:pep-vcard-conversion:0" in pep_disco,
        "account PEP capabilities were not advertised",
    )

    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='disco-server' to='{DOMAIN}'>"
        "<query xmlns='http://jabber.org/protocol/disco#info'/></iq>"
    )
    disco, _ = alice.receive_until("disco-server")
    check(
        "category='server' type='im'" in disco
        and "category='pubsub' type='pep'" not in disco,
        "the server root advertised an incorrect entity identity",
    )
    check(
        all(
            client_feature not in disco
            for client_feature in (
                "urn:xmpp:sce:1",
                "urn:xmpp:stickers:0",
                "urn:xmpp:tm:1",
                "urn:xmpp:atm:1",
                "urn:xmpp:omemo:2",
            )
        ),
        "server root falsely advertised endpoint encryption/trust/rendering capabilities",
    )
    check(
        "urn:xmpp:carbons:2" in disco
        and "urn:xmpp:carbons:rules:0" in disco
        and "urn:xmpp:receipts" in disco
        and "urn:xmpp:push:0" in disco
        and "urn:xmpp:sm:3" in disco
        and "msgoffline" in disco,
        "Carbons rules, receipts, Push, offline messages, or stream management discovery features were missing",
    )
    check("urn:xmpp:sid:0" in disco, "stable stanza IDs were not advertised")
    check(
        "http://jabber.org/network/serverinfo" in disco
        and "mailto:admin@example.test" in disco
        and "xmpp:security@localhost" in disco,
        "XEP-0157 contact addresses were not advertised",
    )
    check("urn:xmpp:extdisco:2" in disco, "external service discovery was not advertised")
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='extdisco' to='{DOMAIN}'>"
        "<services xmlns='urn:xmpp:extdisco:2'/></iq>"
    )
    external_services, _ = alice.receive_until("extdisco")
    check(
        "host='stun.example.test'" in external_services
        and "port='3478'" in external_services
        and "host='turn.example.test'" in external_services
        and "port='5349'" in external_services,
        "XEP-0215 STUN/TURN endpoints were incomplete",
    )
    check(
        "username='" not in external_services and "password='" not in external_services,
        "TURN credentials leaked through service discovery",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='extdisco-turn' to='{DOMAIN}'>"
        "<services xmlns='urn:xmpp:extdisco:2' type='turn'/></iq>"
    )
    turn_only, _ = alice.receive_until("extdisco-turn")
    check(
        "type='turn'" in turn_only and "type='stun'" not in turn_only,
        "selected external service discovery ignored the requested type",
    )
    check(
        "username='" not in turn_only and "password='" not in turn_only,
        "TURN credentials leaked through service discovery instead of the credentials endpoint",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='extdisco-credentials' to='{DOMAIN}'>"
        "<credentials xmlns='urn:xmpp:extdisco:2'>"
        "<service host='turn.example.test' port='5349' type='turn' transport='udp'/>"
        "</credentials></iq>"
    )
    turn_credentials, _ = alice.receive_until("extdisco-credentials")
    turn_username = re.search(r"type='turn'[^>]*username='([^']+)'", turn_credentials)
    turn_password = re.search(r"type='turn'[^>]*password='([^']+)'", turn_credentials)
    check(
        "<credentials xmlns='urn:xmpp:extdisco:2'>" in turn_credentials
        and turn_username is not None
        and turn_password is not None
        and "expires='" in turn_credentials
        and "restricted='true'" in turn_credentials
        and f"{ALICE}@{DOMAIN}" not in turn_username.group(1),
        "explicit TURN credential request failed",
    )
    expected_turn_password = base64.b64encode(
        hmac.new(
            b"integration-turn-shared-secret-32-bytes-minimum-12345",
            turn_username.group(1).encode(),
            hashlib.sha1,
        ).digest()
    ).decode()
    check(
        turn_password.group(1) == expected_turn_password,
        "TURN REST password was not coturn-compatible HMAC-SHA1",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='extdisco-no-match' to='{DOMAIN}'>"
        "<credentials xmlns='urn:xmpp:extdisco:2'>"
        "<service host='other.example.test' port='5349' type='turn'/></credentials></iq>"
    )
    no_matching_credentials, _ = alice.receive_until("extdisco-no-match")
    check(
        "item-not-found" in no_matching_credentials,
        "a non-matching credential selector did not return item-not-found",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='extdisco-bad-port' to='{DOMAIN}'>"
        "<credentials xmlns='urn:xmpp:extdisco:2'>"
        "<service host='turn.example.test' port='not-a-port' type='turn'/></credentials></iq>"
    )
    malformed_credentials, _ = alice.receive_until("extdisco-bad-port")
    check("bad-request" in malformed_credentials, "malformed credential selector was accepted")
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='muc-disco' to='conference.{DOMAIN}'>"
        "<query xmlns='http://jabber.org/protocol/disco#info'/></iq>"
    )
    muc_disco, _ = alice.receive_until("muc-disco")
    check(
        "category='conference'" in muc_disco
        and "http://jabber.org/protocol/muc" in muc_disco,
        "MUC service discovery was incomplete",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='upload-disco' to='upload.{DOMAIN}'>"
        "<query xmlns='http://jabber.org/protocol/disco#info'/></iq>"
    )
    upload_disco, _ = alice.receive_until("upload-disco")
    check(
        "category='store' type='file'" in upload_disco
        and "urn:xmpp:http:upload:0" in upload_disco
        and "26214400" in upload_disco,
        "HTTP Upload discovery was incomplete",
    )
    for upload_id, request, expected_error in [
        (
            "upload-zero",
            "<request xmlns='urn:xmpp:http:upload:0' filename='empty.bin' size='0'/>",
            "bad-request",
        ),
        (
            "upload-unknown-attribute",
            "<request xmlns='urn:xmpp:http:upload:0' filename='cipher.bin' size='1' unexpected='true'/>",
            "bad-request",
        ),
        (
            "upload-purpose-not-advertised",
            "<request xmlns='urn:xmpp:http:upload:0' filename='cipher.bin' size='1'>"
            "<purpose xmlns='urn:xmpp:http:upload:purpose:0'/></request>",
            "feature-not-implemented",
        ),
    ]:
        alice.send(
            f"<iq xmlns='jabber:client' type='get' id='{upload_id}' to='upload.{DOMAIN}'>"
            f"{request}</iq>"
        )
        invalid_upload, _ = alice.receive_until(upload_id)
        check(
            "type='error'" in invalid_upload and expected_error in invalid_upload,
            f"invalid HTTP Upload request {upload_id} was not rejected correctly",
        )
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='upload-too-large' to='upload.{DOMAIN}'>"
        "<request xmlns='urn:xmpp:http:upload:0' filename='large.bin' size='26214401'/></iq>"
    )
    upload_too_large, _ = alice.receive_until("upload-too-large")
    check(
        "type='error'" in upload_too_large
        and "<file-too-large xmlns='urn:xmpp:http:upload:0'>" in upload_too_large
        and "<max-file-size>26214400</max-file-size>" in upload_too_large,
        "oversized HTTP Upload request did not expose the advertised limit",
    )
    upload_body = b"encrypted-upload"
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='upload-slot' to='upload.{DOMAIN}'>"
        f"<request xmlns='urn:xmpp:http:upload:0' filename='cipher.bin' size='{len(upload_body)}' content-type='application/octet-stream'/></iq>"
    )
    upload_slot, _ = alice.receive_until("upload-slot")
    put_match = re.search(r"<put url='([^']+)'>.*?Bearer ([A-Za-z0-9]+)", upload_slot)
    get_match = re.search(r"<get url='([^']+)'", upload_slot)
    check(put_match is not None and get_match is not None, f"invalid HTTP Upload slot: {upload_slot}")
    put_path = re.sub(r"^https?://[^/]+", "", put_match.group(1))
    get_path = re.sub(r"^https?://[^/]+", "", get_match.group(1))
    status, _, _ = raw_http(
        "PUT",
        put_path,
        upload_body,
        {"Authorization": f"Bearer {put_match.group(2)}", "Content-Type": "application/octet-stream"},
    )
    check(status == 201, f"HTTP Upload PUT failed with {status}")
    status, download_headers, downloaded = raw_http("GET", get_path)
    check(
        status == 200
        and downloaded == upload_body
        and download_headers.get("content-type") == "application/octet-stream"
        and download_headers.get("content-disposition") == "attachment"
        and download_headers.get("x-content-type-options") == "nosniff"
        and download_headers.get("content-security-policy")
        == "default-src 'none'; sandbox",
        "HTTP Upload download did not return the reserved ciphertext",
    )
    status, replay_headers, _ = raw_http(
        "PUT",
        put_path,
        upload_body,
        {"Authorization": f"Bearer {put_match.group(2)}", "Content-Type": "application/octet-stream"},
    )
    check(
        status == 201 and replay_headers.get("idempotency-replayed") == "true",
        "byte-identical HTTP Upload retry did not use the bounded replay contract",
    )
    changed_upload_body = bytes([upload_body[0] ^ 1]) + upload_body[1:]
    status, _, _ = raw_http(
        "PUT",
        put_path,
        changed_upload_body,
        {"Authorization": f"Bearer {put_match.group(2)}", "Content-Type": "application/octet-stream"},
    )
    check(status == 409, "HTTP Upload replay accepted different bytes")
    # A completed PUT permits three authenticated, byte-identical retries so a
    # client can recover from lost HTTP responses. The capability is still
    # bounded: a fourth replay must be rejected even when its bytes match.
    for replay_number in (2, 3):
        status, replay_headers, _ = raw_http(
            "PUT",
            put_path,
            upload_body,
            {
                "Authorization": f"Bearer {put_match.group(2)}",
                "Content-Type": "application/octet-stream",
            },
        )
        check(
            status == 201 and replay_headers.get("idempotency-replayed") == "true",
            f"HTTP Upload identical replay {replay_number} was not accepted safely",
        )
    status, _, _ = raw_http(
        "PUT",
        put_path,
        upload_body,
        {"Authorization": f"Bearer {put_match.group(2)}", "Content-Type": "application/octet-stream"},
    )
    check(status == 401, "HTTP Upload replay capability exceeded its fixed maximum")

    # The upload route deliberately overrides the much smaller global API body
    # limit. Exercise the real HTTP stack above 256 KiB so middleware ordering
    # regressions cannot silently break ordinary encrypted attachments.
    route_limit_body = b"northstar-route-limit-probe-" + b"x" * (300 * 1024)
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='upload-route-limit-slot' to='upload.{DOMAIN}'>"
        f"<request xmlns='urn:xmpp:http:upload:0' filename='route-limit.bin' size='{len(route_limit_body)}' content-type='application/octet-stream'/></iq>"
    )
    route_limit_slot, _ = alice.receive_until("upload-route-limit-slot")
    route_limit_put = re.search(
        r"<put url='([^']+)'>.*?Bearer ([A-Za-z0-9]+)", route_limit_slot
    )
    route_limit_get = re.search(r"<get url='([^']+)'", route_limit_slot)
    check(
        route_limit_put is not None and route_limit_get is not None,
        f"invalid route-limit slot: {route_limit_slot}",
    )
    route_limit_put_path = re.sub(r"^https?://[^/]+", "", route_limit_put.group(1))
    route_limit_get_path = re.sub(r"^https?://[^/]+", "", route_limit_get.group(1))
    status, _, _ = raw_http(
        "PUT",
        route_limit_put_path,
        route_limit_body,
        {
            "Authorization": f"Bearer {route_limit_put.group(2)}",
            "Content-Type": "application/octet-stream",
        },
    )
    check(status == 201, f"HTTP Upload route-level body limit failed with {status}")
    status, _, route_limit_download = raw_http("GET", route_limit_get_path)
    check(
        status == 200 and route_limit_download == route_limit_body,
        "HTTP Upload corrupted or rejected a body above the global API limit",
    )

    retry_body = b"retry-after-length-mismatch"
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='upload-retry-slot' to='upload.{DOMAIN}'>"
        f"<request xmlns='urn:xmpp:http:upload:0' filename='retry.bin' size='{len(retry_body)}' content-type='application/octet-stream'/></iq>"
    )
    retry_slot, _ = alice.receive_until("upload-retry-slot")
    retry_put = re.search(r"<put url='([^']+)'>.*?Bearer ([A-Za-z0-9]+)", retry_slot)
    retry_get = re.search(r"<get url='([^']+)'", retry_slot)
    check(retry_put is not None and retry_get is not None, f"invalid retry slot: {retry_slot}")
    retry_put_path = re.sub(r"^https?://[^/]+", "", retry_put.group(1))
    retry_get_path = re.sub(r"^https?://[^/]+", "", retry_get.group(1))
    retry_headers = {
        "Authorization": f"Bearer {retry_put.group(2)}",
        "Content-Type": "application/octet-stream",
    }
    status, _, _ = raw_http("PUT", retry_put_path, b"short", retry_headers)
    check(status == 400, "HTTP Upload accepted a body shorter than the reserved slot")
    status, _, _ = raw_http("PUT", retry_put_path, retry_body, retry_headers)
    check(status == 201, "HTTP Upload did not release a rejected claim for safe retry")
    status, _, retried_download = raw_http("GET", retry_get_path)
    check(
        status == 200 and retried_download == retry_body,
        "retried HTTP Upload was not committed atomically",
    )

    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='roster-set'>"
        f"<query xmlns='jabber:iq:roster'><item jid='{BOB}@{DOMAIN}' name='Bob'/></query></iq>"
    )
    alice.receive_until("roster-set")
    alice.send(
        "<iq xmlns='jabber:client' type='get' id='roster-get'>"
        "<query xmlns='jabber:iq:roster'/></iq>"
    )
    roster, _ = alice.receive_until("roster-get")
    check(f"jid='{BOB}@{DOMAIN}'" in roster, "roster item was not persisted")
    roster_version = re.search(r"<query[^>]*\sver='([^']+)'", roster)
    check(roster_version is not None, "roster version was not returned")
    alice.send(
        "<iq xmlns='jabber:client' type='get' id='roster-unchanged'>"
        f"<query xmlns='jabber:iq:roster' ver='{roster_version.group(1)}'/></iq>"
    )
    unchanged_roster, _ = alice.receive_until("roster-unchanged")
    check(
        "type='result'" in unchanged_roster and "jabber:iq:roster" not in unchanged_roster,
        "unchanged versioned roster did not return an empty result",
    )

    alice.send(
        f"<presence xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='subscribe'/>"
    )
    bob = XmppWebSocket(BOB, PASSWORD, "bob-web")
    subscribe, _ = bob.receive_until("type='subscribe'")
    check(
        f"from='{ALICE}@{DOMAIN}'" in subscribe,
        "offline subscription request was not persisted and delivered",
    )
    bob.send(
        "<iq xmlns='jabber:client' type='get' id='bob-roster-before'>"
        "<query xmlns='jabber:iq:roster'/></iq>"
    )
    bob_roster_before, _ = bob.receive_until("bob-roster-before")
    check(
        f"jid='{ALICE}@{DOMAIN}'" not in bob_roster_before,
        "pending request was incorrectly exposed as an approved roster contact",
    )
    bob.send(
        f"<iq xmlns='jabber:client' type='set' id='bob-roster-accept'>"
        f"<query xmlns='jabber:iq:roster'><item jid='{ALICE}@{DOMAIN}' name='Alice'/></query></iq>"
    )
    bob.receive_until("bob-roster-accept")
    bob.send(
        f"<presence xmlns='jabber:client' to='{ALICE}@{DOMAIN}' type='subscribed'/>"
    )
    _, alice_subscription_frames = alice.receive_until("type='subscribed'")
    if not any("subscription='to'" in frame for frame in alice_subscription_frames):
        _, later_frames = alice.receive_until("subscription='to'")
        alice_subscription_frames.extend(later_frames)
    if not any(
        f"from='{BOB}@{DOMAIN}/bob-web'" in frame and "type='subscribed'" not in frame
        for frame in alice_subscription_frames
    ):
        _, later_frames = alice.receive_until(f"from='{BOB}@{DOMAIN}/bob-web'")
        alice_subscription_frames.extend(later_frames)
    check(
        any("subscription='to'" in frame for frame in alice_subscription_frames),
        "Alice did not receive a roster push with subscription=to",
    )
    check(
        any(
            f"from='{BOB}@{DOMAIN}/bob-web'" in frame and "type='subscribed'" not in frame
            for frame in alice_subscription_frames
        ),
        "Alice did not receive Bob's current availability after approval",
    )
    bob_roster_push, _ = bob.receive_until("subscription='from'")
    check(f"jid='{ALICE}@{DOMAIN}'" in bob_roster_push, "Bob roster direction was not updated")
    alice.send(
        f"<presence xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='subscribe'/>"
    )
    alice.send(
        "<iq xmlns='jabber:client' type='get' id='roster-idempotent-subscribe'>"
        "<query xmlns='jabber:iq:roster'/></iq>"
    )
    alice_idempotent_roster, _ = alice.receive_until("roster-idempotent-subscribe")
    check(
        f"jid='{BOB}@{DOMAIN}'" in alice_idempotent_roster
        and "subscription='to'" in alice_idempotent_roster
        and "ask='subscribe'" not in alice_idempotent_roster,
        "duplicate subscribe recreated a pending request",
    )

    caps_node = "https://northstar.invalid/integration-client"
    caps_verification = "client/pc//Northstar Integration<a-feature<urn:xmpp:receipts<"
    caps_version = base64.b64encode(hashlib.sha1(caps_verification.encode()).digest()).decode()
    bob.send(
        "<presence xmlns='jabber:client'>"
        f"<c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='{caps_node}' ver='{caps_version}'/>"
        "</presence>"
    )
    caps_query, _ = bob.receive_until("node='https://northstar.invalid/integration-client#")
    caps_id = re.search(r"id='([^']+)'", caps_query)
    check(caps_id is not None and "disco#info" in caps_query, "XEP-0115 verification query was not sent")
    bob.send(
        f"<iq xmlns='jabber:client' type='result' id='{caps_id.group(1)}'>"
        f"<query xmlns='http://jabber.org/protocol/disco#info' node='{caps_node}#{caps_version}'>"
        "<identity category='client' type='pc' name='Northstar Integration'/>"
        "<feature var='urn:xmpp:receipts'/><feature var='a-feature'/></query></iq>"
    )
    # Use a same-stream request/result as an ordering barrier.  A query from
    # Alice sent immediately on a different TCP connection can legitimately
    # race ahead of Bob's capability result even though Bob.send() returned.
    bob.send(
        "<iq xmlns='jabber:client' type='get' id='caps-cache-barrier'>"
        "<ping xmlns='urn:xmpp:ping'/></iq>"
    )
    caps_barrier, _ = bob.receive_until("caps-cache-barrier")
    check("type='result'" in caps_barrier, "XEP-0115 cache ordering barrier failed")
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='caps-cache' to='{BOB}@{DOMAIN}/bob-web'>"
        f"<query xmlns='http://jabber.org/protocol/disco#info' node='{caps_node}#{caps_version}'/></iq>"
    )
    cached_caps, _ = alice.receive_until("caps-cache")
    check(
        "Northstar Integration" in cached_caps and "a-feature" in cached_caps,
        f"verified XEP-0115 capabilities were not served from the cache: {cached_caps}",
    )

    # The server routes Jingle signalling; media and file bytes remain
    # end-to-end between clients. Verify delegated initiators and extension-
    # defined application/transport/security payloads over the real wire.
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='jingle-file-init' to='{BOB}@{DOMAIN}/bob-web'>"
        "<jingle xmlns='urn:xmpp:jingle:1' action='session-initiate' "
        f"initiator='controller@{DOMAIN}/call-manager' sid='file-session-1'>"
        "<content creator='initiator' name='file'>"
        "<description xmlns='urn:xmpp:jingle:apps:file-transfer:5'><file>"
        "<name>cipher.bin</name><size>4</size></file></description>"
        "<transport xmlns='urn:xmpp:jingle:transports:s5b:1' sid='stream-1'/>"
        "<security xmlns='urn:xmpp:jingle:security:xtls:0'><method name='x509'/></security>"
        "</content></jingle></iq>"
    )
    jingle_offer, _ = bob.receive_until("jingle-file-init")
    check(
        f"from='{ALICE}@{DOMAIN}/alice-web'" in jingle_offer
        and f"initiator='controller@{DOMAIN}/call-manager'" in jingle_offer
        and "urn:xmpp:jingle:apps:file-transfer:5" in jingle_offer
        and "urn:xmpp:jingle:transports:s5b:1" in jingle_offer
        and "urn:xmpp:jingle:security:xtls:0" in jingle_offer,
        "delegated extension-defined Jingle offer was not routed intact",
    )
    bob.send(
        f"<iq xmlns='jabber:client' type='result' id='jingle-file-init' to='{ALICE}@{DOMAIN}/alice-web'/>"
    )
    jingle_result, _ = alice.receive_until("jingle-file-init")
    check("type='result'" in jingle_result, "Jingle IQ result was not routed to initiator")
    # Alice is subscribed to Bob, but Bob is not subscribed to Alice.  The
    # initial Alice -> Bob request and Bob's IQ result are therefore routable,
    # while a new Bob -> Alice full-JID request must still be denied by the
    # RFC 6121 presence-leak gate.  A directed available presence from Alice
    # then grants Bob access to that exact resource without changing either
    # account's roster subscription.
    bob.send(
        f"<iq xmlns='jabber:client' type='set' id='jingle-file-checksum-denied' to='{ALICE}@{DOMAIN}/alice-web'>"
        "<jingle xmlns='urn:xmpp:jingle:1' action='session-info' sid='file-session-1'>"
        "<checksum xmlns='urn:xmpp:jingle:apps:file-transfer:5' creator='initiator' name='file'>"
        "<file><hash xmlns='urn:xmpp:hashes:2' algo='sha-256'>AA==</hash></file>"
        "</checksum></jingle></iq>"
    )
    denied_checksum, _ = bob.receive_until("jingle-file-checksum-denied")
    check(
        "type='error'" in denied_checksum and "service-unavailable" in denied_checksum,
        f"unauthorized reverse full-JID Jingle IQ leaked Alice's resource: {denied_checksum}",
    )
    alice.send(
        f"<presence xmlns='jabber:client' to='{BOB}@{DOMAIN}/bob-web'>"
        "<show>chat</show><status>jingle-directed-presence</status></presence>"
    )
    directed_presence, _ = bob.receive_until("jingle-directed-presence")
    check(
        f"from='{ALICE}@{DOMAIN}/alice-web'" in directed_presence,
        f"directed-presence Jingle authorization was not delivered: {directed_presence}",
    )
    bob.send(
        f"<iq xmlns='jabber:client' type='set' id='jingle-file-checksum' to='{ALICE}@{DOMAIN}/alice-web'>"
        "<jingle xmlns='urn:xmpp:jingle:1' action='session-info' sid='file-session-1'>"
        "<checksum xmlns='urn:xmpp:jingle:apps:file-transfer:5' creator='initiator' name='file'>"
        "<file><hash xmlns='urn:xmpp:hashes:2' algo='sha-256'>AA==</hash></file>"
        "</checksum></jingle></iq>"
    )
    jingle_checksum, _ = alice.receive_until("jingle-file-checksum")
    check(
        "urn:xmpp:jingle:apps:file-transfer:5" in jingle_checksum
        and "urn:xmpp:hashes:2" in jingle_checksum,
        "Jingle file-transfer session-info was not routed intact",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='result' id='jingle-file-checksum' to='{BOB}@{DOMAIN}/bob-web'/>"
    )
    bob.receive_until("jingle-file-checksum")

    # XEP-0166/0167/0176/0320: malformed server-visible call signalling is
    # rejected before delivery, while valid RTP/ICE/DTLS is routed unchanged
    # to the exact resource. Candidate addresses remain opaque; the server
    # must never connect to a client-asserted ICE address.
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='jingle-ice-missing-credentials' to='{BOB}@{DOMAIN}/bob-web'>"
        "<jingle xmlns='urn:xmpp:jingle:1' action='session-initiate' sid='call-ice-invalid'>"
        "<content creator='initiator' name='audio'>"
        "<description xmlns='urn:xmpp:jingle:apps:rtp:1' media='audio'><payload-type id='111' name='opus'/></description>"
        "<transport xmlns='urn:xmpp:jingle:transports:ice-udp:1'>"
        "<candidate component='1' foundation='1' generation='0' id='candidate-1' ip='127.0.0.1' port='50000' priority='1' protocol='udp' type='host'/>"
        "</transport></content></jingle></iq>"
    )
    invalid_ice, _ = alice.receive_until("jingle-ice-missing-credentials")
    check(
        "type='error'" in invalid_ice and "bad-request" in invalid_ice,
        f"ICE candidates without pwd/ufrag were accepted: {invalid_ice}",
    )

    call_fingerprint = ":".join(["AA"] * 32)
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='jingle-rtp-init' to='{BOB}@{DOMAIN}/bob-web'>"
        "<jingle xmlns='urn:xmpp:jingle:1' action='session-initiate' sid='call-rtp-1'>"
        "<content creator='initiator' name='audio'>"
        "<description xmlns='urn:xmpp:jingle:apps:rtp:1' media='audio'>"
        "<payload-type id='111' name='opus' clockrate='48000' channels='2'>"
        "<parameter name='minptime' value='10'/></payload-type><rtcp-mux/></description>"
        "<transport xmlns='urn:xmpp:jingle:transports:ice-udp:1' pwd='opaque-secret' ufrag='opaque-user'>"
        f"<fingerprint xmlns='urn:xmpp:jingle:apps:dtls:0' hash='sha-256' setup='actpass'>{call_fingerprint}</fingerprint>"
        "<candidate component='1' foundation='1' generation='0' id='candidate-1' ip='127.0.0.1' port='50000' priority='2130706431' protocol='udp' type='host'/>"
        "</transport></content></jingle></iq>"
    )
    call_offer, call_frames = bob.receive_until("jingle-rtp-init")
    check(
        "urn:xmpp:jingle:apps:rtp:1" in call_offer
        and "urn:xmpp:jingle:transports:ice-udp:1" in call_offer
        and "urn:xmpp:jingle:apps:dtls:0" in call_offer
        and "ip='127.0.0.1'" in call_offer
        and f"from='{ALICE}@{DOMAIN}/alice-web'" in call_offer
        and "jingle-ice-missing-credentials" not in "".join(call_frames),
        f"valid exact-resource RTP/ICE/DTLS offer was altered or invalid offer leaked: {call_offer}",
    )
    # Session state and XEP-0166 unknown-session/out-of-order decisions belong
    # to the receiving Jingle endpoint. The routing server must preserve the
    # endpoint's application error rather than treating its copied <jingle/>
    # payload as a new IQ-set request.
    bob.send(
        f"<iq xmlns='jabber:client' type='error' id='jingle-rtp-init' to='{ALICE}@{DOMAIN}/alice-web'>"
        "<jingle xmlns='urn:xmpp:jingle:1' action='session-initiate' sid='call-rtp-1'/>"
        "<error type='cancel'><item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
        "<unknown-session xmlns='urn:xmpp:jingle:errors:1'/></error></iq>"
    )
    call_error, _ = alice.receive_until("jingle-rtp-init")
    check(
        "type='error'" in call_error
        and "urn:xmpp:jingle:errors:1" in call_error
        and "unknown-session" in call_error
        and f"from='{BOB}@{DOMAIN}/bob-web'" in call_error,
        f"endpoint-owned Jingle error was not correlated and routed intact: {call_error}",
    )

    bob.send(
        f"<iq xmlns='jabber:client' type='set' id='jingle-reason-any-action' to='{ALICE}@{DOMAIN}/alice-web'>"
        "<jingle xmlns='urn:xmpp:jingle:1' action='transport-info' sid='call-rtp-1'>"
        "<content creator='initiator' name='audio'><transport xmlns='urn:xmpp:jingle:transports:ice-udp:1'/></content>"
        "<reason><connectivity-error/><text>no pair</text><ice-failure xmlns='urn:example:ice-detail'/></reason>"
        "</jingle></iq>"
    )
    reason_update, _ = alice.receive_until("jingle-reason-any-action")
    check(
        "connectivity-error" in reason_update and "urn:example:ice-detail" in reason_update,
        f"XEP-0166 reason on a non-termination action was not routed: {reason_update}",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='result' id='jingle-reason-any-action' to='{BOB}@{DOMAIN}/bob-web'/>"
    )
    bob.receive_until("jingle-reason-any-action")
    assert_api_session(bob_token, BOB, "after-jingle")

    alice.send(
        "<iq xmlns='jabber:client' type='get' id='roster-catchup'>"
        f"<query xmlns='jabber:iq:roster' ver='{roster_version.group(1)}'/></iq>"
    )
    catchup_result, _ = alice.receive_until("roster-catchup")
    check(
        "type='result'" in catchup_result and "jabber:iq:roster" not in catchup_result,
        "versioned roster catch-up did not begin with an empty IQ result",
    )
    catchup_push, _ = alice.receive_until(f"jid='{BOB}@{DOMAIN}'")
    check(
        "type='set'" in catchup_push
        and "subscription='to'" in catchup_push
        and " ver='" in catchup_push,
        "roster journal did not return the contact's final changed state",
    )

    alice.send("<inactive xmlns='urn:xmpp:csi:0'/>")
    alice.send(
        "<iq xmlns='jabber:client' type='get' id='csi-inactive-barrier'>"
        "<ping xmlns='urn:xmpp:ping'/></iq>"
    )
    alice.receive_until("csi-inactive-barrier")
    bob.send("<presence xmlns='jabber:client'><show>away</show><status>CSI-PRESENCE</status></presence>")
    bob.send(
        f"<message xmlns='jabber:client' to='{ALICE}@{DOMAIN}' type='chat' id='CSI-STATE'>"
        "<composing xmlns='http://jabber.org/protocol/chatstates'/>"
        "<no-store xmlns='urn:xmpp:hints'/></message>"
    )
    bob.send(
        f"<message xmlns='jabber:client' to='{ALICE}@{DOMAIN}' type='chat'>"
        "<received xmlns='urn:xmpp:receipts' id='CSI-IMPORTANT'/></message>"
    )
    important, important_frames = alice.receive_until("CSI-IMPORTANT")
    check(
        "urn:xmpp:receipts" in important
        and not any("CSI-PRESENCE" in frame or "CSI-STATE" in frame for frame in important_frames),
        f"inactive CSI delayed an important receipt or leaked deferred updates: {important_frames}",
    )
    alice.send_with_pow(
        f"<message xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='chat' id='receipt-request'>"
        "<body>receipt integration</body><request xmlns='urn:xmpp:receipts'/></message>",
        alice_token,
    )
    requested, _ = bob.receive_until("receipt-request")
    check("urn:xmpp:receipts" in requested, "XEP-0184 request was not routed")
    bob.send(
        f"<message xmlns='jabber:client' to='{ALICE}@{DOMAIN}' type='chat'>"
        "<received xmlns='urn:xmpp:receipts' id='receipt-request'/></message>"
    )
    receipt, _ = alice.receive_until("id='receipt-request'")
    check("<received xmlns='urn:xmpp:receipts'" in receipt, "XEP-0184 receipt was not routed")
    alice.send(
        f"<message xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='chat'>"
        "<request xmlns='urn:xmpp:receipts'/></message>"
    )
    invalid_receipt, _ = alice.receive_until("bad-request")
    check("type='error'" in invalid_receipt, "receipt request without a stanza id was accepted")

    # XEP-0449 v0.2.0: the server validates and routes the visible sticker
    # marker together with its single XEP-0447 share, without rendering it.
    alice.send_with_pow(
        f"<message xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='chat' id='sticker-valid'>"
        "<body>🙂</body><sticker xmlns='urn:xmpp:stickers:0' pack='integration-pack'/>"
        "<file-sharing xmlns='urn:xmpp:sfs:0'>"
        "<file xmlns='urn:xmpp:file:metadata:0'><media-type>image/png</media-type>"
        "<desc>🙂</desc><size>1</size></file>"
        "<sources><url-data xmlns='http://jabber.org/protocol/url-data' "
        "target='https://files.example.test/sticker.png'/></sources>"
        "</file-sharing></message>",
        alice_token,
    )
    sticker, _ = bob.receive_until("sticker-valid")
    check(
        "urn:xmpp:stickers:0" in sticker and "urn:xmpp:sfs:0" in sticker,
        f"XEP-0449 sticker payload was not routed intact: {sticker}",
    )

    # XEP-0434 v0.6.0: only plaintext/server-visible structure is validated.
    # Endpoint signature/ATM policy and encrypted SCE content remain opaque.
    trust_key = base64.b64encode(hashlib.sha256(b"integration-trust-key").digest()).decode()
    alice.send_with_pow(
        f"<message xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='chat' id='trust-message-valid'>"
        "<store xmlns='urn:xmpp:hints'/><trust-message xmlns='urn:xmpp:tm:1' "
        "usage='urn:xmpp:atm:1' encryption='urn:xmpp:omemo:2'>"
        f"<key-owner jid='{BOB}@{DOMAIN}'><trust>{trust_key}</trust></key-owner>"
        "</trust-message></message>",
        alice_token,
    )
    trust_message, _ = bob.receive_until("trust-message-valid")
    check(
        "urn:xmpp:tm:1" in trust_message
        and "urn:xmpp:atm:1" in trust_message
        and trust_key in trust_message,
        f"XEP-0434 trust message was not routed intact: {trust_message}",
    )

    rejected_modern_ids = ["sticker-invalid", "trust-message-invalid"]
    alice.send(
        f"<message xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='chat' id='sticker-invalid'>"
        "<sticker xmlns='urn:xmpp:stickers:0'/></message>"
    )
    sticker_error, _ = alice.receive_until("sticker-invalid")
    check(
        "type='error'" in sticker_error and "bad-request" in sticker_error,
        f"standalone XEP-0449 marker was not rejected: {sticker_error}",
    )
    alice.send(
        f"<message xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='chat' id='trust-message-invalid'>"
        "<trust-message xmlns='urn:xmpp:tm:1' usage='urn:xmpp:atm:1' "
        "encryption='urn:xmpp:omemo:2'>"
        f"<key-owner jid='{BOB}@{DOMAIN}/forbidden-resource'><trust>not-base64!</trust></key-owner>"
        "</trust-message></message>"
    )
    trust_error, _ = alice.receive_until("trust-message-invalid")
    check(
        "type='error'" in trust_error and "jid-malformed" in trust_error,
        f"malformed XEP-0434 trust message was not rejected: {trust_error}",
    )
    invalid_delivery_deadline = time.time() + 0.5
    while time.time() < invalid_delivery_deadline:
        try:
            unexpected = bob.receive(max(0.05, invalid_delivery_deadline - time.time()))
        except TimeoutError:
            break
        check(
            not any(message_id in unexpected for message_id in rejected_modern_ids),
            f"invalid modern message payload was forwarded: {unexpected}",
        )
    alice.send("<active xmlns='urn:xmpp:csi:0'/>")
    _, csi_frames = alice.receive_until("CSI-STATE")
    check(
        any("CSI-PRESENCE" in frame for frame in csi_frames)
        and any("CSI-STATE" in frame for frame in csi_frames),
        "active CSI did not flush coalesced presence and chat-state updates",
    )
    assert_api_session(bob_token, BOB, "after-csi")

    pubsub_service = f"pubsub.{DOMAIN}"
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='pubsub-disco' to='{pubsub_service}'>"
        "<query xmlns='http://jabber.org/protocol/disco#info'/></iq>"
    )
    pubsub_disco, _ = alice.receive_until("pubsub-disco")
    check(
        "category='pubsub' type='service'" in pubsub_disco
        and "pubsub#publish" in pubsub_disco
        and "pubsub#subscribe" in pubsub_disco
        and "pubsub#config-node" in pubsub_disco
        and "pubsub#modify-affiliations" in pubsub_disco
        and "pubsub#access-authorize" in pubsub_disco,
        "generic PubSub service discovery was incomplete",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='pubsub-managed-create' to='{pubsub_service}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><create node='integration/managed'/>"
        "<configure><x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#node_config</value></field>"
        "<field var='pubsub#title'><value>Managed integration feed</value></field>"
        "<field var='pubsub#access_model'><value>authorize</value></field>"
        "<field var='pubsub#max_items'><value>2</value></field>"
        "<field var='pubsub#type'><value>urn:test</value></field>"
        "</x></configure></pubsub></iq>"
    )
    managed_create, _ = alice.receive_until("pubsub-managed-create")
    check("type='result'" in managed_create, "create-and-configure failed")
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='pubsub-config-get' to='{pubsub_service}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub#owner'>"
        "<configure node='integration/managed'/></pubsub></iq>"
    )
    managed_config, _ = alice.receive_until("pubsub-config-get")
    check(
        "Managed integration feed" in managed_config
        and "authorize" in managed_config
        and "<value>2</value>" in managed_config,
        "node configuration retrieval did not round-trip",
    )
    bob.send(
        f"<iq xmlns='jabber:client' type='set' id='pubsub-pending' to='{pubsub_service}'>"
        f"<pubsub xmlns='http://jabber.org/protocol/pubsub'><subscribe node='integration/managed' jid='{BOB}@{DOMAIN}'/></pubsub></iq>"
    )
    pending, _ = bob.receive_until("pubsub-pending")
    check("subscription='pending'" in pending, "authorize node did not create a pending subscription")
    authorization, _ = alice.receive_until("pubsub#subscribe_authorization")
    check(
        "integration/managed" in authorization and f"{BOB}@{DOMAIN}" in authorization,
        "node owner did not receive the subscription authorization form",
    )
    alice.send(
        f"<message xmlns='jabber:client' to='{pubsub_service}'>"
        "<x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#subscribe_authorization</value></field>"
        "<field var='pubsub#node'><value>integration/managed</value></field>"
        f"<field var='pubsub#subscriber_jid'><value>{BOB}@{DOMAIN}</value></field>"
        "<field var='pubsub#allow'><value>true</value></field>"
        "</x></message>"
    )
    approved, _ = bob.receive_until("subscription='subscribed'")
    check("integration/managed" in approved, "approved PubSub subscription was not announced")
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='pubsub-affiliation-set' to='{pubsub_service}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub#owner'>"
        f"<affiliations node='integration/managed'><affiliation jid='{BOB}@{DOMAIN}' affiliation='publisher'/></affiliations>"
        "</pubsub></iq>"
    )
    affiliation_set, _ = alice.receive_until("pubsub-affiliation-set")
    check("type='result'" in affiliation_set, "owner affiliation update failed")
    bob.receive_until("affiliation='publisher'")
    bob.send(
        f"<iq xmlns='jabber:client' type='set' id='pubsub-publisher-write' to='{pubsub_service}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='integration/managed'>"
        "<item id='managed-1'><value xmlns='urn:test'>one</value></item>"
        "<item id='managed-2'><value xmlns='urn:test'>two</value></item>"
        "</publish></pubsub></iq>"
    )
    publisher_write, _ = bob.receive_until("pubsub-publisher-write")
    check(
        "type='result'" in publisher_write,
        f"publisher affiliation could not publish: {publisher_write}",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='pubsub-managed-items' to='{pubsub_service}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='integration/managed'/></pubsub></iq>"
    )
    managed_items, _ = alice.receive_until("pubsub-managed-items")
    check(
        "managed-2" in managed_items and "managed-1" in managed_items,
        "configured max_items storage failed",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='pubsub-owner-lists' to='{pubsub_service}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub#owner'>"
        "<subscriptions node='integration/managed'/></pubsub></iq>"
    )
    owner_subscriptions, _ = alice.receive_until("pubsub-owner-lists")
    check(
        f"jid='{BOB}@{DOMAIN}'" in owner_subscriptions and "subscription='subscribed'" in owner_subscriptions,
        "owner subscription retrieval failed",
    )
    bob.send(
        f"<iq xmlns='jabber:client' type='get' id='pubsub-own-affiliations' to='{pubsub_service}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><affiliations/></pubsub></iq>"
    )
    own_affiliations, _ = bob.receive_until("pubsub-own-affiliations")
    check(
        "integration/managed" in own_affiliations and "affiliation='publisher'" in own_affiliations,
        "entity affiliation retrieval failed",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='pubsub-node-disco' to='{pubsub_service}'>"
        "<query xmlns='http://jabber.org/protocol/disco#info' node='integration/managed'/></iq>"
    )
    node_disco, _ = alice.receive_until("pubsub-node-disco")
    check(
        "Managed integration feed" in node_disco and "pubsub#meta-data" in node_disco,
        "PubSub node metadata discovery failed",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='pubsub-node-items-disco' to='{pubsub_service}'>"
        "<query xmlns='http://jabber.org/protocol/disco#items' node='integration/managed'/></iq>"
    )
    node_items_disco, _ = alice.receive_until("pubsub-node-items-disco")
    check(
        "managed-1" in node_items_disco and "managed-2" in node_items_disco,
        "PubSub item discovery failed",
    )
    bob.send(
        f"<iq xmlns='jabber:client' type='set' id='pubsub-batch-too-large' to='{pubsub_service}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='integration/managed'>"
        "<item id='batch-1'><value xmlns='urn:test'>one</value></item>"
        "<item id='batch-2'><value xmlns='urn:test'>two</value></item>"
        "<item id='batch-3'><value xmlns='urn:test'>three</value></item>"
        "</publish></pubsub></iq>"
    )
    batch_too_large, _ = bob.receive_until("pubsub-batch-too-large")
    check(
        "type='error'" in batch_too_large
        and "not-allowed" in batch_too_large
        and "max-items-exceeded" in batch_too_large,
        f"oversized PubSub batch did not fail atomically: {batch_too_large}",
    )
    bob.send(
        f"<iq xmlns='jabber:client' type='set' id='pubsub-invalid-payload' to='{pubsub_service}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='integration/managed'>"
        "<item id='wrong-type'><value xmlns='urn:wrong'>wrong</value></item>"
        "</publish></pubsub></iq>"
    )
    invalid_payload, _ = bob.receive_until("pubsub-invalid-payload")
    check(
        "type='error'" in invalid_payload and "invalid-payload" in invalid_payload,
        f"configured PubSub payload namespace was not enforced: {invalid_payload}",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='pubsub-owner-overwrite' to='{pubsub_service}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='integration/managed'>"
        "<item id='managed-2'><value xmlns='urn:test'>owner replacement</value></item>"
        "</publish></pubsub></iq>"
    )
    owner_overwrite, _ = alice.receive_until("pubsub-owner-overwrite")
    check("type='result'" in owner_overwrite, "authorized ItemID overwrite was rejected")
    bob.send(
        f"<iq xmlns='jabber:client' type='set' id='pubsub-wrong-publisher-retract' to='{pubsub_service}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><retract node='integration/managed'>"
        "<item id='managed-2'/></retract></pubsub></iq>"
    )
    wrong_retract, _ = bob.receive_until("pubsub-wrong-publisher-retract")
    check(
        "type='error'" in wrong_retract and "forbidden" in wrong_retract,
        f"item-level PubSub retract authorization was not enforced: {wrong_retract}",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='pubsub-managed-delete' to='{pubsub_service}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub#owner'><delete node='integration/managed'/></pubsub></iq>"
    )
    alice.receive_until("pubsub-managed-delete")
    managed_deleted_event, _ = bob.receive_until("<delete ")
    check(
        "integration/managed" in managed_deleted_event,
        f"managed PubSub deletion event was not delivered: {managed_deleted_event}",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='pubsub-create' to='{pubsub_service}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><create node='integration/news'/></pubsub></iq>"
    )
    created_node, _ = alice.receive_until("pubsub-create")
    check("type='result'" in created_node, "generic PubSub node creation failed")
    bob.send(
        f"<iq xmlns='jabber:client' type='set' id='pubsub-subscribe' to='{pubsub_service}'>"
        f"<pubsub xmlns='http://jabber.org/protocol/pubsub'><subscribe node='integration/news' jid='{BOB}@{DOMAIN}'/></pubsub></iq>"
    )
    subscribed, _ = bob.receive_until("pubsub-subscribe")
    check("subscription='subscribed'" in subscribed, "generic PubSub subscription failed")
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='pubsub-publish' to='{pubsub_service}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub' xmlns:p='urn:integration:payload'>"
        "<publish node='integration/news'><item><p:value p:kind='test'>namespaced payload</p:value></item></publish>"
        "</pubsub></iq>"
    )
    published, _ = alice.receive_until("pubsub-publish")
    published_id = re.search(r"<publish[^>]*node='integration/news'.*?<item id='([^']+)'", published)
    check(published_id is not None, "generated PubSub item ID was not returned")
    event, _ = bob.receive_until("namespaced payload")
    check(
        "urn:integration:payload" in event and "subscription" not in event,
        "generic PubSub event lost its inherited payload namespace",
    )
    bob.send(
        f"<iq xmlns='jabber:client' type='get' id='pubsub-items' to='{pubsub_service}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='integration/news'/></pubsub></iq>"
    )
    retrieved, _ = bob.receive_until("pubsub-items")
    check(
        "namespaced payload" in retrieved and "urn:integration:payload" in retrieved,
        "generic PubSub item retrieval failed",
    )
    bob.send(
        f"<iq xmlns='jabber:client' type='set' id='pubsub-forbidden' to='{pubsub_service}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='integration/news'><item id='attack'><value xmlns='urn:test'/></item></publish></pubsub></iq>"
    )
    forbidden_publish, _ = bob.receive_until("pubsub-forbidden")
    check(
        "type='error'" in forbidden_publish and "forbidden" in forbidden_publish,
        "non-publisher could publish to a publishers-only PubSub node",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='pubsub-retract' to='{pubsub_service}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><retract node='integration/news'>"
        f"<item id='{published_id.group(1)}'/></retract></pubsub></iq>"
    )
    alice.receive_until("pubsub-retract")
    retracted_event, _ = bob.receive_until("<retract ")
    check(published_id.group(1) in retracted_event, "PubSub retraction event was not delivered")
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='pubsub-delete' to='{pubsub_service}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub#owner'><delete node='integration/news'/></pubsub></iq>"
    )
    alice.receive_until("pubsub-delete")
    deleted_event, _ = bob.receive_until("<delete ")
    check("integration/news" in deleted_event, "PubSub deletion event was not delivered")

    for index in range(2):
        request_id = f"pubsub-quota-create-{index}"
        alice.send(
            f"<iq xmlns='jabber:client' type='set' id='{request_id}' to='{pubsub_service}'>"
            f"<pubsub xmlns='http://jabber.org/protocol/pubsub'><create node='integration/quota-{index}'/></pubsub></iq>"
        )
        created, _ = alice.receive_until(request_id)
        check("type='result'" in created, f"PubSub quota setup failed: {created}")
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='pubsub-quota-exceeded' to='{pubsub_service}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><create node='integration/quota-overflow'/></pubsub></iq>"
    )
    quota_exceeded, _ = alice.receive_until("pubsub-quota-exceeded")
    check(
        "type='error'" in quota_exceeded and "resource-constraint" in quota_exceeded,
        f"PubSub owner node quota was not enforced: {quota_exceeded}",
    )
    for index in range(2):
        request_id = f"pubsub-quota-delete-{index}"
        alice.send(
            f"<iq xmlns='jabber:client' type='set' id='{request_id}' to='{pubsub_service}'>"
            "<pubsub xmlns='http://jabber.org/protocol/pubsub#owner'>"
            f"<delete node='integration/quota-{index}'/></pubsub></iq>"
        )
        alice.receive_until(request_id)
    assert_api_session(bob_token, BOB, "after-generic-pubsub")

    alice.close()
    alice = XmppWebSocket(ALICE, PASSWORD, "alice-reconnected")
    bob_presence, _ = alice.receive_until(f"from='{BOB}@{DOMAIN}/bob-web'")
    check("type='unavailable'" not in bob_presence, "initial presence did not restore Bob's online state")

    alice.send(
        "<iq xmlns='jabber:client' type='get' id='mam-prefs'>"
        "<prefs xmlns='urn:xmpp:mam:2'/></iq>"
    )
    prefs, _ = alice.receive_until("mam-prefs")
    check("default='always'" in prefs, "MAM archive preferences were not returned")

    alice.send(
        "<iq xmlns='jabber:client' type='set' id='pep-publish'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        "<publish node='urn:xmpp:omemo:2:devices'><item id='current'>"
        "<devices xmlns='urn:xmpp:omemo:2'><device id='12345'/></devices>"
        "</item></publish></pubsub></iq>"
    )
    alice.receive_until("pep-publish")
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='disco-pep-node' to='{ALICE}@{DOMAIN}'>"
        "<query xmlns='http://jabber.org/protocol/disco#info'/></iq>"
    )
    pep_node_disco, _ = alice.receive_until("disco-pep-node")
    check(
        "http://jabber.org/protocol/pubsub#pep" in pep_node_disco
        and "http://jabber.org/protocol/disco#items" in pep_node_disco
        and "urn:xmpp:omemo:2:devices" not in pep_node_disco
        and "+notify" not in pep_node_disco,
        f"account disco#info crossed the PEP service/capability boundary: {pep_node_disco}",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='disco-pep-items' to='{ALICE}@{DOMAIN}'>"
        "<query xmlns='http://jabber.org/protocol/disco#items'/></iq>"
    )
    pep_node_items, _ = alice.receive_until("disco-pep-items")
    check(
        "<item" in pep_node_items
        and f"jid='{ALICE}@{DOMAIN}'" in pep_node_items
        and "node='urn:xmpp:omemo:2:devices'" in pep_node_items,
        f"published OMEMO device node was absent from account disco#items: {pep_node_items}",
    )
    bob.send(
        f"<iq xmlns='jabber:client' type='get' id='pep-get' to='{ALICE}@{DOMAIN}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        "<items node='urn:xmpp:omemo:2:devices'/></pubsub></iq>"
    )
    pep, _ = bob.receive_until("pep-get")
    check("device id='12345'" in pep, "OMEMO PEP item retrieval failed")

    bundle = omemo2_bundle()
    alice.send(
        "<iq xmlns='jabber:client' type='set' id='pep-bundle-batch'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        "<publish node='urn:xmpp:omemo:2:bundles'>"
        f"<item id='111'>{bundle}</item><item id='222'>{bundle}</item>"
        "</publish><publish-options><x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#publish-options</value></field>"
        "<field var='pubsub#access_model'><value>open</value></field>"
        "<field var='pubsub#max_items'><value>max</value></field>"
        "</x></publish-options></pubsub></iq>"
    )
    bundle_result, _ = alice.receive_until("pep-bundle-batch")
    check("type='result'" in bundle_result, "atomic OMEMO bundle batch publish failed")
    bob.send(
        f"<iq xmlns='jabber:client' type='get' id='pep-bundle-get' to='{ALICE}@{DOMAIN}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        "<items node='urn:xmpp:omemo:2:bundles'/></pubsub></iq>"
    )
    bundles, _ = bob.receive_until("pep-bundle-get")
    check("id='111'" in bundles and "id='222'" in bundles, "OMEMO multi-device bundles were not retained")
    alice.send(
        "<iq xmlns='jabber:client' type='set' id='pep-bundle-retract'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        "<retract node='urn:xmpp:omemo:2:bundles' notify='true'><item id='111'/></retract>"
        "</pubsub></iq>"
    )
    retract_result, _ = alice.receive_until("pep-bundle-retract")
    check("type='result'" in retract_result, "OMEMO bundle retraction failed")
    bob.send(
        f"<iq xmlns='jabber:client' type='get' id='pep-retracted-get' to='{ALICE}@{DOMAIN}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        "<items node='urn:xmpp:omemo:2:bundles'><item id='111'/></items>"
        "</pubsub></iq>"
    )
    retracted, _ = bob.receive_until("pep-retracted-get")
    check("type='error'" in retracted and "item-not-found" in retracted, "retracted bundle remained retrievable")

    alice.send(
        "<iq xmlns='jabber:client' type='set' id='pep-atomic-invalid'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='urn:northstar:test:atomic'>"
        "<item id='would-be-written'><value xmlns='urn:northstar:test'/></item>"
        "<item id='invalid'><one xmlns='urn:northstar:test'/><two xmlns='urn:northstar:test'/></item>"
        "</publish></pubsub></iq>"
    )
    invalid_batch, _ = alice.receive_until("pep-atomic-invalid")
    check("type='error'" in invalid_batch and "invalid-payload" in invalid_batch, "invalid PEP batch was accepted")
    alice.send(
        "<iq xmlns='jabber:client' type='get' id='pep-atomic-check'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        "<items node='urn:northstar:test:atomic'><item id='would-be-written'/></items>"
        "</pubsub></iq>"
    )
    atomic_check, _ = alice.receive_until("pep-atomic-check")
    check("type='error'" in atomic_check and "item-not-found" in atomic_check, "invalid PEP batch was partially committed")

    alice.send(
        "<iq xmlns='jabber:client' type='set' id='pep-presence-publish'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        "<publish node='urn:northstar:test:presence'><item id='current'>"
        "<value xmlns='urn:northstar:test'>private-metadata</value>"
        "</item></publish></pubsub></iq>"
    )
    alice.receive_until("pep-presence-publish")
    admin_xmpp = XmppWebSocket(ADMIN, ADMIN_PASSWORD, "admin-pep-access")
    admin_xmpp.send(
        f"<iq xmlns='jabber:client' type='get' id='pep-presence-denied' to='{ALICE}@{DOMAIN}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        "<items node='urn:northstar:test:presence'/></pubsub></iq>"
    )
    presence_denied, _ = admin_xmpp.receive_until("pep-presence-denied")
    check(
        "type='error'" in presence_denied
        and "presence-subscription-required" in presence_denied,
        "presence-scoped PEP node was exposed to a non-contact",
    )
    assert_api_session(bob_token, BOB, "after-pep-access")

    # Make the publishing resource explicitly interested in XEP-0084 metadata
    # before the vCard mutation. This lets the test capture the notification
    # caused by the vCard commit itself instead of manufacturing a duplicate
    # metadata publication afterwards.
    avatar_caps_node = "https://northstar.invalid/integration-avatar-client"
    avatar_caps_verification = (
        "client/pc//Northstar Avatar Integration<"
        "urn:xmpp:avatar:metadata+notify<"
    )
    avatar_caps_version = base64.b64encode(
        hashlib.sha1(avatar_caps_verification.encode()).digest()
    ).decode()
    alice.send(
        "<presence xmlns='jabber:client'>"
        f"<c xmlns='http://jabber.org/protocol/caps' hash='sha-1' "
        f"node='{avatar_caps_node}' ver='{avatar_caps_version}'/>"
        "</presence>"
    )
    avatar_caps_query, _ = alice.receive_until(
        "node='https://northstar.invalid/integration-avatar-client#"
    )
    avatar_caps_id = re.search(r"id='([^']+)'", avatar_caps_query)
    check(
        avatar_caps_id is not None and "disco#info" in avatar_caps_query,
        f"XEP-0084 notification capability query was not sent: {avatar_caps_query}",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='result' id='{avatar_caps_id.group(1)}'>"
        f"<query xmlns='http://jabber.org/protocol/disco#info' "
        f"node='{avatar_caps_node}#{avatar_caps_version}'>"
        "<identity category='client' type='pc' name='Northstar Avatar Integration'/>"
        "<feature var='urn:xmpp:avatar:metadata+notify'/></query></iq>"
    )
    alice.send(
        "<iq xmlns='jabber:client' type='get' id='avatar-caps-barrier'>"
        "<ping xmlns='urn:xmpp:ping'/></iq>"
    )
    avatar_caps_barrier, _ = alice.receive_until("avatar-caps-barrier")
    check(
        "type='result'" in avatar_caps_barrier,
        f"XEP-0084 capability ordering barrier failed: {avatar_caps_barrier}",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='avatar-caps-cache' "
        f"to='{ALICE}@{DOMAIN}/alice-reconnected'>"
        f"<query xmlns='http://jabber.org/protocol/disco#info' "
        f"node='{avatar_caps_node}#{avatar_caps_version}'/></iq>"
    )
    avatar_caps_cache, _ = alice.receive_until("avatar-caps-cache")
    check(
        "type='result'" in avatar_caps_cache
        and "Northstar Avatar Integration" in avatar_caps_cache
        and "urn:xmpp:avatar:metadata+notify" in avatar_caps_cache,
        "verified XEP-0084 capability was not mapped to Alice's exact resource: "
        f"{avatar_caps_cache}",
    )

    avatar_png = png_1x1_rgba(31, 111, 235)
    avatar_b64 = base64.b64encode(avatar_png).decode()
    avatar_sha1 = hashlib.sha1(avatar_png).hexdigest()
    avatar_size = len(avatar_png)
    alice.send(
        "<iq xmlns='jabber:client' type='set' id='vcard-set'>"
        "<vCard xmlns='vcard-temp'><FN>Alice Integration</FN><PHOTO>"
        f"<TYPE>image/png</TYPE><BINVAL>{avatar_b64}</BINVAL>"
        "</PHOTO></vCard></iq>"
    )
    vcard_set, vcard_set_frames = alice.receive_until("vcard-set")
    check("type='result'" in vcard_set, f"vCard update failed: {vcard_set}")
    avatar_events = "".join(vcard_set_frames)
    if "urn:xmpp:avatar:metadata" not in avatar_events:
        _, later_avatar_frames = alice.receive_until("urn:xmpp:avatar:metadata")
        vcard_set_frames.extend(later_avatar_frames)
        avatar_events = "".join(vcard_set_frames)
    check(
        "urn:xmpp:avatar:metadata" in avatar_events
        and avatar_sha1 in avatar_events
        and f"bytes='{avatar_size}'" in avatar_events
        and "type='image/png'" in avatar_events,
        "vCard commit did not fan out its generated XEP-0084 metadata event: "
        f"frames={vcard_set_frames}",
    )
    bob.send(
        f"<iq xmlns='jabber:client' type='get' id='vcard-get' to='{ALICE}@{DOMAIN}'>"
        "<vCard xmlns='vcard-temp'/></iq>"
    )
    vcard_get, _ = bob.receive_until("vcard-get")
    check(
        "Alice Integration" in vcard_get
        and f"<BINVAL>{avatar_b64}</BINVAL>" in vcard_get,
        f"vCard retrieval did not return the stored avatar: {vcard_get}",
    )
    alice.send(
        "<iq xmlns='jabber:client' type='get' id='avatar-data-get'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        f"<items node='urn:xmpp:avatar:data'><item id='{avatar_sha1}'/></items>"
        "</pubsub></iq>"
    )
    avatar_data_get, _ = alice.receive_until("avatar-data-get")
    check(
        "type='result'" in avatar_data_get
        and f"id='{avatar_sha1}'" in avatar_data_get
        and f"<data xmlns='urn:xmpp:avatar:data'>{avatar_b64}</data>"
        in avatar_data_get,
        f"vCard write did not generate the matching XEP-0084 data item: {avatar_data_get}",
    )
    alice.send(
        "<iq xmlns='jabber:client' type='get' id='avatar-metadata-get'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        "<items node='urn:xmpp:avatar:metadata'/></pubsub></iq>"
    )
    avatar_metadata_get, _ = alice.receive_until("avatar-metadata-get")
    check(
        "type='result'" in avatar_metadata_get
        and f"id='{avatar_sha1}'" in avatar_metadata_get
        and f"bytes='{avatar_size}'" in avatar_metadata_get
        and "type='image/png'" in avatar_metadata_get,
        "vCard write did not generate matching XEP-0084 metadata: "
        f"{avatar_metadata_get}",
    )

    # Exercise the reverse XEP-0398 projection with a second valid PNG:
    # avatar data followed by metadata must atomically update vCard-temp.
    projected_png = png_1x1_rgba(220, 38, 38)
    projected_b64 = base64.b64encode(projected_png).decode()
    projected_sha1 = hashlib.sha1(projected_png).hexdigest()
    alice.send(
        "<iq xmlns='jabber:client' type='set' id='avatar-data-publish'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        "<publish node='urn:xmpp:avatar:data'>"
        f"<item id='{projected_sha1}'><data xmlns='urn:xmpp:avatar:data'>"
        f"{projected_b64}</data></item></publish></pubsub></iq>"
    )
    avatar_data_publish, _ = alice.receive_until("avatar-data-publish")
    check(
        "type='result'" in avatar_data_publish,
        f"second XEP-0084 avatar data publication failed: {avatar_data_publish}",
    )
    alice.send(
        "<iq xmlns='jabber:client' type='set' id='avatar-metadata-publish'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        "<publish node='urn:xmpp:avatar:metadata'>"
        f"<item id='{projected_sha1}'><metadata xmlns='urn:xmpp:avatar:metadata'>"
        f"<info id='{projected_sha1}' bytes='{len(projected_png)}' type='image/png'/>"
        "</metadata></item></publish></pubsub></iq>"
    )
    avatar_metadata_publish, _ = alice.receive_until("avatar-metadata-publish")
    check(
        "type='result'" in avatar_metadata_publish,
        "XEP-0084 metadata to vCard projection failed: "
        f"{avatar_metadata_publish}",
    )
    bob.send(
        f"<iq xmlns='jabber:client' type='get' id='vcard-projected-get' "
        f"to='{ALICE}@{DOMAIN}'><vCard xmlns='vcard-temp'/></iq>"
    )
    projected_vcard, _ = bob.receive_until("vcard-projected-get")
    check(
        "Alice Integration" in projected_vcard
        and f"<BINVAL>{projected_b64}</BINVAL>" in projected_vcard,
        f"XEP-0084 metadata was not projected back to vCard-temp: {projected_vcard}",
    )

    alice.send_with_pow(
        f"<message xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='chat' id='plain-online'>"
        "<body>online plaintext</body></message>",
        alice_token,
    )
    online, _ = bob.receive_until("plain-online")
    check(
        "online plaintext" in online and f"from='{ALICE}@{DOMAIN}/alice-reconnected'" in online,
        "online routing failed",
    )

    alice_self_target = XmppWebSocket(ALICE, PASSWORD, "alice-self-target")
    alice_self_target.send(
        "<presence xmlns='jabber:client'><priority>127</priority></presence>"
    )
    full_normal = (
        f"<message xmlns='jabber:client' to='{ALICE}@{DOMAIN}/alice-self-target' "
        "type='normal' id='resource-affinity-normal'>"
        "<body>exact full resource</body>"
        "<origin-id xmlns='urn:xmpp:sid:0' id='resource-affinity-origin'/>"
        "</message>"
    )
    alice.send_with_pow(full_normal, alice_token)
    full_normal_delivery, _ = alice_self_target.receive_until("resource-affinity-normal")
    check(
        "exact full resource" in full_normal_delivery
        and f"to='{ALICE}@{DOMAIN}/alice-self-target'" in full_normal_delivery,
        f"normal full-JID delivery lost its exact resource: {full_normal_delivery}",
    )
    alice.send_with_pow(full_normal, alice_token)
    affinity_replay_deadline = time.monotonic() + 0.75
    while time.monotonic() < affinity_replay_deadline:
        try:
            replay_frame = alice_self_target.receive(
                max(0.1, affinity_replay_deadline - time.monotonic())
            )
        except (TimeoutError, socket.timeout):
            break
        check(
            "resource-affinity-normal" not in replay_frame,
            f"exact full-JID replay created a second delivery: {replay_frame}",
        )
    alice.send_with_pow(
        "<message xmlns='jabber:client' type='chat' id='message-without-to'>"
        "<body>RFC 6120 self-bare routing</body></message>",
        alice_token,
    )
    self_routed, _ = alice_self_target.receive_until("message-without-to")
    check(
        "RFC 6120 self-bare routing" in self_routed
        and f"from='{ALICE}@{DOMAIN}/alice-reconnected'" in self_routed,
        f"message without to was not routed to the sender bare JID: {self_routed}",
    )

    # RFC 6120 section 10.3.1 also applies to a personal-history mutation.
    # Keep the client XML untouched while the server internally binds the
    # missing recipient to Alice's bare account for authorization, replay and
    # durable C2S projection identity.
    alice.send_with_pow(
        "<message xmlns='jabber:client' type='chat' id='encrypted-self-target'>"
        + omemo2_envelope(
            12345,
            [(f"{ALICE}@{DOMAIN}", [12345])],
            "SELF-RETRACTION-TARGET",
        )
        + "</message>",
        alice_token,
    )
    encrypted_self_target, _ = alice_self_target.receive_until("encrypted-self-target")
    check(
        omemo_payload_b64("SELF-RETRACTION-TARGET") in encrypted_self_target,
        f"encrypted self-message without to was not routed: {encrypted_self_target}",
    )
    alice.send_with_pow(
        "<message xmlns='jabber:client' type='chat' id='self-retract-without-to'>"
        "<retract xmlns='urn:xmpp:message-retract:1' id='encrypted-self-target'/>"
        "</message>",
        alice_token,
    )
    self_retraction, _ = alice_self_target.receive_until("self-retract-without-to")
    self_retraction_root = ET.fromstring(self_retraction)
    check(
        "type='error'" not in self_retraction
        and "urn:xmpp:message-retract:1" in self_retraction
        and "to" not in self_retraction_root.attrib,
        "missing-to self-retraction was rejected or the server rewrote its XML: "
        f"{self_retraction}",
    )
    alice.send_with_pow(
        "<message xmlns='jabber:client' type='chat' id='self-retract-without-to'>"
        "<retract xmlns='urn:xmpp:message-retract:1' id='encrypted-self-target'/>"
        "</message>",
        alice_token,
    )
    replay_deadline = time.monotonic() + 0.75
    while time.monotonic() < replay_deadline:
        try:
            replay_frame = alice_self_target.receive(
                max(0.1, replay_deadline - time.monotonic())
            )
        except (TimeoutError, socket.timeout):
            break
        check(
            "self-retract-without-to" not in replay_frame,
            f"exact retraction replay created a second delivery: {replay_frame}",
        )
    alice_self_target.close()

    # Reject the ambiguous cross-feature mutation before PoW admission, room
    # lookup, affiliation grant, archive, outbox or recipient delivery.
    alice.send(
        f"<message xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='chat' "
        "id='mixed-retraction-direct-invite'>"
        "<retract xmlns='urn:xmpp:message-retract:1' id='encrypted-self-target'/>"
        f"<x xmlns='jabber:x:conference' jid='room@conference.{DOMAIN}'/>"
        "</message>"
    )
    mixed_retraction_error, _ = alice.receive_until("mixed-retraction-direct-invite")
    check(
        "type='error'" in mixed_retraction_error and "bad-request" in mixed_retraction_error,
        "mixed personal retraction and direct MUC invite was accepted: "
        f"{mixed_retraction_error}",
    )
    mixed_deadline = time.monotonic() + 0.5
    while time.monotonic() < mixed_deadline:
        try:
            mixed_recipient_frame = bob.receive(
                max(0.1, mixed_deadline - time.monotonic())
            )
        except (TimeoutError, socket.timeout):
            break
        check(
            "mixed-retraction-direct-invite" not in mixed_recipient_frame,
            "mixed retraction/direct invite reached its recipient before rejection: "
            f"{mixed_recipient_frame}",
        )

    alice_carbon = XmppWebSocket(ALICE, PASSWORD, "alice-carbon")
    assert_api_session(bob_token, BOB, "before-carbons")
    alice_carbon.send(
        "<iq xmlns='jabber:client' type='set' id='carbon-enable'>"
        "<enable xmlns='urn:xmpp:carbons:2'/></iq>"
    )
    carbon_enabled, _ = alice_carbon.receive_until("carbon-enable")
    check(
        "type='result'" in carbon_enabled
        and f"from='{ALICE}@{DOMAIN}'" in carbon_enabled
        and f"to='{ALICE}@{DOMAIN}/alice-carbon'" in carbon_enabled,
        f"message Carbons result did not carry the XEP-0280 bare/full addressing: {carbon_enabled}",
    )
    alice_carbon.send(
        "<iq xmlns='jabber:client' type='set' id='carbon-disable'>"
        "<disable xmlns='urn:xmpp:carbons:2'/></iq>"
    )
    carbon_disabled, _ = alice_carbon.receive_until("carbon-disable")
    check(
        "type='result'" in carbon_disabled
        and f"from='{ALICE}@{DOMAIN}'" in carbon_disabled
        and f"to='{ALICE}@{DOMAIN}/alice-carbon'" in carbon_disabled,
        f"message Carbons disable result was not correctly addressed: {carbon_disabled}",
    )
    alice.send_with_pow(
        f"<message xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='chat' id='carbon-disabled-source'>"
        "<body>disabled carbon must not be copied</body></message>",
        alice_token,
    )
    bob.receive_until("carbon-disabled-source")
    try:
        disabled_copy = alice_carbon.receive(0.5)
        check(
            "carbon-disabled-source" not in disabled_copy,
            f"a disabled resource received a Carbon copy: {disabled_copy}",
        )
    except TimeoutError:
        pass
    alice_carbon.send(
        "<iq xmlns='jabber:client' type='set' id='carbon-reenable'>"
        "<enable xmlns='urn:xmpp:carbons:2'/></iq>"
    )
    carbon_reenabled, _ = alice_carbon.receive_until("carbon-reenable")
    check("type='result'" in carbon_reenabled, "message Carbons could not be re-enabled")
    alice_carbon.send(
        "<iq xmlns='jabber:client' type='set' id='carbon-malformed'>"
        "<enable xmlns='urn:xmpp:carbons:2' unexpected='true'/></iq>"
    )
    carbon_malformed, _ = alice_carbon.receive_until("carbon-malformed")
    check(
        "type='error'" in carbon_malformed
        and "bad-request" in carbon_malformed
        and f"from='{ALICE}@{DOMAIN}'" in carbon_malformed
        and f"to='{ALICE}@{DOMAIN}/alice-carbon'" in carbon_malformed,
        f"malformed Carbons control did not return the addressed XEP error: {carbon_malformed}",
    )
    alice.send_with_pow(
        f"<message xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='chat' id='carbon-sent-source'>"
        "<body>carbon sent copy</body></message>",
        alice_token,
    )
    bob.receive_until("carbon-sent-source")
    sent_carbon, _ = alice_carbon.receive_until("carbon-sent-source")
    assert_carbon_shape(sent_carbon, "sent")
    alice.send_with_pow(
        f"<message xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='chat' id='carbon-bare-no-copy-source'>"
        "<body>bare no-copy does not override RFC routing</body>"
        "<no-copy xmlns='urn:xmpp:hints'/></message>",
        alice_token,
    )
    bob.receive_until("carbon-bare-no-copy-source")
    bare_no_copy_carbon, _ = alice_carbon.receive_until(
        "carbon-bare-no-copy-source"
    )
    check(
        "<sent xmlns='urn:xmpp:carbons:2'>" in bare_no_copy_carbon,
        "XEP-0334 bare-JID no-copy incorrectly overrode RFC 6121/Carbons fan-out",
    )
    bob.send_with_pow(
        f"<message xmlns='jabber:client' to='{ALICE}@{DOMAIN}/alice-reconnected' type='chat' id='carbon-received-source'>"
        "<body>carbon received copy</body></message>",
        bob_token,
    )
    alice.receive_until("carbon-received-source")
    received_carbon, _ = alice_carbon.receive_until("carbon-received-source")
    assert_carbon_shape(received_carbon, "received")
    alice.send_with_pow(
        f"<message xmlns='jabber:client' to='{BOB}@{DOMAIN}/bob-web' type='chat' id='carbon-private-source'>"
        "<body>private carbon suppression</body><private xmlns='urn:xmpp:carbons:2'/></message>",
        alice_token,
    )
    bob.receive_until("carbon-private-source")
    try:
        private_copy = alice_carbon.receive(0.5)
        check(
            "carbon-private-source" not in private_copy,
            f"XEP-0280 private marker leaked a sent Carbon: {private_copy}",
        )
    except (TimeoutError, socket.timeout):
        pass
    bob.send_with_pow(
        f"<message xmlns='jabber:client' to='{ALICE}@{DOMAIN}/alice-reconnected' type='chat' id='carbon-no-copy-source'>"
        "<body>no-copy carbon suppression</body><no-copy xmlns='urn:xmpp:hints'/></message>",
        bob_token,
    )
    alice.receive_until("carbon-no-copy-source")
    try:
        no_copy = alice_carbon.receive(0.5)
        check(
            "carbon-no-copy-source" not in no_copy,
            f"XEP-0334 no-copy leaked a received Carbon: {no_copy}",
        )
    except (TimeoutError, socket.timeout):
        pass
    alice.send("<presence xmlns='jabber:client'><priority>10</priority></presence>")
    alice_carbon.send("<presence xmlns='jabber:client'><priority>1</priority></presence>")
    bob.send_with_pow(
        f"<message xmlns='jabber:client' to='{ALICE}@{DOMAIN}' type='chat' id='priority-route'>"
        "<body>highest priority resource</body></message>",
        bob_token,
    )
    priority_delivery, _ = alice.receive_until("priority-route")
    check("highest priority resource" in priority_delivery, "bare-JID message did not reach highest-priority resource")
    priority_carbon, _ = alice_carbon.receive_until("priority-route")
    assert_carbon_shape(priority_carbon, "received")
    alice_carbon.send(
        "<iq xmlns='jabber:client' type='get' id='blocklist-get'>"
        "<blocklist xmlns='urn:xmpp:blocking'/></iq>"
    )
    empty_blocklist, _ = alice_carbon.receive_until("blocklist-get")
    try:
        empty_blocklist_root = ET.fromstring(empty_blocklist)
    except ET.ParseError as error:
        raise AssertionError(
            f"empty blocklist result was not standalone XML: {empty_blocklist}"
        ) from error
    empty_blocklist_payload = empty_blocklist_root.find(
        "{urn:xmpp:blocking}blocklist"
    )
    check(
        empty_blocklist_root.tag == "{jabber:client}iq"
        and empty_blocklist_root.get("type") == "result"
        and empty_blocklist_payload is not None
        and len(empty_blocklist_payload) == 0,
        f"empty blocklist could not be retrieved: {empty_blocklist}",
    )
    alice_carbon.send(
        f"<iq xmlns='jabber:client' type='get' id='blocklist-addressed' to='{BOB}@{DOMAIN}'>"
        "<blocklist xmlns='urn:xmpp:blocking'/></iq>"
    )
    addressed_blocklist, _ = alice_carbon.receive_until("blocklist-addressed")
    check(
        "type='error'" in addressed_blocklist and "bad-request" in addressed_blocklist,
        "an account-scoped blocking command with a to address was accepted",
    )
    alice_carbon.send(
        "<iq xmlns='jabber:client' type='set' id='block-malformed'>"
        f"<block xmlns='urn:xmpp:blocking'><item jid='{BOB}@{DOMAIN}' extra='forbidden'/></block></iq>"
    )
    malformed_block, _ = alice_carbon.receive_until("block-malformed")
    check(
        "type='error'" in malformed_block and "bad-request" in malformed_block,
        "a blocking command outside the XEP-0191 XML schema was accepted",
    )
    alice.send(
        "<iq xmlns='jabber:client' type='get' id='blocklist-get-main'>"
        "<blocklist xmlns='urn:xmpp:blocking'/></iq>"
    )
    alice.receive_until("blocklist-get-main")
    alice_carbon.send(
        "<iq xmlns='jabber:client' type='set' id='block-bob'>"
        f"<block xmlns='urn:xmpp:blocking'><item jid='{BOB}@{DOMAIN}'/></block></iq>"
    )
    block_result, _ = alice_carbon.receive_until("block-bob")
    check("type='result'" in block_result, "block command failed")
    block_push, _ = alice.receive_until("<block xmlns='urn:xmpp:blocking'>")
    check(f"jid='{BOB}@{DOMAIN}'" in block_push, "block push was not sent to another interested resource")
    alice_carbon.send(
        "<iq xmlns='jabber:client' type='set' id='block-bob-duplicate'>"
        f"<block xmlns='urn:xmpp:blocking'><item jid='{BOB}@{DOMAIN}'/></block></iq>"
    )
    duplicate_result, _ = alice_carbon.receive_until("block-bob-duplicate")
    check("type='result'" in duplicate_result, "idempotent duplicate block failed")
    try:
        duplicate_push = alice.receive(0.5)
        check(
            "<block xmlns='urn:xmpp:blocking'>" not in duplicate_push,
            "duplicate block generated a push despite no durable change",
        )
    except (TimeoutError, socket.timeout):
        pass
    bob.send_with_pow(
        f"<message xmlns='jabber:client' to='{ALICE}@{DOMAIN}' type='chat' id='blocked-inbound'>"
        "<body>blocked inbound</body></message>",
        bob_token,
    )
    blocked_inbound, _ = bob.receive_until("blocked-inbound")
    check("service-unavailable" in blocked_inbound, "blocked inbound message was not rejected")
    alice.send_with_pow(
        f"<message xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='chat' id='blocked-outbound'>"
        "<body>blocked outbound</body></message>",
        alice_token,
    )
    blocked_outbound, _ = alice.receive_until("blocked-outbound")
    check(
        "not-acceptable" in blocked_outbound and "urn:xmpp:blocking:errors" in blocked_outbound,
        "blocked outbound message did not return the standard blocking error",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='blocked-iq-out' to='{BOB}@{DOMAIN}/bob-web'>"
        "<ping xmlns='urn:xmpp:ping'/></iq>"
    )
    blocked_iq_out, _ = alice.receive_until("blocked-iq-out")
    check(
        "not-acceptable" in blocked_iq_out and "urn:xmpp:blocking:errors" in blocked_iq_out,
        "blocked outbound IQ was routed",
    )
    bob.send(
        f"<iq xmlns='jabber:client' type='get' id='blocked-iq-in' to='{ALICE}@{DOMAIN}/alice-reconnected'>"
        "<ping xmlns='urn:xmpp:ping'/></iq>"
    )
    blocked_iq_in, _ = bob.receive_until("blocked-iq-in")
    check("service-unavailable" in blocked_iq_in, "blocked inbound IQ did not hide availability")
    alice_carbon.send(
        "<iq xmlns='jabber:client' type='set' id='unblock-bob'>"
        f"<unblock xmlns='urn:xmpp:blocking'><item jid='{BOB}@{DOMAIN}'/></unblock></iq>"
    )
    unblock_result, _ = alice_carbon.receive_until("unblock-bob")
    check("type='result'" in unblock_result, "unblock command failed")
    alice.receive_until("<unblock xmlns='urn:xmpp:blocking'>")
    bob.send_with_pow(
        f"<message xmlns='jabber:client' to='{ALICE}@{DOMAIN}/alice-reconnected' type='chat' id='unblocked-inbound'>"
        "<body>unblocked inbound</body></message>",
        bob_token,
    )
    try:
        unblocked, _ = alice.receive_until("unblocked-inbound")
    except (TimeoutError, socket.timeout) as delivery_error:
        try:
            sender_frame = bob.receive(0.5)
        except (TimeoutError, socket.timeout):
            sender_frame = "<no sender-side response>"
        raise AssertionError(
            "unblocked message was not delivered; "
            f"sender received: {sender_frame}"
        ) from delivery_error
    check("unblocked inbound" in unblocked, "unblocked message was not delivered")
    alice_carbon.send(
        "<iq xmlns='jabber:client' type='set' id='block-four-shapes'>"
        "<block xmlns='urn:xmpp:blocking'>"
        "<item jid='user@blocked.invalid/Phone'/><item jid='user@blocked.invalid'/>"
        "<item jid='gateway.invalid/Phone'/><item jid='blocked.invalid'/></block></iq>"
    )
    four_shape_result, _ = alice_carbon.receive_until("block-four-shapes")
    check("type='result'" in four_shape_result, "four XEP-0191 JID shapes were not accepted")
    alice.receive_until("user@blocked.invalid/Phone")
    alice_carbon.send(
        "<iq xmlns='jabber:client' type='set' id='unblock-all'>"
        "<unblock xmlns='urn:xmpp:blocking'/></iq>"
    )
    unblock_all_result, _ = alice_carbon.receive_until("unblock-all")
    check("type='result'" in unblock_all_result, "unblock-all failed")
    # XML serializers may use either `<unblock .../>` or an explicit closing
    # tag. Match the element start rather than one lexical empty-element form.
    unblock_all_push, _ = alice.receive_until("<unblock xmlns='urn:xmpp:blocking'")
    check("<item " not in unblock_all_push, "unblock-all push was not empty")

    room = f"integration-room@conference.{DOMAIN}"
    alice.send(
        f"<presence xmlns='jabber:client' to='{room}/Alice'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    alice_join, _ = alice.receive_until("code='110'")
    check(
        "code='201'" in alice_join
        and "affiliation='owner'" in alice_join
        and "role='moderator'" in alice_join,
        "MUC room creation did not grant owner/moderator state",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='muc-config-get' to='{room}'>"
        "<query xmlns='http://jabber.org/protocol/muc#owner'/></iq>"
    )
    muc_config, _ = alice.receive_until("muc-config-get")
    check(
        "muc#roomconfig" in muc_config
        and "muc#roomconfig_maxusers" in muc_config
        and "type='form'" in muc_config,
        "MUC owner configuration form was incomplete",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='muc-config-set' to='{room}'>"
        "<query xmlns='http://jabber.org/protocol/muc#owner'>"
        "<x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#roomconfig</value></field>"
        "<field var='muc#roomconfig_roomname'><value>Integration Room</value></field>"
        "<field var='muc#roomconfig_persistentroom'><value>1</value></field>"
        "<field var='muc#roomconfig_publicroom'><value>true</value></field>"
        "<field var='muc#roomconfig_maxusers'><value>20</value></field>"
        "</x></query></iq>"
    )
    muc_config_set, _ = alice.receive_until("muc-config-set")
    check("type='result'" in muc_config_set, "MUC owner configuration was rejected")
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='muc-room-disco' to='{room}'>"
        "<query xmlns='http://jabber.org/protocol/disco#info'/></iq>"
    )
    muc_room_disco, _ = alice.receive_until("muc-room-disco")
    check(
        "name='Integration Room'" in muc_room_disco and "muc_persistent" in muc_room_disco,
        "MUC configuration was not reflected in room discovery",
    )
    bob.send(
        f"<presence xmlns='jabber:client' to='{room}/Bob'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    bob_join, bob_join_frames = bob.receive_until("code='110'")
    check(
        any(f"from='{room}/Alice'" in frame for frame in bob_join_frames)
        and "affiliation='none'" in bob_join
        and "role='participant'" in bob_join,
        "MUC join did not return the occupant roster and self presence",
    )
    # XEP-0045 sends the current subject after self-presence.  Consume that
    # initial-join subject before issuing a tagged rejoin so the assertion
    # below cannot accidentally match the earlier queued stanza.
    bob.receive_until("<subject>")
    bob.send(
        f"<iq xmlns='jabber:client' type='get' id='muc-occupant-disco' to='{room}'>"
        "<query xmlns='http://jabber.org/protocol/disco#items'>"
        "<set xmlns='http://jabber.org/protocol/rsm'><max>10</max></set>"
        "</query></iq>"
    )
    occupant_disco, _ = bob.receive_until("muc-occupant-disco")
    check(
        f"jid='{room}/Alice'" in occupant_disco
        and f"jid='{room}/Bob'" in occupant_disco
        and "http://jabber.org/protocol/rsm" in occupant_disco,
        "room occupant discovery was incomplete or unpaged",
    )
    bob.send(
        f"<presence xmlns='jabber:client' id='muc-full-resync' to='{room}/Bob'>"
        "<x xmlns='http://jabber.org/protocol/muc'><history maxstanzas='0'/></x></presence>"
    )
    _, resync_frames = bob.receive_until("<subject>")
    resync = "".join(resync_frames)
    check(
        f"from='{room}/Alice'" in resync
        and "id='muc-full-resync'" in resync
        and "code='110'" in resync
        and resync.index(f"from='{room}/Alice'") < resync.index("code='110'")
        < resync.index("<subject>"),
        "repeated tagged MUC join did not return roster, self-presence, then subject",
    )
    alice_saw_bob, _ = alice.receive_until(f"from='{room}/Bob'")
    check("type='unavailable'" not in alice_saw_bob, "MUC join was not broadcast")
    alice_carbon.send(
        f"<presence xmlns='jabber:client' to='{room}/Bob'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    nick_conflict, _ = alice_carbon.receive_until("type='error'")
    check("conflict" in nick_conflict, "duplicate MUC nickname was not rejected")
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='muc-items' to='conference.{DOMAIN}'>"
        "<query xmlns='http://jabber.org/protocol/disco#items'/></iq>"
    )
    muc_items, _ = alice.receive_until("muc-items")
    check(f"jid='{room}'" in muc_items, "public MUC room was not discoverable")
    alice.send_with_pow(
        f"<message xmlns='jabber:client' to='{room}' type='groupchat' id='muc-live'>"
        "<body>live group message</body></message>",
        alice_token,
    )
    bob_group, _ = bob.receive_until("muc-live")
    check(
        f"from='{room}/Alice'" in bob_group
        and "live group message" in bob_group
        and "urn:xmpp:sid:0" in bob_group
        and f"by='{room}'" in bob_group,
        "MUC groupchat message was not broadcast",
    )
    alice.receive_until("muc-live")
    bob.send(
        "<iq xmlns='jabber:client' type='get' id='muc-blocklist-get'>"
        "<blocklist xmlns='urn:xmpp:blocking'/></iq>"
    )
    bob.receive_until("muc-blocklist-get")
    bob.send(
        "<iq xmlns='jabber:client' type='set' id='muc-block-alice'>"
        f"<block xmlns='urn:xmpp:blocking'><item jid='{room}/Alice'/></block></iq>"
    )
    muc_block_result, _ = bob.receive_until("muc-block-alice")
    check("type='result'" in muc_block_result, "MUC occupant block command failed")
    alice.send_with_pow(
        f"<message xmlns='jabber:client' to='{room}' type='groupchat' id='muc-blocked-delivery'>"
        "<body>blocked room occupant must not arrive</body></message>",
        alice_token,
    )
    alice.receive_until("muc-blocked-delivery")
    try:
        blocked_muc_frame = bob.receive(0.75)
        check(
            "muc-blocked-delivery" not in blocked_muc_frame,
            "a blocked MUC occupant message reached the recipient",
        )
    except (TimeoutError, socket.timeout):
        pass
    bob.send(
        "<iq xmlns='jabber:client' type='set' id='muc-unblock-alice'>"
        f"<unblock xmlns='urn:xmpp:blocking'><item jid='{room}/Alice'/></unblock></iq>"
    )
    muc_unblock_result, _ = bob.receive_until("muc-unblock-alice")
    check("type='result'" in muc_unblock_result, "MUC occupant unblock command failed")
    alice.send_with_pow(
        f"<message xmlns='jabber:client' to='{room}' type='groupchat' id='muc-encrypted'>"
        + omemo2_envelope(
            12345,
            [(f"{ALICE}@{DOMAIN}", [12345]), (f"{BOB}@{DOMAIN}", [23456])],
            "MUC-CIPHERTEXT",
        )
        + "</message>",
        alice_token,
    )
    bob.receive_until("muc-encrypted")
    alice.receive_until("muc-encrypted")
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='muc-self-ping' to='{room}/Alice'>"
        "<ping xmlns='urn:xmpp:ping'/></iq>"
    )
    self_ping, _ = alice.receive_until("muc-self-ping")
    check(
        "type='result'" in self_ping and f"from='{room}/Alice'" in self_ping,
        "MUC self-ping was not answered by the room",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='muc-mam' to='{room}'>"
        "<query xmlns='urn:xmpp:mam:2' queryid='muc-mam'>"
        "<set xmlns='http://jabber.org/protocol/rsm'><max>10</max><before/></set>"
        "</query></iq>"
    )
    _, muc_mam_frames = alice.receive_until("<fin ")
    muc_mam = "".join(muc_mam_frames)
    check(
        omemo_payload_b64("MUC-CIPHERTEXT") in muc_mam
        and "MUC-PLAINTEXT-MUST-NOT-PERSIST" not in muc_mam
        and f"from='{room}'" in muc_mam
        and "urn:xmpp:forward:0" in muc_mam,
        "MUC MAM did not return the encrypted room archive safely",
    )
    muc_result_ids = set(re.findall(r"<result\b[^>]*\bid='([^']+)'", muc_mam))
    muc_stanza_ids = {
        match.group(1)
        for tag in re.findall(r"<stanza-id\b[^>]*/>", muc_mam)
        if f"by='{room}'" in tag
        for match in [re.search(r"\bid='([^']+)'", tag)]
        if match is not None
    }
    check(
        muc_result_ids and muc_result_ids.issubset(muc_stanza_ids),
        f"MUC MAM result IDs were not stable room-assigned stanza IDs: results={muc_result_ids}, stanza_ids={muc_stanza_ids}",
    )
    bob.send(f"<presence xmlns='jabber:client' to='{room}/Bob' type='unavailable'/>")
    bob_leave, _ = bob.receive_until("code='110'")
    check("type='unavailable'" in bob_leave, "MUC self leave presence was missing")
    alice_left_notice, _ = alice.receive_until(f"from='{room}/Bob'")
    check("type='unavailable'" in alice_left_notice, "MUC leave was not broadcast")
    bob.send(
        f"<presence xmlns='jabber:client' to='{room}/Bob'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    _, bob_history_frames = bob.receive_until(omemo_payload_b64("MUC-CIPHERTEXT"))
    bob_history = "".join(bob_history_frames)
    check(
        "urn:xmpp:delay" in bob_history
        and "MUC-PLAINTEXT-MUST-NOT-PERSIST" not in bob_history,
        "MUC encrypted history was missing or retained plaintext siblings",
    )
    alice.receive_until(f"from='{room}/Bob'")
    bob.send(f"<presence xmlns='jabber:client' to='{room}/Bob' type='unavailable'/>")
    bob.receive_until("code='110'")
    alice.receive_until(f"from='{room}/Bob'")
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='muc-destroy' to='{room}'>"
        "<query xmlns='http://jabber.org/protocol/muc#owner'>"
        "<destroy><reason>integration cleanup</reason></destroy>"
        "</query></iq>"
    )
    _, destroy_frames = alice.receive_until("muc-destroy")
    if not any("<destroy" in frame for frame in destroy_frames):
        _, destroy_notice_frames = alice.receive_until("<destroy")
        destroy_frames.extend(destroy_notice_frames)
    destroyed = "".join(destroy_frames)
    check(
        "type='unavailable'" in destroyed
        and "<destroy" in destroyed
        and "integration cleanup" in destroyed,
        "MUC room destruction did not notify its occupant",
    )
    alice.send(
        f"<presence xmlns='jabber:client' to='{room}/Alice'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    recreated, _ = alice.receive_until("code='110'")
    check("code='201'" in recreated, "destroyed MUC room could not be recreated")
    alice.send(f"<presence xmlns='jabber:client' to='{room}/Alice' type='unavailable'/>")
    alice.receive_until("code='110'")

    locked_room = f"integration-locked@conference.{DOMAIN}"
    alice.send(
        f"<presence xmlns='jabber:client' id='locked-owner-join' to='{locked_room}/Alice'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    locked_owner, _ = alice.receive_until("locked-owner-join")
    check("code='201'" in locked_owner, "new MUC did not enter initial locked state")
    bob.send(
        f"<iq xmlns='jabber:client' type='get' id='locked-disco-outsider' to='{locked_room}'>"
        "<query xmlns='http://jabber.org/protocol/disco#info'/></iq>"
    )
    locked_disco, _ = bob.receive_until("locked-disco-outsider")
    check(
        "type='error'" in locked_disco and "item-not-found" in locked_disco,
        "an unconfigured MUC leaked through outsider service discovery",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='locked-disco-owner' to='{locked_room}'>"
        "<query xmlns='http://jabber.org/protocol/disco#info'/></iq>"
    )
    owner_locked_disco, _ = alice.receive_until("locked-disco-owner")
    check(
        "type='result'" in owner_locked_disco and "http://jabber.org/protocol/muc" in owner_locked_disco,
        "the exact initial owner could not inspect its locked MUC",
    )
    bob.send(
        f"<presence xmlns='jabber:client' id='locked-second-join' to='{locked_room}/Bob'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    locked_second, _ = bob.receive_until("locked-second-join")
    check(
        "type='error'" in locked_second and "item-not-found" in locked_second,
        "a second actor entered a room before its initial owner configured it",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='locked-cancel' to='{locked_room}'>"
        "<query xmlns='http://jabber.org/protocol/muc#owner'>"
        "<x xmlns='jabber:x:data' type='cancel'/></query></iq>"
    )
    cancelled, _ = alice.receive_until("locked-cancel")
    check("type='result'" in cancelled, "initial owner could not cancel room creation")
    bob.send(
        f"<presence xmlns='jabber:client' id='post-cancel-create' to='{locked_room}/Bob'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    post_cancel, _ = bob.receive_until("post-cancel-create")
    check(
        "code='201'" in post_cancel and "affiliation='owner'" in post_cancel,
        "cancelled locked room was not atomically available for recreation",
    )
    bob.send(
        f"<iq xmlns='jabber:client' type='set' id='post-cancel-instant' to='{locked_room}'>"
        "<query xmlns='http://jabber.org/protocol/muc#owner'>"
        "<x xmlns='jabber:x:data' type='submit'/></query></iq>"
    )
    post_cancel_instant, _ = bob.receive_until("post-cancel-instant")
    check("type='result'" in post_cancel_instant, "recreated room could not become instant")
    bob.send(f"<presence xmlns='jabber:client' to='{locked_room}/Bob' type='unavailable'/>")
    bob.receive_until("code='110'")

    # Exercise the stateful XEP-0045 controls that are easy to miss in unit
    # tests: mediated invitation/decline, room registration and reserved
    # nicknames, moderated voice requests, nickname changes, bounded join
    # history ordering, self-ping, kick, ban, and destruction.
    controls_room = f"integration-controls@conference.{DOMAIN}"
    alice.send(
        f"<presence xmlns='jabber:client' to='{controls_room}/Alice'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    controls_created, _ = alice.receive_until("code='110'")
    check(
        "code='201'" in controls_created and "affiliation='owner'" in controls_created,
        "MUC controls room was not created with owner affiliation",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='muc-controls-config' to='{controls_room}'>"
        "<query xmlns='http://jabber.org/protocol/muc#owner'>"
        "<x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#roomconfig</value></field>"
        "<field var='muc#roomconfig_persistentroom'><value>1</value></field>"
        "<field var='muc#roomconfig_moderatedroom'><value>1</value></field>"
        "<field var='muc#roomconfig_changesubject'><value>1</value></field>"
        "<field var='muc#roomconfig_allowinvites'><value>1</value></field>"
        "<field var='muc#roomconfig_allowregister'><value>1</value></field>"
        "<field var='muc#roomconfig_enablelogging'><value>1</value></field>"
        "<field var='muc#roomconfig_whois'><value>anyone</value></field>"
        "</x></query></iq>"
    )
    controls_config, _ = alice.receive_until("muc-controls-config")
    check("type='result'" in controls_config, "MUC controls configuration failed")

    alice.send_with_pow(
        f"<message xmlns='jabber:client' to='{controls_room}' type='normal' id='muc-invite'>"
        "<x xmlns='http://jabber.org/protocol/muc#user'>"
        f"<invite to='{BOB}@{DOMAIN}'><reason>Join the controls test</reason></invite>"
        "</x></message>",
        alice_token,
    )
    invitation, _ = bob.receive_until("Join the controls test")
    check(
        f"from='{controls_room}'" in invitation
        and f"<invite from='{ALICE}@{DOMAIN}/{alice.resource}'" in invitation,
        "mediated MUC invitation did not preserve room and inviter identity",
    )
    bob.send_with_pow(
        f"<message xmlns='jabber:client' to='{controls_room}' type='normal' id='muc-decline'>"
        "<x xmlns='http://jabber.org/protocol/muc#user'>"
        f"<decline to='{ALICE}@{DOMAIN}'><reason>Declined for runtime coverage</reason></decline>"
        "</x></message>",
        bob_token,
    )
    decline, _ = alice.receive_until("Declined for runtime coverage")
    check(
        f"from='{controls_room}'" in decline
        and f"<decline from='{BOB}@{DOMAIN}'" in decline,
        "mediated MUC decline was not delivered with authoritative identities",
    )

    bob.send(
        f"<iq xmlns='jabber:client' type='get' id='muc-register-get' to='{controls_room}'>"
        "<query xmlns='jabber:iq:register'/></iq>"
    )
    registration_form, _ = bob.receive_until("muc-register-get")
    check(
        "http://jabber.org/protocol/muc#register" in registration_form
        and "muc#register_roomnick" in registration_form,
        "MUC registration form was incomplete",
    )
    bob.send(
        f"<iq xmlns='jabber:client' type='set' id='muc-register-set' to='{controls_room}'>"
        "<query xmlns='jabber:iq:register'><x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#register</value></field>"
        "<field var='muc#register_roomnick'><value>ReservedBob</value></field>"
        "</x></query></iq>"
    )
    registered, _ = bob.receive_until("muc-register-set")
    check("type='result'" in registered, "MUC nickname registration failed")
    registration_notice, _ = alice.receive_until(f"jid='{BOB}@{DOMAIN}'")
    check(
        "type='normal'" in registration_notice
        and "http://jabber.org/protocol/muc#user" in registration_notice
        and "affiliation='member'" in registration_notice
        and "role='none'" in registration_notice,
        "offline room registration did not announce the new member affiliation",
    )
    bob.send(
        f"<iq xmlns='jabber:client' type='get' id='muc-register-confirm' to='{controls_room}'>"
        "<query xmlns='jabber:iq:register'/></iq>"
    )
    registration, _ = bob.receive_until("muc-register-confirm")
    check(
        "<registered" in registration and "<username>ReservedBob</username>" in registration,
        "MUC registered nickname was not returned",
    )
    alice.send(
        f"<presence xmlns='jabber:client' id='muc-reserved-conflict' to='{controls_room}/ReservedBob'/>"
    )
    reserved_conflict, _ = alice.receive_until("muc-reserved-conflict")
    check(
        "type='error'" in reserved_conflict and "conflict" in reserved_conflict,
        "another account could claim a registered MUC nickname",
    )

    bob.send(
        f"<presence xmlns='jabber:client' to='{controls_room}/ReservedBob'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    registered_join, _ = bob.receive_until("code='110'")
    check(
        "affiliation='member'" in registered_join and "role='participant'" in registered_join,
        "registered MUC member did not join with its durable affiliation",
    )
    alice.receive_until(f"from='{controls_room}/ReservedBob'")
    bob.send(
        f"<iq xmlns='jabber:client' type='set' id='muc-unregister' to='{controls_room}'>"
        "<query xmlns='jabber:iq:register'><remove/></query></iq>"
    )
    unregister_result, _ = bob.receive_until("muc-unregister")
    check("type='result'" in unregister_result, "MUC unregister command failed")
    bob_visitor, _ = bob.receive_until(f"from='{controls_room}/ReservedBob'")
    check(
        "affiliation='none'" in bob_visitor and "role='visitor'" in bob_visitor,
        "unregistering did not demote the joined user in the moderated room",
    )
    alice_visitor, _ = alice.receive_until(f"from='{controls_room}/ReservedBob'")
    check(
        "affiliation='none'" in alice_visitor and "role='visitor'" in alice_visitor,
        "MUC registration removal was not broadcast to other occupants",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='muc-visitor-list' to='{controls_room}'>"
        "<query xmlns='http://jabber.org/protocol/muc#admin'>"
        "<item role='visitor'/></query></iq>"
    )
    visitor_list, _ = alice.receive_until("muc-visitor-list")
    check(
        "type='result'" in visitor_list
        and "nick='ReservedBob'" in visitor_list
        and "role='visitor'" in visitor_list,
        "moderator could not retrieve the XEP-0045 visitor role list",
    )

    # A multi-item affiliation SET is one XEP-0045 administrative operation,
    # not a sequence of independently committed rows.  Transfer ownership to
    # Bob while demoting Alice to admin, then have Bob atomically restore the
    # original ownership.  Either intermediate operation must retain an owner
    # and all live role/affiliation presences must describe the committed
    # database state.
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='muc-affiliation-batch-transfer' to='{controls_room}'>"
        "<query xmlns='http://jabber.org/protocol/muc#admin'>"
        f"<item jid='{BOB}@{DOMAIN}' affiliation='owner'/>"
        f"<item jid='{ALICE}@{DOMAIN}' affiliation='admin'/>"
        "</query></iq>"
    )
    transferred, transferred_frames = alice.receive_until("muc-affiliation-batch-transfer")
    check("type='result'" in transferred, "atomic MUC ownership transfer was rejected")
    bob_owner, _ = bob.receive_until(f"from='{controls_room}/ReservedBob'")
    check(
        "affiliation='owner'" in bob_owner and "role='moderator'" in bob_owner,
        "atomic MUC ownership transfer did not update Bob's live identity",
    )
    alice_admin = next(
        (
            frame
            for frame in transferred_frames
            if f"from='{controls_room}/Alice'" in frame
            and "affiliation='admin'" in frame
            and "role='moderator'" in frame
        ),
        None,
    )
    if alice_admin is None:
        alice_admin, _ = alice.receive_until(f"from='{controls_room}/Alice'")
    check(
        "affiliation='admin'" in alice_admin and "role='moderator'" in alice_admin,
        "atomic MUC ownership transfer did not broadcast Alice's committed admin state",
    )
    bob.send(
        f"<iq xmlns='jabber:client' type='set' id='muc-affiliation-batch-restore' to='{controls_room}'>"
        "<query xmlns='http://jabber.org/protocol/muc#admin'>"
        f"<item jid='{ALICE}@{DOMAIN}' affiliation='owner'/>"
        f"<item jid='{BOB}@{DOMAIN}' affiliation='none'/>"
        "</query></iq>"
    )
    restored, restored_frames = bob.receive_until("muc-affiliation-batch-restore")
    check("type='result'" in restored, "atomic MUC ownership restoration was rejected")
    bob_visitor = next(
        (
            frame
            for frame in restored_frames
            if f"from='{controls_room}/ReservedBob'" in frame
            and "affiliation='none'" in frame
            and "role='visitor'" in frame
        ),
        None,
    )
    if bob_visitor is None:
        bob_visitor, _ = bob.receive_until(f"from='{controls_room}/ReservedBob'")
    check(
        "affiliation='none'" in bob_visitor and "role='visitor'" in bob_visitor,
        "atomic MUC ownership restoration did not update Bob's visitor state",
    )
    alice_owner, alice_owner_frames = alice.receive_until(f"from='{controls_room}/Alice'")
    check(
        "affiliation='owner'" in alice_owner and "role='moderator'" in alice_owner,
        "atomic MUC ownership restoration did not restore Alice's live owner identity",
    )
    alice_bob_visitor = next(
        (
            frame
            for frame in alice_owner_frames
            if f"from='{controls_room}/ReservedBob'" in frame
            and "affiliation='none'" in frame
            and "role='visitor'" in frame
        ),
        None,
    )
    if alice_bob_visitor is None:
        alice_bob_visitor, _ = alice.receive_until(f"from='{controls_room}/ReservedBob'")
    check(
        "affiliation='none'" in alice_bob_visitor and "role='visitor'" in alice_bob_visitor,
        "atomic MUC ownership restoration did not broadcast Bob's visitor state",
    )

    bob.send_with_pow(
        f"<message xmlns='jabber:client' to='{controls_room}' type='normal' id='muc-voice-request'>"
        "<x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#request</value></field>"
        "<field var='muc#role'><value>participant</value></field>"
        "</x></message>",
        bob_token,
    )
    voice_request, _ = alice.receive_until("Voice request")
    check(
        f"<value>{BOB}@{DOMAIN}/{bob.resource}</value>" in voice_request
        and "<value>ReservedBob</value>" in voice_request,
        "MUC voice request omitted the exact visitor identity",
    )
    alice.send_with_pow(
        f"<message xmlns='jabber:client' to='{controls_room}' type='normal' id='muc-voice-approve'>"
        "<x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#request</value></field>"
        "<field var='muc#role'><value>participant</value></field>"
        f"<field var='muc#jid'><value>{BOB}@{DOMAIN}/{bob.resource}</value></field>"
        "<field var='muc#roomnick'><value>ReservedBob</value></field>"
        "<field var='muc#request_allow'><value>1</value></field>"
        "</x></message>",
        alice_token,
    )
    voiced, _ = bob.receive_until(f"from='{controls_room}/ReservedBob'")
    check("role='participant'" in voiced, "moderator approval did not grant MUC voice")
    alice.receive_until(f"from='{controls_room}/ReservedBob'")

    bob.send(
        f"<presence xmlns='jabber:client' id='muc-nick-change' to='{controls_room}/RenamedBob'/>"
    )
    nick_change, _ = bob.receive_until("code='303'")
    check(
        "type='unavailable'" in nick_change and "nick='RenamedBob'" in nick_change,
        "MUC nickname change did not emit the 303 transition",
    )
    renamed_self, _ = bob.receive_until(f"from='{controls_room}/RenamedBob'")
    check("code='110'" in renamed_self, "MUC nickname change omitted new self-presence")
    alice_rename, _ = alice.receive_until("code='303'")
    check("nick='RenamedBob'" in alice_rename, "MUC nickname change was not broadcast")
    alice.receive_until(f"from='{controls_room}/RenamedBob'")

    alice.send_with_pow(
        f"<message xmlns='jabber:client' to='{controls_room}' type='groupchat' id='muc-control-history'>"
        "<body>CONTROL-HISTORY</body>"
        "<openpgp xmlns='urn:xmpp:openpgp:0'>ciphertext</openpgp>"
        "<store xmlns='urn:xmpp:hints'/></message>",
        alice_token,
    )
    alice.receive_until("muc-control-history")
    bob.receive_until("muc-control-history")
    alice.send_with_pow(
        f"<message xmlns='jabber:client' to='{controls_room}' type='groupchat' id='muc-control-subject'>"
        "<subject>Control Subject</subject></message>",
        alice_token,
    )
    alice.receive_until("muc-control-subject")
    bob.receive_until("muc-control-subject")
    bob.send(
        f"<presence xmlns='jabber:client' to='{controls_room}/RenamedBob' type='unavailable'/>"
    )
    bob.receive_until("code='110'")
    alice.receive_until(f"from='{controls_room}/RenamedBob'")
    bob.send(
        f"<presence xmlns='jabber:client' to='{controls_room}/HistoryBob'>"
        "<x xmlns='http://jabber.org/protocol/muc'>"
        "<history maxchars='4096' maxstanzas='10' seconds='3600' since='2000-01-01T00:00:00Z'/>"
        "</x></presence>"
    )
    ordered_history_frames = []
    history_deadline = time.monotonic() + 10
    while time.monotonic() < history_deadline:
        frame = bob.receive(max(0.1, history_deadline - time.monotonic()))
        ordered_history_frames.append(frame)
        # A pre-existing room subject is itself delayed per XEP-0045; subject
        # events are excluded from the ordinary history query, so this marker
        # unambiguously terminates the ordered join sequence.
        if "Control Subject" in frame:
            break
    ordered_history = "".join(ordered_history_frames)
    check(
        "code='110'" in ordered_history
        and "id='muc-control-history'" in ordered_history
        and "urn:xmpp:delay" in ordered_history
        and ordered_history.index("code='110'")
        < ordered_history.index("id='muc-control-history'")
        < ordered_history.index("Control Subject"),
        "MUC join sequence was not self-presence, bounded history, then current subject: "
        f"{ordered_history_frames}",
    )
    alice.receive_until(f"from='{controls_room}/HistoryBob'")
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='muc-controls-self-ping' to='{controls_room}/Alice'>"
        "<ping xmlns='urn:xmpp:ping'/></iq>"
    )
    controls_ping, _ = alice.receive_until("muc-controls-self-ping")
    check("type='result'" in controls_ping, "MUC controls self-ping failed")

    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='muc-kick' to='{controls_room}'>"
        "<query xmlns='http://jabber.org/protocol/muc#admin'>"
        "<item nick='HistoryBob' role='none'><reason>Runtime kick</reason></item>"
        "</query></iq>"
    )
    kick_result, _ = alice.receive_until("muc-kick")
    check("type='result'" in kick_result, "MUC moderator kick was rejected")
    kicked, _ = bob.receive_until("code='307'")
    check(
        "type='unavailable'" in kicked and "Runtime kick" in kicked,
        "kicked occupant did not receive status 307 and the reason",
    )
    bob.send(
        f"<presence xmlns='jabber:client' to='{controls_room}/ReturnBob'>"
        "<x xmlns='http://jabber.org/protocol/muc'/>"
        "</presence>"
    )
    returned, _ = bob.receive_until("code='110'")
    check("role='visitor'" in returned, "kicked visitor could not rejoin the moderated room")
    alice.receive_until(f"from='{controls_room}/ReturnBob'")
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='muc-ban' to='{controls_room}'>"
        "<query xmlns='http://jabber.org/protocol/muc#admin'>"
        f"<item jid='{BOB}@{DOMAIN}' affiliation='outcast'><reason>Runtime ban</reason></item>"
        "</query></iq>"
    )
    ban_result, _ = alice.receive_until("muc-ban")
    check("type='result'" in ban_result, "MUC ban was rejected")
    banned, _ = bob.receive_until("code='301'")
    check(
        "type='unavailable'" in banned and "Runtime ban" in banned,
        "banned occupant did not receive status 301 and the reason",
    )
    bob.send(
        f"<presence xmlns='jabber:client' id='muc-banned-rejoin' to='{controls_room}/BannedBob'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    banned_rejoin, _ = bob.receive_until("muc-banned-rejoin")
    check(
        "type='error'" in banned_rejoin and "forbidden" in banned_rejoin,
        "outcast user could rejoin the MUC room",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='muc-controls-destroy' to='{controls_room}'>"
        "<query xmlns='http://jabber.org/protocol/muc#owner'>"
        "<destroy><reason>Controls complete</reason></destroy>"
        "</query></iq>"
    )
    _, controls_destroy_frames = alice.receive_until("muc-controls-destroy")
    if not any("<destroy" in frame for frame in controls_destroy_frames):
        _, controls_destroy_notice = alice.receive_until("<destroy")
        controls_destroy_frames.extend(controls_destroy_notice)
    check(
        any("Controls complete" in frame and "type='unavailable'" in frame for frame in controls_destroy_frames),
        "MUC controls room destruction did not notify the remaining occupant",
    )

    omemo_room = f"integration-omemo-room@conference.{DOMAIN}"
    alice.send(
        f"<presence xmlns='jabber:client' to='{omemo_room}/Alice'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    omemo_owner_join, _ = alice.receive_until("code='110'")
    check(
        "code='201'" in omemo_owner_join and "affiliation='owner'" in omemo_owner_join,
        "OMEMO MUC creation did not grant owner affiliation",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='muc-omemo-config' to='{omemo_room}'>"
        "<query xmlns='http://jabber.org/protocol/muc#owner'>"
        "<x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#roomconfig</value></field>"
        "<field var='muc#roomconfig_persistentroom'><value>1</value></field>"
        "<field var='muc#roomconfig_membersonly'><value>1</value></field>"
        "<field var='muc#roomconfig_publicroom'><value>0</value></field>"
        "<field var='muc#roomconfig_whois'><value>anyone</value></field>"
        "</x></query></iq>"
    )
    omemo_config, _ = alice.receive_until("muc-omemo-config")
    check("type='result'" in omemo_config, "OMEMO MUC configuration was rejected")
    alice.send_with_pow(
        f"<message xmlns='jabber:client' to='{omemo_room}' type='normal' id='muc-omemo-invite'>"
        "<x xmlns='http://jabber.org/protocol/muc#user'>"
        f"<invite to='{BOB}@{DOMAIN}'><reason>OMEMO offline member sync</reason></invite>"
        "</x></message>",
        alice_token,
    )
    omemo_invitation, _ = bob.receive_until("OMEMO offline member sync")
    check(
        f"from='{omemo_room}'" in omemo_invitation,
        "members-only OMEMO invitation was not delivered",
    )
    offline_member_notice, _ = alice.receive_until(f"jid='{BOB}@{DOMAIN}'")
    check(
        "type='normal'" in offline_member_notice
        and "http://jabber.org/protocol/muc#user" in offline_member_notice
        and "affiliation='member'" in offline_member_notice
        and "role='none'" in offline_member_notice,
        "members-only invitation did not announce the offline member affiliation",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='muc-omemo-member' to='{omemo_room}'>"
        "<query xmlns='http://jabber.org/protocol/muc#admin'>"
        f"<item jid='{BOB}@{DOMAIN}' affiliation='member'/></query></iq>"
    )
    member_grant, member_grant_frames = alice.receive_until("muc-omemo-member")
    check("type='result'" in member_grant, "OMEMO MUC member grant failed")
    check(
        not any(
            "type='normal'" in frame
            and "http://jabber.org/protocol/muc#user" in frame
            and f"jid='{BOB}@{DOMAIN}'" in frame
            for frame in member_grant_frames
        ),
        "idempotent MUC affiliation update emitted a duplicate offline-member notice",
    )
    bob.send(
        f"<presence xmlns='jabber:client' to='{omemo_room}/Bob'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    omemo_member_join, _ = bob.receive_until("code='110'")
    check(
        "affiliation='member'" in omemo_member_join
        and f"jid='{BOB}@{DOMAIN}/{bob.resource}'" in omemo_member_join,
        "OMEMO MUC member join did not expose the member's real JID",
    )
    alice_omemo_saw_bob, _ = alice.receive_until(f"from='{omemo_room}/Bob'")
    check(
        f"jid='{BOB}@{DOMAIN}/{bob.resource}'" in alice_omemo_saw_bob,
        "OMEMO MUC did not broadcast the member's real JID",
    )

    for requested_affiliation, expected_jid in (
        ("owner", f"{ALICE}@{DOMAIN}"),
        ("admin", None),
        ("member", f"{BOB}@{DOMAIN}"),
    ):
        request_id = f"muc-omemo-list-{requested_affiliation}"
        bob.send(
            f"<iq xmlns='jabber:client' type='get' id='{request_id}' to='{omemo_room}'>"
            "<query xmlns='http://jabber.org/protocol/muc#admin'>"
            f"<item affiliation='{requested_affiliation}'/></query></iq>"
        )
        affiliation_list, _ = bob.receive_until(request_id)
        check(
            "type='result'" in affiliation_list,
            f"OMEMO MUC member could not retrieve {requested_affiliation} list",
        )
        if expected_jid is not None:
            check(
                f"jid='{expected_jid}'" in affiliation_list,
                f"OMEMO MUC {requested_affiliation} list omitted {expected_jid}",
            )

    bob.send(
        f"<iq xmlns='jabber:client' type='get' id='muc-omemo-list-outcast' to='{omemo_room}'>"
        "<query xmlns='http://jabber.org/protocol/muc#admin'>"
        "<item affiliation='outcast'/></query></iq>"
    )
    outcast_denied, _ = bob.receive_until("muc-omemo-list-outcast")
    check(
        "type='error'" in outcast_denied and "forbidden" in outcast_denied,
        "ordinary MUC member could retrieve the outcast list",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='muc-omemo-destroy' to='{omemo_room}'>"
        "<query xmlns='http://jabber.org/protocol/muc#owner'>"
        "<destroy><reason>integration cleanup</reason></destroy>"
        "</query></iq>"
    )
    alice.receive_until("muc-omemo-destroy")
    bob.receive_until("<destroy")

    bob.send(
        "<iq xmlns='jabber:client' type='set' id='push-enable'>"
        f"<enable xmlns='urn:xmpp:push:0' jid='{ADMIN}@{DOMAIN}' node='push-node'>"
        "<x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE' type='hidden'><value>http://jabber.org/protocol/pubsub#publish-options</value></field>"
        "<field var='secret'><value>opaque-secret</value></field></x>"
        "</enable></iq>"
    )
    push_enable, _ = bob.receive_until("push-enable")
    check("type='result'" in push_enable, "XEP-0357 push subscription could not be enabled")
    bob.send(
        "<iq xmlns='jabber:client' type='set' id='push-enable-optional-node'>"
        f"<enable xmlns='urn:xmpp:push:0' jid='{ADMIN}@{DOMAIN}'/>"
        "</iq>"
    )
    optional_enable, _ = bob.receive_until("push-enable-optional-node")
    check(
        "type='result'" in optional_enable,
        "XEP-0357 subscription with an omitted node was rejected",
    )

    bob.close()
    time.sleep(0.2)
    alice.send_with_pow(
        f"<message xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='chat' id='plain-offline'>"
        "<body>must not persist</body></message>",
        alice_token,
    )
    plain_error, _ = alice.receive_until("plain-offline")
    check("type='error'" in plain_error and "service-unavailable" in plain_error, "offline plaintext was not rejected")

    alice.send_with_pow(
        f"<message xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='chat' id='encrypted-offline'>"
        + omemo2_envelope(
            12345,
            [(f"{ALICE}@{DOMAIN}", [12345]), (f"{BOB}@{DOMAIN}", [23456])],
            "CIPHERTEXT-123",
        )
        + "</message>",
        alice_token,
    )
    # The administrator connection is the single-resource local mock push
    # service.  Using Alice here made the assertion depend on which one of her
    # two resources won bare-JID routing, rather than on XEP-0357 itself.
    push_notification, push_frames = admin_xmpp.receive_until("push-node")
    push_notifications = [
        frame for frame in push_frames if "urn:xmpp:push:summary" in frame
    ]
    check(
        len(push_notifications) == 2,
        f"omitted-node and explicit-node push targets were not both notified: {push_frames}",
    )
    optional_notification = next(
        (frame for frame in push_notifications if "<publish>" in frame), None
    )
    check(
        optional_notification is not None
        and "node=''" not in optional_notification
        and "<publish node=" not in optional_notification,
        f"omitted push node leaked as a synthetic empty attribute: {optional_notification}",
    )
    check(
        "urn:xmpp:push:summary" in push_notification
        and "<value>1</value>" in push_notification
        and "pending-subscription-count" in push_notification
        and "<publish-options>" in push_notification
        and "opaque-secret" in push_notification
        and f"from='{DOMAIN}'" in push_notification
        and omemo_payload_b64("CIPHERTEXT-123") not in push_notification
        and f"{ALICE}@{DOMAIN}" not in push_notification.split("<notification", 1)[-1],
        "push notification was missing or leaked message metadata",
    )
    push_id = re.search(r"id='(push-[^']+)'", push_notification)
    check(push_id is not None, "push notification request ID was missing")
    admin_xmpp.send(
        f"<iq xmlns='jabber:client' type='result' id='{push_id.group(1)}' to='{DOMAIN}'/>"
    )
    optional_push_id = re.search(r"id='(push-[^']+)'", optional_notification)
    check(optional_push_id is not None, "omitted-node push request ID was missing")
    admin_xmpp.send(
        f"<iq xmlns='jabber:client' type='error' id='{optional_push_id.group(1)}' to='{DOMAIN}'>"
        "<error type='cancel'><service-unavailable "
        "xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>"
    )
    admin_xmpp.send(
        "<iq xmlns='jabber:client' type='get' id='push-response-barrier'>"
        "<ping xmlns='urn:xmpp:ping'/></iq>"
    )
    admin_xmpp.receive_until("push-response-barrier")
    bob = XmppWebSocket(BOB, PASSWORD, "bob-reconnected", initial_presence=False)
    # RFC 6121 section 2.1.6 scopes roster pushes to available resources that
    # have requested the roster.  This is a fresh resource, so establish that
    # interest explicitly before later asserting subscription-state pushes.
    bob.send(
        "<iq xmlns='jabber:client' type='get' id='bob-reconnected-roster'>"
        "<query xmlns='jabber:iq:roster'/></iq>"
    )
    bob.receive_until("bob-reconnected-roster")
    bob.send("<presence xmlns='jabber:client'><priority>-1</priority></presence>")
    try:
        negative_priority_delivery = bob.receive(0.5)
        check(
            "encrypted-offline" not in negative_priority_delivery,
            f"XEP-0160 delivered an offline message to a negative-priority resource: {negative_priority_delivery}",
        )
    except (TimeoutError, socket.timeout):
        pass
    bob.send("<presence xmlns='jabber:client'><priority>0</priority></presence>")
    offline, _ = bob.receive_until("encrypted-offline")
    check(omemo_payload_b64("CIPHERTEXT-123") in offline, "encrypted offline payload missing")
    check("LEAK-ME-NEVER" not in offline and "LEAK-SUBJECT" not in offline, "plaintext leaked into offline storage")
    check("<body" not in offline, "XEP-0420 OMEMO replay gained a forbidden fallback body")

    alice.send_with_pow(
        f"<message xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='chat' id='transient-encrypted'>"
        + omemo2_envelope(
            12345,
            [(f"{ALICE}@{DOMAIN}", [12345]), (f"{BOB}@{DOMAIN}", [23456])],
            None,
        )
        + "<origin-id xmlns='urn:xmpp:sid:0' id='client-origin-1'/>"
        f"<stanza-id xmlns='urn:xmpp:sid:0' id='spoof-sender' by='{ALICE}@{DOMAIN}'/>"
        f"<stanza-id xmlns='urn:xmpp:sid:0' id='spoof-recipient' by='{BOB}@{DOMAIN}'/>"
        "<no-store xmlns='urn:xmpp:hints'/><no-permanent-store xmlns='urn:xmpp:hints'/>"
        "</message>",
        alice_token,
    )
    transient, _ = bob.receive_until("transient-encrypted")
    check(
        "client-origin-1" in transient
        and "spoof-sender" not in transient
        and "spoof-recipient" not in transient
        and transient.count("<stanza-id") == 1
        and f"by='{ALICE}@{DOMAIN}'" not in transient
        and f"by='{BOB}@{DOMAIN}'" in transient,
        "origin ID was not preserved or the recipient-account stanza ID was spoofable: "
        f"{transient}",
    )

    alice.send_with_pow(
        f"<message xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='chat' id='encrypted-page-two'>"
        + omemo2_envelope(
            12345,
            [(f"{ALICE}@{DOMAIN}", [12345]), (f"{BOB}@{DOMAIN}", [23456])],
            "CIPHERTEXT-456",
        )
        + "</message>",
        alice_token,
    )
    bob.receive_until("encrypted-page-two")

    alice.send(
        "<iq xmlns='jabber:client' type='get' id='mam-form'>"
        "<query xmlns='urn:xmpp:mam:2'/></iq>"
    )
    mam_form_reply, _ = alice.receive_until("mam-form")
    check(
        "type='form'" in mam_form_reply
        and "var='start'" in mam_form_reply
        and "var='end'" in mam_form_reply,
        "MAM query form was incomplete",
    )

    alice.send(
        "<iq xmlns='jabber:client' type='set' id='mam-page-one'>"
        "<query xmlns='urn:xmpp:mam:2' queryid='mam-page-one'>"
        f"<x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>urn:xmpp:mam:2</value></field><field var='with'><value>{BOB}@{DOMAIN}</value></field></x>"
        "<set xmlns='http://jabber.org/protocol/rsm'><max>1</max><before/></set>"
        "</query></iq>"
    )
    _, first_page_frames = alice.receive_until("<fin ")
    first_page = "".join(first_page_frames)
    first_page_id_match = re.search(r"<result[^>]*\sid='([^']+)'", first_page)
    check(first_page_id_match is not None, "MAM first page did not contain a result ID")
    first_page_id = first_page_id_match.group(1)
    check(
        "<count>2</count>" in first_page and "complete='false'" in first_page,
        f"MAM first page metadata was incorrect: {first_page}",
    )
    alice.send(
        "<iq xmlns='jabber:client' type='set' id='mam-page-two'>"
        "<query xmlns='urn:xmpp:mam:2' queryid='mam-page-two'>"
        f"<x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>urn:xmpp:mam:2</value></field><field var='with'><value>{BOB}@{DOMAIN}</value></field></x>"
        f"<set xmlns='http://jabber.org/protocol/rsm'><max>1</max><before>{first_page_id}</before></set>"
        "</query></iq>"
    )
    second_initial = alice.receive()
    check("type='error'" not in second_initial, f"MAM previous-page query failed: {second_initial}")
    if "<fin " in second_initial:
        second_page_frames = [second_initial]
    else:
        _, second_page_tail = alice.receive_until("<fin ")
        second_page_frames = [second_initial, *second_page_tail]
    second_page = "".join(second_page_frames)
    check(
        first_page_id not in second_page
        and "<count>2</count>" in second_page
        and "complete='true'" in second_page
        and "index='0'" in second_page,
        f"MAM previous-page result was incorrect: {second_page}",
    )

    alice.send(
        "<iq xmlns='jabber:client' type='set' id='mam-query'>"
        "<query xmlns='urn:xmpp:mam:2' queryid='mam-query-1'/></iq>"
    )
    _, mam_frames = alice.receive_until("<fin ")
    joined_mam = "".join(mam_frames)
    check(omemo_payload_b64("CIPHERTEXT-123") in joined_mam, "encrypted MAM payload missing")
    check("TRANSIENT-CONTROL" not in joined_mam, "XEP-0334 no-store stanza leaked into MAM")
    check("queryid='mam-query-1'" in joined_mam, "MAM results were not correlated to the query")
    check("LEAK-ME-NEVER" not in joined_mam and "must not persist" not in joined_mam, "plaintext leaked into MAM")
    check(mam_frames[-1].find("<fin ") >= 0, "MAM fin was not sent after results")
    mam_result_ids = set(re.findall(r"<result\b[^>]*\bid='([^']+)'", joined_mam))
    mam_stanza_ids = {
        match.group(1)
        for tag in re.findall(r"<stanza-id\b[^>]*/>", joined_mam)
        if f"by='{ALICE}@{DOMAIN}'" in tag
        for match in [re.search(r"\bid='([^']+)'", tag)]
        if match is not None
    }
    check(
        mam_result_ids and mam_result_ids.issubset(mam_stanza_ids),
        "MAM result IDs were not identical to stable stanza IDs assigned by the account",
    )

    status, history = api("GET", f"/api/v1/history?with={BOB}@{DOMAIN}", token=alice_token)
    check(status == 200 and history["all_end_to_end_encrypted"], "REST encrypted history failed")
    serialized_history = json.dumps(history)
    check(
        omemo_payload_b64("CIPHERTEXT-123") in serialized_history
        and "LEAK-ME-NEVER" not in serialized_history,
        "REST history leaked plaintext",
    )

    # A report carries only an archive row owned by the reporter plus the
    # optional original client stanza id. Sender, timestamp and encryption
    # provenance are deliberately reconstructed by the server.
    report_archive = next(
        (
            row
            for row in history.get("messages", [])
            if row.get("encrypted") and row.get("peer_jid") == f"{BOB}@{DOMAIN}"
        ),
        None,
    )
    check(report_archive is not None, "REST history exposed no reportable encrypted archive row")
    report_intent_payload = {
        "reported_jid": f"{BOB}@{DOMAIN}",
        "category": "spam",
        "description": "integration evidence ownership test",
        "evidence": [
            {
                "archive_id": report_archive["id"],
                "client_message_id": report_archive.get("stanza_id"),
                "body_text": "integration decrypted evidence",
            }
        ],
    }
    report_payload = {
        **report_intent_payload,
        "pow": solve_pow(
            alice_token,
            "report",
            pow_intent("POST", "/api/v1/reports", report_intent_payload),
        ),
    }
    report_body = json.dumps(report_payload, separators=(",", ":")).encode()
    report_status, _, report_raw = raw_http(
        "POST",
        "/api/v1/reports",
        report_body,
        {
            "Authorization": f"Bearer {alice_token}",
            "Content-Type": "application/json",
            "Idempotency-Key": f"integration-report-{time.time_ns()}",
        },
    )
    report_result = json.loads(report_raw)
    check(
        report_status == 201 and report_result.get("status") == "submitted",
        f"authoritative archived evidence report failed: {report_status} {report_result}",
    )

    foreign_report_intent_payload = {
        "reported_jid": f"{ALICE}@{DOMAIN}",
        "category": "spam",
        "description": None,
        "evidence": report_payload["evidence"],
    }
    foreign_report_payload = {
        **foreign_report_intent_payload,
        "pow": solve_pow(
            bob_token,
            "report",
            pow_intent("POST", "/api/v1/reports", foreign_report_intent_payload),
        ),
    }
    foreign_body = json.dumps(foreign_report_payload, separators=(",", ":")).encode()
    foreign_status, _, foreign_raw = raw_http(
        "POST",
        "/api/v1/reports",
        foreign_body,
        {
            "Authorization": f"Bearer {bob_token}",
            "Content-Type": "application/json",
            "Idempotency-Key": f"integration-foreign-report-{time.time_ns()}",
        },
    )
    foreign_result = json.loads(foreign_raw)
    check(
        foreign_status == 400
        and foreign_result.get("error", {}).get("code") == "bad_request",
        f"foreign archive evidence was accepted: {foreign_status} {foreign_result}",
    )

    status, stats = api("GET", "/api/v1/admin/stats", token=admin_token)
    check(status == 200 and stats["archived_stanzas"] == 4, f"unexpected archive count: {stats}")
    check(stats["offline_stanzas"] == 0, "offline queue was not drained")
    check(
        stats["registration_open"] is True
        and stats["island_mode"] is False
        and stats["federation_configured"] is True
        and stats["federation_enabled"] is True,
        f"admin runtime switches were missing or inconsistent: {stats}",
    )

    # XEP-0353 deliberately uses the ordinary message path so that abuse
    # controls, Carbons, MAM, Push and CSI semantics remain consistent. Run
    # this after the fixed-count archive assertions above.
    alice.send_with_pow(
        f"<message xmlns='jabber:client' type='chat' id='jmi-propose' to='{BOB}@{DOMAIN}'>"
        "<propose xmlns='urn:xmpp:jingle-message:0' id='jmi-call-1'>"
        "<description xmlns='urn:xmpp:jingle:apps:rtp:1' media='audio'/></propose>"
        "<store xmlns='urn:xmpp:hints'/></message>",
        alice_token,
    )
    jmi_propose, _ = bob.receive_until("jmi-propose")
    check(
        "urn:xmpp:jingle-message:0" in jmi_propose
        and "jmi-call-1" in jmi_propose
        and f"from='{ALICE}@{DOMAIN}/alice-reconnected'" in jmi_propose,
        f"XEP-0353 proposal did not traverse the abuse-rated message path: {jmi_propose}",
    )
    bob.send_with_pow(
        f"<message xmlns='jabber:client' type='chat' id='jmi-ringing' to='{ALICE}@{DOMAIN}/alice-reconnected'>"
        "<ringing xmlns='urn:xmpp:jingle-message:0' id='jmi-call-1'/><store xmlns='urn:xmpp:hints'/></message>",
        bob_token,
    )
    jmi_ringing, _ = alice.receive_until("jmi-ringing")
    check(
        "<ringing xmlns='urn:xmpp:jingle-message:0'" in jmi_ringing,
        f"XEP-0353 ringing response was not routed: {jmi_ringing}",
    )

    status, metrics = metrics_api()
    check(
        status == 200
        and "xmpp_messages_routed_total" in metrics
        and "xmpp_database_up 1" in metrics
        and "xmpp_database_pool_connections" in metrics
        and "xmpp_pep_items_retracted_total" in metrics
        and "xmpp_moderation_pending_reports" in metrics
        and "xmpp_moderation_pending_appeals" in metrics
        and "xmpp_active_invitation_tokens" in metrics,
        "Prometheus metrics missing",
    )

    status, nuke_disabled = api(
        "POST",
        "/api/v1/admin/nuke",
        {
            "confirm_phrase": "I understand this will delete all data",
            "current_password": ADMIN_PASSWORD,
        },
        token=admin_token,
    )
    check(
        status == 503
        and nuke_disabled.get("error", {}).get("code") == "operation_disabled",
        f"destructive administration was not disabled: {nuke_disabled}",
    )

    status, registration_state = api(
        "POST", "/api/v1/admin/registration", {"enabled": False}, token=admin_token
    )
    check(status == 200 and not registration_state["open_registration"], "admin registration close failed")
    status, closed_config = api("GET", "/api/v1/config")
    check(status == 200 and not closed_config["open_registration"], "public registration state was stale")
    status, closed_registration = api(
        "POST", "/api/v1/register", {"username": "must_not_register", "password": PASSWORD}
    )
    check(status == 403, f"runtime registration close was bypassed: {closed_registration}")
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='closed-registration-disco' to='{DOMAIN}'>"
        "<query xmlns='http://jabber.org/protocol/disco#info'/></iq>"
    )
    closed_disco, _ = alice.receive_until("closed-registration-disco")
    check(
        "urn:xmpp:register:0" not in closed_disco
        and "jabber:iq:register" in closed_disco,
        "closed registration advertised the IBR2 signup flow or hid authenticated "
        "XEP-0077 account maintenance",
    )
    status, _ = api(
        "POST", "/api/v1/admin/registration", {"enabled": True}, token=admin_token
    )
    check(status == 200, "admin registration reopen failed")

    island_key = f"island-enable-{time.time_ns()}"
    _, island_location, _ = admin_operation_request(
        "POST", "/api/v1/admin/island_mode", admin_token, {"enabled": True},
        island_key, verify_replay=True,
    )
    wait_operation(admin_token, island_location)
    conflict_headers = {
        "Authorization": f"Bearer {admin_token}", "Content-Type": "application/json",
        "Idempotency-Key": island_key,
    }
    conflict_status, _, conflict_raw = raw_http(
        "POST", "/api/v1/admin/island_mode", b'{"enabled":false}', conflict_headers,
    )
    conflict = json.loads(conflict_raw)
    check(
        conflict_status == 409 and conflict.get("error", {}).get("code") == "idempotency_key_conflict",
        f"different idempotent request was not rejected: {conflict_status} {conflict}",
    )
    status, isolated_config = api("GET", "/api/v1/config")
    check(status == 200 and not isolated_config["federation_enabled"], "island mode was not public")
    _, island_off_location, _ = admin_operation_request(
        "POST", "/api/v1/admin/island_mode", admin_token, {"enabled": False}
    )
    wait_operation(admin_token, island_off_location)

    kick_target = XmppWebSocket(BOB, PASSWORD, "admin-kick-target")
    status, sessions = api("GET", "/api/v1/admin/sessions", token=admin_token)
    kick_jid = f"{BOB}@{DOMAIN}/admin-kick-target"
    check(
        status == 200 and isinstance(sessions.get("sessions"), list),
        f"admin session page envelope failed: {sessions}",
    )
    malformed_status, malformed_headers, malformed_raw = raw_http(
        "DELETE",
        "/api/v1/admin/sessions/not-a-uuid",
        headers={"Authorization": f"Bearer {admin_token}", "Idempotency-Key": f"bad-uuid-{time.time_ns()}"},
    )
    malformed = json.loads(malformed_raw) if "json" in malformed_headers.get("content-type", "") else None
    check(
        malformed_status == 400
        and isinstance(malformed, dict)
        and malformed.get("error", {}).get("code") == "bad_request",
        f"malformed connection UUID did not return structured JSON: {malformed_status} {malformed_raw!r}",
    )
    kick_row = next((row for row in sessions["sessions"] if row["jid"] == kick_jid), None)
    check(kick_row is not None and kick_row.get("connection_id"), "admin session listing failed")
    _, kick_location, _ = admin_operation_request(
        "DELETE", f"/api/v1/admin/sessions/{kick_row['connection_id']}", admin_token
    )
    wait_operation(admin_token, kick_location)
    expect_orderly_websocket_close(kick_target, "admin session kick")

    kick_operation_id = kick_location.rsplit("/", 1)[1]
    status, operation_page = api(
        "GET", "/api/v1/admin/operations?limit=10", token=admin_token
    )
    check(
        status == 200
        and any(row["id"] == kick_operation_id for row in operation_page.get("items", [])),
        f"operation list did not expose the enqueued kick: {operation_page}",
    )
    status, filtered_operation_page = api(
        "GET",
        "/api/v1/admin/operations?status=succeeded&kind=admin.session_kick&limit=10",
        token=admin_token,
    )
    check(
        status == 200
        and any(
            row["id"] == kick_operation_id
            for row in filtered_operation_page.get("items", [])
        ),
        "operation list did not bind combined status/kind filters: "
        f"{filtered_operation_page}",
    )
    status, target_page = api(
        "GET", f"/api/v1/admin/operations/{kick_operation_id}/targets?limit=10",
        token=admin_token,
    )
    check(
        status == 200 and len(target_page.get("items", [])) == 1,
        f"operation targets were not readable: {target_page}",
    )
    target_id = target_page["items"][0]["id"]
    cancel_path = f"/api/v1/admin/operations/{kick_operation_id}/cancel"
    cancel_headers = {
        "Authorization": f"Bearer {admin_token}",
        "Idempotency-Key": f"cancel-terminal-{time.time_ns()}",
    }
    status, first_cancel_headers, first_cancel_body = raw_http(
        "POST", cancel_path, headers=cancel_headers
    )
    cancel_result = json.loads(first_cancel_body)
    check(
        status == 200 and cancel_result.get("outcome") == "already_terminal",
        f"terminal operation cancel was not safely idempotent: {cancel_result}",
    )
    replay_status, replay_cancel_headers, replay_cancel_body = raw_http(
        "POST", cancel_path, headers=cancel_headers
    )
    check(
        replay_status == status
        and replay_cancel_body == first_cancel_body
        and replay_cancel_headers.get("idempotency-replayed") == "true"
        and replay_cancel_headers.get("idempotency-original-request-id")
        == first_cancel_headers.get("x-request-id"),
        "terminal cancel did not replay its exact stored response",
    )
    reconcile_path = f"/api/v1/admin/operations/{kick_operation_id}/reconcile"
    reconcile_body = json.dumps(
        {
            "succeeded": True,
            "evidence_note": "integration terminal-state reachability check",
        },
        separators=(",", ":"),
    ).encode()
    reconcile_headers = {
        "Authorization": f"Bearer {admin_token}",
        "Content-Type": "application/json",
        "Idempotency-Key": f"reconcile-terminal-{time.time_ns()}",
    }
    status, _, reconcile_raw = raw_http(
        "POST", reconcile_path, reconcile_body, reconcile_headers
    )
    reconcile_result = json.loads(reconcile_raw)
    check(
        status == 409 and reconcile_result.get("error", {}).get("code") == "conflict",
        f"parent reconciliation endpoint was not reachable: {reconcile_result}",
    )
    status, _, target_reconcile_raw = raw_http(
        "POST",
        f"/api/v1/admin/operations/{kick_operation_id}/targets/{target_id}/reconcile",
        json.dumps(
            {
                "succeeded": True,
                "evidence_note": "integration terminal target reachability check",
            },
            separators=(",", ":"),
        ).encode(),
        {
            "Authorization": f"Bearer {admin_token}",
            "Content-Type": "application/json",
            "Idempotency-Key": f"reconcile-target-terminal-{time.time_ns()}",
        },
    )
    target_reconcile = json.loads(target_reconcile_raw)
    check(
        status == 409 and target_reconcile.get("error", {}).get("code") == "conflict",
        f"target reconciliation endpoint was not reachable: {target_reconcile}",
    )
    for invalid_query in (
        "unknown=1",
        "limit=1&limit=2",
        "status=Running",
        "kind=admin.private_future_kind",
    ):
        invalid_status, invalid_body = api(
            "GET", f"/api/v1/admin/operations?{invalid_query}", token=admin_token
        )
        check(
            invalid_status == 400
            and isinstance(invalid_body, dict)
            and invalid_body.get("error", {}).get("code") == "bad_request",
            f"operation query was not rejected with structured JSON: {invalid_query} {invalid_status} {invalid_body}",
        )

    # RFC 6121 section 2.5.2 on the real WebSocket wire: build a mutual
    # subscription, then verify that both generated cancellation stanzas are
    # delivered to the contact before its resulting roster push.
    # Alice also reconnected earlier in this fixture; section 2.1.6 requires
    # this new resource to request its roster before it is eligible for pushes.
    alice.send(
        "<iq xmlns='jabber:client' type='get' id='alice-mutual-roster-interest'>"
        "<query xmlns='jabber:iq:roster'/></iq>"
    )
    alice.receive_until("alice-mutual-roster-interest")
    bob.send(
        f"<presence xmlns='jabber:client' to='{ALICE}@{DOMAIN}' type='subscribe'/>"
    )
    alice.receive_until("type='subscribe'")
    alice.send(
        f"<presence xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='subscribed'/>"
    )
    bob.receive_until("type='subscribed'")
    bob.receive_until("subscription='both'")
    alice.receive_until("subscription='both'")
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='roster-remove-mutual'>"
        f"<query xmlns='jabber:iq:roster'><item jid='{BOB}@{DOMAIN}' subscription='remove'/></query></iq>"
    )
    _, removal_contact_frames = bob.receive_until("subscription='none'")
    unsubscribe_index = next(
        (
            index
            for index, frame in enumerate(removal_contact_frames)
            if "<presence" in frame and "type='unsubscribe'" in frame
        ),
        None,
    )
    unsubscribed_index = next(
        (
            index
            for index, frame in enumerate(removal_contact_frames)
            if "<presence" in frame and "type='unsubscribed'" in frame
        ),
        None,
    )
    contact_push_index = next(
        index
        for index, frame in enumerate(removal_contact_frames)
        if "jabber:iq:roster" in frame and "subscription='none'" in frame
    )
    check(
        unsubscribe_index is not None
        and unsubscribed_index is not None
        and unsubscribe_index < contact_push_index
        and unsubscribed_index < contact_push_index,
        f"roster removal did not preserve cancellation-before-push ordering: {removal_contact_frames}",
    )
    removal_result, removal_owner_frames = alice.receive_until("roster-remove-mutual")
    if not any("subscription='remove'" in frame for frame in removal_owner_frames):
        _, later_removal_owner_frames = alice.receive_until("subscription='remove'")
        removal_owner_frames.extend(later_removal_owner_frames)
    check(
        "type='result'" in removal_result
        and any(
            "jabber:iq:roster" in frame and "subscription='remove'" in frame
            for frame in removal_owner_frames
        ),
        f"roster removal did not push remove and acknowledge the initiator: {removal_owner_frames}",
    )

    # A retry after a potentially lost result is an item-not-found error and
    # cannot regenerate cancellation stanzas. Bob's ping is an ordering
    # barrier after Alice has observed the completed retry.
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='roster-remove-retry'>"
        f"<query xmlns='jabber:iq:roster'><item jid='{BOB}@{DOMAIN}' subscription='remove'/></query></iq>"
    )
    retry_remove, _ = alice.receive_until("roster-remove-retry")
    check(
        "type='error'" in retry_remove and "item-not-found" in retry_remove,
        f"duplicate roster removal was not idempotently rejected: {retry_remove}",
    )
    bob.send(
        "<iq xmlns='jabber:client' type='get' id='roster-remove-barrier'>"
        "<ping xmlns='urn:xmpp:ping'/></iq>"
    )
    _, retry_contact_frames = bob.receive_until("roster-remove-barrier")
    check(
        not any(
            "<presence" in frame
            and ("type='unsubscribe'" in frame or "type='unsubscribed'" in frame)
            for frame in retry_contact_frames
        ),
        f"duplicate roster removal regenerated a cancellation: {retry_contact_frames}",
    )

    password_target = XmppWebSocket(BOB, PASSWORD, "password-revoke-target")
    rotated_password = f"{PASSWORD}-rotated"
    status, changed = api(
        "PATCH",
        "/api/v1/me/password",
        {
            "current_password": PASSWORD,
            "new_password": rotated_password,
            "pow": solve_pow(
                bob_token,
                "password_change",
                pow_intent(
                    "PATCH",
                    "/api/v1/me/password",
                    {
                        "current_password": PASSWORD,
                        "new_password": rotated_password,
                    },
                ),
            ),
        },
        token=bob_token,
    )
    check(
        status == 200 and changed.get("sessions_revoked"),
        f"password change did not report session revocation: {changed}",
    )
    expect_orderly_websocket_close(password_target, "password change")
    status, _ = api("GET", "/api/v1/me", token=bob_token)
    check(status == 401, "password change did not revoke the REST session")
    status, _ = api("POST", "/api/v1/login", {"username": BOB, "password": PASSWORD})
    check(status == 401, "old password remained valid")
    status, rotated_login = api(
        "POST", "/api/v1/login", {"username": BOB, "password": rotated_password}
    )
    check(status == 200, f"rotated password was not usable: {rotated_login}")

    disable_target = XmppWebSocket(BOB, rotated_password, "disable-revoke-target")
    bob_id = next(row["id"] for row in users["users"] if row["username"] == BOB)
    _, disable_location, _ = admin_operation_request(
        "PATCH", f"/api/v1/admin/users/{bob_id}", admin_token, {"disabled": True}
    )
    wait_operation(admin_token, disable_location)
    expect_orderly_websocket_close(disable_target, "account disable")
    status, _ = api("GET", "/api/v1/me", token=rotated_login["token"])
    check(status == 401, "disabled account retained REST access")
    status, _ = api(
        "POST", "/api/v1/login", {"username": BOB, "password": rotated_password}
    )
    check(status == 401, "disabled account could authenticate")
    status, _ = api(
        "PATCH", f"/api/v1/admin/users/{bob_id}", {"disabled": False}, token=admin_token
    )
    check(status == 200, "administrator could not re-enable the test account")

    delete_username = "delete_it"
    status, result = register_account(delete_username, PASSWORD)
    check(status == 201, f"XEP-0077 deletion account registration failed: {result}")
    status, delete_login = api(
        "POST", "/api/v1/login", {"username": delete_username, "password": PASSWORD}
    )
    check(status == 200, f"XEP-0077 deletion account REST login failed: {delete_login}")
    delete_primary = XmppWebSocket(delete_username, PASSWORD, "delete-primary")
    delete_resumable = XmppWebSocket(delete_username, PASSWORD, "delete-resumable")
    delete_resumable.send("<enable xmlns='urn:xmpp:sm:3' resume='true'/>")
    enabled, _ = delete_resumable.receive_until("<enabled ")
    check("resume='true'" in enabled, "deletion test did not create resumable SM state")
    delete_primary.send(
        "<iq xmlns='jabber:client' type='set' id='account-remove'>"
        "<query xmlns='jabber:iq:register'><remove/></query></iq>"
    )
    removed, _ = delete_primary.receive_until("account-remove")
    check("type='result'" in removed, f"XEP-0077 removal failed: {removed}")
    expect_orderly_websocket_close(delete_resumable, "XEP-0077 sibling-session revocation")
    status, _ = api("GET", "/api/v1/me", token=delete_login["token"])
    check(status == 401, "XEP-0077 removal retained REST access")
    status, _ = api(
        "POST", "/api/v1/login", {"username": delete_username, "password": PASSWORD}
    )
    check(status == 401, "XEP-0077 removed account could authenticate")

    admin_xmpp.close()
    bob.close()
    alice_carbon.close()
    alice.close()
    print("integration: REST/no-store, admin, STARTTLS, WebSocket, roster, atomic/access-controlled PEP with owner quotas and OMEMO bundle retraction, vCard avatars, routing, SM resume, Carbons, blocking, MUC, HTTP Upload, XEP-0352 CSI, XEP-0357 push, paged MAM, credential/session revocation and metrics passed")


if __name__ == "__main__":
    run()
