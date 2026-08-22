#!/usr/bin/env python3
"""Dependency-free integration test for a locally running Northstar instance."""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import re
import socket
import ssl
import struct
import time


HTTP_HOST = os.environ.get("XMPP_TEST_HOST", "127.0.0.1")
HTTP_PORT = int(os.environ.get("XMPP_TEST_HTTP_PORT", "18080"))
XMPP_PORT = int(os.environ.get("XMPP_TEST_CLIENT_PORT", "15222"))
DOMAIN = os.environ.get("XMPP_TEST_DOMAIN", "localhost")
ALICE = "alice_it"
BOB = "bob_it"
PASSWORD = "integration-password-123"
ADMIN = "admin_it"
ADMIN_PASSWORD = "integration-admin-password-123"


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


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


def raw_http(method: str, path: str, body: bytes | None = None, headers=None):
    connection = http.client.HTTPConnection(HTTP_HOST, HTTP_PORT, timeout=10)
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    result = response.read()
    status = response.status
    response_headers = {name.lower(): value for name, value in response.getheaders()}
    connection.close()
    return status, response_headers, result


def solve_pow(token: str, action: str) -> dict[str, str]:
    status, challenge = api(
        "POST",
        "/api/v1/anti-abuse/challenge",
        {"action": action},
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


def recv_exact(sock: socket.socket, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        chunk = sock.recv(length - len(result))
        if not chunk:
            raise EOFError("WebSocket connection closed")
        result.extend(chunk)
    return bytes(result)


class XmppWebSocket:
    def __init__(self, username: str, password: str, resource: str, resume=None):
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
            "Sec-WebSocket-Protocol: xmpp\r\n\r\n"
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
        self.login(resume)

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
        proof = solve_pow(token, "message")
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
            frame = self.receive(max(0.1, deadline - time.monotonic()))
            frames.append(frame)
            if marker in frame:
                return frame, frames
        raise TimeoutError(f"timed out waiting for {marker!r}; frames={frames!r}")

    def login(self, resume=None) -> None:
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
        check("type='result'" in reply, f"resource binding failed: {reply}")
        self.send("<presence xmlns='jabber:client'/>")

    def abort(self) -> None:
        self.sock.close()

    def close(self) -> None:
        try:
            self.send("<close xmlns='urn:ietf:params:xml:ns:xmpp-framing'/>")
        except OSError:
            pass
        self.sock.close()


def run() -> None:
    wait_ready()
    status, config = api("GET", "/api/v1/config")
    check(status == 200 and config["domain"] == DOMAIN, "public config failed")
    check(config["archive_policy"] == "encrypted_only", "encrypted archive policy is not active")

    for username in (ALICE, BOB):
        status, result = api(
            "POST", "/api/v1/register", {"username": username, "password": PASSWORD}
        )
        check(status == 201, f"registration failed for {username}: {status} {result}")

    status, alice_login = api("POST", "/api/v1/login", {"username": ALICE, "password": PASSWORD})
    check(status == 200, f"Alice REST login failed: {alice_login}")
    alice_token = alice_login["token"]
    status, bob_login = api("POST", "/api/v1/login", {"username": BOB, "password": PASSWORD})
    check(status == 200, f"Bob REST login failed: {bob_login}")
    bob_token = bob_login["token"]
    status, me = api("GET", "/api/v1/me", token=alice_token)
    check(status == 200 and me["jid"] == f"{ALICE}@{DOMAIN}", "current-user endpoint failed")

    status, admin_login = api(
        "POST", "/api/v1/login", {"username": ADMIN, "password": ADMIN_PASSWORD}
    )
    check(status == 200 and admin_login["is_admin"], "bootstrap administrator login failed")
    admin_token = admin_login["token"]
    status, users = api("GET", "/api/v1/admin/users", token=admin_token)
    check(status == 200 and len(users["users"]) == 3, "administrator user listing failed")

    tcp_starttls_login()

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
    time.sleep(0.2)
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
        "<iq xmlns='jabber:client' type='get' id='disco-1' to='localhost'>"
        "<query xmlns='http://jabber.org/protocol/disco#info'/></iq>"
    )
    disco, _ = alice.receive_until("disco-1")
    check("category='pubsub' type='pep'" in disco, "PEP identity was not advertised")
    check(
        "http://jabber.org/protocol/pubsub#multi-items" in disco
        and "http://jabber.org/protocol/pubsub#persistent-items" in disco
        and "http://jabber.org/protocol/pubsub#publish-options" in disco
        and "http://jabber.org/protocol/pubsub#retract-items" in disco
        and "http://jabber.org/protocol/pubsub#retrieve-items" in disco
        and "urn:xmpp:omemo:2:devices+notify" in disco
        and "urn:xmpp:sce:1" in disco,
        "OMEMO 2 PEP capabilities were not advertised",
    )
    check(
        "urn:xmpp:carbons:2" in disco and "urn:xmpp:sm:3" in disco,
        "Carbons or stream management discovery features were missing",
    )
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
    status, _, _ = raw_http(
        "PUT",
        put_path,
        upload_body,
        {"Authorization": f"Bearer {put_match.group(2)}", "Content-Type": "application/octet-stream"},
    )
    check(status == 401, "HTTP Upload slot token was reusable")

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
    check(
        any("subscription='to'" in frame for frame in alice_subscription_frames),
        "Alice did not receive a roster push with subscription=to",
    )
    check(
        any(f"from='{BOB}@{DOMAIN}/bob-web'" in frame and "type='subscribed'" not in frame for frame in alice_subscription_frames),
        "Alice did not receive Bob's current availability after approval",
    )
    bob_roster_push, _ = bob.receive_until("subscription='from'")
    check(f"jid='{ALICE}@{DOMAIN}'" in bob_roster_push, "Bob roster direction was not updated")
    alice.send(
        f"<presence xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='subscribe'/>"
    )
    alice_idempotent_push, _ = alice.receive_until("subscription='to'")
    check("ask='subscribe'" not in alice_idempotent_push, "duplicate subscribe recreated a pending request")

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
    bob.send(
        f"<iq xmlns='jabber:client' type='get' id='pep-get' to='{ALICE}@{DOMAIN}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        "<items node='urn:xmpp:omemo:2:devices'/></pubsub></iq>"
    )
    pep, _ = bob.receive_until("pep-get")
    check("device id='12345'" in pep, "OMEMO PEP item retrieval failed")

    bundle = (
        "<bundle xmlns='urn:xmpp:omemo:2'><spk id='1'>c3Br</spk>"
        "<spks>c2ln</spks><ik>aWRlbnRpdHk=</ik><prekeys>"
        "<pk id='1'>cHJla2V5</pk></prekeys></bundle>"
    )
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
    alice.send(
        "<iq xmlns='jabber:client' type='set' id='vcard-set'>"
        "<vCard xmlns='vcard-temp'><FN>Alice Integration</FN><PHOTO><TYPE>image/png</TYPE><BINVAL>UE5H</BINVAL></PHOTO></vCard></iq>"
    )
    vcard_set, _ = alice.receive_until("vcard-set")
    check("type='result'" in vcard_set, "vCard update failed")
    bob.send(
        f"<iq xmlns='jabber:client' type='get' id='vcard-get' to='{ALICE}@{DOMAIN}'>"
        "<vCard xmlns='vcard-temp'/></iq>"
    )
    vcard_get, _ = bob.receive_until("vcard-get")
    check(
        "Alice Integration" in vcard_get and "<BINVAL>UE5H</BINVAL>" in vcard_get,
        "vCard retrieval did not return the stored avatar",
    )
    alice.send(
        "<iq xmlns='jabber:client' type='set' id='avatar-publish'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='urn:xmpp:avatar:metadata'>"
        "<item id='avatarhash'><metadata xmlns='urn:xmpp:avatar:metadata'><info id='avatarhash' bytes='3' type='image/png'/></metadata></item>"
        "</publish></pubsub></iq>"
    )
    _, avatar_frames = alice.receive_until("avatar-publish")
    avatar_events = "".join(avatar_frames)
    if "urn:xmpp:avatar:metadata" not in avatar_events:
        avatar_event, _ = alice.receive_until("urn:xmpp:avatar:metadata")
        avatar_events += avatar_event
    check("avatarhash" in avatar_events, "PEP avatar metadata event was not sent to the publisher's resources")

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

    alice_carbon = XmppWebSocket(ALICE, PASSWORD, "alice-carbon")
    alice_carbon.send(
        "<iq xmlns='jabber:client' type='set' id='carbon-enable'>"
        "<enable xmlns='urn:xmpp:carbons:2'/></iq>"
    )
    carbon_enabled, _ = alice_carbon.receive_until("carbon-enable")
    check("type='result'" in carbon_enabled, "message carbons could not be enabled")
    alice.send_with_pow(
        f"<message xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='chat' id='carbon-sent-source'>"
        "<body>carbon sent copy</body></message>",
        alice_token,
    )
    bob.receive_until("carbon-sent-source")
    sent_carbon, _ = alice_carbon.receive_until("carbon-sent-source")
    check(
        "<sent xmlns='urn:xmpp:carbons:2'>" in sent_carbon
        and "<forwarded xmlns='urn:xmpp:forward:0'>" in sent_carbon,
        "sent carbon was not delivered to the second resource",
    )
    bob.send_with_pow(
        f"<message xmlns='jabber:client' to='{ALICE}@{DOMAIN}/alice-reconnected' type='chat' id='carbon-received-source'>"
        "<body>carbon received copy</body></message>",
        bob_token,
    )
    alice.receive_until("carbon-received-source")
    received_carbon, _ = alice_carbon.receive_until("carbon-received-source")
    check(
        "<received xmlns='urn:xmpp:carbons:2'>" in received_carbon,
        "received carbon was not delivered to the second resource",
    )
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
    check("<received xmlns='urn:xmpp:carbons:2'>" in priority_carbon, "lower-priority resource did not receive a Carbon")
    alice_carbon.send(
        "<iq xmlns='jabber:client' type='get' id='blocklist-get'>"
        "<blocklist xmlns='urn:xmpp:blocking'/></iq>"
    )
    empty_blocklist, _ = alice_carbon.receive_until("blocklist-get")
    check("<blocklist xmlns='urn:xmpp:blocking'>" in empty_blocklist, "empty blocklist could not be retrieved")
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
        f"from='{room}/Alice'" in bob_group and "live group message" in bob_group,
        "MUC groupchat message was not broadcast",
    )
    alice.receive_until("muc-live")
    alice.send_with_pow(
        f"<message xmlns='jabber:client' to='{room}' type='groupchat' id='muc-encrypted'>"
        "<body>MUC-PLAINTEXT-MUST-NOT-PERSIST</body>"
        "<encrypted xmlns='urn:xmpp:omemo:2'><header sid='12345'/><payload>MUC-CIPHERTEXT</payload></encrypted>"
        "</message>",
        alice_token,
    )
    bob.receive_until("muc-encrypted")
    alice.receive_until("muc-encrypted")
    bob.send(f"<presence xmlns='jabber:client' to='{room}/Bob' type='unavailable'/>")
    bob_leave, _ = bob.receive_until("code='110'")
    check("type='unavailable'" in bob_leave, "MUC self leave presence was missing")
    alice_left_notice, _ = alice.receive_until(f"from='{room}/Bob'")
    check("type='unavailable'" in alice_left_notice, "MUC leave was not broadcast")
    bob.send(
        f"<presence xmlns='jabber:client' to='{room}/Bob'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    _, bob_history_frames = bob.receive_until("MUC-CIPHERTEXT")
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
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='muc-omemo-member' to='{omemo_room}'>"
        "<query xmlns='http://jabber.org/protocol/muc#admin'>"
        f"<item jid='{BOB}@{DOMAIN}' affiliation='member'/></query></iq>"
    )
    member_grant, _ = alice.receive_until("muc-omemo-member")
    check("type='result'" in member_grant, "OMEMO MUC member grant failed")
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
        f"<enable xmlns='urn:xmpp:push:0' jid='{ALICE}@{DOMAIN}' node='push-node'>"
        "<x xmlns='jabber:x:data' type='submit'><field var='secret'><value>opaque-secret</value></field></x>"
        "</enable></iq>"
    )
    push_enable, _ = bob.receive_until("push-enable")
    check("type='result'" in push_enable, "XEP-0357 push subscription could not be enabled")

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
        "<body>LEAK-ME-NEVER</body><subject>LEAK-SUBJECT</subject>"
        "<encrypted xmlns='urn:xmpp:omemo:2'><header sid='12345'/><payload>CIPHERTEXT-123</payload></encrypted>"
        "</message>",
        alice_token,
    )
    push_notification, _ = alice.receive_until("push-node")
    check(
        "urn:xmpp:push:summary" in push_notification
        and "message-count" in push_notification
        and "CIPHERTEXT-123" not in push_notification
        and f"{ALICE}@{DOMAIN}" not in push_notification.split("<notification", 1)[-1],
        "push notification was missing or leaked message metadata",
    )
    time.sleep(0.2)
    bob = XmppWebSocket(BOB, PASSWORD, "bob-reconnected")
    offline, _ = bob.receive_until("encrypted-offline")
    check("CIPHERTEXT-123" in offline, "encrypted offline payload missing")
    check("LEAK-ME-NEVER" not in offline and "LEAK-SUBJECT" not in offline, "plaintext leaked into offline storage")
    check("end-to-end encrypted" in offline, "generic encrypted fallback body missing")

    alice.send_with_pow(
        f"<message xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='chat' id='transient-encrypted'>"
        "<encrypted xmlns='urn:xmpp:omemo:2'><header sid='12345'/><payload>TRANSIENT-CONTROL</payload></encrypted>"
        "<no-store xmlns='urn:xmpp:hints'/><no-permanent-store xmlns='urn:xmpp:hints'/>"
        "</message>",
        alice_token,
    )
    transient, _ = bob.receive_until("transient-encrypted")
    check("TRANSIENT-CONTROL" in transient, "transient encrypted stanza was not routed")

    alice.send_with_pow(
        f"<message xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='chat' id='encrypted-page-two'>"
        "<encrypted xmlns='urn:xmpp:omemo:2'><header sid='12345'/><payload>CIPHERTEXT-456</payload></encrypted>"
        "</message>",
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
    check("CIPHERTEXT-123" in joined_mam, "encrypted MAM payload missing")
    check("TRANSIENT-CONTROL" not in joined_mam, "XEP-0334 no-store stanza leaked into MAM")
    check("queryid='mam-query-1'" in joined_mam, "MAM results were not correlated to the query")
    check("LEAK-ME-NEVER" not in joined_mam and "must not persist" not in joined_mam, "plaintext leaked into MAM")
    check(mam_frames[-1].find("<fin ") >= 0, "MAM fin was not sent after results")

    status, history = api("GET", f"/api/v1/history?with={BOB}@{DOMAIN}", token=alice_token)
    check(status == 200 and history["all_end_to_end_encrypted"], "REST encrypted history failed")
    serialized_history = json.dumps(history)
    check("CIPHERTEXT-123" in serialized_history and "LEAK-ME-NEVER" not in serialized_history, "REST history leaked plaintext")

    status, stats = api("GET", "/api/v1/admin/stats", token=admin_token)
    check(status == 200 and stats["archived_stanzas"] == 4, f"unexpected archive count: {stats}")
    check(stats["offline_stanzas"] == 0, "offline queue was not drained")

    status, metrics = api("GET", "/metrics")
    check(
        status == 200
        and "xmpp_messages_routed_total" in metrics
        and "xmpp_database_up 1" in metrics
        and "xmpp_database_pool_connections" in metrics
        and "xmpp_pep_items_retracted_total" in metrics,
        "Prometheus metrics missing",
    )

    admin_xmpp.close()
    bob.close()
    alice_carbon.close()
    alice.close()
    print("integration: REST, admin, STARTTLS, WebSocket, roster, atomic/access-controlled PEP with OMEMO bundle retraction, vCard avatars, routing, SM resume, Carbons, blocking, MUC, HTTP Upload, XEP-0357 push, paged MAM and metrics passed")


if __name__ == "__main__":
    run()
