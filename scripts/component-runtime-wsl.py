#!/usr/bin/env python3
"""Crash/restart runtime probe for the durable XEP-0114 component boundary."""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import base64
import json
import os
import pathlib
import re
import secrets
import socket
import ssl
import sys
import time


ROOT = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("northstar_integration", ROOT / "integration-wsl.py")
fixture = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(fixture)

USERNAME = "component_runtime"
PASSWORD = "component-runtime-password-123"
COMPONENT_DOMAIN = "gateway.localhost"
COMPONENT_ALIAS = "alias.gateway.localhost"
OUTBOUND_COMPONENT_DOMAIN = "outbound.localhost"
COMPONENT_SECRET = os.environ["COMPONENT_RUNTIME_SECRET"]
COMPONENT_PORT = int(os.environ.get("COMPONENT_RUNTIME_PORT", "15347"))
COMPONENT_CONNECT_PORT = int(os.environ.get("COMPONENT_CONNECT_RUNTIME_PORT", "15348"))
COMPONENT_CONNECT_SECRET = os.environ["COMPONENT_CONNECT_RUNTIME_SECRET"]
COMPONENT_CA_FILE = os.environ["COMPONENT_RUNTIME_CA_FILE"]
_READ_BUFFERS: dict[object, bytearray] = {}
_READINESS_NONCE = re.compile(r"^[0-9a-f]{16,128}$")


def publish_connect_readiness(listener: socket.socket) -> None:
    """Publish the mock's child-owned endpoint without a bind-close race.

    The component connect mock is a fixture child just like Northstar.  When
    the parent asks for a record, it must receive an atomically installed,
    nonce- and PID-bound endpoint only after this process owns the socket.
    Leaving both variables unset preserves the standalone mock's historical
    direct-invocation behavior.
    """

    raw_path = os.environ.get("COMPONENT_CONNECT_READINESS_FILE")
    nonce = os.environ.get("COMPONENT_CONNECT_READINESS_NONCE")
    if raw_path is None and nonce is None:
        return
    if not raw_path or not nonce:
        raise RuntimeError(
            "COMPONENT_CONNECT_READINESS_FILE and COMPONENT_CONNECT_READINESS_NONCE "
            "must be set together"
        )
    if not _READINESS_NONCE.fullmatch(nonce):
        raise RuntimeError("component connect readiness nonce is not canonical")

    destination = pathlib.Path(raw_path)
    if not destination.is_absolute() or not destination.parent.is_dir():
        raise RuntimeError("component connect readiness destination is not an existing absolute path")
    if destination.exists():
        raise RuntimeError(f"refusing to overwrite component connect readiness record: {destination}")

    host, port = listener.getsockname()[:2]
    if host != "127.0.0.1" or not isinstance(port, int) or not 1 <= port <= 65535:
        raise RuntimeError(f"component connect mock did not bind a canonical loopback endpoint: {host}:{port}")
    payload = json.dumps(
        {
            "version": 1,
            "instance_nonce": nonce,
            "pid": os.getpid(),
            "listeners": {"component-connect": f"{host}:{port}"},
        },
        separators=(",", ":"),
    ).encode() + b"\n"
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    descriptor = -1
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            descriptor = -1
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        # `link` is create-only, unlike replace: a racing pre-existing record
        # makes startup fail instead of allowing one fixture to overwrite
        # another fixture's proof.
        os.link(temporary, destination)
    except FileExistsError as error:
        raise RuntimeError(f"component connect readiness record already exists: {destination}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def make_connect_listener(backlog: int) -> socket.socket:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", COMPONENT_CONNECT_PORT))
    listener.listen(backlog)
    publish_connect_readiness(listener)
    return listener


def login(*, register: bool) -> tuple[object, str]:
    fixture.wait_ready()
    if register:
        status, result = fixture.register_account(USERNAME, PASSWORD)
        fixture.check(
            status == 201,
            f"component test account registration failed: {status} {result}",
        )
    status, result = fixture.api(
        "POST", "/api/v1/login", {"username": USERNAME, "password": PASSWORD}
    )
    fixture.check(status == 200, f"component test REST login failed: {status} {result}")
    return fixture.XmppWebSocket(USERNAME, PASSWORD, "component-runtime"), result["token"]


def enqueue() -> None:
    client, token = login(register=True)
    client.send(
        "<iq xmlns='jabber:client' type='get' id='component-root-disco' to='localhost'>"
        "<query xmlns='http://jabber.org/protocol/disco#items'/></iq>"
    )
    discovery, _ = client.receive_until("component-root-disco", timeout=15)
    fixture.check(
        COMPONENT_DOMAIN in discovery
        and COMPONENT_ALIAS in discovery
        and OUTBOUND_COMPONENT_DOMAIN in discovery,
        f"configured component domains missing from server discovery: {discovery}",
    )
    client.send_with_pow(
        "<message xmlns='jabber:client' type='chat' id='durable-component' "
        f"to='echo@{COMPONENT_DOMAIN}'><body>survive restart</body></message>",
        token,
    )
    client.send_with_pow(
        "<message xmlns='jabber:client' type='chat' id='durable-connect' "
        f"to='echo@{OUTBOUND_COMPONENT_DOMAIN}'><body>connect survives restart</body></message>",
        token,
    )
    # Do not close the WebSocket while the two message frames may still be in
    # the server's transport queue. A subsequent IQ result is an in-order
    # processing barrier and also exposes any stanza error returned for either
    # proof-bound message.
    client.send(
        "<iq xmlns='jabber:client' type='get' id='component-enqueue-barrier' "
        "to='localhost'><ping xmlns='urn:xmpp:ping'/></iq>"
    )
    barrier, preceding = client.receive_until("component-enqueue-barrier", timeout=15)
    fixture.check("type='result'" in barrier, f"component enqueue barrier failed: {barrier}")
    message_errors = [
        frame
        for frame in preceding
        if "<message" in frame and "type='error'" in frame
    ]
    fixture.check(not message_errors, f"component enqueue was rejected: {message_errors}")
    client.close()


def read_until(sock: socket.socket, marker: bytes, timeout: float = 15) -> bytes:
    deadline = time.monotonic() + timeout
    value = _READ_BUFFERS.setdefault(sock, bytearray())
    while True:
        end = value.find(marker)
        if end >= 0:
            end += len(marker)
            result = bytes(value[:end])
            del value[:end]
            return result
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"component socket timed out before {marker!r}: {bytes(value)!r}")
        sock.settimeout(remaining)
        chunk = sock.recv(8192)
        if not chunk:
            raise EOFError(f"component socket closed before {marker!r}: {bytes(value)!r}")
        value.extend(chunk)


def _xml_token_end(value: bytearray, start: int) -> int | None:
    quote: int | None = None
    cursor = start + 1
    while cursor < len(value):
        byte = value[cursor]
        if quote is not None:
            if byte == quote:
                quote = None
        elif byte in (ord("'"), ord('"')):
            quote = byte
        elif byte == ord(">"):
            return cursor + 1
        cursor += 1
    return None


def _take_xml_frame(value: bytearray) -> bytes | None:
    while value and value[0] in b" \t\r\n":
        del value[0]
    if not value or value[0] != ord("<"):
        return None
    depth = 0
    cursor = 0
    started = False
    while cursor < len(value):
        start = value.find(b"<", cursor)
        if start < 0:
            return None
        if value.startswith(b"<!--", start):
            end = value.find(b"-->", start + 4)
            if end < 0:
                return None
            cursor = end + 3
            continue
        if value.startswith(b"<![CDATA[", start):
            end = value.find(b"]]>", start + 9)
            if end < 0:
                return None
            cursor = end + 3
            continue
        token_end = _xml_token_end(value, start)
        if token_end is None:
            return None
        token = bytes(value[start:token_end]).rstrip()
        if token.startswith((b"<?", b"<!")):
            cursor = token_end
            continue
        if token.startswith(b"</"):
            if not started:
                frame = bytes(value[:token_end])
                del value[:token_end]
                return frame
            depth -= 1
        else:
            started = True
            depth += 1
            if token.endswith(b"/>"):
                depth -= 1
        cursor = token_end
        if started and depth == 0:
            frame = bytes(value[:cursor])
            del value[:cursor]
            return frame
    return None


def read_xml_frame(sock: socket.socket, timeout: float = 15) -> bytes:
    deadline = time.monotonic() + timeout
    value = _READ_BUFFERS.setdefault(sock, bytearray())
    while True:
        frame = _take_xml_frame(value)
        if frame is not None:
            return frame
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"component socket timed out before a complete stanza: {bytes(value)!r}")
        sock.settimeout(remaining)
        chunk = sock.recv(8192)
        if not chunk:
            raise EOFError(f"component socket closed with an incomplete stanza: {bytes(value)!r}")
        value.extend(chunk)


class StanzaInbox:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.pending: list[bytes] = []

    @staticmethod
    def _has_id(frame: bytes, stanza_id: str) -> bool:
        encoded = re.escape(stanza_id.encode())
        return re.search(rb"\bid=['\"]" + encoded + rb"['\"]", frame) is not None

    def receive_id(self, stanza_id: str, timeout: float = 15) -> bytes:
        deadline = time.monotonic() + timeout
        while True:
            for index, frame in enumerate(self.pending):
                if self._has_id(frame, stanza_id):
                    return self.pending.pop(index)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"component inbox timed out waiting for id={stanza_id!r}; pending={self.pending!r}"
                )
            self.pending.append(read_xml_frame(self.sock, remaining))


def reader_selftest() -> None:
    left, right = socket.socketpair()
    try:
        inbox = StanzaInbox(left)
        right.sendall(
            b"<message id='second'><body>two</body></message>"
            b"<message id='first'><forwarded><message id='nested'><body>one</body></message>"
            b"</forwarded></message>"
        )
        first = inbox.receive_id("first", timeout=1)
        second = inbox.receive_id("second", timeout=1)
        fixture.check(b"id='nested'" in first, "incremental reader split a nested stanza")
        fixture.check(b"<body>two</body>" in second, "inbox did not preserve an unmatched stanza")
    finally:
        left.close()
        right.close()
    print("component stanza inbox coalescing, nesting and out-of-order self-test passed")


def legacy_connect(secret: str) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", COMPONENT_PORT), timeout=10)
    sock.sendall(
        ("<stream:stream xmlns='jabber:component:accept' "
         "xmlns:stream='http://etherx.jabber.org/streams' "
         f"to='{COMPONENT_DOMAIN}'>").encode()
    )
    opening = read_until(sock, b">")
    stream_id = re.search(rb"\bid=['\"]([^'\"]+)['\"]", opening)
    fixture.check(stream_id is not None, f"component stream id missing: {opening!r}")
    proof = hashlib.sha1(stream_id.group(1) + secret.encode()).hexdigest()
    sock.sendall(f"<handshake>{proof}</handshake>".encode())
    return sock


def modern_starttls(
    *,
    server_hostname: str = "localhost",
    tls_version: ssl.TLSVersion | None = None,
) -> ssl.SSLSocket:
    modern = socket.create_connection(("127.0.0.1", COMPONENT_PORT), timeout=10)
    opening = (
        "<stream:stream xmlns='jabber:client' "
        "xmlns:stream='http://etherx.jabber.org/streams' "
        f"from='{COMPONENT_DOMAIN}' to='localhost' version='1.0'>"
    )
    modern.sendall(opening.encode())
    features = read_until(modern, b"</stream:features>")
    fixture.check(b"<starttls" in features, f"modern STARTTLS missing: {features!r}")
    modern.sendall(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
    fixture.check(b"<proceed" in read_until(modern, b"/>"), "modern STARTTLS rejected")
    context = ssl.create_default_context(cafile=COMPONENT_CA_FILE)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    if tls_version is not None:
        context.minimum_version = tls_version
        context.maximum_version = tls_version
    return context.wrap_socket(modern, server_hostname=server_hostname)


def modern_tls_stream() -> ssl.SSLSocket:
    modern_tls = modern_starttls()
    opening = (
        "<stream:stream xmlns='jabber:client' "
        "xmlns:stream='http://etherx.jabber.org/streams' "
        f"from='{COMPONENT_DOMAIN}' to='localhost' version='1.0'>"
    )
    modern_tls.sendall(opening.encode())
    mechanisms = read_until(modern_tls, b"</stream:features>")
    fixture.check(b"<mechanism>PLAIN</mechanism>" in mechanisms, "modern SASL PLAIN missing")
    return modern_tls


def modern_authenticate(modern_tls: ssl.SSLSocket, retry_once: bool) -> None:
    if retry_once:
        malformed_value = base64.b64encode(
            f"\0{COMPONENT_DOMAIN}\0{COMPONENT_SECRET}".encode()
        ).decode()
        modern_tls.sendall(
            ("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN' "
             f"forged='true'>{malformed_value}</auth>").encode()
        )
        malformed = read_until(modern_tls, b"</failure>")
        fixture.check(
            b"malformed-request" in malformed,
            f"malformed SASL PLAIN shape received the wrong error: {malformed!r}",
        )
        rejected = base64.b64encode(
            f"\0{COMPONENT_DOMAIN}\0definitely-the-wrong-secret".encode()
        ).decode()
        modern_tls.sendall(
            ("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>"
             f"{rejected}</auth>").encode()
        )
        failure = read_until(modern_tls, b"</failure>")
        fixture.check(b"not-authorized" in failure, f"bad SASL credential was not rejected: {failure!r}")
    authentication = base64.b64encode(
        f"\0{COMPONENT_DOMAIN}\0{COMPONENT_SECRET}".encode()
    ).decode()
    modern_tls.sendall(
        ("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>"
         f"{authentication}</auth>").encode()
    )
    fixture.check(b"<success" in read_until(modern_tls, b"/>"), "modern SASL failed")
    opening = (
        "<stream:stream xmlns='jabber:client' "
        "xmlns:stream='http://etherx.jabber.org/streams' "
        f"from='{COMPONENT_DOMAIN}' to='localhost' version='1.0'>"
    )
    modern_tls.sendall(opening.encode())
    bind_features = read_until(modern_tls, b"</stream:features>")
    fixture.check(
        b"urn:xmpp:component:0" in bind_features and b"<required" in bind_features,
        "modern required bind feature missing",
    )


def connect_mock() -> None:
    listener = make_connect_listener(8)
    listener.settimeout(60)
    completed_sessions = 0
    rejected_credentials = 0
    rejected_stream_identities = 0
    connection_attempts = 0
    try:
        while completed_sessions < 2:
            connection, _ = listener.accept()
            connection.settimeout(20)
            try:
                connection_attempts += 1
                opening = read_until(connection, b">")
                fixture.check(
                    b"jabber:component:connect" in opening
                    and f"from='{OUTBOUND_COMPONENT_DOMAIN}'".encode() in opening
                    and re.search(rb"\bto=['\"]", opening) is None,
                    f"invalid connect-mode initiating stream: {opening!r}",
                )
                stream_id = secrets.token_hex(16)
                if connection_attempts == 2:
                    connection.sendall(
                        ("<stream:stream xmlns='jabber:component:connect' "
                         "xmlns:stream='http://etherx.jabber.org/streams' "
                         f"to='forged.example' id='{stream_id}'>").encode()
                    )
                    fixture.check(
                        connection.recv(8192) == b"",
                        "server continued after forged connect-mode to identity",
                    )
                    rejected_stream_identities += 1
                    continue
                if connection_attempts == 3:
                    connection.sendall(
                        ("<stream:stream xmlns='jabber:component:connect' "
                         "xmlns:stream='http://etherx.jabber.org/streams' "
                         f"to='{OUTBOUND_COMPONENT_DOMAIN}' from='forged.example' "
                         f"id='{stream_id}'>").encode()
                    )
                    fixture.check(
                        connection.recv(8192) == b"",
                        "server continued after forged connect-mode from identity",
                    )
                    rejected_stream_identities += 1
                    continue
                connection.sendall(
                    ("<stream:stream xmlns='jabber:component:connect' "
                     "xmlns:stream='http://etherx.jabber.org/streams' "
                     f"to='{OUTBOUND_COMPONENT_DOMAIN}' id='{stream_id}'>").encode()
                )
                handshake = read_until(connection, b"</handshake>")
                supplied = re.search(rb"<handshake[^>]*>([0-9a-f]{40})</handshake>", handshake)
                expected = hashlib.sha1(
                    stream_id.encode() + COMPONENT_CONNECT_SECRET.encode()
                ).hexdigest().encode()
                if supplied is None or not hmac.compare_digest(supplied.group(1), expected):
                    rejected_credentials += 1
                    connection.sendall(
                        b"<stream:error><not-authorized xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"
                        b"</stream:error></stream:stream>"
                    )
                    continue
                connection.sendall(b"<handshake/>")
                inbox = StanzaInbox(connection)

                expected_id = "durable-connect" if completed_sessions == 0 else "connect-after-reconnect"
                delivered = inbox.receive_id(expected_id, timeout=20)
                fixture.check(
                    expected_id.encode() in delivered,
                    f"connect-mode durable stanza missing after authentication: {delivered!r}",
                )
                if completed_sessions == 0:
                    connection.sendall(
                        ("<message xmlns='jabber:component:connect' from='forged.example' "
                         f"to='{USERNAME}@localhost/component-runtime' id='connect-forged'>"
                         "<body>must not arrive</body></message>").encode()
                    )
                    forged = inbox.receive_id("connect-forged")
                    fixture.check(b"not-authorized" in forged, "connect-mode forged from was accepted")
                    connection.sendall(
                        (f"<message xmlns='jabber:component:connect' from='{OUTBOUND_COMPONENT_DOMAIN}' "
                         "to='recipient@remote.invalid' id='connect-remote-relay'>"
                         "<body>must not relay</body></message>").encode()
                    )
                    remote = inbox.receive_id("connect-remote-relay")
                    fixture.check(
                        b"remote-server-not-found" in remote,
                        "connect-mode component acquired remote relay outside the federation "
                        f"allowlist; response={remote!r}",
                    )
                    connection.sendall(
                        (f"<message xmlns='jabber:component:connect' from='{OUTBOUND_COMPONENT_DOMAIN}' "
                         f"to='echo@{COMPONENT_DOMAIN}' id='component-cross-route'>"
                         "<body>component to component</body></message>").encode()
                    )
                    live = inbox.receive_id("connect-live")
                    fixture.check(
                        b"connect-live" in live,
                        f"live client stanza did not reach connect-mode component: {live!r}",
                    )
                    response_id = "outbound-component-reply"
                    response_body = "outbound component reply"
                else:
                    response_id = "outbound-reconnect-reply"
                    response_body = "outbound reconnect reply"
                connection.sendall(
                    (f"<message xmlns='jabber:component:connect' from='{OUTBOUND_COMPONENT_DOMAIN}' "
                     f"to='{USERNAME}@localhost/component-runtime' id='{response_id}'>"
                     f"<body>{response_body}</body></message>").encode()
                )
                completed_sessions += 1
            finally:
                connection.close()
    finally:
        listener.close()
    fixture.check(rejected_credentials >= 1, "wrong connect-mode mounted secret was not rejected")
    fixture.check(
        rejected_stream_identities == 2,
        "connect-mode server did not reject forged to/from stream identities",
    )
    print("connect-mode mock rejected forged stream identities and wrong secret, then completed two authenticated reconnect sessions")


def connect_disabled_federation_mock() -> None:
    """Prove that a connect-mode component cannot bypass a disabled federation router."""
    listener = make_connect_listener(1)
    listener.settimeout(60)
    try:
        connection, _ = listener.accept()
        connection.settimeout(20)
        try:
            opening = read_until(connection, b">")
            fixture.check(
                b"jabber:component:connect" in opening
                and f"from='{OUTBOUND_COMPONENT_DOMAIN}'".encode() in opening,
                f"invalid federation-disabled connect-mode stream: {opening!r}",
            )
            stream_id = secrets.token_hex(16)
            connection.sendall(
                ("<stream:stream xmlns='jabber:component:connect' "
                 "xmlns:stream='http://etherx.jabber.org/streams' "
                 f"to='{OUTBOUND_COMPONENT_DOMAIN}' id='{stream_id}'>").encode()
            )
            handshake = read_until(connection, b"</handshake>")
            supplied = re.search(rb"<handshake[^>]*>([0-9a-f]{40})</handshake>", handshake)
            expected = hashlib.sha1(
                stream_id.encode() + COMPONENT_CONNECT_SECRET.encode()
            ).hexdigest().encode()
            fixture.check(
                supplied is not None and hmac.compare_digest(supplied.group(1), expected),
                "federation-disabled connect-mode component authentication failed",
            )
            connection.sendall(b"<handshake/>")
            inbox = StanzaInbox(connection)
            for target, stanza_id in (
                ("remote.invalid", "connect-federation-disabled"),
                ("allowed.remote.invalid", "connect-federation-disabled-allowlisted"),
            ):
                connection.sendall(
                    (f"<message xmlns='jabber:component:connect' "
                     f"from='{OUTBOUND_COMPONENT_DOMAIN}' to='recipient@{target}' "
                     f"id='{stanza_id}'><body>must not relay</body></message>").encode()
                )
                rejected = inbox.receive_id(stanza_id)
                fixture.check(
                    b"remote-server-not-found" in rejected and b"type='error'" in rejected,
                    "connect-mode component acquired remote relay while federation was disabled; "
                    f"target={target} response={rejected!r}",
                )
        finally:
            connection.close()
    finally:
        listener.close()
    print("connect-mode component remote relay remained disabled, including for an allowlisted domain")


def component() -> None:
    client, token = login(register=False)

    non_utf8 = socket.create_connection(("127.0.0.1", COMPONENT_PORT), timeout=10)
    non_utf8.sendall(b"\xff")
    non_utf8_error = read_until(non_utf8, b"</stream:stream>")
    fixture.check(
        b"unsupported-encoding" in non_utf8_error,
        f"non-UTF-8 component entity received the wrong stream error: {non_utf8_error!r}",
    )
    non_utf8.close()

    declared_encoding = socket.create_connection(("127.0.0.1", COMPONENT_PORT), timeout=10)
    declared_encoding.sendall(
        ("<?xml version='1.0' encoding='ISO-8859-1'?>"
         "<stream:stream xmlns='jabber:client' "
         "xmlns:stream='http://etherx.jabber.org/streams' "
         f"from='{COMPONENT_DOMAIN}' to='localhost' version='1.0'>").encode()
    )
    declared_encoding_error = read_until(declared_encoding, b"</stream:stream>")
    fixture.check(
        b"unsupported-encoding" in declared_encoding_error,
        f"non-UTF-8 XML declaration received the wrong stream error: {declared_encoding_error!r}",
    )
    declared_encoding.close()

    oversized_open = socket.create_connection(("127.0.0.1", COMPONENT_PORT), timeout=10)
    try:
        oversized_open.sendall(b"<stream:stream " + b"A" * (1024 * 1024 + 1))
    except (BrokenPipeError, ConnectionResetError):
        pass
    oversized_open_error = read_until(oversized_open, b"</stream:stream>")
    fixture.check(
        b"policy-violation" in oversized_open_error,
        f"oversized component opening received the wrong stream error: {oversized_open_error!r}",
    )
    oversized_open.close()

    unknown = socket.create_connection(("127.0.0.1", COMPONENT_PORT), timeout=10)
    unknown.sendall(
        ("<stream:stream xmlns='jabber:client' "
         "xmlns:stream='http://etherx.jabber.org/streams' "
         "from='unknown.localhost' to='localhost' version='1.0'>").encode()
    )
    unknown_error = read_until(unknown, b"</stream:stream>")
    fixture.check(
        b"host-unknown" in unknown_error,
        f"unknown modern component did not receive host-unknown: {unknown_error!r}",
    )
    unknown.close()

    tls_required = socket.create_connection(("127.0.0.1", COMPONENT_PORT), timeout=10)
    tls_required.sendall(
        ("<stream:stream xmlns='jabber:client' "
         "xmlns:stream='http://etherx.jabber.org/streams' "
         f"from='{COMPONENT_DOMAIN}' to='localhost' version='1.0'>").encode()
    )
    read_until(tls_required, b"</stream:features>")
    tls_required.sendall(b"<message xmlns='jabber:client'/>")
    tls_policy = read_until(tls_required, b"</stream:stream>")
    fixture.check(
        b"policy-violation" in tls_policy,
        f"modern component bypassed required STARTTLS: {tls_policy!r}",
    )
    tls_required.close()

    invalid_namespace = socket.create_connection(("127.0.0.1", COMPONENT_PORT), timeout=10)
    invalid_namespace.sendall(
        b"<stream:stream xmlns='urn:invalid:component' "
        b"xmlns:stream='http://etherx.jabber.org/streams' to='gateway.localhost'>"
    )
    invalid_namespace_error = read_until(invalid_namespace, b"</stream:stream>")
    fixture.check(
        b"jabber:component:accept" in invalid_namespace_error
        and b"invalid-namespace" in invalid_namespace_error,
        f"legacy invalid namespace did not receive a complete stream error: {invalid_namespace_error!r}",
    )
    invalid_namespace.close()

    unknown_legacy = socket.create_connection(("127.0.0.1", COMPONENT_PORT), timeout=10)
    unknown_legacy.sendall(
        b"<stream:stream xmlns='jabber:component:accept' "
        b"xmlns:stream='http://etherx.jabber.org/streams' to='unknown.localhost'>"
    )
    unknown_legacy_error = read_until(unknown_legacy, b"</stream:stream>")
    fixture.check(
        b"from='unknown.localhost'" in unknown_legacy_error
        and b"host-unknown" in unknown_legacy_error,
        f"legacy unknown host did not receive a complete stream error: {unknown_legacy_error!r}",
    )
    unknown_legacy.close()

    malformed_legacy = socket.create_connection(("127.0.0.1", COMPONENT_PORT), timeout=10)
    malformed_legacy.sendall(
        b"<stream:stream xmlns='jabber:component:accept' "
        b"xmlns:stream='http://etherx.jabber.org/streams'>"
    )
    malformed_legacy_error = read_until(malformed_legacy, b"</stream:stream>")
    fixture.check(
        b"improper-addressing" in malformed_legacy_error,
        f"legacy missing to address received the wrong stream error: {malformed_legacy_error!r}",
    )
    malformed_legacy.close()

    old_version = socket.create_connection(("127.0.0.1", COMPONENT_PORT), timeout=10)
    old_version.sendall(
        ("<stream:stream xmlns='jabber:client' "
         "xmlns:stream='http://etherx.jabber.org/streams' "
         f"from='{COMPONENT_DOMAIN}' to='localhost' version='0.9'>").encode()
    )
    old_version_error = read_until(old_version, b"</stream:stream>")
    fixture.check(
        b"unsupported-version" in old_version_error,
        f"modern unsupported version received the wrong stream error: {old_version_error!r}",
    )
    old_version.close()

    for tls_version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
        versioned = modern_starttls(tls_version=tls_version)
        fixture.check(
            versioned.version()
            == ("TLSv1.2" if tls_version == ssl.TLSVersion.TLSv1_2 else "TLSv1.3"),
            f"modern component did not negotiate the requested {tls_version.name}",
        )
        versioned.close()

    try:
        wrong_sni = modern_starttls(server_hostname="wrong.invalid")
    except ssl.SSLCertVerificationError:
        pass
    else:
        wrong_sni.close()
        raise AssertionError("modern component accepted a certificate for the wrong TLS name")

    oversized_auth = modern_tls_stream()
    try:
        oversized_auth.sendall(
            b"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>"
            + b"A" * (1024 * 1024 + 1)
            + b"</auth>"
        )
    except (BrokenPipeError, ConnectionResetError):
        pass
    oversized_auth_error = read_until(oversized_auth, b"</stream:stream>")
    fixture.check(
        b"policy-violation" in oversized_auth_error,
        f"oversized TLS component authentication received the wrong error: {oversized_auth_error!r}",
    )
    oversized_auth.close()

    rejected = legacy_connect("this-is-not-the-configured-component-secret")
    rejected_reply = read_until(rejected, b"</stream:stream>")
    fixture.check(b"not-authorized" in rejected_reply, "invalid legacy secret was accepted")
    rejected.close()

    sock = legacy_connect(COMPONENT_SECRET)
    authenticated = read_until(sock, b"<handshake/>")
    fixture.check(b"<handshake/>" in authenticated, "legacy component authentication failed")
    inbox = StanzaInbox(sock)

    client.send_with_pow(
        "<message xmlns='jabber:client' type='chat' id='connect-live' "
        f"to='echo@{OUTBOUND_COMPONENT_DOMAIN}'><body>live connect delivery</body></message>",
        token,
    )
    outbound_reply, _ = client.receive_until("outbound-component-reply", timeout=20)
    fixture.check(
        "outbound component reply" in outbound_reply,
        f"connect-mode component reply missing: {outbound_reply}",
    )
    client.send_with_pow(
        "<message xmlns='jabber:client' type='chat' id='connect-after-reconnect' "
        f"to='echo@{OUTBOUND_COMPONENT_DOMAIN}'><body>reconnect delivery</body></message>",
        token,
    )
    reconnect_reply, _ = client.receive_until("outbound-reconnect-reply", timeout=20)
    fixture.check(
        "outbound reconnect reply" in reconnect_reply,
        f"connect-mode reconnect reply missing: {reconnect_reply}",
    )

    duplicate = socket.create_connection(("127.0.0.1", COMPONENT_PORT), timeout=10)
    duplicate.sendall(
        ("<stream:stream xmlns='jabber:component:accept' "
         "xmlns:stream='http://etherx.jabber.org/streams' "
         f"to='{COMPONENT_DOMAIN}'>").encode()
    )
    conflict = read_until(duplicate, b"</stream:stream>")
    fixture.check(b"conflict" in conflict, f"duplicate component was not rejected: {conflict!r}")
    duplicate.close()

    durable_component = inbox.receive_id("durable-component")
    cross_component = inbox.receive_id("component-cross-route")
    fixture.check(
        b"survive restart" in durable_component,
        f"durable stanza missing or changed: {durable_component!r}",
    )
    fixture.check(
        b"component to component" in cross_component,
        f"authorized component-to-component route failed: {cross_component!r}",
    )

    room = "component-runtime-room@conference.localhost"
    client.send(
        f"<presence xmlns='jabber:client' to='{room}/LocalUser'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    local_join, _ = client.receive_until("code='110'", timeout=15)
    fixture.check("code='201'" in local_join, "local component-runtime MUC was not created")
    client.send(
        f"<iq xmlns='jabber:client' type='set' id='component-room-config' to='{room}'>"
        "<query xmlns='http://jabber.org/protocol/muc#owner'>"
        "<x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#roomconfig</value></field>"
        "<field var='muc#roomconfig_persistentroom'><value>1</value></field>"
        "</x></query></iq>"
    )
    room_configured, _ = client.receive_until("component-room-config", timeout=15)
    fixture.check(
        "type='result'" in room_configured,
        f"local component-runtime MUC configuration failed: {room_configured}",
    )
    sock.sendall(
        (f"<presence xmlns='jabber:component:accept' from='bot@{COMPONENT_DOMAIN}/runtime' "
         f"to='{room}/GatewayBot' id='component-muc-join'>"
         "<x xmlns='http://jabber.org/protocol/muc'/></presence>").encode()
    )
    muc_component_reply = inbox.receive_id("component-muc-join")
    fixture.check(
        b"muc#user" in muc_component_reply,
        f"component did not receive its local MUC admission response: {muc_component_reply!r}",
    )
    local_saw_component, _ = client.receive_until(f"from='{room}/GatewayBot'", timeout=15)
    fixture.check(
        "type='unavailable'" not in local_saw_component,
        "component MUC occupant was not admitted as an active participant",
    )

    sock.sendall(
        (f"<iq xmlns='jabber:component:accept' from='bot@{COMPONENT_DOMAIN}' "
         "to='mix.localhost' type='set' id='component-mix-create'>"
         "<create xmlns='urn:xmpp:mix:core:1' channel='component-runtime'/></iq>").encode()
    )
    mix_reply = inbox.receive_id("component-mix-create")
    fixture.check(
        b"component-mix-create" in mix_reply
        and b"type='result'" in mix_reply
        and b"<create" in mix_reply,
        f"component MIX service dispatch/response failed: {mix_reply!r}",
    )
    sock.sendall(
        (f"<iq xmlns='jabber:component:accept' from='bot@{COMPONENT_DOMAIN}' "
         "to='upload.localhost' type='get' id='component-upload-denied'>"
         "<request xmlns='urn:xmpp:http:upload:0' filename='component.bin' size='1'/></iq>").encode()
    )
    upload_reply = inbox.receive_id("component-upload-denied")
    fixture.check(
        b"component-upload-denied" in upload_reply and b"not-authorized" in upload_reply,
        f"component was not explicitly denied a local-user upload reservation: {upload_reply!r}",
    )
    sock.sendall(
        (f"<message xmlns='jabber:component:accept' from='{COMPONENT_DOMAIN}' "
         "to='recipient@allowed.remote.invalid' id='component-allowed-federation'>"
         "<body>durable allowed federation handoff</body></message>").encode()
    )
    client.send(
        "<iq xmlns='jabber:client' type='get' id='component-disco-pass' "
        f"to='{COMPONENT_DOMAIN}'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>"
    )
    component_query = inbox.receive_id("component-disco-pass")
    fixture.check(
        b"component-disco-pass" in component_query and b"disco#info" in component_query,
        f"component disco request was not transparently routed: {component_query!r}",
    )
    sock.sendall(
        (f"<iq xmlns='jabber:component:accept' from='{COMPONENT_DOMAIN}' "
         f"to='{USERNAME}@localhost/component-runtime' type='result' id='component-disco-pass'>"
         "<query xmlns='http://jabber.org/protocol/disco#info'>"
         "<identity category='gateway' type='generic' name='Runtime Component'/>"
         "<feature var='urn:xmpp:ping'/></query></iq>").encode()
    )
    component_disco, _ = client.receive_until("component-disco-pass", timeout=15)
    fixture.check("Runtime Component" in component_disco, "component disco response was not routed")

    sock.sendall(
        ("<message xmlns='jabber:component:accept' from='forged.example' "
         f"to='{USERNAME}@localhost/component-runtime' id='forged-reply'>"
         "<body>must not arrive</body></message>").encode()
    )
    forged = inbox.receive_id("forged-reply")
    fixture.check(b"not-authorized" in forged and b"type='error'" in forged,
                  f"forged component sender was not rejected: {forged!r}")

    sock.sendall(
        (f"<message xmlns='jabber:component:accept' from='{COMPONENT_DOMAIN}' "
         "to='recipient@remote.invalid' id='remote-relay'>"
         "<body>must not relay outside the federation allowlist</body></message>").encode()
    )
    remote = inbox.receive_id("remote-relay")
    fixture.check(
        b"remote-server-not-found" in remote,
        f"component acquired a remote relay route outside the federation allowlist: {remote!r}",
    )

    sock.sendall(
        (f"<message xmlns='jabber:component:accept' from='{COMPONENT_DOMAIN}' "
         f"to='{USERNAME}@localhost/component-runtime' id='component-reply'><body>component reply</body></message>").encode()
    )
    reply, _ = client.receive_until("component-reply", timeout=15)
    fixture.check("component reply" in reply, f"component-to-client route failed: {reply}")
    sock.sendall(b"</stream:stream>")
    sock.close()
    component_departed, _ = client.receive_until(f"from='{room}/GatewayBot'", timeout=15)
    fixture.check(
        "type='unavailable'" in component_departed and "code='333'" in component_departed,
        f"component disconnect did not clean up its MUC occupant: {component_departed}",
    )
    time.sleep(0.3)

    declaration = legacy_connect(COMPONENT_SECRET)
    fixture.check(
        b"<handshake/>" in read_until(declaration, b"<handshake/>"),
        "XML declaration placement fixture could not authenticate",
    )
    declaration.sendall(
        b"<?xml version='1.0'?><message xmlns='jabber:component:accept' "
        b"from='gateway.localhost' to='component-runtime@localhost'/>"
    )
    declaration_error = read_until(declaration, b"</stream:stream>")
    fixture.check(
        b"not-well-formed" in declaration_error,
        f"second XML declaration inside one component entity was accepted: {declaration_error!r}",
    )
    declaration.close()
    time.sleep(0.3)

    # Queue while no component owns the domain, then prove the Deferred
    # XEP-0225 STARTTLS/SASL/bind path drains the same durable boundary.
    client.send_with_pow(
        "<message xmlns='jabber:client' type='chat' id='modern-component' "
        f"to='echo@{COMPONENT_DOMAIN}'><body>modern queued</body></message>",
        token,
    )
    modern_tls = modern_tls_stream()
    modern_authenticate(modern_tls, retry_once=True)
    modern_inbox = StanzaInbox(modern_tls)
    modern_tls.sendall(
        ("<iq xmlns='jabber:client' type='set' id='bind-malformed'>"
         "<bind xmlns='urn:xmpp:component:0'>"
         f"<hostname>{COMPONENT_DOMAIN}</hostname></bind>"
         "<unbind xmlns='urn:xmpp:component:0'>"
         f"<hostname>{COMPONENT_DOMAIN}</hostname></unbind></iq>").encode()
    )
    malformed = modern_inbox.receive_id("bind-malformed")
    fixture.check(b"bad-request" in malformed, f"malformed multi-bind IQ accepted: {malformed!r}")
    modern_tls.sendall(
        ("<iq xmlns='jabber:client' type='set' id='bind-gateway'>"
         "<bind xmlns='urn:xmpp:component:0'>"
         f"<hostname>{COMPONENT_DOMAIN}</hostname></bind></iq>").encode()
    )
    bound = modern_inbox.receive_id("bind-gateway")
    fixture.check(b"type='result'" in bound and COMPONENT_DOMAIN.encode() in bound,
                  f"modern hostname bind failed: {bound!r}")
    modern_tls.sendall(
        ("<iq xmlns='jabber:client' type='set' id='bind-duplicate'>"
         "<bind xmlns='urn:xmpp:component:0'>"
         f"<hostname>{COMPONENT_DOMAIN}</hostname></bind></iq>").encode()
    )
    duplicate_bind = modern_inbox.receive_id("bind-duplicate")
    fixture.check(b"conflict" in duplicate_bind, "duplicate hostname bind was accepted")
    modern_tls.sendall(
        ("<iq xmlns='jabber:client' type='set' id='bind-unknown'>"
         "<bind xmlns='urn:xmpp:component:0'>"
         "<hostname>unknown.gateway.localhost</hostname></bind></iq>").encode()
    )
    unknown_bind = modern_inbox.receive_id("bind-unknown")
    fixture.check(b"not-allowed" in unknown_bind, "unconfigured hostname bind was accepted")
    modern_tls.sendall(
        ("<iq xmlns='jabber:client' type='set' id='unbind-never-bound'>"
         "<unbind xmlns='urn:xmpp:component:0'>"
         f"<hostname>{COMPONENT_ALIAS}</hostname></unbind></iq>").encode()
    )
    never_bound = modern_inbox.receive_id("unbind-never-bound")
    fixture.check(b"not-allowed" in never_bound, "never-bound hostname was unbound")
    modern_tls.sendall(
        ("<iq xmlns='jabber:client' type='set' id='bind-alias'>"
         "<bind xmlns='urn:xmpp:component:0'>"
         f"<hostname>{COMPONENT_ALIAS}</hostname></bind></iq>").encode()
    )
    alias_bound = modern_inbox.receive_id("bind-alias")
    fixture.check(b"type='result'" in alias_bound and COMPONENT_ALIAS.encode() in alias_bound,
                  f"component alias bind failed: {alias_bound!r}")
    modern_tls.sendall(
        (f"<presence xmlns='jabber:client' from='bot@{COMPONENT_ALIAS}/runtime' "
         f"to='{room}/GatewayAlias' id='component-alias-muc-join'>"
         "<x xmlns='http://jabber.org/protocol/muc'/></presence>").encode()
    )
    alias_muc_reply = modern_inbox.receive_id("component-alias-muc-join")
    fixture.check(
        b"muc#user" in alias_muc_reply,
        f"bound alias could not join the local MUC: {alias_muc_reply!r}",
    )
    alias_joined, _ = client.receive_until(f"from='{room}/GatewayAlias'", timeout=15)
    fixture.check(
        "type='unavailable'" not in alias_joined,
        "bound alias MUC occupant was not admitted",
    )
    modern_tls.sendall(
        ("<iq xmlns='jabber:client' type='set' id='unbind-alias'>"
         "<unbind xmlns='urn:xmpp:component:0'>"
         f"<hostname>{COMPONENT_ALIAS}</hostname></unbind></iq>").encode()
    )
    alias_unbound = modern_inbox.receive_id("unbind-alias")
    fixture.check(b"type='result'" in alias_unbound, f"component alias unbind failed: {alias_unbound!r}")
    alias_departed, _ = client.receive_until(f"from='{room}/GatewayAlias'", timeout=15)
    fixture.check(
        "type='unavailable'" in alias_departed and "code='333'" in alias_departed,
        f"component alias unbind did not clean up its MUC occupant: {alias_departed}",
    )
    modern_tls.sendall(
        (f"<message xmlns='jabber:client' from='{COMPONENT_ALIAS}' "
         f"to='{USERNAME}@localhost/component-runtime' id='unbound-alias'>"
         "<body>must not arrive</body></message>").encode()
    )
    unbound = modern_inbox.receive_id("unbound-alias")
    fixture.check(b"not-authorized" in unbound, "unbound component alias retained route authority")
    modern_delivery = modern_inbox.receive_id("modern-component")
    fixture.check(b"modern queued" in modern_delivery,
                  f"modern durable delivery failed: {modern_delivery!r}")
    modern_tls.sendall(
        (f"<message xmlns='jabber:client' from='{COMPONENT_DOMAIN}' "
         f"to='{USERNAME}@localhost' id='modern-reply'><body>modern reply</body></message>").encode()
    )
    modern_reply, _ = client.receive_until("modern-reply", timeout=15)
    fixture.check("modern reply" in modern_reply, "modern component reverse route failed")
    modern_tls.sendall(b"</stream:stream>")
    modern_tls.close()

    no_bind = modern_tls_stream()
    modern_authenticate(no_bind, retry_once=False)
    binding_timeout = read_until(no_bind, b"</stream:stream>")
    fixture.check(
        b"policy-violation" in binding_timeout,
        f"authenticated component could hold an unbound stream: {binding_timeout!r}",
    )
    no_bind.close()

    changed_identity = modern_starttls()
    changed_identity.sendall(
        ("<stream:stream xmlns='jabber:client' "
         "xmlns:stream='http://etherx.jabber.org/streams' "
         f"from='{COMPONENT_ALIAS}' to='localhost' version='1.0'>").encode()
    )
    changed_error = read_until(changed_identity, b"</stream:stream>")
    fixture.check(
        b"invalid-from" in changed_error,
        f"component changed its authenticated stream identity: {changed_error!r}",
    )
    changed_identity.close()

    exhausted = modern_tls_stream()
    for attempt in range(3):
        exhausted.sendall(
            b"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL'>=</auth>"
        )
        failure = read_until(exhausted, b"</failure>")
        fixture.check(
            b"invalid-mechanism" in failure,
            f"unsupported component SASL mechanism attempt {attempt + 1} was mishandled: {failure!r}",
        )
    exhausted_error = read_until(exhausted, b"</stream:stream>")
    fixture.check(
        b"policy-violation" in exhausted_error,
        f"component SASL retry ceiling did not close the stream: {exhausted_error!r}",
    )
    exhausted.close()

    fatal = modern_tls_stream()
    modern_authenticate(fatal, retry_once=False)
    fatal_inbox = StanzaInbox(fatal)
    fatal.sendall(
        ("<iq xmlns='jabber:client' type='set' id='bind-before-fatal'>"
         "<bind xmlns='urn:xmpp:component:0'>"
         f"<hostname>{COMPONENT_DOMAIN}</hostname></bind></iq>").encode()
    )
    fixture.check(
        b"type='result'" in fatal_inbox.receive_id("bind-before-fatal"),
        "fatal-frame fixture could not bind hostname",
    )
    fatal.sendall(b"<unsupported xmlns='jabber:client'/>")
    fatal_error = read_until(fatal, b"</stream:stream>")
    fixture.check(
        b"unsupported-stanza-type" in fatal_error,
        f"unsupported component frame did not produce stream error: {fatal_error!r}",
    )
    fatal.close()
    client.close()
    print("isolated XEP-0114/XEP-0225 TLS trust/name/version, encoding/size, authentication, conflict, anti-forgery, discovery, bind/unbind, deadline, crash/reconnect and bidirectional routing passed")


if __name__ == "__main__":
    commands = {
        "enqueue": enqueue,
        "component": component,
        "connect-mock": connect_mock,
        "connect-disabled-federation-mock": connect_disabled_federation_mock,
        "reader-selftest": reader_selftest,
    }
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        raise SystemExit(
            "usage: component-runtime-wsl.py enqueue|component|connect-mock|"
            "connect-disabled-federation-mock|reader-selftest"
        )
    commands[sys.argv[1]]()
