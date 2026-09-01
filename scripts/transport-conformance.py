#!/usr/bin/env python3
"""Dependency-free BOSH/RFC 7395 smoke test against an already running server.

This script never starts or stops Northstar. Example for a local development
instance (the default TRUSTED_PROXY_IPS includes loopback):

    python3 scripts/transport-conformance.py \
      --bosh http://127.0.0.1:8080/http-bind \
      --websocket ws://127.0.0.1:8080/xmpp-websocket \
      --domain localhost

Use wss/https for a deployed instance. `--insecure` is intentionally explicit
and exists only for a manually approved development certificate.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import os
import socket
import ssl
import struct
import sys
import urllib.parse
import xml.etree.ElementTree as ET


BOSH_NS = "http://jabber.org/protocol/httpbind"
FRAMING_NS = "urn:ietf:params:xml:ns:xmpp-framing"


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def ssl_context(insecure: bool) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def open_socket(url: urllib.parse.SplitResult, insecure: bool) -> socket.socket:
    port = url.port or (443 if url.scheme in {"https", "wss"} else 80)
    sock = socket.create_connection((url.hostname, port), timeout=8)
    if url.scheme in {"https", "wss"}:
        sock = ssl_context(insecure).wrap_socket(sock, server_hostname=url.hostname)
    sock.settimeout(8)
    return sock


def loopback_host(host: str | None) -> bool:
    return host in {"localhost", "127.0.0.1", "::1"}


def read_http_head(sock: socket.socket) -> bytes:
    response = bytearray()
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response.extend(chunk)
        check(len(response) <= 64 * 1024, "HTTP upgrade response is too large")
    return bytes(response)


class RawWebSocket:
    def __init__(
        self,
        endpoint: str,
        domain: str,
        insecure: bool,
        origin: str | None = None,
        subprotocol: str | None = "xmpp",
    ) -> None:
        self.url = urllib.parse.urlsplit(endpoint)
        check(self.url.scheme in {"ws", "wss"}, "WebSocket URL must use ws or wss")
        check(bool(self.url.hostname), "WebSocket URL requires a host")
        self.sock = open_socket(self.url, insecure)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        authority = self.url.netloc
        path = urllib.parse.urlunsplit(("", "", self.url.path or "/", self.url.query, ""))
        headers = [
            f"GET {path} HTTP/1.1",
            f"Host: {authority}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {key}",
            "Sec-WebSocket-Version: 13",
        ]
        if origin is not None:
            headers.append(f"Origin: {origin}")
        if subprotocol is not None:
            headers.append(f"Sec-WebSocket-Protocol: {subprotocol}")
        if self.url.scheme == "ws" and loopback_host(self.url.hostname):
            # The local HTTP listener is the trusted-proxy side of the
            # deployment boundary. This lets the probe exercise that boundary
            # without pretending that public ws:// is acceptable.
            headers.append("X-Forwarded-Proto: https")
        self.sock.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))
        response = read_http_head(self.sock)
        check(response.startswith(b"HTTP/1.1 101"), f"WebSocket upgrade failed: {response!r}")
        check(
            b"sec-websocket-protocol: xmpp" in response.lower(),
            "upgrade response omitted the exact xmpp subprotocol",
        )
        expected = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()
        )
        check(expected.lower() in response.lower(), "invalid Sec-WebSocket-Accept")
        self.domain = domain

    def send_frame(self, opcode: int, payload: bytes, fin: bool = True) -> None:
        first = (0x80 if fin else 0) | opcode
        mask = os.urandom(4)
        length = len(payload)
        if length < 126:
            header = bytes((first, 0x80 | length))
        elif length <= 0xFFFF:
            header = bytes((first, 0x80 | 126)) + struct.pack("!H", length)
        else:
            header = bytes((first, 0x80 | 127)) + struct.pack("!Q", length)
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self.sock.sendall(header + mask + masked)

    def send_text(self, value: str) -> None:
        self.send_frame(1, value.encode("utf-8"))

    def send_fragmented_text(self, value: str) -> None:
        payload = value.encode("utf-8")
        cut = max(1, len(payload) // 2)
        self.send_frame(1, payload[:cut], fin=False)
        self.send_frame(0, payload[cut:], fin=True)

    def send_fragmented_binary(self, payload: bytes) -> None:
        cut = max(1, len(payload) // 2)
        self.send_frame(2, payload[:cut], fin=False)
        self.send_frame(0, payload[cut:], fin=True)

    def receive(self) -> tuple[int, bytes]:
        first = self.sock.recv(2)
        check(len(first) == 2, "WebSocket closed before a complete frame header")
        opcode = first[0] & 0x0F
        length = first[1] & 0x7F
        check(first[1] & 0x80 == 0, "server WebSocket frames must not be masked")
        if length == 126:
            length = struct.unpack("!H", self._read_exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._read_exact(8))[0]
        payload = self._read_exact(length)
        if opcode == 9:
            self.send_frame(10, payload)
            return self.receive()
        return opcode, payload

    def receive_text(self) -> str:
        opcode, payload = self.receive()
        check(opcode == 1, f"expected text frame, got opcode {opcode}")
        return payload.decode("utf-8")

    def _read_exact(self, length: int) -> bytes:
        data = bytearray()
        while len(data) < length:
            chunk = self.sock.recv(length - len(data))
            check(bool(chunk), "WebSocket closed inside a frame")
            data.extend(chunk)
        return bytes(data)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


def assert_upgrade_rejects_missing_subprotocol(endpoint: str, insecure: bool) -> None:
    url = urllib.parse.urlsplit(endpoint)
    sock = open_socket(url, insecure)
    try:
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        path = urllib.parse.urlunsplit(("", "", url.path or "/", url.query, ""))
        request = (
            f"GET {path} HTTP/1.1\r\nHost: {url.netloc}\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
        )
        if url.scheme == "ws" and loopback_host(url.hostname):
            request += "X-Forwarded-Proto: https\r\n"
        request += "\r\n"
        sock.sendall(request.encode("ascii"))
        check(not read_http_head(sock).startswith(b"HTTP/1.1 101"), "upgrade accepted without xmpp")
    finally:
        sock.close()


def open_stream(ws: RawWebSocket, fragmented: bool = False) -> None:
    opening = f"<open xmlns='{FRAMING_NS}' to='{ws.domain}' version='1.0'/>"
    (ws.send_fragmented_text if fragmented else ws.send_text)(opening)
    check(ws.receive_text().startswith("<open "), "server did not answer with an open frame")
    check("features" in ws.receive_text(), "server did not send stream features separately")


def expect_opening_error_sequence(ws: RawWebSocket, condition: str) -> None:
    # RFC 7395 section 3.5 requires this server <open/> before an error raised
    # while the peer's opening frame is being processed. It is part of the
    # failure sequence, not evidence that the offending frame was accepted.
    check(ws.receive_text().startswith("<open "), "opening error was not preceded by server open")
    check(condition in ws.receive_text(), f"missing {condition} stream error")
    check("<close " in ws.receive_text(), "XMPP close frame missing after stream error")
    opcode, _ = ws.receive()
    check(opcode == 8, "WebSocket closing handshake was not initiated")


def expect_opening_error(ws: RawWebSocket, payload: str, condition: str) -> None:
    ws.send_text(payload)
    expect_opening_error_sequence(ws, condition)


def expect_binary_opening_rejected(ws: RawWebSocket, fragmented: bool = False) -> None:
    # The XML is deliberately a completely valid RFC 7395 opening. A parser
    # that wrongly converted opcode 0x2 to text would accept it and return
    # stream features, so this fixture distinguishes opcode handling from XML
    # syntax rejection.
    payload = (
        f"<open xmlns='{FRAMING_NS}' to='{ws.domain}' version='1.0'/>".encode("utf-8")
    )
    if fragmented:
        ws.send_fragmented_binary(payload)
    else:
        ws.send_frame(2, payload)
    expect_opening_error_sequence(ws, "unsupported-stanza-type")


def expect_established_stream_binary_rejected(ws: RawWebSocket) -> None:
    # After an ordinary text opening there is no RFC 7395 server-open prelude
    # to confuse the result: the first reply must be the terminal stream
    # error. The payload would otherwise be a valid XMPP ping request.
    payload = (
        "<iq xmlns='jabber:client' type='get' id='binary-ping'>"
        "<ping xmlns='urn:xmpp:ping'/></iq>"
    ).encode("utf-8")
    ws.send_frame(2, payload)
    error = ws.receive_text()
    check(
        "unsupported-stanza-type" in error and "binary-ping" not in error,
        f"established-stream binary frame was not rejected: {error}",
    )
    check("<close " in ws.receive_text(), "XMPP close frame missing after binary rejection")
    check(ws.receive()[0] == 8, "WebSocket close missing after binary rejection")


def test_websocket(endpoint: str, domain: str, insecure: bool) -> None:
    assert_upgrade_rejects_missing_subprotocol(endpoint, insecure)
    origin = "http://localhost"

    ws = RawWebSocket(endpoint, domain, insecure, origin)
    try:
        open_stream(ws, fragmented=True)
        ws.send_text(f"<close xmlns='{FRAMING_NS}'/>")
        check("<close " in ws.receive_text(), "server did not acknowledge XMPP close")
        check(ws.receive()[0] == 8, "server did not initiate WebSocket close")
    finally:
        ws.close()

    for payload, condition in [
        (f"<open xmlns='urn:invalid' to='{domain}' version='1.0'/>", "invalid-namespace"),
        (f" <open xmlns='{FRAMING_NS}' to='{domain}' version='1.0'/>", "not-well-formed"),
    ]:
        ws = RawWebSocket(endpoint, domain, insecure, origin)
        try:
            expect_opening_error(ws, payload, condition)
        finally:
            ws.close()

    for fragmented in (False, True):
        ws = RawWebSocket(endpoint, domain, insecure, origin)
        try:
            expect_binary_opening_rejected(ws, fragmented)
        finally:
            ws.close()

    ws = RawWebSocket(endpoint, domain, insecure, origin)
    try:
        open_stream(ws)
        expect_established_stream_binary_rejected(ws)
    finally:
        ws.close()


def bosh_post(endpoint: str, body: str, insecure: bool) -> bytes:
    url = urllib.parse.urlsplit(endpoint)
    check(url.scheme in {"http", "https"}, "BOSH URL must use http or https")
    connection_type = http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection
    kwargs = {"timeout": 8}
    if url.scheme == "https":
        kwargs["context"] = ssl_context(insecure)
    connection = connection_type(url.hostname, url.port, **kwargs)
    path = urllib.parse.urlunsplit(("", "", url.path or "/", url.query, ""))
    connection.request(
        "POST",
        path,
        body=body.encode("utf-8"),
        headers={"Content-Type": "text/plain", "X-Forwarded-Proto": "https"},
    )
    response = connection.getresponse()
    data = response.read()
    connection.close()
    check(response.status == 200, f"BOSH returned HTTP {response.status}: {data!r}")
    return data


def sha1_hex(value: str) -> str:
    return hashlib.sha1(value.encode("ascii")).hexdigest()


def test_bosh(endpoint: str, domain: str, insecure: bool) -> None:
    rid = int.from_bytes(os.urandom(6), "big") + 100
    k0 = os.urandom(20).hex()
    k1, k2, k3 = sha1_hex(k0), "", ""
    k2 = sha1_hex(k1)
    k3 = sha1_hex(k2)
    creation = (
        "<?xml version='1.0' encoding='UTF-8'?>"
        f"<body xmlns='{BOSH_NS}' xmlns:xmpp='urn:xmpp:xbosh' rid='{rid}' "
        f"to='{domain}' wait='0' hold='0' ver='1.11' ack='1' newkey='{k3}' "
        "xmpp:version='1.0'/>"
    )
    created = bosh_post(endpoint, creation, insecure)
    root = ET.fromstring(created)
    sid = root.attrib.get("sid")
    check(bool(sid), f"BOSH creation did not return a SID: {created!r}")
    check(root.attrib.get("ack") == str(rid), "BOSH creation did not acknowledge its RID")

    request = f"<body xmlns='{BOSH_NS}' rid='{rid + 1}' sid='{sid}' key='{k2}'/>"
    first = bosh_post(endpoint, request, insecure)
    repeated = bosh_post(endpoint, request, insecure)
    check(first == repeated, "duplicate RID did not replay the byte-identical response")

    terminate = (
        f"<body xmlns='{BOSH_NS}' rid='{rid + 2}' sid='{sid}' ack='{rid + 1}' "
        f"key='{k1}' type='terminate'/>"
    )
    terminated = ET.fromstring(bosh_post(endpoint, terminate, insecure))
    check(terminated.attrib.get("type") == "terminate", "BOSH did not terminate cleanly")

    rid += 10
    created = ET.fromstring(
        bosh_post(
            endpoint,
            f"<body xmlns='{BOSH_NS}' rid='{rid}' to='{domain}' wait='0' hold='0' newkey='{k3}'/>",
            insecure,
        )
    )
    sid = created.attrib["sid"]
    invalid = ET.fromstring(
        bosh_post(
            endpoint,
            f"<body xmlns='{BOSH_NS}' rid='{rid + 1}' sid='{sid}' key='{'0' * 40}'/>",
            insecure,
        )
    )
    check(
        invalid.attrib.get("type") == "terminate"
        and invalid.attrib.get("condition") == "item-not-found",
        "invalid BOSH key sequence was not terminated with item-not-found",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bosh", required=True, help="BOSH endpoint URL")
    parser.add_argument("--websocket", required=True, help="WebSocket endpoint URL")
    parser.add_argument("--domain", required=True, help="XMPP service domain")
    parser.add_argument("--insecure", action="store_true", help="accept a development TLS certificate")
    args = parser.parse_args()
    test_bosh(args.bosh, args.domain, args.insecure)
    print("BOSH: creation, XML declaration, media-type tolerance, replay, ack, key chain and terminate passed")
    test_websocket(args.websocket, args.domain, args.insecure)
    print("WebSocket: subprotocol, text fragmentation, binary rejection, framing errors and two-layer close passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, OSError, ET.ParseError) as error:
        print(f"transport conformance FAILED: {error}", file=sys.stderr)
        raise SystemExit(1)
