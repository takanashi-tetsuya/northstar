#!/usr/bin/env python3
"""Exercise bidirectional messaging with an independent XMPP server in the lab."""

from __future__ import annotations

import argparse
import base64
import importlib.util
import pathlib
import socket
import ssl
import sys
import time


NORTHSTAR_DOMAIN = "ns-a.lab.test"


def receive_until(conn: socket.socket, marker: str, timeout: int = 15) -> str:
    conn.settimeout(timeout)
    collected = bytearray()
    while marker.encode() not in collected:
        chunk = conn.recv(8192)
        if not chunk:
            raise RuntimeError(f"peer closed while waiting for {marker}")
        collected.extend(chunk)
        if len(collected) > 1024 * 1024:
            raise RuntimeError("peer reply exceeded 1 MiB")
    return collected.decode()


def connect_peer(
    domain: str, user: str, password: str, *, host: str | None = None,
    resource: str = "vm-lab",
) -> ssl.SSLSocket:
    stream_open = (
        "<stream:stream xmlns='jabber:client' "
        "xmlns:stream='http://etherx.jabber.org/streams' "
        f"to='{domain}' version='1.0'>"
    ).encode()
    raw = socket.create_connection((host or domain, 5222), timeout=10)
    raw.sendall(stream_open)
    features = receive_until(raw, "</stream:features>")
    assert "urn:ietf:params:xml:ns:xmpp-tls" in features, features
    raw.sendall(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
    receive_until(raw, "<proceed")
    context = ssl.create_default_context(cafile="/etc/northstar-lab-pki/ca.pem")
    conn = context.wrap_socket(raw, server_hostname=domain)
    conn.sendall(stream_open)
    features = receive_until(conn, "</stream:features>")
    assert "PLAIN" in features, features
    encoded = base64.b64encode(f"\0{user}\0{password}".encode()).decode()
    conn.sendall(
        f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{encoded}</auth>".encode()
    )
    receive_until(conn, "<success")
    conn.sendall(stream_open)
    features = receive_until(conn, "</stream:features>")
    assert "urn:ietf:params:xml:ns:xmpp-bind" in features, features
    conn.sendall(
        ("<iq type='set' id='lab-bind'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>"
         f"<resource>{resource}</resource></bind></iq>").encode()
    )
    bind = receive_until(conn, "lab-bind")
    if "type='result'" not in bind and 'type="result"' not in bind:
        bind += receive_until(conn, "</iq>")
    assert f"{user}@{domain}" in bind, bind
    conn.sendall(b"<presence/>")
    return conn


def connect_northstar_client(fixture: object, password: str):
    resource = f"vm-lab-{time.time_ns()}"
    alice = fixture.XmppWebSocket("alice", password, resource)
    try:
        # The preceding cross-node probe closes other Alice resources just
        # before this check. Wait until this exact route is advertised as the
        # preferred one before testing inbound federation delivery.
        alice.send("<presence xmlns='jabber:client'><priority>10</priority></presence>")
        presence, _ = alice.receive_until("<priority>10</priority>")
        assert f"from='alice@{NORTHSTAR_DOMAIN}/{resource}'" in presence, presence
        return alice
    except Exception:
        alice.close()
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("peer", choices=("prosody", "ejabberd"))
    parser.add_argument("--mode", choices=("both", "send", "receive"), default="both")
    parser.add_argument("--marker", help="required when receiving a queued message")
    args = parser.parse_args()
    if args.mode == "receive" and not args.marker:
        parser.error("--mode receive requires --marker")
    domain = f"{args.peer}.lab.test"
    user = "bob" if args.peer == "prosody" else "carol"
    password = pathlib.Path("/home/lab/northstar/secrets/prosody-test-password").read_text().strip()
    spec = importlib.util.spec_from_file_location(
        "northstar_integration", "/home/lab/northstar/integration-wsl.py"
    )
    assert spec and spec.loader
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    fixture.HTTP_HOST = "127.0.0.1"
    fixture.HTTP_PORT = 8080
    fixture.DOMAIN = NORTHSTAR_DOMAIN
    if args.mode == "receive":
        peer = connect_peer(domain, user, password)
        try:
            inbound = receive_until(peer, args.marker, timeout=90)
            assert args.marker in inbound, inbound
            print(f"queued message delivered to {args.peer}: {args.marker}")
        finally:
            peer.close()
        return
    if args.mode == "send":
        alice = connect_northstar_client(fixture, password)
        try:
            marker = f"lab-retry-{time.time_ns()}"
            alice.send(
                f"<message xmlns='jabber:client' to='{user}@{domain}' type='chat' "
                f"id='{marker}'><body>{marker}</body></message>"
            )
            print(marker)
        finally:
            alice.close()
        return
    peer = connect_peer(domain, user, password)
    try:
        alice = connect_northstar_client(fixture, password)
        try:
            outbound_marker = f"lab-outbound-{time.time_ns()}"
            alice.send(
                f"<message xmlns='jabber:client' to='{user}@{domain}' type='chat' "
                f"id='{outbound_marker}'><body>{outbound_marker}</body></message>"
            )
            inbound = receive_until(peer, outbound_marker)
            assert outbound_marker in inbound, inbound
            print(f"Northstar -> {args.peer}: delivered")

            inbound_marker = f"lab-inbound-{time.time_ns()}"
            peer.sendall(
                f"<message to='alice@{NORTHSTAR_DOMAIN}' type='chat' "
                f"id='{inbound_marker}'><body>{inbound_marker}</body></message>".encode()
            )
            received, _ = alice.receive_until(inbound_marker, timeout=15)
            assert inbound_marker in received, received
            print(f"{args.peer} -> Northstar: delivered")
        finally:
            alice.close()
    finally:
        peer.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"federation check failed: {error}", file=sys.stderr)
        raise
