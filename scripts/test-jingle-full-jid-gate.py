#!/usr/bin/env python3
"""Real-wire regression for directional full-JID Jingle authorization."""

from __future__ import annotations

import importlib.util
import pathlib


ROOT = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "northstar_integration", ROOT / "integration-wsl.py"
)
assert spec is not None and spec.loader is not None
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def main() -> None:
    fixture.wait_ready()
    for username in (fixture.ALICE, fixture.BOB):
        status, result = fixture.register_account(username, fixture.PASSWORD)
        fixture.check(
            status == 201,
            f"registration failed for {username}: {status} {result}",
        )

    rest_tokens: dict[str, str] = {}
    for username in (fixture.ALICE, fixture.BOB):
        status, result = fixture.api(
            "POST",
            "/api/v1/login",
            {"username": username, "password": fixture.PASSWORD},
        )
        fixture.check(status == 200, f"REST login failed for {username}: {status} {result}")
        token = result["token"]
        status, me = fixture.api("GET", "/api/v1/me", token=token)
        fixture.check(
            status == 200 and me.get("jid") == f"{username}@{fixture.DOMAIN}",
            f"fresh REST bearer was not bound to {username}: {status} {me}",
        )
        rest_tokens[username] = token
    alice = fixture.XmppWebSocket(fixture.ALICE, fixture.PASSWORD, "alice-web")
    bob = fixture.XmppWebSocket(fixture.BOB, fixture.PASSWORD, "bob-web")
    try:
        # A directed presence grant is directional. Bob makes his exact
        # resource visible to Alice, while Alice has not yet authorized Bob.
        bob.send(
            f"<presence xmlns='jabber:client' "
            f"to='{fixture.ALICE}@{fixture.DOMAIN}/alice-web'>"
            "<show>chat</show><status>bob-authorizes-alice</status></presence>"
        )
        bob_grant, _ = alice.receive_until("bob-authorizes-alice")
        fixture.check(
            f"from='{fixture.BOB}@{fixture.DOMAIN}/bob-web'" in bob_grant,
            f"Bob's directed presence was not delivered: {bob_grant}",
        )

        alice.send(
            f"<iq xmlns='jabber:client' type='set' id='jingle-gate-init' "
            f"to='{fixture.BOB}@{fixture.DOMAIN}/bob-web'>"
            "<jingle xmlns='urn:xmpp:jingle:1' action='session-initiate' "
            "sid='jingle-gate-session'>"
            "<content creator='initiator' name='file'>"
            "<description xmlns='urn:xmpp:jingle:apps:file-transfer:5'><file>"
            "<name>cipher.bin</name><size>4</size></file></description>"
            "<transport xmlns='urn:xmpp:jingle:transports:s5b:1' sid='stream-1'/>"
            "</content></jingle></iq>"
        )
        offer, _ = bob.receive_until("jingle-gate-init")
        fixture.check(
            "urn:xmpp:jingle:apps:file-transfer:5" in offer,
            f"authorized Jingle offer was not routed intact: {offer}",
        )
        bob.send(
            f"<iq xmlns='jabber:client' type='result' id='jingle-gate-init' "
            f"to='{fixture.ALICE}@{fixture.DOMAIN}/alice-web'/>"
        )
        result, _ = alice.receive_until("jingle-gate-init")
        fixture.check("type='result'" in result, f"Jingle result was not routed: {result}")

        bob.send(
            f"<iq xmlns='jabber:client' type='set' id='jingle-gate-denied' "
            f"to='{fixture.ALICE}@{fixture.DOMAIN}/alice-web'>"
            "<jingle xmlns='urn:xmpp:jingle:1' action='session-info' "
            "sid='jingle-gate-session'>"
            "<checksum xmlns='urn:xmpp:jingle:apps:file-transfer:5' "
            "creator='initiator' name='file'><file>"
            "<hash xmlns='urn:xmpp:hashes:2' algo='sha-256'>AA==</hash>"
            "</file></checksum></jingle></iq>"
        )
        denied, _ = bob.receive_until("jingle-gate-denied")
        fixture.check(
            "type='error'" in denied and "service-unavailable" in denied,
            f"unauthorized reverse full-JID IQ was not denied: {denied}",
        )

        alice.send(
            f"<presence xmlns='jabber:client' "
            f"to='{fixture.BOB}@{fixture.DOMAIN}/bob-web'>"
            "<show>chat</show><status>alice-authorizes-bob</status></presence>"
        )
        alice_grant, _ = bob.receive_until("alice-authorizes-bob")
        fixture.check(
            f"from='{fixture.ALICE}@{fixture.DOMAIN}/alice-web'" in alice_grant,
            f"Alice's directed presence was not delivered: {alice_grant}",
        )
        bob.send(
            f"<iq xmlns='jabber:client' type='set' id='jingle-gate-authorized' "
            f"to='{fixture.ALICE}@{fixture.DOMAIN}/alice-web'>"
            "<jingle xmlns='urn:xmpp:jingle:1' action='session-info' "
            "sid='jingle-gate-session'>"
            "<checksum xmlns='urn:xmpp:jingle:apps:file-transfer:5' "
            "creator='initiator' name='file'><file>"
            "<hash xmlns='urn:xmpp:hashes:2' algo='sha-256'>AA==</hash>"
            "</file></checksum></jingle></iq>"
        )
        authorized, _ = alice.receive_until("jingle-gate-authorized")
        fixture.check(
            "urn:xmpp:jingle:apps:file-transfer:5" in authorized
            and "urn:xmpp:hashes:2" in authorized,
            f"authorized reverse Jingle IQ was not routed intact: {authorized}",
        )
    finally:
        alice.close()
        bob.close()

    print("Directional full-JID Jingle authorization wire test passed")


if __name__ == "__main__":
    main()
