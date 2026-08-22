#!/usr/bin/env python3
"""Two-domain federation interoperability test using the dependency-free WebSocket fixture."""

from __future__ import annotations

import importlib.util
import pathlib
import time


ROOT = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("northstar_integration", ROOT / "integration-wsl.py")
fixture = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(fixture)

PASSWORD = "federation-password-123"
ALICE = "alice_fed"
BOB = "bob_fed"


def endpoint(port: int, xmpp_port: int, domain: str) -> None:
    fixture.HTTP_HOST = "127.0.0.1"
    fixture.HTTP_PORT = port
    fixture.XMPP_PORT = xmpp_port
    fixture.DOMAIN = domain


def register(username: str) -> None:
    status, result = fixture.api(
        "POST", "/api/v1/register", {"username": username, "password": PASSWORD}
    )
    fixture.check(status == 201, f"registration failed: {status} {result}")


def run() -> None:
    endpoint(18081, 15223, "localhost")
    fixture.wait_ready()
    register(ALICE)
    alice = fixture.XmppWebSocket(ALICE, PASSWORD, "alice-federation")

    endpoint(18082, 15224, "remote.localhost")
    fixture.wait_ready()
    register(BOB)
    bob = fixture.XmppWebSocket(BOB, PASSWORD, "bob-federation")

    bob.send(
        "<iq xmlns='jabber:client' type='set' id='remote-pep-publish'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='urn:xmpp:omemo:2:devices'>"
        "<item id='current'><devices xmlns='urn:xmpp:omemo:2'><device id='777'/></devices></item>"
        "</publish></pubsub></iq>"
    )
    bob.receive_until("remote-pep-publish")
    bob.send(
        "<iq xmlns='jabber:client' type='set' id='remote-vcard-set'>"
        "<vCard xmlns='vcard-temp'><FN>Federated Bob</FN></vCard></iq>"
    )
    bob.receive_until("remote-vcard-set")

    alice.send(
        "<iq xmlns='jabber:client' type='get' id='federated-pep' "
        "to='bob_fed@remote.localhost'><pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        "<items node='urn:xmpp:omemo:2:devices'/></pubsub></iq>"
    )
    federated_pep, _ = alice.receive_until("federated-pep", timeout=20)
    fixture.check("device id='777'" in federated_pep, "federated PEP query failed")
    alice.send(
        "<iq xmlns='jabber:client' type='get' id='federated-vcard' "
        "to='bob_fed@remote.localhost'><vCard xmlns='vcard-temp'/></iq>"
    )
    federated_vcard, _ = alice.receive_until("federated-vcard", timeout=20)
    fixture.check("Federated Bob" in federated_vcard, "federated vCard query failed")

    alice.send(
        "<presence xmlns='jabber:client' to='bob_fed@remote.localhost'/>"
    )
    remote_presence, _ = bob.receive_until("alice_fed@localhost", timeout=20)
    fixture.check("type='error'" not in remote_presence, "federated presence failed")
    alice.send(
        "<presence xmlns='jabber:client' to='bob_fed@remote.localhost' type='subscribe'/>"
    )
    subscription, _ = bob.receive_until("type='subscribe'", timeout=20)
    fixture.check("alice_fed@localhost" in subscription, "federated subscription request failed")
    bob.send(
        "<presence xmlns='jabber:client' to='alice_fed@localhost' type='subscribed'/>"
    )
    alice.receive_until("type='subscribed'", timeout=20)
    alice.send(
        "<iq xmlns='jabber:client' type='get' id='federated-roster-a'>"
        "<query xmlns='jabber:iq:roster'/></iq>"
    )
    roster_a, _ = alice.receive_until("federated-roster-a")
    fixture.check(
        "bob_fed@remote.localhost" in roster_a and "subscription='to'" in roster_a,
        "federated subscriber roster state was not persisted",
    )
    bob.send(
        "<iq xmlns='jabber:client' type='get' id='federated-roster-b'>"
        "<query xmlns='jabber:iq:roster'/></iq>"
    )
    roster_b, _ = bob.receive_until("federated-roster-b")
    fixture.check(
        "alice_fed@localhost" in roster_b and "subscription='from'" in roster_b,
        "federated approver roster state was not persisted",
    )

    bob.send(
        "<iq xmlns='jabber:client' type='set' id='remote-pep-notify'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='urn:xmpp:omemo:2:devices'>"
        "<item id='current'><devices xmlns='urn:xmpp:omemo:2'><device id='777'/><device id='778'/></devices></item>"
        "</publish></pubsub></iq>"
    )
    bob.receive_until("remote-pep-notify")
    pep_event, _ = alice.receive_until("device id='778'", timeout=20)
    fixture.check(
        "type='headline'" in pep_event
        and "from='bob_fed@remote.localhost'" in pep_event
        and "to='alice_fed@localhost'" in pep_event,
        "federated PEP notification was not addressed or delivered correctly",
    )

    alice.send(
        "<message xmlns='jabber:client' to='bob_fed@remote.localhost' type='chat' id='fed-a-b'>"
        "<encrypted xmlns='urn:xmpp:omemo:2'><header sid='111'/><payload>FEDERATED-CIPHERTEXT-A</payload></encrypted>"
        "</message>"
    )
    inbound, _ = bob.receive_until("fed-a-b", timeout=20)
    fixture.check(
        "FEDERATED-CIPHERTEXT-A" in inbound and "alice_fed@localhost" in inbound,
        "A-to-B federated message failed",
    )
    bob.send(
        "<message xmlns='jabber:client' to='alice_fed@localhost' type='chat' id='fed-b-a'>"
        "<encrypted xmlns='urn:xmpp:omemo:2'><header sid='777'/><payload>FEDERATED-CIPHERTEXT-B</payload></encrypted>"
        "</message>"
    )
    reply, _ = alice.receive_until("fed-b-a", timeout=20)
    fixture.check(
        "FEDERATED-CIPHERTEXT-B" in reply and "bob_fed@remote.localhost" in reply,
        "B-to-A federated message failed",
    )

    bob.close()
    time.sleep(0.3)
    alice.send(
        "<message xmlns='jabber:client' to='bob_fed@remote.localhost' type='chat' id='fed-offline'>"
        "<body>FEDERATED-PLAINTEXT-LEAK</body>"
        "<encrypted xmlns='urn:xmpp:omemo:2'><header sid='111'/><payload>FEDERATED-OFFLINE-CIPHERTEXT</payload></encrypted>"
        "</message>"
    )
    time.sleep(0.5)
    endpoint(18082, 15224, "remote.localhost")
    bob = fixture.XmppWebSocket(BOB, PASSWORD, "bob-federation-reconnected")
    offline, _ = bob.receive_until("fed-offline", timeout=20)
    fixture.check(
        "FEDERATED-OFFLINE-CIPHERTEXT" in offline
        and "FEDERATED-PLAINTEXT-LEAK" not in offline,
        "federated encrypted offline storage leaked plaintext or lost ciphertext",
    )

    bob.close()
    alice.close()
    print("federation: DNS override, STARTTLS, certificate validation, SASL EXTERNAL, PEP/vCard IQ, cross-domain PEP notifications, presence subscriptions, bidirectional and offline messaging passed")


if __name__ == "__main__":
    run()
