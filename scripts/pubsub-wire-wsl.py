#!/usr/bin/env python3
"""Isolated real-wire and restart audit for the advertised XEP-0060 profile."""

from __future__ import annotations

import importlib.util
import os
import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("northstar_integration", ROOT / "integration-wsl.py")
fixture = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(fixture)

PASSWORD = "pubsub-wire-password-123"
ALICE = "pubsub_wire_alice"
BOB = "pubsub_wire_bob"


def configure_endpoint() -> None:
    fixture.HTTP_HOST = os.environ.get("XMPP_TEST_HOST", "127.0.0.1")
    fixture.HTTP_PORT = int(os.environ["XMPP_TEST_HTTP_PORT"])
    fixture.XMPP_PORT = int(os.environ["XMPP_TEST_CLIENT_PORT"])
    fixture.DOMAIN = os.environ.get("XMPP_TEST_DOMAIN", "localhost")


def register(username: str) -> None:
    status, result = fixture.register_account(username, PASSWORD)
    fixture.check(status == 201, f"registration failed for {username}: {status} {result}")


def setup_restart_queue() -> None:
    fixture.wait_ready()
    register(ALICE)
    register(BOB)
    alice = fixture.XmppWebSocket(ALICE, PASSWORD, "setup-alice")
    bob = fixture.XmppWebSocket(BOB, PASSWORD, "setup-bob")
    service = f"pubsub.{fixture.DOMAIN}"
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='digest-create' to='{service}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><create node='wire/digest'/></pubsub></iq>"
    )
    created, _ = alice.receive_until("digest-create")
    fixture.check("type='result'" in created, f"digest node creation failed: {created}")
    bob.send(
        f"<iq xmlns='jabber:client' type='set' id='digest-subscribe' to='{service}'>"
        f"<pubsub xmlns='http://jabber.org/protocol/pubsub'><subscribe node='wire/digest' jid='{BOB}@{fixture.DOMAIN}'/>"
        "<options><x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#subscribe_options</value></field>"
        "<field var='pubsub#digest'><value>true</value></field>"
        "<field var='pubsub#digest_frequency'><value>1000</value></field>"
        "</x></options></pubsub></iq>"
    )
    subscribed, _ = bob.receive_until("digest-subscribe")
    fixture.check("subscription='subscribed'" in subscribed, f"digest subscription failed: {subscribed}")
    bob.abort()
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='digest-publish' to='{service}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='wire/digest'>"
        "<item id='restart-item'><value xmlns='urn:wire'>RESTART-DIGEST-EVENT</value></item>"
        "</publish></pubsub></iq>"
    )
    published, _ = alice.receive_until("digest-publish")
    fixture.check("type='result'" in published, f"digest publication failed: {published}")
    alice.close()
    print("PubSub restart setup: durable digest queued while subscriber offline")


def finish_profile() -> None:
    fixture.wait_ready()
    bob = fixture.XmppWebSocket(BOB, PASSWORD, "finish-bob")
    # Becoming available has two independent, standards-visible effects here:
    # the persisted digest is retried after restart, and send_last_published_item
    # replays the node's current item with XEP-0203 delay metadata.  Their
    # scheduling order is deliberately unspecified.  The outbox worker may
    # claim the pre-restart digest before presence enqueues the delayed
    # last-item replay, so they can be one batched headline or two ordered
    # headlines. Classify the logical events rather than assuming one batch.
    restarted = bob.receive_until("RESTART-DIGEST-EVENT", timeout=20)[0]
    deliveries = restarted
    if deliveries.count("RESTART-DIGEST-EVENT") < 2:
        deliveries += bob.receive_until("RESTART-DIGEST-EVENT", timeout=20)[0]
    fixture.check(
        deliveries.count("RESTART-DIGEST-EVENT") == 2
        and deliveries.count("urn:xmpp:delay") == 1,
        f"expected one delayed last-item replay and one ordinary event after restart: {deliveries}",
    )
    try:
        duplicate, _ = bob.receive_until("RESTART-DIGEST-EVENT", timeout=2)
    except TimeoutError:
        pass
    else:
        raise AssertionError(f"restart produced a duplicate PubSub delivery: {duplicate}")
    alice = fixture.XmppWebSocket(ALICE, PASSWORD, "finish-alice")
    service = f"pubsub.{fixture.DOMAIN}"

    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='profile-disco' to='{service}'>"
        "<query xmlns='http://jabber.org/protocol/disco#info'/></iq>"
    )
    disco, _ = alice.receive_until("profile-disco")
    for feature in (
        "auto-create",
        "collections",
        "leased-subscription",
        "manage-subscriptions",
        "multi-collections",
        "publish-options",
        "rsm",
        "subscription-notifications",
        "subscription-options",
    ):
        fixture.check(f"pubsub#{feature}" in disco, f"advertised profile omitted {feature}")

    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='collection-create' to='{service}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><create node='wire/collection'/>"
        "<configure><x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#node_config</value></field>"
        "<field var='pubsub#node_type'><value>collection</value></field>"
        "</x></configure></pubsub></iq>"
    )
    fixture.check(
        "type='result'" in alice.receive_until("collection-create")[0],
        "collection creation failed",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='collection-config' to='{service}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub#owner'>"
        "<configure node='wire/collection'/></pubsub></iq>"
    )
    collection_config = alice.receive_until("collection-config")[0]
    fixture.check(
        "pubsub#children_association_policy" in collection_config
        and "<value>owners</value>" in collection_config,
        f"collection policy did not use the registered owners value: {collection_config}",
    )
    bob.send(
        f"<iq xmlns='jabber:client' type='set' id='collection-subscribe' to='{service}'>"
        f"<pubsub xmlns='http://jabber.org/protocol/pubsub'><subscribe node='wire/collection' jid='{BOB}@{fixture.DOMAIN}/finish-bob'/></pubsub></iq>"
    )
    fixture.check(
        "subscription='subscribed'" in bob.receive_until("collection-subscribe")[0],
        "collection subscription failed",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='collection-child-create' to='{service}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><create node='wire/collection-child'/>"
        "<configure><x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#node_config</value></field>"
        "<field var='pubsub#collection'><value>wire/collection</value></field>"
        "</x></configure></pubsub></iq>"
    )
    fixture.check(
        "type='result'" in alice.receive_until("collection-child-create")[0],
        "child creation with collection failed",
    )
    created_event = bob.receive_until("<create node='wire/collection-child'")[0]
    fixture.check(
        "<header name='Collection'>wire/collection</header>" in created_event,
        f"collection create notification omitted Collection SHIM: {created_event}",
    )
    for request_id in ("collection-dissociate", "collection-dissociate-again"):
        alice.send(
            f"<iq xmlns='jabber:client' type='set' id='{request_id}' to='{service}'>"
            "<pubsub xmlns='http://jabber.org/protocol/pubsub#owner'>"
            "<collection node='wire/collection'><dissociate node='wire/collection-child'/></collection>"
            "</pubsub></iq>"
        )
        response = alice.receive_until(request_id)[0]
        if request_id == "collection-dissociate":
            fixture.check("type='result'" in response, f"collection dissociation failed: {response}")
        else:
            fixture.check(
                "type='error'" in response and "bad-request" in response,
                f"missing collection edge did not return bad-request: {response}",
            )

    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='profile-create' to='{service}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><create node='wire/profile'/>"
        "<configure><x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#node_config</value></field>"
        "<field var='pubsub#max_items'><value>2</value></field>"
        "<field var='pubsub#type'><value>urn:wire</value></field>"
        "</x></configure></pubsub></iq>"
    )
    created, _ = alice.receive_until("profile-create")
    fixture.check("type='result'" in created, f"create-and-configure failed: {created}")
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='profile-grants' to='{service}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub#owner'>"
        f"<affiliations node='wire/profile'><affiliation jid='{BOB}@{fixture.DOMAIN}' affiliation='publisher'/></affiliations>"
        "</pubsub></iq>"
    )
    fixture.check("type='result'" in alice.receive_until("profile-grants")[0], "publisher grant failed")
    bob.receive_until("affiliation='publisher'")
    bob.send(
        f"<iq xmlns='jabber:client' type='set' id='profile-subscribe' to='{service}'>"
        f"<pubsub xmlns='http://jabber.org/protocol/pubsub'><subscribe node='wire/profile' jid='{BOB}@{fixture.DOMAIN}/finish-bob'/></pubsub></iq>"
    )
    full_subscription = bob.receive_until("profile-subscribe")[0]
    fixture.check(
        "subscription='subscribed'" in full_subscription
        and f"jid='{BOB}@{fixture.DOMAIN}/finish-bob'" in full_subscription,
        f"full-JID subscription was not preserved: {full_subscription}",
    )

    bob.send(
        f"<iq xmlns='jabber:client' type='set' id='batch-too-large' to='{service}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='wire/profile'>"
        "<item id='b1'><v xmlns='urn:wire'>1</v></item><item id='b2'><v xmlns='urn:wire'>2</v></item>"
        "<item id='b3'><v xmlns='urn:wire'>3</v></item></publish></pubsub></iq>"
    )
    too_large, _ = bob.receive_until("batch-too-large")
    fixture.check(
        "type='error'" in too_large and "max-items-exceeded" in too_large,
        f"oversized batch was not rejected: {too_large}",
    )
    bob.send(
        f"<iq xmlns='jabber:client' type='set' id='wrong-payload' to='{service}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='wire/profile'>"
        "<item id='wrong'><v xmlns='urn:wrong'>wrong</v></item></publish></pubsub></iq>"
    )
    wrong, _ = bob.receive_until("wrong-payload")
    fixture.check("invalid-payload" in wrong, f"payload namespace mismatch was accepted: {wrong}")
    bob.send(
        f"<iq xmlns='jabber:client' type='set' id='publisher-write' to='{service}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='wire/profile'>"
        "<item id='shared'><v xmlns='urn:wire'>publisher value</v></item></publish></pubsub></iq>"
    )
    fixture.check("type='result'" in bob.receive_until("publisher-write")[0], "publisher write failed")
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='owner-overwrite' to='{service}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='wire/profile'>"
        "<item id='shared'><v xmlns='urn:wire'>owner replacement</v></item></publish></pubsub></iq>"
    )
    fixture.check("type='result'" in alice.receive_until("owner-overwrite")[0], "ItemID overwrite failed")
    bob.send(
        f"<iq xmlns='jabber:client' type='set' id='wrong-retract' to='{service}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><retract node='wire/profile'>"
        "<item id='shared'/></retract></pubsub></iq>"
    )
    denied, _ = bob.receive_until("wrong-retract")
    fixture.check("type='error'" in denied and "forbidden" in denied, f"foreign retract was not forbidden: {denied}")

    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='make-outcast' to='{service}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub#owner'>"
        f"<affiliations node='wire/profile'><affiliation jid='{BOB}@{fixture.DOMAIN}' affiliation='outcast'/></affiliations>"
        "</pubsub></iq>"
    )
    fixture.check("type='result'" in alice.receive_until("make-outcast")[0], "outcast update failed")
    bob.receive_until("affiliation='outcast'")
    revoked, _ = bob.receive_until("subscription='none'")
    fixture.check("subid=" in revoked, "outcast subscription revocation omitted SubID")
    alice.close()
    bob.close()
    print("PubSub wire audit: discovery/config/errors/overwrite/retract/outcast/restart PASS")


if __name__ == "__main__":
    configure_endpoint()
    mode = sys.argv[1] if len(sys.argv) > 1 else "finish"
    if mode == "setup":
        setup_restart_queue()
    elif mode == "finish":
        finish_profile()
    else:
        raise SystemExit(f"unknown mode: {mode}")
