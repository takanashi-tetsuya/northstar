#!/usr/bin/env python3
"""Real WebSocket/restart fixture for OMEMO:2 and SCE server semantics.

This is deliberately not a second cryptographic implementation.  Browser
tests exercise X3DH, Double Ratchet and attachment encryption with real keys.
Here, opaque canonical Base64 proves that Northstar validates the public
OMEMO envelope, routes it through the relevant server features byte-for-byte,
and never needs plaintext or private key material.
"""

from __future__ import annotations

import importlib.util
import os
import pathlib
import socket
import sys
import time


ROOT = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("northstar_integration", ROOT / "integration-wsl.py")
fixture = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(fixture)

PASSWORD = "omemo-runtime-password-123"
ALICE = "omemo_wire_alice"
BOB = "omemo_wire_bob"
EMPTY = "omemo_wire_empty"
ALICE_DEVICE = 11001
ALICE_SECOND_DEVICE = 11002
BOB_DEVICE = 22001
LIVE_MARKER = "OMEMO-WIRE-LIVE-CIPHERTEXT"
CARBON_MARKER = "OMEMO-WIRE-CARBON-CIPHERTEXT"
CSI_MARKER = "OMEMO-WIRE-CSI-CIPHERTEXT"
OFFLINE_MARKER = "OMEMO-WIRE-OFFLINE-CIPHERTEXT"
MUC_MARKER = "OMEMO-WIRE-MUC-CIPHERTEXT"
ROOM_LOCALPART = "omemo-wire-room"
OMEMO_DEVICES = "urn:xmpp:omemo:2:devices"
OMEMO_BUNDLES = "urn:xmpp:omemo:2:bundles"


def configure_endpoint() -> None:
    fixture.HTTP_HOST = os.environ.get("XMPP_TEST_HOST", "127.0.0.1")
    fixture.HTTP_PORT = int(os.environ["XMPP_TEST_HTTP_PORT"])
    fixture.XMPP_PORT = int(os.environ["XMPP_TEST_CLIENT_PORT"])
    fixture.DOMAIN = os.environ.get("XMPP_TEST_DOMAIN", "localhost")


def register(username: str) -> None:
    status, result = fixture.register_account(username, PASSWORD)
    fixture.check(status == 201, f"registration failed for {username}: {status} {result}")


def token(username: str) -> str:
    status, result = fixture.api(
        "POST", "/api/v1/login", {"username": username, "password": PASSWORD}
    )
    fixture.check(status == 200, f"REST login failed for {username}: {status} {result}")
    return result["token"]


def iq(session, request_id: str, kind: str, payload: str, to: str | None = None) -> str:
    target = f" to='{to}'" if to else ""
    session.send(
        f"<iq xmlns='jabber:client' type='{kind}' id='{request_id}'{target}>{payload}</iq>"
    )
    return session.receive_until(request_id)[0]


def pep_publish(session, request_id: str, node: str, items: str, options: str = "") -> str:
    return iq(
        session,
        request_id,
        "set",
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        f"<publish node='{node}'>{items}</publish>{options}</pubsub>",
    )


def pep_get(session, request_id: str, owner: str, node: str, item_id: str | None = None) -> str:
    selected = f"<item id='{item_id}'/>" if item_id else ""
    return iq(
        session,
        request_id,
        "get",
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        f"<items node='{node}'>{selected}</items></pubsub>",
        owner,
    )


def envelope(marker: str | None, *, sender: int = ALICE_DEVICE) -> str:
    domain = fixture.DOMAIN
    return fixture.omemo2_envelope(
        sender,
        [
            (f"{ALICE}@{domain}", [ALICE_DEVICE, ALICE_SECOND_DEVICE]),
            (f"{BOB}@{domain}", [BOB_DEVICE]),
        ],
        marker,
    )


def send_encrypted(
    session,
    bearer: str,
    target: str,
    stanza_id: str,
    marker: str,
    *,
    sender: int = ALICE_DEVICE,
) -> None:
    session.send_with_pow(
        f"<message xmlns='jabber:client' to='{target}' type='chat' id='{stanza_id}'>"
        + envelope(marker, sender=sender)
        + "<origin-id xmlns='urn:xmpp:sid:0' id='"
        + stanza_id
        + "'/></message>",
        bearer,
    )


def assert_marker(frame: str, marker: str, context: str) -> None:
    encoded = fixture.omemo_payload_b64(marker)
    fixture.check(encoded in frame, f"{context} lost the OMEMO payload: {frame}")
    fixture.check(
        "<body" not in frame and marker not in frame,
        f"{context} exposed plaintext or added an XEP-0420 fallback body: {frame}",
    )


def assert_not_received(session, stanza_id: str) -> None:
    deadline = time.monotonic() + 0.75
    while time.monotonic() < deadline:
        try:
            frame = session.receive(max(0.05, deadline - time.monotonic()))
        except (TimeoutError, socket.timeout):
            return
        fixture.check(stanza_id not in frame, f"rejected OMEMO stanza was delivered: {frame}")


def rejected_message(
    alice,
    bob,
    alice_token: str,
    stanza_id: str,
    children: str,
    expected_condition: str,
) -> None:
    alice.send_with_pow(
        f"<message xmlns='jabber:client' to='{BOB}@{fixture.DOMAIN}' type='chat' id='{stanza_id}'>"
        f"{children}</message>",
        alice_token,
    )
    error = alice.receive_until(stanza_id)[0]
    fixture.check(
        "type='error'" in error and expected_condition in error,
        f"malformed OMEMO stanza did not fail with {expected_condition}: {error}",
    )
    assert_not_received(bob, stanza_id)


def mam_query(session, request_id: str, owner: str | None = None, with_jid: str | None = None) -> str:
    form = ""
    if with_jid:
        form = (
            "<x xmlns='jabber:x:data' type='submit'>"
            "<field var='FORM_TYPE'><value>urn:xmpp:mam:2</value></field>"
            f"<field var='with'><value>{with_jid}</value></field></x>"
        )
    target = f" to='{owner}'" if owner else ""
    session.send(
        f"<iq xmlns='jabber:client' type='set' id='{request_id}'{target}>"
        f"<query xmlns='urn:xmpp:mam:2' queryid='{request_id}'>{form}"
        "<set xmlns='http://jabber.org/protocol/rsm'><max>50</max><before/></set>"
        "</query></iq>"
    )
    _, frames = session.receive_until("<fin ", timeout=20)
    return "".join(frames)


def setup() -> None:
    fixture.wait_ready()
    for username in (ALICE, BOB, EMPTY):
        register(username)
    alice_bare = f"{ALICE}@{fixture.DOMAIN}"
    bob_bare = f"{BOB}@{fixture.DOMAIN}"
    alice_token = token(ALICE)
    bob_token = token(BOB)
    alice = fixture.XmppWebSocket(ALICE, PASSWORD, "omemo-alice")
    alice_carbon = fixture.XmppWebSocket(ALICE, PASSWORD, "omemo-alice-carbon")
    bob = fixture.XmppWebSocket(BOB, PASSWORD, "omemo-bob")

    account_disco = iq(
        alice,
        "omemo-account-disco",
        "get",
        "<query xmlns='http://jabber.org/protocol/disco#info'/>",
        alice_bare,
    )
    for feature in (
        "http://jabber.org/protocol/pubsub#pep",
        "http://jabber.org/protocol/pubsub#persistent-items",
        "http://jabber.org/protocol/pubsub#multi-items",
        "http://jabber.org/protocol/pubsub#publish-options",
        "http://jabber.org/protocol/pubsub#access-open",
    ):
        fixture.check(feature in account_disco, f"OMEMO PEP disco omitted {feature}")

    device_items = (
        "<item id='current'><devices xmlns='urn:xmpp:omemo:2'>"
        f"<device id='{ALICE_DEVICE}'/><device id='{ALICE_SECOND_DEVICE}'/>"
        "</devices></item>"
    )
    published = pep_publish(alice, "omemo-devices-publish", OMEMO_DEVICES, device_items)
    fixture.check("type='result'" in published, f"device list publication failed: {published}")
    bundle = fixture.omemo2_bundle()
    bundles = pep_publish(
        alice,
        "omemo-bundles-publish",
        OMEMO_BUNDLES,
        f"<item id='{ALICE_DEVICE}'>{bundle}</item>"
        f"<item id='{ALICE_SECOND_DEVICE}'>{bundle}</item>",
    )
    fixture.check("type='result'" in bundles, f"multi-device bundle publication failed: {bundles}")

    bad_bundle = pep_publish(
        alice,
        "omemo-short-bundle",
        OMEMO_BUNDLES,
        f"<item id='11003'>{fixture.omemo2_bundle(24)}</item>",
    )
    fixture.check(
        "type='error'" in bad_bundle and "invalid-payload" in bad_bundle,
        f"bundle with fewer than 25 prekeys was accepted: {bad_bundle}",
    )
    absent = pep_get(bob, "omemo-short-bundle-check", alice_bare, OMEMO_BUNDLES, "11003")
    fixture.check(
        "type='error'" in absent and "item-not-found" in absent,
        f"rejected bundle partially committed: {absent}",
    )
    unsigned_label = pep_publish(
        alice,
        "omemo-unsigned-label",
        OMEMO_DEVICES,
        "<item id='current'><devices xmlns='urn:xmpp:omemo:2'>"
        f"<device id='{ALICE_DEVICE}' label='Phone'/></devices></item>",
    )
    fixture.check(
        "type='result'" in unsigned_label,
        f"device announcement with an ignorable unsigned label was rejected: {unsigned_label}",
    )
    unsigned_visible = pep_get(bob, "omemo-devices-unsigned-label", alice_bare, OMEMO_DEVICES)
    fixture.check(
        f"device id='{ALICE_DEVICE}'" in unsigned_visible
        and "label='Phone'" in unsigned_visible,
        f"server did not transparently store the client-validated label metadata: {unsigned_visible}",
    )
    restored = pep_publish(alice, "omemo-devices-restore", OMEMO_DEVICES, device_items)
    fixture.check("type='result'" in restored, f"device list restoration failed: {restored}")
    empty_session = fixture.XmppWebSocket(EMPTY, PASSWORD, "omemo-empty")
    empty = pep_publish(
        empty_session,
        "omemo-empty-devices",
        OMEMO_DEVICES,
        "<item id='current'><devices xmlns='urn:xmpp:omemo:2'/></item>",
    )
    fixture.check("type='result'" in empty, f"empty device list was rejected: {empty}")
    empty_session.close()

    bob_bundle = pep_publish(
        bob,
        "omemo-bob-bundle",
        OMEMO_BUNDLES,
        f"<item id='{BOB_DEVICE}'>{fixture.omemo2_bundle()}</item>",
    )
    fixture.check("type='result'" in bob_bundle, f"Bob bundle publication failed: {bob_bundle}")
    bob_devices = pep_publish(
        bob,
        "omemo-bob-devices",
        OMEMO_DEVICES,
        "<item id='current'><devices xmlns='urn:xmpp:omemo:2'>"
        f"<device id='{BOB_DEVICE}'/></devices></item>",
    )
    fixture.check("type='result'" in bob_devices, f"Bob device publication failed: {bob_devices}")
    visible = pep_get(bob, "omemo-bundles-get", alice_bare, OMEMO_BUNDLES)
    fixture.check(
        f"id='{ALICE_DEVICE}'" in visible
        and f"id='{ALICE_SECOND_DEVICE}'" in visible
        and visible.count("<pk id=") >= 50,
        f"public multi-device bundles were incomplete: {visible}",
    )

    enabled = iq(
        alice_carbon,
        "omemo-carbon-enable",
        "set",
        "<enable xmlns='urn:xmpp:carbons:2'/>",
    )
    fixture.check("type='result'" in enabled, f"Carbons enable failed: {enabled}")
    send_encrypted(alice, alice_token, bob_bare, "omemo-live", LIVE_MARKER)
    live = bob.receive_until("omemo-live")[0]
    assert_marker(live, LIVE_MARKER, "live delivery")
    carbon = alice_carbon.receive_until("omemo-live")[0]
    fixture.check("<sent xmlns='urn:xmpp:carbons:2'>" in carbon, f"sent Carbon missing: {carbon}")
    assert_marker(carbon, LIVE_MARKER, "sent Carbon")

    rejected_message(
        alice,
        bob,
        alice_token,
        "omemo-plaintext-downgrade",
        "<body>PLAINTEXT-DOWNGRADE-MUST-NEVER-PERSIST</body>" + envelope("DOWNGRADE"),
        "not-acceptable",
    )
    rejected_message(
        alice,
        bob,
        alice_token,
        "omemo-direct-sce",
        "<envelope xmlns='urn:xmpp:sce:1'><content><body xmlns='jabber:client'>leak</body>"
        "</content><rpad>x</rpad></envelope>",
        "not-allowed",
    )
    duplicate_key = (
        "<encrypted xmlns='urn:xmpp:omemo:2'><header sid='11001'>"
        f"<keys jid='{bob_bare}'><key rid='{BOB_DEVICE}'>AQ==</key>"
        f"<key rid='{BOB_DEVICE}'>Ag==</key></keys></header><payload>Aw==</payload></encrypted>"
        "<store xmlns='urn:xmpp:hints'/>"
    )
    rejected_message(
        alice, bob, alice_token, "omemo-duplicate-rid", duplicate_key, "bad-request"
    )
    no_store = fixture.omemo2_envelope(
        ALICE_DEVICE, [(bob_bare, [BOB_DEVICE])], "NO-STORE-DOWNGRADE", store=False
    )
    rejected_message(
        alice, bob, alice_token, "omemo-missing-store", no_store, "not-acceptable"
    )

    # XEP-0352 may coalesce presence/chat-state noise, but encrypted content
    # is important and must not be delayed or rewritten while the client is inactive.
    alice.send("<inactive xmlns='urn:xmpp:csi:0'/>")
    send_encrypted(
        bob,
        bob_token,
        alice_bare,
        "omemo-csi",
        CSI_MARKER,
        sender=BOB_DEVICE,
    )
    csi = alice.receive_until("omemo-csi")[0]
    assert_marker(csi, CSI_MARKER, "CSI-inactive delivery")
    alice.send("<active xmlns='urn:xmpp:csi:0'/>")

    room = f"{ROOM_LOCALPART}@conference.{fixture.DOMAIN}"
    alice.send(
        f"<presence xmlns='jabber:client' to='{room}/Alice'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    owner_join = alice.receive_until("code='110'")[0]
    fixture.check("code='201'" in owner_join, f"MUC creation failed: {owner_join}")
    configured = iq(
        alice,
        "omemo-muc-config",
        "set",
        "<query xmlns='http://jabber.org/protocol/muc#owner'>"
        "<x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#roomconfig</value></field>"
        "<field var='muc#roomconfig_persistentroom'><value>1</value></field>"
        "<field var='muc#roomconfig_whois'><value>anyone</value></field>"
        "</x></query>",
        room,
    )
    fixture.check("type='result'" in configured, f"persistent MUC config failed: {configured}")
    bob.send(
        f"<presence xmlns='jabber:client' to='{room}/Bob'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    bob.receive_until("code='110'")
    alice.receive_until(f"from='{room}/Bob'")
    alice.send_with_pow(
        f"<message xmlns='jabber:client' to='{room}' type='groupchat' id='omemo-muc'>"
        + envelope(MUC_MARKER)
        + "</message>",
        alice_token,
    )
    muc_live = bob.receive_until("omemo-muc")[0]
    assert_marker(muc_live, MUC_MARKER, "MUC delivery")
    alice.receive_until("omemo-muc")
    muc_mam = mam_query(alice, "omemo-muc-mam-before-restart", room)
    assert_marker(muc_mam, MUC_MARKER, "MUC MAM")

    bob.close()
    time.sleep(0.25)
    send_encrypted(alice, alice_token, bob_bare, "omemo-offline", OFFLINE_MARKER)
    barrier = iq(
        alice,
        "omemo-offline-barrier",
        "get",
        "<ping xmlns='urn:xmpp:ping'/>",
    )
    fixture.check("type='result'" in barrier, f"offline commit barrier failed: {barrier}")
    alice.close()
    alice_carbon.close()
    print("omemo runtime setup: PEP lifecycle, negative validation, live/Carbon/CSI/MUC/offline passed")


def finish() -> None:
    fixture.wait_ready()
    alice_bare = f"{ALICE}@{fixture.DOMAIN}"
    bob_bare = f"{BOB}@{fixture.DOMAIN}"
    room = f"{ROOM_LOCALPART}@conference.{fixture.DOMAIN}"
    bob = fixture.XmppWebSocket(BOB, PASSWORD, "omemo-bob-restart", initial_presence=False)
    bob.send("<presence xmlns='jabber:client'><priority>0</priority></presence>")
    offline = bob.receive_until("omemo-offline", timeout=20)[0]
    assert_marker(offline, OFFLINE_MARKER, "offline replay after restart")

    personal_mam = mam_query(bob, "omemo-personal-mam-restart", with_jid=alice_bare)
    assert_marker(personal_mam, OFFLINE_MARKER, "personal MAM after restart")
    fixture.check(
        "PLAINTEXT-DOWNGRADE-MUST-NEVER-PERSIST" not in personal_mam,
        "rejected plaintext downgrade reached personal MAM",
    )

    alice = fixture.XmppWebSocket(ALICE, PASSWORD, "omemo-alice-restart")
    devices = pep_get(bob, "omemo-devices-restart", alice_bare, OMEMO_DEVICES)
    bundles = pep_get(bob, "omemo-bundles-restart", alice_bare, OMEMO_BUNDLES)
    fixture.check(
        f"device id='{ALICE_DEVICE}'" in devices
        and f"device id='{ALICE_SECOND_DEVICE}'" in devices
        and f"id='{ALICE_DEVICE}'" in bundles
        and f"id='{ALICE_SECOND_DEVICE}'" in bundles,
        "OMEMO device list or bundles did not survive restart",
    )

    retracted = iq(
        alice,
        "omemo-retract-second",
        "set",
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        f"<retract node='{OMEMO_BUNDLES}' notify='true'>"
        f"<item id='{ALICE_SECOND_DEVICE}'/></retract></pubsub>",
    )
    fixture.check("type='result'" in retracted, f"bundle revocation failed: {retracted}")
    reduced = pep_publish(
        alice,
        "omemo-device-list-revoke",
        OMEMO_DEVICES,
        "<item id='current'><devices xmlns='urn:xmpp:omemo:2'>"
        f"<device id='{ALICE_DEVICE}'/></devices></item>",
    )
    fixture.check("type='result'" in reduced, f"device-list revocation failed: {reduced}")
    missing = pep_get(
        bob,
        "omemo-retracted-second-check",
        alice_bare,
        OMEMO_BUNDLES,
        str(ALICE_SECOND_DEVICE),
    )
    fixture.check(
        "type='error'" in missing and "item-not-found" in missing,
        f"revoked OMEMO bundle remained visible: {missing}",
    )

    alice.send(
        f"<presence xmlns='jabber:client' to='{room}/AliceAfterRestart'>"
        "<x xmlns='http://jabber.org/protocol/muc'><history maxstanzas='0'/></x></presence>"
    )
    alice.receive_until("code='110'")
    muc_mam = mam_query(alice, "omemo-muc-mam-restart", room)
    assert_marker(muc_mam, MUC_MARKER, "MUC MAM after restart")
    alice.close()
    bob.close()
    print("omemo runtime finish: restart replay/MAM/PEP revocation/MUC persistence passed")


def main() -> None:
    configure_endpoint()
    fixture.check(len(sys.argv) == 2, "expected setup or finish")
    if sys.argv[1] == "setup":
        setup()
    elif sys.argv[1] == "finish":
        finish()
    else:
        raise AssertionError(f"unknown OMEMO runtime phase: {sys.argv[1]}")


if __name__ == "__main__":
    main()
