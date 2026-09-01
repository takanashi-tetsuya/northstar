#!/usr/bin/env python3
"""Real-wire/restart fixture for vCard, avatars, and private profile storage."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import os
import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("northstar_integration", ROOT / "integration-wsl.py")
fixture = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(fixture)

PASSWORD = "profile-storage-password-123"
ALICE = "profile_storage_alice"
BOB = "profile_storage_bob"
NO_CARD = "profile_storage_no_card"
VCARD4 = "urn:xmpp:vcard4"
CONTACTS = "urn:xmpp:contacts"
AVATAR_DATA = "urn:xmpp:avatar:data"
AVATAR_METADATA = "urn:xmpp:avatar:metadata"
BOOKMARKS2 = "urn:xmpp:bookmarks:1"


def configure_endpoint() -> None:
    fixture.HTTP_HOST = os.environ.get("XMPP_TEST_HOST", "127.0.0.1")
    fixture.HTTP_PORT = int(os.environ["XMPP_TEST_HTTP_PORT"])
    fixture.XMPP_PORT = int(os.environ["XMPP_TEST_CLIENT_PORT"])
    fixture.DOMAIN = os.environ.get("XMPP_TEST_DOMAIN", "localhost")


def register(username: str) -> None:
    status, result = fixture.register_account(username, PASSWORD)
    fixture.check(status == 201, f"registration failed for {username}: {status} {result}")


def iq(session, request_id: str, kind: str, payload: str, to: str | None = None):
    target = f" to='{to}'" if to else ""
    session.send(
        f"<iq xmlns='jabber:client' type='{kind}' id='{request_id}'{target}>{payload}</iq>"
    )
    return session.receive_until(request_id)


def pep_get(session, request_id: str, owner: str, node: str, item_id: str | None = None):
    item = f"<item id='{item_id}'/>" if item_id else ""
    return iq(
        session,
        request_id,
        "get",
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        f"<items node='{node}'>{item}</items></pubsub>",
        owner,
    )


def subscribe(session, request_id: str, owner: str, node: str, subscriber: str):
    return iq(
        session,
        request_id,
        "set",
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        f"<subscribe node='{node}' jid='{subscriber}'/></pubsub>",
        owner,
    )


def advertise_profile_caps(session) -> None:
    caps_node = "https://northstar.invalid/profile-storage-client"
    features = [f"{CONTACTS}+notify", f"{VCARD4}+notify"]
    verification = "client/pc//Northstar Profile Storage<" + "".join(
        f"{feature}<" for feature in sorted(features)
    )
    version = base64.b64encode(hashlib.sha1(verification.encode()).digest()).decode()
    session.send(
        "<presence xmlns='jabber:client'>"
        "<c xmlns='http://jabber.org/protocol/caps' hash='sha-1' "
        f"node='{caps_node}' ver='{version}'/></presence>"
    )
    query, _ = session.receive_until(f"node='{caps_node}#")
    query_id = re.search(r"id='([^']+)'", query)
    fixture.check(query_id is not None, f"profile caps verification query missing: {query}")
    session.send(
        f"<iq xmlns='jabber:client' type='result' id='{query_id.group(1)}'>"
        f"<query xmlns='http://jabber.org/protocol/disco#info' node='{caps_node}#{version}'>"
        "<identity category='client' type='pc' name='Northstar Profile Storage'/>"
        + "".join(f"<feature var='{feature}'/>" for feature in features)
        + "</query></iq>"
    )
    barrier = iq(
        session,
        "profile-caps-barrier",
        "get",
        "<ping xmlns='urn:xmpp:ping'/>",
    )[0]
    fixture.check("type='result'" in barrier, f"profile caps barrier failed: {barrier}")


def setup() -> None:
    fixture.wait_ready()
    for username in (ALICE, BOB, NO_CARD):
        register(username)
    domain = fixture.DOMAIN
    alice_bare = f"{ALICE}@{domain}"
    bob_bare = f"{BOB}@{domain}"
    alice = fixture.XmppWebSocket(ALICE, PASSWORD, "profile-alice")
    alice_sync = fixture.XmppWebSocket(ALICE, PASSWORD, "profile-alice-sync")
    bob = fixture.XmppWebSocket(BOB, PASSWORD, "profile-bob")
    advertise_profile_caps(alice_sync)

    server_disco = iq(
        alice,
        "profile-server-disco",
        "get",
        "<query xmlns='http://jabber.org/protocol/disco#info'/>",
        domain,
    )[0]
    fixture.check(
        "jabber:iq:private" in server_disco and "vcard-temp" in server_disco,
        f"server profile-storage discovery is incomplete: {server_disco}",
    )
    account_disco = iq(
        alice,
        "profile-account-disco",
        "get",
        "<query xmlns='http://jabber.org/protocol/disco#info'/>",
        alice_bare,
    )[0]
    for feature in (
        AVATAR_DATA,
        AVATAR_METADATA,
        VCARD4,
        CONTACTS,
        BOOKMARKS2,
        "urn:xmpp:bookmarks:1#compat",
        "urn:xmpp:pep-vcard-conversion:0",
    ):
        fixture.check(feature in account_disco, f"account disco omitted {feature}")

    clear_without_data = iq(
        alice,
        "avatar-clear-without-data-node",
        "set",
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        f"<publish node='{AVATAR_METADATA}'><item id='current'>"
        f"<metadata xmlns='{AVATAR_METADATA}'/></item></publish></pubsub>",
    )[0]
    fixture.check(
        "type='result'" in clear_without_data,
        f"empty avatar metadata incorrectly required a data node: {clear_without_data}",
    )
    initial_external_hash = "a" * 40
    external_without_data = iq(
        alice,
        "avatar-url-without-data-node",
        "set",
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        f"<publish node='{AVATAR_METADATA}'><item id='{initial_external_hash}'>"
        f"<metadata xmlns='{AVATAR_METADATA}'><info bytes='42' id='{initial_external_hash}' "
        "type='image/png' url='https://avatars.example.test/initial.png'/>"
        "</metadata></item></publish></pubsub>",
    )[0]
    fixture.check(
        "type='result'" in external_without_data,
        f"URL-only avatar metadata incorrectly required a data node: {external_without_data}",
    )

    empty_get = iq(
        alice,
        "private-empty-get",
        "get",
        "<query xmlns='jabber:iq:private'/>",
    )[0]
    fixture.check(
        "type='error'" in empty_get
        and "<bad-format xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>" in empty_get,
        f"empty private get did not return the XEP-0049 bad-format condition: {empty_get}",
    )
    reserved_get = iq(
        alice,
        "private-reserved-get",
        "get",
        "<query xmlns='jabber:iq:private'><prefs/></query>",
    )[0]
    fixture.check(
        "type='error'" in reserved_get and "not-acceptable" in reserved_get,
        f"reserved private-storage namespace did not return not-acceptable: {reserved_get}",
    )
    for request_id, payload in (
        ("private-empty-set", "<query xmlns='jabber:iq:private'/>"),
        (
            "private-inherited-namespace",
            "<query xmlns='jabber:iq:private'><prefs/></query>",
        ),
    ):
        invalid_private = iq(alice, request_id, "set", payload)[0]
        fixture.check(
            "type='error'" in invalid_private and "not-acceptable" in invalid_private,
            f"invalid private-storage payload was accepted: {invalid_private}",
        )
    forbidden = iq(
        alice,
        "private-foreign-set",
        "set",
        "<query xmlns='jabber:iq:private'><prefs xmlns='urn:profile:foreign'/></query>",
        bob_bare,
    )[0]
    fixture.check(
        "type='error'" in forbidden and "forbidden" in forbidden,
        f"foreign private storage write was not forbidden: {forbidden}",
    )
    batch = iq(
        alice,
        "private-batch-set",
        "set",
        "<query xmlns='jabber:iq:private'>"
        "<one xmlns='urn:profile:prefs'><value>first</value></one>"
        "<two xmlns='urn:profile:prefs'><value>second</value></two>"
        "</query>",
    )[0]
    fixture.check("type='result'" in batch, f"multi-element private write failed: {batch}")
    batch_get = iq(
        alice,
        "private-batch-get",
        "get",
        "<query xmlns='jabber:iq:private'>"
        "<one xmlns='urn:profile:prefs'/><two xmlns='urn:profile:prefs'/>"
        "</query>",
    )[0]
    fixture.check(
        "type='result'" in batch_get
        and "<value>first</value>" in batch_get
        and "<value>second</value>" in batch_get,
        f"same-namespace multi-element private read failed: {batch_get}",
    )
    mixed_get = iq(
        alice,
        "private-mixed-get",
        "get",
        "<query xmlns='jabber:iq:private'>"
        "<one xmlns='urn:profile:prefs'/><other xmlns='urn:profile:other'/>"
        "</query>",
    )[0]
    fixture.check(
        "type='error'" in mixed_get and "bad-request" in mixed_get,
        f"mixed-namespace private get was accepted: {mixed_get}",
    )
    mixed = iq(
        alice,
        "private-mixed-set",
        "set",
        "<query xmlns='jabber:iq:private'>"
        "<badone xmlns='urn:profile:a'>must-not-commit</badone>"
        "<badtwo xmlns='urn:profile:b'>must-not-commit</badtwo>"
        "</query>",
    )[0]
    fixture.check(
        "type='error'" in mixed and "not-acceptable" in mixed,
        f"mixed-namespace private batch was accepted: {mixed}",
    )
    absent = iq(
        alice,
        "private-mixed-check",
        "get",
        "<query xmlns='jabber:iq:private'><badone xmlns='urn:profile:a'/></query>",
    )[0]
    fixture.check(
        "must-not-commit" not in absent and "<badone xmlns='urn:profile:a'/>" in absent,
        f"rejected private batch partially committed: {absent}",
    )

    legacy = iq(
        alice,
        "legacy-bookmarks-set",
        "set",
        "<query xmlns='jabber:iq:private'><storage xmlns='storage:bookmarks'>"
        "<conference jid='ROOM@Conference.LocalHost' name='Wire room' autojoin='true'>"
        "<nick>Alice</nick></conference>"
        "<url name='Docs &amp; Help' url='https://example.test/docs'/>"
        "</storage></query>",
    )[0]
    fixture.check("type='result'" in legacy, f"legacy bookmark write failed: {legacy}")
    modern = pep_get(alice, "bookmarks-modern-get", alice_bare, BOOKMARKS2)[0]
    fixture.check(
        "room@conference.localhost" in modern
        and "Wire room" in modern
        and "https://example.test/docs" not in modern,
        f"legacy-to-modern bookmark projection was incorrect: {modern}",
    )
    projected_legacy = iq(
        alice,
        "bookmarks-legacy-get",
        "get",
        "<query xmlns='jabber:iq:private'><storage xmlns='storage:bookmarks'/></query>",
    )[0]
    fixture.check(
        "room@conference.localhost" in projected_legacy
        and "https://example.test/docs" in projected_legacy,
        f"modern-to-legacy view lost the URL bookmark: {projected_legacy}",
    )

    for request_id, card in (
        ("vcard-bad-case", "<vCard xmlns='vcard-temp'><fn>Alice</fn></vCard>"),
        ("vcard-bad-tel", "<vCard xmlns='vcard-temp'><FN>Alice</FN><TEL><VOICE/></TEL></vCard>"),
        ("vcard-bad-email", "<vCard xmlns='vcard-temp'><FN>Alice</FN><EMAIL><INTERNET/></EMAIL></vCard>"),
    ):
        response = iq(alice, request_id, "set", card)[0]
        fixture.check("type='error'" in response, f"invalid vCard was accepted: {response}")

    first_png = fixture.png_1x1_rgba(31, 111, 235)
    first_b64 = base64.b64encode(first_png).decode()
    first_hash = hashlib.sha1(first_png).hexdigest()
    valid_card = (
        "<vCard xmlns='vcard-temp' version='3.0'><FN>Alice Profile</FN>"
        "<TEL><VOICE/><NUMBER>+81-555-0100</NUMBER></TEL>"
        "<EMAIL><INTERNET/><USERID>alice@example.test</USERID></EMAIL>"
        "<NOTE>must survive avatar projection</NOTE><PHOTO>"
        f"<TYPE>image/png</TYPE><BINVAL>{first_b64}</BINVAL>"
        "</PHOTO></vCard>"
    )
    stored = iq(alice, "vcard-valid-set", "set", valid_card)[0]
    fixture.check("type='result'" in stored, f"valid vCard write failed: {stored}")
    public_card = iq(bob, "vcard-public-get", "get", "<vCard xmlns='vcard-temp'/>", alice_bare)[0]
    fixture.check(
        "Alice Profile" in public_card and first_b64 in public_card,
        f"public vCard retrieval failed: {public_card}",
    )
    no_card = iq(
        bob,
        "vcard-no-card",
        "get",
        "<vCard xmlns='vcard-temp'/>",
        f"{NO_CARD}@{domain}",
    )[0]
    no_user = iq(
        bob,
        "vcard-no-user",
        "get",
        "<vCard xmlns='vcard-temp'/>",
        f"profile_storage_missing@{domain}",
    )[0]
    fixture.check(
        "service-unavailable" in no_card
        and "service-unavailable" in no_user
        and "item-not-found" not in no_card + no_user,
        f"vCard absence leaked account existence: card={no_card} user={no_user}",
    )

    initial_vcard4 = iq(
        alice,
        "vcard4-first",
        "set",
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        f"<publish node='{VCARD4}'><item id='first'>"
        "<vcard xmlns='urn:ietf:params:xml:ns:vcard-4.0'><fn><text>Alice</text></fn></vcard>"
        "</item></publish></pubsub>",
    )[0]
    fixture.check("type='result'" in initial_vcard4, f"initial vCard4 publish failed: {initial_vcard4}")
    initial_vcard4_event = alice_sync.receive_until("id='first'")[0]
    fixture.check(
        f"node='{VCARD4}'" in initial_vcard4_event
        and "<item id='first'/>" in initial_vcard4_event
        and "<vcard" not in initial_vcard4_event,
        f"same-account vCard4 event was not a pure notification: {initial_vcard4_event}",
    )
    subscribed = subscribe(
        bob,
        "vcard4-subscribe",
        alice_bare,
        VCARD4,
        f"{bob_bare}/profile-bob",
    )[0]
    fixture.check("subscription='subscribed'" in subscribed, f"vCard4 subscription failed: {subscribed}")
    second_vcard4, vcard4_frames = iq(
        alice,
        "vcard4-second",
        "set",
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        f"<publish node='{VCARD4}'><item id='second'>"
        "<vcard xmlns='urn:ietf:params:xml:ns:vcard-4.0'><fn><text>Alice Updated</text></fn></vcard>"
        "</item></publish></pubsub>",
    )
    fixture.check("type='result'" in second_vcard4, f"vCard4 update failed: {second_vcard4}")
    vcard4_event = bob.receive_until("id='second'")[0]
    fixture.check(
        f"node='{VCARD4}'" in vcard4_event
        and "<item id='second'/>" in vcard4_event
        and "<vcard" not in vcard4_event,
        f"vCard4 notification was not payload-free: {vcard4_event}; publisher={vcard4_frames}",
    )
    second_vcard4_event = alice_sync.receive_until("id='second'")[0]
    fixture.check(
        f"node='{VCARD4}'" in second_vcard4_event and "<vcard" not in second_vcard4_event,
        f"second resource received an invalid vCard4 event: {second_vcard4_event}",
    )
    invalid_vcard4 = iq(
        alice,
        "vcard4-invalid",
        "set",
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        f"<publish node='{VCARD4}'><item id='invalid'>"
        "<vcard xmlns='urn:ietf:params:xml:ns:vcard-4.0'/></item></publish></pubsub>",
    )[0]
    fixture.check(
        "type='error'" in invalid_vcard4 and "invalid-payload" in invalid_vcard4,
        f"vCard4 without mandatory FN was accepted: {invalid_vcard4}",
    )

    contact_publish = iq(
        alice,
        "contact-vcard-publish",
        "set",
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        f"<publish node='{CONTACTS}'><item id='{bob_bare.upper()}'>"
        "<vcard xmlns='urn:ietf:params:xml:ns:vcard-4.0'><fn><text>Bob Contact</text></fn>"
        f"<impp><uri>xmpp:{bob_bare}</uri></impp></vcard>"
        "</item></publish></pubsub>",
    )[0]
    fixture.check("type='result'" in contact_publish, f"contact vCard publish failed: {contact_publish}")
    contact_event = alice_sync.receive_until("Bob Contact")[0]
    fixture.check(
        f"node='{CONTACTS}'" in contact_event
        and f"id='{bob_bare}'" in contact_event
        and "<vcard xmlns='urn:ietf:params:xml:ns:vcard-4.0'>" in contact_event
        and f"xmpp:{bob_bare}" in contact_event,
        f"contact vCard was not pushed with its payload to an interested resource: {contact_event}",
    )
    private_contact = pep_get(bob, "contact-vcard-denied", alice_bare, CONTACTS)[0]
    fixture.check(
        "type='error'" in private_contact
        and ("forbidden" in private_contact or "not-authorized" in private_contact),
        f"private contact vCard node was exposed: {private_contact}",
    )

    temporary_raw = "TEMP@BÜCHER.example"
    temporary_canonical = "temp@xn--bcher-kva.example"
    temporary_publish = iq(
        alice,
        "contact-canonical-publish",
        "set",
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        f"<publish node='{CONTACTS}'><item id='{temporary_raw}'>"
        "<vcard xmlns='urn:ietf:params:xml:ns:vcard-4.0'>"
        "<fn><text>Temporary Contact</text></fn></vcard>"
        "</item></publish></pubsub>",
    )[0]
    fixture.check(
        "type='result'" in temporary_publish,
        f"Unicode/IDNA contact ItemID publish failed: {temporary_publish}",
    )
    temporary_event = alice_sync.receive_until("Temporary Contact")[0]
    fixture.check(
        f"id='{temporary_canonical}'" in temporary_event,
        f"contact event did not expose the canonical ItemID: {temporary_event}",
    )
    temporary_get = pep_get(
        alice,
        "contact-canonical-get",
        alice_bare,
        CONTACTS,
        temporary_raw,
    )[0]
    fixture.check(
        "Temporary Contact" in temporary_get and f"id='{temporary_canonical}'" in temporary_get,
        f"equivalent raw ItemID could not retrieve the canonical contact: {temporary_get}",
    )
    temporary_retract = iq(
        alice,
        "contact-canonical-retract",
        "set",
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        f"<retract node='{CONTACTS}'><item id='{temporary_raw}'/></retract></pubsub>",
    )[0]
    fixture.check(
        "type='result'" in temporary_retract,
        f"equivalent raw ItemID could not retract the canonical contact: {temporary_retract}",
    )
    temporary_retract_event = alice_sync.receive_until(temporary_canonical)[0]
    fixture.check(
        f"<retract id='{temporary_canonical}'/>" in temporary_retract_event,
        f"contact retraction event did not use the canonical ItemID: {temporary_retract_event}",
    )
    missing_temporary = pep_get(
        alice,
        "contact-canonical-missing",
        alice_bare,
        CONTACTS,
        temporary_raw,
    )[0]
    fixture.check(
        "type='error'" in missing_temporary and "item-not-found" in missing_temporary,
        f"retracted canonical contact remained retrievable: {missing_temporary}",
    )

    jpeg = bytes((0xFF, 0xD8, 0xFF, 0xD9))
    jpeg_hash = hashlib.sha1(jpeg).hexdigest()
    rejected_jpeg = iq(
        alice,
        "avatar-jpeg-data",
        "set",
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        f"<publish node='{AVATAR_DATA}'><item id='{jpeg_hash}'>"
        f"<data xmlns='{AVATAR_DATA}'>{base64.b64encode(jpeg).decode()}</data>"
        "</item></publish></pubsub>",
    )[0]
    fixture.check(
        "type='error'" in rejected_jpeg and "invalid-payload" in rejected_jpeg,
        f"non-PNG XEP-0084 data was accepted: {rejected_jpeg}",
    )

    subscribed_avatar = subscribe(
        bob,
        "avatar-subscribe",
        alice_bare,
        AVATAR_METADATA,
        f"{bob_bare}/profile-bob",
    )[0]
    fixture.check(
        "subscription='subscribed'" in subscribed_avatar,
        f"avatar metadata subscription failed: {subscribed_avatar}",
    )
    second_png = fixture.png_1x1_rgba(220, 38, 38)
    second_b64 = base64.b64encode(second_png).decode()
    second_hash = hashlib.sha1(second_png).hexdigest()
    folded_b64 = second_b64[:32] + "\n" + second_b64[32:]
    data_publish = iq(
        alice,
        "avatar-png-data",
        "set",
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        f"<publish node='{AVATAR_DATA}'><item id='{second_hash}'>"
        f"<data xmlns='{AVATAR_DATA}'>{folded_b64}</data>"
        "</item></publish></pubsub>",
    )[0]
    fixture.check("type='result'" in data_publish, f"folded PNG avatar data failed: {data_publish}")
    gif_only = iq(
        alice,
        "avatar-no-png-metadata",
        "set",
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        f"<publish node='{AVATAR_METADATA}'><item id='{second_hash}'>"
        f"<metadata xmlns='{AVATAR_METADATA}'><info bytes='{len(second_png)}' "
        f"id='{second_hash}' type='image/gif'/></metadata></item></publish></pubsub>",
    )[0]
    fixture.check(
        "type='error'" in gif_only and "invalid-payload" in gif_only,
        f"metadata without the mandatory PNG representation was accepted: {gif_only}",
    )
    metadata_publish, metadata_frames = iq(
        alice,
        "avatar-valid-metadata",
        "set",
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        f"<publish node='{AVATAR_METADATA}'><item id='{second_hash}'>"
        f"<metadata xmlns='{AVATAR_METADATA}'><info bytes='{len(second_png)}' height='1' "
        f"id='{second_hash}' type='image/png' width='1'/></metadata>"
        "</item></publish></pubsub>",
    )
    fixture.check("type='result'" in metadata_publish, f"valid avatar metadata failed: {metadata_publish}")
    avatar_event = bob.receive_until(second_hash)[0]
    fixture.check(
        f"node='{AVATAR_METADATA}'" in avatar_event and "type='image/png'" in avatar_event,
        f"avatar metadata notification failed: {avatar_event}; publisher={metadata_frames}",
    )
    projected = iq(bob, "vcard-avatar-projected", "get", "<vCard xmlns='vcard-temp'/>", alice_bare)[0]
    fixture.check(
        "Alice Profile" in projected
        and "must survive avatar projection" in projected
        and second_b64 in projected,
        f"XEP-0398 projection lost profile data or image bytes: {projected}",
    )

    external_hash = "3333333333333333333333333333333333333333"
    external_metadata = iq(
        alice,
        "avatar-external-metadata",
        "set",
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        f"<publish node='{AVATAR_METADATA}'><item id='{external_hash}'>"
        f"<metadata xmlns='{AVATAR_METADATA}'><info bytes='2048' height='64' "
        f"id='{external_hash}' type='IMAGE/PNG' width='64' "
        "url='HTTPS://avatars.example.test/external.png'/></metadata>"
        "</item></publish></pubsub>",
    )[0]
    fixture.check(
        "type='result'" in external_metadata,
        f"valid URL-only XEP-0084 metadata was rejected: {external_metadata}",
    )
    external_event = bob.receive_until(external_hash)[0]
    fixture.check(
        "avatars.example.test/external.png" in external_event,
        f"external avatar metadata notification failed: {external_event}",
    )
    external_projection = iq(
        bob,
        "vcard-external-preserved",
        "get",
        "<vCard xmlns='vcard-temp'/>",
        alice_bare,
    )[0]
    fixture.check(
        second_b64 in external_projection and "must survive avatar projection" in external_projection,
        f"URL-only avatar metadata clobbered the existing vCard fallback: {external_projection}",
    )
    restored_metadata = iq(
        alice,
        "avatar-inline-restore",
        "set",
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        f"<publish node='{AVATAR_METADATA}'><item id='{second_hash}'>"
        f"<metadata xmlns='{AVATAR_METADATA}'><info bytes='{len(second_png)}' height='1' "
        f"id='{second_hash}' type='image/png' width='1'/></metadata>"
        "</item></publish></pubsub>",
    )[0]
    fixture.check(
        "type='result'" in restored_metadata,
        f"inline avatar metadata restore failed: {restored_metadata}",
    )
    restored_event = bob.receive_until(second_hash)[0]
    fixture.check(
        f"node='{AVATAR_METADATA}'" in restored_event,
        f"restored avatar metadata notification failed: {restored_event}",
    )

    alice.send(f"<presence xmlns='jabber:client' to='{bob_bare}/profile-bob'/>")
    injected = bob.receive_until(second_hash)[0]
    fixture.check(
        "vcard-temp:x:update" in injected and f"<photo>{second_hash}</photo>" in injected,
        f"directed presence omitted the authoritative avatar hash: {injected}",
    )
    alice.send(
        f"<presence xmlns='jabber:client' to='{bob_bare}/profile-bob'>"
        "<x xmlns='vcard-temp:x:update'><photo/></x></presence>"
    )
    opted_out = bob.receive_until("vcard-temp:x:update")[0]
    fixture.check(
        second_hash not in opted_out and ("<photo/>" in opted_out or "<photo></photo>" in opted_out),
        f"explicit empty-photo opt-out was overwritten: {opted_out}",
    )

    alice.close()
    alice_sync.close()
    bob.close()
    print(f"profile storage setup PASS: avatar={second_hash} first={first_hash}")


def finish() -> None:
    fixture.wait_ready()
    domain = fixture.DOMAIN
    alice_bare = f"{ALICE}@{domain}"
    bob_bare = f"{BOB}@{domain}"
    alice = fixture.XmppWebSocket(ALICE, PASSWORD, "profile-alice-restart")
    bob = fixture.XmppWebSocket(BOB, PASSWORD, "profile-bob-restart")

    for element, expected in (("one", "first"), ("two", "second")):
        response = iq(
            alice,
            f"private-restart-{element}",
            "get",
            f"<query xmlns='jabber:iq:private'><{element} xmlns='urn:profile:prefs'/></query>",
        )[0]
        fixture.check(expected in response, f"private XML did not survive restart: {response}")
    legacy = iq(
        alice,
        "bookmarks-restart",
        "get",
        "<query xmlns='jabber:iq:private'><storage xmlns='storage:bookmarks'/></query>",
    )[0]
    fixture.check(
        "room@conference.localhost" in legacy and "https://example.test/docs" in legacy,
        f"bookmark compatibility did not survive restart: {legacy}",
    )
    vcard = iq(bob, "vcard-restart", "get", "<vCard xmlns='vcard-temp'/>", alice_bare)[0]
    fixture.check(
        "Alice Profile" in vcard and "must survive avatar projection" in vcard,
        f"vCard did not survive restart: {vcard}",
    )
    vcard4 = pep_get(bob, "vcard4-restart", alice_bare, VCARD4)[0]
    fixture.check("Alice Updated" in vcard4, f"vCard4 did not survive restart: {vcard4}")
    contacts = pep_get(alice, "contacts-restart", alice_bare, CONTACTS)[0]
    fixture.check(
        "Bob Contact" in contacts and f"xmpp:{bob_bare}" in contacts,
        f"private contact vCard did not survive restart: {contacts}",
    )
    denied = pep_get(bob, "contacts-restart-denied", alice_bare, CONTACTS)[0]
    fixture.check("type='error'" in denied, f"contact vCards became public after restart: {denied}")
    metadata = pep_get(alice, "avatar-metadata-restart", alice_bare, AVATAR_METADATA)[0]
    match = __import__("re").search(r"<info[^>]+id='([0-9a-f]{40})'[^>]+type='image/png'", metadata)
    fixture.check(match is not None, f"avatar metadata did not survive restart: {metadata}")
    data = pep_get(alice, "avatar-data-restart", alice_bare, AVATAR_DATA, match.group(1))[0]
    fixture.check("<data xmlns='urn:xmpp:avatar:data'>" in data, f"avatar data did not survive restart: {data}")

    alice.close()
    bob.close()
    print("profile storage restart PASS: private/vCard/vCard4/contacts/avatar/bookmarks")


if __name__ == "__main__":
    configure_endpoint()
    if len(sys.argv) != 2 or sys.argv[1] not in {"setup", "finish"}:
        raise SystemExit("usage: profile-storage-runtime-wsl.py setup|finish")
    if sys.argv[1] == "setup":
        setup()
    else:
        finish()
