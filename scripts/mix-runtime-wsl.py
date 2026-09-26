#!/usr/bin/env python3
"""Two-client, wire-level MIX family acceptance probe."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import pathlib
import re
import socket
import sys
import time


ROOT = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("northstar_integration", ROOT / "integration-wsl.py")
fixture = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(fixture)

DOMAIN = fixture.DOMAIN
MIX = f"mix.{DOMAIN}"
CHANNEL = f"runtime@{MIX}"
PASSWORD = "mix-runtime-password-123"
ALICE = "mix_runtime_alice"
BOB = "mix_runtime_bob"
CORE = "urn:xmpp:mix:core:1"
PAM = "urn:xmpp:mix:pam:2"
ADMIN = "urn:xmpp:mix:admin:0"
ANON = "urn:xmpp:mix:anon:0"
MISC = "urn:xmpp:mix:misc:0"
PUBSUB = "http://jabber.org/protocol/pubsub"


def check(value: bool, message: str) -> None:
    fixture.check(value, message)


def _token_end(value: bytearray, start: int) -> int | None:
    quote = None
    for cursor in range(start + 1, len(value)):
        byte = value[cursor]
        if quote is not None:
            if byte == quote:
                quote = None
        elif byte in (ord("'"), ord('"')):
            quote = byte
        elif byte == ord(">"):
            return cursor + 1
    return None


def take_xml_frame(value: bytearray) -> bytes | None:
    while value and value[0] in b" \t\r\n":
        del value[0]
    depth = 0
    cursor = 0
    started = False
    while value and cursor < len(value):
        start = value.find(b"<", cursor)
        if start < 0:
            return None
        end = _token_end(value, start)
        if end is None:
            return None
        token = bytes(value[start:end]).rstrip()
        if token.startswith(b"</"):
            depth -= 1
        elif not token.startswith((b"<?", b"<!")):
            started = True
            depth += 1
            if token.endswith(b"/>"):
                depth -= 1
        cursor = end
        if started and depth == 0:
            frame = bytes(value[:cursor])
            del value[:cursor]
            return frame
    return None


def reader_selftest() -> None:
    value = bytearray(
        b"<message id='outer'><forwarded><message id='inner'/></forwarded></message>"
        b"<iq id='next'/>"
    )
    first = take_xml_frame(value)
    second = take_xml_frame(value)
    check(first is not None and b"id='inner'" in first, "nested stanza was split")
    check(second == b"<iq id='next'/>", "coalesced stanza was lost")
    ids = (
        "00000000-0000-0000-0000-000000000101",
        "00000000-0000-0000-0000-000000000102",
    )

    class FakeMamClient:
        def __init__(self) -> None:
            self.frames = iter([
                f"<message><result xmlns='urn:xmpp:mam:2' id='{ids[0]}' "
                "queryid='selftest'><body>page two</body></result></message>",
                f"<message><result xmlns='urn:xmpp:mam:2' id='{ids[1]}' "
                "queryid='selftest'><body>page three</body></result></message>",
                f"<iq type='result' id='selftest'><fin xmlns='urn:xmpp:mam:2'>"
                f"<set><first index='0'>{ids[0]}</first><last>{ids[1]}</last>"
                "<count>2</count></set></fin></iq>",
            ])

        def send(self, _stanza: str) -> None:
            pass

        def receive(self, _timeout: float) -> str:
            return next(self.frames)

    archive_ids, count, index = mam_page(
        Inbox(FakeMamClient()), "selftest", ("page two", "page three")
    )
    check(
        archive_ids == list(ids) and count == 2 and index == 0,
        "MAM result was mistaken for the final IQ",
    )
    print("MIX reader and MAM result buffering self-test: PASS")


class Inbox:
    def __init__(self, client: object):
        self.client = client
        self.pending: list[str] = []

    def wait(self, marker: str, timeout: float = 15) -> str:
        deadline = time.monotonic() + timeout
        while True:
            for index, frame in enumerate(self.pending):
                if marker in frame:
                    return self.pending.pop(index)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"MIX inbox timed out for {marker!r}: {self.pending!r}")
            try:
                self.pending.append(self.client.receive(remaining))
            except TimeoutError as error:
                raise TimeoutError(
                    f"MIX inbox timed out for {marker!r}: {self.pending!r}"
                ) from error

    def send(self, stanza: str) -> None:
        self.client.send(stanza)

    def send_message(self, stanza: str, token: str) -> None:
        self.client.send_with_pow(stanza, token)

    def close(self) -> None:
        self.client.close()


def iq(client: Inbox, stanza_id: str, payload: str, to: str, kind: str = "set") -> str:
    client.send(
        f"<iq xmlns='jabber:client' type='{kind}' id='{stanza_id}' to='{to}'>{payload}</iq>"
    )
    return client.wait(f"id='{stanza_id}'")


def mam_page(
    client: Inbox, query_id: str, expected_markers: tuple[str, ...],
    before: str | None = None,
) -> tuple[list[str], int, int]:
    cursor = "<before/>" if before is None else f"<before>{before}</before>"
    client.send(
        f"<iq xmlns='jabber:client' type='set' id='{query_id}' to='{CHANNEL}'>"
        f"<query xmlns='urn:xmpp:mam:2' queryid='{query_id}'>"
        "<x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE'><value>urn:xmpp:mam:2</value></field></x>"
        f"<set xmlns='http://jabber.org/protocol/rsm'><max>2</max>{cursor}</set>"
        "</query></iq>"
    )
    fin = client.wait("<fin xmlns='urn:xmpp:mam:2'")
    count = re.search(r"<count>(\d+)</count>", fin)
    first = re.search(r"<first index='(\d+)'>([^<]+)</first>", fin)
    last = re.search(r"<last>([^<]+)</last>", fin)
    check(
        re.search(rf"<iq\b[^>]*\bid='{re.escape(query_id)}'", fin) is not None
        and "type='result'" in fin and count is not None,
        f"MIX MAM final page missing: {fin}",
    )
    results = [
        frame for frame in client.pending if f"queryid='{query_id}'" in frame
    ]
    client.pending = [
        frame for frame in client.pending if f"queryid='{query_id}'" not in frame
    ]
    check(len(results) == len(expected_markers), f"MIX MAM page size is wrong: {fin} {results}")
    ids = []
    for result, marker in zip(results, expected_markers):
        match = re.search(r"<result\b[^>]*\bid='([0-9a-f-]{36})'", result)
        check(match is not None, f"MIX MAM result has no archive ID: {result}")
        check(marker in result, f"MIX MAM result has the wrong group message: {result}")
        check(
            f"{ALICE}@{DOMAIN}" not in result,
            f"maybe-visible MAM leaked a real JID: {result}",
        )
        ids.append(match.group(1))
    check(first is not None and last is not None, f"MIX MAM omitted RSM bounds: {fin}")
    check(
        first.group(2) == ids[0] and last.group(1) == ids[-1],
        f"MIX MAM RSM bounds do not match the page: {fin} {ids}",
    )
    return ids, int(count.group(1)), int(first.group(1))


def preference_form(jid: str, private: str, vcard: str = "block", presence: str = "share") -> str:
    return (
        "<x xmlns='jabber:x:data' type='submit'>"
        f"<field var='FORM_TYPE'><value>{ANON}</value></field>"
        f"<field var='JID Visibility'><value>{jid}</value></field>"
        f"<field var='Private Messages'><value>{private}</value></field>"
        f"<field var='vCard'><value>{vcard}</value></field>"
        f"<field var='Presence'><value>{presence}</value></field></x>"
    )


def pam_join(client: Inbox, username: str, nick: str, preference: str) -> str:
    nodes = "".join(
        f"<subscribe node='{node}'/>"
        for node in (
            "urn:xmpp:mix:nodes:messages",
            "urn:xmpp:mix:nodes:presence",
            "urn:xmpp:mix:nodes:participants",
            "urn:xmpp:mix:nodes:info",
            "urn:xmpp:avatar:metadata",
        )
    )
    return iq(
        client,
        f"join-{username}",
        f"<client-join xmlns='{PAM}' channel='{CHANNEL}'><join xmlns='{ANON}'>{nodes}<nick>{nick}</nick>{preference}</join></client-join>",
        f"{username}@{DOMAIN}",
    )


def register(username: str) -> str:
    status, result = fixture.register_account(username, PASSWORD)
    check(status == 201, f"registration failed for {username}: {status} {result}")
    status, result = fixture.api("POST", "/api/v1/login", {"username": username, "password": PASSWORD})
    check(status == 200, f"REST login failed for {username}: {status} {result}")
    return result["token"]


def advertise_mix(client: Inbox, suffix: str) -> None:
    node = f"https://northstar.invalid/mix-runtime-{suffix}"
    name = "Northstar MIX Runtime"
    verification = (
        f"client/pc//{name}<"
        "urn:xmpp:mix:core:1<"
        "urn:xmpp:mix:pam:2<"
    )
    version = base64.b64encode(hashlib.sha1(verification.encode()).digest()).decode()
    client.send(
        "<presence xmlns='jabber:client'>"
        f"<c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='{node}' ver='{version}'/>"
        "</presence>"
    )
    query = client.wait(f"node='{node}#")
    query_id = re.search(r"id='([^']+)'", query)
    check(query_id is not None, f"MIX capability query missing id: {query}")
    client.send(
        f"<iq xmlns='jabber:client' type='result' id='{query_id.group(1)}'>"
        f"<query xmlns='http://jabber.org/protocol/disco#info' node='{node}#{version}'>"
        f"<identity category='client' type='pc' name='{name}'/>"
        "<feature var='urn:xmpp:mix:core:1'/><feature var='urn:xmpp:mix:pam:2'/>"
        "</query></iq>"
    )
    barrier_id = f"caps-barrier-{suffix}"
    iq(client, barrier_id, "<ping xmlns='urn:xmpp:ping'/>", DOMAIN, "get")


def run() -> None:
    reader_selftest()
    fixture.wait_ready()
    alice_token = register(ALICE)
    bob_token = register(BOB)
    alice = Inbox(fixture.XmppWebSocket(ALICE, PASSWORD, "mix-a"))
    bob = Inbox(fixture.XmppWebSocket(BOB, PASSWORD, "mix-b"))
    advertise_mix(alice, "alice")
    advertise_mix(bob, "bob")

    created = iq(alice, "create", f"<create xmlns='{CORE}' channel='runtime'/>", MIX)
    check("type='result'" in created and "channel='runtime'" in created, f"MIX create failed: {created}")

    configured = iq(
        alice,
        "configure",
        f"<pubsub xmlns='{PUBSUB}'><publish node='urn:xmpp:mix:nodes:config'><item><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>{ADMIN}</value></field><field var='JID Visibility'><value>jid-maybe-visible</value></field><field var='Mandatory Nicks'><value>1</value></field><field var='Private Messages'><value>1</value></field><field var='User Message Retraction'><value>1</value></field></x></item></publish></pubsub>",
        CHANNEL,
    )
    check("type='result'" in configured, f"MIX configure failed: {configured}")

    disco = iq(
        alice,
        "service-rsm",
        "<query xmlns='http://jabber.org/protocol/disco#items'><set xmlns='http://jabber.org/protocol/rsm'><max>1</max></set></query>",
        MIX,
        "get",
    )
    check(CHANNEL in disco and "<count>1</count>" in disco, f"MIX service RSM failed: {disco}")

    alice_join = pam_join(alice, ALICE, "Alice", preference_form("always", "allow", "allow"))
    bob_join = pam_join(bob, BOB, "Bob", preference_form("prefer not", "block"))
    check("type='result'" in alice_join and "type='result'" in bob_join, "PAM join failed")
    alice_id = re.search(r"jid='([^']+#runtime@mix\.[^']+)'", alice_join)
    bob_id = re.search(r"jid='([^']+#runtime@mix\.[^']+)'", bob_join)
    check(alice_id is not None and bob_id is not None, f"encoded participant JIDs missing: {alice_join} {bob_join}")
    alice_encoded = alice_id.group(1)
    bob_encoded = bob_id.group(1)

    bob.send("<presence xmlns='jabber:client' to='%s'><show>away</show></presence>" % CHANNEL)
    reflected = alice.wait("<show>away</show>")
    check("mix_runtime_bob" not in reflected and "<jid>" not in reflected, f"anonymous presence leaked JID: {reflected}")
    public_from = re.search(r"from='([^']+)'", reflected)
    check(public_from is not None and public_from.group(1).startswith(bob_encoded + "/"), f"anonymous public resource invalid: {reflected}")
    check(not public_from.group(1).endswith("/mix-b"), f"real resource leaked: {reflected}")

    # The MIX outbox is intentionally strict per recipient.  Receiving this
    # reverse-direction presence proves Bob's verified capability route and
    # drains every earlier Bob delivery before the message assertion below;
    # a generic IQ ping only orders C2S input and is not an outbox barrier.
    alice.send(
        "<presence xmlns='jabber:client' to='%s'><show>chat</show>"
        "<status>MIX Bob delivery barrier</status></presence>" % CHANNEL
    )
    bob_barrier = bob.wait("MIX Bob delivery barrier", timeout=30)
    barrier_from = re.search(r"from='([^']+)'", bob_barrier)
    check(
        barrier_from is not None and barrier_from.group(1).startswith(alice_encoded + "/"),
        f"reverse MIX delivery barrier used the wrong participant identity: {bob_barrier}",
    )

    alice.send_message(
        f"<message xmlns='jabber:client' type='chat' id='private-blocked' to='{bob_encoded}'><body>blocked private</body></message>",
        alice_token,
    )
    blocked = alice.wait("id='private-blocked'")
    check("type='error'" in blocked and "forbidden" in blocked, f"private-message block ignored: {blocked}")
    preference = iq(
        bob,
        "preference-allow",
        f"<user-preference xmlns='{ANON}'>{preference_form('prefer not', 'allow')}</user-preference>",
        CHANNEL,
    )
    check("type='result'" in preference and "<value>allow</value>" in preference, f"preference update failed: {preference}")
    alice.send_message(
        f"<message xmlns='jabber:client' type='chat' id='private-allowed' to='{bob_encoded}'><body>allowed private</body></message>",
        alice_token,
    )
    private = bob.wait("allowed private")
    check("type='chat'" in private and "type='groupchat'" not in private, f"private channel message was transformed incorrectly: {private}")

    alice.send_message(
        f"<message xmlns='jabber:client' type='groupchat' id='group-one' to='{CHANNEL}'><body>MIX runtime message</body></message>",
        alice_token,
    )
    # The ping is an input-order barrier: if message admission produced a
    # stanza error, that error must already be in Alice's ordered output before
    # the ping result.  Live delivery remains a separate durable outbox effect.
    group_barrier = iq(
        alice,
        "group-admission-barrier",
        "<ping xmlns='urn:xmpp:ping'/>",
        DOMAIN,
        "get",
    )
    check("type='result'" in group_barrier, f"MIX message admission barrier failed: {group_barrier}")
    group_errors = [
        frame
        for frame in alice.pending
        if "id='group-one'" in frame and "type='error'" in frame
    ]
    check(not group_errors, f"MIX group message admission failed: {group_errors}")
    # The reverse-direction delivery above already proved the recipient's
    # capability route and drained earlier ordered work. Keep the normal
    # deadline here so a new admission or fan-out latency regression fails CI.
    group = bob.wait("MIX runtime message")
    stanza_id = re.search(r"stanza-id[^>]+id='([0-9a-f-]{36})'", group)
    check(stanza_id is not None and f"<jid>{ALICE}@{DOMAIN}</jid>" in group, f"live maybe-visible identity/stanza-id failed: {group}")
    archive_id = stanza_id.group(1)
    delivered_ids = [archive_id]

    for suffix in ("two", "three"):
        marker = f"MIX runtime page {suffix}"
        alice.send_message(
            f"<message xmlns='jabber:client' type='groupchat' id='group-{suffix}' to='{CHANNEL}'><body>{marker}</body></message>",
            alice_token,
        )
        delivered = bob.wait(marker)
        delivered_id = re.search(r"stanza-id[^>]+id='([0-9a-f-]{36})'", delivered)
        check(
            "type='groupchat'" in delivered and delivered_id is not None,
            f"MIX page fixture {suffix} was not delivered: {delivered}",
        )
        delivered_ids.append(delivered_id.group(1))
    latest_ids, total, latest_index = mam_page(
        bob, "mix-runtime-latest", ("MIX runtime page two", "MIX runtime page three")
    )
    previous_ids, previous_total, previous_index = mam_page(
        bob, "mix-runtime-previous", ("MIX runtime message",), before=latest_ids[0]
    )
    check(
        total == 3 and previous_total == total
        and latest_index + len(latest_ids) == total
        and previous_index + len(previous_ids) == latest_index
        and not set(latest_ids).intersection(previous_ids),
        "MIX MAM adjacent pages have inconsistent count, index or IDs",
    )
    check(
        previous_ids + latest_ids == delivered_ids,
        "MIX MAM pages do not match the delivered group messages",
    )

    jidmap_owner = iq(alice, "jidmap-owner", f"<pubsub xmlns='{PUBSUB}'><items node='urn:xmpp:mix:nodes:jidmap'/></pubsub>", CHANNEL, "get")
    check("type='result'" in jidmap_owner and f"{BOB}@{DOMAIN}" in jidmap_owner, f"owner jidmap failed: {jidmap_owner}")
    jidmap_guest = iq(bob, "jidmap-guest", f"<pubsub xmlns='{PUBSUB}'><items node='urn:xmpp:mix:nodes:jidmap'/></pubsub>", CHANNEL, "get")
    check("type='error'" in jidmap_guest and "forbidden" in jidmap_guest, f"jidmap privilege bypass: {jidmap_guest}")

    png = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=")
    avatar_id = hashlib.sha1(png).hexdigest()
    avatar_data = base64.b64encode(png).decode()
    avatar = iq(alice, "avatar-owner", f"<pubsub xmlns='{PUBSUB}'><publish node='urn:xmpp:avatar:data'><item id='{avatar_id}'><data xmlns='urn:xmpp:avatar:data'>{avatar_data}</data></item></publish></pubsub>", CHANNEL)
    check("type='result'" in avatar, f"owner avatar publish failed: {avatar}")
    avatar_denied = iq(bob, "avatar-guest", f"<pubsub xmlns='{PUBSUB}'><publish node='urn:xmpp:avatar:data'><item id='{avatar_id}'><data xmlns='urn:xmpp:avatar:data'>{avatar_data}</data></item></publish></pubsub>", CHANNEL)
    check("type='error'" in avatar_denied and "forbidden" in avatar_denied, f"avatar privilege bypass: {avatar_denied}")

    registered = iq(alice, "register-nick", f"<register xmlns='{MISC}'><nick>Alice Registered</nick></register>", MIX)
    check("type='result'" in registered and "Alice Registered" in registered, f"service nick registration failed: {registered}")
    nick_event = bob.wait("Alice Registered")
    check("urn:xmpp:mix:nodes:participants" in nick_event, f"nick registration did not publish participant update: {nick_event}")
    participant_items = iq(
        bob,
        "participants-after-register",
        f"<pubsub xmlns='{PUBSUB}'><items node='urn:xmpp:mix:nodes:participants'/></pubsub>",
        CHANNEL,
        "get",
    )
    check(
        "type='result'" in participant_items and "Alice Registered" in participant_items,
        f"registered nick was not stored in the participants projection: {participant_items}",
    )

    alice.send_message(
        f"<message xmlns='jabber:client' type='groupchat' id='retract' to='{CHANNEL}'><retract xmlns='{MISC}' id='{archive_id}'/></message>",
        alice_token,
    )
    retracted = bob.wait(f"<retract xmlns='{MISC}' id='{archive_id}'")
    check("<body>" not in retracted, f"MIX retraction was not bodyless: {retracted}")

    bob.close()
    bob = Inbox(fixture.XmppWebSocket(BOB, PASSWORD, "mix-b-reconnected"))
    advertise_mix(bob, "bob-reconnected")
    reconnected_participants = iq(
        bob,
        "participants-after-reconnect",
        f"<pubsub xmlns='{PUBSUB}'><items node='urn:xmpp:mix:nodes:participants'/></pubsub>",
        CHANNEL,
        "get",
    )
    check(
        "type='result'" in reconnected_participants
        and "Alice Registered" in reconnected_participants,
        f"registered nick projection did not survive reconnect: {reconnected_participants}",
    )
    alice.send_message(
        f"<message xmlns='jabber:client' type='groupchat' id='after-reconnect' to='{CHANNEL}'><body>membership survived reconnect</body></message>",
        alice_token,
    )
    survived = bob.wait("membership survived reconnect")
    check("type='groupchat'" in survived, f"PAM membership did not survive reconnect: {survived}")

    alice.close()
    bob.close()
    print("MIX wire runtime: create/config/disco-RSM/PAM/ANON/presence/private/MAM/jidmap/avatar/nick/retract/reconnect PASS")


if __name__ == "__main__":
    if sys.argv[1:] == ["reader-selftest"]:
        reader_selftest()
    else:
        run()
