#!/usr/bin/env python3
"""Phase 7 MUC Integration Test Script."""

import sys
import time
import pathlib

# Import utilities from the existing integration script
import importlib.util
root = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("integration", root / "integration-wsl.py")
integration = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(integration)

class XmppWebSocket(integration.XmppWebSocket):
    """Keep this focused fixture on the RFC 6120 client stanza namespace."""

    @staticmethod
    def _with_client_namespace(text: str, opcode: int) -> str:
        if opcode == 1 and text.startswith(("<iq ", "<message ", "<presence ")):
            opening_end = text.find(">")
            if opening_end > 0 and "xmlns=" not in text[:opening_end]:
                element_end = text.find(" ")
                text = text[:element_end] + " xmlns='jabber:client'" + text[element_end:]
        return text

    def send(self, text: str, opcode: int = 1) -> None:
        text = self._with_client_namespace(text, opcode)
        super().send(text, opcode)

    def send_with_pow(self, text: str, token: str) -> None:
        # PoW v2 commits the exact pow-less UTF-8 stanza.  Normalize the root
        # namespace before hashing so the overridden send() cannot change the
        # commitment after the challenge has been issued.
        super().send_with_pow(self._with_client_namespace(text, 1), token)
wait_ready = integration.wait_ready
DOMAIN = integration.DOMAIN
check = integration.check
PASSWORD = integration.PASSWORD
ALICE = "muc_alice_it"
BOB = "muc_bob_it"

def run_test():
    print("Waiting for Northstar XMPP Server to be ready...")
    wait_ready()

    for username in (ALICE, BOB):
        status, result = integration.register_account(username, PASSWORD)
        check(status == 201, f"registration failed for {username}: {status} {result}")
    status, alice_login = integration.api(
        "POST", "/api/v1/login", {"username": ALICE, "password": PASSWORD}
    )
    check(status == 200, f"Alice REST login failed: {alice_login}")
    alice_token = alice_login["token"]
    status, bob_login = integration.api(
        "POST", "/api/v1/login", {"username": BOB, "password": PASSWORD}
    )
    check(status == 200, f"Bob REST login failed: {bob_login}")
    bob_token = bob_login["token"]
    
    print("Logging in Alice and Bob...")
    alice = XmppWebSocket(ALICE, PASSWORD, "client1")
    bob = XmppWebSocket(BOB, PASSWORD, "client2")
    
    room_jid = f"testroom@conference.{DOMAIN}"
    
    # 1. Alice creates the room
    print(f"Alice creating room {room_jid}...")
    alice.send(f"<presence to='{room_jid}/Alice'><x xmlns='http://jabber.org/protocol/muc'/></presence>")
    reply, _ = alice.receive_until("code='110'")
    check("affiliation='owner'" in reply, "Alice should be owner")
    
    # Alice configures the room
    alice.send(
        f"<iq type='set' id='config1' to='{room_jid}'>"
        "<query xmlns='http://jabber.org/protocol/muc#owner'>"
        "<x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#roomconfig</value></field>"
        "<field var='muc#roomconfig_persistentroom'><value>1</value></field>"
        "</x></query></iq>"
    )
    alice.receive_until("id='config1'")

    # Mediated invitations can be declined before the invitee joins.
    print("Testing mediated invitation decline...")
    alice.send_with_pow(
        f"<message to='{room_jid}' type='normal' id='invite1'>"
        "<x xmlns='http://jabber.org/protocol/muc#user'>"
        f"<invite to='{BOB}@{DOMAIN}'><reason>Join us</reason></invite>"
        "</x></message>",
        alice_token,
    )
    bob.receive_until("<invite")
    bob.send_with_pow(
        f"<message to='{room_jid}' type='normal' id='decline1'>"
        "<x xmlns='http://jabber.org/protocol/muc#user'>"
        f"<decline to='{ALICE}@{DOMAIN}'><reason>Later</reason></decline>"
        "</x></message>",
        bob_token,
    )
    declined, _ = alice.receive_until("<decline")
    check(f"from='{BOB}@{DOMAIN}'" in declined and "Later" in declined,
          "Mediated invitation decline was not routed through the room")

    # XEP-0045 room registration reserves a nickname without locking the
    # registrant to that nickname.
    print("Testing room registration and reserved nickname discovery...")
    bob.send(
        f"<iq type='get' id='reg-get' to='{room_jid}'>"
        "<query xmlns='jabber:iq:register'/></iq>"
    )
    registration, _ = bob.receive_until("id='reg-get'")
    check("muc#register_roomnick" in registration, "Room registration form missing")
    bob.send(
        f"<iq type='set' id='reg-set' to='{room_jid}'>"
        "<query xmlns='jabber:iq:register'>"
        "<x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#register</value></field>"
        "<field var='muc#register_roomnick'><value>BobReserved</value></field>"
        "</x></query></iq>"
    )
    bob.receive_until("id='reg-set'")
    bob.send(
        f"<iq type='get' id='reserved' to='{room_jid}'>"
        "<query xmlns='http://jabber.org/protocol/disco#info' node='x-roomuser-item'/></iq>"
    )
    reserved, _ = bob.receive_until("id='reserved'")
    check("name='BobReserved'" in reserved, "Reserved room nickname discovery failed")
    alice.send(f"<presence to='{room_jid}/BobReserved'/>")
    reserved_conflict, _ = alice.receive_until("type='error'")
    check("conflict" in reserved_conflict, "Another account used a reserved nickname")
    
    # 2. Alice sends five opaque OMEMO envelopes.  The integration server
    # deliberately runs with REQUIRE_ENCRYPTED_ARCHIVE=true, so a plaintext
    # body is routed live but MUST NOT be persisted as room history.  Keeping
    # the marker inside the base64 payload tests the real encrypted-history
    # policy instead of weakening it for this legacy fixture.
    print("Alice sending 5 encrypted messages...")
    history_markers = []
    for i in range(1, 6):
        marker = f"Message {i}"
        wire_marker = integration.omemo_payload_b64(marker)
        history_markers.append(wire_marker)
        alice.send_with_pow(
            f"<message to='{room_jid}' type='groupchat'>"
            + integration.omemo2_envelope(
                12345,
                [(f"{ALICE}@{DOMAIN}", [12345]), (f"{BOB}@{DOMAIN}", [23456])],
                marker,
            )
            + "</message>",
            alice_token,
        )
        reflected, _ = alice.receive_until(wire_marker) # wait for reflection
        check(
            "type='error'" not in reflected,
            f"encrypted MUC message was rejected instead of reflected: {reflected}",
        )
    
    # 3. Bob joins with maxstanzas=2
    print("Bob joining with maxstanzas=2...")
    bob.send(f"<presence to='{room_jid}/Bob'><x xmlns='http://jabber.org/protocol/muc'><history maxstanzas='2'/></x></presence>")
    # Bob should receive presence, then subject, then exactly 2 history messages
    reply, frames = bob.receive_until(history_markers[4], timeout=5)
    
    # Count how many messages Bob received in total
    history_messages = [f for f in frames if "<message" in f and "<delay" in f]
    check(len(history_messages) == 2, f"Bob should receive exactly 2 history messages, got {len(history_messages)}")
    check(
        history_markers[3] in history_messages[0]
        or history_markers[3] in history_messages[1],
        "Should contain the fourth history item",
    )

    bob.send(
        f"<iq type='set' id='reg-remove' to='{room_jid}'>"
        "<query xmlns='jabber:iq:register'><remove/></query></iq>"
    )
    bob.receive_until("id='reg-remove'")
    
    # 4. Moderated Room Test
    print("Alice sets room to moderated...")
    alice.send(
        f"<iq type='set' id='config2' to='{room_jid}'>"
        "<query xmlns='http://jabber.org/protocol/muc#owner'>"
        "<x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#roomconfig</value></field>"
        "<field var='muc#roomconfig_moderatedroom'><value>1</value></field>"
        "</x></query></iq>"
    )
    alice.receive_until("id='config2'")
    
    print("Bob rejoins as visitor...")
    # Bob leaves and rejoins
    bob.send(f"<presence to='{room_jid}/Bob' type='unavailable'/>")
    bob.receive_until("type='unavailable'")
    alice.receive_until("type='unavailable'") # Alice sees Bob leave
    
    bob.send(f"<presence to='{room_jid}/Bob'><x xmlns='http://jabber.org/protocol/muc'/></presence>")
    reply, _ = bob.receive_until("role='visitor'")
    check("role='visitor'" in reply, "Bob should be visitor in moderated room")
    alice.receive_until("role='visitor'")
    
    print("Bob tries to speak and is rejected...")
    bob.send_with_pow(
        f"<message to='{room_jid}' type='groupchat' id='msg_b1'><body>Hi</body></message>",
        bob_token,
    )
    error_reply, _ = bob.receive_until("error")
    check("forbidden" in error_reply, "Visitor should get forbidden error when speaking")
    
    # 5. Bob requests voice and Alice approves the XEP-0045 data form.
    print("Bob requests voice and Alice approves...")
    bob.send_with_pow(
        f"<message to='{room_jid}' type='normal' id='voice-request'>"
        "<x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#request</value></field>"
        "<field var='muc#role'><value>participant</value></field>"
        "</x></message>",
        bob_token,
    )
    approval_form, _ = alice.receive_until("muc#request_allow")
    check("Bob" in approval_form and f"{BOB}@{DOMAIN}/client2" in approval_form,
          "Moderator did not receive a complete voice approval form")
    alice.send_with_pow(
        f"<message to='{room_jid}' type='normal' id='voice-approve'>"
        "<x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#request</value></field>"
        "<field var='muc#role'><value>participant</value></field>"
        f"<field var='muc#jid'><value>{BOB}@{DOMAIN}/client2</value></field>"
        "<field var='muc#roomnick'><value>Bob</value></field>"
        "<field var='muc#request_allow'><value>true</value></field>"
        "</x></message>",
        alice_token,
    )
    # The authoritative role operation fans out to every exact room audience.
    # Observing the moderator copy first also preserves any stanza error in the
    # timeout diagnostics instead of reporting only that Bob saw no presence.
    alice_role, _ = alice.receive_until("role='participant'")
    check("type='error'" not in alice_role, f"voice approval was rejected: {alice_role}")
    bob.receive_until("role='participant'") # Bob sees his new role

    bob.send(
        f"<iq type='get' id='self-ping' to='{room_jid}/Bob'>"
        "<ping xmlns='urn:xmpp:ping'/></iq>"
    )
    self_ping, _ = bob.receive_until("id='self-ping'")
    check("type='result'" in self_ping and f"from='{room_jid}/Bob'" in self_ping,
          "MUC self-ping optimization did not confirm the exact occupant")
    
    print("Bob speaks successfully...")
    bob.send_with_pow(
        f"<message to='{room_jid}' type='groupchat' id='msg_b2'><body>Hi now!</body></message>",
        bob_token,
    )
    bob.receive_until("Hi now!")
    alice.receive_until("Hi now!")
    
    # 6. Alice Kicks Bob
    print("Alice kicks Bob...")
    alice.send(
        f"<iq type='set' id='admin2' to='{room_jid}'>"
        "<query xmlns='http://jabber.org/protocol/muc#admin'>"
        "<item nick='Bob' role='none'/>"
        "</query></iq>"
    )
    alice.receive_until("id='admin2'")
    bob_kick, _ = bob.receive_until("type='unavailable'")
    check("role='none'" in bob_kick, "Bob should be kicked with role=none")
    
    # 7. Alice Bans Bob
    print("Alice bans Bob (outcast)...")
    alice.send(
        f"<iq type='set' id='admin3' to='{room_jid}'>"
        "<query xmlns='http://jabber.org/protocol/muc#admin'>"
        f"<item jid='{BOB}@{DOMAIN}' affiliation='outcast'/>"
        "</query></iq>"
    )
    alice.receive_until("id='admin3'")
    
    print("Bob tries to join and is forbidden...")
    bob.send(f"<presence to='{room_jid}/Bob'><x xmlns='http://jabber.org/protocol/muc'/></presence>")
    error_join, _ = bob.receive_until("error")
    check("forbidden" in error_join, "Banned user should get forbidden error when joining")

    print("Alice destroys the room...")
    alice.send(
        f"<iq type='set' id='destroy1' to='{room_jid}'>"
        "<query xmlns='http://jabber.org/protocol/muc#owner'>"
        "<destroy><reason>Integration complete</reason></destroy>"
        "</query></iq>"
    )
    _, destroy_frames = alice.receive_until("id='destroy1'")
    if not any("<destroy" in frame for frame in destroy_frames):
        _, destroy_notice_frames = alice.receive_until("<destroy")
        destroy_frames.extend(destroy_notice_frames)
    destroyed = "".join(destroy_frames)
    check("<destroy" in destroyed and "type='unavailable'" in destroyed,
          "Room destroy presence was not delivered")
    
    alice.close()
    bob.close()
    print("All MUC Phase 7 tests passed successfully! 🎉")

if __name__ == "__main__":
    try:
        run_test()
    except Exception as e:
        print(f"Test failed: {e}")
        sys.exit(1)
