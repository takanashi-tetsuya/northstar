#!/usr/bin/env python3
"""Phase 7 MUC Integration Test Script."""

import sys
import time

# Import utilities from the existing integration script
import importlib.util
spec = importlib.util.spec_from_file_location("integration", "scripts/integration-wsl.py")
integration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(integration)

from integration import (
    XmppWebSocket, wait_ready, ALICE, BOB, DOMAIN, check
)

def run_test():
    print("Waiting for Northstar XMPP Server to be ready...")
    wait_ready()
    
    print("Logging in Alice and Bob...")
    alice = XmppWebSocket(ALICE, "integration-password-123", "client1")
    bob = XmppWebSocket(BOB, "integration-password-123", "client2")
    
    room_jid = f"testroom@conference.{DOMAIN}"
    
    # 1. Alice creates the room
    print(f"Alice creating room {room_jid}...")
    alice.send(f"<presence to='{room_jid}/Alice'><x xmlns='http://jabber.org/protocol/muc'/></presence>")
    reply, _ = alice.receive_until("</presence>")
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
    
    # 2. Alice sends 5 messages
    print("Alice sending 5 messages...")
    for i in range(1, 6):
        alice.send(f"<message to='{room_jid}' type='groupchat'><body>Message {i}</body></message>")
        alice.receive_until(f"Message {i}") # wait for reflection
    
    # 3. Bob joins with maxstanzas=2
    print("Bob joining with maxstanzas=2...")
    bob.send(f"<presence to='{room_jid}/Bob'><x xmlns='http://jabber.org/protocol/muc'><history maxstanzas='2'/></x></presence>")
    # Bob should receive presence, then subject, then exactly 2 history messages
    reply, frames = bob.receive_until("Message 5", timeout=5)
    
    # Count how many messages Bob received in total
    history_messages = [f for f in frames if "<message" in f and "<delay" in f]
    check(len(history_messages) == 2, f"Bob should receive exactly 2 history messages, got {len(history_messages)}")
    check("Message 4" in history_messages[0] or "Message 4" in history_messages[1], "Should contain Message 4")
    
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
    bob.send(f"<message to='{room_jid}' type='groupchat' id='msg_b1'><body>Hi</body></message>")
    error_reply, _ = bob.receive_until("error")
    check("forbidden" in error_reply, "Visitor should get forbidden error when speaking")
    
    # 5. Alice grants Voice (participant)
    print("Alice grants Bob voice (participant)...")
    alice.send(
        f"<iq type='set' id='admin1' to='{room_jid}'>"
        "<query xmlns='http://jabber.org/protocol/muc#admin'>"
        "<item nick='Bob' role='participant'/>"
        "</query></iq>"
    )
    alice.receive_until("id='admin1'")
    bob.receive_until("role='participant'") # Bob sees his new role
    
    print("Bob speaks successfully...")
    bob.send(f"<message to='{room_jid}' type='groupchat' id='msg_b2'><body>Hi now!</body></message>")
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
    
    alice.close()
    bob.close()
    print("All MUC Phase 7 tests passed successfully! 🎉")

if __name__ == "__main__":
    try:
        run_test()
    except Exception as e:
        print(f"Test failed: {e}")
        sys.exit(1)
