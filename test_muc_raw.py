#!/usr/bin/env python3
"""Raw TCP test for MUC join - bypasses slixmpp's TLS/SASL issues."""
import socket, ssl, base64, time, sys, re

HOST = "127.0.0.1"
PORT = 15222

def connect_and_auth(username, password):
    """Connect, STARTTLS, authenticate with PLAIN, bind resource."""
    sock = socket.create_connection((HOST, PORT))
    
    # Send stream open
    sock.sendall(b"<stream:stream to='localhost' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>")
    data = sock.recv(4096)
    print(f"  [{username}] Stream features: {data[:200]}")
    
    # STARTTLS
    sock.sendall(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
    data = sock.recv(4096)
    print(f"  [{username}] STARTTLS response: {data[:100]}")
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = ctx.wrap_socket(sock, server_hostname='localhost')
    
    # Re-open stream after TLS
    sock.sendall(b"<stream:stream to='localhost' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>")
    data = sock.recv(4096)
    
    # PLAIN auth
    creds = base64.b64encode(f"\x00{username}\x00{password}".encode()).decode()
    sock.sendall(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{creds}</auth>".encode())
    data = sock.recv(4096)
    print(f"  [{username}] Auth response: {data[:100]}")
    if b'<success' not in data:
        print(f"  [{username}] AUTH FAILED!")
        return None
    
    # Re-open stream after auth
    sock.sendall(b"<stream:stream to='localhost' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>")
    data = sock.recv(4096)
    
    # Bind resource
    import uuid
    res = f"raw_{uuid.uuid4().hex[:8]}"
    sock.sendall(f"<iq type='set' id='bind1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>{res}</resource></bind></iq>".encode())
    data = sock.recv(4096)
    print(f"  [{username}] Bind response: {data[:200]}")
    
    # Send presence
    sock.sendall(b"<presence/>")
    time.sleep(0.5)
    # Drain any roster/presence responses
    sock.setblocking(False)
    try:
        while True:
            sock.recv(4096)
    except:
        pass
    sock.setblocking(True)
    
    return sock

def main():
    print("=== STEP 1: Connect test1, join room, configure, add member ===")
    s1 = connect_and_auth("test1", "123")
    if not s1:
        sys.exit(1)
    
    # Join room
    room = f"testjoin_{int(time.time())}@conference.localhost"
    s1.sendall(f"<presence to='{room}/test1_raw'><x xmlns='http://jabber.org/protocol/muc'/></presence>".encode())
    time.sleep(1)
    s1.setblocking(False)
    try:
        data = s1.recv(8192)
        print(f"  [test1] Join response: {data[:300]}")
    except:
        pass
    s1.setblocking(True)
    
    # Configure as members-only
    print("\n=== STEP 2: Configure room as members-only ===")
    config_iq = f"""<iq to='{room}' type='set' id='cfg1'>
      <query xmlns='http://jabber.org/protocol/muc#owner'>
        <x xmlns='jabber:x:data' type='submit'>
          <field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#roomconfig</value></field>
          <field var='muc#roomconfig_membersonly'><value>1</value></field>
          <field var='muc#roomconfig_persistentroom'><value>1</value></field>
        </x>
      </query>
    </iq>"""
    s1.sendall(config_iq.encode())
    time.sleep(0.5)
    data = s1.recv(4096)
    print(f"  Config response: {data[:200]}")
    
    # Set test2 as member via admin
    print("\n=== STEP 3: Set test2 as member ===")
    admin_iq = f"""<iq to='{room}' type='set' id='aff1'>
      <query xmlns='http://jabber.org/protocol/muc#admin'>
        <item jid='test2@localhost' affiliation='member'/>
      </query>
    </iq>"""
    s1.sendall(admin_iq.encode())
    time.sleep(0.5)
    data = s1.recv(4096)
    print(f"  Admin set response: {data[:200]}")
    
    # Now connect test2 and try to join
    print("\n=== STEP 4: Connect test2 and join room ===")
    s2 = connect_and_auth("test2", "123")
    if not s2:
        sys.exit(1)
    
    s2.sendall(f"<presence to='{room}/test2_raw'><x xmlns='http://jabber.org/protocol/muc'/></presence>".encode())
    time.sleep(2)
    
    s2.setblocking(False)
    all_data = b""
    try:
        while True:
            chunk = s2.recv(8192)
            if not chunk:
                break
            all_data += chunk
    except:
        pass
    s2.setblocking(True)
    
    print(f"  [test2] Join response ({len(all_data)} bytes): {all_data[:500]}")
    
    if b'registration-required' in all_data:
        print("\n!!! FAILED: registration-required error - test2 can't join !!!")
        result = False
    elif b'error' in all_data.lower():
        print(f"\n!!! FAILED: error in response !!!")
        result = False
    elif b'type="unavailable"' in all_data or b"type='unavailable'" in all_data:
        print("\n!!! FAILED: got unavailable presence !!!")
        result = False
    elif b'<presence' in all_data and room.encode() in all_data:
        print("\n=== SUCCESS: test2 joined the room! ===")
        result = True
    else:
        print("\n??? UNCLEAR: check raw response above")
        result = False
    
    # Check server logs
    print("\n=== STEP 5: Check server MUC logs ===")
    s1.sendall(b"</stream:stream>")
    s2.sendall(b"</stream:stream>")
    s1.close()
    s2.close()
    
    sys.exit(0 if result else 1)

if __name__ == "__main__":
    main()
