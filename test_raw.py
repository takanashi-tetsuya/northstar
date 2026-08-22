import socket
import sys
import time

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 15222))
s.send(b"<stream:stream to='localhost' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>")
time.sleep(0.5)
print(s.recv(1024).decode())

import base64
auth_str = f"\\x00test6\\x001234"
auth_b64 = base64.b64encode(auth_str.encode()).decode()
s.send(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{auth_b64}</auth>".encode())
time.sleep(0.5)
print(s.recv(1024).decode())

s.send(b"<stream:stream to='localhost' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>")
time.sleep(0.5)
print(s.recv(1024).decode())

s.send(b"<iq type='set' id='bind_1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>test</resource></bind></iq>")
time.sleep(0.5)
print(s.recv(1024).decode())

s.send(b"<presence><c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='http://gajim.org' ver='Qyp/93Cj7O0='/></presence>")
time.sleep(0.5)
print(s.recv(1024).decode())

s.send(b"<presence to='otuxabiz@conference.localhost/test6'><x xmlns='http://jabber.org/protocol/muc'/></presence>")
time.sleep(0.5)

s.send(b"<iq type='get' id='disco_1' to='otuxabiz@conference.localhost/test6'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")
time.sleep(0.5)

while True:
    try:
        s.settimeout(0.5)
        data = s.recv(4096)
        if not data: break
        print(data.decode())
    except Exception:
        break
