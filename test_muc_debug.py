import sys
import logging
from slixmpp import ClientXMPP

class MUCLogger(ClientXMPP):
    def __init__(self, jid, password, room):
        super().__init__(jid, password)
        self.room = room
        self.add_event_handler("session_start", self.start)
        self.add_event_handler("message", self.message)
        self.add_event_handler("presence", self.presence)
        self.add_event_handler("raw_recv", self.raw_recv)

    def start(self, event):
        self.send_presence(pstatus="Available", pshow="chat")
        
        # Add CAPS manually to simulate Gajim
        pres = self.make_presence()
        caps = pres.xml.makeelement("{http://jabber.org/protocol/caps}c")
        caps.set("hash", "sha-1")
        caps.set("node", "http://gajim.org")
        caps.set("ver", "Qyp/93Cj7O0=")
        pres.xml.append(caps)
        pres.send()
        
        self.plugin['xep_0045'].join_muc(self.room, self.boundjid.user)

    def message(self, msg):
        print(f"\n[MSG] {msg}")

    def presence(self, pres):
        print(f"\n[PRESENCE] {pres}")

    def raw_recv(self, data):
        print(f"\n[RAW IN] {data}")

if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING, format='%(levelname)-8s %(message)s')
    xmpp = MUCLogger('test6@localhost', '1234', 'otuxabiz@conference.localhost')
    xmpp.register_plugin('xep_0030') # Service Discovery
    xmpp.register_plugin('xep_0045') # MUC
    xmpp.register_plugin('xep_0199') # XMPP Ping
    xmpp.connect(('127.0.0.1', 5222))
    xmpp.process()
