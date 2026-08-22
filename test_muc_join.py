#!/usr/bin/env python3
"""Test MUC invite + join flow end-to-end."""
import asyncio
import ssl
import slixmpp
import logging
import sys

logging.basicConfig(level=logging.WARNING, format='%(asctime)s %(name)s %(levelname)s %(message)s')
log = logging.getLogger("test_muc")
log.setLevel(logging.DEBUG)

HOST = "127.0.0.1"
PORT = 15222
ROOM = "testjoin@muc.localhost"

def make_ssl_context():
    """Create an SSL context that doesn't verify certificates (for self-signed certs)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

class Inviter(slixmpp.ClientXMPP):
    def __init__(self):
        super().__init__("test1@localhost", "123")
        self.ssl_context = make_ssl_context()
        self.sasl_mech = 'PLAIN'
        self.register_plugin("xep_0045")
        self.register_plugin("xep_0004")
        self.add_event_handler("session_start", self.start)
        self.done = asyncio.Event()

    async def start(self, event):
        self.send_presence()
        await asyncio.sleep(0.5)
        
        log.info("STEP 1: Joining room")
        self.plugin["xep_0045"].join_muc(ROOM, "test1")
        await asyncio.sleep(1)
        
        log.info("STEP 2: Configuring room as members-only + persistent")
        form = self.plugin["xep_0004"].make_form()
        form["type"] = "submit"
        form.add_field(var="muc#roomconfig_membersonly", value="1")
        form.add_field(var="muc#roomconfig_persistentroom", value="1")
        try:
            await self.plugin["xep_0045"].set_room_config(ROOM, config=form)
            log.info("Room configured!")
        except Exception as e:
            log.error(f"Config failed: {e}")
        
        log.info("STEP 3: Setting test2 affiliation to member")
        try:
            await self.plugin["xep_0045"].set_affiliation(ROOM, jid="test2@localhost", affiliation="member")
            log.info("test2 set as member!")
        except Exception as e:
            log.error(f"Affiliation set failed: {e}")
        
        await asyncio.sleep(1)
        log.info("STEP 4: Inviter ready")
        self.done.set()


class Joiner(slixmpp.ClientXMPP):
    def __init__(self):
        super().__init__("test2@localhost", "123")
        self.ssl_context = make_ssl_context()
        self.sasl_mech = 'PLAIN'
        self.register_plugin("xep_0045")
        self.add_event_handler("session_start", self.start)
        self.add_event_handler("muc::%s::got_online" % ROOM, self.muc_online)
        self.add_event_handler("presence_error", self.on_error)
        self.result = asyncio.Event()
        self.join_success = False

    async def start(self, event):
        self.send_presence()
        await asyncio.sleep(0.5)
        
        log.info("STEP 5: test2 attempting to join room")
        self.plugin["xep_0045"].join_muc(ROOM, "test2")
        await asyncio.sleep(3)
        
        if not self.join_success:
            log.error("JOIN FAILED - no got_online event received")
        
        self.result.set()

    def muc_online(self, presence):
        nick = presence['muc']['nick']
        log.info(f"MUC online: {nick}")
        if nick == "test2":
            log.info("JOIN SUCCESS! test2 is in the room")
            self.join_success = True

    def on_error(self, presence):
        log.error(f"Presence error received: type={presence.get('type')} from={presence.get('from')}")
        for child in presence.xml:
            if child.tag.endswith('error'):
                for sub in child:
                    log.error(f"  error detail: {sub.tag}")


async def main():
    inviter = Inviter()
    inviter.connect(host=HOST, port=PORT)
    await inviter.done.wait()
    
    log.info("--- Inviter done, launching joiner ---")
    
    joiner = Joiner()
    joiner.connect(host=HOST, port=PORT)
    await joiner.result.wait()
    
    result = "SUCCESS" if joiner.join_success else "FAILED"
    log.info(f"TEST COMPLETE - Join result: {result}")
    
    joiner.disconnect()
    inviter.disconnect()
    await asyncio.sleep(0.5)
    
    sys.exit(0 if joiner.join_success else 1)

if __name__ == "__main__":
    asyncio.run(main())
