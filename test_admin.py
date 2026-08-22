import asyncio
import slixmpp
import logging

logging.basicConfig(level=logging.DEBUG)

class UserA(slixmpp.ClientXMPP):
    def __init__(self, jid, password):
        super().__init__(jid, password)
        self.register_plugin("xep_0045")
        self.add_event_handler("session_start", self.start)

    async def start(self, event):
        self.send_presence()
        room = "testroom@muc.localhost"
        
        # join
        self.plugin["xep_0045"].join_muc(room, "test1")
        await asyncio.sleep(1)
        
        # configure as members only
        form = self.plugin["xep_0004"].make_form()
        form["type"] = "submit"
        form.add_field(var="muc#roomconfig_membersonly", value="1")
        try:
            await self.plugin["xep_0045"].set_room_config(room, config=form)
            print("Room configured!")
        except Exception as e:
            print("Config failed:", e)

        # add member
        try:
            await self.plugin["xep_0045"].set_affiliation(room, jid="test2@localhost", affiliation="member")
            print("Member added!")
        except Exception as e:
            print("Affiliation failed:", e)

        await asyncio.sleep(1)
        self.disconnect()

if __name__ == "__main__":
    a = UserA("test1@localhost", "123")
    a.connect(("127.0.0.1", 15222))
    loop = asyncio.get_event_loop()
    loop.run_until_complete(a.connected_event.wait())
    loop.run_forever()
