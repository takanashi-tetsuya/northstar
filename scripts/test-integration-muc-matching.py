#!/usr/bin/env python3
"""Pure in-memory regression checks for the controls-room join fixture.

No WebSocket constructor, socket, listener, process, service, or database is
used. Only send/receive mocks and a fake monotonic clock drive the fixture.
integration-wsl.py has environment reads and definitions at import time;
its integration run is protected by the __main__ guard.
"""

import importlib.util
from pathlib import Path
import unittest
from unittest import mock
import xml.etree.ElementTree as ET


SPEC = importlib.util.spec_from_file_location(
    "integration_muc_matching", Path(__file__).with_name("integration-wsl.py")
)
integration = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(integration)

ROOM = "integration-controls@conference.localhost"
OCCUPANT = f"{ROOM}/Alice"
JOIN_ID = "muc-controls-owner-join"


def presence(
    sender=OCCUPANT, join_id=JOIN_ID, affiliation="owner", statuses=("110", "201"),
    stanza_type=None,
):
    type_attr = "" if stanza_type is None else f" type='{stanza_type}'"
    status_xml = "".join(f"<status code='{code}'/>" for code in statuses)
    return (
        f"<presence xmlns='jabber:client' from='{sender}' id='{join_id}'{type_attr}>"
        "<x xmlns='http://jabber.org/protocol/muc#user'>"
        f"<item affiliation='{affiliation}' role='moderator'/>{status_xml}"
        "</x></presence>"
    )


# This is a constructed queue entry, not a captured frame from the failed CI.
PRIOR_ROOM = presence(
    sender="integration-locked@conference.localhost/Alice",
    join_id="locked-owner-join", affiliation="none", statuses=("110",),
    stanza_type="unavailable",
)
CREATED = presence()


class ControlsRoomMatchingTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        clock = mock.patch.object(integration.time, "monotonic", lambda: self.now)
        clock.start()
        self.addCleanup(clock.stop)
        # Bypass __init__ so no transport can be constructed or authenticated.
        self.client = object.__new__(integration.XmppWebSocket)
        self.client.send = mock.Mock()
        self.client.receive = mock.Mock()

    def create(self, replies):
        self.client.receive.side_effect = replies
        return integration.create_muc_controls_room(self.client, ROOM)

    def assert_diagnostic(self, error, frames):
        message = str(error)
        self.assertIn(OCCUPANT, message)
        self.assertIn(JOIN_ID, message)
        self.assertIn(f"frames={frames!r}", message)

    def test_old_substring_wait_accepts_unrelated_self_presence(self):
        self.client.receive.side_effect = [PRIOR_ROOM, CREATED]
        selected, frames = self.client.receive_until("code='110'")
        self.assertEqual(selected, PRIOR_ROOM)
        self.assertEqual(frames, [PRIOR_ROOM])
        self.client.receive.assert_called_once()

    def test_controls_join_skips_prior_room_and_accepts_actual_reply(self):
        self.create([PRIOR_ROOM, CREATED])
        self.assertEqual(self.client.receive.call_count, 2)
        self.client.send.assert_called_once()
        request = ET.fromstring(self.client.send.call_args.args[0])
        self.assertEqual(request.tag, "{jabber:client}presence")
        self.assertEqual(request.get("to"), OCCUPANT)
        self.assertEqual(request.get("id"), JOIN_ID)
        self.assertIsNotNone(request.find("{http://jabber.org/protocol/muc}x"))

    def test_reply_requires_exact_root_from_and_join_id(self):
        unrelated = [
            presence(sender=ROOM),
            presence(sender=f"{ROOM}/Bob"),
            presence(sender=f"{OCCUPANT}-other"),
            presence(join_id=f"{JOIN_ID}-other"),
            CREATED.replace(f" id='{JOIN_ID}'", ""),
            CREATED.replace("jabber:client", "urn:unrelated"),
            CREATED.replace("<presence ", "<message ").replace("</presence>", "</message>"),
            f"<message xmlns='jabber:client'><body>{JOIN_ID}</body>{CREATED}</message>",
        ]
        self.create([*unrelated, CREATED])
        self.assertEqual(self.client.receive.call_count, len(unrelated) + 1)

    def test_valid_reply_supports_xml_quotes_and_namespace_prefixes(self):
        self.create([
            f'<c:presence xmlns:c="jabber:client" id="{JOIN_ID}" from="{OCCUPANT}">'
            '<u:x xmlns:u="http://jabber.org/protocol/muc#user">'
            '<u:item role="moderator" affiliation="owner"/>'
            '<u:status code="201"/><u:status code="110"/></u:x></c:presence>'
        ])
        self.client.receive.assert_called_once()

    def test_correlated_error_fails_before_later_success(self):
        error_reply = (
            f"<presence xmlns='jabber:client' from='{OCCUPANT}' id='{JOIN_ID}' type='error'>"
            "<x xmlns='http://jabber.org/protocol/muc'/><error type='cancel'>"
            "<item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>"
        )
        with self.assertRaisesRegex(AssertionError, "not created with owner affiliation") as caught:
            self.create([PRIOR_ROOM, error_reply, CREATED])
        self.assertEqual(self.client.receive.call_count, 2)
        self.assert_diagnostic(caught.exception, [PRIOR_ROOM, error_reply])

    def test_correlated_invalid_creation_fails_before_later_success(self):
        for invalid in (
            presence(affiliation="member"),
            presence(statuses=("110",)),
            presence(statuses=("110", "210")),
            presence(statuses=("201",)),
            presence(stanza_type="unavailable"),
            presence(stanza_type="error"),
            CREATED.replace("http://jabber.org/protocol/muc#user", "urn:unrelated"),
        ):
            with self.subTest(reply=invalid):
                self.client.receive.reset_mock()
                with self.assertRaisesRegex(AssertionError, "not created with owner affiliation") as caught:
                    self.create([invalid, CREATED])
                self.client.receive.assert_called_once()
                self.assert_diagnostic(caught.exception, [invalid])

    def test_receive_timeout_retains_all_observed_frames(self):
        failure = TimeoutError("fake receive deadline")
        frames = [PRIOR_ROOM, presence(join_id="another-join")]
        with self.assertRaises(TimeoutError) as caught:
            self.create([*frames, failure])
        self.assert_diagnostic(caught.exception, frames)
        self.assertIs(caught.exception.__cause__, failure)

    def test_eof_and_connection_error_fail_with_observed_frames(self):
        for failure in (EOFError("fake closed frame"), ConnectionResetError("fake reset")):
            with self.subTest(error=type(failure).__name__):
                with self.assertRaises(EOFError) as caught:
                    self.create([PRIOR_ROOM, failure])
                self.assert_diagnostic(caught.exception, [PRIOR_ROOM])
                self.assertIs(caught.exception.__cause__, failure)

    def test_skipped_frames_share_one_ten_second_deadline(self):
        delays = iter((4, 6))

        def receive(timeout):
            self.now += next(delays)
            return PRIOR_ROOM

        with self.assertRaises(TimeoutError) as caught:
            self.create(receive)
        self.assertEqual(self.client.receive.call_args_list, [mock.call(10), mock.call(6)])
        self.assert_diagnostic(caught.exception, [PRIOR_ROOM, PRIOR_ROOM])


if __name__ == "__main__":
    unittest.main()
