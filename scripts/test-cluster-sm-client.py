#!/usr/bin/env python3
"""Offline checks for the cluster fixture's strict same-device SM client."""

import base64
from collections import deque
import contextlib
import importlib.util
import io
from pathlib import Path
import time
import traceback
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("cluster_fixture", Path(__file__).with_name("cluster-wsl.py"))
cluster = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cluster)
DEVICE = "d78260e0-08b3-4bc4-90cb-c57c3924d989"
SECRET = "test-only-secret-resumption-identifier"
OPEN_FEATURES = (
    "<open xmlns='urn:ietf:params:xml:ns:xmpp-framing'/>"
    f"<stream:features xmlns:stream='{cluster.STREAM_NAMESPACE}'>"
    f"<authentication xmlns='{cluster.SASL2_NAMESPACE}'/></stream:features>"
)
SUCCESS_FEATURES = (
    f"<success xmlns='{cluster.SASL2_NAMESPACE}'/>"
    f"<stream:features xmlns:stream='{cluster.STREAM_NAMESPACE}'>"
    f"<sm xmlns='{cluster.SM_NAMESPACE}'/></stream:features>"
)


def client():
    instance = object.__new__(cluster.DeviceXmppWebSocket)
    instance.device_id = DEVICE
    instance.username = cluster.BOB
    instance.password = cluster.PASSWORD
    instance.resource = "bob-node-b"
    instance._construction_deadline = time.monotonic() + 10
    instance._protocol_frames = deque()
    return instance


class DeviceClientTests(unittest.TestCase):
    def test_split_preserves_all_original_siblings_and_nested_self_closing_xml(self):
        parts = ["<open/>", "<features><x a='a>b'/></features>", '<message><body>雪</body></message>']
        self.assertEqual(cluster.split_protocol_elements("".join(parts)), parts)
        self.assertEqual(cluster.split_protocol_elements("<fixture/>"), ["<fixture/>"])

    def test_authentication_keeps_stable_device_and_exact_resource_without_inline_bind(self):
        bind = (
            "<iq xmlns='jabber:client' id='bind-bob-node-b' type='result'>"
            "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>"
            f"<jid>{cluster.BOB}@{cluster.DOMAIN}/bob-node-b</jid></bind></iq>"
        )
        with patch.object(cluster.fixture.XmppWebSocket, "receive", side_effect=[OPEN_FEATURES, SUCCESS_FEATURES, bind]), \
                patch.object(cluster.fixture.XmppWebSocket, "send") as send:
            client().login()
        sent = [call.args[0] for call in send.call_args_list]
        auth = cluster.protocol_element(sent[1])
        self.assertEqual(auth.tag, f"{{{cluster.SASL2_NAMESPACE}}}authenticate")
        self.assertEqual(auth.find(f"{{{cluster.SASL2_NAMESPACE}}}user-agent").get("id"), DEVICE)
        proof = auth.find(f"{{{cluster.SASL2_NAMESPACE}}}initial-response").text
        self.assertEqual(base64.b64decode(proof).decode(), f"\0{cluster.BOB}\0{cluster.PASSWORD}")
        self.assertIsNone(auth.find("{urn:xmpp:bind:0}bind"))
        self.assertIsNone(auth.find(f"{{{cluster.SM_NAMESPACE}}}enable"))
        self.assertEqual(sum("<open " in item for item in sent), 1)
        self.assertIn("<resource>bob-node-b</resource>", sent[2])
        self.assertEqual(sent[3], "<presence xmlns='jabber:client'/>")

    def test_resume_authenticates_same_device_without_bind_or_presence_and_keeps_replay(self):
        replay = "<message xmlns='jabber:client' id='replayed'><body>kept</body></message>"
        frames = [OPEN_FEATURES, SUCCESS_FEATURES,
                  f'<resumed xmlns="{cluster.SM_NAMESPACE}" previd="{SECRET}" h="0"/>' + replay]
        instance = client()
        output = io.StringIO()
        with patch.object(cluster.fixture.XmppWebSocket, "receive", side_effect=frames), \
                patch.object(cluster.fixture.XmppWebSocket, "send") as send, contextlib.redirect_stdout(output):
            instance.login(resume=(SECRET, 0))
            self.assertEqual(instance.receive(), replay)
        sent = [call.args[0] for call in send.call_args_list]
        self.assertEqual(len(sent), 3)
        auth = cluster.protocol_element(sent[1])
        self.assertEqual(auth.find(f"{{{cluster.SASL2_NAMESPACE}}}user-agent").get("id"), DEVICE)
        self.assertEqual(cluster.protocol_element(sent[2]).get("h"), "0")
        self.assertFalse(any("<bind" in item or "<presence" in item for item in sent))
        self.assertNotIn(SECRET, output.getvalue())

    def test_enabled_parser_accepts_xml_quotes_and_logs_only_safe_metadata(self):
        output = io.StringIO()
        with patch.object(cluster.fixture.XmppWebSocket, "receive", return_value=(
            f'<enabled xmlns="{cluster.SM_NAMESPACE}" resume="true" id="{SECRET}"/>'
        )), patch.object(cluster.fixture.XmppWebSocket, "send"), contextlib.redirect_stdout(output):
            self.assertEqual(client().enable_resumption(), SECRET)
        self.assertIn("id_present=True resume=true", output.getvalue())
        self.assertNotIn(SECRET, output.getvalue())

    def test_disabled_or_rejected_sm_never_echoes_the_identifier(self):
        for frame in [
            f"<enabled xmlns='{cluster.SM_NAMESPACE}' resume='false' id='{SECRET}'/>",
            f"<failed xmlns='{cluster.SM_NAMESPACE}' secret='{SECRET}'/>",
            f"<enabled xmlns='urn:unexpected' id='{SECRET}'/>",
            f"<enabled xmlns='{cluster.SM_NAMESPACE}' id='{SECRET}'",
        ]:
            with self.subTest(frame_kind=frame.split(" ", 1)[0]):
                output = io.StringIO()
                with patch.object(cluster.fixture.XmppWebSocket, "receive", side_effect=[frame, EOFError("closed")]), \
                        patch.object(cluster.fixture.XmppWebSocket, "send"), contextlib.redirect_stdout(output):
                    with self.assertRaises((RuntimeError, AssertionError)) as caught:
                        client().enable_resumption()
                self.assertNotIn(SECRET, str(caught.exception))
                self.assertNotIn(SECRET, output.getvalue())

    def test_mismatched_exact_resource_and_resume_identifier_are_rejected(self):
        bind = (
            "<iq xmlns='jabber:client' id='bind-bob-node-b' type='result'>"
            "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>other@cluster.localhost/r</jid></bind></iq>"
        )
        with patch.object(cluster.fixture.XmppWebSocket, "receive", side_effect=[OPEN_FEATURES, SUCCESS_FEATURES, bind]), \
                patch.object(cluster.fixture.XmppWebSocket, "send"), self.assertRaises(AssertionError):
            client().login()
        with patch.object(cluster.fixture.XmppWebSocket, "receive", side_effect=[OPEN_FEATURES, SUCCESS_FEATURES,
                f"<resumed xmlns='{cluster.SM_NAMESPACE}' previd='{SECRET}-wrong' h='0'/>"]), \
                patch.object(cluster.fixture.XmppWebSocket, "send"), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(AssertionError) as caught:
                client().login(resume=(SECRET, 0))
        self.assertNotIn(SECRET, str(caught.exception))

    def test_invalid_device_and_unbounded_or_declaration_xml_are_rejected(self):
        for device in ["00000000-0000-0000-0000-000000000000", DEVICE.upper(), "invalid"]:
            with self.assertRaises(RuntimeError):
                cluster.DeviceXmppWebSocket("unused", "unused", "unused", device_id=device)
        for frame in ["x" * (2 * 1024 * 1024 + 1), "<x/>" * 257, "<!DOCTYPE x [<!ENTITY a 'value'>]><x>&a;</x>"]:
            with self.assertRaises(RuntimeError):
                cluster.split_protocol_elements(frame)

    def test_business_wait_errors_never_echo_queued_enabled_or_resumed_identifiers(self):
        for element in ["enabled", "resumed"]:
            for error in [EOFError("closed"), TimeoutError("late")]:
                with self.subTest(element=element, error=type(error).__name__):
                    instance = client()
                    instance._protocol_frames.append(
                        f"<{element} xmlns='{cluster.SM_NAMESPACE}' id='{SECRET}' previd='{SECRET}'/>"
                    )
                    with patch.object(cluster.fixture.XmppWebSocket, "receive", side_effect=error):
                        with self.assertRaises(type(error)) as caught:
                            instance.receive_until("not-present")
                    self.assertIn("frames_received=1", str(caught.exception))
                    self.assertNotIn(SECRET, "".join(traceback.format_exception(caught.exception)))

    def test_business_wait_keeps_original_success_tuple_and_following_sibling(self):
        first, target, later = "<presence id='first'/>", "<message id='target'/>", "<presence id='later'/>"
        instance = client()
        with patch.object(cluster.fixture.XmppWebSocket, "receive", return_value=first + target + later):
            self.assertEqual(instance.receive_until("id='target'"), (target, [first, target]))
            self.assertEqual(instance.receive(), later)


if __name__ == "__main__":
    unittest.main()
