#!/usr/bin/env python3
"""Verify that both version-skew negative probes request volatile delivery."""

import importlib.util
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET


spec = importlib.util.spec_from_file_location("cluster_fixture", Path(__file__).with_name("cluster-wsl.py"))
cluster = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cluster)


class VersionSkewProbeTests(unittest.TestCase):
    def test_both_version_directions_have_exact_volatile_chat_semantics(self):
        recipient = "bob_cluster@cluster.localhost/fault-bob"
        for stanza_id in ("newer-peer-version", "legacy-peer-version"):
            with self.subTest(stanza_id=stanza_id):
                root = ET.fromstring(cluster.version_skew_probe_stanza(recipient, stanza_id))
                self.assertEqual(root.tag, "{jabber:client}message")
                self.assertEqual(root.attrib, {"to": recipient, "type": "chat", "id": stanza_id})
                self.assertEqual(root.findtext("{jabber:client}body"), "incompatible peer contract must fail")
                self.assertEqual(len(root.findall("{urn:xmpp:hints}no-store")), 1)
                self.assertIsNone(root.find("{urn:xmpp:hints}store"))

    def test_attribute_text_cannot_change_probe_target_or_delivery_policy(self):
        recipient = "bob@example.test/resource'&<"
        stanza_id = "probe'&<"
        root = ET.fromstring(cluster.version_skew_probe_stanza(recipient, stanza_id))
        self.assertEqual(root.get("to"), recipient)
        self.assertEqual(root.get("id"), stanza_id)
        self.assertEqual(len(root), 2)
        self.assertEqual(len(root.findall("{urn:xmpp:hints}no-store")), 1)


if __name__ == "__main__":
    unittest.main()
