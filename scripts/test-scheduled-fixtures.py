#!/usr/bin/env python3
"""Check scheduled fixtures against runner toolchains and device-bound login."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("integration", ROOT / "integration-wsl.py")
integration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(integration)
DEVICE = "b8095b5c-16fa-4fbe-915a-0f19b572c86e"


class DeviceLoginTests(unittest.TestCase):
    def client(self):
        client = object.__new__(integration.XmppWebSocket)
        client.username = "load"
        client.password = "test-password"
        client.resource = "load-17"
        client.device_id = DEVICE
        return client

    def login(self, resume=None):
        features = "<stream:features><sm xmlns='urn:xmpp:sm:3'/><csi xmlns='urn:xmpp:csi:0'/></stream:features>"
        replies = [
            ("<open/>", []),
            ("<stream:features><authentication xmlns='urn:xmpp:sasl:2'/></stream:features>", []),
            (features, ["<success xmlns='urn:xmpp:sasl:2'></success>", features]),
            ("<resumed previd='test-resume-id'/>" if resume else "<iq type='result'/>", []),
        ]
        with patch.object(integration.XmppWebSocket, "receive_until", side_effect=replies), \
                patch.object(integration.XmppWebSocket, "send") as send:
            self.client().login(resume=resume, initial_presence=False)
        return [call.args[0] for call in send.call_args_list]

    def test_device_authentication_preserves_the_requested_resource(self):
        sent = self.login()
        authentication = ET.fromstring(sent[1])
        self.assertEqual(authentication.tag, "{urn:xmpp:sasl:2}authenticate")
        self.assertEqual(authentication.find("{urn:xmpp:sasl:2}user-agent").get("id"), DEVICE)
        self.assertIn("<resource>load-17</resource>", sent[2])
        self.assertEqual(len(sent), 3)

    def test_resume_reuses_device_identity_without_rebinding(self):
        sent = self.login(resume=("test-resume-id", 0))
        authentication = ET.fromstring(sent[1])
        self.assertEqual(authentication.find("{urn:xmpp:sasl:2}user-agent").get("id"), DEVICE)
        resume = ET.fromstring(sent[2])
        self.assertEqual(resume.tag, "{urn:xmpp:sm:3}resume")
        self.assertEqual(resume.attrib, {"previd": "test-resume-id", "h": "0"})
        self.assertEqual(len(sent), 3)


class ParserRunnerTests(unittest.TestCase):
    def test_ci_toolchain_layout_runs_every_target_with_the_pinned_nightly(self):
        with tempfile.TemporaryDirectory(prefix="northstar-fuzz-runner-test-") as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            (root / "fuzz").mkdir()
            (root / "fuzz/Cargo.toml").touch()
            script = root / "scripts/parser-robustness-wsl.sh"
            script.write_bytes((ROOT / script.name).read_bytes())
            cargo = root / "cargo"
            cargo.write_text(
                "#!/usr/bin/env python3\nimport json,os,sys\n"
                "with open(os.environ['CALL_LOG'], 'a') as output:\n"
                " output.write(json.dumps(sys.argv[1:]) + '\\n')\n"
            )
            cargo.chmod(0o700)
            log = root / "calls.jsonl"
            result = subprocess.run(
                ["bash", str(script), "30"], capture_output=True, text=True, timeout=10,
                env={**os.environ, "PATH": f"{root}:/usr/bin:/bin",
                     "XMPP_TEST_SYSTEM_TOOLCHAIN": "true", "CALL_LOG": str(log)},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertEqual(calls[0], ["+nightly-2026-08-25", "fuzz", "--help"])
            self.assertEqual([call[3] for call in calls[1:]], [
                "xml_framing", "semantic_stanza", "bosh_ws_framing",
                "rest_extractors", "sasl_sm_state", "mam_pubsub_parsing",
            ])
            for call in calls[1:]:
                self.assertEqual(call[:3], ["+nightly-2026-08-25", "fuzz", "run"])
                self.assertIn("-max_total_time=30", call)
                self.assertIn("-timeout=5", call)
                self.assertIn("-rss_limit_mb=2048", call)
            self.assertIn("PARSER_ROBUSTNESS_PASS targets=6 duration_each=30s", result.stdout)


if __name__ == "__main__":
    unittest.main()
