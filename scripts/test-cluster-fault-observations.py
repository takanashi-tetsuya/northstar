#!/usr/bin/env python3
"""Offline checks for fresh, bounded cluster rejection observations."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import traceback
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("cluster_fixture", Path(__file__).with_name("cluster-wsl.py"))
cluster = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cluster)
MAX_BYTES = 256 * 1024
SECRET = "synthetic-private-log-content-must-not-be-reported"


def rejection(**changes):
    event = {
        "target": "rust_xmpp_server::cluster",
        "fields": {
            "message": "rejected unauthenticated cluster protocol envelope",
            "error": "cluster envelope is oversized",
        },
    }
    event.update(changes)
    return (json.dumps(event) + "\n").encode()


class RejectionObservationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="northstar-cluster-observation-test-")
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "node-b.log"
        self.path.write_bytes(b"")

    def observe(self, offset=0):
        return cluster.authentication_rejection_since(self.path, offset)

    def test_accepts_only_a_new_complete_matching_event(self):
        previous = rejection()
        self.path.write_bytes(previous)
        self.assertFalse(self.observe(len(previous)))
        with self.path.open("ab") as log:
            log.write(rejection())
        self.assertTrue(self.observe(len(previous)))

    def test_incomplete_json_and_missing_newline_remain_pending(self):
        event = rejection()
        self.path.write_bytes(event[:len(event) // 2])
        self.assertFalse(self.observe())
        self.path.write_bytes(event.rstrip(b"\n"))
        self.assertFalse(self.observe())
        with self.path.open("ab") as log:
            log.write(b"\n")
        self.assertTrue(self.observe())

    def test_wrong_target_message_or_reason_never_counts(self):
        expected = json.loads(rejection())
        wrong_events = [
            rejection(target="rust_xmpp_server::xmpp"),
            rejection(fields={**expected["fields"], "message": "different rejection"}),
            rejection(fields={**expected["fields"], "error": "cluster signature is invalid"}),
            rejection(fields={**expected["fields"], "error": "cluster envelope is oversized: extra"}),
        ]
        for event in wrong_events:
            with self.subTest(event=event):
                self.path.write_bytes(event)
                self.assertFalse(self.observe())

    def test_unstructured_or_malformed_lines_never_count(self):
        for event in [b"not JSON\n", b"null\n", b"[]\n", b"{}\n", b"\xff\n",
                      rejection(fields=None), rejection(fields=[]), rejection(fields=SECRET)]:
            with self.subTest(event=event):
                self.path.write_bytes(event)
                self.assertFalse(self.observe())

    def test_unrelated_complete_lines_do_not_hide_a_later_matching_event(self):
        self.path.write_bytes(b"not JSON\nnull\n" + rejection() + b"unfinished tail")
        self.assertTrue(self.observe())

    def test_bound_applies_to_current_suffix_including_incomplete_tail(self):
        event = rejection()
        self.path.write_bytes(event + b" " * (MAX_BYTES - len(event)))
        self.assertTrue(self.observe())
        with self.path.open("ab") as log:
            log.write(b" ")
        with self.assertRaisesRegex(AssertionError, "byte bound"):
            self.observe()

    def test_large_previous_log_does_not_consume_current_suffix_budget(self):
        previous = b"x" * (MAX_BYTES + 1) + b"\n"
        self.path.write_bytes(previous + rejection())
        self.assertTrue(self.observe(len(previous)))

    def test_truncation_and_invalid_offsets_are_visible_errors(self):
        self.path.write_bytes(rejection())
        for offset in [-1, True, 0.5]:
            with self.subTest(offset=offset), self.assertRaisesRegex(AssertionError, "offset"):
                self.observe(offset)
        with self.assertRaisesRegex(AssertionError, "truncated"):
            self.observe(self.path.stat().st_size + 1)

    def test_read_failure_is_visible_without_echoing_path_or_content(self):
        self.path.unlink()
        private_path = self.path.parent / SECRET
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            try:
                cluster.authentication_rejection_since(private_path, 0)
            except RuntimeError:
                diagnostic = traceback.format_exc()
            else:
                self.fail("missing node-B log was silently accepted")
        self.assertNotIn(SECRET, diagnostic + output.getvalue())
        self.assertIn("could not read", diagnostic)

    def test_expired_deadline_does_not_read_or_accept_an_existing_event(self):
        self.path.write_bytes(rejection())
        with patch.object(cluster.time, "monotonic", return_value=3.0), \
                patch.object(cluster, "authentication_rejection_since") as observe, \
                patch.object(cluster.time, "sleep") as sleep:
            self.assertFalse(cluster.wait_for_authentication_rejection(self.path, 0, 3.0))
        observe.assert_not_called()
        sleep.assert_not_called()

    def test_event_read_that_crosses_deadline_cannot_turn_the_result_green(self):
        now = [0.0]

        def late_event(*_arguments):
            now[0] = 3.001
            return True

        with patch.object(cluster.time, "monotonic", side_effect=lambda: now[0]), \
                patch.object(cluster, "authentication_rejection_since", side_effect=late_event) as observe, \
                patch.object(cluster.time, "sleep") as sleep:
            self.assertFalse(cluster.wait_for_authentication_rejection(self.path, 0, 3.0))
        self.assertEqual(observe.call_count, 1)
        sleep.assert_not_called()

    def test_pending_poll_uses_only_remaining_budget_without_a_final_late_read(self):
        now = [2.98]
        sleeps = []

        def advance(duration):
            sleeps.append(duration)
            now[0] += duration

        with patch.object(cluster.time, "monotonic", side_effect=lambda: now[0]), \
                patch.object(cluster, "authentication_rejection_since", return_value=False) as observe, \
                patch.object(cluster.time, "sleep", side_effect=advance):
            self.assertFalse(cluster.wait_for_authentication_rejection(self.path, 0, 3.0))
        self.assertEqual(observe.call_count, 1)
        self.assertEqual(len(sleeps), 1)
        self.assertAlmostEqual(sleeps[0], 0.02)
        self.assertAlmostEqual(now[0], 3.0)

    def test_new_event_during_original_window_succeeds_without_resetting_deadline(self):
        now = [0.0]

        def advance(duration):
            now[0] += duration

        with patch.object(cluster.time, "monotonic", side_effect=lambda: now[0]), \
                patch.object(cluster, "authentication_rejection_since", side_effect=[False, True]) as observe, \
                patch.object(cluster.time, "sleep", side_effect=advance):
            self.assertTrue(cluster.wait_for_authentication_rejection(self.path, 0, 3.0))
        self.assertEqual(observe.call_count, 2)
        self.assertAlmostEqual(now[0], 0.05)


if __name__ == "__main__":
    unittest.main()
