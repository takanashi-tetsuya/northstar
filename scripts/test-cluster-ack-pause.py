#!/usr/bin/env python3
"""Offline checks for bounded ACK fault isolation and exact request identity."""

from contextlib import contextmanager
import copy
import importlib.util
from pathlib import Path
import signal
from types import SimpleNamespace
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("cluster_fixture", Path(__file__).with_name("cluster-wsl.py"))
cluster = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cluster)
TARGET = "bob@cluster.localhost/fake-ack-target"


@contextmanager
def fake_pause_environment(states=None, active_timer=(0.0, 0.0)):
    events = []
    now = [0.0]
    installed = [None]
    previous_handler = object()

    def handler_change(_signal, handler):
        installed[0] = handler
        events.append(("handler", handler))

    def read_status(_path):
        events.append(("proc",))
        return next(statuses)

    statuses = iter(states or ["State:\tT (stopped)\n"])
    with patch.object(cluster.signal, "getitimer", return_value=active_timer), \
            patch.object(cluster.signal, "getsignal", return_value=previous_handler), \
            patch.object(cluster.signal, "signal", side_effect=handler_change), \
            patch.object(cluster.signal, "setitimer", side_effect=lambda kind, delay: events.append(("timer", delay))), \
            patch.object(cluster.os, "kill", side_effect=lambda pid, kind: events.append(("kill", pid, kind))), \
            patch.object(cluster.pathlib.Path, "read_text", autospec=True, side_effect=read_status), \
            patch.object(cluster.time, "monotonic", side_effect=lambda: now[0]), \
            patch.object(cluster.time, "sleep", side_effect=lambda delay: now.__setitem__(0, now[0] + delay)):
        yield events, now, installed, previous_handler


def probe(stanza_id="forged-ack", request_id="request-1", nonce="nonce-1"):
    return {"payload": {
        "target": TARGET,
        "protocol_version": cluster.CLUSTER_PROTOCOL_VERSION,
        "delivery": {"reliability": "volatile"},
        "stanza": f"<message xmlns='jabber:client' to='{TARGET}' id='{stanza_id}'/>",
        "request_id": request_id,
        "ack_nonce": nonce,
    }}


class AckPauseTests(unittest.TestCase):
    def assert_resumed(self, events, previous):
        self.assertEqual(events[-3:], [
            ("timer", 0), ("kill", 1234, signal.SIGCONT), ("handler", previous),
        ])

    def test_body_runs_only_after_observing_same_process_stopped(self):
        with fake_pause_environment(["State:\tR (running)\n", "State:\tT (stopped)\n"]) as (events, now, _, previous):
            with cluster.paused_node_for_ack(1234):
                events.append(("body",))
                self.assertEqual(events[-3:], [("proc",), ("proc",), ("body",)])
                self.assertGreater(now[0], 0)
            self.assertIn(("kill", 1234, signal.SIGSTOP), events)
            self.assert_resumed(events, previous)

    def test_body_exception_is_preserved_and_process_is_resumed(self):
        with fake_pause_environment() as (events, _, _, previous):
            with self.assertRaisesRegex(ValueError, "original failure"):
                with cluster.paused_node_for_ack(1234):
                    raise ValueError("original failure")
            self.assert_resumed(events, previous)

    def test_alarm_interrupt_is_failure_and_process_is_resumed(self):
        with fake_pause_environment() as (events, _, installed, previous):
            with self.assertRaisesRegex(TimeoutError, "three-second budget"):
                with cluster.paused_node_for_ack(1234):
                    installed[0](signal.SIGALRM, None)
            self.assert_resumed(events, previous)

    def test_late_return_cannot_pass_even_if_alarm_delivery_was_delayed(self):
        with fake_pause_environment() as (events, now, _, previous):
            with self.assertRaisesRegex(TimeoutError, "three-second budget"):
                with cluster.paused_node_for_ack(1234):
                    now[0] = 3.001
            self.assert_resumed(events, previous)

    def test_existing_alarm_is_never_replaced(self):
        with fake_pause_environment(active_timer=(1.0, 0.0)) as (events, _, _, _):
            with self.assertRaisesRegex(AssertionError, "active alarm"):
                with cluster.paused_node_for_ack(1234):
                    self.fail("fixture accepted an existing alarm")
            self.assertEqual(events, [])

    def test_following_request_has_exact_message_and_fresh_request_and_nonce(self):
        first = cluster.validate_ack_probe_request(probe(), TARGET, "forged-ack")
        second = probe("duplicate-ack", "request-2", "nonce-2")
        self.assertEqual(cluster.validate_ack_probe_request(second, TARGET, "duplicate-ack", first), second["payload"])
        for field in ("request_id", "ack_nonce"):
            stale = copy.deepcopy(second)
            stale["payload"][field] = first[field]
            with self.subTest(field=field), self.assertRaisesRegex(AssertionError, "previous correlation"):
                cluster.validate_ack_probe_request(stale, TARGET, "duplicate-ack", first)

    def test_stale_message_wrong_target_and_durable_contract_cannot_mask_ack_case(self):
        for field, value in (("target", "another@example.test/resource"),
                             ("delivery", {"reliability": "durable"}),
                             ("protocol_version", "old"),
                             ("stanza", "<message xmlns='jabber:client' id='old'/>") ):
            wrong = probe()
            wrong["payload"][field] = value
            with self.subTest(field=field), self.assertRaises(AssertionError):
                cluster.validate_ack_probe_request(wrong, TARGET, "forged-ack")
        with self.assertRaisesRegex(AssertionError, "different message"):
            cluster.validate_ack_probe_request(probe(), TARGET, "duplicate-ack")


class ClusterRecoveryTests(unittest.TestCase):
    def test_every_round_requires_both_nodes_ready_before_fresh_delivery(self):
        now = [0.0]
        calls = []
        statuses = iter([200, 503, 503, 200, 200, 200])

        @contextmanager
        def response(url, timeout):
            calls.append((url, timeout))
            yield SimpleNamespace(status=next(statuses))

        with patch.object(cluster.time, "monotonic", side_effect=lambda: now[0]), \
                patch.object(cluster.time, "sleep", side_effect=lambda delay: now.__setitem__(0, now[0] + delay)), \
                patch.object(cluster.urllib.request, "urlopen", side_effect=response):
            self.assertTrue(cluster.wait_for_cluster_recovery((1001, 1002), 40))
        self.assertEqual(len(calls), 6)
        self.assertEqual([url for url, _ in calls], ["http://127.0.0.1:1001/readyz", "http://127.0.0.1:1002/readyz"] * 3)

    def test_recovery_cannot_reset_or_accept_success_after_the_shared_deadline(self):
        now = [39.75]

        @contextmanager
        def late_response(_url, timeout):
            self.assertEqual(timeout, 0.25)
            now[0] = 40.001
            yield SimpleNamespace(status=200)

        with patch.object(cluster.time, "monotonic", side_effect=lambda: now[0]), \
                patch.object(cluster.urllib.request, "urlopen", side_effect=late_response) as request:
            self.assertFalse(cluster.wait_for_cluster_recovery((1001, 1002), 40))
            self.assertFalse(cluster.wait_for_cluster_recovery((1001, 1002), 40))
        self.assertEqual(request.call_count, 1)


if __name__ == "__main__":
    unittest.main()
