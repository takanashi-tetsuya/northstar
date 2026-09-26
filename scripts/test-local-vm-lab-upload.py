#!/usr/bin/env python3
"""Offline checks for the isolated VM upload probe's slot admission retry."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location(
    "local_vm_lab_upload", Path(__file__).with_name("local-vm-lab-upload.py")
)
assert SPEC and SPEC.loader
upload = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(upload)
DOMAIN = "upload.ns-a.lab.test"


def error_reply(request_id: str, error_type: str = "wait",
                condition: str = "resource-constraint", domain: str = DOMAIN) -> str:
    return (f"<iq xmlns='jabber:client' from='{domain}' id='{request_id}' type='error'>"
            f"<error type='{error_type}'><{condition} xmlns='{upload.STANZA_NS}'/>"
            "</error></iq>")


class Client:
    def __init__(self, failures: int, *, error_type: str = "wait",
                 condition: str = "resource-constraint") -> None:
        self.failures = failures
        self.error_type = error_type
        self.condition = condition
        self.sent: list[str] = []

    def send(self, stanza: str) -> None:
        self.sent.append(stanza)

    def receive_until(self, request_id: str, timeout: float) -> tuple[str, list[str]]:
        assert 0 < timeout <= 10
        if len(self.sent) <= self.failures:
            return error_reply(request_id, self.error_type, self.condition), []
        return (f"<iq xmlns='jabber:client' from='{DOMAIN}' "
                f"id='{request_id}' type='result'/>", [])


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class SlotRetryTests(unittest.TestCase):
    def test_two_busy_replies_then_success(self) -> None:
        client = Client(2)
        clock = Clock()
        events: list[dict[str, object]] = []
        result = upload.request_slot(client, DOMAIN, 24, emit=events.append,
                                     sleep=clock.sleep, clock=clock)
        self.assertEqual(upload.slot_reply_kind(result, "northstar-storage-probe-3", DOMAIN),
                         "result")
        self.assertEqual(len(client.sent), 3)
        self.assertEqual(clock.now, sum(upload.SLOT_BACKOFF_SECONDS))
        self.assertEqual([event["event"] for event in events], [
            "slot_admission_attempt", "slot_admission_retry",
            "slot_admission_attempt", "slot_admission_retry",
            "slot_admission_attempt", "slot_admission_success",
        ])
        self.assertEqual([event["backoff_ms"] for event in events
                          if event["event"] == "slot_admission_retry"], [1000, 3000])
        self.assertNotIn("Bearer", json.dumps(events))

    def test_other_errors_fail_without_retry(self) -> None:
        for error_type, condition in (("cancel", "resource-constraint"),
                                      ("wait", "internal-server-error")):
            with self.subTest(error_type=error_type, condition=condition):
                client = Client(3, error_type=error_type, condition=condition)
                clock = Clock()
                with self.assertRaisesRegex(RuntimeError, "non-retryable"):
                    upload.request_slot(client, DOMAIN, 24, emit=lambda _: None,
                                        sleep=clock.sleep, clock=clock)
                self.assertEqual(len(client.sent), 1)
                self.assertEqual(clock.now, 0)

    def test_busy_replies_exhaust_attempt_limit(self) -> None:
        client = Client(3)
        clock = Clock()
        events: list[dict[str, object]] = []
        with self.assertRaisesRegex(RuntimeError, "after 3 attempts"):
            upload.request_slot(client, DOMAIN, 24, emit=events.append,
                                sleep=clock.sleep, clock=clock)
        self.assertEqual(len(client.sent), upload.SLOT_ATTEMPTS)
        self.assertEqual(events[-1]["event"], "slot_admission_exhausted")
        self.assertEqual(events[-1]["condition"], "wait/resource-constraint")

    def test_deadline_stops_retry(self) -> None:
        clock = Clock()
        class SlowClient(Client):
            def receive_until(self, request_id: str, timeout: float) -> tuple[str, list[str]]:
                clock.now += 19.5
                return error_reply(request_id), []

        events: list[dict[str, object]] = []
        with self.assertRaisesRegex(RuntimeError, "20-second deadline"):
            upload.request_slot(SlowClient(3), DOMAIN, 24, emit=events.append,
                                sleep=clock.sleep, clock=clock)
        self.assertEqual(events[-1]["condition"], "deadline")

    def test_wrong_iq_identity_fails(self) -> None:
        for response in (error_reply("wrong-id"),
                         error_reply("northstar-storage-probe-1", domain="other.lab.test")):
            with self.subTest(response=response):
                with self.assertRaisesRegex(RuntimeError, "wrong IQ identity"):
                    upload.slot_reply_kind(response, "northstar-storage-probe-1", DOMAIN)


if __name__ == "__main__":
    unittest.main()
