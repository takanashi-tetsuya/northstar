#!/usr/bin/env python3
"""Check the integration client's handling of upload backpressure."""

import importlib.util
import pathlib
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location(
    "integration_upload_retry", pathlib.Path(__file__).with_name("integration-wsl.py")
)
integration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(integration)

BUSY = (409, {"retry-after": "1"}, b'{"error":{"code":"upload_in_progress"}}')
CREATED = (201, {"idempotency-replayed": "true"}, b"")


class UploadRetryTests(unittest.TestCase):
    def setUp(self):
        self.now = 0.0
        self.headers = {"Authorization": "Bearer fixture-token"}
        self.clock = mock.patch.object(integration.time, "monotonic", lambda: self.now)
        self.sleep = mock.patch.object(integration.time, "sleep", self.advance)
        self.clock.start()
        self.sleep.start()
        self.addCleanup(self.clock.stop)
        self.addCleanup(self.sleep.stop)

    def advance(self, seconds):
        self.now += seconds

    def put(self):
        return integration.put_upload_when_ready("/api/v1/upload/fixture", b"ciphertext", self.headers)

    def test_busy_response_preserves_capability_and_bytes(self):
        with mock.patch.object(integration, "raw_http", side_effect=[BUSY, CREATED]) as request:
            self.assertEqual(self.put(), CREATED)
        self.assertEqual(self.now, 1)
        self.assertEqual(request.call_args_list, [
            mock.call("PUT", "/api/v1/upload/fixture", b"ciphertext", self.headers, timeout=10),
            mock.call("PUT", "/api/v1/upload/fixture", b"ciphertext", self.headers, timeout=9),
        ])

    def test_other_responses_are_not_retried(self):
        for response in [
            CREATED, (401, {}, b""), (429, {"retry-after": "1"}, b""), (503, {}, b""),
            (409, {"retry-after": "1"}, b'{"error":{"code":"conflict"}}'),
            (409, {"retry-after": "1"}, b'{"error":{"code":"idempotency_replay_invalidated"}}'),
            (409, {"retry-after": "1"}, b"not JSON"),
            (409, {"retry-after": "1"}, b'{"error":null}'),
            (409, {"retry-after": "1"}, b"[]"),
        ]:
            with self.subTest(response=response), mock.patch.object(integration, "raw_http", return_value=response) as request:
                self.assertEqual(self.put(), response)
                request.assert_called_once()

    def test_busy_response_requires_a_bounded_positive_retry_after(self):
        for value in ("", "0", "-1", "1.5", " 1", "999999999999999999"):
            with self.subTest(value=value), mock.patch.object(integration, "raw_http",
                    return_value=(BUSY[0], {"retry-after": value}, BUSY[2])) as request:
                with self.assertRaisesRegex(AssertionError, "valid Retry-After"):
                    self.put()
                request.assert_called_once()

    def test_all_attempts_share_one_deadline(self):
        with mock.patch.object(integration, "raw_http", return_value=BUSY) as request:
            with self.assertRaisesRegex(AssertionError, "ten-second deadline"):
                self.put()
        self.assertEqual(self.now, 9)
        self.assertEqual(request.call_count, 10)
        self.assertEqual([call.kwargs["timeout"] for call in request.call_args_list], list(range(10, 0, -1)))

    def test_time_spent_receiving_a_busy_response_counts_against_deadline(self):
        def delayed(*args, **kwargs):
            self.advance(9.5)
            return BUSY
        with mock.patch.object(integration, "raw_http", side_effect=delayed) as request:
            with self.assertRaisesRegex(AssertionError, "ten-second deadline"):
                self.put()
            request.assert_called_once()

    def test_delayed_wakeup_cannot_start_an_attempt_after_deadline(self):
        with mock.patch.object(integration, "raw_http", return_value=BUSY) as request, \
                mock.patch.object(integration.time, "sleep", lambda _: self.advance(11)):
            with self.assertRaisesRegex(AssertionError, "remained busy"):
                self.put()
            request.assert_called_once()

    def test_transport_failure_is_not_retried(self):
        with mock.patch.object(integration, "raw_http", side_effect=TimeoutError) as request:
            with self.assertRaises(TimeoutError):
                self.put()
            request.assert_called_once()


if __name__ == "__main__":
    unittest.main()
