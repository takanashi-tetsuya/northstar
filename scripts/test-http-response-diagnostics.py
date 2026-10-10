#!/usr/bin/env python3
"""Pure byte-only controls for failure diagnostics; no sockets or services."""

import json
import unittest

from lib.http_response_diagnostics import MAX_HEADER_BYTES, summarize_http_response


BODY = b'{"error": {"code": "fixture_429"}}'


def response(body=BODY, *, headers=None, status=b"HTTP/1.1 429 Too Many Requests"):
    if headers is None:
        headers = [b"Content-Length: " + str(len(body)).encode(), b"Connection: close"]
    return status + b"\r\n" + b"\r\n".join(headers) + b"\r\n\r\n" + body


class HttpResponseDiagnosticsTests(unittest.TestCase):
    def summarize(self, data):
        return summarize_http_response((data,))

    def assert_unknown(self, summary):
        self.assertIsNone(summary["http_response_complete"])
        self.assertEqual(summary["receive_phase"], "unclassified")
        self.assertFalse(summary["recv_eof_observed"])

    def test_complete_content_length_is_still_waiting_for_recv_eof(self):
        self.assertEqual(len(BODY), 34)
        data = response()
        summary = self.summarize(data)
        self.assertEqual(summary["status"], 429)
        self.assertEqual(summary["framing"], "content_length")
        self.assertEqual(summary["declared_body_bytes"], 34)
        self.assertEqual(summary["received_body_bytes"], 34)
        self.assertTrue(summary["connection_close"])
        self.assertTrue(summary["http_response_complete"])
        self.assertEqual(summary["receive_phase"], "awaiting_recv_eof")
        self.assertFalse(summary["recv_eof_observed"])
        self.assertEqual(summary["header_bytes"] + 34, len(data))

    def test_every_split_point_retains_same_summary(self):
        data = response()
        expected = self.summarize(data)
        for split in range(len(data) + 1):
            with self.subTest(split=split):
                self.assertEqual(summarize_http_response((data[:split], data[split:])), expected)
        self.assertEqual(summarize_http_response(bytes([byte]) for byte in data), expected)

    def test_missing_and_partial_headers(self):
        for data in (b"", b"HTTP/1.1 429 Too", response().split(b"\r\n\r\n")[0] + b"\r\n\r"):
            with self.subTest(data=data):
                summary = self.summarize(data)
                self.assertFalse(summary["http_response_complete"])
                self.assertEqual(summary["receive_phase"], "awaiting_response_headers")
                self.assertIsNone(summary["received_body_bytes"])

    def test_incomplete_body(self):
        summary = self.summarize(response()[:-1])
        self.assertFalse(summary["http_response_complete"])
        self.assertEqual(summary["received_body_bytes"], 33)
        self.assertEqual(summary["receive_phase"], "awaiting_response_body")

    def test_zero_length_body(self):
        summary = self.summarize(response(b""))
        self.assertEqual(summary["declared_body_bytes"], 0)
        self.assertTrue(summary["http_response_complete"])
        self.assertEqual(summary["receive_phase"], "awaiting_recv_eof")

    def test_bytes_beyond_content_length_are_ambiguous(self):
        summary = self.summarize(response() + b"extra")
        self.assert_unknown(summary)
        self.assertEqual(summary["received_body_bytes"], 39)
        self.assertEqual(summary["parse_note"], "bytes_after_declared_body")

    def test_duplicate_lengths_never_claim_completion(self):
        for second in (b"34", b"33"):
            with self.subTest(second=second):
                summary = self.summarize(response(headers=[b"Content-Length: 34", b"content-length: " + second]))
                self.assert_unknown(summary)
                self.assertEqual(summary["parse_note"], "duplicate_content_length")

    def test_invalid_and_unsupported_lengths(self):
        for length in (b"", b"-1", b"+34", b"34, 34", b"3.4", b"3 4", b"\xff", b"9" * 21, b"9" * 5000):
            with self.subTest(length=length[:30]):
                summary = self.summarize(response(headers=[b"Content-Length: " + length]))
                self.assert_unknown(summary)
                self.assertEqual(summary["parse_note"], "invalid_or_unsupported_content_length")

    def test_header_case_and_optional_whitespace(self):
        summary = self.summarize(response(headers=[b"cOnTeNt-LeNgTh:\t034 \t", b"cOnNeCtIoN: keep-alive, ClOsE"]))
        self.assertTrue(summary["http_response_complete"])
        self.assertTrue(summary["connection_close"])

    def test_transfer_encoding_takes_precedence_over_length(self):
        for encoding in (b"chunked", b"gzip, chunked", b"", b"identity", b"invalid"):
            with self.subTest(encoding=encoding):
                summary = self.summarize(response(headers=[b"Content-Length: 34", b"Transfer-Encoding: " + encoding]))
                self.assert_unknown(summary)
                self.assertEqual(summary["declared_body_bytes"], 34)
                self.assertEqual(summary["framing"], "transfer_encoding_unclassified")
                self.assertEqual(summary["parse_note"], "transfer_encoding_with_content_length")

    def test_chunked_bytes_are_not_treated_as_decoded_body(self):
        summary = self.summarize(response(b"2\r\n{}\r\n0\r\n\r\n", headers=[b"Transfer-Encoding: chunked"]))
        self.assert_unknown(summary)
        self.assertEqual(summary["received_body_bytes"], 12)
        self.assertEqual(summary["framing"], "transfer_encoding_unclassified")

    def test_close_header_without_length_does_not_prove_completion(self):
        summary = self.summarize(response(headers=[b"Connection: close"]))
        self.assert_unknown(summary)
        self.assertTrue(summary["connection_close"])
        self.assertEqual(summary["framing"], "close_delimited_unclassified")

    def test_malformed_headers_and_status_remain_unknown(self):
        for header in (b"Content-Length : 34", b" Content-Length: 34", b"Content-Length 34", b"X-Other: bad\x00value", b"X-Other: bad\x7fvalue", b"X-Other: folded\r\n value"):
            with self.subTest(header=header):
                summary = self.summarize(response(headers=[b"Content-Length: 34", header]))
                self.assert_unknown(summary)
                self.assertEqual(summary["parse_note"], "invalid_header_field")
        for status in (b"invalid", b"HTTP/2 429 Bad", b"HTTP/1.1 099 Bad", b"HTTP/1.1 429 Bad\x00"):
            with self.subTest(status=status):
                summary = self.summarize(response(status=status))
                self.assert_unknown(summary)
                self.assertIsNone(summary["status"])

    def test_informational_and_bodyless_statuses_are_not_misclassified(self):
        for status in (b"100 Continue", b"101 Switching Protocols", b"204 No Content", b"304 Not Modified"):
            with self.subTest(status=status):
                summary = self.summarize(response(b"", status=b"HTTP/1.1 " + status))
                self.assert_unknown(summary)
                self.assertEqual(summary["parse_note"], "response_kind_unclassified")

    def test_capture_limit_never_claims_missing_headers_are_complete(self):
        for data in (b"x" * MAX_HEADER_BYTES, b"x" * (MAX_HEADER_BYTES + 1), response(headers=[b"X-Large: " + b"x" * MAX_HEADER_BYTES, b"Content-Length: 34"])):
            with self.subTest(size=len(data)):
                summary = self.summarize(data)
                self.assert_unknown(summary)
                self.assertEqual(summary["received_bytes"], len(data))
                self.assertEqual(summary["parse_note"], "header_capture_limit")

    def test_large_body_is_counted_beyond_capture_limit(self):
        body = b"x" * (MAX_HEADER_BYTES + 123)
        summary = self.summarize(response(body))
        self.assertTrue(summary["http_response_complete"])
        self.assertEqual(summary["received_body_bytes"], len(body))

    def test_summary_does_not_expose_header_values_or_body(self):
        summary = self.summarize(response(headers=[b"Content-Length: 34", b"X-Private: fixture-private-header"]))
        encoded = json.dumps(summary)
        self.assertNotIn("fixture-private-header", encoded)
        self.assertNotIn("fixture_429", encoded)
        self.assertLess(len(encoded), 1024)


if __name__ == "__main__":
    unittest.main()
