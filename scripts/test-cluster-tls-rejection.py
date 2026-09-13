#!/usr/bin/env python3
"""Require a real, case-specific TLS rejection in the current fixture phase."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import tempfile


EXPECTED = {
    "wrong-hostname": ("SSLV3_ALERT_BAD_CERTIFICATE", None),
    "wrong-ca": ("TLSV1_ALERT_UNKNOWN_CA", None),
    "wrong-client-cert": ("CERTIFICATE_VERIFY_FAILED", 20),
}
MAX_LOG_BYTES = 128 * 1024


def check(label: str, application: str, observations: bytes) -> None:
    if not any(context in application for context in (
        "failed to connect to Redis for cluster manager",
        "failed to publish the initial signed cluster node lease",
    )):
        raise ValueError("child did not reach Redis initialization")
    if not observations or len(observations) > MAX_LOG_BYTES or not observations.endswith(b"\n"):
        raise ValueError("missing, oversized, or incomplete current-phase TLS observations")
    expected = EXPECTED[label]
    events = [json.loads(line) for line in observations.splitlines()]
    if any(not isinstance(event, dict) for event in events):
        raise ValueError("TLS observation is not a structured event")
    for event in events:
        if (
            event.get("event") == "redis_tls_handshake_rejected"
            and (event.get("reason"), event.get("verify_code")) == expected
        ):
            return
    raise ValueError(f"no matching current-phase TLS rejection for {label}")


def read_observations(path: Path, offset: int) -> bytes:
    with path.open("rb") as source:
        size = source.seek(0, 2)
        if not 0 <= offset <= size:
            raise ValueError("TLS observation offset is outside the owned log")
        if offset:
            source.seek(offset - 1)
            if source.read(1) != b"\n":
                raise ValueError("TLS observation offset splits an older event")
        source.seek(offset)
        return source.read(MAX_LOG_BYTES + 1)


def self_test() -> None:
    context = "Error: failed to publish the initial signed cluster node lease\nCaused by: Timed out"

    def event(label: str) -> bytes:
        reason, code = EXPECTED[label]
        return (json.dumps({"event": "redis_tls_handshake_rejected", "reason": reason, "verify_code": code}) + "\n").encode()

    def rejected(label: str, application: str, observations: bytes) -> None:
        try:
            check(label, application, observations)
        except (ValueError, TypeError):
            return
        raise AssertionError("unrelated or absent TLS failure was accepted")

    for label in EXPECTED:
        check(label, context, event(label))
        rejected(label, "upload namespace differs from immutable database authority", event(label))
        rejected(label, context, b"")
        rejected(label, context, event(label).rstrip())
        rejected(label, context, b'{"event":"redis_tls_handshake_rejected","reason":"OTHER_TLS_ERROR","verify_code":null}\n')
        rejected(label, context, event(label) + b"incomplete JSON\n")
        rejected(label, context, b"{}\n" * MAX_LOG_BYTES)
        for other in EXPECTED:
            if other != label:
                rejected(label, context, event(other))
    rejected("wrong-client-cert", context, event("wrong-client-cert").replace(b'"verify_code": 20', b'"verify_code": 21'))
    with tempfile.TemporaryDirectory(prefix="northstar-tls-rejection-check-") as directory:
        log = Path(directory) / "relay.log"
        previous = event("wrong-hostname")
        log.write_bytes(previous + event("wrong-ca"))
        current = read_observations(log, len(previous))
        check("wrong-ca", context, current)
        rejected("wrong-hostname", context, current)
        try:
            read_observations(log, 1)
        except ValueError:
            pass
        else:
            raise AssertionError("mid-event offset was accepted")
    print("cluster TLS rejection checks passed: exact causes, Redis initialization, fresh complete events")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--label", choices=EXPECTED)
    parser.add_argument("--application-log", type=Path)
    parser.add_argument("--relay-log", type=Path)
    parser.add_argument("--offset", type=int)
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if any(value is None for value in (args.label, args.application_log, args.relay_log, args.offset)):
        parser.error("the label, application log, relay log and offset are required")
    with args.application_log.open("rb") as source:
        application = source.read(MAX_LOG_BYTES + 1)
    if len(application) > MAX_LOG_BYTES:
        raise ValueError("application diagnostic exceeds the fixture bound")
    check(args.label, application.decode("utf-8"), read_observations(args.relay_log, args.offset))
    print(f"Redis TLS rejection verified: {args.label}")


if __name__ == "__main__":
    main()
