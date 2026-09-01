#!/usr/bin/env python3
"""Open and verify 1,000 simultaneous authenticated XMPP WebSocket sessions."""

from __future__ import annotations

import concurrent.futures
import importlib.util
import os
import pathlib
import re
import time


ROOT = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("northstar_integration", ROOT / "integration-wsl.py")
fixture = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(fixture)

USERNAME = "load_user"
PASSWORD = "load-test-password-123"
SESSION_COUNT = int(os.environ.get("XMPP_LOAD_SESSIONS", "1000"))
WORKERS = int(os.environ.get("XMPP_LOAD_WORKERS", "64"))


def connect(index: int):
    # This probe measures the documented 1,000 authenticated-session design
    # envelope.  Broadcasting initial presence for 1,000 resources of one
    # synthetic account creates an RFC 6121-required O(n^2) self-presence
    # storm (roughly one million stanzas), which models one user with 1,000
    # devices rather than 1,000 users and can bury the subsequent IQ probes.
    # Presence fanout has dedicated integration coverage; keep these sessions
    # bound but unavailable, as the production-envelope probe does.
    return fixture.XmppWebSocket(
        USERNAME, PASSWORD, f"load-{index}", initial_presence=False
    )


def active_sessions() -> int:
    status, body = fixture.metrics_api()
    fixture.check(status == 200, "metrics endpoint was not reachable during load test")
    match = re.search(r"^xmpp_active_sessions (\d+)$", body, re.MULTILINE)
    fixture.check(match is not None, "active-session metric was missing")
    return int(match.group(1))


def ping_session(index: int, session) -> None:
    ping_id = f"load-ping-{index}"
    session.send(
        f"<iq xmlns='jabber:client' type='get' id='{ping_id}'>"
        "<ping xmlns='urn:xmpp:ping'/></iq>"
    )
    reply, _ = session.receive_until(ping_id)
    fixture.check("type='result'" in reply, f"loaded session {index} did not answer XMPP ping")


def run() -> None:
    fixture.wait_ready()
    status, result = fixture.register_account(USERNAME, PASSWORD)
    fixture.check(status == 201, f"load-test account registration failed: {status} {result}")

    sessions = []
    started = time.monotonic()
    completed = False
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
            futures = [executor.submit(connect, index) for index in range(SESSION_COUNT)]
            for future in concurrent.futures.as_completed(futures):
                sessions.append(future.result())

        elapsed = time.monotonic() - started
        fixture.check(
            active_sessions() == SESSION_COUNT,
            f"server did not retain all {SESSION_COUNT} simultaneous sessions",
        )
        with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
            futures = [executor.submit(ping_session, index, session) for index, session in enumerate(sessions)]
            for future in concurrent.futures.as_completed(futures):
                future.result()
        fixture.check(active_sessions() == SESSION_COUNT, "sessions were lost during the all-session ping probe")
        completed = True
        print(
            f"load: {SESSION_COUNT} simultaneous authenticated sessions retained; "
            f"all {SESSION_COUNT} pings passed; connection ramp took {elapsed:.1f}s"
        )
    finally:
        for session in sessions:
            session.close()
    if completed:
        deadline = time.monotonic() + 30
        remaining = active_sessions()
        while remaining and time.monotonic() < deadline:
            time.sleep(0.1)
            remaining = active_sessions()
        fixture.check(remaining == 0, f"server retained {remaining} sessions after orderly close")
        print("load cleanup: all authenticated sessions were released")


if __name__ == "__main__":
    run()
