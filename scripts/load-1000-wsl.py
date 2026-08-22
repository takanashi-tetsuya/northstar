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
    return fixture.XmppWebSocket(USERNAME, PASSWORD, f"load-{index}")


def active_sessions() -> int:
    status, body = fixture.api("GET", "/metrics")
    fixture.check(status == 200, "metrics endpoint was not reachable during load test")
    match = re.search(r"^xmpp_active_sessions (\d+)$", body, re.MULTILINE)
    fixture.check(match is not None, "active-session metric was missing")
    return int(match.group(1))


def run() -> None:
    fixture.wait_ready()
    status, result = fixture.api(
        "POST", "/api/v1/register", {"username": USERNAME, "password": PASSWORD}
    )
    fixture.check(status == 201, f"load-test account registration failed: {status} {result}")

    sessions = []
    started = time.monotonic()
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
        for index, session in enumerate(sessions[:10]):
            ping_id = f"load-ping-{index}"
            session.send(
                f"<iq xmlns='jabber:client' type='get' id='{ping_id}'>"
                "<ping xmlns='urn:xmpp:ping'/></iq>"
            )
            reply, _ = session.receive_until(ping_id)
            fixture.check("type='result'" in reply, "a loaded session did not answer XMPP ping")
        print(
            f"load: {SESSION_COUNT} simultaneous authenticated sessions retained; "
            f"sample pings passed; connection ramp took {elapsed:.1f}s"
        )
    finally:
        for session in sessions:
            session.close()


if __name__ == "__main__":
    run()
