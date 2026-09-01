#!/usr/bin/env python3
"""Actual-process restart fixture for XEP-0160/XEP-0203 encrypted replay."""

from __future__ import annotations

import importlib.util
import pathlib
import socket
import sys


ROOT = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("northstar_integration", ROOT / "integration-wsl.py")
fixture = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(fixture)

SENDER = "restart_sender"
RECIPIENT = "restart_recipient"
PASSWORD = "restart-message-password-123"
MESSAGE_ID = "message-family-restart-offline"


def register(username: str) -> None:
    status, result = fixture.register_account(username, PASSWORD)
    fixture.check(status == 201, f"restart fixture registration failed: {status} {result}")


def prepare() -> None:
    fixture.wait_ready()
    register(SENDER)
    register(RECIPIENT)
    status, login = fixture.api(
        "POST", "/api/v1/login", {"username": SENDER, "password": PASSWORD}
    )
    fixture.check(status == 200, f"restart sender login failed: {status} {login}")
    sender = fixture.XmppWebSocket(SENDER, PASSWORD, "restart-sender")
    sender.send_with_pow(
        f"<message xmlns='jabber:client' to='{RECIPIENT}@{fixture.DOMAIN}' type='chat' id='{MESSAGE_ID}'>"
        + fixture.omemo2_envelope(
            911,
            [
                (f"{SENDER}@{fixture.DOMAIN}", [911]),
                (f"{RECIPIENT}@{fixture.DOMAIN}", [912]),
            ],
            "RESTART-CIPHERTEXT-PERSISTS",
        )
        + "</message>",
        login["token"],
    )
    # An IQ barrier on the same ordered stream proves the offline transaction
    # committed before the shell terminates the process.
    sender.send(
        "<iq xmlns='jabber:client' type='get' id='restart-prepare-barrier'>"
        "<ping xmlns='urn:xmpp:ping'/></iq>"
    )
    barrier, _ = sender.receive_until("restart-prepare-barrier")
    fixture.check("type='result'" in barrier, "offline restart prepare barrier failed")
    sender.close()


def verify() -> None:
    fixture.wait_ready()
    recipient = fixture.XmppWebSocket(
        RECIPIENT,
        PASSWORD,
        "restart-recipient",
        initial_presence=False,
    )
    recipient.send("<presence xmlns='jabber:client'><priority>-1</priority></presence>")
    try:
        unexpected = recipient.receive(0.75)
        fixture.check(
            MESSAGE_ID not in unexpected,
            f"negative-priority resource received offline replay after restart: {unexpected}",
        )
    except (TimeoutError, socket.timeout):
        pass
    recipient.send("<presence xmlns='jabber:client'><priority>0</priority></presence>")
    replayed, _ = recipient.receive_until(MESSAGE_ID, timeout=20)
    fixture.check(
        fixture.omemo_payload_b64("RESTART-CIPHERTEXT-PERSISTS") in replayed
        and "RESTART-PLAINTEXT-MUST-NOT-PERSIST" not in replayed
        and "urn:xmpp:delay" in replayed
        and f"from='{fixture.DOMAIN}'" in replayed,
        f"durable encrypted offline replay was altered after restart: {replayed}",
    )
    recipient.close()


def main() -> None:
    fixture.check(len(sys.argv) == 2, "expected prepare or verify")
    if sys.argv[1] == "prepare":
        prepare()
    elif sys.argv[1] == "verify":
        verify()
    else:
        raise AssertionError(f"unknown restart fixture mode: {sys.argv[1]}")


if __name__ == "__main__":
    main()
