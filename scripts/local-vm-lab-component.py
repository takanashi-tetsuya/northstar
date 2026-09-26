#!/usr/bin/env python3
"""Bounded XEP-0114 accept probe using Slixmpp's independent component stack.

Run inside the isolated Northstar guest.  The server listener must be bound to
loopback.  This program deliberately handles only lab-marker messages.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import importlib.metadata
import json
import os
import pathlib
import re
import sqlite3
import stat
import tempfile
import time
import xml.etree.ElementTree as ET


MARKER = re.compile(r"^component-lab-[0-9a-f]{16,64}$")
SID_NS = "{urn:xmpp:sid:0}stanza-id"


def protected_secret(path: pathlib.Path) -> str:
    if not path.is_absolute():
        raise ValueError("secret path must be absolute")
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_mode & 0o077:
        raise ValueError("secret must be an owner-only regular file")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("secret changed while opening")
        raw = os.read(descriptor, 4097)
    finally:
        os.close(descriptor)
    raw = raw.rstrip(b"\r\n")
    if not 32 <= len(raw) <= 4096 or b"\0" in raw:
        raise ValueError("secret must contain 32 to 4096 bytes without NUL")
    return raw.decode("utf-8")


class Evidence:
    def __init__(self, events: pathlib.Path, ledger: pathlib.Path):
        for path in (events, ledger):
            if not path.is_absolute() or not path.parent.is_dir() or path.is_symlink():
                raise ValueError("evidence paths must be absolute non-symlink files")
        old_umask = os.umask(0o077)
        try:
            self.output = os.fdopen(
                os.open(events, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600),
                "a", encoding="utf-8", buffering=1,
            )
            self.database = sqlite3.connect(ledger)
            self.database.execute(
                "CREATE TABLE IF NOT EXISTS seen (authority TEXT NOT NULL, "
                "stanza_id TEXT NOT NULL, PRIMARY KEY (authority, stanza_id))"
            )
            self.database.commit()
        finally:
            os.umask(old_umask)

    def write(self, event: str, **fields: object) -> None:
        self.output.write(json.dumps({
            "time_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "monotonic_ns": time.monotonic_ns(),
            "event": event, **fields,
        }, sort_keys=True) + "\n")
        self.output.flush()
        os.fsync(self.output.fileno())

    def duplicate(self, authority: str, stanza_id: str) -> bool:
        cursor = self.database.execute(
            "INSERT OR IGNORE INTO seen (authority, stanza_id) VALUES (?, ?)",
            (authority, stanza_id),
        )
        self.database.commit()
        return cursor.rowcount == 0

    def close(self) -> None:
        self.database.close()
        self.output.close()


def stable_id(message: object, trusted_by: str) -> tuple[str, str] | None:
    # Only a server-assigned XEP-0359 ID is a dedupe key.  The message's own
    # `id` attribute may be chosen afresh by a sender and is recorded separately.
    for child in message.xml.findall(SID_NS):
        authority = child.attrib.get("by", "")
        stanza_id = child.attrib.get("id", "")
        if authority == trusted_by and stanza_id:
            return authority, stanza_id
    return None


def self_test() -> None:
    class Sample:
        xml = ET.fromstring(
            "<message><stanza-id xmlns='urn:xmpp:sid:0' by='forged.test' id='bad'/>"
            "<stanza-id xmlns='urn:xmpp:sid:0' by='alice@ns-a.lab.test' id='stable-id'/>"
            "</message>"
        )

    assert stable_id(Sample(), "alice@ns-a.lab.test") == ("alice@ns-a.lab.test", "stable-id")
    assert stable_id(Sample(), "bob@ns-a.lab.test") is None
    with tempfile.TemporaryDirectory(prefix="northstar-component-ledger-") as directory:
        base = pathlib.Path(directory)
        evidence = Evidence(base / "events.jsonl", base / "seen.sqlite3")
        assert not evidence.duplicate("ns-a.lab.test", "stable-id")
        evidence.write("first")
        evidence.close()
        reopened = Evidence(base / "events.jsonl", base / "seen.sqlite3")
        assert reopened.duplicate("ns-a.lab.test", "stable-id")
        assert not reopened.duplicate("ns-b.lab.test", "stable-id")
        reopened.close()
        records = [json.loads(line) for line in (base / "events.jsonl").read_text().splitlines()]
        assert records[0]["event"] == "first"
    print("component evidence ledger restart and authority scoping passed")


def run(args: argparse.Namespace) -> None:
    if args.host not in ("127.0.0.1", "::1"):
        raise ValueError("the XEP-0114 lab component may connect only to loopback")
    if not 1 <= args.port <= 65535 or not 5 <= args.seconds <= 3600:
        raise ValueError("port or duration is outside the bounded lab range")
    secret = protected_secret(args.secret_file)
    version = importlib.metadata.version("slixmpp")
    if version != args.slixmpp_version:
        raise ValueError(f"Slixmpp version differs: expected {args.slixmpp_version}, got {version}")
    from slixmpp.componentxmpp import ComponentXMPP

    evidence = Evidence(args.events, args.ledger)

    class LabComponent(ComponentXMPP):
        def __init__(self) -> None:
            super().__init__(args.jid, secret, args.host, args.port)
            self.authenticated = False
            self.add_event_handler("session_start", self.on_session_start)
            self.add_event_handler("disconnected", self.on_disconnected)
            self.add_event_handler("message", self.on_message)

        def on_session_start(self, _event: object) -> None:
            self.authenticated = True
            evidence.write("authenticated", jid=args.jid, library_version=version)

        def on_disconnected(self, _event: object) -> None:
            evidence.write("disconnected")

        def on_message(self, message: object) -> None:
            if message["type"] not in ("chat", "normal"):
                return
            body = str(message["body"])
            if not MARKER.fullmatch(body):
                evidence.write("ignored_non_lab_message")
                return
            identity = stable_id(message, args.trusted_by)
            duplicate = evidence.duplicate(*identity) if identity else False
            evidence.write(
                "message", marker=body, sender=str(message["from"]),
                recipient=str(message["to"]), client_id=str(message["id"]),
                stanza_id=(identity[1] if identity else None),
                stanza_id_by=(identity[0] if identity else None), duplicate=duplicate,
            )
            if not duplicate:
                message.reply("northstar-component-echo:" + body).send()

    component = LabComponent()
    loop = asyncio.get_event_loop()
    loop.call_later(args.seconds, loop.stop)
    evidence.write("start", jid=args.jid, library_version=version, seconds=args.seconds)
    try:
        component.connect()
        loop.run_forever()
        if not component.authenticated:
            raise RuntimeError("component did not authenticate within the run deadline")
    finally:
        component.disconnect()
        evidence.write("stop", authenticated=component.authenticated)
        evidence.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--jid", default="gateway.ns-a.lab.test")
    parser.add_argument("--trusted-by", default="alice@ns-a.lab.test")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5347)
    parser.add_argument("--secret-file", type=pathlib.Path)
    parser.add_argument("--slixmpp-version")
    parser.add_argument("--events", type=pathlib.Path)
    parser.add_argument("--ledger", type=pathlib.Path)
    parser.add_argument("--seconds", type=int, default=600)
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if any(value is None for value in (
        args.secret_file, args.slixmpp_version, args.events, args.ledger,
    )):
        parser.error("--secret-file, --slixmpp-version, --events and --ledger are required")
    run(args)


if __name__ == "__main__":
    main()
