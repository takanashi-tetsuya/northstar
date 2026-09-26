#!/usr/bin/env python3
"""Send bounded XMPP messages to the isolated Slixmpp component probe."""

from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import os
import pathlib
import re
import secrets
import time


ECHO = re.compile(r"northstar-component-echo:(component-lab-[0-9a-f]{16,64})")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--component-domain", default="gateway.ns-a.lab.test")
    parser.add_argument("--server-domain", default="ns-a.lab.test")
    parser.add_argument("--username", default="alice")
    parser.add_argument("--password-file", type=pathlib.Path, required=True)
    parser.add_argument("--fixture", type=pathlib.Path, required=True)
    parser.add_argument("--http-port", type=int, default=8080)
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--events", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.count <= 64 or not 1 <= args.timeout <= 300:
        parser.error("count must be 1..64 and timeout 1..300 seconds")
    domain_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
    if not domain_pattern.fullmatch(args.component_domain) or not domain_pattern.fullmatch(args.server_domain):
        parser.error("server and component domains must be canonical ASCII hostnames")
    if not re.fullmatch(r"[a-z0-9_]{1,64}", args.username):
        parser.error("username must be a canonical test account name")
    if not 1 <= args.http_port <= 65535:
        parser.error("http-port must be a valid TCP port")
    if not args.events.is_absolute() or not args.events.parent.is_dir() or args.events.is_symlink():
        parser.error("events must be an absolute non-symlink path with an existing parent")
    if not args.fixture.is_file():
        parser.error("fixture script is missing")
    spec = importlib.util.spec_from_file_location("northstar_integration", args.fixture)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the XMPP WebSocket fixture")
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    fixture.HTTP_HOST = "127.0.0.1"
    fixture.HTTP_PORT = args.http_port
    fixture.DOMAIN = args.server_domain
    password = args.password_file.read_text(encoding="utf-8").rstrip("\r\n")
    markers = ["component-lab-" + secrets.token_hex(12) for _ in range(args.count)]
    pending = set(markers)
    old_umask = os.umask(0o077)
    try:
        output = os.fdopen(
            os.open(args.events, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600),
            "a", encoding="utf-8", buffering=1,
        )
    finally:
        os.umask(old_umask)

    def record(event: str, **fields: object) -> None:
        output.write(json.dumps({
            "time_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "monotonic_ns": time.monotonic_ns(), "event": event, **fields,
        }, sort_keys=True) + "\n")
        output.flush()
        os.fsync(output.fileno())

    client = None
    try:
        client = fixture.XmppWebSocket(
            args.username, password, "component-lab-" + secrets.token_hex(6),
        )
        for marker in markers:
            client.send(
                "<message xmlns='jabber:client' type='chat' "
                f"id='{marker}' to='echo@{args.component_domain}'>"
                f"<body>{marker}</body></message>"
            )
            record("sent", marker=marker)
        deadline = time.monotonic() + args.timeout
        while pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"component echo deadline expired with {len(pending)} pending")
            try:
                frame = client.receive(min(remaining, 10))
            except TimeoutError:
                continue
            if len(frame) > 1024 * 1024:
                raise RuntimeError("component reply exceeded 1 MiB")
            match = ECHO.search(frame)
            if match is None:
                if "type='error'" in frame or 'type="error"' in frame:
                    record("error", frame=frame)
                    raise RuntimeError("component message returned an XMPP error")
                continue
            marker = match.group(1)
            if marker not in pending:
                record("unexpected_or_duplicate_reply", marker=marker, frame=frame)
                raise RuntimeError("unexpected or duplicate component echo")
            if f"from='echo@{args.component_domain}'" not in frame and f'from="echo@{args.component_domain}"' not in frame:
                record("wrong_sender", marker=marker, frame=frame)
                raise RuntimeError("component echo sender was not the configured domain")
            pending.remove(marker)
            record("received", marker=marker, frame=frame)
        print(json.dumps({"status": "passed", "count": len(markers), "events": str(args.events)}))
    except Exception as error:
        record("failed", pending=sorted(pending), error=str(error))
        raise
    finally:
        if client is not None:
            client.close()
        output.close()


if __name__ == "__main__":
    main()
