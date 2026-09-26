#!/usr/bin/env python3
"""Check a lab-only XEP-0225 component through a real Northstar C2S session.

This is an observer, not a component implementation. The peer must be an
independently packaged XEP-0225 component such as Tigase.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import secrets
import stat
import time
import xml.etree.ElementTree as ET


CLIENT_NS = "jabber:client"
DISCO_NS = "http://jabber.org/protocol/disco#info"
MUC_NS = "http://jabber.org/protocol/muc"


def lab_domain(value: str) -> bool:
    return len(value) <= 253 and value.endswith(".lab.test") and all(
        len(label) <= 63
        and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in value.split(".")
    )


def check_disco(frame: str, request_id: str, domain: str) -> bool:
    """Return whether this is the expected MUC reply; reject a matching error."""
    if request_id not in frame:
        return False
    root = ET.fromstring(frame)
    if root.tag not in ("iq", f"{{{CLIENT_NS}}}iq") or root.get("id") != request_id:
        return False
    if root.get("from") != domain:
        raise ValueError("disco response came from a different component domain")
    if root.get("type") != "result":
        raise ValueError("component returned a non-result disco response")
    queries = root.findall(f"{{{DISCO_NS}}}query")
    if len(queries) != 1:
        raise ValueError("disco response omitted its query")
    query = queries[0]
    if query.get("node") is not None:
        raise ValueError("component disco response described a different node")
    if not any(node.get("category") == "conference" for node in query.findall(f"{{{DISCO_NS}}}identity")):
        raise ValueError("independent component did not advertise a conference identity")
    if not any(node.get("var") == MUC_NS for node in query.findall(f"{{{DISCO_NS}}}feature")):
        raise ValueError("independent component did not advertise the MUC feature")
    return True


def protected_text(path: pathlib.Path) -> str:
    if not path.is_absolute():
        raise ValueError("password path must be absolute")
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_mode & 0o077:
        raise ValueError("password must be an owner-only regular file")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("password changed while opening")
        if not stat.S_ISREG(opened.st_mode) or opened.st_mode & 0o077:
            raise ValueError("password must remain an owner-only regular file")
        raw = os.read(descriptor, 4097)
    finally:
        os.close(descriptor)
    value = raw.rstrip(b"\r\n")
    if not 1 <= len(value) <= 4096 or b"\0" in value:
        raise ValueError("password length or contents are invalid")
    return value.decode("utf-8")


def self_test() -> None:
    domain = "muc.ns-a.lab.test"
    request_id = "component-0225-abc"
    reply = (
        f"<iq xmlns='{CLIENT_NS}' from='{domain}' id='{request_id}' type='result'>"
        f"<query xmlns='{DISCO_NS}'><identity category='conference' type='text'/>"
        f"<feature var='{MUC_NS}'/></query></iq>"
    )
    assert check_disco(reply, request_id, domain)
    assert not check_disco(reply, "other-id", domain)
    for wrong in (
        reply.replace(f"from='{domain}'", "from='forged.lab.test'"),
        reply.replace(MUC_NS, "urn:wrong:feature"),
        reply.replace("type='result'", "type='error'"),
        reply.replace(f"<query xmlns='{DISCO_NS}'", f"<query xmlns='{DISCO_NS}' node='other'"),
    ):
        try:
            check_disco(wrong, request_id, domain)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid independent component response was accepted")
    print("XEP-0225 C2S observer parser self-test passed")


def run(args: argparse.Namespace) -> None:
    if not lab_domain(args.server_domain) or not lab_domain(args.component_domain):
        raise ValueError("server and component must be canonical .lab.test domains")
    if args.component_domain == args.server_domain:
        raise ValueError("component must use a distinct lab domain")
    if args.component_domain in {
        f"{service}.{args.server_domain}"
        for service in ("pubsub", "conference", "mix", "upload")
    }:
        raise ValueError("component domain must not be a Northstar built-in service")
    if not re.fullmatch(r"[a-z0-9_]{1,64}", args.username):
        raise ValueError("username must be a canonical test account")
    if not 1 <= args.http_port <= 65535 or not 5 <= args.timeout <= 120:
        raise ValueError("port or timeout exceeds the bounded lab range")
    if not args.fixture.is_absolute() or not args.fixture.is_file() or args.fixture.is_symlink():
        raise ValueError("fixture must be an absolute regular non-symlink path")
    if not args.events.is_absolute() or args.events.exists() or args.events.is_symlink():
        raise ValueError("events must be a fresh absolute path")
    parent = args.events.parent
    if not parent.is_dir() or parent.is_symlink() or parent.stat().st_mode & 0o077:
        raise ValueError("events parent must be an existing owner-only directory")
    password = protected_text(args.password_file)
    spec = importlib.util.spec_from_file_location("northstar_integration", args.fixture)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the XMPP WebSocket fixture")
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    fixture.HTTP_HOST = "127.0.0.1"
    fixture.HTTP_PORT = args.http_port
    fixture.DOMAIN = args.server_domain
    fixture_hash = hashlib.sha256(args.fixture.read_bytes()).hexdigest()
    request_id = "component-0225-" + secrets.token_hex(12)
    old_umask = os.umask(0o077)
    try:
        output = os.fdopen(os.open(
            args.events, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
        ), "w", encoding="utf-8", buffering=1)
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
        record("start", component_domain=args.component_domain,
               server_domain=args.server_domain, fixture_sha256=fixture_hash,
               request_id=request_id, timeout_seconds=args.timeout)
        client = fixture.XmppWebSocket(
            args.username, password, "component-0225-" + secrets.token_hex(6),
        )
        client.send(
            f"<iq xmlns='{CLIENT_NS}' type='get' id='{request_id}' "
            f"to='{args.component_domain}'><query xmlns='{DISCO_NS}'/></iq>"
        )
        record("sent", request_id=request_id)
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            try:
                frame = client.receive(min(10, max(0.1, deadline - time.monotonic())))
            except TimeoutError:
                continue
            if len(frame) > 65536:
                raise ValueError("XMPP response exceeded 64 KiB")
            if check_disco(frame, request_id, args.component_domain):
                record("received", frame=frame)
                print(json.dumps({"status": "passed", "events": str(args.events)}))
                return
        raise TimeoutError("independent component disco reply was not received")
    except Exception as error:
        record("failed", error=str(error))
        raise
    finally:
        if client is not None:
            client.close()
        output.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--component-domain", default="muc.ns-a.lab.test")
    parser.add_argument("--server-domain", default="ns-a.lab.test")
    parser.add_argument("--username", default="alice")
    parser.add_argument("--password-file", type=pathlib.Path)
    parser.add_argument("--fixture", type=pathlib.Path)
    parser.add_argument("--events", type=pathlib.Path)
    parser.add_argument("--http-port", type=int, default=8080)
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if args.password_file is None or args.fixture is None or args.events is None:
        parser.error("--password-file, --fixture and --events are required")
    run(args)


if __name__ == "__main__":
    main()
