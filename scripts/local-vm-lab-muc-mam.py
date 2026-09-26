#!/usr/bin/env python3
"""Check room MAM ordering and archive visibility on an isolated Northstar VM."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import sys
import tempfile
import time
import uuid
from pathlib import Path


DOMAIN = "ns-a.lab.test"
MAX_XML_BYTES = 64 * 1024
MAX_EVIDENCE_BYTES = 1024 * 1024


class Evidence:
    """Keep bounded, private raw stanza evidence after the login handshake."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.file = os.fdopen(
            os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),
            "w", encoding="utf-8",
        )
        self.bytes_written = 0

    def record(self, phase: str, direction: str, xml: str) -> None:
        if len(xml.encode()) > MAX_XML_BYTES:
            raise RuntimeError(f"{phase} stanza exceeded {MAX_XML_BYTES} bytes")
        line = json.dumps({
            "time_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "monotonic_ns": time.monotonic_ns(),
            "phase": phase, "direction": direction, "xml": xml,
        }, sort_keys=True) + "\n"
        size = len(line.encode())
        if self.bytes_written + size > MAX_EVIDENCE_BYTES:
            raise RuntimeError(f"raw evidence exceeded {MAX_EVIDENCE_BYTES} bytes")
        self.file.write(line)
        self.file.flush()
        os.fsync(self.file.fileno())
        self.bytes_written += size

    def digest(self) -> str:
        self.file.flush()
        os.fsync(self.file.fileno())
        return hashlib.sha256(self.path.read_bytes()).hexdigest()

    def close(self) -> None:
        self.file.close()


def exchange(client: object, phase: str, xml: str, marker: str, evidence: Evidence) -> tuple[str, list[str], int]:
    evidence.record(phase, "sent", xml)
    start = time.monotonic_ns()
    client.send(xml)
    reply, frames = client.receive_until(marker, timeout=20)
    elapsed_ms = (time.monotonic_ns() - start) // 1_000_000
    for frame in frames:
        evidence.record(phase, "received", frame)
    return reply, frames, elapsed_ms


def page(
    client: object, room: str, before: str | None, evidence: Evidence,
) -> tuple[list[str], int, int, int]:
    query_id = f"muc-mam-{uuid.uuid4().hex[:12]}"
    cursor = "<before/>" if before is None else f"<before>{before}</before>"
    query = (
        f"<iq xmlns='jabber:client' type='set' id='{query_id}' to='{room}'>"
        f"<query xmlns='urn:xmpp:mam:2' queryid='{query_id}'>"
        f"<set xmlns='http://jabber.org/protocol/rsm'><max>2</max>{cursor}</set>"
        "</query></iq>"
    )
    _, frames, elapsed_ms = exchange(client, "room_mam_page", query, "<fin ", evidence)
    reply = "".join(frames)
    fin = frames[-1]
    assert f"id='{query_id}'" in fin and "type='result'" in fin, fin
    ids = []
    for result in re.findall(
        rf"<result\b(?=[^>]*\bqueryid='{re.escape(query_id)}')[^>]*>.*?</result>",
        reply, re.S,
    ):
        match = re.search(r"\bid='([0-9a-f-]{36})'", result)
        assert match, result
        ids.append(match.group(1))
        assert "urn:xmpp:forward:0" in result and f"from='{room}/" in result, result
        assert "<encrypted xmlns='jabber:x:encrypted'" in result, result
        assert "lab-muc-mam-" not in result, "plaintext fallback leaked into room MAM"
    assert len(ids) <= 2 and len(ids) == len(set(ids)), reply
    count = re.search(r"<count>(\d+)</count>", fin)
    first = re.search(r"<first index='(\d+)'", fin)
    assert count and (not ids or first), fin
    if ids:
        assert f">{ids[0]}</first>" in fin and f"<last>{ids[-1]}</last>" in fin, fin
    return ids, int(count.group(1)), int(first.group(1)) if first else 0, elapsed_ms


def self_test() -> None:
    class FakeClient:
        def __init__(self) -> None:
            self.sent = ""

        def send(self, xml: str) -> None:
            self.sent = xml

        def receive_until(self, marker: str, timeout: int = 20) -> tuple[str, list[str]]:
            assert marker == "<fin " and timeout == 20
            query_id = re.search(r"queryid='([^']+)'", self.sent).group(1)
            row_id = "00000000-0000-0000-0000-000000000001"
            result = (
                f"<message><result xmlns='urn:xmpp:mam:2' queryid='{query_id}' id='{row_id}'>"
                "<forwarded xmlns='urn:xmpp:forward:0'>"
                "<message from='room@conference.ns-a.lab.test/Alice'>"
                "<encrypted xmlns='jabber:x:encrypted'>AQIDBA==</encrypted>"
                "</message></forwarded></result></message>"
            )
            fin = (
                f"<iq id='{query_id}' type='result'><fin xmlns='urn:xmpp:mam:2'>"
                "<set><count>1</count>"
                f"<first index='0'>{row_id}</first><last>{row_id}</last>"
                "</set></fin></iq>"
            )
            return fin, [result, fin]

    with tempfile.TemporaryDirectory() as directory:
        evidence = Evidence(Path(directory) / "stanzas.jsonl")
        try:
            ids, count, index, _ = page(
                FakeClient(), "room@conference.ns-a.lab.test", None, evidence,
            )
            assert len(ids) == count == 1 and index == 0
            assert len(evidence.digest()) == 64
            records = [json.loads(line) for line in evidence.path.read_text().splitlines()]
            assert [row["direction"] for row in records] == ["sent", "received", "received"]
            assert evidence.path.stat().st_mode & 0o777 == 0o600
            try:
                evidence.record("oversized", "received", "x" * (MAX_XML_BYTES + 1))
            except RuntimeError:
                pass
            else:
                raise AssertionError("oversized stanza was accepted")
        finally:
            evidence.close()
    print("local-vm-lab-muc-mam self-test passed")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    evidence_path = args.evidence or Path(
        f"/tmp/northstar-lab-muc-mam-{uuid.uuid4().hex}.jsonl"
    )
    spec = importlib.util.spec_from_file_location(
        "northstar_lab_integration", "/home/lab/northstar/integration-wsl.py"
    )
    assert spec and spec.loader
    lab = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lab)
    lab.HTTP_HOST = "127.0.0.1"
    lab.HTTP_PORT = 8080
    lab.DOMAIN = DOMAIN
    password = Path("/home/lab/northstar/secrets/prosody-test-password").read_text().strip()
    resource = f"muc-mam-{uuid.uuid4().hex[:12]}"
    room = f"lab-mam-{uuid.uuid4().hex[:12]}@conference.{DOMAIN}"
    client = lab.XmppWebSocket("alice", password, resource)
    evidence = Evidence(evidence_path)
    room_created = False
    room_destroyed = False
    try:
        joined, _, join_ms = exchange(client, "room_join", (
            f"<presence xmlns='jabber:client' to='{room}/Alice'>"
            "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
        ), "code='110'", evidence)
        assert "code='201'" in joined and "affiliation='owner'" in joined, joined
        room_created = True
        config_id = f"muc-config-{uuid.uuid4().hex[:12]}"
        configured, _, config_ms = exchange(client, "room_config", (
            f"<iq xmlns='jabber:client' type='set' id='{config_id}' to='{room}'>"
            "<query xmlns='http://jabber.org/protocol/muc#owner'>"
            "<x xmlns='jabber:x:data' type='submit'/></query></iq>"
        ), config_id, evidence)
        assert "type='result'" in configured, configured
        markers = []
        echo_ms = []
        for _ in range(3):
            marker = f"lab-muc-mam-{time.time_ns()}"
            echo, _, elapsed_ms = exchange(client, "groupchat_echo", (
                f"<message xmlns='jabber:client' to='{room}' type='groupchat' id='{marker}'>"
                "<encrypted xmlns='jabber:x:encrypted'>AQIDBA==</encrypted>"
                f"<body>{marker}</body></message>"
            ), marker, evidence)
            assert f"from='{room}/Alice'" in echo, echo
            markers.append(marker)
            echo_ms.append(elapsed_ms)
        last_ids, total, last_index, last_page_ms = page(client, room, None, evidence)
        assert len(last_ids) == 2 and total >= 3 and last_index + 2 == total
        previous_ids, previous_total, previous_index, previous_page_ms = page(
            client, room, last_ids[0], evidence,
        )
        assert previous_ids and not set(last_ids).intersection(previous_ids)
        assert previous_total == total and previous_index + len(previous_ids) == last_index
        destroy_id = f"muc-destroy-{uuid.uuid4().hex[:12]}"
        destroyed, _, destroy_ms = exchange(client, "room_destroy", (
            f"<iq xmlns='jabber:client' type='set' id='{destroy_id}' to='{room}'>"
            "<query xmlns='http://jabber.org/protocol/muc#owner'>"
            "<destroy/></query></iq>"
        ), destroy_id, evidence)
        assert "type='result'" in destroyed, destroyed
        room_destroyed = True
        print(json.dumps({
            "time_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "status": "passed", "probe": "room-mam-adjacent-pages",
            "room": room, "last_rows": len(last_ids), "total": total,
            "last_first_index": last_index, "previous_rows": len(previous_ids),
            "previous_first_index": previous_index, "last_marker": markers[-1],
            "join_ms": join_ms, "config_ms": config_ms,
            "echo_ms": echo_ms, "last_page_ms": last_page_ms,
            "previous_page_ms": previous_page_ms, "destroy_ms": destroy_ms,
            "evidence_jsonl": str(evidence.path),
            "evidence_sha256": evidence.digest(),
            "evidence_bytes": evidence.bytes_written,
        }, sort_keys=True))
    finally:
        if room_created and not room_destroyed:
            try:
                destroy_id = f"muc-destroy-{uuid.uuid4().hex[:12]}"
                exchange(client, "room_destroy_after_error", (
                    f"<iq xmlns='jabber:client' type='set' id='{destroy_id}' to='{room}'>"
                    "<query xmlns='http://jabber.org/protocol/muc#owner'>"
                    "<destroy/></query></iq>"
                ), destroy_id, evidence)
            except Exception as error:
                print(f"MUC room cleanup failed: {error}", file=sys.stderr)
        print(json.dumps({
            "evidence_jsonl": str(evidence.path),
            "evidence_sha256": evidence.digest(),
            "evidence_bytes": evidence.bytes_written,
        }, sort_keys=True), file=sys.stderr)
        evidence.close()
        client.close()


if __name__ == "__main__":
    main()
