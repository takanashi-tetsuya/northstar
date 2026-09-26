#!/usr/bin/env python3
"""Check room MAM ordering and archive visibility on an isolated Northstar VM."""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
import re
import time
import uuid
from pathlib import Path


DOMAIN = "ns-a.lab.test"


def page(client: object, room: str, before: str | None) -> tuple[list[str], int, int]:
    query_id = f"muc-mam-{uuid.uuid4().hex[:12]}"
    cursor = "<before/>" if before is None else f"<before>{before}</before>"
    client.send(
        f"<iq xmlns='jabber:client' type='set' id='{query_id}' to='{room}'>"
        f"<query xmlns='urn:xmpp:mam:2' queryid='{query_id}'>"
        f"<set xmlns='http://jabber.org/protocol/rsm'><max>2</max>{cursor}</set>"
        "</query></iq>"
    )
    _, frames = client.receive_until("<fin ", timeout=20)
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
    return ids, int(count.group(1)), int(first.group(1)) if first else 0


def main() -> None:
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
    try:
        client.send(
            f"<presence xmlns='jabber:client' to='{room}/Alice'>"
            "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
        )
        joined, _ = client.receive_until("code='110'", timeout=20)
        assert "code='201'" in joined and "affiliation='owner'" in joined, joined
        config_id = f"muc-config-{uuid.uuid4().hex[:12]}"
        client.send(
            f"<iq xmlns='jabber:client' type='set' id='{config_id}' to='{room}'>"
            "<query xmlns='http://jabber.org/protocol/muc#owner'>"
            "<x xmlns='jabber:x:data' type='submit'/></query></iq>"
        )
        configured, _ = client.receive_until(config_id, timeout=20)
        assert "type='result'" in configured, configured
        markers = []
        for _ in range(3):
            marker = f"lab-muc-mam-{time.time_ns()}"
            client.send(
                f"<message xmlns='jabber:client' to='{room}' type='groupchat' id='{marker}'>"
                "<encrypted xmlns='jabber:x:encrypted'>AQIDBA==</encrypted>"
                f"<body>{marker}</body></message>"
            )
            echo, _ = client.receive_until(marker, timeout=20)
            assert f"from='{room}/Alice'" in echo, echo
            markers.append(marker)
        last_ids, total, last_index = page(client, room, None)
        assert len(last_ids) == 2 and total >= 3 and last_index + 2 == total
        previous_ids, previous_total, previous_index = page(client, room, last_ids[0])
        assert previous_ids and not set(last_ids).intersection(previous_ids)
        assert previous_total == total and previous_index + len(previous_ids) == last_index
        print(json.dumps({
            "time_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "status": "passed", "probe": "room-mam-adjacent-pages",
            "room": room, "last_rows": len(last_ids), "total": total,
            "last_first_index": last_index, "previous_rows": len(previous_ids),
            "previous_first_index": previous_index, "last_marker": markers[-1],
        }, sort_keys=True))
    finally:
        client.close()


if __name__ == "__main__":
    main()
