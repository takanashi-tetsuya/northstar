#!/usr/bin/env python3
"""Check personal MAM paging over a real C2S connection in the isolated lab."""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
import re
import socket
import time
import uuid
from pathlib import Path


DOMAIN = "ns-a.lab.test"
PEER = "bob@prosody.lab.test"
MAX_PAGE = 2


def read_page(
    connection: socket.socket, query_id: str, before: str | None = None,
) -> tuple[list[str], list[str], int, int]:
    cursor = "<before/>" if before is None else f"<before>{before}</before>"
    connection.sendall(
        (
            f"<iq xmlns='jabber:client' type='set' id='{query_id}'>"
            f"<query xmlns='urn:xmpp:mam:2' queryid='{query_id}'>"
            "<x xmlns='jabber:x:data' type='submit'>"
            "<field var='FORM_TYPE'><value>urn:xmpp:mam:2</value></field>"
            f"<field var='with'><value>{PEER}</value></field></x>"
            f"<set xmlns='http://jabber.org/protocol/rsm'><max>{MAX_PAGE}</max>{cursor}</set>"
            "</query></iq>"
        ).encode()
    )
    response = bytearray()
    terminal = re.compile(
        rf"<iq\b[^>]*\bid=['\"]{re.escape(query_id)}['\"][^>]*>.*?</iq>", re.S
    )
    connection.settimeout(20)
    while not terminal.search(response.decode(errors="replace")):
        chunk = connection.recv(8192)
        if not chunk:
            raise RuntimeError("C2S connection closed before the MAM terminal IQ")
        response.extend(chunk)
        if len(response) > 2 * 1024 * 1024:
            raise RuntimeError("MAM page response exceeded 2 MiB")
    data = response.decode()
    terminal_iq = terminal.search(data)
    assert terminal_iq is not None
    assert re.search(r"\btype=['\"]result['\"]", terminal_iq.group()), (
        terminal_iq.group()
    )
    assert "<fin " in terminal_iq.group(), terminal_iq.group()
    result_pattern = re.compile(
        rf"<result\b(?=[^>]*\bqueryid=['\"]{re.escape(query_id)}['\"])[^>]*>.*?</result>",
        re.S,
    )
    results = result_pattern.findall(data)
    assert len(results) <= MAX_PAGE, f"MAM returned {len(results)} rows above the page limit"
    ids = []
    for result in results:
        match = re.search(r"\bid=['\"]([0-9a-f-]{36})['\"]", result)
        assert match, result
        ids.append(match.group(1))
    fin = terminal_iq.group()
    count = re.search(r"<count>([0-9]+)</count>", fin)
    assert count, fin
    first_index = re.search(r"<first\s+index=['\"]([0-9]+)['\"]", fin)
    if ids:
        assert first_index, fin
        assert re.search(rf"<first\b[^>]*>{re.escape(ids[0])}</first>", fin), fin
        assert f"<last>{ids[-1]}</last>" in fin, fin
    return (
        results, ids, int(count.group(1)),
        int(first_index.group(1)) if first_index else 0,
    )


def main() -> None:
    helper_path = Path("/home/lab/northstar/local-vm-lab-federation.py")
    spec = importlib.util.spec_from_file_location("northstar_lab_federation", helper_path)
    assert spec and spec.loader
    lab = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lab)
    password = Path("/home/lab/northstar/secrets/prosody-test-password").read_text().strip()
    resource = f"mam-{uuid.uuid4().hex[:12]}"
    alice = lab.connect_peer(DOMAIN, "alice", password, host=DOMAIN, resource=resource)
    try:
        bob = lab.connect_peer("prosody.lab.test", "bob", password)
        try:
            # The lab's default policy archives only encrypted-envelope
            # stanzas. These opaque fixture bytes test MAM, not E2EE.
            markers = []
            for _ in range(3):
                marker = f"lab-mam-{time.time_ns()}"
                alice.sendall(
                    (
                        f"<message to='{PEER}' type='chat' id='{marker}'>"
                        "<encrypted xmlns='jabber:x:encrypted'>AQIDBA==</encrypted></message>"
                    ).encode()
                )
                assert marker in lab.receive_until(bob, marker), (
                    "outbound message was not delivered"
                )
                markers.append(marker)
        finally:
            bob.close()
        query_id = f"mam-{uuid.uuid4().hex[:12]}"
        results, ids, total, first_index = read_page(alice, query_id)
        if total == 0:
            preferences_id = f"mam-prefs-{uuid.uuid4().hex[:12]}"
            alice.sendall(
                (
                    f"<iq xmlns='jabber:client' type='get' id='{preferences_id}'>"
                    "<prefs xmlns='urn:xmpp:mam:2'/></iq>"
                ).encode()
            )
            preferences = lab.receive_until(alice, "</iq>")
            raise RuntimeError(f"MAM returned no rows; preferences reply: {preferences[-800:]}")
        assert any(markers[-1] in result for result in results), (
            f"delivered marker was absent from MAM: rows={len(results)} total={total} "
            f"latest_result={results[-1][-320:] if results else 'none'}"
        )
        assert len(set(ids)) == len(ids), "MAM page repeated an archive ID"
        assert total >= 3 and len(results) == MAX_PAGE
        assert first_index + len(results) == total, "MAM last-page index disagreed with count"
        previous, previous_ids, previous_total, previous_index = read_page(
            alice, f"mam-{uuid.uuid4().hex[:12]}", before=ids[0],
        )
        assert previous and not set(ids).intersection(previous_ids), "MAM pages overlap"
        assert previous_index + len(previous) == first_index, "MAM page indexes are not adjacent"
        print(json.dumps(
            {
                "time_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                "status": "passed",
                "probe": "personal-mam-adjacent-pages",
                "rows": len(results),
                "total": total,
                "first_index": first_index,
                "previous_rows": len(previous),
                "previous_total": previous_total,
                "previous_first_index": previous_index,
                "marker": markers[-1],
            },
            sort_keys=True,
        ))
    finally:
        alice.close()


if __name__ == "__main__":
    main()
