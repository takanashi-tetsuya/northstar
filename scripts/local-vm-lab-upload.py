#!/usr/bin/env python3
"""Upload one lab object through XMPP and verify its S3-backed HTTP read."""

from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import pathlib
import re
import sys
import time
from typing import Callable
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET


SLOT_ATTEMPTS = 3
SLOT_DEADLINE_SECONDS = 20
SLOT_BACKOFF_SECONDS = (1.0, 3.0)
STANZA_NS = "urn:ietf:params:xml:ns:xmpp-stanzas"


def log_slot_event(event: dict[str, object]) -> None:
    payload = json.dumps(event, sort_keys=True)
    # The soak controller retains stdout on success and includes stderr on
    # failure; emit the credential-free attempt record to both paths.
    print(payload, flush=True)
    print(payload, file=sys.stderr, flush=True)


def slot_reply_kind(response: str, request_id: str, upload_domain: str) -> str:
    """Classify only this upload IQ; never infer admission from arbitrary text."""
    try:
        iq = ET.fromstring(response)
    except ET.ParseError as error:
        raise RuntimeError("upload slot reply is malformed XML") from error
    if (iq.tag not in ("iq", "{jabber:client}iq")
            or iq.get("id") != request_id
            or iq.get("from") != upload_domain):
        raise RuntimeError("upload slot reply has the wrong IQ identity")
    if iq.get("type") == "result":
        return "result"
    if iq.get("type") != "error":
        raise RuntimeError("upload slot reply has an invalid IQ type")
    errors = [child for child in iq if child.tag in ("error", "{jabber:client}error")]
    if len(errors) == 1 and errors[0].get("type") == "wait":
        conditions = [child.tag for child in errors[0] if child.tag != f"{{{STANZA_NS}}}text"]
        if conditions == [f"{{{STANZA_NS}}}resource-constraint"]:
            return "retryable_admission"
    raise RuntimeError("upload slot IQ failed with a non-retryable error")


def request_slot(client: object, upload_domain: str, size: int, *,
                 emit: Callable[[dict[str, object]], None] = log_slot_event,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic) -> str:
    started = clock()
    deadline = started + SLOT_DEADLINE_SECONDS

    def record(event: str, attempt: int, **details: object) -> None:
        emit({"event": event, "time_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
              "monotonic_ns": time.monotonic_ns(), "attempt": attempt,
              "iq_id": f"northstar-storage-probe-{attempt}" if attempt > 0 else None,
              "elapsed_ms": round((clock() - started) * 1000),
              "max_attempts": SLOT_ATTEMPTS, **details})

    for attempt in range(1, SLOT_ATTEMPTS + 1):
        remaining = deadline - clock()
        if remaining <= 0:
            record("slot_admission_exhausted", attempt - 1,
                   condition="deadline", deadline_seconds=SLOT_DEADLINE_SECONDS)
            raise RuntimeError("upload slot admission exceeded its 20-second deadline")
        request_id = f"northstar-storage-probe-{attempt}"
        record("slot_admission_attempt", attempt,
               deadline_seconds=SLOT_DEADLINE_SECONDS)
        client.send(
            f"<iq xmlns='jabber:client' type='get' id='{request_id}' "
            f"to='{upload_domain}'><request xmlns='urn:xmpp:http:upload:0' "
            f"filename='lab.bin' size='{size}' "
            "content-type='application/octet-stream'/></iq>"
        )
        remaining = deadline - clock()
        if remaining <= 0:
            record("slot_admission_exhausted", attempt,
                   condition="deadline", deadline_seconds=SLOT_DEADLINE_SECONDS)
            raise RuntimeError("upload slot admission exceeded its 20-second deadline")
        response, _ = client.receive_until(request_id, timeout=min(10.0, remaining))
        if clock() >= deadline:
            record("slot_admission_exhausted", attempt,
                   condition="deadline", deadline_seconds=SLOT_DEADLINE_SECONDS)
            raise RuntimeError("upload slot admission exceeded its 20-second deadline")
        if slot_reply_kind(response, request_id, upload_domain) == "result":
            record("slot_admission_success", attempt, condition="result")
            return response
        if attempt == SLOT_ATTEMPTS:
            record("slot_admission_exhausted", attempt,
                   condition="wait/resource-constraint")
            raise RuntimeError(f"upload slot admission remained busy after {SLOT_ATTEMPTS} attempts")
        backoff = SLOT_BACKOFF_SECONDS[attempt - 1]
        if clock() + backoff >= deadline:
            record("slot_admission_exhausted", attempt,
                   condition="deadline", deadline_seconds=SLOT_DEADLINE_SECONDS)
            raise RuntimeError("upload slot admission exceeded its 20-second deadline")
        record("slot_admission_retry", attempt,
               condition="wait/resource-constraint", next_attempt=attempt + 1,
               backoff_ms=round(backoff * 1000))
        sleep(backoff)
    raise AssertionError("bounded slot attempts did not terminate")


def main() -> None:
    spec = importlib.util.spec_from_file_location(
        "northstar_integration", "/home/lab/northstar/integration-wsl.py"
    )
    assert spec and spec.loader
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    fixture.HTTP_HOST = "127.0.0.1"
    fixture.HTTP_PORT = 8080
    fixture.DOMAIN = "ns-a.lab.test"
    password = pathlib.Path(
        "/home/lab/northstar/secrets/prosody-test-password"
    ).read_text().strip()
    body = f"northstar-lab-upload-{time.time_ns()}".encode()
    client = fixture.XmppWebSocket("alice", password, "vm-lab-upload")
    try:
        response = request_slot(client, f"upload.{fixture.DOMAIN}", len(body))
        put = re.search(r"<put url='([^']+)'>.*?Bearer ([A-Za-z0-9]+)", response)
        get = re.search(r"<get url='([^']+)'", response)
        if not put or not get:
            raise RuntimeError("upload slot result lacks a usable put or get URL")
        put_path = urlsplit(put.group(1)).path
        get_path = urlsplit(get.group(1)).path
        status, _, _ = fixture.put_upload_when_ready(
            put_path, body,
            {"Authorization": f"Bearer {put.group(2)}", "Content-Type": "application/octet-stream"},
        )
        assert status == 201, status
        status, _, actual = fixture.raw_http("GET", get_path)
        assert status == 200 and actual == body, status
        print(f"{get_path} {hashlib.sha256(body).hexdigest()}")
    finally:
        client.close()


if __name__ == "__main__":
    main()
