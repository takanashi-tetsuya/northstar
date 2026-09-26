#!/usr/bin/env python3
"""Upload one lab object through XMPP and verify its S3-backed HTTP read."""

from __future__ import annotations

import hashlib
import importlib.util
import pathlib
import re
import time
from urllib.parse import urlsplit


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
        client.send(
            f"<iq xmlns='jabber:client' type='get' id='northstar-storage-probe' "
            f"to='upload.{fixture.DOMAIN}'><request xmlns='urn:xmpp:http:upload:0' "
            f"filename='lab.bin' size='{len(body)}' "
            "content-type='application/octet-stream'/></iq>"
        )
        response, _ = client.receive_until("northstar-storage-probe")
        put = re.search(r"<put url='([^']+)'>.*?Bearer ([A-Za-z0-9]+)", response)
        get = re.search(r"<get url='([^']+)'", response)
        assert put and get, response
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
