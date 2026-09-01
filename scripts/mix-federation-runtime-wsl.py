#!/usr/bin/env python3
"""Two-domain MIX-PAM and durable S2S handoff runtime probe."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import os
import pathlib
import re
import sys
import time


ROOT = pathlib.Path(__file__).resolve().parent
PASSWORD = "mix-federation-password-123"
ALICE = "mix_fed_alice"
BOB = "mix_fed_bob"
CHANNEL = "fedruntime@mix.remote.localhost"
CORE = "urn:xmpp:mix:core:1"
PAM = "urn:xmpp:mix:pam:2"


def load_fixture(name: str, domain: str, http_port: str):
    saved = {key: os.environ.get(key) for key in ("XMPP_TEST_DOMAIN", "XMPP_TEST_HTTP_PORT")}
    os.environ["XMPP_TEST_DOMAIN"] = domain
    os.environ["XMPP_TEST_HTTP_PORT"] = http_port
    spec = importlib.util.spec_from_file_location(name, ROOT / "integration-wsl.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    return module


A = load_fixture("northstar_mix_fed_a", "localhost", os.environ["MIX_FED_HTTP_A"])
B = load_fixture("northstar_mix_fed_b", "remote.localhost", os.environ["MIX_FED_HTTP_B"])


class Inbox:
    def __init__(self, client: object):
        self.client = client
        self.pending: list[str] = []

    def wait(self, marker: str, timeout: float = 30) -> str:
        deadline = time.monotonic() + timeout
        while True:
            for index, frame in enumerate(self.pending):
                if marker in frame:
                    return self.pending.pop(index)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"federated MIX inbox timed out for {marker!r}: {self.pending!r}")
            self.pending.append(self.client.receive(remaining))

    def send(self, stanza: str) -> None:
        self.client.send(stanza)

    def close(self) -> None:
        self.client.close()


def check(value: bool, message: str) -> None:
    if not value:
        raise AssertionError(message)


def register(fixture, username: str) -> str:
    status, result = fixture.register_account(username, PASSWORD)
    check(status == 201, f"registration failed for {username}: {status} {result}")
    return login(fixture, username)


def login(fixture, username: str) -> str:
    status, result = fixture.api("POST", "/api/v1/login", {"username": username, "password": PASSWORD})
    check(status == 200, f"login failed for {username}: {status} {result}")
    return result["token"]


def connect(fixture, username: str, resource: str) -> Inbox:
    client = Inbox(fixture.XmppWebSocket(username, PASSWORD, resource))
    node = f"https://northstar.invalid/mix-fed-{username}-{resource}"
    name = "Northstar MIX Federation Runtime"
    verification = f"client/pc//{name}<urn:xmpp:mix:core:1<urn:xmpp:mix:pam:2<"
    version = base64.b64encode(hashlib.sha1(verification.encode()).digest()).decode()
    client.send(
        "<presence xmlns='jabber:client'>"
        f"<c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='{node}' ver='{version}'/>"
        "</presence>"
    )
    query = client.wait(f"node='{node}#")
    query_id = re.search(r"id='([^']+)'", query)
    check(query_id is not None, f"caps query lacked id: {query}")
    client.send(
        f"<iq xmlns='jabber:client' type='result' id='{query_id.group(1)}'>"
        f"<query xmlns='http://jabber.org/protocol/disco#info' node='{node}#{version}'>"
        f"<identity category='client' type='pc' name='{name}'/>"
        "<feature var='urn:xmpp:mix:core:1'/><feature var='urn:xmpp:mix:pam:2'/></query></iq>"
    )
    barrier = f"barrier-{resource}"
    client.send(f"<iq xmlns='jabber:client' type='get' id='{barrier}'><ping xmlns='urn:xmpp:ping'/></iq>")
    check("type='result'" in client.wait(f"id='{barrier}'"), "caps barrier failed")
    return client


def iq(client: Inbox, stanza_id: str, to: str, payload: str) -> str:
    client.send(f"<iq xmlns='jabber:client' type='set' id='{stanza_id}' to='{to}'>{payload}</iq>")
    return client.wait(f"id='{stanza_id}'")


def setup() -> None:
    A.wait_ready()
    B.wait_ready()
    register(A, ALICE)
    bob_token = register(B, BOB)
    alice = connect(A, ALICE, "setup-a")
    bob = connect(B, BOB, "setup-b")
    created = iq(bob, "fed-create", "mix.remote.localhost", f"<create xmlns='{CORE}' channel='fedruntime'/>")
    check("type='result'" in created, f"remote channel create failed: {created}")
    nodes = "".join(
        f"<subscribe node='{node}'/>"
        for node in (
            "urn:xmpp:mix:nodes:messages",
            "urn:xmpp:mix:nodes:presence",
            "urn:xmpp:mix:nodes:participants",
        )
    )
    bob_join = iq(
        bob,
        "fed-join-bob",
        "mix_fed_bob@remote.localhost",
        f"<client-join xmlns='{PAM}' channel='{CHANNEL}'><join xmlns='{CORE}'>{nodes}<nick>Bob</nick></join></client-join>",
    )
    check("type='result'" in bob_join, f"local PAM join failed: {bob_join}")
    alice_join = iq(
        alice,
        "fed-join-alice",
        "mix_fed_alice@localhost",
        f"<client-join xmlns='{PAM}' channel='{CHANNEL}'><join xmlns='{CORE}'>{nodes}<nick>Alice</nick></join></client-join>",
    )
    check("type='result'" in alice_join and "#fedruntime@mix.remote.localhost" in alice_join, f"federated PAM join failed: {alice_join}")
    bob.client.send_with_pow(
        f"<message xmlns='jabber:client' type='groupchat' id='fed-live' to='{CHANNEL}'><body>federated MIX live</body></message>",
        bob_token,
    )
    live = alice.wait("federated MIX live")
    check("type='groupchat'" in live, f"reverse federated MIX delivery failed: {live}")
    alice.close()
    bob.close()
    print("MIX federation setup: create/local-PAM/remote-PAM/reverse-delivery PASS")


def enqueue() -> None:
    token = login(A, ALICE)
    alice = connect(A, ALICE, "enqueue-a")
    alice.client.send_with_pow(
        f"<message xmlns='jabber:client' type='groupchat' id='fed-durable' to='{CHANNEL}'><body>durable MIX handoff</body></message>",
        token,
    )
    time.sleep(1)
    alice.close()
    print("MIX federation durable message submitted while remote server is down")


def finish() -> None:
    A.wait_ready()
    B.wait_ready()
    alice_token = login(A, ALICE)
    bob_token = login(B, BOB)
    bob = connect(B, BOB, "finish-b")
    alice = connect(A, ALICE, "finish-a")
    replayed_live = bob.wait("durable MIX handoff")
    check(
        "<result xmlns='urn:xmpp:mam:2'" not in replayed_live,
        f"durable outbox replay unexpectedly arrived as a MAM wrapper: {replayed_live}",
    )
    mam = iq(
        bob,
        "fed-durable-mam",
        CHANNEL,
        "<query xmlns='urn:xmpp:mam:2' queryid='fed-durable-query'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>urn:xmpp:mam:2</value></field></x><set xmlns='http://jabber.org/protocol/rsm'><max>20</max></set></query>",
    )
    check("<fin " in mam, f"durable MIX MAM query failed: {mam}")
    durable = bob.wait("durable MIX handoff")
    check(
        "<result xmlns='urn:xmpp:mam:2'" in durable,
        f"durable MIX handoff was not committed to channel MAM: {durable}",
    )
    alice.client.send_with_pow(
        f"<message xmlns='jabber:client' type='groupchat' id='fed-after' to='{CHANNEL}'><body>MIX federation after restart</body></message>",
        alice_token,
    )
    after = bob.wait("MIX federation after restart")
    check("type='groupchat'" in after, f"post-restart federated delivery failed: {after}")
    bob.client.send_with_pow(
        f"<message xmlns='jabber:client' type='groupchat' id='fed-reverse' to='{CHANNEL}'><body>MIX reverse after restart</body></message>",
        bob_token,
    )
    reverse = alice.wait("MIX reverse after restart")
    check("type='groupchat'" in reverse, f"post-restart reverse delivery failed: {reverse}")
    left = iq(
        alice,
        "fed-leave",
        "mix_fed_alice@localhost",
        f"<client-leave xmlns='{PAM}' channel='{CHANNEL}'><leave xmlns='{CORE}'/></client-leave>",
    )
    check("type='result'" in left, f"federated PAM leave failed: {left}")
    alice.close()
    bob.close()
    print("MIX federation finish: durable-drain/bidirectional-delivery/PAM-leave PASS")


if __name__ == "__main__":
    {"setup": setup, "enqueue": enqueue, "finish": finish}[sys.argv[1]]()
