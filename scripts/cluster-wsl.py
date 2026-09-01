#!/usr/bin/env python3
"""Two-node Redis routing test for Northstar's experimental cluster layer."""

from __future__ import annotations

import importlib.util
import base64
import hashlib
import os
import pathlib
import re
import signal
import socket
import json
import select
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid


ROOT = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("northstar_integration", ROOT / "integration-wsl.py")
fixture = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(fixture)

DOMAIN = "cluster.localhost"
PASSWORD = "cluster-password-123"
ALICE = "alice_cluster"
BOB = "bob_cluster"
HTTP_A = int(os.environ.get("NORTHSTAR_CLUSTER_HTTP_A", "18581"))
HTTP_B = int(os.environ.get("NORTHSTAR_CLUSTER_HTTP_B", "18582"))
XMPP_A = int(os.environ.get("NORTHSTAR_CLUSTER_XMPP_A", "16522"))
XMPP_B = int(os.environ.get("NORTHSTAR_CLUSTER_XMPP_B", "16523"))
METRICS_A = int(os.environ.get("NORTHSTAR_CLUSTER_METRICS_A", "0"))
METRICS_B = int(os.environ.get("NORTHSTAR_CLUSTER_METRICS_B", "0"))
REDIS_PORT = int(os.environ.get("NORTHSTAR_CLUSTER_REDIS_PORT", "0"))
REDIS_PASSWORD = os.environ.get("NORTHSTAR_CLUSTER_REDIS_PASSWORD", "")
REDIS_PID = int(os.environ.get("NORTHSTAR_CLUSTER_REDIS_PID", "0"))
REDIS_CA = os.environ.get("NORTHSTAR_CLUSTER_REDIS_CA", "")
REDIS_CERT = os.environ.get("NORTHSTAR_CLUSTER_REDIS_CERT", "")
REDIS_KEY = os.environ.get("NORTHSTAR_CLUSTER_REDIS_KEY", "")
LOG_B = os.environ.get("NORTHSTAR_CLUSTER_LOG_B", "")
SCHEMA = os.environ.get("NORTHSTAR_CLUSTER_SCHEMA", "")
PID_B = int(os.environ.get("NORTHSTAR_CLUSTER_PID_B", "0"))
NODE_B_PRIVATE_KEY_DER = os.environ.get("NORTHSTAR_CLUSTER_NODE_B_PRIVATE_KEY_DER", "")


def redis_cli(*arguments: str, input_bytes: bytes | None = None) -> str:
    environment = dict(os.environ)
    environment["REDISCLI_AUTH"] = REDIS_PASSWORD
    result = subprocess.run(
        [
            "redis-cli",
            "--raw",
            "--tls",
            "--cacert",
            REDIS_CA,
            "--cert",
            REDIS_CERT,
            "--key",
            REDIS_KEY,
            "--user",
            "northstar",
            "-h",
            "localhost",
            "-p",
            str(REDIS_PORT),
            *arguments,
        ],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        env=environment,
    )
    return result.stdout.decode("utf-8", "strict").strip()


def redis_subscriber(channel: str) -> subprocess.Popen[bytes]:
    environment = dict(os.environ)
    environment["REDISCLI_AUTH"] = REDIS_PASSWORD
    process = subprocess.Popen(
        [
            "redis-cli",
            "--raw",
            "--tls",
            "--cacert",
            REDIS_CA,
            "--cert",
            REDIS_CERT,
            "--key",
            REDIS_KEY,
            "--user",
            "northstar",
            "-h",
            "localhost",
            "-p",
            str(REDIS_PORT),
            "subscribe",
            channel,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )
    assert process.stdout is not None
    fixture.check(process.stdout.readline().strip() == b"subscribe", "Redis subscription did not start")
    fixture.check(process.stdout.readline().decode().strip() == channel, "Redis subscribed to the wrong channel")
    fixture.check(process.stdout.readline().strip() == b"1", "Redis subscription count is wrong")
    return process


def offline_marker_count(marker: str) -> int:
    fixture.check(
        re.fullmatch(r"[a-z_][a-z0-9_]*", SCHEMA) is not None,
        "cluster PostgreSQL schema is missing or invalid",
    )
    fixture.check(
        re.fullmatch(r"[a-z0-9-]+", marker) is not None,
        "offline marker is unsafe for the PostgreSQL fixture",
    )
    environment = dict(os.environ)
    environment["PGPASSWORD"] = "xmpp-test-password"
    environment["PGOPTIONS"] = f"-c search_path={SCHEMA}"
    result = subprocess.run(
        [
            "psql",
            "--no-psqlrc",
            "--quiet",
            "--tuples-only",
            "--no-align",
            "--host",
            "127.0.0.1",
            "--username",
            "xmpp_test",
            "--dbname",
            "xmpp_test",
            "--set",
            "ON_ERROR_STOP=1",
            "--command",
            "SELECT COUNT(*) FROM offline_messages "
            f"WHERE stanza LIKE '%{marker}%';",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        env=environment,
        text=True,
    )
    return int(result.stdout.strip())


def offline_account_snapshot(username: str) -> str:
    fixture.check(
        re.fullmatch(r"[a-z_][a-z0-9_]*", username) is not None,
        "offline snapshot username is unsafe",
    )
    environment = dict(os.environ)
    environment["PGPASSWORD"] = "xmpp-test-password"
    environment["PGOPTIONS"] = f"-c search_path={SCHEMA}"
    result = subprocess.run(
        [
            "psql",
            "--no-psqlrc",
            "--quiet",
            "--tuples-only",
            "--no-align",
            "--host",
            "127.0.0.1",
            "--username",
            "xmpp_test",
            "--dbname",
            "xmpp_test",
            "--set",
            "ON_ERROR_STOP=1",
            "--command",
            "SELECT message.id::TEXT || ':' || message.stanza "
            "FROM offline_messages message JOIN users ON users.id=message.recipient_id "
            f"WHERE users.username='{username}' ORDER BY message.created_at,message.id;",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        env=environment,
        text=True,
    )
    return result.stdout.strip()


def metric_value(port: int, name: str) -> int:
    fixture.check(port > 0, "cluster metrics listener is not configured")
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=3) as response:
        body = response.read().decode("utf-8", "strict")
    match = re.search(rf"^{re.escape(name)} ([0-9]+)$", body, re.MULTILINE)
    fixture.check(match is not None, f"cluster metric is missing: {name}")
    return int(match.group(1))


def subscriber_envelope(process: subprocess.Popen[bytes], timeout: float = 5) -> dict:
    assert process.stdout is not None
    ready, _, _ = select.select([process.stdout], [], [], timeout)
    fixture.check(bool(ready), "timed out observing a Redis cluster request")
    fixture.check(process.stdout.readline().strip() == b"message", "Redis event was not a message")
    process.stdout.readline()
    envelope = json.loads(process.stdout.readline())
    fixture.check(isinstance(envelope, dict), "Redis cluster envelope is not an object")
    fixture.check(isinstance(envelope.get("payload"), dict), "cluster envelope omitted its payload")
    return envelope


def subscriber_payload(process: subprocess.Popen[bytes], timeout: float = 5) -> dict:
    return subscriber_envelope(process, timeout)["payload"]


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def signed_ack_envelope(request: dict, payload: dict) -> str:
    fixture.check(bool(NODE_B_PRIVATE_KEY_DER), "node B signing fixture is missing")
    fixture.check(request.get("destination_node") == "node-b", "request is not addressed to node B")
    now = int(time.time())
    # serde_json::Value uses its deterministic map order in the Rust signer.
    # Re-materialize the nested payload in that same order before serializing
    # the fixed-order UnsignedEnvelope fields below.
    payload = json.loads(json.dumps(payload, separators=(",", ":"), sort_keys=True))
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    envelope = {
        "version": request["version"],
        "namespace": request["namespace"],
        "source_node": request["destination_node"],
        "destination_node": request["source_node"],
        "destination_connection_uuid": request["connection_uuid"],
        "destination_connection_epoch": request["connection_epoch"],
        "destination_key_id": request["key_id"],
        "destination_key_epoch": request["key_epoch"],
        "channel": f"northstar:{DOMAIN}:node:{request['source_node']}",
        "kind": "ack",
        "event_id": payload["request_id"],
        "request_id": payload["request_id"],
        "issued_at": now,
        "expires_at": now + 10,
        "payload_sha256": b64url(hashlib.sha256(payload_bytes).digest()),
        "key_id": request["destination_key_id"],
        "key_epoch": request["destination_key_epoch"],
        "connection_uuid": request["destination_connection_uuid"],
        "connection_epoch": request["destination_connection_epoch"],
        "payload": payload,
    }
    unsigned = json.dumps(envelope, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    signature = subprocess.run(
        [
            "openssl",
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            NODE_B_PRIVATE_KEY_DER,
            "-keyform",
            "DER",
        ],
        input=unsigned,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout
    envelope["signature"] = b64url(signature)
    return json.dumps(envelope, separators=(",", ":"), ensure_ascii=False)


def database_scalar(command: str) -> str:
    fixture.check(
        re.fullmatch(r"[a-z_][a-z0-9_]*", SCHEMA) is not None,
        "cluster PostgreSQL schema is missing or invalid",
    )
    environment = dict(os.environ)
    environment["PGPASSWORD"] = "xmpp-test-password"
    environment["PGOPTIONS"] = f"-c search_path={SCHEMA}"
    result = subprocess.run(
        [
            "psql",
            "--no-psqlrc",
            "--quiet",
            "--tuples-only",
            "--no-align",
            "--host",
            "127.0.0.1",
            "--username",
            "xmpp_test",
            "--dbname",
            "xmpp_test",
            "--set",
            "ON_ERROR_STOP=1",
            "--command",
            command,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        env=environment,
        text=True,
    )
    return result.stdout.strip()


def endpoint(http_port: int, xmpp_port: int) -> None:
    fixture.HTTP_HOST = "127.0.0.1"
    fixture.HTTP_PORT = http_port
    fixture.XMPP_PORT = xmpp_port
    fixture.DOMAIN = DOMAIN


def register(username: str) -> None:
    status, result = fixture.register_account(username, PASSWORD)
    fixture.check(status == 201, f"registration failed: {status} {result}")


def run() -> None:
    endpoint(HTTP_A, XMPP_A)
    fixture.wait_ready()
    register(ALICE)
    register(BOB)
    alice_a = fixture.XmppWebSocket(ALICE, PASSWORD, "alice-node-a")

    endpoint(HTTP_B, XMPP_B)
    fixture.wait_ready()
    duplicate = fixture.XmppWebSocket(
        ALICE,
        PASSWORD,
        "alice-node-a",
        expect_bind_conflict=True,
    )
    duplicate.close()
    bob_b = fixture.XmppWebSocket(BOB, PASSWORD, "bob-node-b")
    alice_b = fixture.XmppWebSocket(ALICE, PASSWORD, "alice-node-b")
    alice_b.send(
        "<iq xmlns='jabber:client' type='set' id='cluster-carbons'>"
        "<enable xmlns='urn:xmpp:carbons:2'/></iq>"
    )
    alice_b.receive_until("cluster-carbons")

    for client, request_id in (
        (alice_a, "alice-a-roster-interest"),
        (alice_b, "alice-b-roster-interest"),
        (bob_b, "bob-roster-interest"),
    ):
        client.send(
            f"<iq xmlns='jabber:client' type='get' id='{request_id}'>"
            "<query xmlns='jabber:iq:roster'/></iq>"
        )
        client.receive_until(request_id)

    alice_a.send(
        f"<presence xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='subscribe'/>"
    )
    cross_node_subscribe, _ = bob_b.receive_until("type='subscribe'")
    fixture.check(
        f"from='{ALICE}@{DOMAIN}'" in cross_node_subscribe,
        "presence subscription notification did not cross nodes",
    )
    bob_b.send(
        f"<presence xmlns='jabber:client' to='{ALICE}@{DOMAIN}' type='subscribed'/>"
    )
    cross_node_approval, _ = alice_a.receive_until("type='subscribed'")
    fixture.check(
        f"from='{BOB}@{DOMAIN}'" in cross_node_approval,
        "presence subscription approval did not cross nodes",
    )
    bob_b.send(
        "<presence xmlns='jabber:client'><status>CROSS-NODE-PROBE-STATE</status></presence>"
    )
    alice_a.receive_until("CROSS-NODE-PROBE-STATE")
    alice_a.send("<presence xmlns='jabber:client' type='unavailable'/>")
    alice_a.send("<presence xmlns='jabber:client'><status>ALICE-REAVAILABLE</status></presence>")
    replayed_presence, _ = alice_a.receive_until("CROSS-NODE-PROBE-STATE")
    fixture.check(
        f"from='{BOB}@{DOMAIN}/bob-node-b'" in replayed_presence,
        "initial-presence probe did not replay the remote node's exact resource state",
    )

    alice_a.send(
        f"<message xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='chat' id='cluster-message'>"
        "<body>cross-node message</body></message>"
    )
    routed, _ = bob_b.receive_until("cluster-message")
    fixture.check(
        "cross-node message" in routed and f"from='{ALICE}@{DOMAIN}/alice-node-a'" in routed,
        "cross-node direct message was not delivered",
    )
    carbon, _ = alice_b.receive_until("cluster-message")
    fixture.check(
        "urn:xmpp:carbons:2" in carbon and "<sent" in carbon,
        "cross-node sent carbon was not delivered",
    )

    # The outer sent-Carbon wrapper is self-addressed. The receiving node must
    # evaluate a resource-local privacy list against the forwarded message's
    # recipient instead; using the wrapper's `from` would make the deny rule
    # ineffective only when the other resource lives on a different node.
    alice_b.send(
        "<iq xmlns='jabber:client' type='set' id='cluster-sent-carbon-privacy-list'>"
        "<query xmlns='jabber:iq:privacy'><list name='cluster-deny-bob-carbon'>"
        f"<item type='jid' value='{BOB}@{DOMAIN}' action='deny' order='1'><message/></item>"
        "</list></query></iq>"
    )
    privacy_list, _ = alice_b.receive_until("cluster-sent-carbon-privacy-list")
    fixture.check("type='result'" in privacy_list, "cross-node Carbon privacy list failed")
    alice_b.send(
        "<iq xmlns='jabber:client' type='set' id='cluster-sent-carbon-privacy-active'>"
        "<query xmlns='jabber:iq:privacy'><active name='cluster-deny-bob-carbon'/></query></iq>"
    )
    privacy_active, _ = alice_b.receive_until("cluster-sent-carbon-privacy-active")
    fixture.check("type='result'" in privacy_active, "cross-node Carbon privacy activation failed")
    alice_a.send(
        f"<message xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='chat' "
        "id='cluster-sent-carbon-privacy-denied'>"
        "<body>cross-node private Carbon policy</body></message>"
    )
    routed, _ = bob_b.receive_until("cluster-sent-carbon-privacy-denied")
    fixture.check(
        "cross-node private Carbon policy" in routed,
        "the primary cross-node message was lost while filtering its sent Carbon",
    )
    denied_deadline = time.monotonic() + 1
    while time.monotonic() < denied_deadline:
        try:
            unexpected = alice_b.receive(max(0.05, denied_deadline - time.monotonic()))
        except (TimeoutError, socket.timeout):
            break
        fixture.check(
            "cluster-sent-carbon-privacy-denied" not in unexpected,
            f"cross-node sent Carbon bypassed the resource active privacy list: {unexpected}",
        )
    alice_b.send(
        "<iq xmlns='jabber:client' type='set' id='cluster-sent-carbon-privacy-clear'>"
        "<query xmlns='jabber:iq:privacy'><active/></query></iq>"
    )
    privacy_clear, _ = alice_b.receive_until("cluster-sent-carbon-privacy-clear")
    fixture.check("type='result'" in privacy_clear, "cross-node Carbon privacy reset failed")

    # A server stanza-id is an XEP-0359 identity, not evidence that an
    # offline row exists. Cross-node no-store must therefore remain volatile
    # even though the recipient delivery is annotated with such an ID.
    durable_before = metric_value(
        METRICS_B, "xmpp_online_queue_durable_acceptances_total"
    )
    volatile_before = metric_value(
        METRICS_B, "xmpp_online_queue_volatile_acceptances_total"
    )
    alice_a.send(
        f"<message xmlns='jabber:client' to='{BOB}@{DOMAIN}' type='chat' "
        "id='cluster-no-store-volatile'>"
        "<body>cross-node volatile delivery</body>"
        "<private xmlns='urn:xmpp:carbons:2'/>"
        "<no-store xmlns='urn:xmpp:hints'/></message>"
    )
    volatile_message, _ = bob_b.receive_until("cluster-no-store-volatile")
    fixture.check(
        "cross-node volatile delivery" in volatile_message,
        "cross-node no-store message was not delivered online",
    )
    fixture.check(
        offline_marker_count("cluster-no-store-volatile") == 0,
        "cross-node no-store message created a PostgreSQL spool row",
    )
    deadline = time.monotonic() + 7
    durable_after = durable_before
    volatile_after = volatile_before
    while time.monotonic() < deadline:
        durable_after = metric_value(
            METRICS_B, "xmpp_online_queue_durable_acceptances_total"
        )
        volatile_after = metric_value(
            METRICS_B, "xmpp_online_queue_volatile_acceptances_total"
        )
        if volatile_after > volatile_before:
            break
        time.sleep(0.25)
    fixture.check(
        durable_after == durable_before,
        "cross-node no-store message was counted as a durable queue acceptance",
    )
    fixture.check(
        volatile_after == volatile_before + 1,
        "cross-node no-store message was not counted exactly once as volatile; "
        f"before={volatile_before} after={volatile_after}",
    )

    alice_a.send(
        "<iq xmlns='jabber:client' type='set' id='cluster-roster'>"
        f"<query xmlns='jabber:iq:roster'><item jid='{BOB}@{DOMAIN}' name='Bob Cluster'/></query>"
        "</iq>"
    )
    alice_a.receive_until("cluster-roster")
    roster_push, _ = alice_b.receive_until("Bob Cluster")
    fixture.check(
        "jabber:iq:roster" in roster_push and " ver='" in roster_push,
        "versioned roster push did not cross nodes",
    )

    room = f"cluster-room@conference.{DOMAIN}"
    alice_a.send(
        f"<presence xmlns='jabber:client' to='{room}/Alice'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    alice_a.receive_until("code='110'")
    alice_a.send(
        f"<iq xmlns='jabber:client' type='set' id='cluster-instant-room' to='{room}'>"
        "<query xmlns='http://jabber.org/protocol/muc#owner'>"
        "<x xmlns='jabber:x:data' type='submit'/></query></iq>"
    )
    instant_room, _ = alice_a.receive_until("cluster-instant-room")
    fixture.check("type='result'" in instant_room, "cluster MUC could not become instant")
    bob_b.send(
        f"<presence xmlns='jabber:client' to='{room}/Bob'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    bob_self, bob_join_frames = bob_b.receive_until("code='110'")
    fixture.check(
        "role='participant'" in bob_self
        and any(f"from='{room}/Alice'" in frame for frame in bob_join_frames),
        "cross-node MUC join did not return the global occupant roster",
    )
    alice_join_notice, _ = alice_a.receive_until(f"from='{room}/Bob'")
    fixture.check(
        "type='unavailable'" not in alice_join_notice,
        "cross-node MUC join presence was not broadcast",
    )

    # Redis is a bounded, disposable MUC routing projection. Every live exact
    # occupant refresh must keep all three companion keys leased, while a
    # crashed node embedded in a still-active room must be pruned rather than
    # retained forever by the other node's sliding lease.
    muc_prefix = f"northstar:{DOMAIN}"
    occupants_key = f"{muc_prefix}:muc_occupants:{room}"
    owners_key = f"{muc_prefix}:muc_occupant_nodes:{room}"
    nodes_key = f"{muc_prefix}:muc_nodes:{room}"
    for key in (occupants_key, owners_key, nodes_key):
        ttl = int(redis_cli("ttl", key))
        fixture.check(
            1 <= ttl <= 300,
            f"live MUC soft-state key has no bounded sliding lease: {key} ttl={ttl}",
        )
    redis_cli("hset", occupants_key, "Ghost", "{}")
    redis_cli("hset", owners_key, "Ghost", "crashed-node")
    redis_cli("sadd", nodes_key, "crashed-node")
    bob_b.send(
        f"<message xmlns='jabber:client' to='{room}' type='groupchat' id='cluster-muc-prune'>"
        "<body>prune crashed Redis owner</body></message>"
    )
    alice_a.receive_until("cluster-muc-prune")
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if redis_cli("hexists", occupants_key, "Ghost") == "0":
            break
        time.sleep(0.05)
    fixture.check(
        redis_cli("hexists", occupants_key, "Ghost") == "0"
        and redis_cli("hexists", owners_key, "Ghost") == "0"
        and "crashed-node" not in redis_cli("smembers", nodes_key).splitlines(),
        "live room renewal retained a crashed-node MUC soft-state member",
    )

    cleanup_room = f"soft-state-cleanup@conference.{DOMAIN}"
    alice_b.send(
        f"<presence xmlns='jabber:client' to='{cleanup_room}/Only'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    alice_b.receive_until("code='110'")
    alice_b.send(
        f"<presence xmlns='jabber:client' to='{cleanup_room}/Only' type='unavailable'/>"
    )
    alice_b.receive_until(f"from='{cleanup_room}/Only'")
    cleanup_keys = (
        f"{muc_prefix}:muc_occupants:{cleanup_room}",
        f"{muc_prefix}:muc_occupant_nodes:{cleanup_room}",
        f"{muc_prefix}:muc_nodes:{cleanup_room}",
    )
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if all(redis_cli("exists", key) == "0" for key in cleanup_keys):
            break
        time.sleep(0.05)
    fixture.check(
        all(redis_cli("exists", key) == "0" for key in cleanup_keys),
        "last MUC occupant leave retained disposable Redis room keys",
    )

    # Owner configuration is PostgreSQL-authoritative, but every process
    # caches its own live occupants. Verify moderated voice, whois visibility
    # and members-only eviction change the remote node immediately rather
    # than only taking effect after a reconnect.
    policy_room = f"cluster-policy@conference.{DOMAIN}"
    alice_a.send(
        f"<presence xmlns='jabber:client' to='{policy_room}/Owner'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    alice_a.receive_until("code='110'")
    alice_a.send(
        f"<iq xmlns='jabber:client' type='set' id='cluster-policy-instant' to='{policy_room}'>"
        "<query xmlns='http://jabber.org/protocol/muc#owner'>"
        "<x xmlns='jabber:x:data' type='submit'/></query></iq>"
    )
    alice_a.receive_until("cluster-policy-instant")
    bob_b.send(
        f"<presence xmlns='jabber:client' to='{policy_room}/Remote'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    bob_b.receive_until("code='110'")
    alice_a.receive_until(f"from='{policy_room}/Remote'")
    alice_a.send(
        f"<iq xmlns='jabber:client' type='set' id='cluster-policy-moderated' to='{policy_room}'>"
        "<query xmlns='http://jabber.org/protocol/muc#owner'>"
        "<x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#roomconfig</value></field>"
        "<field var='muc#roomconfig_moderatedroom'><value>1</value></field>"
        "<field var='muc#roomconfig_whois'><value>moderators</value></field>"
        "</x></query></iq>"
    )
    alice_a.receive_until("cluster-policy-moderated")
    remote_demoted, _ = bob_b.receive_until("role='visitor'")
    fixture.check(
        f"from='{policy_room}/Remote'" in remote_demoted,
        "moderated room configuration did not update the remote-node occupant role",
    )
    bob_b.send(
        f"<message xmlns='jabber:client' to='{policy_room}' type='groupchat' id='cluster-policy-muted'>"
        "<body>must be rejected while visitor</body></message>"
    )
    muted, _ = bob_b.receive_until("cluster-policy-muted")
    fixture.check(
        "type='error'" in muted and "forbidden" in muted,
        "remote-node visitor retained voice after moderated configuration",
    )
    alice_a.send(
        f"<iq xmlns='jabber:client' type='set' id='cluster-policy-whois' to='{policy_room}'>"
        "<query xmlns='http://jabber.org/protocol/muc#owner'>"
        "<x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#roomconfig</value></field>"
        "<field var='muc#roomconfig_whois'><value>anyone</value></field>"
        "</x></query></iq>"
    )
    alice_a.receive_until("cluster-policy-whois")
    # The preceding moderated+whois=moderators update can leave an older
    # privacy-safe Owner presence queued behind Remote's role update.  Wait
    # for the newly disclosed real JID itself so asynchronous cross-node
    # delivery order cannot make that stale frame satisfy the assertion.
    disclosed, _ = bob_b.receive_until(f"jid='{ALICE}@{DOMAIN}/alice-node-a'")
    fixture.check(
        f"from='{policy_room}/Owner'" in disclosed,
        "non-anonymous room configuration did not update remote-node JID visibility",
    )
    alice_a.send(
        f"<iq xmlns='jabber:client' type='set' id='cluster-policy-members' to='{policy_room}'>"
        "<query xmlns='http://jabber.org/protocol/muc#owner'>"
        "<x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#roomconfig</value></field>"
        "<field var='muc#roomconfig_membersonly'><value>1</value></field>"
        "</x></query></iq>"
    )
    alice_a.receive_until("cluster-policy-members")
    evicted_by_policy, _ = bob_b.receive_until("code='322'")
    fixture.check(
        "type='unavailable'" in evicted_by_policy,
        "members-only configuration did not evict the remote-node non-member",
    )

    bob_b.send("<enable xmlns='urn:xmpp:sm:3' resume='true'/>")
    enabled, _ = bob_b.receive_until("<enabled ")
    resume_match = re.search(r"id='([^']+)'", enabled)
    fixture.check(
        resume_match is not None and "resume='true'" in enabled,
        "cluster MUC stream did not enable resumable SM",
    )
    resume_id = resume_match.group(1)
    bob_b.abort()
    endpoint(HTTP_B, XMPP_B)
    bob_b = fixture.XmppWebSocket(
        BOB,
        PASSWORD,
        "ignored-after-muc-resume",
        resume=(resume_id, 0),
    )
    bob_b.send(
        f"<message xmlns='jabber:client' to='{room}' type='groupchat' id='resumed-muc-send'>"
        "<body>SM connection ownership rebound</body></message>"
    )
    resumed_group, _ = alice_a.receive_until("resumed-muc-send")
    fixture.check(
        "SM connection ownership rebound" in resumed_group,
        "resumed MUC actor did not retain epoch with the new connection owner",
    )

    alice_b.send(
        f"<presence xmlns='jabber:client' to='{room}/Alice'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    collision, _ = alice_b.receive_until("type='error'")
    fixture.check(
        "conflict" in collision,
        "Redis MUC nickname reservation did not reject an exact duplicate",
    )

    bob_b.send(
        f"<message xmlns='jabber:client' to='{room}' type='groupchat' id='cluster-muc-message'>"
        "<body>cross-node group message</body></message>"
    )
    alice_group, _ = alice_a.receive_until("cluster-muc-message")
    fixture.check(
        f"from='{room}/Bob'" in alice_group and "cross-node group message" in alice_group,
        "cross-node MUC message was not broadcast",
    )

    alice_a.send(
        f"<iq xmlns='jabber:client' to='{room}' type='set' id='cluster-kick'>"
        "<query xmlns='http://jabber.org/protocol/muc#admin'>"
        "<item nick='Bob' role='none'><reason>runtime kick</reason></item>"
        "</query></iq>"
    )
    alice_a.receive_until("cluster-kick")
    kicked, _ = bob_b.receive_until("code='307'")
    fixture.check("type='unavailable'" in kicked, "remote kick was not acknowledged by owner node")
    bob_b.send(
        f"<message xmlns='jabber:client' to='{room}' type='groupchat' id='kicked-send'>"
        "<body>must not pass</body></message>"
    )
    rejected, _ = bob_b.receive_until("kicked-send")
    fixture.check("type='error'" in rejected, "kicked session retained MUC send authority")

    alice_b.send(
        f"<presence xmlns='jabber:client' to='{room}/Bob'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    alice_b.receive_until("code='110'")
    bob_b.close()
    alice_b.send(
        f"<message xmlns='jabber:client' to='{room}' type='groupchat' id='reused-nick-send'>"
        "<body>replacement survived old drop</body></message>"
    )
    replacement_message, _ = alice_a.receive_until("reused-nick-send")
    fixture.check(
        "replacement survived old drop" in replacement_message,
        "old kicked session Drop removed the reused nickname",
    )

    bob_b = fixture.XmppWebSocket(BOB, PASSWORD, "bob-node-b-rejoined")
    bob_b.send(
        f"<presence xmlns='jabber:client' to='{room}/Bob2'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    bob_b.receive_until("code='110'")
    alice_a.send(
        f"<iq xmlns='jabber:client' to='{room}' type='set' id='cluster-ban'>"
        "<query xmlns='http://jabber.org/protocol/muc#admin'>"
        f"<item jid='{BOB}@{DOMAIN}' affiliation='outcast'><reason>runtime ban</reason></item>"
        "</query></iq>"
    )
    alice_a.receive_until("cluster-ban")
    banned, _ = bob_b.receive_until("code='301'")
    fixture.check("type='unavailable'" in banned, "remote ban did not evict exact occupancy")
    bob_b.send(
        f"<message xmlns='jabber:client' to='{room}' type='groupchat' id='banned-send'>"
        "<body>must not pass after ban</body></message>"
    )
    ban_rejected, _ = bob_b.receive_until("banned-send")
    fixture.check("type='error'" in ban_rejected, "banned session retained MUC send authority")

    alice_a.send(
        f"<iq xmlns='jabber:client' to='{room}' type='set' id='cluster-destroy'>"
        "<query xmlns='http://jabber.org/protocol/muc#owner'>"
        "<destroy><reason>runtime destroy</reason></destroy>"
        "</query></iq>"
    )
    alice_a.receive_until("cluster-destroy")
    destroyed_remote, _ = alice_b.receive_until("<destroy")
    fixture.check(
        "type='unavailable'" in destroyed_remote,
        "room destroy did not revoke the exact remote occupancy",
    )

    # Recreate the same room/nickname after destroy. A delayed destroy control
    # must carry the previous occupancy identities and cannot match this join.
    alice_b.send(
        f"<presence xmlns='jabber:client' to='{room}/Bob'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    alice_b.receive_until("code='110'")
    alice_b.send(
        f"<message xmlns='jabber:client' to='{room}' type='groupchat' id='post-destroy-rejoin'>"
        "<body>new room epoch remains live</body></message>"
    )
    alice_b.receive_until("post-destroy-rejoin")

    # A real process termination must notify each locally-owned MUC occupant
    # with XEP-0045 status 332 before the transport is drained. This is wire
    # evidence, not merely a unit call of the shutdown helper.
    shutdown_room = f"shutdown-room@conference.{DOMAIN}"
    alice_a.send(
        f"<presence xmlns='jabber:client' to='{shutdown_room}/Alice'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    alice_a.receive_until("code='110'")
    alice_a.send(
        f"<iq xmlns='jabber:client' type='set' id='shutdown-room-instant' to='{shutdown_room}'>"
        "<query xmlns='http://jabber.org/protocol/muc#owner'>"
        "<x xmlns='jabber:x:data' type='submit'/></query></iq>"
    )
    alice_a.receive_until("shutdown-room-instant")
    server_a_pid = int(os.environ["NORTHSTAR_CLUSTER_PID_A"])
    os.kill(server_a_pid, signal.SIGTERM)
    # One connection can occupy several rooms; graceful shutdown emits 332
    # for each of them.  Select the dedicated fixture room instead of taking
    # whichever valid 332 happens to be queued first.
    shutdown_presence, _ = alice_a.receive_until(f"from='{shutdown_room}/Alice'")
    fixture.check(
        "type='unavailable'" in shutdown_presence
        and "code='332'" in shutdown_presence,
        f"graceful shutdown omitted XEP-0045 status 332: {shutdown_presence}",
    )

    alice_a.close()
    alice_b.close()
    bob_b.close()
    print(
        "cluster: Redis full-resource conflict/session routing, delivery acknowledgements, cross-node Carbons, "
        "subscription notifications, initial-presence replay, versioned roster pushes, global MUC roster, "
        "runtime room-policy synchronization, exact nickname reservation, broadcasts and shutdown 332 passed"
    )


def expect_no_frame(client: object, marker: str, timeout: float = 0.75) -> None:
    try:
        frame, _ = client.receive_until(marker, timeout=timeout)
    except (TimeoutError, socket.timeout):
        return
    raise AssertionError(
        f"unexpected cluster delivery was received for {marker}: {frame}"
    )


def run_faults() -> None:
    fixture.check(
        REDIS_PORT > 0
        and REDIS_PID > 0
        and REDIS_PASSWORD
        and REDIS_CA
        and REDIS_CERT
        and REDIS_KEY,
        "Redis TLS fault-injection environment is incomplete",
    )
    prefix = f"northstar:{DOMAIN}"
    endpoint(HTTP_A, XMPP_A)
    fixture.wait_ready()
    alice_a = fixture.XmppWebSocket(ALICE, PASSWORD, "fault-alice")
    alice_a.send("<enable xmlns='urn:xmpp:sm:3' resume='false'/>")
    sm_enabled, _ = alice_a.receive_until("<enabled ")
    fixture.check("urn:xmpp:sm:3" in sm_enabled, "fault sender could not enable SM")
    endpoint(HTTP_B, XMPP_B)
    fixture.wait_ready()
    bob_b = fixture.XmppWebSocket(BOB, PASSWORD, "fault-bob")
    bob_full = f"{BOB}@{DOMAIN}/fault-bob"
    bob_route = f"{prefix}:session:{bob_full}"
    bob_node = redis_cli("get", bob_route)
    fixture.check(bool(bob_node), "Bob's Redis session route is absent")
    bob_alive = f"{prefix}:node:{bob_node}:alive"
    bob_channel = f"{prefix}:node:{bob_node}"

    # Pause the real control plane beyond the Redis client's bounded response
    # timeout. HTTP remains independently healthy; the stanza is not routed
    # around Redis. A fresh request after SIGCONT proves pool and PubSub
    # recovery rather than relying on the stalled request completing later.
    os.kill(REDIS_PID, signal.SIGSTOP)
    try:
        time.sleep(0.25)
        for port in (HTTP_A, HTTP_B):
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/readyz", timeout=2) as response:
                fixture.check(response.status == 200, "node readiness failed during Redis pause")
        alice_a.send(
            f"<message xmlns='jabber:client' to='{bob_full}' type='normal' id='redis-pause-bounded'>"
            "<body>must not bypass the paused control plane</body>"
            # The fault assertion is about a stale Redis command executing
            # after recovery. Without no-store, normal/chat has a legitimate
            # PostgreSQL offline fallback and may be replayed with <delay/>.
            "<no-store xmlns='urn:xmpp:hints'/></message>"
        )
        rejected, _ = alice_a.receive_until("redis-pause-bounded", timeout=6)
        fixture.check(
            "type='error'" in rejected and "service-unavailable" in rejected,
            f"paused Redis no-store route did not fail explicitly: {rejected}",
        )
        # Do not use a wall-clock sleep from the client's socket write: message
        # admission and archive work happen before Redis routing, so that
        # creates a load-dependent race. An XEP-0198 request is processed in
        # stream order and becomes the deterministic barrier proving the
        # message handler itself completed while Redis remained paused.
        alice_a.send("<r xmlns='urn:xmpp:sm:3'/>")
        handled, _ = alice_a.receive_until("<a ", timeout=6)
        fixture.check(
            "urn:xmpp:sm:3" in handled,
            "server did not finish the paused-Redis stanza within its bounded timeout",
        )
        fixture.check(
            offline_marker_count("redis-pause-bounded") == 0,
            "no-store fault marker entered the PostgreSQL offline queue",
        )

        # Preserve the complementary production behavior: ordinary chat is
        # durably accepted into PostgreSQL when the Redis route is unavailable.
        # Reconnecting Bob after recovery below must replay it with XEP-0203.
        alice_a.send(
            f"<message xmlns='jabber:client' to='{bob_full}' type='chat' "
            "id='redis-pause-offline-fallback'>"
            "<body>durable offline fallback while Redis is paused</body></message>"
        )
        alice_a.send("<r xmlns='urn:xmpp:sm:3'/>")
        fallback_handled, _ = alice_a.receive_until("<a ", timeout=6)
        fixture.check(
            "urn:xmpp:sm:3" in fallback_handled,
            "ordinary fallback message did not finish while Redis remained paused",
        )
        fallback_rows = offline_marker_count("redis-pause-offline-fallback")
        fixture.check(
            fallback_rows == 1,
            "ordinary chat was not durably queued exactly once during the Redis outage; "
            f"matching_rows={fallback_rows}; account_rows={offline_account_snapshot(BOB)!r}",
        )
    finally:
        os.kill(REDIS_PID, signal.SIGCONT)
    expect_no_frame(bob_b, "redis-pause-bounded")
    fixture.check(
        offline_marker_count("redis-pause-offline-fallback") == 1,
        "durable Redis-outage fallback disappeared before reconnect replay",
    )
    bob_b.close()
    time.sleep(0.5)
    bob_b = fixture.XmppWebSocket(BOB, PASSWORD, "fault-bob")
    fallback, _ = bob_b.receive_until("redis-pause-offline-fallback", timeout=10)
    fixture.check(
        "urn:xmpp:delay" in fallback
        and "durable offline fallback while Redis is paused" in fallback,
        f"Redis-outage fallback was not replayed as delayed offline content: {fallback}",
    )
    deadline = time.monotonic() + 5
    while (
        time.monotonic() < deadline
        and offline_marker_count("redis-pause-offline-fallback") != 0
    ):
        time.sleep(0.1)
    fixture.check(
        offline_marker_count("redis-pause-offline-fallback") == 0,
        "offline replay did not acknowledge and delete the durable fallback row",
    )
    time.sleep(0.25)
    alice_a.send(
        f"<message xmlns='jabber:client' to='{bob_full}' type='chat' id='redis-pause-recovery'>"
        "<body>fresh route after Redis resumes</body></message>"
    )
    recovered, _ = bob_b.receive_until("redis-pause-recovery", timeout=10)
    fixture.check(
        "fresh route after Redis resumes" in recovered,
        "cluster route did not recover after Redis SIGCONT",
    )

    # A hostile/buggy trusted broker publisher cannot make the listener parse
    # an unbounded body. The subsequent authenticated route proves liveness.
    authentication_failures_before = metric_value(
        METRICS_B, "xmpp_cluster_authentication_failures_total"
    )
    redis_cli("-x", "publish", bob_channel, input_bytes=b"x" * (2 * 1024 * 1024 + 1))
    deadline = time.monotonic() + 3
    while (
        time.monotonic() < deadline
        and metric_value(METRICS_B, "xmpp_cluster_authentication_failures_total")
        <= authentication_failures_before
    ):
        time.sleep(0.05)
    fixture.check(
        metric_value(METRICS_B, "xmpp_cluster_authentication_failures_total")
        > authentication_failures_before,
        "node B did not reject the oversized Redis envelope",
    )
    alice_a.send(
        f"<message xmlns='jabber:client' to='{bob_full}' type='chat' id='after-oversize'>"
        "<body>listener remains live</body></message>"
    )
    bob_b.receive_until("after-oversize")

    # Mixed application versions fail closed in both directions. Presence
    # replay now carries UUID/generation authority which a v9 process would
    # ignore, so a v10 sender must never publish executable traffic to it.
    redis_cli("set", bob_alive, "11", "EX", "90")
    alice_a.send(
        f"<message xmlns='jabber:client' to='{bob_full}' type='chat' id='newer-peer-version'>"
        "<body>unknown peer contract must fail</body>"
        "<no-store xmlns='urn:xmpp:hints'/></message>"
    )
    newer_rejected, _ = alice_a.receive_until("newer-peer-version", timeout=6)
    fixture.check(
        "type='error'" in newer_rejected and "service-unavailable" in newer_rejected,
        f"unknown newer cluster delivery contract did not fail closed: {newer_rejected}",
    )
    expect_no_frame(bob_b, "newer-peer-version")
    redis_cli("set", bob_alive, "9", "EX", "90")
    alice_a.send(
        f"<message xmlns='jabber:client' to='{bob_full}' type='chat' id='legacy-peer-version'>"
        "<body>peer version 9</body></message>"
    )
    legacy_rejected, _ = alice_a.receive_until("legacy-peer-version", timeout=6)
    fixture.check(
        "type='error'" in legacy_rejected and "service-unavailable" in legacy_rejected,
        f"older cluster application version did not fail closed: {legacy_rejected}",
    )
    expect_no_frame(bob_b, "legacy-peer-version")
    redis_cli("set", bob_alive, "10", "EX", "90")

    # Claim a dedicated nonexistent full resource through the real
    # PostgreSQL process/connection authority, then pause node B so the test
    # harness is the only actor producing acknowledgements.  This exercises
    # the production fixed node channel and signed reverse envelope instead
    # of the removed per-request ACK channel or an unauthoritative Redis key.
    fixture.check(
        PID_B > 0 and NODE_B_PRIVATE_KEY_DER,
        "node B process/signing fault fixture is incomplete",
    )
    fake_node = "node-b"
    fake_channel = f"{prefix}:node:{fake_node}"
    fake_full = f"{BOB}@{DOMAIN}/fake-ack-target"
    fake_connection = str(uuid.uuid4())
    node_b_authority = database_scalar(
        "SELECT instance_uuid::TEXT || '|' || instance_epoch::TEXT "
        "FROM cluster_node_instances "
        "WHERE xmpp_domain='cluster.localhost' AND node_id='node-b' "
        "AND lease_until>clock_timestamp() "
        "ORDER BY lease_until DESC LIMIT 1"
    )
    fixture.check("|" in node_b_authority, "node B PostgreSQL authority is absent")
    node_b_instance, node_b_epoch = node_b_authority.split("|", 1)

    # EXECUTE on the route capability is not enough to invent a connection.
    # It must first prove the exact live-session lease (or one of the two
    # bounded publication claims).  This negative probe is intentionally made
    # before the test fixture installs its exact lease.
    unbacked_connection = str(uuid.uuid4())
    authority_rejected = database_scalar(
        "DO $cluster_route_negative$ DECLARE rejected BOOLEAN:=FALSE; BEGIN "
        "BEGIN PERFORM northstar_claim_cluster_session_route("
        f"'{DOMAIN}','{fake_full}','{BOB}@{DOMAIN}','node-b',"
        f"'{node_b_instance}'::UUID,{int(node_b_epoch)},"
        f"'{unbacked_connection}'::UUID,NULL::UUID,NULL::UUID,900); "
        "EXCEPTION WHEN SQLSTATE '55000' THEN rejected:=TRUE; END; "
        "IF NOT rejected THEN RAISE EXCEPTION "
        "'unbacked cluster route was accepted' USING ERRCODE='P0001'; END IF; "
        "END $cluster_route_negative$; SELECT 'rejected'"
    )
    fixture.check(
        authority_rejected == "rejected",
        f"unbacked cluster route negative probe did not complete: {authority_rejected}",
    )
    installed_lease = database_scalar(
        "INSERT INTO deployment_session_leases("
        "lease_id,connection_id,user_id,full_jid,lease_until) "
        f"SELECT '{fake_connection}'::UUID,'{fake_connection}'::UUID,id,"
        f"'{fake_full}',clock_timestamp()+INTERVAL '15 minutes' "
        f"FROM users WHERE username='{BOB}' "
        "RETURNING connection_id::TEXT"
    )
    fixture.check(
        installed_lease == fake_connection,
        f"fake exact live-session lease was not installed: {installed_lease}",
    )
    claim = database_scalar(
        "SELECT northstar_claim_cluster_session_route("
        f"'{DOMAIN}','{fake_full}','{BOB}@{DOMAIN}','node-b',"
        f"'{node_b_instance}'::UUID,{int(node_b_epoch)},"
        f"'{fake_connection}'::UUID,NULL::UUID,NULL::UUID,900)"
    )
    fixture.check(claim == "claimed", f"fake exact route claim failed: {claim}")
    subscriber = redis_subscriber(fake_channel)
    os.kill(PID_B, signal.SIGSTOP)
    try:
        alice_a.send(
            f"<message xmlns='jabber:client' to='{fake_full}' type='normal' id='forged-ack'>"
            "<body>must not reach the live resource</body>"
            "<no-store xmlns='urn:xmpp:hints'/></message>"
        )
        request_envelope = subscriber_envelope(subscriber)
        request = request_envelope["payload"]
        fixture.check(
            request.get("protocol_version") == "10"
            and request.get("delivery") == {"reliability": "volatile"},
            f"cluster no-store envelope omitted its volatile v10 contract: {request}",
        )
        request_id = request["request_id"]
        nonce = request["ack_nonce"]
        ack_channel = f"{prefix}:node:{request_envelope['source_node']}"
        invalid_acks = (
            {
                "request_id": "stale-request",
                "nonce": nonce,
                "node_id": fake_node,
                "delivered": 1,
                "accepted_full_jid": fake_full,
                "delivery": request["delivery"],
            },
            {
                "request_id": request_id,
                "nonce": "wrong-nonce",
                "node_id": fake_node,
                "delivered": 1,
                "accepted_full_jid": fake_full,
                "delivery": request["delivery"],
            },
            {
                "request_id": request_id,
                "nonce": nonce,
                "node_id": "wrong-node",
                "delivered": 1,
                "accepted_full_jid": fake_full,
                "delivery": request["delivery"],
            },
        )
        for ack in invalid_acks:
            redis_cli(
                "publish",
                ack_channel,
                signed_ack_envelope(request_envelope, ack),
            )
        oversized_ack = dict(invalid_acks[-1])
        oversized_ack["request_id"] = str(uuid.uuid4())
        oversized_ack["padding"] = "x" * 4097
        redis_cli(
            "publish",
            ack_channel,
            signed_ack_envelope(request_envelope, oversized_ack),
        )
        rejected, _ = alice_a.receive_until("forged-ack", timeout=5)
        fixture.check(
            "type='error'" in rejected and "service-unavailable" in rejected,
            f"invalid cluster ACKs did not fail the exact route: {rejected}",
        )
        expect_no_frame(bob_b, "forged-ack")
        deadline = time.monotonic() + 40
        node_a_ready = False
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{HTTP_A}/readyz", timeout=2
                ) as response:
                    node_a_ready = response.status == 200
            except (OSError, urllib.error.URLError):
                node_a_ready = False
            if node_a_ready:
                break
            time.sleep(0.25)
        fixture.check(
            node_a_ready,
            "node A did not rotate/reconcile after the invalid ACK timeout",
        )

        # A valid negative ACK is deliberately duplicated. It can end the
        # request once, but it cannot manufacture a positive delivery.
        alice_a.send(
            f"<message xmlns='jabber:client' to='{fake_full}' type='normal' id='duplicate-ack'>"
            "<body>duplicate negative acknowledgement</body>"
            "<no-store xmlns='urn:xmpp:hints'/></message>"
        )
        duplicate_envelope = subscriber_envelope(subscriber)
        duplicate_request = duplicate_envelope["payload"]
        negative_ack = {
            "request_id": duplicate_request["request_id"],
            "nonce": duplicate_request["ack_nonce"],
            "node_id": fake_node,
            "delivered": 0,
            "accepted_full_jid": None,
            "delivery": duplicate_request["delivery"],
        }
        duplicate_channel = f"{prefix}:node:{duplicate_envelope['source_node']}"
        signed_negative = signed_ack_envelope(duplicate_envelope, negative_ack)
        redis_cli("publish", duplicate_channel, signed_negative)
        redis_cli("publish", duplicate_channel, signed_negative)
        duplicate_rejected, _ = alice_a.receive_until("duplicate-ack", timeout=5)
        fixture.check(
            "type='error'" in duplicate_rejected
            and "service-unavailable" in duplicate_rejected,
            f"duplicate negative ACK did not fail the exact route: {duplicate_rejected}",
        )
        expect_no_frame(bob_b, "duplicate-ack")
    finally:
        database_scalar(
            "SELECT northstar_release_cluster_session_route("
            f"'{DOMAIN}','{fake_full}','node-b','{node_b_instance}'::UUID,"
            f"{int(node_b_epoch)},'{fake_connection}'::UUID)"
        )
        database_scalar(
            "DELETE FROM deployment_session_leases "
            f"WHERE connection_id='{fake_connection}'::UUID"
        )
        os.kill(PID_B, signal.SIGCONT)
        subscriber.terminate()
        subscriber.wait(timeout=5)

    alice_a.send(
        f"<message xmlns='jabber:client' to='{bob_full}' type='chat' id='after-forged-acks'>"
        "<body>real correlated acknowledgement restored</body></message>"
    )
    bob_b.receive_until("after-forged-acks")

    # Kill node A without cleanup and wait for both its PostgreSQL process
    # authority and disposable Redis lease to expire naturally.  The same
    # exact resource must then be claimable on node B.  The test deliberately
    # does not edit either authority, so it covers the production ABA fence.
    endpoint(HTTP_A, XMPP_A)
    takeover_a = fixture.XmppWebSocket(ALICE, PASSWORD, "ttl-takeover")
    takeover_full = f"{ALICE}@{DOMAIN}/ttl-takeover"
    takeover_route = f"{prefix}:session:{takeover_full}"
    takeover_owner = redis_cli("get", takeover_route)
    fixture.check(bool(takeover_owner), "takeover route was not registered on node A")
    os.kill(int(os.environ["NORTHSTAR_CLUSTER_PID_A"]), signal.SIGKILL)
    takeover_alive = f"{prefix}:node:{takeover_owner}:alive"
    original_ttl = int(redis_cli("ttl", takeover_alive))
    fixture.check(original_ttl > 1, "crashed node did not have a real liveness TTL")
    deadline = time.monotonic() + 105
    while time.monotonic() < deadline and redis_cli("exists", takeover_alive) != "0":
        time.sleep(0.1)
    fixture.check(
        redis_cli("exists", takeover_alive) == "0",
        "crashed node liveness lease did not expire within its production TTL",
    )
    endpoint(HTTP_B, XMPP_B)
    takeover_b = fixture.XmppWebSocket(ALICE, PASSWORD, "ttl-takeover")
    takeover_b.close()
    takeover_a.abort()
    alice_a.abort()
    bob_b.close()
    print(
        "cluster faults: rediss pool/PubSub SIGSTOP recovery, oversized payload rejection, "
        "version skew, stale/wrong/oversized/duplicate ACK handling, and SIGKILL TTL takeover passed"
    )


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "faults":
        run_faults()
    else:
        run()
