#!/usr/bin/env python3
"""Focused message-PoW crash/replay wire validation for an isolated server."""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import time


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "northstar_integration_helpers", SCRIPT_DIR / "integration-wsl.py"
)
assert SPEC is not None and SPEC.loader is not None
helpers = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helpers)

STATE_FILE = pathlib.Path(os.environ["XMPP_TEST_MESSAGE_POW_STATE"])
DB_HOST = os.environ.get("XMPP_TEST_DB_HOST", "127.0.0.1")
DB_NAME = os.environ.get("XMPP_TEST_DATABASE", "xmpp_test")
DB_USER = os.environ.get("XMPP_TEST_DB_USER", "xmpp_test")
PASSWORD = "message-pow-wire-password-123"


def psql(sql: str) -> str:
    environment = os.environ.copy()
    environment["PGPASSWORD"] = os.environ.get(
        "XMPP_TEST_DB_PASSWORD", "xmpp-test-password"
    )
    completed = subprocess.run(
        [
            "psql",
            "--host",
            DB_HOST,
            "--username",
            DB_USER,
            "--dbname",
            DB_NAME,
            "--tuples-only",
            "--no-align",
            "--set",
            "ON_ERROR_STOP=1",
            "--command",
            sql,
        ],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"psql failed with status {completed.returncode}: {completed.stderr.strip()}"
        )
    return completed.stdout.strip()


def sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def no_matching_frame(client, marker: str, timeout: float = 0.75) -> None:
    deadline = time.monotonic() + timeout
    frames: list[str] = []
    while time.monotonic() < deadline:
        try:
            frame = client.receive(max(0.05, deadline - time.monotonic()))
        except (TimeoutError, OSError):
            break
        frames.append(frame)
        helpers.check(marker not in frame, f"duplicate message escaped replay guard: {frames}")


def login_token(username: str) -> str:
    status, result = helpers.api(
        "POST", "/api/v1/login", {"username": username, "password": PASSWORD}
    )
    helpers.check(status == 200 and result.get("token"), f"login failed: {status} {result}")
    return result["token"]


def register(username: str) -> None:
    request = {
        "username": username,
        "password": PASSWORD,
        "invitation_token": None,
    }
    proof = helpers.solve_pow(
        None,
        "registration",
        helpers.pow_intent("POST", "/api/v1/register", request),
    )
    status, result = helpers.api(
        "POST",
        "/api/v1/register",
        {**request, "pow": proof},
    )
    helpers.check(status == 201, f"registration failed: {username}: {status} {result}")


def stanza(
    recipient: str,
    stanza_id: str,
    origin: str,
    marker: str,
    *,
    no_permanent_store: bool = False,
) -> str:
    hint = (
        "<no-permanent-store xmlns='urn:xmpp:hints'/>"
        if no_permanent_store
        else "<store xmlns='urn:xmpp:hints'/>"
    )
    return (
        f"<message xmlns='jabber:client' to='{recipient}' type='chat' id='{stanza_id}'>"
        f"<body>{marker}</body>{hint}"
        f"<origin-id xmlns='urn:xmpp:sid:0' id='{origin}'/></message>"
    )


def prepare() -> None:
    helpers.wait_ready()
    run_id = os.environ["XMPP_TEST_RUN_ID"]
    alice_name = f"powalice{run_id[:10]}"
    bob_name = f"powbob{run_id[:10]}"
    register(alice_name)
    register(bob_name)
    token = login_token(alice_name)
    alice = helpers.XmppWebSocket(alice_name, PASSWORD, "pow-wire-alice")
    bob = helpers.XmppWebSocket(bob_name, PASSWORD, "pow-wire-bob")
    alice_jid = f"{alice_name}@{helpers.DOMAIN}"
    bob_jid = f"{bob_name}@{helpers.DOMAIN}"

    accepted_marker = f"POW-ACCEPTED-{run_id}"
    accepted_origin = f"pow-accepted-{run_id}"
    accepted = stanza(
        bob_jid,
        f"accepted-{run_id}",
        accepted_origin,
        accepted_marker,
    )
    alice.send_with_pow(accepted, token)
    delivered, _ = bob.receive_until(accepted_marker)
    helpers.check(accepted_origin in delivered, f"accepted message lost origin-id: {delivered}")
    alice.send_with_pow(accepted, token)
    no_matching_frame(bob, accepted_marker)

    changed = stanza(
        bob_jid,
        f"accepted-changed-{run_id}",
        accepted_origin,
        f"{accepted_marker}-CHANGED",
    )
    alice.send_with_pow(changed, token)
    conflict, _ = alice.receive_until(f"accepted-changed-{run_id}")
    helpers.check(
        "type='error'" in conflict and "<conflict" in conflict,
        f"same origin-id with changed payload was not rejected: {conflict}",
    )
    no_matching_frame(bob, f"{accepted_marker}-CHANGED")

    remote_marker = f"POW-OUTBOX-{run_id}"
    remote_origin = f"pow-outbox-{run_id}"
    remote = stanza(
        "nobody@pow-wire.invalid",
        f"outbox-{run_id}",
        remote_origin,
        remote_marker,
    )
    alice.send_with_pow(remote, token)
    time.sleep(0.25)
    helpers.check(
        psql(
            "SELECT COUNT(*) FROM s2s_outbox WHERE stanza LIKE "
            + sql_literal(f"%{remote_marker}%")
        )
        == "1",
        "remote message did not create exactly one durable outbox row",
    )
    alice.send_with_pow(remote, token)
    time.sleep(0.25)
    helpers.check(
        psql(
            "SELECT COUNT(*) FROM s2s_outbox WHERE stanza LIKE "
            + sql_literal(f"%{remote_marker}%")
        )
        == "1",
        "exact remote replay duplicated the durable outbox row",
    )
    remote_changed = stanza(
        "nobody@pow-wire.invalid",
        f"outbox-changed-{run_id}",
        remote_origin,
        f"{remote_marker}-CHANGED",
    )
    alice.send_with_pow(remote_changed, token)
    conflict, _ = alice.receive_until(f"outbox-changed-{run_id}")
    helpers.check(
        "type='error'" in conflict and "<conflict" in conflict,
        f"changed remote replay was not a conflict: {conflict}",
    )
    helpers.check(
        psql(
            "SELECT COUNT(*) FROM s2s_outbox WHERE stanza LIKE "
            + sql_literal(f"%{remote_marker}%")
        )
        == "1",
        "remote conflict changed outbox cardinality",
    )

    bob.close()
    temporary_marker = f"POW-TEMPORARY-{run_id}"
    temporary_origin = f"pow-temporary-{run_id}"
    temporary = stanza(
        bob_jid,
        f"temporary-{run_id}",
        temporary_origin,
        temporary_marker,
        no_permanent_store=True,
    )
    alice.send_with_pow(temporary, token)
    time.sleep(0.25)
    helpers.check(
        psql(
            "SELECT COUNT(*) FROM offline_messages WHERE stanza LIKE "
            + sql_literal(f"%{temporary_marker}%")
        )
        == "1",
        "no-permanent-store message was not temporarily recoverable",
    )
    helpers.check(
        psql(
            "SELECT COUNT(*) FROM message_archive WHERE stanza LIKE "
            + sql_literal(f"%{temporary_marker}%")
        )
        == "0",
        "no-permanent-store message leaked into MAM",
    )
    bob = helpers.XmppWebSocket(bob_name, PASSWORD, "pow-wire-bob-temporary")
    bob.receive_until(temporary_marker)
    bob.close()
    time.sleep(0.25)
    helpers.check(
        psql(
            "SELECT COUNT(*) FROM offline_messages WHERE stanza LIKE "
            + sql_literal(f"%{temporary_marker}%")
        )
        == "0",
        "temporary content row survived acknowledged delivery",
    )
    grace = float(
        psql(
            "SELECT EXTRACT(EPOCH FROM (expires_at-clock_timestamp()))::float8 "
            "FROM offline_message_admissions WHERE offline_message_id IS NULL "
            "ORDER BY created_at DESC LIMIT 1"
        )
    )
    helpers.check(
        30 * 86_400 - 30 <= grace <= 30 * 86_400,
        f"delivered tombstone grace was not bounded to 30 days: {grace}",
    )
    # Remove only the newest accepted anti-abuse marker, then prove the
    # independent offline tombstone still suppresses an exact late retry.
    psql(
        "DELETE FROM abuse_message_admissions WHERE admission_key=("
        "SELECT admission_key FROM abuse_message_admissions "
        "WHERE actor_id=(SELECT id FROM users WHERE username="
        + sql_literal(alice_name)
        + ") AND state='accepted' ORDER BY accepted_at DESC LIMIT 1)"
    )
    alice.send_with_pow(temporary, token)
    time.sleep(0.25)
    helpers.check(
        psql(
            "SELECT COUNT(*) FROM offline_messages WHERE stanza LIKE "
            + sql_literal(f"%{temporary_marker}%")
        )
        == "0",
        "late exact retry escaped the delivered offline tombstone",
    )
    helpers.check(
        psql(
            "SELECT COUNT(*) FROM message_archive WHERE stanza LIKE "
            + sql_literal(f"%{temporary_marker}%")
        )
        == "0",
        "late no-permanent-store retry leaked into MAM",
    )

    # Materialize a realistic post-admission/pre-route crash cut without any
    # client observing the stanza: remove the temporary queue side effect and
    # restore the newest admission to an expired pending fencing lease.
    crash_marker = f"POW-CRASH-RESUME-{run_id}"
    crash_origin = f"pow-crash-resume-{run_id}"
    crash = stanza(
        bob_jid,
        f"crash-{run_id}",
        crash_origin,
        crash_marker,
        no_permanent_store=True,
    )
    alice.send_with_pow(crash, token)
    time.sleep(0.25)
    helpers.check(
        psql(
            "SELECT COUNT(*) FROM offline_messages WHERE stanza LIKE "
            + sql_literal(f"%{crash_marker}%")
        )
        == "1",
        "crash fixture did not reach durable temporary storage",
    )
    psql(
        "DELETE FROM offline_message_admissions WHERE offline_message_id IN ("
        "SELECT id FROM offline_messages WHERE stanza LIKE "
        + sql_literal(f"%{crash_marker}%")
        + "); DELETE FROM offline_messages WHERE stanza LIKE "
        + sql_literal(f"%{crash_marker}%")
        + "; UPDATE abuse_message_admissions SET state='pending',accepted_at=NULL,"
        "lease_expires_at=GREATEST(created_at,clock_timestamp()-INTERVAL '1 millisecond'),"
        "expires_at=clock_timestamp()+INTERVAL '20 minutes' WHERE admission_key=("
        "SELECT admission_key FROM abuse_message_admissions WHERE actor_id=("
        "SELECT id FROM users WHERE username="
        + sql_literal(alice_name)
        + ") AND state='accepted' ORDER BY accepted_at DESC LIMIT 1);"
    )
    helpers.check(
        psql(
            "SELECT COUNT(*) FROM abuse_message_admissions WHERE actor_id=("
            "SELECT id FROM users WHERE username="
            + sql_literal(alice_name)
            + ") AND state='pending' AND lease_expires_at < clock_timestamp()"
        )
        == "1",
        "crash fixture did not leave one resumable pending admission",
    )

    alice.close()
    STATE_FILE.write_text(
        json.dumps(
            {
                "alice": alice_name,
                "bob": bob_name,
                "accepted_marker": accepted_marker,
                "accepted_origin": accepted_origin,
                "accepted_stanza": accepted,
                "remote_marker": remote_marker,
                "crash_marker": crash_marker,
                "crash_origin": crash_origin,
                "crash_stanza": crash,
            }
        ),
        encoding="utf-8",
    )
    print("message PoW wire prepare phase passed")


def verify() -> None:
    helpers.wait_ready()
    state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    token = login_token(state["alice"])
    alice = helpers.XmppWebSocket(state["alice"], PASSWORD, "pow-wire-alice-restart")
    bob = helpers.XmppWebSocket(state["bob"], PASSWORD, "pow-wire-bob-restart")

    alice.send_with_pow(state["accepted_stanza"], token)
    no_matching_frame(bob, state["accepted_marker"])
    alice.send_with_pow(state["crash_stanza"], token)
    resumed, _ = bob.receive_until(state["crash_marker"])
    helpers.check(
        state["crash_origin"] in resumed,
        f"resumed message lost stable origin identity: {resumed}",
    )
    alice.send_with_pow(state["crash_stanza"], token)
    no_matching_frame(bob, state["crash_marker"])
    helpers.check(
        psql(
            "SELECT COUNT(*) FROM abuse_message_admissions WHERE actor_id=("
            "SELECT id FROM users WHERE username="
            + sql_literal(state["alice"])
            + ") AND state='pending'"
        )
        == "0",
        "crash-resumed admission did not become terminal",
    )
    helpers.check(
        psql(
            "SELECT COUNT(*) FROM s2s_outbox WHERE stanza LIKE "
            + sql_literal(f"%{state['remote_marker']}%")
        )
        == "1",
        "durable outbox cardinality changed across process restart",
    )
    alice.close()
    bob.close()
    print("message PoW exact replay/conflict/crash-resume/restart wire phase passed")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in {"prepare", "verify"}:
        raise SystemExit("usage: message-pow-wire-wsl.py prepare|verify")
    prepare() if sys.argv[1] == "prepare" else verify()
