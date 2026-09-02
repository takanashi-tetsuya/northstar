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
from collections.abc import Callable


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


def wait_for_sql(
    sql: str,
    accepted: Callable[[str], bool],
    label: str,
    timeout: float = 10.0,
) -> str:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        last = psql(sql)
        if accepted(last):
            return last
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {label}; last database value={last!r}")


def ordering_barrier(client, barrier_id: str) -> None:
    client.send(
        f"<iq xmlns='jabber:client' type='get' id='{barrier_id}'>"
        "<ping xmlns='urn:xmpp:ping'/></iq>"
    )
    result, _ = client.receive_until(barrier_id)
    helpers.check(
        "type='result'" in result,
        f"message ordering barrier failed: {result}",
    )


def wait_for_abuse_admission(
    username: str, challenge_id: str, expected_state: str
) -> str:
    query = (
        "SELECT encode(admission_key,'hex') || '|' || state || '|' || "
        "(accepted_at IS NOT NULL)::text FROM abuse_message_admissions "
        "WHERE actor_id=(SELECT id FROM users WHERE username="
        + sql_literal(username)
        + ") AND proof_challenge_id="
        + sql_literal(challenge_id)
        + "::pg_catalog.uuid"
    )
    expected_suffix = (
        "|accepted|true" if expected_state == "accepted" else "|pending|false"
    )
    value = wait_for_sql(
        query,
        lambda result: len(result.splitlines()) == 1
        and result.endswith(expected_suffix),
        f"exact {expected_state} abuse admission for challenge {challenge_id}",
    )
    key, state, accepted_at = value.split("|")
    helpers.check(
        len(key) == 64
        and state == expected_state
        and accepted_at == ("true" if expected_state == "accepted" else "false"),
        f"malformed exact abuse admission: {value}",
    )
    return key


def wait_for_personal_delivery_projection(
    actor_jid: str, target_jid: str, origin_id: str
) -> tuple[str, str]:
    query = (
        "SELECT admission.id::text || '|' || delivery.id::text "
        "FROM personal_message_admissions AS admission "
        "JOIN offline_messages AS delivery ON delivery.id=admission.offline_message_id "
        "WHERE admission.identity_kind='local-origin' AND admission.actor_scope="
        + sql_literal(actor_jid)
        + " AND admission.target_scope="
        + sql_literal(target_jid)
        + " AND admission.identity_value="
        + sql_literal(origin_id)
        + " AND admission.sender_archive_id IS NULL "
        "AND admission.recipient_archive_id IS NULL "
        "AND admission.s2s_outbox_id IS NULL "
        "AND admission.delivery_completed_at IS NULL"
    )
    value = wait_for_sql(
        query,
        lambda result: len(result.splitlines()) == 1 and result.count("|") == 1,
        f"personal C2S projection for {origin_id}",
    )
    return tuple(value.split("|", 1))


def wait_for_personal_tombstone(
    actor_jid: str, target_jid: str, origin_id: str
) -> tuple[str, str, float]:
    query = (
        "SELECT id::text || '|' || delivery_completed_at::text || '|' || "
        "EXTRACT(EPOCH FROM ((delivery_completed_at + INTERVAL '30 days')"
        "-clock_timestamp()))::float8::text FROM personal_message_admissions "
        "WHERE identity_kind='local-origin' AND actor_scope="
        + sql_literal(actor_jid)
        + " AND target_scope="
        + sql_literal(target_jid)
        + " AND identity_value="
        + sql_literal(origin_id)
        + " AND sender_archive_id IS NULL AND recipient_archive_id IS NULL "
        "AND offline_message_id IS NULL AND s2s_outbox_id IS NULL "
        "AND delivery_completed_at IS NOT NULL"
    )
    value = wait_for_sql(
        query,
        lambda result: len(result.splitlines()) == 1 and result.count("|") == 2,
        f"completed personal-delivery tombstone for {origin_id}",
    )
    admission_id, completed_at, grace = value.split("|", 2)
    return admission_id, completed_at, float(grace)


def recipient_ordering_barrier(
    sender,
    recipient,
    recipient_jid: str,
    barrier_id: str,
    forbidden_markers: list[str],
) -> None:
    marker = f"POW-ROUTE-BARRIER-{barrier_id}"
    sender.send(
        f"<presence xmlns='jabber:client' to='{recipient_jid}' id='{barrier_id}'>"
        f"<status>{marker}</status></presence>"
    )
    _, frames = recipient.receive_until(marker)
    for forbidden in forbidden_markers:
        helpers.check(
            all(forbidden not in frame for frame in frames),
            f"duplicate message preceded the ordered recipient barrier: {frames}",
        )


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
    accepted_proof = alice.send_with_pow(accepted, token)
    delivered, _ = bob.receive_until(accepted_marker)
    helpers.check(accepted_origin in delivered, f"accepted message lost origin-id: {delivered}")
    alice.send_with_pow_proof(accepted, accepted_proof)
    recipient_ordering_barrier(
        alice,
        bob,
        bob_jid,
        f"accepted-replay-barrier-{run_id}",
        [accepted_marker],
    )

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
    recipient_ordering_barrier(
        alice,
        bob,
        bob_jid,
        f"accepted-conflict-barrier-{run_id}",
        [f"{accepted_marker}-CHANGED"],
    )

    remote_marker = f"POW-OUTBOX-{run_id}"
    remote_origin = f"pow-outbox-{run_id}"
    remote = stanza(
        "nobody@pow-wire.invalid",
        f"outbox-{run_id}",
        remote_origin,
        remote_marker,
    )
    remote_proof = alice.send_with_pow(remote, token)
    ordering_barrier(alice, f"remote-store-barrier-{run_id}")
    wait_for_abuse_admission(alice_name, remote_proof["challenge_id"], "accepted")
    helpers.check(
        wait_for_sql(
            "SELECT COUNT(*) FROM s2s_outbox WHERE stanza LIKE "
            + sql_literal(f"%{remote_marker}%"),
            lambda result: result == "1",
            "one durable remote outbox row",
        )
        == "1",
        "remote message did not create exactly one durable outbox row",
    )
    alice.send_with_pow_proof(remote, remote_proof)
    ordering_barrier(alice, f"remote-replay-barrier-{run_id}")
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
    temporary_proof = alice.send_with_pow(temporary, token)
    ordering_barrier(alice, f"temporary-store-barrier-{run_id}")
    temporary_admission_key = wait_for_abuse_admission(
        alice_name, temporary_proof["challenge_id"], "accepted"
    )
    temporary_personal_id, temporary_offline_id = wait_for_personal_delivery_projection(
        alice_jid, bob_jid, temporary_origin
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
    ordering_barrier(bob, f"temporary-delivery-barrier-{run_id}")
    temporary_tombstone_id, temporary_completed_at, grace = wait_for_personal_tombstone(
        alice_jid, bob_jid, temporary_origin
    )
    helpers.check(
        temporary_tombstone_id == temporary_personal_id,
        "acknowledged temporary delivery changed its personal admission identity",
    )
    helpers.check(
        psql(
            "SELECT COUNT(*) FROM offline_messages WHERE id="
            + sql_literal(temporary_offline_id)
            + "::pg_catalog.uuid"
        )
        == "0",
        "temporary content row survived acknowledged delivery",
    )
    bob.close()
    # Durable local C2S admission owns the origin-id replay identity.  Once the
    # temporary content row is acknowledged, its trigger detaches the final
    # projection and starts the fixed personal-delivery retention horizon.
    # Query that canonical authority by the exact wire identity instead of the
    # legacy offline-only admission table, which is not populated when the
    # message entered through the atomic personal C2S admission path.
    helpers.check(
        30 * 86_400 - 30 <= grace <= 30 * 86_400,
        f"delivered tombstone grace was not bounded to 30 days: {grace}",
    )
    # Remove only this message's accepted anti-abuse marker, then prove the
    # independent personal-delivery tombstone still suppresses an exact retry.
    psql(
        "DELETE FROM abuse_message_admissions WHERE admission_key=decode("
        + sql_literal(temporary_admission_key)
        + ",'hex') AND proof_challenge_id="
        + sql_literal(temporary_proof["challenge_id"])
        + "::pg_catalog.uuid AND state='accepted'"
    )
    helpers.check(
        psql(
            "SELECT COUNT(*) FROM abuse_message_admissions WHERE admission_key=decode("
            + sql_literal(temporary_admission_key)
            + ",'hex')"
        )
        == "0",
        "temporary message anti-abuse admission was not removed exactly",
    )
    temporary_retry_proof = alice.send_with_pow(temporary, token)
    ordering_barrier(alice, f"temporary-replay-barrier-{run_id}")
    wait_for_abuse_admission(
        alice_name, temporary_retry_proof["challenge_id"], "accepted"
    )
    replay_tombstone_id, replay_completed_at, _ = wait_for_personal_tombstone(
        alice_jid, bob_jid, temporary_origin
    )
    helpers.check(
        (replay_tombstone_id, replay_completed_at)
        == (temporary_tombstone_id, temporary_completed_at),
        "late exact retry mutated the completed personal-delivery tombstone",
    )
    helpers.check(
        psql(
            "SELECT COUNT(*) FROM offline_messages WHERE stanza LIKE "
            + sql_literal(f"%{temporary_marker}%")
        )
        == "0",
        "late exact retry escaped the personal-delivery tombstone",
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
    # client observing the stanza: remove the canonical route side effects and
    # restore this exact admission to an expired pending fencing lease.
    crash_marker = f"POW-CRASH-RESUME-{run_id}"
    crash_origin = f"pow-crash-resume-{run_id}"
    crash = stanza(
        bob_jid,
        f"crash-{run_id}",
        crash_origin,
        crash_marker,
        no_permanent_store=True,
    )
    crash_proof = alice.send_with_pow(crash, token)
    ordering_barrier(alice, f"crash-store-barrier-{run_id}")
    crash_admission_key = wait_for_abuse_admission(
        alice_name, crash_proof["challenge_id"], "accepted"
    )
    crash_personal_id, crash_offline_id = wait_for_personal_delivery_projection(
        alice_jid, bob_jid, crash_origin
    )
    # This is one synthetic crash cut, not ordinary retention: roll back every
    # durable route projection before deleting the content row so its DELETE
    # trigger cannot create a completed replay tombstone.  Leave only the exact
    # anti-abuse lease in an expired pending state for restart takeover.
    psql(
        "BEGIN; DELETE FROM personal_message_admissions WHERE id="
        + sql_literal(crash_personal_id)
        + "::pg_catalog.uuid; DELETE FROM offline_messages WHERE id="
        + sql_literal(crash_offline_id)
        + "::pg_catalog.uuid; UPDATE abuse_message_admissions "
        "SET state='pending',accepted_at=NULL,updated_at=clock_timestamp(),"
        "lease_expires_at=GREATEST(created_at,clock_timestamp()-INTERVAL '1 millisecond'),"
        "expires_at=created_at+INTERVAL '30 minutes' "
        "WHERE admission_key=decode("
        + sql_literal(crash_admission_key)
        + ",'hex') AND proof_challenge_id="
        + sql_literal(crash_proof["challenge_id"])
        + "::pg_catalog.uuid AND state='accepted'; COMMIT;"
    )
    helpers.check(
        psql(
            "SELECT COUNT(*) FROM personal_message_admissions WHERE id="
            + sql_literal(crash_personal_id)
            + "::pg_catalog.uuid"
        )
        == "0",
        "crash fixture retained a personal-delivery authority row",
    )
    helpers.check(
        psql(
            "SELECT COUNT(*) FROM offline_messages WHERE id="
            + sql_literal(crash_offline_id)
            + "::pg_catalog.uuid"
        )
        == "0",
        "crash fixture retained a durable delivery projection",
    )
    helpers.check(
        wait_for_abuse_admission(
            alice_name, crash_proof["challenge_id"], "pending"
        )
        == crash_admission_key,
        "crash fixture did not leave one resumable pending admission",
    )
    helpers.check(
        psql(
            "SELECT COUNT(*) FROM abuse_message_admissions "
            "WHERE admission_key=decode("
            + sql_literal(crash_admission_key)
            + ",'hex') AND lease_expires_at < clock_timestamp() "
            "AND expires_at=created_at+INTERVAL '30 minutes'"
        )
        == "1",
        "crash fixture lease/retention timestamps do not match production pending state",
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
                "accepted_proof": accepted_proof,
                "remote_marker": remote_marker,
                "crash_marker": crash_marker,
                "crash_origin": crash_origin,
                "crash_admission_key": crash_admission_key,
                "crash_proof": crash_proof,
                "crash_stanza": crash,
            }
        ),
        encoding="utf-8",
    )
    print("message PoW wire prepare phase passed")


def verify() -> None:
    helpers.wait_ready()
    state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    alice = helpers.XmppWebSocket(state["alice"], PASSWORD, "pow-wire-alice-restart")
    bob = helpers.XmppWebSocket(state["bob"], PASSWORD, "pow-wire-bob-restart")

    alice.send_with_pow_proof(state["accepted_stanza"], state["accepted_proof"])
    recipient_ordering_barrier(
        alice,
        bob,
        f"{state['bob']}@{helpers.DOMAIN}",
        "accepted-restart-replay-barrier",
        [state["accepted_marker"]],
    )
    alice.send_with_pow_proof(state["crash_stanza"], state["crash_proof"])
    resumed, _ = bob.receive_until(state["crash_marker"])
    helpers.check(
        state["crash_origin"] in resumed,
        f"resumed message lost stable origin identity: {resumed}",
    )
    alice_jid = f"{state['alice']}@{helpers.DOMAIN}"
    bob_jid = f"{state['bob']}@{helpers.DOMAIN}"
    wait_for_personal_tombstone(alice_jid, bob_jid, state["crash_origin"])
    alice.send_with_pow_proof(state["crash_stanza"], state["crash_proof"])
    recipient_ordering_barrier(
        alice,
        bob,
        bob_jid,
        "crash-restart-replay-barrier",
        [state["crash_marker"]],
    )
    helpers.check(
        psql(
            "SELECT COUNT(*) FROM personal_message_admissions "
            "WHERE identity_kind='local-origin' AND actor_scope="
            + sql_literal(alice_jid)
            + " AND target_scope="
            + sql_literal(bob_jid)
            + " AND identity_value="
            + sql_literal(state["crash_origin"])
            + " AND sender_archive_id IS NULL AND recipient_archive_id IS NULL "
            "AND offline_message_id IS NULL AND s2s_outbox_id IS NULL "
            "AND delivery_completed_at IS NOT NULL"
        )
        == "1",
        "crash-resumed delivery did not converge to one personal tombstone",
    )
    helpers.check(
        psql(
            "SELECT COUNT(*) FROM offline_messages WHERE stanza LIKE "
            + sql_literal(f"%{state['crash_marker']}%")
        )
        == "0",
        "crash-resumed delivery retained an orphan queue projection",
    )
    helpers.check(
        psql(
            "SELECT COUNT(*) FROM abuse_message_admissions "
            "WHERE admission_key=decode("
            + sql_literal(state["crash_admission_key"])
            + ",'hex') AND proof_challenge_id="
            + sql_literal(state["crash_proof"]["challenge_id"])
            + "::pg_catalog.uuid AND state='accepted' AND accepted_at IS NOT NULL"
        )
        == "1",
        "crash-resumed admission did not converge to the exact accepted row",
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
