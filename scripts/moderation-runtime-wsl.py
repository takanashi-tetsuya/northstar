#!/usr/bin/env python3
"""End-to-end REST/XMPP moderation workflow probe for an isolated server.

The shell wrapper owns PostgreSQL, process and filesystem isolation.  This
client deliberately stays dependency-free by reusing the small HTTP, PoW and
XMPP WebSocket fixtures from integration-wsl.py.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pathlib
import sys
import time


ROOT = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("northstar_integration", ROOT / "integration-wsl.py")
fixture = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(fixture)

REPORTER = os.environ["MODERATION_REPORTER_USERNAME"]
TARGET = os.environ["MODERATION_TARGET_USERNAME"]
INTRUDER = os.environ["MODERATION_INTRUDER_USERNAME"]
ADMIN = os.environ["MODERATION_ADMIN_USERNAME"]
USER_PASSWORD = os.environ["MODERATION_USER_PASSWORD"]
ADMIN_PASSWORD = os.environ["MODERATION_ADMIN_PASSWORD"]
STATE_PATH = pathlib.Path(os.environ["MODERATION_RUNTIME_STATE"])


def login(username: str, password: str) -> str:
    status, result = fixture.api(
        "POST", "/api/v1/login", {"username": username, "password": password}
    )
    fixture.check(status == 200 and isinstance(result.get("token"), str),
                  f"login failed for {username}: {status} {result}")
    return result["token"]


def json_request(
    method: str,
    path: str,
    token: str,
    payload: dict | None,
    idempotency_key: str | None = None,
) -> tuple[int, dict[str, str], bytes, object]:
    body = None
    headers = {"Authorization": f"Bearer {token}"}
    if payload is not None:
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
        headers["Content-Type"] = "application/json"
    if idempotency_key is not None:
        headers["Idempotency-Key"] = idempotency_key
    status, response_headers, raw = fixture.raw_http(method, path, body, headers)
    parsed = json.loads(raw) if raw else None
    return status, response_headers, raw, parsed


def mutation(
    method: str,
    path: str,
    token: str,
    payload: dict,
    key: str,
    expected_status: int,
    *,
    replay: bool = True,
) -> tuple[dict, str]:
    status, headers, raw, parsed = json_request(method, path, token, payload, key)
    fixture.check(
        status == expected_status and isinstance(parsed, dict),
        f"mutation failed for {path}: {status} {parsed}",
    )
    request_id = headers.get("x-request-id")
    fixture.check(request_id is not None, f"mutation response omitted X-Request-Id: {path}")
    if replay:
        replay_status, replay_headers, replay_raw, _ = json_request(
            method, path, token, payload, key
        )
        fixture.check(
            replay_status == status
            and replay_raw == raw
            and replay_headers.get("idempotency-replayed") == "true"
            and replay_headers.get("idempotency-original-request-id") == request_id,
            f"idempotency replay was not stable for {path}: "
            f"{replay_status} {replay_headers} {replay_raw!r}",
        )
    return parsed, request_id


def pow_proof(
    token: str,
    action: str,
    path: str,
    body: dict,
) -> tuple[dict[str, str], dict]:
    status, challenge = fixture.api(
        "POST",
        "/api/v1/anti-abuse/challenge",
        {
            "action": action,
            "intent": fixture.pow_intent("POST", path, body),
        },
        token=token,
    )
    fixture.check(status == 200, f"could not obtain {action} challenge: {status} {challenge}")
    requirement = challenge["requirement"]
    wait_seconds = max(
        int(requirement.get("hard_wait_seconds", 0)),
        int(requirement.get("retry_after_seconds", 0)),
    )
    if wait_seconds:
        time.sleep(wait_seconds + 0.1)
    factor = max(1, int(requirement["work_factor"]))
    target = ((1 << 64) - 1) // factor
    prefix = challenge["prefix"].encode()
    nonce = 0
    while int.from_bytes(hashlib.sha256(prefix + str(nonce).encode()).digest()[:8], "big") > target:
        nonce += 1
    return {"challenge_id": challenge["challenge_id"], "nonce": str(nonce)}, requirement


def register_users() -> None:
    for username in (REPORTER, TARGET, INTRUDER):
        status, result = fixture.register_account(username, USER_PASSWORD)
        fixture.check(status == 201, f"registration failed for {username}: {status} {result}")


def archived_evidence(reporter_token: str, target_token: str) -> dict:
    marker = f"moderation-evidence-{time.time_ns()}"
    reporter = fixture.XmppWebSocket(REPORTER, USER_PASSWORD, "moderation-reporter")
    target = fixture.XmppWebSocket(TARGET, USER_PASSWORD, "moderation-target")
    try:
        target.send_with_pow(
            f"<message xmlns='jabber:client' type='chat' to='{REPORTER}@{fixture.DOMAIN}' "
            f"id='{marker}'><body>{marker}</body><store xmlns='urn:xmpp:hints'/></message>",
            target_token,
        )
        delivered, _ = reporter.receive_until(marker)
        fixture.check(marker in delivered, "report evidence message was not delivered")

        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            status, history = fixture.api(
                "GET", f"/api/v1/history?with={TARGET}@{fixture.DOMAIN}", token=reporter_token
            )
            fixture.check(status == 200, f"history lookup failed: {status} {history}")
            row = next(
                (item for item in history.get("messages", []) if marker in item.get("stanza", "")),
                None,
            )
            if row is not None:
                return {
                    "archive_id": row["id"],
                    "client_message_id": row.get("stanza_id"),
                    "body_text": marker,
                }
            time.sleep(0.1)
        raise AssertionError("delivered evidence was not archived for the reporter")
    finally:
        target.close()
        reporter.close()


def only_visible_to_reporter(reporter_token: str, target_token: str, intruder_token: str, report_id: str) -> None:
    status, own = fixture.api("GET", "/api/v1/reports", token=reporter_token)
    fixture.check(status == 200 and any(row["id"] == report_id for row in own["reports"]),
                  "reporter could not see the submitted report")
    for label, token in (("reported account", target_token), ("unrelated account", intruder_token)):
        status, page = fixture.api("GET", "/api/v1/reports", token=token)
        fixture.check(status == 200 and all(row["id"] != report_id for row in page["reports"]),
                      f"{label} could see another user's report")


def workflow() -> None:
    fixture.wait_ready()
    register_users()
    reporter_token = login(REPORTER, USER_PASSWORD)
    target_token = login(TARGET, USER_PASSWORD)
    intruder_token = login(INTRUDER, USER_PASSWORD)
    admin_token = login(ADMIN, ADMIN_PASSWORD)
    evidence = archived_evidence(reporter_token, target_token)

    foreign_report_body = {
        "reported_jid": f"{TARGET}@{fixture.DOMAIN}",
        "category": "spam",
        "description": "An unrelated account must not reuse another user's archive row.",
        "evidence": [evidence],
    }
    foreign_report_pow, _ = pow_proof(
        intruder_token,
        "report",
        "/api/v1/reports",
        foreign_report_body,
    )
    foreign_report, _ = mutation(
        "POST",
        "/api/v1/reports",
        intruder_token,
        {**foreign_report_body, "pow": foreign_report_pow},
        f"moderation-foreign-report-{time.time_ns()}",
        400,
    )
    fixture.check(
        foreign_report.get("error", {}).get("code") == "bad_request",
        f"foreign archive evidence did not fail closed: {foreign_report}",
    )

    report_body = {
        "reported_jid": f"{TARGET}@{fixture.DOMAIN}",
        "category": "spam",
        "description": "Runtime moderation workflow evidence.",
        "evidence": [evidence],
    }
    report_pow, report_requirement = pow_proof(
        reporter_token,
        "report",
        "/api/v1/reports",
        report_body,
    )
    report_payload = {**report_body, "pow": report_pow}
    report_result, report_create_request = mutation(
        "POST", "/api/v1/reports", reporter_token, report_payload,
        f"moderation-report-{time.time_ns()}", 201,
    )
    report_id = report_result["id"]
    fixture.check(report_result.get("status") == "submitted", "new report was not submitted")
    only_visible_to_reporter(reporter_token, target_token, intruder_token, report_id)

    denied_status, _, _, denied = json_request(
        "GET", "/api/v1/admin/reports", intruder_token, None
    )
    fixture.check(
        denied_status == 403 and denied.get("error", {}).get("code") == "forbidden",
        f"non-administrator accessed moderation queue: {denied_status} {denied}",
    )

    report_review_payload = {"status": "reviewing", "resolution": ""}
    report_review_key = f"moderation-report-review-{time.time_ns()}"
    _, report_review_request = mutation(
        "PATCH", f"/api/v1/admin/reports/{report_id}", admin_token,
        report_review_payload, report_review_key, 200,
    )
    conflict_status, _, _, conflict = json_request(
        "PATCH", f"/api/v1/admin/reports/{report_id}", admin_token,
        {"status": "actioned", "resolution": "different body under the same key"},
        report_review_key,
    )
    fixture.check(
        conflict_status == 409
        and conflict.get("error", {}).get("code") == "idempotency_key_conflict",
        f"changed idempotent report mutation was accepted: {conflict_status} {conflict}",
    )
    _, report_final_request = mutation(
        "PATCH", f"/api/v1/admin/reports/{report_id}", admin_token,
        {"status": "actioned", "resolution": "Confirmed spam; moderation action recorded."},
        f"moderation-report-final-{time.time_ns()}", 200,
    )

    status, own = fixture.api("GET", "/api/v1/reports", token=reporter_token)
    own_report = next((row for row in own.get("reports", []) if row["id"] == report_id), None)
    fixture.check(
        status == 200
        and own_report is not None
        and own_report["status"] == "actioned"
        and own_report["resolution"] == "Confirmed spam; moderation action recorded.",
        f"reporter did not receive the final report result: {status} {own_report}",
    )

    appeal_path = f"/api/v1/reports/{report_id}/appeals"
    intruder_appeal_body = {
        "reason": "I do not own this report and must not be allowed to appeal it."
    }
    intruder_pow, _ = pow_proof(
        intruder_token,
        "appeal",
        appeal_path,
        intruder_appeal_body,
    )
    intruder_status, _, _, intruder_result = json_request(
        "POST", appeal_path, intruder_token,
        {**intruder_appeal_body, "pow": intruder_pow},
        f"moderation-foreign-appeal-{time.time_ns()}",
    )
    fixture.check(
        intruder_status == 409 and intruder_result.get("error", {}).get("code") == "conflict",
        f"another account appealed the report: {intruder_status} {intruder_result}",
    )

    appeal_body = {
        "reason": "I disagree with the outcome and request a careful independent review."
    }
    appeal_pow, appeal_requirement = pow_proof(
        reporter_token,
        "appeal",
        appeal_path,
        appeal_body,
    )
    fixture.check(
        int(appeal_requirement["work_factor"]) >= int(report_requirement["work_factor"]) * 4
        and int(appeal_requirement["hard_wait_seconds"]) >= 15
        and int(appeal_requirement["max_work_factor"]) >= int(appeal_requirement["work_factor"])
        and int(appeal_requirement["approximate_max_device_seconds"]) <= 30
        and "maximum" in appeal_requirement["notice"].lower()
        and int(appeal_requirement["cooldown_seconds"]) > 0,
        f"appeal PoW was not the advertised stricter bounded policy: "
        f"report={report_requirement} appeal={appeal_requirement}",
    )
    appeal_payload = {**appeal_body, "pow": appeal_pow}
    appeal_result, appeal_create_request = mutation(
        "POST", appeal_path, reporter_token,
        appeal_payload, f"moderation-appeal-{time.time_ns()}", 201,
    )
    appeal_id = appeal_result["id"]
    fixture.check(appeal_result.get("status") == "submitted", "new appeal was not submitted")

    _, appeal_review_request = mutation(
        "PATCH", f"/api/v1/admin/appeals/{appeal_id}", admin_token,
        {"status": "reviewing", "resolution": ""},
        f"moderation-appeal-review-{time.time_ns()}", 200,
    )
    _, appeal_final_request = mutation(
        "PATCH", f"/api/v1/admin/appeals/{appeal_id}", admin_token,
        {"status": "denied", "resolution": "Independent review confirmed the original decision."},
        f"moderation-appeal-final-{time.time_ns()}", 200,
    )

    status, own = fixture.api("GET", "/api/v1/reports", token=reporter_token)
    own_report = next((row for row in own.get("reports", []) if row["id"] == report_id), None)
    appeal = own_report.get("appeal") if own_report else None
    fixture.check(
        status == 200
        and appeal is not None
        and appeal["id"] == appeal_id
        and appeal["status"] == "denied"
        and appeal["resolution"] == "Independent review confirmed the original decision.",
        f"reporter did not receive the final appeal result: {status} {own_report}",
    )
    status, queue = fixture.api("GET", "/api/v1/admin/reports", token=admin_token)
    queued = next((row for row in queue.get("reports", []) if row["id"] == report_id), None)
    fixture.check(
        status == 200 and queued is not None and queued.get("appeal", {}).get("id") == appeal_id,
        "administrator queue did not contain the report and appeal",
    )

    expired_token = login(ADMIN, ADMIN_PASSWORD)
    state = {
        "report_id": report_id,
        "appeal_id": appeal_id,
        "report_create_request": report_create_request,
        "report_review_request": report_review_request,
        "report_final_request": report_final_request,
        "appeal_create_request": appeal_create_request,
        "appeal_review_request": appeal_review_request,
        "appeal_final_request": appeal_final_request,
        "evidence_marker": evidence["body_text"],
        "reporter_token": reporter_token,
        "target_token": target_token,
        "intruder_token": intruder_token,
        "admin_token": admin_token,
        "expired_token": expired_token,
        "expired_token_hash": hashlib.sha256(expired_token.encode()).hexdigest(),
    }
    STATE_PATH.parent.resolve().mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(STATE_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(state, handle, separators=(",", ":"))
    print("moderation runtime HTTP/XMPP workflow passed")


def expired_token() -> None:
    with STATE_PATH.open("r", encoding="utf-8") as handle:
        state = json.load(handle)
    token = state["expired_token"]
    status, result = fixture.api("GET", "/api/v1/admin/reports", token=token)
    fixture.check(
        status == 401 and result.get("error", {}).get("code") == "unauthorized",
        f"expired administrator token retained access: {status} {result}",
    )
    print("moderation runtime expired-token rejection passed")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in {"workflow", "expired-token"}:
        raise SystemExit("usage: moderation-runtime-wsl.py workflow|expired-token")
    workflow() if sys.argv[1] == "workflow" else expired_token()
