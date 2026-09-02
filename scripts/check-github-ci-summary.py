#!/usr/bin/env python3
"""Deterministic self-test for the GitHub Actions failure summarizer."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIRECTORY))

import github_ci_summary as summary  # noqa: E402


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def test_noise_priority_and_deduplication() -> None:
    log = "\n".join(
        [f"psql:migration.sql:{line}: NOTICE: expected cleanup noise" for line in range(500)]
        + ["CREATE TABLE", "INSERT 0 1", '{"level":"error","event":"probe"}'] * 80
        + [
            "restore generation probe started",
            "ERROR: canonical restore marker mismatch",
            "DETAIL: expected generation 9 but observed generation 8",
            "ERROR: canonical restore marker mismatch",
            "bash: warning: execute_coproc: coproc still exists",
        ]
    )
    message = summary.summarize_log(log)
    require("canonical restore marker mismatch" in message, "root error was dropped")
    require(message.index("canonical restore marker mismatch") < 200, "root error was not first")
    require("NOTICE:" not in message, "PostgreSQL NOTICE noise survived")
    require("CREATE TABLE" not in message, "SQL command tag survived")
    require('"event":"probe"' not in message, "structured JSON noise survived")
    require(message.count("ERROR: canonical restore marker mismatch") == 1, "error was not deduplicated")


def test_sensitive_value_redaction() -> None:
    private_key = """-----BEGIN PRIVATE KEY-----
very-private-material
-----END PRIVATE KEY-----"""
    text = "\n".join(
        [
            "ERROR: credential-bearing diagnostic",
            "postgresql://alice:db-canary@database.example/northstar",
            "redis://:redis-canary@cache.example/0",
            "custom+tls://service:custom-uri-canary@peer.example/resource",
            "Authorization: Bearer authorization-canary",
            "prefix Authorization: Basic embedded-authorization-canary",
            "Proxy-Authorization: Basic proxy-canary",
            "Cookie: session=cookie-canary",
            'password="password-canary" token=token-canary API_KEY: api-canary',
            "PGPASSWORD=pg-canary --password cli-canary",
            "--access-token 'access token canary' --refresh_token=refresh-canary",
            "token=comma-canary,suffix-canary;still-canary",
            "https://objects.example/item?X-Amz-Signature=signature-canary&X-Amz-Credential=credential-canary",
            private_key,
        ]
    )
    redacted = summary.redact_sensitive(text)
    for canary in (
        "db-canary",
        "redis-canary",
        "custom-uri-canary",
        "authorization-canary",
        "embedded-authorization-canary",
        "proxy-canary",
        "cookie-canary",
        "password-canary",
        "token-canary",
        "api-canary",
        "pg-canary",
        "cli-canary",
        "access token canary",
        "refresh-canary",
        "comma-canary",
        "suffix-canary",
        "still-canary",
        "signature-canary",
        "credential-canary",
        "very-private-material",
    ):
        require(canary not in redacted, f"sensitive canary leaked: {canary}")
    require("[REDACTED]" in redacted, "redaction marker is absent")
    require("[REDACTED PRIVATE KEY]" in redacted, "PEM block was not redacted")


def test_utf8_and_workflow_byte_budget() -> None:
    log = (
        "\x1b[31mERROR: 根本原因 🚨 跨字节边界\x1b[0m\n"
        + ("百分比%与多字节資料🙂" * 1_000)
        + "\x00\x01\u202e"
    )
    command = summary.render_error_command("restore:failure,测试\nline", log)
    payload = command.split("::", 2)[2]
    require(len(command.encode("utf-8")) <= 3_800, "workflow command exceeds byte budget")
    require(len(payload.encode("utf-8")) < 3_800, "escaped payload did not reserve command overhead")
    require("根本原因" in command, "UTF-8 root error was lost")
    require("\x1b" not in command and "\x00" not in command, "control sequence survived")
    require("%25" in payload, "percent was not workflow-command escaped")
    require(summary.escape_message("a%\r\nb") == "a%25%0D%0Ab", "message escaping is incomplete")
    require(
        summary.escape_property("restore:failure,测试\nline")
        == "restore%3Afailure%2C测试%0Aline",
        "workflow title property escaping is incomplete",
    )
    require("title=restore%3Afailure%2C测试 line" in command, "rendered title was not normalized")


def test_unterminated_pem_and_quoted_assignment() -> None:
    text = (
        "ERROR: malformed key output\n"
        "client_secret: 'quoted secret value'\n"
        "-----BEGIN OPENSSH PRIVATE KEY-----\nunterminated-canary"
    )
    redacted = summary.redact_sensitive(text)
    require("quoted secret value" not in redacted, "quoted assignment leaked")
    require("unterminated-canary" not in redacted, "unterminated PEM leaked")


def test_tail_fallback() -> None:
    log = "\n".join(
        ["NOTICE: cleanup", '{"event":"noise"}', "ordinary phase marker", "last useful line"]
    )
    message = summary.summarize_log(log)
    require("ordinary phase marker" in message, "fallback discarded useful tail")
    require("last useful line" in message, "fallback discarded final line")


def test_overlong_anchor_preserves_error() -> None:
    log = "diagnostic-prefix-" + ("x" * 8_000) + " ERROR: terminal-root-cause"
    message = summary.summarize_log(log)
    require("ERROR: terminal-root-cause" in message, "overlong line hid its error anchor")


def test_cli_output() -> None:
    with tempfile.TemporaryDirectory() as temporary_directory:
        log_path = Path(temporary_directory) / "failure.log"
        log_path.write_bytes("ERROR: cli smoke test 🙂\n".encode("utf-8"))
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_DIRECTORY / "github_ci_summary.py"),
                "--title",
                "CLI smoke test",
                str(log_path),
            ],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
    require(result.returncode == 0, f"CLI exited with {result.returncode}: {result.stderr}")
    require(result.stdout.startswith("::error title=CLI smoke test::"), "CLI emitted no annotation")
    require("cli smoke test" in result.stdout, "CLI omitted the root error")


def main() -> int:
    tests = (
        test_noise_priority_and_deduplication,
        test_sensitive_value_redaction,
        test_utf8_and_workflow_byte_budget,
        test_unterminated_pem_and_quoted_assignment,
        test_tail_fallback,
        test_overlong_anchor_preserves_error,
        test_cli_output,
    )
    for test in tests:
        test()
    print(f"GitHub CI summary self-test passed ({len(tests)} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
