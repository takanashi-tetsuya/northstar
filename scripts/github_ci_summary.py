#!/usr/bin/env python3
"""Build a bounded, redacted GitHub Actions failure annotation from a job log.

The complete command output remains in the ordinary job log.  This module only
selects the most useful failure context for the check-run annotation, whose
payload is subject to a small byte limit.  Redaction here is defense in depth;
the workflow must still avoid printing secrets and register every CI secret
with the runner so its authoritative log masking remains effective.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


MAX_WORKFLOW_COMMAND_BYTES = 3_800
MAX_ESCAPED_LINE_BYTES = 900

_ANSI_OSC_RE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_ANSI_CSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_ANSI_OTHER_RE = re.compile(r"\x1b[@-_]")
_BIDI_CONTROLS = frozenset(
    "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
)

_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?"
    r"-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
_UNTERMINATED_PEM_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*\Z",
    re.IGNORECASE | re.DOTALL,
)
_URI_USERINFO_RE = re.compile(
    r"(?P<scheme>\b[a-z][a-z0-9+.-]*://)(?:[^/\s?#@]+)@",
    re.IGNORECASE,
)
_SENSITIVE_HEADER_RE = re.compile(
    r"(?im)(?P<prefix>\b(?:authorization|proxy-authorization|cookie|"
    r"set-cookie)\s*:\s*)[^\r\n]*"
)
_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?ix)"
    r"(?P<prefix>"
    r"(?:\"|')?"
    r"(?:password|passwd|pwd|secret|token|access[_-]?token|refresh[_-]?token|"
    r"api[_-]?key|client[_-]?secret|database_url|redis_url|pgpassword|"
    r"session[_-]?token|github[_-]?token|gh_token|oauth[_-]?token|"
    r"aws_access_key_id|aws_secret_access_key|private_key)"
    r"(?:\"|')?\s*(?:=|:)\s*"
    r")"
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s]+)"
)
_SENSITIVE_OPTION_RE = re.compile(
    r"(?ix)(?P<prefix>(?<![\w-])--(?:password|passwd|pwd|secret|token|"
    r"access[_-]?token|refresh[_-]?token|session[_-]?token|oauth[_-]?token|"
    r"github[_-]?token|api[_-]?key|client[_-]?secret)(?:=|\s+))"
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s]+)"
)
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_SIGNED_QUERY_RE = re.compile(
    r"(?ix)(?P<prefix>[?&](?:"
    r"x-amz-signature|x-amz-credential|x-amz-security-token|"
    r"awsaccesskeyid|signature|sig|access_token|token"
    r")=)[^&\s]+"
)

_NOTICE_RE = re.compile(r"(?:^|:\s*)NOTICE:\s", re.IGNORECASE)
_PURE_COMMAND_TAG_RE = re.compile(
    r"(?ix)^(?:"
    r"(?:CREATE|ALTER|DROP)\s+(?:DATABASE|ROLE|SCHEMA|TABLE|INDEX|VIEW|"
    r"SEQUENCE|FUNCTION|PROCEDURE|TRIGGER|TYPE|EXTENSION|POLICY)|"
    r"(?:INSERT)\s+\d+\s+\d+|(?:UPDATE|DELETE|SELECT|COPY|MERGE)\s+\d+|"
    r"BEGIN|COMMIT|ROLLBACK|DO|GRANT|REVOKE|SET|RESET|VACUUM|ANALYZE|"
    r"CREATE\s+TABLE\s+AS"
    r")$"
)
_RUNNER_BOILERPLATE_RE = re.compile(
    r"^(?:##\[(?:group|endgroup)\]|shell:\s|env:\s*$)", re.IGNORECASE
)
_PSQL_ROW_COUNT_RE = re.compile(r"^\(\d+\s+rows?\)$", re.IGNORECASE)

_SEVERE_RE = re.compile(
    r"(?ix)(?:"
    r"(?:^|\b)(?:ERROR|FATAL|PANIC|PANICKED|TRACEBACK|ASSERTIONERROR|"
    r"FAILURE|FAILED)(?:\b|:)|"
    r"assertion\s+failed|segmentation\s+fault|"
    r"process\s+completed\s+with\s+exit\s+code\s+[1-9]\d*|"
    r"command\s+exited\s+with\s+non-zero"
    r")"
)
_ACTIONABLE_RE = re.compile(
    r"(?ix)\b(?:timed?\s*out|timeout|permission\s+denied|access\s+denied|"
    r"connection\s+refused|no\s+such\s+file|does\s+not\s+exist|missing|"
    r"mismatch|unexpected|invalid|cannot|could\s+not|unable\s+to)\b"
)
_WARNING_RE = re.compile(r"(?i)(?:^|\b)warnings?(?:\b|:)")
_RUNNER_EXIT_RE = re.compile(
    r"(?i)process\s+completed\s+with\s+exit\s+code\s+[1-9]\d*"
)
_SUCCESS_COUNTER_RE = re.compile(
    r"(?i)(?:\b0\s+failed\b|\b0\s+errors?\b|test\s+result:\s+ok)"
)


@dataclass(frozen=True)
class LogLine:
    number: int
    text: str


def _strip_terminal_and_controls(text: str) -> str:
    text = _ANSI_OSC_RE.sub("", text)
    text = _ANSI_CSI_RE.sub("", text)
    text = _ANSI_OTHER_RE.sub("", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    cleaned: list[str] = []
    for character in text:
        if character in "\n\t":
            cleaned.append(character)
            continue
        if character in _BIDI_CONTROLS:
            cleaned.append(" ")
            continue
        if unicodedata.category(character) == "Cc":
            cleaned.append(" ")
            continue
        cleaned.append(character)
    return "".join(cleaned)


def redact_sensitive(text: str) -> str:
    """Redact common CI credentials without relying on runner-side masking."""

    text = _PEM_BLOCK_RE.sub("[REDACTED PRIVATE KEY]", text)
    text = _UNTERMINATED_PEM_RE.sub("[REDACTED PRIVATE KEY]", text)
    text = _URI_USERINFO_RE.sub(r"\g<scheme>[REDACTED]@", text)
    text = _SENSITIVE_HEADER_RE.sub(r"\g<prefix>[REDACTED]", text)
    text = _SENSITIVE_ASSIGNMENT_RE.sub(r"\g<prefix>[REDACTED]", text)
    text = _SENSITIVE_OPTION_RE.sub(r"\g<prefix>[REDACTED]", text)
    text = _SIGNED_QUERY_RE.sub(r"\g<prefix>[REDACTED]", text)
    return _BEARER_RE.sub("Bearer [REDACTED]", text)


def redact_diagnostic_log(log_text: str) -> str:
    """Return a control-free, credential-redacted diagnostic transcript.

    This is intentionally less selective than a workflow annotation: a failed
    command may need its phase history to be useful after the ephemeral runner
    is gone. It is still safe to place in a restricted CI artifact because it
    applies the same defense-in-depth secret filtering as the annotation.
    """

    return redact_sensitive(_strip_terminal_and_controls(log_text))


def _is_json_noise(line: str) -> bool:
    stripped = line.strip()
    if not stripped or stripped[0] not in "[{":
        return False
    try:
        value = json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        return False
    return isinstance(value, (dict, list))


def _is_noise(line: str) -> bool:
    stripped = line.strip()
    return (
        not stripped
        or _NOTICE_RE.search(stripped) is not None
        or _PURE_COMMAND_TAG_RE.fullmatch(stripped) is not None
        or _RUNNER_BOILERPLATE_RE.match(stripped) is not None
        or _PSQL_ROW_COUNT_RE.fullmatch(stripped) is not None
        or _is_json_noise(stripped)
    )


def _deduplicate_keep_last(lines: Iterable[LogLine]) -> list[LogLine]:
    """Keep the most recent instance of an identical normalized line."""

    kept_reversed: list[LogLine] = []
    seen: set[str] = set()
    for line in reversed(list(lines)):
        key = " ".join(line.text.split())
        if key in seen:
            continue
        seen.add(key)
        kept_reversed.append(line)
    return list(reversed(kept_reversed))


def clean_log(log_text: str) -> list[LogLine]:
    cleaned = redact_diagnostic_log(log_text)
    useful = [
        LogLine(number, line.rstrip())
        for number, line in enumerate(cleaned.splitlines(), start=1)
        if not _is_noise(line)
    ]
    return _deduplicate_keep_last(useful)


def _priority(line: str) -> int:
    if _SUCCESS_COUNTER_RE.search(line):
        return 0
    if _RUNNER_EXIT_RE.search(line):
        return 2
    if _SEVERE_RE.search(line):
        return 3
    if _ACTIONABLE_RE.search(line):
        return 2
    if _WARNING_RE.search(line):
        return 1
    return 0


def escape_message(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escape_property(text: str) -> str:
    return (
        text.replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
        .replace(":", "%3A")
        .replace(",", "%2C")
    )


def _escaped_size(text: str) -> int:
    return len(escape_message(text).encode("utf-8"))


def _truncate_escaped(text: str, budget: int, marker: str) -> str:
    if _escaped_size(text) <= budget:
        return text

    marker_size = _escaped_size(marker)
    if marker_size > budget:
        marker = "[truncated]"
        marker_size = _escaped_size(marker)

    remaining = max(0, budget - marker_size)
    prefix: list[str] = []
    used = 0
    for character in text:
        character_size = _escaped_size(character)
        if used + character_size > remaining:
            break
        prefix.append(character)
        used += character_size
    return "".join(prefix).rstrip() + marker


def _truncate_property(text: str, budget: int, marker: str) -> str:
    if len(escape_property(text).encode("utf-8")) <= budget:
        return text

    marker_size = len(escape_property(marker).encode("utf-8"))
    remaining = max(0, budget - marker_size)
    prefix: list[str] = []
    used = 0
    for character in text:
        character_size = len(escape_property(character).encode("utf-8"))
        if used + character_size > remaining:
            break
        prefix.append(character)
        used += character_size
    return "".join(prefix).rstrip() + marker


def _bounded_line(line: str) -> str:
    return _truncate_escaped(
        line,
        MAX_ESCAPED_LINE_BYTES,
        " … [line truncated]",
    )


def _bounded_anchor(line: str) -> str:
    """Keep the matched error visible even when one physical line is huge."""

    if _escaped_size(line) <= MAX_ESCAPED_LINE_BYTES:
        return line
    match = _SEVERE_RE.search(line) or _ACTIONABLE_RE.search(line)
    if match is None:
        return _bounded_line(line)
    start = max(0, match.start() - 120)
    excerpt = line[start:]
    if start:
        excerpt = "… " + excerpt
    return _bounded_line(excerpt)


def _failure_sections(lines: list[LogLine]) -> list[str]:
    if not lines:
        return ["The command failed without producing a usable diagnostic line."]

    priorities = [_priority(line.text) for line in lines]
    anchors = [index for index, priority in enumerate(priorities) if priority >= 2]
    anchors.sort(key=lambda index: (priorities[index], index), reverse=True)

    # If no explicit error survived filtering, a warning is still preferable to
    # an arbitrary prefix.  The final non-noise tail is always appended below.
    if not anchors:
        warnings = [index for index, priority in enumerate(priorities) if priority == 1]
        if warnings:
            anchors = [warnings[-1]]

    selected_numbers: set[int] = set()
    sections: list[str] = []
    emitted_windows = 0

    for anchor_index in anchors:
        anchor = lines[anchor_index]
        if anchor.number in selected_numbers:
            continue
        sections.append(f"Failure context near log line {anchor.number}:")
        sections.append(_bounded_anchor(anchor.text))
        selected_numbers.add(anchor.number)

        before = lines[max(0, anchor_index - 4) : anchor_index]
        after = lines[anchor_index + 1 : anchor_index + 7]
        if before:
            sections.append("Preceding context:")
            for line in before:
                if line.number not in selected_numbers:
                    sections.append(_bounded_line(line.text))
                    selected_numbers.add(line.number)
        if after:
            sections.append("Following context:")
            for line in after:
                if line.number not in selected_numbers:
                    sections.append(_bounded_line(line.text))
                    selected_numbers.add(line.number)

        emitted_windows += 1
        if emitted_windows == 3:
            break

    tail = [line for line in lines[-20:] if line.number not in selected_numbers]
    if tail:
        sections.append("Final non-noise log tail:")
        sections.extend(_bounded_line(line.text) for line in tail)

    if not sections:
        sections = ["The command failed without producing a usable diagnostic line."]
    return sections


def summarize_log(
    log_text: str,
    max_escaped_bytes: int = MAX_WORKFLOW_COMMAND_BYTES,
) -> str:
    """Return a redacted summary whose workflow-escaped form fits the budget."""

    message = "\n".join(_failure_sections(clean_log(log_text)))
    message = _truncate_escaped(
        message,
        max_escaped_bytes,
        "\n… [annotation truncated; full output remains in the job log]",
    )
    if _escaped_size(message) > max_escaped_bytes:
        raise AssertionError("annotation escaped-byte budget was not enforced")
    return message


def render_error_command(title: str, log_text: str) -> str:
    clean_title = redact_sensitive(_strip_terminal_and_controls(title))
    clean_title = " ".join(clean_title.splitlines()).strip() or "CI command failed"
    clean_title = _truncate_property(clean_title, 160, "…")
    prefix = f"::error title={escape_property(clean_title)}::"
    message_budget = MAX_WORKFLOW_COMMAND_BYTES - len(prefix.encode("utf-8"))
    message = summarize_log(log_text, max_escaped_bytes=message_budget)
    command = prefix + escape_message(message)
    if len(command.encode("utf-8")) > MAX_WORKFLOW_COMMAND_BYTES:
        raise AssertionError("workflow command byte budget was not enforced")
    return command


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log_file", type=Path)
    parser.add_argument("--title", required=True)
    parser.add_argument(
        "--redacted-copy",
        type=Path,
        help="write a complete control-free, credential-redacted diagnostic copy",
    )
    arguments = parser.parse_args()

    log_text = arguments.log_file.read_bytes().decode("utf-8", errors="replace")
    if arguments.redacted_copy is not None:
        arguments.redacted_copy.write_bytes(redact_diagnostic_log(log_text).encode("utf-8"))
        arguments.redacted_copy.chmod(0o600)
    # Write UTF-8 bytes explicitly.  Runner locales are normally UTF-8, but the
    # annotation must remain valid on self-hosted runners with legacy encodings.
    command = render_error_command(arguments.title, log_text)
    sys.stdout.buffer.write((command + "\n").encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
