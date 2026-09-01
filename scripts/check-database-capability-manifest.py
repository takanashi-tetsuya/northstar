#!/usr/bin/env python3
"""Fail closed when PostgreSQL capability manifests drift.

The canonical SQL manifest is deliberately independent from both the migration
security loops and the grants it controls.  This checker compares those
independent representations as sets, so database CI never needs fragile
numeric counts and grant reconciliation cannot attest itself.
"""

from __future__ import annotations

import re
import sys
import hashlib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "deploy/postgres-init/lib/northstar-capability-manifest.sql"
GRANTS = ROOT / "deploy/postgres-init/lib/apply-northstar-grants.sql"
GRANT_WRAPPER = ROOT / "deploy/postgres-init/lib/reconcile-northstar-grants.sql"
ROLE_ATTESTATION = ROOT / "src/db/role_attestation.rs"
ROLE_RECONCILER = ROOT / "scripts/reconcile-database-roles.sh"
DATABASE_CI = ROOT / "scripts/database-role-boundary-db-ci.sh"
MIGRATION_UPGRADE_TEST = ROOT / "src/db/migration_upgrade_test.rs"
MIGRATION_LEDGER = (
    ROOT / "deploy/postgres-init/lib/northstar-migration-ledger-manifest.sql"
)
MIGRATION_LEDGER_GENERATOR = ROOT / "scripts/generate-database-migration-ledger.py"
GRANT_IMAGE = ROOT / "deploy/database-grants.Dockerfile"
BACKUP_IMAGE = ROOT / "deploy/backup.Dockerfile"
GRANT_RUNNER = ROOT / "scripts/reconcile-database-grants.sh"
BACKUP_RUNNER = ROOT / "scripts/backup.sh"
BACKUP_RESTORE_CI = ROOT / "scripts/backup-restore-wsl.sh"
AUTHENTICATION_HARDENING = (
    ROOT / "migrations/0124_authentication_credential_hardening.sql"
)

MIGRATIONS = {
    "0112": ROOT / "migrations/0112_cluster_runtime_capacity_and_authority.sql",
    "0113": ROOT / "migrations/0113_upload_authority_capabilities.sql",
    "0114": ROOT / "migrations/0114_session_authority_capabilities.sql",
    "0126": ROOT / "migrations/0126_mix_delivery_release_journal.sql",
    "0127": ROOT / "migrations/0127_sm_resume_authority_notifications.sql",
    "0128": ROOT / "migrations/0128_mix_capacity_authorities.sql",
}

# A later migration may replace an existing routine without changing its
# callable identity.  Its local hardening loop must then re-pin that routine as
# well as every newly introduced capability, while the canonical manifest keeps
# ownership attributed to the migration that first introduced the identity.
RESECURED_BY_MIGRATION = {
    "0127": {
        "northstar_sm_claim(bytea,uuid,inet,uuid,text,bool,uuid,int8)",
        "northstar_session_capability_catalog_healthy(text)",
    },
}

ROW = re.compile(
    r"^\s*\('([^']+\([^']*\))','(runtime|command|private)',"
    r"'(baseline-0111|0112|0113|0114|0126|0127|0128)'\)[,;]\s*$",
    re.MULTILINE,
)
LEDGER_ROW = re.compile(
    r"^\s*\(([0-9]+),'((?:[^']|'')*)',"
    r"pg_catalog\.decode\('([0-9a-f]{96})','hex'\)\)[,;]\s*$",
    re.MULTILINE,
)
QUOTED_SIGNATURE = re.compile(r"'([^']+\([^']*\))'")
CREATE_ROUTINE = re.compile(
    r"\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:FUNCTION|PROCEDURE)\s+([a-z][a-z0-9_]*)\s*\(",
    re.IGNORECASE,
)
ROUTINE_HEADER = re.compile(
    r"\bCREATE\s+(?:OR\s+REPLACE\s+)?(?P<kind>FUNCTION|PROCEDURE)\s+"
    r"(?P<name>(?:\"(?:[^\"]|\"\")*\"|[a-z_][a-z0-9_$]*)"
    r"(?:\.(?:\"(?:[^\"]|\"\")*\"|[a-z_][a-z0-9_$]*))?)\s*\(",
    re.IGNORECASE,
)
DROP_ROUTINE_HEADER = re.compile(
    r"\bDROP\s+(?P<kind>FUNCTION|PROCEDURE)\s+(?:IF\s+EXISTS\s+)?"
    r"(?P<name>(?:\"(?:[^\"]|\"\")*\"|[a-z_][a-z0-9_$]*)"
    r"(?:\.(?:\"(?:[^\"]|\"\")*\"|[a-z_][a-z0-9_$]*))?)\s*\(",
    re.IGNORECASE,
)
ALTER_ROUTINE_HEADER = re.compile(
    r"\bALTER\s+(?P<kind>FUNCTION|PROCEDURE)\s+"
    r"(?P<name>(?:\"(?:[^\"]|\"\")*\"|[a-z_][a-z0-9_$]*)"
    r"(?:\.(?:\"(?:[^\"]|\"\")*\"|[a-z_][a-z0-9_$]*))?)\s*\(",
    re.IGNORECASE,
)
INVALID_QUALIFIED_ALIAS = re.compile(
    r"\bpg_catalog\s*\.\s*(?:bigint|bigserial|boolean|integer|int|smallint|"
    r"smallserial|serial|serial2|serial4|serial8|real|float|decimal|dec|double\s+precision|"
    r"bit\s+varying|character\s+varying|char\s+varying|character|"
    r"national\s+character(?:\s+varying)?|nchar(?:\s+varying)?|"
    r"time(?:stamp)?\s+with(?:out)?\s+time\s+zone)\b",
    re.IGNORECASE,
)
HARDCODED_PUBLIC_SCHEMA = re.compile(
    r'(?<![a-z0-9_$])(?:public|"public")\s*\.\s*'
    r'(?:[a-z_][a-z0-9_$]*|"(?:[^"]|"")+")',
    re.IGNORECASE,
)
TYPE_ALIASES = {
    "bigint": "int8",
    "boolean": "bool",
    "integer": "int4",
    "smallint": "int2",
    "real": "float4",
    "doubleprecision": "float8",
    "decimal": "numeric",
    "charactervarying": "varchar",
    "character": "bpchar",
    "timestampwithtimezone": "timestamptz",
    "timestampwithouttimezone": "timestamp",
}


def fail(message: str) -> "NoReturn":
    print(f"database capability manifest check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        fail(f"could not read {path.relative_to(ROOT)}: {error}")


def signatures_between(text: str, start: str, end: str) -> list[str]:
    start_index = text.find(start)
    if start_index < 0:
        fail(f"missing manifest boundary: {start!r}")
    end_index = text.find(end, start_index + len(start))
    if end_index < 0:
        fail(f"missing manifest boundary: {end!r}")
    return QUOTED_SIGNATURE.findall(text[start_index:end_index])


def require_exact(label: str, actual: list[str] | set[str], expected: set[str]) -> None:
    actual_list = list(actual)
    duplicates = sorted(name for name, count in Counter(actual_list).items() if count != 1)
    if duplicates:
        fail(f"{label} contains duplicate signatures: {', '.join(duplicates)}")
    actual_set = set(actual_list)
    missing = sorted(expected - actual_set)
    unexpected = sorted(actual_set - expected)
    if missing or unexpected:
        details = []
        if missing:
            details.append("missing=" + ", ".join(missing))
        if unexpected:
            details.append("unexpected=" + ", ".join(unexpected))
        fail(f"{label} drifted ({'; '.join(details)})")


def matching_parenthesis(text: str, opening: int) -> int:
    depth = 0
    quote: str | None = None
    index = opening
    while index < len(text):
        char = text[index]
        if quote:
            if char == quote:
                if index + 1 < len(text) and text[index + 1] == quote:
                    index += 2
                    continue
                quote = None
        elif char in ("'", '"'):
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    fail("unterminated CREATE FUNCTION argument list")


def split_arguments(arguments: str) -> list[str]:
    if not arguments.strip():
        return []
    parts: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    for index, char in enumerate(arguments):
        if quote:
            if char == quote:
                quote = None
        elif char in ("'", '"'):
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(arguments[start:index])
            start = index + 1
    parts.append(arguments[start:])
    return parts


def normalize_identity_type(argument: str) -> str | None:
    argument = re.split(r"\bDEFAULT\b|=", argument, maxsplit=1, flags=re.IGNORECASE)[0]
    argument = re.sub(r"/\*.*?\*/|--[^\r\n]*", " ", argument, flags=re.DOTALL)
    tokens = argument.strip().split()
    if not tokens:
        fail("empty function argument in CREATE FUNCTION")
    mode = "in"
    if tokens[0].lower() in {"in", "out", "inout", "variadic"}:
        mode = tokens.pop(0).lower()
    if mode == "out":
        return None
    if not tokens:
        fail("function argument mode has no type")
    first = tokens[0].strip('"').lower()
    known_type_start = (
        first.startswith("pg_catalog.")
        or first in TYPE_ALIASES
        or first
        in {
            "aclitem", "bit", "bool", "bpchar", "bytea", "cidr", "date",
            "float4", "float8", "inet", "int2", "int4", "int8", "interval",
            "json", "jsonb", "name", "numeric", "oid", "record", "regclass",
            "regprocedure", "text", "time", "timestamp", "timestamptz",
            "timetz", "trigger", "uuid", "varbit", "varchar", "xml",
        }
    )
    type_tokens = tokens if len(tokens) == 1 or known_type_start else tokens[1:]
    if not type_tokens:
        fail(f"function argument has no identity type: {argument!r}")
    identity = "".join(type_tokens).replace('"', "").lower()
    identity = re.sub(r"^pg_catalog\.", "", identity)
    array_suffix = ""
    while identity.endswith("[]"):
        identity = identity[:-2]
        array_suffix += "[]"
    identity = re.sub(r"\([^)]*\)$", "", identity)
    identity = TYPE_ALIASES.get(identity, identity)
    return identity + array_suffix


def normalized_routine_signature(text: str, match: re.Match[str]) -> tuple[str, int]:
    opening = match.end() - 1
    closing = matching_parenthesis(text, opening)
    arguments = [
        normalized
        for argument in split_arguments(text[opening + 1 : closing])
        if (normalized := normalize_identity_type(argument)) is not None
    ]
    raw_name = match.group("name").split(".")[-1].replace('"', "")
    return f"{raw_name.lower()}({','.join(arguments)})", closing


def normalized_routine_definitions(text: str) -> list[tuple[str, bool, str, int]]:
    definitions: list[tuple[str, bool, str, int]] = []
    for match in ROUTINE_HEADER.finditer(text):
        opening = match.end() - 1
        signature, closing = normalized_routine_signature(text, match)

        dollar = re.search(r"\bAS\s+(\$[a-z0-9_]*\$)", text[closing:], re.IGNORECASE)
        if dollar:
            body_open = closing + dollar.start(1)
            delimiter = dollar.group(1)
            body_close = text.find(delimiter, body_open + len(delimiter))
            if body_close < 0:
                fail(f"unterminated body for {signature}")
            statement_end = text.find(";", body_close + len(delimiter))
            if statement_end < 0:
                statement_end = body_close + len(delimiter)
            clauses = (
                text[closing + 1 : body_open]
                + text[body_close + len(delimiter) : statement_end]
            )
        else:
            statement_end = text.find(";", closing)
            clauses = text[closing + 1 : statement_end if statement_end >= 0 else len(text)]
        definitions.append(
            (
                signature,
                bool(re.search(r"\bSECURITY\s+DEFINER\b", clauses, re.IGNORECASE)),
                match.group("kind").lower(),
                match.start(),
            )
        )
    return definitions


def normalized_dropped_routines(text: str) -> list[tuple[str, str, int]]:
    dropped: list[tuple[str, str, int]] = []
    for match in DROP_ROUTINE_HEADER.finditer(text):
        signature, _ = normalized_routine_signature(text, match)
        dropped.append((signature, match.group("kind").lower(), match.start()))
    return dropped


def normalized_altered_security_modes(text: str) -> list[tuple[str, bool, str, int]]:
    altered: list[tuple[str, bool, str, int]] = []
    for match in ALTER_ROUTINE_HEADER.finditer(text):
        signature, closing = normalized_routine_signature(text, match)
        statement_end = text.find(";", closing)
        clauses = text[closing + 1 : statement_end if statement_end >= 0 else len(text)]
        mode = re.search(r"\bSECURITY\s+(DEFINER|INVOKER)\b", clauses, re.IGNORECASE)
        if mode:
            altered.append(
                (
                    signature,
                    mode.group(1).lower() == "definer",
                    match.group("kind").lower(),
                    match.start(),
                )
            )
    return altered


def mask_sql_comments(text: str) -> str:
    """Replace SQL comments with spaces without hiding quoted SQL text.

    Migration functions use dollar-quoted bodies, so comments inside those
    bodies are still SQL comments and must be masked. Single- and
    double-quoted text is preserved: a dynamically constructed
    ``public.table`` reference remains a schema-neutrality violation.
    """
    result = list(text)
    index = 0
    quote: str | None = None
    block_depth = 0
    while index < len(text):
        character = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if block_depth:
            if character == "/" and following == "*":
                result[index] = result[index + 1] = " "
                block_depth += 1
                index += 2
                continue
            if character == "*" and following == "/":
                result[index] = result[index + 1] = " "
                block_depth -= 1
                index += 2
                continue
            if character not in "\r\n":
                result[index] = " "
            index += 1
            continue
        if quote:
            if character == quote:
                if following == quote:
                    index += 2
                    continue
                quote = None
            index += 1
            continue
        if character in ("'", '"'):
            quote = character
            index += 1
            continue
        if character == "-" and following == "-":
            result[index] = result[index + 1] = " "
            index += 2
            while index < len(text) and text[index] not in "\r\n":
                result[index] = " "
                index += 1
            continue
        if character == "/" and following == "*":
            result[index] = result[index + 1] = " "
            block_depth = 1
            index += 2
            continue
        index += 1
    return "".join(result)


CATALOG_CHAR_COLUMNS = (
    "defaclobjtype",
    "relkind",
    "prokind",
    "typtype",
    "tgenabled",
    "deptype",
)


def source_line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def assert_catalog_char_concatenation_safe(path: Path, text: str) -> None:
    """Reject ambiguous ``text || pg_catalog.\"char\"`` expressions.

    PostgreSQL's catalog discriminator columns use its internal one-byte
    ``\"char\"`` type.  Unlike ordinary ``char``, it has no unique implicit
    concatenation path to text, so an audit query can fail before reporting a
    privilege drift.  A surrounding CAST is naturally outside these direct
    operand patterns and an explicit ``::text`` is accepted.
    """

    columns = "|".join(CATALOG_CHAR_COLUMNS)
    operand = rf"(?:[a-z_][a-z0-9_]*\s*\.\s*)?(?:{columns})"
    patterns = (
        re.compile(
            rf"(?P<field>{operand})\s*(?P<cast>::\s*(?:pg_catalog\s*\.\s*)?text)?"
            r"\s*\|\|",
            re.IGNORECASE,
        ),
        re.compile(
            r"\|\|\s*(?P<field>"
            + operand
            + r")\s*(?P<cast>::\s*(?:pg_catalog\s*\.\s*)?text)?",
            re.IGNORECASE,
        ),
    )
    masked = mask_sql_comments(text)
    for pattern in patterns:
        for match in pattern.finditer(masked):
            if match.group("cast") is None:
                fail(
                    f"{path.relative_to(ROOT)}:{source_line(text, match.start())} "
                    f"concatenates catalog internal-char column {match.group('field')!r} "
                    "without an explicit text cast"
                )


def assert_sequence_privilege_dispatch_safe(path: Path, text: str) -> None:
    """Require pg_class OIDs to be type-dispatched through CASE.

    SQL AND/OR evaluation order is deliberately unspecified.  Guarding
    ``has_sequence_privilege(..., relation.oid, ...)`` with a neighbouring
    ``relkind='S'`` predicate is therefore unsafe: PostgreSQL may invoke the
    sequence-only helper for a table or TOAST relation before applying the
    predicate.
    """

    masked = mask_sql_comments(text)
    call_pattern = re.compile(
        r"\b(?:pg_catalog\s*\.\s*)?has_sequence_privilege\s*\(",
        re.IGNORECASE,
    )
    for match in call_pattern.finditer(masked):
        opening = masked.find("(", match.start(), match.end())
        closing = matching_parenthesis(masked, opening)
        arguments = split_arguments(masked[opening + 1 : closing])
        if len(arguments) < 2:
            fail(
                f"{path.relative_to(ROOT)}:{source_line(text, match.start())} "
                "has_sequence_privilege call has fewer than two arguments"
            )
        oid = re.fullmatch(
            r"\s*([a-z_][a-z0-9_]*)\s*\.\s*oid\s*",
            arguments[1],
            re.IGNORECASE,
        )
        if oid is None:
            # A literal regclass/name is already constrained to a sequence by
            # PostgreSQL's argument resolution and needs no pg_class dispatch.
            continue
        alias = re.escape(oid.group(1))
        prefix_start = max(0, match.start() - 1200)
        prefix = masked[prefix_start : match.start()]
        guards = list(
            re.finditer(
                rf"\bCASE\s+WHEN\s+{alias}\s*\.\s*relkind\s*=\s*'S'\s+THEN\b",
                prefix,
                re.IGNORECASE,
            )
        )
        if not guards:
            fail(
                f"{path.relative_to(ROOT)}:{source_line(text, match.start())} "
                f"passes {oid.group(1)}.oid to has_sequence_privilege without "
                "CASE dispatch on the same relkind"
            )
        guard = guards[-1]
        if re.search(r"\bEND\b", prefix[guard.end() :], re.IGNORECASE):
            fail(
                f"{path.relative_to(ROOT)}:{source_line(text, match.start())} "
                "has_sequence_privilege is outside the nearest relkind CASE branch"
            )
        suffix = masked[closing + 1 : closing + 1400]
        if re.search(r"\bEND\b", suffix, re.IGNORECASE) is None:
            fail(
                f"{path.relative_to(ROOT)}:{source_line(text, match.start())} "
                "relkind CASE guarding has_sequence_privilege is unterminated"
            )


def assert_captured_psql_includes_are_quiet(path: Path, text: str) -> None:
    """Prevent psql command tags from corrupting captured scalar results."""

    lines = text.splitlines()
    assignment = re.compile(r"^\s*[a-z_][a-z0-9_]*\s*=\s*\$\(", re.IGNORECASE)
    delimiter = re.compile(r"<<-?\s*['\"]?([a-z_][a-z0-9_]*)['\"]?\s*$", re.IGNORECASE)
    include = re.compile(r"^\s*\\i(?:r)?(?:\s|$)", re.IGNORECASE)
    index = 0
    while index < len(lines):
        if assignment.search(lines[index]) is None:
            index += 1
            continue
        # A complete one-line substitution cannot capture a later heredoc;
        # do not let a subsequent psql invocation become part of this header.
        if lines[index].rstrip().endswith(")") and delimiter.search(lines[index]) is None:
            index += 1
            continue
        header = [lines[index]]
        opening_line = index
        tag: str | None = None
        cursor = index
        while cursor < min(len(lines), index + 24):
            if cursor != index:
                header.append(lines[cursor])
            found = delimiter.search(lines[cursor])
            if found:
                tag = found.group(1)
                break
            if cursor != index and lines[cursor].strip() == ")":
                break
            cursor += 1
        if tag is None or "psql" not in "\n".join(header).lower():
            index += 1
            continue
        body_start = cursor + 1
        body_end = body_start
        while body_end < len(lines) and lines[body_end].strip() != tag:
            body_end += 1
        if body_end == len(lines):
            fail(f"{path.relative_to(ROOT)}:{opening_line + 1} has an unterminated psql heredoc")
        if any(include.search(line) for line in lines[body_start:body_end]):
            invocation = "\n".join(header)
            if re.search(r"(?:^|\s)(?:--quiet|-q)(?=\s|$)", invocation) is None:
                fail(
                    f"{path.relative_to(ROOT)}:{opening_line + 1} captures a psql "
                    "heredoc containing \\i/\\ir without --quiet"
                )
        index = body_end + 1


def assert_dynamic_search_path_quoting(path: Path, text: str) -> None:
    """Reject dynamic schema interpolation that does not quote identifiers."""

    masked = mask_sql_comments(text)
    unsafe_patterns = (
        re.compile(r"search_path=pg_catalog,[^'\"\r\n]{0,160}%s", re.IGNORECASE),
        re.compile(r"search_path=pg_catalog,[^'\"\r\n]{0,160}\{\}", re.IGNORECASE),
        re.compile(
            r"(['\"]search_path=pg_catalog,\s*['\"])\s*\|\|"
            r"(?!\s*(?:pg_catalog\s*\.\s*)?quote_ident\s*\()",
            re.IGNORECASE,
        ),
    )
    for pattern in unsafe_patterns:
        match = pattern.search(masked)
        if match:
            fail(
                f"{path.relative_to(ROOT)}:{source_line(text, match.start())} "
                "constructs a dynamic search_path without identifier quoting"
            )


def assert_canonical_int2_literals_are_typed(
    path: Path, text: str, signatures: list[str]
) -> None:
    """Reject untyped integer literals at canonical SMALLINT call positions."""

    by_name_and_arity: dict[tuple[str, int], list[list[str]]] = {}
    for signature in signatures:
        name, raw_arguments = signature[:-1].split("(", 1)
        argument_types = raw_arguments.split(",") if raw_arguments else []
        if "int2" in argument_types:
            by_name_and_arity.setdefault((name, len(argument_types)), []).append(argument_types)

    for (name, _), candidate_types in by_name_and_arity.items():
        call_pattern = re.compile(
            rf"\b(?:SELECT|PERFORM)\s+(?:\*\s+FROM\s+)?{re.escape(name)}\s*\(",
            re.IGNORECASE,
        )
        for match in call_pattern.finditer(text):
            opening = text.find("(", match.start(), match.end())
            closing = matching_parenthesis(text, opening)
            arguments = split_arguments(text[opening + 1 : closing])
            matching_types = [types for types in candidate_types if len(types) == len(arguments)]
            if len(matching_types) != 1:
                continue
            for position, argument_type in enumerate(matching_types[0]):
                if argument_type != "int2":
                    continue
                if re.fullmatch(r"\s*[+-]?[0-9]+\s*", arguments[position]):
                    fail(
                        f"{path.relative_to(ROOT)}:{source_line(text, match.start())} "
                        f"calls {name} with an untyped numeric literal at SMALLINT "
                        f"argument {position + 1}"
                    )


def repository_migration_ledger() -> list[tuple[int, str, str]]:
    rows: list[tuple[int, str, str]] = []
    seen: set[int] = set()
    migration_name = re.compile(
        r"^([0-9]{4})_([a-z0-9]+(?:_[a-z0-9]+)*)\.sql$"
    )
    candidates = sorted((ROOT / "migrations").glob("*.sql"))
    if not candidates:
        fail("repository contains no numbered SQL migrations")
    for path in candidates:
        match = migration_name.fullmatch(path.name)
        if match is None:
            fail(f"non-canonical migration filename: {path.name}")
        version = int(match.group(1), 10)
        if version <= 0 or version in seen:
            fail(f"duplicate or invalid migration version: {path.name}")
        seen.add(version)
        description = match.group(2).replace("_", " ")
        migration_bytes = path.read_bytes()
        if b"\r" in migration_bytes:
            fail(
                "migration SQL must use repository-canonical LF line endings: "
                f"{path.name}"
            )
        checksum = hashlib.sha384(migration_bytes).hexdigest()
        rows.append((version, description, checksum))
    rows.sort(key=lambda row: row[0])
    if not {113, 114, 115}.issubset(seen):
        fail("repository migration ledger lost the 0113/0114/0115 boundary")
    return rows


def static_parser_regressions() -> None:
    from contextlib import redirect_stderr
    from io import StringIO

    def rejects(check: object, *arguments: object) -> bool:
        try:
            with redirect_stderr(StringIO()):
                check(*arguments)  # type: ignore[operator]
        except SystemExit as error:
            return error.code == 1
        return False

    fixture = ROOT / "scripts/check-database-capability-manifest.py"
    sample = """
      CREATE FUNCTION overloaded(value BIGINT) RETURNS void LANGUAGE sql AS $$ SELECT 1 $$;
      CREATE FUNCTION overloaded(value pg_catalog.int4) RETURNS void LANGUAGE sql AS $$ SELECT 1 $$;
    """
    signatures = [signature for signature, _, _, _ in normalized_routine_definitions(sample)]
    if signatures != ["overloaded(int8)", "overloaded(int4)"]:
        fail("function-signature parser no longer distinguishes normalized overloads")
    if not INVALID_QUALIFIED_ALIAS.search("x pg_catalog.BIGINT"):
        fail("invalid pg_catalog-qualified alias regression was not detected")
    if INVALID_QUALIFIED_ALIAS.search("x pg_catalog.int8"):
        fail("canonical pg_catalog type was mistaken for an invalid alias")
    if not INVALID_QUALIFIED_ALIAS.search("x pg_catalog.serial8"):
        fail("invalid pg_catalog-qualified serial alias regression was not detected")
    procedure = """
      CREATE PROCEDURE rotate(value BIGINT) LANGUAGE SQL SECURITY DEFINER
      AS $$ SELECT 1 $$;
    """
    parsed = normalized_routine_definitions(procedure)
    if parsed[0][:3] != ("rotate(int8)", True, "procedure"):
        fail("SECURITY DEFINER procedure parser regression")
    altered = normalized_altered_security_modes(
        "ALTER PROCEDURE rotate(BIGINT) SECURITY DEFINER;"
    )
    if altered[0][:3] != ("rotate(int8)", True, "procedure"):
        fail("ALTER PROCEDURE SECURITY DEFINER parser regression")
    lifecycle = """
      DROP FUNCTION IF EXISTS revived();
      CREATE FUNCTION revived() RETURNS void LANGUAGE sql SECURITY DEFINER
      AS $$ SELECT 1 $$;
    """
    definition_position = normalized_routine_definitions(lifecycle)[0][3]
    drop_position = normalized_dropped_routines(lifecycle)[0][2]
    if drop_position > definition_position:
        fail("routine lifecycle parser lost DROP-before-CREATE ordering")
    comment_only = mask_sql_comments(
        "-- prose may mention public.users\n"
        "/* nested /* public.audit_log */ comment */ SELECT users.id FROM users;"
    )
    if HARDCODED_PUBLIC_SCHEMA.search(comment_only):
        fail("schema-neutrality parser treated a SQL comment as executable SQL")
    dynamic_sql = mask_sql_comments("EXECUTE 'SELECT id FROM public.users';")
    if not HARDCODED_PUBLIC_SCHEMA.search(dynamic_sql):
        fail("schema-neutrality parser lost a hard-coded dynamic SQL reference")
    if not rejects(
        assert_catalog_char_concatenation_safe,
        fixture,
        "SELECT 'relation=' || relation.relkind;",
    ):
        fail("catalog internal-char concatenation regression was not detected")
    assert_catalog_char_concatenation_safe(
        fixture, "SELECT 'relation=' || relation.relkind::pg_catalog.text;"
    )
    if not rejects(
        assert_sequence_privilege_dispatch_safe,
        fixture,
        "SELECT relation.relkind='S' AND "
        "pg_catalog.has_sequence_privilege(current_user,relation.oid,'UPDATE');",
    ):
        fail("unsafe sequence privilege short-circuit regression was not detected")
    assert_sequence_privilege_dispatch_safe(
        fixture,
        "SELECT CASE WHEN relation.relkind='S' THEN "
        "pg_catalog.has_sequence_privilege(current_user,relation.oid,'UPDATE') "
        "ELSE FALSE END;",
    )
    unsafe_capture = """result=$(control_psql --tuples-only <<'PSQL'
\\i manifest.sql
SELECT TRUE;
PSQL
)
"""
    if not rejects(assert_captured_psql_includes_are_quiet, fixture, unsafe_capture):
        fail("captured psql include without --quiet was not detected")
    assert_captured_psql_includes_are_quiet(
        fixture, unsafe_capture.replace("--tuples-only", "--quiet --tuples-only")
    )
    if not rejects(
        assert_dynamic_search_path_quoting,
        fixture,
        "expected := 'search_path=pg_catalog, ' || migration_schema || ', pg_temp';",
    ):
        fail("unquoted dynamic search_path regression was not detected")
    assert_dynamic_search_path_quoting(
        fixture,
        "expected := 'search_path=pg_catalog, ' || "
        "pg_catalog.quote_ident(migration_schema) || ', pg_temp';",
    )
    if not rejects(
        assert_canonical_int2_literals_are_typed,
        fixture,
        "SELECT northstar_probe('x',0);",
        ["northstar_probe(text,int2)"],
    ):
        fail("untyped canonical SMALLINT call regression was not detected")
    assert_canonical_int2_literals_are_typed(
        fixture,
        "SELECT northstar_probe('x',0::pg_catalog.int2);",
        ["northstar_probe(text,int2)"],
    )


expected_migration_ledger = repository_migration_ledger()
ledger_text = read(MIGRATION_LEDGER)
actual_migration_ledger = [
    (int(version, 10), description.replace("''", "'"), checksum)
    for version, description, checksum in LEDGER_ROW.findall(ledger_text)
]
if actual_migration_ledger != expected_migration_ledger:
    fail(
        "generated migration ledger differs by version, description, ordering, "
        "or SHA-384 checksum; run generate-database-migration-ledger.py --write"
    )
if len({version for version, _, _ in actual_migration_ledger}) != len(
    actual_migration_ledger
):
    fail("generated migration ledger contains duplicate versions")
# SQLx migration versions are identities rather than a contiguous counter.
# Keep the known deliberate 0021 hole, but reject any unreviewed additional
# hole so deleting an intermediate migration cannot be normalized away.
ledger_versions = {version for version, _, _ in actual_migration_ledger}
ledger_gaps = set(range(1, max(ledger_versions) + 1)) - ledger_versions
if ledger_gaps != {21}:
    fail(
        "migration-version gaps drifted "
        f"(expected=[21] actual={sorted(ledger_gaps)})"
    )

generator_text = read(MIGRATION_LEDGER_GENERATOR)
for required in (
    'if b"\\r" in migration_bytes:',
    "hashlib.sha384(migration_bytes).hexdigest()",
    "migration SQL file does not use the canonical NNNN_name.sql form",
    "ordered = sorted(rows, key=lambda row: row[0])",
    "migration chain is missing the 0113/0114/0115 boundary",
    "unexpected migration version gaps",
    "INTENTIONAL_GAPS = {21}",
):
    if required not in generator_text:
        fail(f"migration ledger generator omits invariant: {required}")
if "ON COMMIT DROP" in generator_text:
    fail("migration ledger temp table would disappear in autocommit audit sessions")

manifest_text = read(MANIFEST)
if "'baseline-0111','0112','0113','0114','0126','0127','0128'" not in manifest_text:
    fail("canonical manifest origin constraint omits a reviewed capability migration")
rows = ROW.findall(manifest_text)
if not rows:
    fail("canonical manifest contains no capability rows")
manifest_signatures = [signature for signature, _, _ in rows]
require_exact("canonical manifest", manifest_signatures, set(manifest_signatures))

by_workload = {
    workload: {signature for signature, row_workload, _ in rows if row_workload == workload}
    for workload in ("runtime", "command", "private")
}
by_origin = {
    origin: {signature for signature, _, row_origin in rows if row_origin == origin}
    for origin in ("baseline-0111", "0112", "0113", "0114", "0126", "0127", "0128")
}
manifest_origin_by_signature = {
    signature: origin for signature, _, origin in rows
}
if set().union(*by_workload.values()) != set(manifest_signatures):
    fail("workload partitions do not cover the canonical manifest")
if any(by_workload[left] & by_workload[right] for left in by_workload for right in by_workload if left < right):
    fail("a capability is assigned to more than one workload")

manifest_signature_set = set(manifest_signatures)
migration_documents = [
    (migration, read(migration))
    for migration in sorted((ROOT / "migrations").glob("*.sql"))
]

# These checks cover the exact SQL surfaces that enforce the database role
# boundary.  Migration bodies are included because their SECURITY DEFINER
# catalog health functions execute again at runtime, not only during install.
postgresql_safety_documents = migration_documents + [
    (GRANTS, read(GRANTS)),
    (ROLE_ATTESTATION, read(ROLE_ATTESTATION)),
    (ROLE_RECONCILER, read(ROLE_RECONCILER)),
    (DATABASE_CI, read(DATABASE_CI)),
    (BACKUP_RUNNER, read(BACKUP_RUNNER)),
]
for safety_path, safety_text in postgresql_safety_documents:
    assert_catalog_char_concatenation_safe(safety_path, safety_text)
    assert_sequence_privilege_dispatch_safe(safety_path, safety_text)

for shell_script in sorted((ROOT / "scripts").glob("*.sh")):
    assert_captured_psql_includes_are_quiet(shell_script, read(shell_script))

for search_path_source, search_path_text in migration_documents + [
    (MIGRATION_UPGRADE_TEST, read(MIGRATION_UPGRADE_TEST)),
]:
    assert_dynamic_search_path_quoting(search_path_source, search_path_text)

assert_canonical_int2_literals_are_typed(
    DATABASE_CI, read(DATABASE_CI), manifest_signatures
)

authentication_hardening_text = read(AUTHENTICATION_HARDENING)
for required in (
    "ADD COLUMN scram_sha256_iteration_floor INTEGER NOT NULL DEFAULT 4096",
    "ADD COLUMN scram_sha1_iteration_floor INTEGER NOT NULL DEFAULT 4096",
    "CREATE TRIGGER users_scram_iteration_floors_insert",
    "CREATE TRIGGER users_scram_iteration_floors_update",
    "ALTER FUNCTION %I.%s SECURITY DEFINER SET search_path TO pg_catalog, %I, pg_temp",
    "ALTER FUNCTION %I.%s SECURITY INVOKER SET search_path TO pg_catalog, %I, pg_temp",
    "REVOKE ALL ON FUNCTION %I.%s FROM PUBLIC",
):
    if required not in authentication_hardening_text:
        fail(f"authentication hardening migration omits invariant: {required}")
authentication_login_signature = (
    "northstar_user_apply_login(uuid,text,int8,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea)"
)
if authentication_login_signature not in by_workload["runtime"]:
    fail("authentication login replacement lost its runtime definer capability")
reviewed_invoker_signatures = {
    "prevent_legal_hold_link_mutation()",
    "northstar_enforce_scram_iteration_floors()",
    "northstar_user_credentials_valid(text,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea)",
}
for invoker_signature in sorted(reviewed_invoker_signatures):
    if invoker_signature in manifest_signature_set:
        fail(
            f"SECURITY INVOKER helper {invoker_signature} was elevated into "
            "the SECURITY DEFINER manifest"
        )
    invoker_definitions = [
        (declared_definer, kind)
        for _, text in migration_documents
        for signature, declared_definer, kind, _ in normalized_routine_definitions(text)
        if signature == invoker_signature
    ]
    if not invoker_definitions or any(
        declared_definer or kind != "function"
        for declared_definer, kind in invoker_definitions
    ):
        fail(f"reviewed helper {invoker_signature} is no longer SECURITY INVOKER")
    if any(
        signature == invoker_signature and promoted
        for _, text in migration_documents
        for signature, promoted, _, _ in normalized_altered_security_modes(text)
    ):
        fail(f"reviewed SECURITY INVOKER helper {invoker_signature} was promoted")

upgraded_trigger_signature = "fence_cluster_muc_outbox_identity()"
upgraded_trigger_definitions = [
    declared_definer
    for _, text in migration_documents
    for signature,declared_definer,kind,_ in normalized_routine_definitions(text)
    if signature==upgraded_trigger_signature and kind=="function"
]
if upgraded_trigger_definitions != [False,True]:
    fail("ordered invoker-to-SECURITY-DEFINER trigger upgrade lifecycle drifted")
if upgraded_trigger_signature not in manifest_signature_set:
    fail("the final SECURITY DEFINER trigger upgrade is absent from the manifest")


def has_later_exact_drop(
    migration_index: int, position: int, signature: str, kind: str
) -> bool:
    for candidate_index, (_, candidate) in enumerate(migration_documents):
        if candidate_index < migration_index:
            continue
        for dropped_signature, dropped_kind, dropped_position in normalized_dropped_routines(candidate):
            if (
                dropped_signature == signature
                and dropped_kind == kind
                and (candidate_index > migration_index or dropped_position > position)
            ):
                return True
    return False


def identity_signature_pattern(signature: str) -> str:
    name, raw_arguments = signature[:-1].split("(",1)
    aliases = {
        "int8": ("int8","bigint"),
        "int4": ("int4","integer","int"),
        "int2": ("int2","smallint"),
        "bool": ("bool","boolean"),
        "float4": ("float4","real"),
        "float8": ("float8","double\\s+precision"),
        "numeric": ("numeric","decimal","dec"),
        "varchar": ("varchar","character\\s+varying","char\\s+varying"),
        "bpchar": ("bpchar","character"),
    }
    argument_patterns: list[str] = []
    for argument in raw_arguments.split(",") if raw_arguments else []:
        suffix = ""
        while argument.endswith("[]"):
            argument = argument[:-2]
            suffix += r"\[\]"
        alternatives = aliases.get(argument,(re.escape(argument),))
        argument_patterns.append(
            r"(?:pg_catalog\s*\.\s*)?(?:" + "|".join(alternatives) + ")" + suffix
        )
    gap = r"[\s']*"
    arguments = (gap + "," + gap).join(argument_patterns)
    return re.escape(name) + r"\s*\(" + gap + arguments + gap + r"\)"


def capability_security_proof(signature: str, candidate: str, declared_definer: bool) -> bool:
    name = signature.split("(", 1)[0]
    loop_header = re.compile(
        r"FOREACH\s+(?P<variable>[a-z_][a-z0-9_]*)\s+IN\s+ARRAY\s+ARRAY\[",
        re.IGNORECASE,
    )
    for header in loop_header.finditer(candidate):
        list_end = candidate.find("] LOOP", header.end())
        if list_end < 0:
            continue
        literal = f"'{signature}'"
        if literal not in candidate[header.end() : list_end]:
            continue
        block_end = candidate.find("END LOOP", list_end)
        if block_end < 0:
            continue
        block = candidate[header.start() : block_end]
        block_body = candidate[list_end:block_end]
        variable = re.escape(header.group("variable"))
        resolves_exact_target = len(
            re.findall(rf"\b{variable}\b",block_body,re.IGNORECASE)
        )>=2
        safe_path = re.search(
            r"ALTER\s+FUNCTION\s+%I\.%s[\s\S]{0,160}"
            r"SET\s+search_path\s+TO\s+pg_catalog\s*,\s*%I\s*,\s*pg_temp",
            block,
            re.IGNORECASE,
        )
        public_revoke = re.search(
            r"REVOKE\s+ALL\s+(?:PRIVILEGES\s+)?ON\s+FUNCTION\s+%I\.%s"
            r"[\s\S]{0,80}FROM\s+PUBLIC",
            block,
            re.IGNORECASE,
        )
        promotion = declared_definer or bool(
            re.search(r"ALTER\s+FUNCTION\s+%I\.%s[\s\S]{0,100}SECURITY\s+DEFINER", block, re.IGNORECASE)
        )
        if resolves_exact_target and safe_path and public_revoke and promotion:
            return True

    if signature.endswith("()"):
        name_loop_header = re.compile(
            r"FOR\s+(?P<variable>[a-z_][a-z0-9_]*)\s+IN\s+"
            r"SELECT\s+pg_catalog\.unnest\s*\(\s*ARRAY\[",
            re.IGNORECASE,
        )
        for header in name_loop_header.finditer(candidate):
            list_end = candidate.find("]",header.end())
            loop_start = candidate.find("LOOP",list_end)
            if list_end < 0 or loop_start < 0 or loop_start-list_end>160:
                continue
            if f"'{name}'" not in candidate[header.end():list_end]:
                continue
            block_end = candidate.find("END LOOP",loop_start)
            if block_end < 0:
                continue
            block = candidate[header.start():block_end]
            variable = re.escape(header.group("variable"))
            if not re.search(variable,block,re.IGNORECASE):
                continue
            safe_path = re.search(
                r"ALTER\s+FUNCTION\s+%I\.%I\(\)[\s\S]{0,160}"
                r"SET\s+search_path\s+TO\s+pg_catalog\s*,\s*%I\s*,\s*pg_temp",
                block,re.IGNORECASE,
            )
            public_revoke = re.search(
                r"REVOKE\s+ALL\s+(?:PRIVILEGES\s+)?ON\s+FUNCTION\s+%I\.%I\(\)"
                r"[\s\S]{0,100}FROM\s+PUBLIC",
                block,re.IGNORECASE,
            )
            promotion = declared_definer or bool(re.search(
                r"ALTER\s+FUNCTION\s+%I\.%I\(\)[\s\S]{0,100}SECURITY\s+DEFINER",
                block,re.IGNORECASE,
            ))
            if safe_path and public_revoke and promotion:
                return True

    # Some historical migrations harden one exact overload directly instead
    # of using an array loop. Match its complete identity signature (including
    # catalog-qualified canonical types and SQL aliases), not merely the name.
    exact_target = identity_signature_pattern(signature)
    direct_path = re.search(
        rf"ALTER\s+FUNCTION\s+%I\.{exact_target}[\s\S]{{0,200}}"
        r"SET\s+search_path\s+TO\s+pg_catalog\s*,\s*%I\s*,\s*pg_temp",
        candidate,
        re.IGNORECASE,
    )
    direct_revoke = re.search(
        rf"REVOKE\s+ALL\s+(?:PRIVILEGES\s+)?ON\s+FUNCTION\s+(?:%I\.)?{exact_target}"
        r"[\s\S]{0,120}FROM\s+PUBLIC",
        candidate,
        re.IGNORECASE,
    )
    direct_promotion = declared_definer or bool(
        re.search(
            rf"ALTER\s+FUNCTION\s+%I\.{exact_target}[\s\S]{{0,120}}SECURITY\s+DEFINER",
            candidate,
            re.IGNORECASE,
        )
    )
    if direct_path and direct_revoke and direct_promotion:
        return True
    return False


static_parser_regressions()
if capability_security_proof(
    "target()",
    """
      FOREACH signature IN ARRAY ARRAY['target()'] LOOP
        PERFORM pg_catalog.to_regprocedure(signature);
      END LOOP;
      FOREACH signature IN ARRAY ARRAY['other()'] LOOP
        PERFORM pg_catalog.to_regprocedure(signature);
        EXECUTE pg_catalog.format(
          'ALTER FUNCTION %I.%s SECURITY DEFINER SET search_path TO pg_catalog, %I, pg_temp',
          schema_name,signature,schema_name);
        EXECUTE pg_catalog.format('REVOKE ALL ON FUNCTION %I.%s FROM PUBLIC',schema_name,signature);
      END LOOP;
    """,
    False,
):
    fail("an unrelated hardening loop was accepted as a target capability proof")


security_definition_count = 0
for migration_index, (migration, text) in enumerate(migration_documents):
    schema_reference_text = mask_sql_comments(text)
    hardcoded_public = HARDCODED_PUBLIC_SCHEMA.search(schema_reference_text)
    if hardcoded_public:
        line = text.count("\n", 0, hardcoded_public.start()) + 1
        fail(
            f"{migration.name}:{line} hard-codes public and breaks "
            "quoted/isolated installation schemas"
        )
    invalid_alias = INVALID_QUALIFIED_ALIAS.search(text)
    if invalid_alias:
        line = text.count("\n", 0, invalid_alias.start()) + 1
        fail(
            f"{migration.name}:{line} uses invalid PostgreSQL catalog-qualified "
            f"type alias {invalid_alias.group(0)!r}; use the real typname"
        )

    definitions = normalized_routine_definitions(text)
    for signature, declared_definer, kind, position in definitions:
        # A CREATE OR REPLACE may be emitted as invoker and promoted to definer
        # by the schema-local hardening loop later in the same migration.
        # Membership in the canonical manifest identifies those replacements
        # without falling back to a loose function-name allowlist.
        # A historical invoker-rights trigger/routine is not retroactively a
        # database capability merely because a later stopped-writer migration
        # replaces and promotes the same callable identity.  Begin enforcing
        # the capability proof at its canonical manifest origin.  A historical
        # SECURITY DEFINER is never ignored: it was already privileged at that
        # point and must remain registered and independently hardened/dropped.
        definition_version = int(migration.name.split("_", 1)[0])
        origin = manifest_origin_by_signature.get(signature)
        origin_version = (
            111 if origin == "baseline-0111" else int(origin)
            if origin is not None
            else None
        )
        historical_invoker_definition = (
            not declared_definer
            and origin_version is not None
            and definition_version < origin_version
        )
        capability_definition = declared_definer or (
            signature in manifest_signature_set and not historical_invoker_definition
        )
        if not capability_definition:
            continue
        security_definition_count += 1
        if kind != "function" and signature in manifest_signature_set:
            fail(
                f"{migration.name} defines manifest capability {signature} as a "
                f"{kind}; canonical capabilities must be functions"
            )
        if signature not in manifest_signature_set and not has_later_exact_drop(
            migration_index, position, signature, kind
        ):
            fail(
                f"{migration.name} defines SECURITY DEFINER {kind} {signature} outside "
                "the canonical full-signature manifest without a later exact DROP"
            )
        if signature in manifest_signature_set and not any(
            capability_security_proof(
                signature,
                proof_text,
                declared_definer or any(
                    proof_signature==signature and proof_declared
                    for proof_signature,proof_declared,_,_
                    in normalized_routine_definitions(proof_text)
                ),
            )
            for proof_index, (_, proof_text) in enumerate(migration_documents)
            if (
                proof_index == migration_index
                or (
                    int(migration.name.split("_", 1)[0]) < 107
                    and proof_index > migration_index
                )
            )
        ):
            fail(
                f"{migration.name} has no full-signature, fixed-search-path, "
                f"PUBLIC-revoked hardening proof for {signature}"
            )

    for signature, promoted, kind, position in normalized_altered_security_modes(text):
        if not promoted:
            continue
        security_definition_count += 1
        if kind != "function" and signature in manifest_signature_set:
            fail(
                f"{migration.name} promotes manifest capability {signature} as a procedure"
            )
        if signature not in manifest_signature_set and not has_later_exact_drop(
            migration_index, position, signature, kind
        ):
            fail(
                f"{migration.name} promotes SECURITY DEFINER {kind} {signature} outside "
                "the canonical full-signature manifest without a later exact DROP"
            )

if security_definition_count == 0:
    fail("no SECURITY DEFINER definitions were discovered across migrations")

for origin, migration in MIGRATIONS.items():
    text = read(migration)
    marker_matches = list(re.finditer(r"FOREACH\s+\w+\s+IN\s+ARRAY\s+ARRAY\[", text, re.IGNORECASE))
    if not marker_matches:
        fail(f"{migration.name} has no migration-local capability security loop")
    start = marker_matches[-1].end()
    end = text.find("] LOOP", start)
    if end < 0:
        fail(f"{migration.name} capability security loop is unterminated")
    migration_signatures = QUOTED_SIGNATURE.findall(text[start:end])
    resecured = RESECURED_BY_MIGRATION.get(origin, set())
    if not resecured <= manifest_signature_set:
        fail(
            f"{migration.name} resecures identities outside the canonical manifest: "
            f"{sorted(resecured-manifest_signature_set)}"
        )
    require_exact(
        f"{migration.name} security loop",
        migration_signatures,
        by_origin[origin] | resecured,
    )

    created_names = set(CREATE_ROUTINE.findall(text))
    secured_names = {signature.split("(", 1)[0] for signature in migration_signatures}
    # A hardening migration may re-pin an authority trigger created by an
    # earlier migration.  Every function it creates must be secured here;
    # additional secured names are allowed only because the exact origin set
    # is independently fixed by the canonical manifest above.
    if not created_names <= secured_names:
        fail(
            f"{migration.name} creates a function outside its security loop "
            f"(missing={sorted(created_names-secured_names)})"
        )
    for required in (
        "pg_catalog.current_schema()",
        "SECURITY DEFINER SET search_path TO pg_catalog",
        "REVOKE ALL ON FUNCTION",
    ):
        if required not in text:
            fail(f"{migration.name} is missing schema-local security invariant: {required}")

grants_text = read(GRANTS)
runtime_grant = signatures_between(
    grants_text,
    "JOIN (VALUES\n       ('northstar_transfer_cluster_muc_outbox",
    ") AS allowed(signature)\n   ON routine.oid",
)
require_exact("runtime grant allowlist", runtime_grant, by_workload["runtime"])

command_grant_start = grants_text.find(
    "JOIN (VALUES\n       ('northstar_admin_command_create_session",
    grants_text.find(") AS allowed(signature)\n   ON routine.oid") + 1,
)
if command_grant_start < 0:
    fail("command grant allowlist is missing")
command_grant_end = grants_text.find(") AS allowed(signature)\n   ON routine.oid", command_grant_start)
require_exact(
    "command grant allowlist",
    QUOTED_SIGNATURE.findall(grants_text[command_grant_start:command_grant_end]),
    by_workload["command"],
)

for required in (
    "pg_temp.northstar_capability_manifest",
    "northstar_canonical_capability_manifest_is_exact",
    "pg_catalog.pg_get_userbyid(routine.proowner)<>:'migrator_role'",
    "expected.workload='runtime'",
    "expected.workload='command'",
    "privilege.grantee=0",
    "REVOKE ALL PRIVILEGES ON ROUTINE",
    "privilege.grantee<>routine.proowner",
    "NOT privilege.is_grantable",
    "<>CASE WHEN expected.workload='private' THEN 1 ELSE 2 END",
    "privilege.grantee=routine.proowner",
    "privilege.grantor=routine.proowner",
    "routine.prokind<>'f'",
    "REVOKE ALL PRIVILEGES ON TABLE %I.%I FROM %I",
    "REVOKE ALL PRIVILEGES ON SEQUENCE %I.%I FROM %I",
    "northstar_relation_grantee_set_is_exact",
    "northstar_default_acl_set_is_exact",
    "pg_catalog.acldefault('T',data_type.typowner)",
    "data_type.typtype='c'",
    "FROM %s CASCADE",
    "pg_temp.northstar_migration_ledger_manifest",
    "ledger_matches_prepare",
    "ledger_matches_exact",
    "pg_catalog.count(*)=pg_catalog.count(DISTINCT version)",
    "pg_catalog.octet_length(checksum)=48",
    "default_acl.defaclobjtype NOT IN ('r','S','f','T','n')",
    "FROM (VALUES ('f'::\"char\"),('T'::\"char\"))",
    "WHEN 'n' THEN 'SCHEMAS'",
    "REVOKE ALL PRIVILEGES ON SCHEMAS",
    'ON TABLE public.users FROM :"runtime_role"',
    "GRANT SELECT ON ALL TABLES IN SCHEMA public",
):
    if required not in grants_text:
        fail(f"grant policy is not bound to the canonical manifest: {required}")

wrapper_text = read(GRANT_WRAPPER)
if "\\ir northstar-capability-manifest.sql" not in wrapper_text:
    fail("ordinary grant reconciliation does not load the canonical manifest")
if "\\ir northstar-migration-ledger-manifest.sql" not in wrapper_text:
    fail("ordinary grant reconciliation does not load the canonical migration ledger")

attestation_text = read(ROLE_ATTESTATION)
runtime_attestation = signatures_between(
    attestation_text,
    "WITH expected_definer(signature) AS (",
    "), resolved_definer AS (",
)
require_exact("runtime startup attestation", runtime_attestation, by_workload["runtime"])
command_attestation = signatures_between(
    attestation_text,
    "WITH expected(signature) AS (",
    "), resolved AS (",
)
require_exact("command startup attestation", command_attestation, by_workload["command"])
for required in (
    "CAPABILITY_MANIFEST_SQL",
    "attest_security_definer_capability_acls(pool).await?",
    "routine.workload_role",
    "routine.workload='private'",
    "privilege.grantee<>routine.proowner",
    "privilege.is_grantable",
    "expected.oid IS NULL",
    "attest_database_capability_catalog(pool).await?",
    "unexpected_default",
    "application_type",
    "composite_relation.relkind='c'",
    "rolvaliduntil IS NOT DISTINCT FROM",
    "privilege.grantor=relation.relowner",
    "northstar_backup",
    "MIGRATION_LEDGER_MANIFEST_SQL",
    "attest_migration_ledger(pool).await?",
    "repository migration ledger",
    "pg_catalog.encode(checksum,'hex')",
    "embedded migration ledger contains an unreviewed version gap",
    "pg_catalog.format('%I.users',namespace.nspname)",
):
    if required not in attestation_text:
        fail(f"startup role attestation omits exact SECURITY DEFINER ACL invariant: {required}")

role_reconciler_text = read(ROLE_RECONCILER)
for required in (
    "\\i :capability_manifest_sql",
    "\\i :migration_ledger_manifest_sql",
    "canonical SECURITY DEFINER capability manifest drifted",
    "pg_temp.northstar_capability_manifest",
    "unexpected explicit relation ACL grantee",
    "unexpected explicit column ACL grantee",
    "repository migration ledger differs by version, description, success, or SHA-384 checksum",
    "privilege.grantor=relation.relowner",
    "privilege.privilege_type='USAGE'",
):
    if required not in role_reconciler_text:
        fail(f"existing-volume audit omits canonical manifest invariant: {required}")

database_ci_text = read(DATABASE_CI)
if re.search(r"count\s*\([^\n]*\)\s*=\s*(?:52|35|8)\b", database_ci_text, re.IGNORECASE):
    fail("database CI still contains a hard-coded capability count")
for required in (
    "\\i deploy/postgres-init/lib/northstar-capability-manifest.sql",
    "expected_capability.workload='runtime'",
    "expected_capability.workload='command'",
    "'northstar_runtime','public.sm_resume_sessions','peer_ip','SELECT'",
    "SM ${ip_policy} IP policy accepted a NULL claimant address",
    "SM exact/subnet policy accepted a snapshot with NULL stored peer_ip",
    "northstar_ci_stale_grantee",
    "canonical verifier did not report the seeded stale routine grantee",
    "grant reconciliation retained a stale SECURITY DEFINER grantee",
    "canonical verifier did not report the seeded stale relation grantee",
    "grant reconciliation retained a stale relation or sensitive-column grantee",
    "runtime SM create capability oversized joined-room snapshot",
    "runtime SM snapshot capability accepted or persisted oversized state",
    "alien EXECUTE grant did not make startup capability health fail closed",
    "same-name session trigger function substitution was not rejected",
    "same-name trigger with a reduced UPDATE OF column set was not rejected",
    "same-name trigger with TG_ARGV data was not rejected",
    "constraint/deferrable trigger substitution was not rejected",
    "SECURITY DEFINER promotion of an invoker capacity trigger was not rejected",
    "unfixed capacity trigger search_path was not rejected",
    "real quoted-schema migration chain escaped into the populated public decoy",
    "northstar_ci_delegated_grantee",
    "northstar_ci_acl_composite",
    "future objects inherited a workload, PUBLIC, stale, or delegated default ACL",
    "grant reconciliation did not rebuild canonical owner/runtime/type ACLs",
    "SM strict same-device policy accepted a legacy NULL stored device ID",
    "SM strict same-device policy accepted a NULL claimant device ID",
    "SM compatibility mode rejected a legacy NULL stored device ID",
    "audit accepted disappeared owner-only routine/type default ACL overrides",
    "GRANT CREATE ON SCHEMAS TO northstar_ci_stale_grantee WITH GRANT OPTION",
    "expect_ledger_audit_failure missing",
    "expect_ledger_audit_failure unknown",
    "expect_ledger_audit_failure failed",
    "expect_ledger_audit_failure tampered",
):
    if required not in database_ci_text:
        fail(f"database CI omits capability/ACL invariant: {required}")

for image in (GRANT_IMAGE, BACKUP_IMAGE):
    if "northstar-migration-ledger-manifest.sql" not in read(image):
        fail(f"{image.relative_to(ROOT)} does not ship the migration ledger manifest")

grant_runner_text = read(GRANT_RUNNER)
for required in (
    "northstar-migration-ledger-manifest.sql",
    "database migration ledger manifest is missing",
    "--set=grant_phase=exact",
):
    if required not in grant_runner_text:
        fail(f"post-migration grant runner omits ledger invariant: {required}")

backup_restore_text = read(BACKUP_RESTORE_CI)
for required in (
    "apply_repository_migrations northstar_backup_source",
    "sha384sum \"$migration\"",
    "CREATE TABLE public._sqlx_migrations",
    "--set grant_phase=exact",
):
    if required not in backup_restore_text:
        fail(f"backup/restore drill omits real migration fixture invariant: {required}")
for forbidden in (
    "INSERT INTO _sqlx_migrations VALUES (13, TRUE)",
    "CREATE TABLE upload_slots (id TEXT PRIMARY KEY",
):
    if forbidden in backup_restore_text:
        fail(f"backup/restore drill still contains a synthetic migration fixture: {forbidden}")

backup_runner_text = read(BACKUP_RUNNER)
for required in (
    "attest_repository_migration_ledger",
    "database migration ledger differs by version, description, success, or SHA-384 checksum",
    "pg_catalog.count(DISTINCT version)",
    "pg_catalog.octet_length(checksum)<>48",
    "source.count(\"pg_catalog.decode('\") != len(rows)",
    "len(versions) != len(set(versions))",
    "gaps != {21}",
    "northstar-database-role-policy-v1",
    "__POLICY_LOCK_OK__",
):
    if required not in backup_runner_text:
        fail(f"backup runner omits repository ledger invariant: {required}")

session_hardening = read(ROOT / "migrations/0114_session_authority_capabilities.sql")
for required in (
    "trigger.tgattr::pg_catalog.int2[]",
    "trigger.tgnargs<>0",
    "pg_catalog.octet_length(trigger.tgargs)<>0",
    "trigger.tgconstraint<>0",
    "trigger.tgdeferrable",
    "trigger.tginitdeferred",
    "trigger.tgparentid<>0",
    "routine.prokind<>'f' OR routine.prosecdef",
    "routine.proconfig IS DISTINCT FROM ARRAY[",
    "routine.prorettype<>'pg_catalog.trigger'::pg_catalog.regtype",
):
    if required not in session_hardening:
        fail(f"session trigger manifest omits exact catalog invariant: {required}")

sm_event_authority = read(
    ROOT / "migrations/0127_sm_resume_authority_notifications.sql"
)
for required in (
    "ADD COLUMN state_version BIGINT NOT NULL DEFAULT 1",
    "CREATE TRIGGER sm_resume_sessions_authority_version",
    "CREATE TRIGGER sm_resume_sessions_authority_notify",
    "'northstar_sm_authority_v1'",
    "'schema', TG_TABLE_SCHEMA",
    "'session_id', changed_id",
    "'state_version', changed_version",
    "pending_reason := CASE",
    "IF stream.expires_at<=authority_now THEN",
    "retry_at := least(",
    "stream.expires_at",
    "stream.live_lease_until",
    "stream.claimed_until",
    "'northstar_sm_state_version()','private'",
    "'northstar_sm_state_notify()','private'",
    "'state_version','SELECT'",
):
    if required not in sm_event_authority:
        fail(f"SM event-authority migration omits invariant: {required}")
if "payload" in sm_event_authority.lower():
    # The notification JSON is intentionally inspected by exact key literals
    # below; this branch is only a guard against later prose/code introducing a
    # misleading generic payload field into the authority function itself.
    notify_body = sm_event_authority.split(
        "CREATE FUNCTION northstar_sm_state_notify()", 1
    )[1].split("$$;", 1)[0]
    if "'payload'" in notify_body.lower():
        fail("SM authority notifications must not contain a generic payload field")

upload_bounds = read(ROOT / "migrations/0115_upload_runtime_reconciliation_bounds.sql")
for required in (
    "migration_schema IN ('pg_catalog','information_schema','pg_toast')",
    "migration_owner<>(",
    "routine.prokind='f'",
    "routine.proretset",
    "routine.proargmodes=ARRAY[",
    "routine.proallargtypes=ARRAY[",
    "FROM %I CASCADE",
):
    if required not in upload_bounds:
        fail(f"upload runtime-bounds migration omits owner/schema/ABI invariant: {required}")

print(
    "database capability manifest static check passed: "
    f"total={len(manifest_signatures)} "
    + " ".join(f"{name}={len(values)}" for name, values in by_workload.items())
    + " "
    + " ".join(f"{origin}={len(values)}" for origin, values in by_origin.items())
)
