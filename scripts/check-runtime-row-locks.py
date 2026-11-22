#!/usr/bin/env python3
"""Reject direct row locks the runtime PostgreSQL role is not privileged to take.

PostgreSQL requires UPDATE on a relation (or one of its columns) for every
SELECT ... FOR KEY SHARE / FOR SHARE / FOR NO KEY UPDATE / FOR UPDATE that
locks it.  The runtime relation manifest deliberately leaves some relations
without UPDATE (users above all), so a direct locking SELECT on one of them
fails with SQLSTATE 42501 in production while every development fixture that
runs as the schema owner still passes.  Such locks must go through a reviewed
SECURITY DEFINER capability (for users: northstar_lock_auth_generation,
northstar_lock_enabled_user_name or northstar_lock_user_rows_*).

This gate scans the SQL string literals of every production Rust module
(test modules and test/test-support-only items excluded) and fails when a
locking clause targets a relation whose runtime manifest row has no UPDATE.
Code that never runs as the runtime role is listed explicitly below with the
exact relations it locks, so the exemption cannot silently grow.

With --emit-runtime-capability-replay the script instead prints a psql script
that PREPAREs and EXECUTEs (with NULL arguments, inside a rolled-back
transaction) every production statement that calls a runtime account lock
capability.  scripts/database-role-boundary-db-ci.sh runs it as the reconciled
northstar_runtime login, so each such statement is proven to pass PostgreSQL's
executor-start privilege checks as the identity that runs it in production.
"""

from __future__ import annotations

import re
import subprocess
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "deploy/postgres-init/lib/northstar-capability-manifest.sql"

# Modules executed only by a non-runtime database identity.  Each entry names
# the relations it locks and the number of locking clauses per relation;
# drift in either direction fails, so a stale or widened exemption is caught.
NON_RUNTIME_LOCKS: dict[str, tuple[str, dict[str, int]]] = {
    "crates/contexts/upload/northstar-upload-postgres/src/migration.rs": (
        "offline `storage migrate` connects with the migrator role",
        {
            "upload_storage_authority": 1,
            "upload_storage_migration_items": 2,
            "upload_storage_migration_runs": 4,
        },
    ),
    "crates/contexts/workflows/northstar-data-tools/src/pie_repository.rs": (
        "PIE import connects with the migrator role",
        {"users": 1},
    ),
}

RELATION_ROW = re.compile(
    r"^\s*\('([a-z_][a-z0-9_]*)',(TRUE|FALSE),(TRUE|FALSE),(TRUE|FALSE),"
    r"(TRUE|FALSE),'(?:sqlx|[0-9]{4})'\)[,;]\s*$",
    re.MULTILINE,
)
LOCK_CLAUSE = re.compile(
    r"\bFOR\s+(NO\s+KEY\s+UPDATE|KEY\s+SHARE|SHARE|UPDATE)\b"
    r"(?:\s+OF\s+(?P<of>[a-z_][a-z0-9_]*(?:\s*\.\s*[a-z_][a-z0-9_]*)?"
    r"(?:\s*,\s*[a-z_][a-z0-9_]*(?:\s*\.\s*[a-z_][a-z0-9_]*)?)*))?",
    re.IGNORECASE,
)
FROM_ITEM = re.compile(
    r"\b(?:FROM|JOIN)\s+(?:ONLY\s+)?"
    r"(?P<relation>\{[^{}]*\}|(?:[a-z_][a-z0-9_]*\s*\.\s*)?[a-z_][a-z0-9_]*)"
    r"(?P<call>\s*\()?"
    r"(?:\s+(?:AS\s+)?(?P<alias>(?!(?:WHERE|ON|USING|JOIN|LEFT|RIGHT|INNER|FULL|CROSS|"
    r"NATURAL|LATERAL|ORDER|GROUP|HAVING|LIMIT|OFFSET|FOR|WINDOW|UNION|EXCEPT|"
    r"INTERSECT|RETURNING|SET|TABLESAMPLE)\b)[a-z_][a-z0-9_]*))?",
    re.IGNORECASE,
)
ITEM_KEYWORD = re.compile(
    r"(?:\s|#\s*\[[^\]]*\])*(?:pub(?:\s*\([^)]*\))?\s+)?"
    r"(?:async\s+|unsafe\s+|extern\s+(?:\"[^\"]*\"\s+)?)*"
    r"(?:fn|mod|impl|struct|enum|trait|type|const|static|use|let|macro_rules!)\b"
)
RUNTIME_LOCK_CAPABILITY_CALL = re.compile(
    r"\bnorthstar_lock_(?:user_rows_(?:key_share|share|update)|auth_generation|enabled_user_name)\s*\("
)
REPLAY_STATEMENT_START = re.compile(r"^\s*(?:SELECT|WITH|INSERT|UPDATE|DELETE)\b", re.IGNORECASE)
CFG_ATTRIBUTE = re.compile(r"#\s*\[\s*cfg\s*\(", re.IGNORECASE)
TEST_ONLY_PREDICATE = re.compile(
    r'^(?:test|feature\s*=\s*"test-support"|any\((?:\s*(?:test|feature\s*=\s*"test-support")\s*,?)+\))$'
)


def fail(message: str) -> "NoReturn":
    print(f"runtime row-lock check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def runtime_read_only_relations(manifest_text: str) -> set[str]:
    rows = RELATION_ROW.findall(manifest_text)
    if not rows:
        fail("canonical manifest contains no runtime relation rows")
    read_only = {name for name, _select, _insert, update, _delete in rows if update == "FALSE"}
    if "users" not in read_only:
        fail("the runtime relation manifest no longer keeps users read-only")
    return read_only


def mask_rust(text: str) -> tuple[str, list[tuple[int, int, str]]]:
    """Blank comments and literal bodies; return the mask and string literals.

    The mask keeps every offset and newline so braces and attributes can be
    matched without being confused by SQL text.  Each literal is returned as
    (start offset, end offset, decoded body); a normal string's line
    continuations are folded the way rustc folds them.
    """

    masked = list(text)
    literals: list[tuple[int, int, str]] = []
    index = 0
    length = len(text)

    def blank(start: int, end: int) -> None:
        for position in range(start, end):
            if masked[position] not in "\r\n":
                masked[position] = " "

    while index < length:
        character = text[index]
        following = text[index + 1] if index + 1 < length else ""
        if character == "/" and following == "/":
            end = text.find("\n", index)
            end = length if end < 0 else end
            blank(index, end)
            index = end
            continue
        if character == "/" and following == "*":
            depth = 1
            end = index + 2
            while end < length and depth:
                if text.startswith("/*", end):
                    depth += 1
                    end += 2
                elif text.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            blank(index, end)
            index = end
            continue
        raw = re.match(r'(?:b|c)?r(#*)"', text[index : index + 260])
        if raw and (index == 0 or not (text[index - 1].isalnum() or text[index - 1] == "_")):
            hashes = raw.group(1)
            body_start = index + raw.end()
            terminator = '"' + hashes
            body_end = text.find(terminator, body_start)
            if body_end < 0:
                fail("unterminated raw string literal")
            literals.append((index, body_end + len(terminator), text[body_start:body_end]))
            blank(body_start, body_end)
            index = body_end + len(terminator)
            continue
        if character == '"' or (
            character in "bc"
            and following == '"'
            and (index == 0 or not (text[index - 1].isalnum() or text[index - 1] == "_"))
        ):
            body_start = index + (1 if character == '"' else 2)
            cursor = body_start
            decoded: list[str] = []
            while cursor < length and text[cursor] != '"':
                if text[cursor] == "\\":
                    escaped = text[cursor + 1] if cursor + 1 < length else ""
                    if escaped == "\n":
                        cursor += 2
                        while cursor < length and text[cursor] in " \t\r\n":
                            cursor += 1
                        continue
                    decoded.append({"n": "\n", "t": "\t", "r": "\r"}.get(escaped, escaped))
                    cursor += 2
                    continue
                decoded.append(text[cursor])
                cursor += 1
            if cursor >= length:
                fail("unterminated string literal")
            literals.append((index, cursor + 1, "".join(decoded)))
            blank(body_start, cursor)
            index = cursor + 1
            continue
        if character == "'":
            # A char literal ('x', '\n', '\u{..}'); a lifetime has no closing quote.
            char_literal = re.match(r"'(?:\\(?:u\{[0-9a-fA-F]+\}|x[0-9a-fA-F]{2}|.)|[^\\'])'", text[index : index + 12])
            if char_literal:
                blank(index + 1, index + char_literal.end() - 1)
                index += char_literal.end()
                continue
        index += 1
    return "".join(masked), literals


def matching_bracket(masked: str, opening: int) -> int:
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack = [pairs[masked[opening]]]
    index = opening + 1
    while index < len(masked):
        character = masked[index]
        if character in pairs:
            stack.append(pairs[character])
        elif character in ")]}":
            if not stack or character != stack.pop():
                fail(f"unbalanced bracket at offset {index}")
            if not stack:
                return index
        index += 1
    fail(f"unterminated bracket at offset {opening}")


def item_end(masked: str, start: int) -> int:
    """Return the end of the item, statement, field or arm starting at start.

    A keyword-introduced item (fn, mod, impl, const, ...) ends only at `;` or
    its block, because commas in its generics or signature do not end it.  A
    field, arm or expression also ends at a top-level comma; stopping early
    there only narrows the exclusion, never widens it.
    """

    keyword = ITEM_KEYWORD.match(masked, start)
    commas_end_item = keyword is None
    index = start
    while index < len(masked):
        character = masked[index]
        if character == "#" and masked[index + 1 : index + 2] == "[":
            index = matching_bracket(masked, index + 1) + 1
            continue
        if character in "([":
            index = matching_bracket(masked, index) + 1
            continue
        if character == "{":
            return matching_bracket(masked, index) + 1
        if character == ";" or (character == "," and commas_end_item):
            return index + 1
        if character in ")]}":
            return index
        index += 1
    return index


def test_only_regions(text: str, masked: str) -> list[tuple[int, int]]:
    regions: list[tuple[int, int]] = []
    for attribute in CFG_ATTRIBUTE.finditer(masked):
        opening = masked.index("(", attribute.start())
        closing = matching_bracket(masked, opening)
        # The mask blanks string bodies, so read the predicate from the source.
        predicate = re.sub(r"\s+", " ", text[opening + 1 : closing]).strip()
        if not TEST_ONLY_PREDICATE.match(predicate):
            continue
        bracket_end = masked.index("]", closing) + 1
        regions.append((attribute.start(), item_end(masked, bracket_end)))
    return regions


def locked_relations(sql: str) -> list[tuple[int, str, list[str]]]:
    """Return (offset, strength, relations) for each locking clause in sql."""

    results: list[tuple[int, str, list[str]]] = []
    for clause in LOCK_CLAUSE.finditer(sql):
        before = sql[: clause.start()]
        statement = before[before.rfind(";") + 1 :]
        depth = 0
        start = 0
        for position in range(len(statement) - 1, -1, -1):
            character = statement[position]
            if character == ")":
                depth += 1
            elif character == "(":
                if depth == 0:
                    start = position + 1
                    break
                depth -= 1
        select = statement[start:]
        flattened = None
        while flattened != select:
            flattened = select
            select = re.sub(r"\((?:[^()]*)\)", lambda match: "(" + " " * (len(match.group(0)) - 2) + ")", select)
        from_items = []
        for item in FROM_ITEM.finditer(select):
            if item.group("call"):
                continue  # A set-returning function is not a lockable relation.
            relation = re.sub(r"\s+", "", item.group("relation")).lower()
            relation = relation.split(".")[-1] if not relation.startswith("{") else relation
            alias = (item.group("alias") or relation).lower()
            from_items.append((relation, alias))
        if clause.group("of"):
            named = [
                re.sub(r"\s+", "", name).split(".")[-1].lower()
                for name in clause.group("of").split(",")
            ]
            by_alias = {alias: relation for relation, alias in from_items}
            relations = [by_alias.get(name, name) for name in named]
        else:
            relations = [relation for relation, _alias in from_items]
        strength = re.sub(r"\s+", " ", clause.group(1).upper())
        results.append((clause.start(), strength, relations))
    return results


def production_files() -> list[Path]:
    roots = sorted(
        {
            path
            for pattern in ("crates/**/src/lib.rs", "crates/**/src/main.rs", "crates/**/src/bin/*.rs")
            for path in ROOT.glob(pattern)
        }
        | {path for path in (ROOT / "src/main.rs", ROOT / "src/lib.rs") if path.exists()}
    )
    if not roots:
        fail("no production crate roots were found")
    files: set[Path] = set()
    for root in roots:
        try:
            output = subprocess.check_output(
                [
                    "node",
                    "scripts/lib/source-module.mjs",
                    "files",
                    "--production",
                    root.relative_to(ROOT).as_posix(),
                ],
                cwd=ROOT,
                text=True,
                stderr=subprocess.PIPE,
            )
        except (OSError, subprocess.CalledProcessError) as error:
            detail = error.stderr.strip() if isinstance(error, subprocess.CalledProcessError) else error
            fail(f"could not enumerate production modules of {root.relative_to(ROOT)}: {detail}")
        files.update(ROOT / name for name in output.splitlines() if name)
    return sorted(files)


def scan(text: str, read_only: set[str]) -> list[tuple[int, str, str]]:
    """Return (line, strength, relation) for every forbidden or unresolvable lock."""

    masked, literals = mask_rust(text)
    regions = test_only_regions(text, masked)
    findings: list[tuple[int, str, str]] = []
    for start, end, body in literals:
        if any(region_start <= start and end <= region_end for region_start, region_end in regions):
            continue
        for offset, strength, relations in locked_relations(body):
            line = text.count("\n", 0, start) + 1 + body.count("\n", 0, offset)
            for relation in relations:
                if relation.startswith("{"):
                    findings.append((line, strength, f"dynamic relation {relation}"))
                elif relation in read_only:
                    findings.append((line, strength, relation))
    return findings


def self_test(read_only: set[str]) -> None:
    cases = {
        'sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")': ["users"],
        'q("SELECT TRUE FROM users AS actor JOIN api_sessions AS session ON session.user_id=actor.id\n'
        '     WHERE actor.id=$1 FOR UPDATE OF actor,session")': ["users"],
        'q("SELECT token.id FROM fast_tokens token JOIN users ON users.id=token.user_id FOR UPDATE OF token")': [],
        'q("SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 FOR SHARE)")': ["users"],
        'q("SELECT locked.id FROM northstar_lock_user_rows_update(ARRAY[$1::uuid]) locked")': [],
        'q("INSERT INTO legal_hold_scopes(a,b) SELECT $1,id FROM users WHERE id=$2 FOR KEY SHARE")': ["users"],
        'format!("SELECT id FROM {table} WHERE id=$1 FOR KEY SHARE")': ["dynamic relation {table}"],
        'q(r#"SELECT id FROM users\n WHERE id=$1 FOR NO KEY UPDATE"#)': ["users"],
        'q("SELECT id FROM users \\\n    WHERE id=$1 FOR SHARE")': ["users"],
        '// q("SELECT id FROM users FOR UPDATE")\nlet x = 1;': [],
        '#[cfg(test)]\nmod tests { fn f() { q("SELECT id FROM users FOR UPDATE"); } }': [],
        '#[cfg(any(test, feature = "test-support"))]\npub async fn f(a: [u8; 2]) { q("SELECT id FROM users FOR UPDATE"); }\n'
        'fn g() { q("SELECT id FROM users FOR SHARE"); }': ["users"],
        '#[cfg(not(test))]\nfn f() { q("SELECT id FROM users FOR UPDATE"); }': ["users"],
        '#[cfg(any(test, feature = "test-support"))]\nasync fn f(tx: &mut T<\'_, P>) -> Result<(), E> {\n'
        '    q("SELECT id FROM users FOR UPDATE");\n}': [],
        'fn f() { let c = \'"\'; q("SELECT id FROM users FOR UPDATE"); }': ["users"],
    }
    for source, expected in cases.items():
        actual = [relation for _line, _strength, relation in scan(source, read_only)]
        if actual != expected:
            fail(f"self-test drifted for {source!r}: expected {expected}, got {actual}")


def production_literals(text: str) -> list[tuple[int, str]]:
    """Return (line, body) for every string literal outside test-only items."""

    masked, literals = mask_rust(text)
    regions = test_only_regions(text, masked)
    return [
        (text.count("\n", 0, start) + 1, body)
        for start, end, body in literals
        if not any(region_start <= start and end <= region_end for region_start, region_end in regions)
    ]


def capability_replay_statements(files: list[Path]) -> list[tuple[str, str]]:
    statements: list[tuple[str, str]] = []
    for path in files:
        relative = path.relative_to(ROOT).as_posix()
        for line, body in production_literals(path.read_text(encoding="utf-8")):
            if not RUNTIME_LOCK_CAPABILITY_CALL.search(body):
                continue
            sql = body.strip().rstrip(";").rstrip()
            if not REPLAY_STATEMENT_START.match(sql) or ";" in sql or "\\" in sql:
                fail(f"{relative}:{line} calls a runtime lock capability outside one replayable statement")
            statements.append((f"{relative}:{line}", sql))
    if not statements:
        fail("no production statement calls a runtime account lock capability")
    for capability in ("key_share", "share", "update"):
        if not any(f"northstar_lock_user_rows_{capability}(" in sql for _label, sql in statements):
            fail(f"no production statement calls northstar_lock_user_rows_{capability}")
    return statements


# The replay first runs the pre-0162 statement shape.  The database must report
# 42501 for it, which proves the harness surfaces a privilege failure.
REPLAY_CANARY = ("canary:direct-account-lock", "SELECT id FROM users WHERE id=$1 FOR UPDATE")


def emit_capability_replay(statements: list[tuple[str, str]]) -> str:
    lines = [
        "-- Generated by scripts/check-runtime-row-locks.py --emit-runtime-capability-replay.",
        "\\set ON_ERROR_STOP off",
        "\\o /dev/null",
    ]
    for label, sql in [REPLAY_CANARY, *statements]:
        lines += [
            "BEGIN;",
            "PREPARE northstar_ci_replay AS",
            f"{sql};",
            "\\if :ERROR",
            f"\\echo REPLAY {label} PREPARE :LAST_ERROR_SQLSTATE",
            "\\else",
            "SELECT CASE WHEN pg_catalog.cardinality(parameter_types)=0",
            "            THEN 'EXECUTE northstar_ci_replay'",
            "            ELSE 'EXECUTE northstar_ci_replay(' || pg_catalog.array_to_string(",
            "                   pg_catalog.array_fill('NULL'::pg_catalog.text,",
            "                     ARRAY[pg_catalog.cardinality(parameter_types)]),',') || ')'",
            "       END AS northstar_ci_replay_execute",
            "  FROM pg_catalog.pg_prepared_statements WHERE name='northstar_ci_replay' \\gset",
            ":northstar_ci_replay_execute;",
            "\\if :ERROR",
            f"\\echo REPLAY {label} EXECUTE :LAST_ERROR_SQLSTATE",
            "\\else",
            f"\\echo REPLAY {label} EXECUTE 00000",
            "\\endif",
            "\\endif",
            "ROLLBACK;",
            # A prepared statement belongs to the session, not the transaction.
            "DEALLOCATE ALL;",
            "\\unset northstar_ci_replay_execute",
        ]
    lines.append(f"\\echo REPLAY-COUNT {len(statements)}")
    return "\n".join(lines) + "\n"


def main() -> None:
    try:
        manifest_text = MANIFEST.read_text(encoding="utf-8")
    except OSError as error:
        fail(f"could not read {MANIFEST.relative_to(ROOT)}: {error}")
    read_only = runtime_read_only_relations(manifest_text)
    self_test(read_only)
    arguments = sys.argv[1:]
    if arguments == ["--emit-runtime-capability-replay"]:
        sys.stdout.write(emit_capability_replay(capability_replay_statements(production_files())))
        return
    if arguments:
        fail("usage: check-runtime-row-locks.py [--emit-runtime-capability-replay]")

    violations: list[str] = []
    exempted: dict[str, Counter[str]] = {path: Counter() for path in NON_RUNTIME_LOCKS}
    files = production_files()
    for path in files:
        relative = path.relative_to(ROOT).as_posix()
        findings = scan(path.read_text(encoding="utf-8"), read_only)
        for line, strength, relation in findings:
            if relative in NON_RUNTIME_LOCKS and not relation.startswith("dynamic"):
                exempted[relative][relation] += 1
                continue
            violations.append(f"{relative}:{line} FOR {strength} locks {relation}")
    for relative, (reason, expected) in NON_RUNTIME_LOCKS.items():
        if (ROOT / relative) not in files:
            fail(f"non-runtime exemption names a missing production module: {relative}")
        if dict(exempted[relative]) != expected:
            fail(
                f"non-runtime exemption drifted for {relative} ({reason}): "
                f"expected {expected}, found {dict(exempted[relative])}"
            )
    if violations:
        fail(
            "runtime SQL locks relations whose runtime manifest row has no UPDATE "
            "(use a reviewed SECURITY DEFINER lock capability):\n  "
            + "\n  ".join(violations)
        )
    print(
        "runtime row-lock check passed: "
        f"{len(files)} production modules, {len(read_only)} runtime read-only relations, "
        f"{len(NON_RUNTIME_LOCKS)} non-runtime modules"
    )


if __name__ == "__main__":
    main()
