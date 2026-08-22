#!/usr/bin/env python3
"""Run a PostgreSQL client without exposing a password-bearing URL to the child."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from urllib.parse import parse_qsl, unquote, urlsplit


ENVIRONMENT_BY_PARAMETER = {
    "application_name": "PGAPPNAME",
    "channel_binding": "PGCHANNELBINDING",
    "connect_timeout": "PGCONNECT_TIMEOUT",
    "dbname": "PGDATABASE",
    "gssencmode": "PGGSSENCMODE",
    "host": "PGHOST",
    "hostaddr": "PGHOSTADDR",
    "keepalives": "PGKEEPALIVES",
    "keepalives_count": "PGKEEPALIVESCOUNT",
    "keepalives_idle": "PGKEEPALIVESIDLE",
    "keepalives_interval": "PGKEEPALIVESINTERVAL",
    "krbsrvname": "PGKRBSRVNAME",
    "load_balance_hosts": "PGLOADBALANCEHOSTS",
    "options": "PGOPTIONS",
    "passfile": "PGPASSFILE",
    "port": "PGPORT",
    "require_auth": "PGREQUIREAUTH",
    "requirepeer": "PGREQUIREPEER",
    "service": "PGSERVICE",
    "servicefile": "PGSERVICEFILE",
    "sslcert": "PGSSLCERT",
    "sslcrl": "PGSSLCRL",
    "sslcrldir": "PGSSLCRLDIR",
    "sslkey": "PGSSLKEY",
    "sslmode": "PGSSLMODE",
    "sslnegotiation": "PGSSLNEGOTIATION",
    "sslpassword": "PGSSLPASSWORD",
    "sslrootcert": "PGSSLROOTCERT",
    "sslsni": "PGSSLSNI",
    "target_session_attrs": "PGTARGETSESSIONATTRS",
    "tcp_user_timeout": "PGTCPUSER_TIMEOUT",
    "user": "PGUSER",
}


def fail(message: str) -> "NoReturn":
    raise SystemExit(message)


def load_url(explicit_file: str | None) -> str:
    environment_file = os.environ.get("DATABASE_URL_FILE")
    database_url = os.environ.get("DATABASE_URL")
    if explicit_file and environment_file and explicit_file != environment_file:
        fail("DATABASE_URL_FILE conflicts with --database-url-file")
    selected_file = explicit_file or environment_file
    if selected_file and database_url:
        fail("DATABASE_URL and DATABASE_URL_FILE are mutually exclusive")
    if selected_file:
        path = Path(selected_file)
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 65536:
            fail("database URL secret must be a regular file no larger than 64 KiB")
        value = path.read_text(encoding="utf-8").rstrip("\r\n")
    else:
        value = database_url or ""
    if not value:
        fail("set DATABASE_URL or pass --database-url-file")
    return value


def connection_environment(database_url: str) -> tuple[dict[str, str], str | None]:
    parsed = urlsplit(database_url)
    if parsed.scheme not in {"postgres", "postgresql"}:
        fail("database URL must use the postgres or postgresql scheme")
    if parsed.fragment:
        fail("database URL fragments are not supported")

    parameters: dict[str, str] = {}
    password = unquote(parsed.password) if parsed.password is not None else None
    if parsed.username is not None:
        parameters["user"] = unquote(parsed.username)
    if parsed.hostname is not None:
        parameters["host"] = unquote(parsed.hostname)
    try:
        if parsed.port is not None:
            parameters["port"] = str(parsed.port)
    except ValueError as error:
        fail(f"invalid database URL port: {error}")
    if parsed.path and parsed.path != "/":
        parameters["dbname"] = unquote(parsed.path[1:])

    for key, value in parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True):
        if key == "password":
            password = value
        elif key in ENVIRONMENT_BY_PARAMETER:
            parameters[key] = value
        else:
            fail(f"unsupported PostgreSQL connection option: {key}")

    environment = os.environ.copy()
    for variable in set(ENVIRONMENT_BY_PARAMETER.values()) | {"PGPASSWORD"}:
        environment.pop(variable, None)
    environment.pop("DATABASE_URL", None)
    environment.pop("DATABASE_URL_FILE", None)
    for parameter, value in parameters.items():
        environment[ENVIRONMENT_BY_PARAMETER[parameter]] = value
    return environment, password


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database-url-file")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    command = arguments.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        fail("a PostgreSQL client command is required after --")

    environment, password = connection_environment(load_url(arguments.database_url_file))
    with tempfile.TemporaryDirectory(prefix="northstar-pgpass-") as temporary_directory:
        if password is not None:
            if "\n" in password or "\r" in password:
                fail("database passwords containing line endings are not supported")
            escaped_password = password.replace("\\", "\\\\").replace(":", "\\:")
            passfile = Path(temporary_directory, "pgpass")
            passfile.write_text(f"*:*:*:*:{escaped_password}\n", encoding="utf-8")
            passfile.chmod(0o600)
            environment["PGPASSFILE"] = str(passfile)
        return subprocess.run(command, env=environment, check=False).returncode


if __name__ == "__main__":
    sys.exit(main())
