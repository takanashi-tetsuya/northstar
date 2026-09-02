#!/usr/bin/env python3
"""Run a PostgreSQL client without exposing a password-bearing URL to the child."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
from typing import NoReturn
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


def fail(message: str) -> NoReturn:
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


def install_password_memfd(password: str, environment: dict[str, str]) -> None:
    """Expose a 0600 libpq passfile without creating a filesystem pathname.

    The wrapper immediately execs the PostgreSQL client, so the registered
    process ID remains the exact client process.  Keeping this descriptor
    inheritable is intentional: libpq opens the same anonymous regular file
    through /proc after exec and the kernel closes it when the client exits.
    """

    if "\n" in password or "\r" in password:
        fail("database passwords containing line endings are not supported")
    if not hasattr(os, "memfd_create") or not Path("/proc/self/fd").is_dir():
        fail("a Linux memfd and /proc are required for password-safe PostgreSQL execution")

    escaped_password = password.replace("\\", "\\\\").replace(":", "\\:")
    payload = f"*:*:*:*:{escaped_password}\n".encode("utf-8")
    descriptor = os.memfd_create("northstar-pgpass", flags=0)
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                fail("could not write the anonymous PostgreSQL password file")
            view = view[written:]
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.set_inheritable(descriptor, True)
        environment["PGPASSFILE"] = f"/proc/self/fd/{descriptor}"
    except BaseException:
        os.close(descriptor)
        raise


def main() -> NoReturn:
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
    if password is not None:
        install_password_memfd(password, environment)
    try:
        os.execvpe(command[0], command, environment)
    except OSError as error:
        fail(f"could not execute PostgreSQL client: {error}")


if __name__ == "__main__":
    main()
