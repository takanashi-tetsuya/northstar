#!/usr/bin/env python3
"""Read-only OMEMO database diagnostics without printing cryptographic material."""

import sqlite3
import sys


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: inspect-gajim-omemo.py DATABASE")

    connection = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
    try:
        tables = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
            )
        ]
        for table in tables:
            columns = [row[1] for row in connection.execute(f"PRAGMA table_info({table})")]
            print(f"{table}: {', '.join(columns)}")

        if "identities" in tables:
            print("\nidentities (cryptographic keys omitted):")
            for row in connection.execute(
                """
                SELECT recipient_id, registration_id, trust, shown, timestamp
                FROM identities
                ORDER BY recipient_id, registration_id
                """
            ):
                print(
                    "  recipient={!r} device={} trust={} shown={} timestamp={}".format(
                        *row
                    )
                )

        if "sessions" in tables:
            print("\nsessions (session records omitted):")
            for row in connection.execute(
                """
                SELECT recipient_id, device_id, active, timestamp
                FROM sessions
                ORDER BY recipient_id, device_id
                """
            ):
                print(
                    "  recipient={!r} device={} active={} timestamp={}".format(*row)
                )
    finally:
        connection.close()


if __name__ == "__main__":
    main()
