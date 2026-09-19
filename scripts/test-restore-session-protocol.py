#!/usr/bin/env python3
"""Bounded restore marker tests, with optional private-fixture PostgreSQL evidence."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest


SOURCE = Path(__file__).with_name("restore-backup.sh").read_text(encoding="utf-8")


def function_source(name: str) -> str:
    start = SOURCE.index(f"{name}() {{\n")
    end = SOURCE.index("\n}\n", start) + 3
    return SOURCE[start:end]


class SessionResponseTests(unittest.TestCase):
    def run_response(self, records: list[bytes], *, keep_open: bool = False) -> subprocess.CompletedProcess[str]:
        reader, writer = os.pipe()
        stop = threading.Event()

        def produce() -> None:
            try:
                for record in records:
                    os.write(writer, record)
                    if keep_open and stop.wait(0.1):
                        return
                if keep_open:
                    stop.wait(4)
            except BrokenPipeError:
                pass
            finally:
                os.close(writer)

        producer = threading.Thread(target=produce)
        producer.start()
        try:
            with tempfile.TemporaryDirectory(prefix="northstar-restore-marker-") as directory:
                program = function_source("psql_session_wait_token") + "\n" + (
                    'session_response_timeout_seconds=1\n'
                    'psql_session_wait_token "$1" __DONE__ "$2"\n'
                )
                return subprocess.run(
                    ["bash", "-c", program, "restore-marker-test", str(reader), f"{directory}/response.out"],
                    pass_fds=(reader,), capture_output=True, text=True, timeout=4, check=False,
                )
        finally:
            os.close(reader)
            stop.set()
            producer.join(timeout=1)

    def test_only_exact_marker_completes_response(self) -> None:
        result = self.run_response([b"not-__DONE__\n", b"__DONE__\n"])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_eof_without_marker_is_not_success(self) -> None:
        result = self.run_response([b"committed\n"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outcome remains unproven", result.stderr)

    def test_idle_open_writer_cannot_block_forever(self) -> None:
        result = self.run_response([], keep_open=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("timed out", result.stderr)

    def test_output_does_not_reset_response_deadline(self) -> None:
        started = time.monotonic()
        result = self.run_response([b"progress\n"] * 35, keep_open=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertLess(time.monotonic() - started, 3)


class PostgresBarrierTests(unittest.TestCase):
    def test_generated_barrier_arbitrates_committed_and_aborted_xids(self) -> None:
        # This mode is called only by backup-restore-wsl.sh after it has created
        # its private Unix-socket-only cluster and disposable login. Refuse any
        # ambient/shared target before executing even a read-only statement.
        socket = os.environ.get("PGHOST", "")
        self.assertRegex(socket, r"^/tmp/northstar-backup-restore\.[A-Za-z0-9]+/socket$")
        self.assertEqual(os.environ.get("PGDATABASE"), "postgres")
        self.assertEqual(os.environ.get("PGUSER"), "northstar_test_bootstrap")
        with tempfile.TemporaryDirectory(prefix="northstar-restore-barrier-") as directory:
            for outcome, finish in (("committed", "COMMIT"), ("aborted", "ROLLBACK")):
                with self.subTest(outcome=outcome):
                    xid = subprocess.run(
                        ["psql", "-XqAt", "-v", "ON_ERROR_STOP=1"],
                        input=f"BEGIN; SELECT pg_catalog.pg_current_xact_id(); {finish};\n",
                        capture_output=True, text=True, timeout=5, check=True,
                    ).stdout.strip()
                    self.assertRegex(xid, r"^[1-9][0-9]*$")
                    program = function_source("wait_for_restore_transaction_barrier") + "\n" + r'''
set -euo pipefail
work_dir="$1"
restore_id=00000000000000000000000000000001
database_outcome_unknown=false
target_coordinator_command() {
  psql -XqAt -v ON_ERROR_STOP=1 --file "$1" >"$2"
}
wait_for_restore_transaction_barrier "northstar-restore-$restore_id-incoming" restored incoming "$2"
[[ "$database_outcome_unknown" == false && "$last_restore_transaction_status" == "$3" ]]
'''
                    result = subprocess.run(
                        ["bash", "-c", program, "restore-barrier-test", directory, xid, outcome],
                        capture_output=True, text=True, timeout=5, check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--postgres", action="store_true", help="include the private fixture's real transaction-status test")
    arguments = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(SessionResponseTests)
    if arguments.postgres:
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(PostgresBarrierTests))
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
