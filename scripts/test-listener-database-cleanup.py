#!/usr/bin/env python3
"""Ownership, bounded concurrency, cancellation and parent-ledger regressions."""
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'scripts/listener-database-cleanup.py'
spec = importlib.util.spec_from_file_location('cleanup', SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
PREFIX = 'northstar_listener_federation_' + 'a' * 16
NAMES = [f'{PREFIX}_r1_p{i}_a' for i in range(1, 9)]


class CleanupTests(unittest.TestCase):
    def test_names_reject_duplicates_foreign_and_unbounded_input_before_sql(self):
        self.assertEqual(m.names_from_input(PREFIX, ('\n'.join(NAMES)+'\n').encode()), NAMES)
        for data in (b'', b'postgres\n', (NAMES[0]+'\n'+NAMES[0]).encode(), b'x'*8193,
                     (PREFIX+'_r1_p1_a;SELECT\n').encode()):
            with self.subTest(data=data[:60]), self.assertRaises(ValueError):
                m.names_from_input(PREFIX, data)
        with self.assertRaises(ValueError):
            m.names_from_input('northstar_listener_other', NAMES[0].encode())

    def test_owner_absence_and_errors_never_issue_drop(self):
        for reply, expected in [('absent', 'absent'), ('foreign', 'owner_mismatch'),
                                ('garbage', 'owner_query_failed')]:
            with self.subTest(reply=reply), mock.patch.object(m, 'query', return_value=reply) as query:
                self.assertEqual(m.cleanup_one(NAMES[0], 5432), expected)
                query.assert_called_once()
        with mock.patch.object(m, 'query', side_effect=m.QueryFailed()):
            self.assertEqual(m.cleanup_one(NAMES[0], 5432), 'owner_query_failed')

    def test_drop_requires_owner_and_confirmed_absence(self):
        for replies, expected in [(['owned', '', 'f'], 'dropped'),
                                  (['owned', '', 't'], 'postcheck_failed'),
                                  (['owned', m.QueryFailed()], 'drop_failed')]:
            with self.subTest(expected=expected), mock.patch.object(m, 'query', side_effect=replies) as query:
                self.assertEqual(m.cleanup_one(NAMES[0], 5432), expected)
                self.assertEqual(query.call_args_list[1].args[0], f'DROP DATABASE "{NAMES[0]}" WITH (FORCE)')

    def test_attestation_failure_prevents_all_deletion(self):
        with mock.patch.object(m, 'query', return_value='f'), mock.patch.object(m, 'cleanup_one') as one:
            result = m.cleanup(NAMES, 5432, 4)
        one.assert_not_called()
        self.assertTrue(all(row['status']=='attestation_failed' for row in result['results']))

    def test_parallelism_is_bounded_and_every_result_is_retained_in_input_order(self):
        active = peak = 0
        lock = threading.Lock()

        def one(name, _port):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(.03)
            with lock:
                active -= 1
            return 'drop_failed' if name == NAMES[3] else 'dropped'

        with mock.patch.object(m, 'query', return_value='t'), mock.patch.object(m, 'cleanup_one', side_effect=one):
            result = m.cleanup(NAMES, 5432, 4)
        self.assertGreater(peak, 1)
        self.assertLessEqual(peak, 4)
        rows = m.validate_result(result, NAMES)
        self.assertEqual([row['name'] for row in rows], NAMES)
        self.assertEqual(rows[3]['status'], 'drop_failed')

    def test_result_cannot_forget_missing_foreign_duplicate_or_unknown_outcomes(self):
        valid = {'schema_version': 1, 'results': [dict(name=name, status='dropped') for name in NAMES]}
        m.validate_result(valid, NAMES)
        for change in ('missing', 'foreign', 'duplicate', 'unknown', 'schema'):
            value = json.loads(json.dumps(valid))
            if change == 'missing': value['results'].pop()
            if change == 'foreign': value['results'][0]['name'] = 'postgres'
            if change == 'duplicate': value['results'][0] = value['results'][1]
            if change == 'unknown': value['results'][0]['status'] = 'success'
            if change == 'schema': value['schema_version'] = True
            with self.subTest(change=change), self.assertRaises(ValueError):
                m.validate_result(value, NAMES)

    def test_cancel_reaps_owned_psql_before_returning(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            fake = base / 'psql'
            fake.write_text('#!' + sys.executable + '\n' +
                "import os,sys,time\nfrom pathlib import Path\n"
                "if 'inet_server_addr' in sys.argv[-1]: print('t')\n"
                "else:\n Path(os.environ['CHILD_PID']).write_text(str(os.getpid()))\n time.sleep(60)\n")
            fake.chmod(0o700)
            pid_file = base / 'pid'
            process = subprocess.Popen([sys.executable, str(SOURCE), '--prefix', PREFIX, '--jobs', '1'],
                env={**os.environ, 'PATH': str(base)+os.pathsep+os.environ['PATH'], 'CHILD_PID': str(pid_file)},
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                process.stdin.write(NAMES[0]+'\n')
                process.stdin.close()
                process.stdin = None
                deadline = time.monotonic()+5
                while not pid_file.exists():
                    self.assertIsNone(process.poll())
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(.02)
                pid = int(pid_file.read_text())
                process.send_signal(signal.SIGTERM)
                out, err = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 1, err)
                self.assertEqual(json.loads(out)['results'][0]['status'], 'cancelled')
                with self.assertRaises(ProcessLookupError): os.kill(pid, 0)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=3)

    def test_parent_keeps_original_ledger_when_output_is_incomplete(self):
        source = (ROOT / 'scripts/listener-readiness-stress-wsl.sh').read_text()
        function = re.search(r'^drop_round_databases\(\) \{\n.*?^\}$', source, re.M|re.S).group(0)
        with tempfile.TemporaryDirectory() as directory:
            script = '\n'.join([
                'set -euo pipefail', 'umask 077', f'project_dir={shlex.quote(str(ROOT))}',
                f'runtime_dir={shlex.quote(directory)}', 'parent_diagnostic_raw="$runtime_dir/log"',
                f'database_prefix={PREFIX}', 'database_fixture_port=5432', 'database_cleanup_jobs=4',
                'declare -a round_databases=('+ ' '.join(NAMES)+')',
                'declare -A pair_database_a=([keep]=value) pair_database_b=([keep]=value)',
                'record_cleanup_debt() { :; }',
                # Simulate a missing helper response; verification must fail.
                'python3() { if [[ "$*" == *--verify-result* ]]; then command python3 "$@"; else cat >/dev/null; printf "{}"; fi; }',
                function, 'if drop_round_databases; then exit 3; fi',
                '[[ ${#round_databases[@]} == 8 && ${pair_database_a[keep]} == value ]]',
            ])
            result = subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
