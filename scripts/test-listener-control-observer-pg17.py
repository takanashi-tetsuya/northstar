#!/usr/bin/env python3
"""Real observer/wrapper integration against a private, disposable PG17 cluster.

Usage: python3 scripts/test-listener-control-observer-pg17.py --pg-bin /path/to/bin
No external DSN, system service, application secrets, or workload substitution.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('observed_entry', ROOT / 'scripts/listener-readiness-observed-wsl.py')
ENTRY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ENTRY)
PG_BIN = None

RUNNER = r'''
import importlib.util, os, signal, sys
from pathlib import Path
root, control, source = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
sys.path.insert(0, str(root / 'scripts'))
spec = importlib.util.spec_from_file_location('entry', root / 'scripts/listener-readiness-observed-wsl.py')
entry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entry)
for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    signal.signal(sig, entry.stop_requested)
raise SystemExit(entry.run_observed(
    [sys.executable, '-c', source],
    [sys.executable, str(root / 'scripts/lib/listener-control-observer.py'),
     '--output-dir', str(control / 'observer'), '--failure-marker', str(control / 'first-failure.json'),
     '--database-hash-salt-file', str(control / 'database-hash-salt'),
     '--parent-pid', str(os.getpid()), '--max-seconds', '40'],
    control_dir=control, output_dir=control / 'observer', environment=dict(os.environ), expected_pairs=1))
'''


def environment():
    return {key: value for key, value in os.environ.items()
            if not key.startswith(('PG', 'NORTHSTAR_LISTENER_STRESS_'))}


class PostgreSQLIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.getuid() == 0:
            raise RuntimeError('run the isolated fixture as an ordinary user')
        version = subprocess.check_output([str(PG_BIN / 'postgres'), '--version'], text=True, timeout=5)
        if not version.startswith('postgres (PostgreSQL) 17.'):
            raise RuntimeError('the fixture requires PostgreSQL 17')
        cls.temp = tempfile.TemporaryDirectory(prefix='northstar-observer-pg17.')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        cls.root.chmod(0o700)
        password = cls.root / 'password'
        password.write_text('xmpp-test-password\n')
        password.chmod(0o600)
        cls.env = environment()
        subprocess.run([str(PG_BIN / 'initdb'), '-D', str(cls.root / 'data'),
                        '--username=xmpp_test', '--auth-local=trust', '--auth-host=scram-sha-256',
                        '--pwfile=' + str(password), '--no-locale', '--encoding=UTF8'],
                       env=cls.env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                       check=True, timeout=30)
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            cls.port = reservation.getsockname()[1]
        cls.log = (cls.root / 'postgres.log').open('wb')
        cls.addClassCleanup(cls.log.close)
        cls.server = subprocess.Popen(
            [str(PG_BIN / 'postgres'), '-D', str(cls.root / 'data'), '-k', str(cls.root),
             '-h', '127.0.0.1', '-p', str(cls.port), '-c', 'max_connections=16',
             '-c', 'shared_buffers=16MB', '-c', 'fsync=on'],
            env=cls.env, stdout=cls.log, stderr=subprocess.STDOUT, start_new_session=True,
        )
        cls.addClassCleanup(cls.stop_server)
        cls.env.update(PGHOST='127.0.0.1', PGPORT=str(cls.port), PGUSER='xmpp_test',
                       PGPASSWORD='xmpp-test-password', PGDATABASE='postgres', PGCONNECT_TIMEOUT='2')
        deadline = time.monotonic() + 10
        while True:
            if cls.server.poll() is not None:
                raise RuntimeError('private PostgreSQL exited during startup')
            ready = subprocess.run([str(PG_BIN / 'pg_isready'), '-q'], env=cls.env, timeout=3)
            if ready.returncode == 0:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError('private PostgreSQL startup deadline')
            time.sleep(.1)
        for name in ('northstar_observer_case_a', 'northstar_observer_case_b'):
            subprocess.run([str(PG_BIN / 'psql'), '-XqAt', '-v', 'ON_ERROR_STOP=1',
                            '-c', 'CREATE DATABASE ' + name], env=cls.env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True, timeout=5)
        print('Private PG17 fixture: fsync=on, two control connections, one observer connection', flush=True)

    @classmethod
    def stop_server(cls):
        if cls.server.poll() is None:
            # Popen retains ownership of this exact unreaped child PID.
            cls.server.send_signal(signal.SIGINT)
            try:
                cls.server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                cls.server.kill()
                cls.server.wait(timeout=5)
                raise AssertionError('private PostgreSQL did not shut down cleanly')
        if cls.server.returncode != 0:
            raise AssertionError('private PostgreSQL exited unsuccessfully')

    def setUp(self):
        self.control = Path(tempfile.mkdtemp(prefix='case.', dir=self.root))
        self.control.chmod(0o700)
        self.salt = os.urandom(16).hex()
        salt_path = self.control / 'database-hash-salt'
        salt_path.write_text(self.salt)
        salt_path.chmod(0o600)
        self.wrapper_env = environment()
        self.wrapper_env.update(
            NORTHSTAR_LISTENER_STRESS_DATABASE_PORT=str(self.port),
            NORTHSTAR_LISTENER_STRESS_OBSERVER_SALT_FILE=str(salt_path),
            NORTHSTAR_LISTENER_STRESS_OBSERVER_MAP_FILE=str(self.control / 'database-map.json'),
        )
        self.databases = ('northstar_observer_case_a', 'northstar_observer_case_b')
        ENTRY.publish_case_map(3, 1, ''.join(f'1\t{node}\t{database}\n'
                               for node, database in zip(('A', 'B'), self.databases)).encode(), self.wrapper_env)
        self.backends = []
        self.identities = {}
        for node, database in zip(('A', 'B'), self.databases):
            process = subprocess.Popen([str(PG_BIN / 'psql'), '-XqAt', '-v', 'ON_ERROR_STOP=1'],
                env={**self.env, 'PGDATABASE': database, 'PGAPPNAME': 'northstar-runtime-control'},
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            self.backends.append(process)
            self.addCleanup(self.close_backend, process)
            process.stdin.write("SELECT json_build_object('pid',pid,'backend_start',backend_start) "
                                "FROM pg_stat_activity WHERE pid=pg_backend_pid();\n")
            process.stdin.flush()
            self.assertTrue(select.select([process.stdout], [], [], 5)[0], 'control connection startup')
            self.identities[node] = json.loads(process.stdout.readline())

    def close_backend(self, process):
        if not process.stdin.closed:
            process.stdin.close()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
            self.fail('control connection did not close')
        finally:
            process.stdout.close()

    def start_wrapper(self, source):
        process = subprocess.Popen([sys.executable, '-c', RUNNER, str(ROOT), str(self.control), source],
                                   env=self.wrapper_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(self.close_wrapper, process)
        return process

    def close_wrapper(self, process):
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
        try:
            process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)
            self.fail('wrapper did not cancel within its cleanup budget')

    def result(self, process, status, expected_peak=2):
        output, error = process.communicate(timeout=30)
        self.assertEqual(process.returncode, status, output + error)
        result = json.loads((self.control / 'observer/observer-result.json').read_text())
        wrapper = json.loads((self.control / 'wrapper-result.json').read_text())
        observations = (self.control / 'observer/observations.jsonl').read_text()
        records = [json.loads(line) for line in observations.splitlines()]
        retained = [path for path in self.control.rglob('*') if path.is_file() and path.name != 'database-hash-salt']
        self.assertLessEqual(sum(path.stat().st_size for path in retained), 8 * 1024 * 1024)
        for path in retained:
            data = path.read_text()
            for secret in (*self.databases, self.salt, 'xmpp-test-password', 'pg_sleep'):
                self.assertNotIn(secret, data)
        self.assertEqual(result['peak_runtime_backends'], expected_peak)
        # Only this observer's backend has ended; the two control owners remain.
        if expected_peak:
            self.assertEqual(result['observer_backend_pid'], json.loads(
                (self.control / 'observer/observer-ready.json').read_text())['observer_backend_pid'])
        return result, wrapper, records

    def wait_ready(self, process):
        deadline = time.monotonic() + 10
        while not (self.control / 'observer/observer-ready.json').exists():
            self.assertIsNone(process.poll())
            self.assertLess(time.monotonic(), deadline)
            time.sleep(.02)

    def test_failure_wait_mapping_and_fixed_post_window(self):
        for backend in self.backends:
            backend.stdin.write('SELECT pg_sleep(6);\n')
            backend.stdin.flush()
        process = self.start_wrapper('import time;time.sleep(2);raise SystemExit(7)')
        result, wrapper, records = self.result(process, 7)
        self.assertTrue(wrapper['diagnostic_ok'], wrapper)
        self.assertTrue(result['post_window_complete'])
        self.assertEqual(result['sample_errors'], 0)
        marker = next(row for row in records if row['type'] == 'first_failure')
        self.assertAlmostEqual(marker['capture_until_monotonic'] - marker['monotonic_ns'] / 1e9, 15)
        self.assertGreaterEqual(time.monotonic(), marker['capture_until_monotonic'])
        mapping = json.loads((self.control / 'database-map.json').read_text())['cases']
        for case in mapping:
            identity = self.identities[case['node']]
            rows = [row for record in records if record['type'] == 'sample' for row in record['rows']
                    if row['pid'] == identity['pid'] and row['backend_start'] == identity['backend_start']]
            self.assertTrue(rows)
            self.assertTrue(all(row['database_hash'] == case['database_hash'] for row in rows))
            self.assertTrue(any(row['state'] == 'active' and row['wait_event'] == 'PgSleep' for row in rows))
            self.assertTrue(any(row['state'] == 'idle' for row in rows))

    def test_success_and_normal_disappearance_do_not_dump_ring(self):
        process = self.start_wrapper('import time;time.sleep(2)')
        self.wait_ready(process)
        self.close_backend(self.backends[1])
        result, wrapper, records = self.result(process, 0)
        self.assertTrue(wrapper['diagnostic_ok'], wrapper)
        self.assertGreaterEqual(result['backend_disappearances_unclassified'], 1)
        self.assertFalse(result['failure_marker_seen'])
        self.assertEqual([row['type'] for row in records], ['metadata', 'terminal'])

    def test_failed_attestation_cannot_make_successful_driver_green(self):
        def set_createdb(enabled):
            subprocess.run([str(PG_BIN / 'psql'), '-XqAt', '-v', 'ON_ERROR_STOP=1', '-c',
                            'ALTER ROLE xmpp_test ' + ('CREATEDB' if enabled else 'NOCREATEDB')],
                           env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                           check=True, timeout=5)

        set_createdb(False)
        try:
            result, wrapper, records = self.result(self.start_wrapper('raise SystemExit(0)'), 2, 0)
            self.assertEqual(result['error_code'], 'observer_database_attestation_failed')
            self.assertFalse(wrapper['observer_ready'])
            self.assertFalse(wrapper['diagnostic_ok'])
            self.assertEqual(wrapper['driver_exit_status'], 0)
            self.assertEqual([row['type'] for row in records], ['metadata', 'terminal'])
        finally:
            set_createdb(True)

    def test_parent_cancel_reaps_observer_and_reports_incomplete_window(self):
        driver_ready = self.control / 'driver-ready'
        process = self.start_wrapper('import time;from pathlib import Path;'
                                     f'Path({str(driver_ready)!r}).touch();time.sleep(60)')
        deadline = time.monotonic() + 10
        while not driver_ready.exists():
            self.assertIsNone(process.poll())
            self.assertLess(time.monotonic(), deadline)
            time.sleep(.02)
        process.send_signal(signal.SIGTERM)
        result, wrapper, _ = self.result(process, 143)
        self.assertTrue(wrapper['cleanup_ok'])
        self.assertFalse(wrapper['diagnostic_ok'])
        self.assertFalse(result['post_window_complete'])
        self.assertEqual(result['error_code'], 'post_window_incomplete')
        marker = json.loads((self.control / 'first-failure.json').read_text())
        self.assertEqual(marker['cause'], 'parent_cancel')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pg-bin', type=Path, required=True)
    args, remaining = parser.parse_known_args()
    PG_BIN = args.pg_bin.resolve()
    unittest.main(argv=[sys.argv[0], *remaining], verbosity=2)
