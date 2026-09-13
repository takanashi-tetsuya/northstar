#!/usr/bin/env python3
"""Exercise the fixture monitor with real owned children and process handles."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

SOURCE = Path(__file__).with_name('run-test-with-servers.py')


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='northstar-server-monitor.')
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.children = []
        self.servers = [self.child('import time; time.sleep(30)') for _ in range(2)]

    def child(self, program):
        process = subprocess.Popen([sys.executable, '-c', program])
        self.children.append(process)
        return process

    def monitor(self, program, servers=None):
        environment = dict(os.environ, NORTHSTAR_LISTENER_STRESS_FAILURE_MARKER=str(self.root / 'first-failure.json'))
        arguments = [sys.executable, str(SOURCE)]
        for server in servers or self.servers:
            arguments += ['--server', str(server.pid)]
        process = subprocess.Popen(arguments + ['--', sys.executable, '-c', program],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment)
        self.children.append(process)
        return process

    def ready(self, process):
        deadline = time.monotonic() + 3
        path = self.root / 'workload.json'
        while not path.exists():
            self.assertIsNone(process.poll(), 'monitor exited before workload startup')
            if time.monotonic() >= deadline:
                self.fail('workload did not start')
            time.sleep(.01)
        return json.loads(path.read_text())

    def waiting_program(self, ignore_term=False):
        return ('import json,os,signal,time; from pathlib import Path; '
                + ('signal.signal(signal.SIGTERM, signal.SIG_IGN); ' if ignore_term else '')
                + f'path=Path({str(self.root / "workload.tmp")!r}); path.write_text(json.dumps([os.getpid(),os.getpgrp()])); '
                + f'path.replace({str(self.root / "workload.json")!r}); '
                + 'time.sleep(30)')

    def tearDown(self):
        for child in reversed(self.children):
            if child.poll() is None:
                child.kill()
            child.wait(timeout=3)
            if child.stdout:
                child.stdout.close()
            if child.stderr:
                child.stderr.close()
        self.temporary.cleanup()

    def test_success_and_workload_failure_preserve_exit_status(self):
        for code in (0, 7):
            process = self.monitor(f'import sys; sys.exit({code})')
            output = process.communicate(timeout=3)
            self.assertEqual(process.returncode, code, output)
            self.assertTrue(all(server.poll() is None for server in self.servers))
            if code == 0:
                self.assertFalse((self.root / 'first-failure.json').exists())
            else:
                self.assertEqual(json.loads((self.root / 'first-failure.json').read_text())['cause'], 'command_exit')

    def test_server_exit_interrupts_polling_and_publishes_marker_promptly(self):
        process = self.monitor(self.waiting_program())
        pid, group = self.ready(process)
        self.assertEqual(group, os.getpgrp(), 'workload escaped outer supervisor process group')
        started = time.monotonic()
        self.servers[1].terminate()
        output = process.communicate(timeout=3)
        self.assertEqual(process.returncode, 1, output)
        marker = json.loads((self.root / 'first-failure.json').read_text())
        self.assertEqual(marker['cause'], 'lifecycle')
        self.assertLess(marker['monotonic_ns'] / 1e9 - started, 1)
        self.assertFalse(Path(f'/proc/{pid}').exists(), 'owned workload was not reaped')
        self.assertIsNone(self.servers[0].poll(), 'monitor signalled a server it does not own')

    def test_already_exited_server_never_launches_workload(self):
        self.servers[0].terminate()
        self.servers[0].wait(timeout=3)
        process = self.monitor(self.waiting_program())
        output = process.communicate(timeout=3)
        self.assertEqual(process.returncode, 1, output)
        self.assertFalse((self.root / 'workload.json').exists())

    def test_unrelated_parent_and_duplicate_server_are_rejected(self):
        for servers in ([self.servers[0], self.servers[0]], [self.servers[0], type('Process', (), {'pid': os.getpid()})()]):
            process = self.monitor(self.waiting_program(), servers)
            process.communicate(timeout=3)
            self.assertNotEqual(process.returncode, 0)
            self.assertFalse((self.root / 'workload.json').exists())
            self.assertTrue(all(server.poll() is None for server in self.servers))

    def test_parent_cancel_reaps_term_resistant_workload_without_signalling_servers(self):
        process = self.monitor(self.waiting_program(ignore_term=True))
        pid, _ = self.ready(process)
        process.terminate()
        output = process.communicate(timeout=4)
        self.assertEqual(process.returncode, 143, output)
        self.assertFalse(Path(f'/proc/{pid}').exists())
        self.assertTrue(all(server.poll() is None for server in self.servers))


if __name__ == '__main__':
    unittest.main(verbosity=2)
