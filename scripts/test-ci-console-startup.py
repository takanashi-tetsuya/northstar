#!/usr/bin/env python3
"""Exercise real console helper startup separately from bounded frame delivery."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('console_supervisor', Path(__file__).with_name('github_ci_supervisor.py'))
SUPERVISOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SUPERVISOR
SPEC.loader.exec_module(SUPERVISOR)
POPEN = subprocess.Popen


class ConsoleStartupTests(unittest.TestCase):
    def test_slow_start_does_not_spend_first_delivery_deadline(self):
        children = []
        with tempfile.TemporaryFile() as output:
            def delayed(arguments, **kwargs):
                # Simulate a slow interpreter/import startup, then execute the
                # unmodified helper and send real frames over its private pipes.
                child = POPEN([sys.executable, '-c',
                    'import os,sys,time;time.sleep(1.5);os.execv(sys.argv[1],sys.argv[1:])',
                    *arguments], **(kwargs | {'stdout': output}))
                children.append(child)
                return child
            forwarder = None
            try:
                with patch.object(SUPERVISOR.subprocess, 'Popen', delayed):
                    forwarder = SUPERVISOR.spawn_console_forwarder()
                state = SUPERVISOR.OutputCopyState(1024)
                for payload in (b'first-frame\n', b'second-frame\n'):
                    self.assertTrue(SUPERVISOR.forward_console_frame(
                        forwarder, payload, threading.Event(), state), state.failure())
                self.assertIsNone(state.failure())
                self.assertTrue(SUPERVISOR.finalize_console_forwarder(forwarder))
                forwarder = None
                output.seek(0)
                self.assertEqual(output.read(), b'first-frame\nsecond-frame\n')
            finally:
                if forwarder is not None:
                    SUPERVISOR.finalize_console_forwarder(forwarder)
                for child in children:
                    if child.poll() is None:
                        child.kill()
                        child.wait(timeout=2)

    def assert_failed_start_is_reaped(self, program):
        children = []
        descriptors = set(os.listdir('/proc/self/fd'))
        def substitute(arguments, **kwargs):
            ack = arguments[arguments.index('--acknowledgement-fd') + 1]
            child = POPEN([sys.executable, '-c', program, ack], **kwargs)
            children.append(child)
            return child
        started = time.monotonic()
        try:
            with patch.object(SUPERVISOR.subprocess, 'Popen', substitute), \
                    patch.object(SUPERVISOR, 'CONSOLE_START_SECONDS', .3):
                with self.assertRaises(OSError):
                    SUPERVISOR.spawn_console_forwarder()
            self.assertLess(time.monotonic() - started, 3)
            self.assertEqual(len(children), 1)
            self.assertIsNotNone(children[0].poll())
            self.assertEqual(set(os.listdir('/proc/self/fd')), descriptors)
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=2)

    def test_never_ready_is_bounded_and_reaped(self):
        self.assert_failed_start_is_reaped('import time;time.sleep(30)')

    def test_delivery_ack_cannot_impersonate_startup(self):
        self.assert_failed_start_is_reaped(
            'import os,sys,time;os.write(int(sys.argv[1]),b"\\x01");time.sleep(30)')

    def test_early_exit_cannot_impersonate_startup(self):
        self.assert_failed_start_is_reaped('raise SystemExit(0)')


if __name__ == '__main__':
    unittest.main()
