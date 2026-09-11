#!/usr/bin/env python3
"""Small phase/admission regressions; no Northstar, database, or network load."""

from contextlib import contextmanager, redirect_stderr
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent


def load_module(name, file):
    spec = importlib.util.spec_from_file_location(name, file)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


phases = load_module("listener_stress_phases", ROOT / "listener-stress-phases.py")
readiness = load_module("listener_http_readiness", ROOT / "wait-test-readiness.py")


class PhaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="northstar-stress-phase-test-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name) / "round"
        self.nonce = "a" * 64
        phases.initialize(self.directory, self.nonce, 1, 2, os.getpid())
        self.config = phases.configuration(self.directory, self.nonce, 1)

    def spawn_worker(self, pair, phase="prepared"):
        # In production the outer worker survives preparation and starts its
        # servers. Keep this tiny publisher alive until all same-batch permits
        # exist too, so a fast pair cannot look like a dead production leader.
        program = r'''
import json, pathlib, runpy, sys, time
sys.argv = sys.argv[1:]
runpy.run_path(sys.argv[0], run_name="__main__")
if sys.argv[5] == "prepared":
    directory = pathlib.Path(sys.argv[2])
    pairs = json.loads((directory / "round.json").read_text())["pairs"]
    deadline = time.monotonic() + 3
    while not all((directory / f"prepared-start-{pair}.json").exists() for pair in range(1, pairs + 1)):
        if time.monotonic() >= deadline:
            raise TimeoutError("other prepared test workers were not admitted")
        time.sleep(0.01)
'''
        process = subprocess.Popen([
            sys.executable, "-c", program, str(ROOT / "listener-stress-phases.py"), "worker",
            str(self.directory), self.nonce, "1", phase, str(pair), "5",
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        def cleanup():
            if process.poll() is None:
                process.terminate()
            process.communicate(timeout=5)

        self.addCleanup(cleanup)
        deadline = time.monotonic() + 5
        while not (self.directory / f"{phase}-{pair}.json").exists():
            self.assertIsNone(process.poll(), "fixture exited while waiting for its barrier")
            if time.monotonic() >= deadline:
                self.fail("fixture did not publish its small local preparation record")
            time.sleep(0.01)
        return process

    def test_all_pairs_must_prepare_before_concurrent_release(self):
        first = self.spawn_worker(1)
        self.assertFalse(phases.all_prepared(self.directory, self.config, "prepared"))
        self.assertIsNone(first.poll())
        self.assertFalse((self.directory / "prepared-release.json").exists())
        second = self.spawn_worker(2)
        self.assertTrue(phases.all_prepared(self.directory, self.config, "prepared"))
        phases.release(self.directory, self.nonce, 1, "prepared", 2, [first.pid, second.pid])
        for process in (first, second):
            _, error = process.communicate(timeout=3)
            self.assertEqual(process.returncode, 0, error)

    def test_stale_round_and_nonce_fail_closed(self):
        for nonce, round_number in (("b" * 64, 1), (self.nonce, 2)):
            with self.assertRaisesRegex(ValueError, "round identity"):
                phases.configuration(self.directory, nonce, round_number)

    def test_wrong_pair_record_cannot_release_another_pair(self):
        record = phases.ready_record(self.config, "prepared", 2, os.getpid())
        phases.publish(self.directory / "prepared-1.json", record)
        with self.assertRaisesRegex(ValueError, "readiness identity"):
            phases.all_prepared(self.directory, self.config, "prepared")

    def test_duplicate_leaders_and_dead_workers_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "distinct worker leader"):
            phases.release(self.directory, self.nonce, 1, "prepared", 1, [os.getpid()] * 2)
        with patch.object(phases, "process_alive", side_effect=lambda pid: pid == os.getpid()):
            with self.assertRaisesRegex(ValueError, "worker leader exited"):
                phases.release(self.directory, self.nonce, 1, "prepared", 1, [os.getpid(), 123456789])

    def test_symlink_and_duplicate_records_are_rejected(self):
        file = self.directory / "prepared-1.json"
        file.symlink_to(self.directory / "round.json")
        with self.assertRaisesRegex(ValueError, "private regular file"):
            phases.read_record(file)
        with self.assertRaisesRegex(ValueError, "only be published once"):
            phases.publish(self.directory / "round.json", {})

    def mark_live_release(self):
        for phase in ("prepared", "live"):
            phases.publish(self.directory / f"{phase}-release.json", {
                **self.config, "phase": phase, "released": True,
            })

    def test_transport_rejects_out_of_order_and_wrong_release_identity(self):
        for phase in ("live", "transport"):
            with self.subTest(phase=phase), self.assertRaisesRegex(ValueError, "previous fixture phase"):
                phases.worker(self.directory, self.nonce, 1, phase, 1, 1)
            self.assertFalse((self.directory / f"{phase}-1.json").exists())
        with self.assertRaisesRegex(ValueError, "previous fixture phase"):
            phases.release(self.directory, self.nonce, 1, "transport", 1, [os.getpid(), os.getppid()])
        phases.publish(self.directory / "live-release.json", {
            **self.config, "nonce": "b" * 64, "phase": "live", "released": True,
        })
        with self.assertRaisesRegex(ValueError, "release identity"):
            phases.worker(self.directory, self.nonce, 1, "transport", 1, 1)
        self.assertFalse((self.directory / "transport-1.json").exists())

    def test_transport_rejects_swapped_workers_and_dead_leader(self):
        self.mark_live_release()
        first = self.spawn_worker(1, "transport")
        second = self.spawn_worker(2, "transport")
        with self.assertRaisesRegex(ValueError, "assigned worker"):
            phases.release(self.directory, self.nonce, 1, "transport", 1, [second.pid, first.pid])
        self.assertFalse((self.directory / "transport-release.json").exists())
        second.terminate()
        second.communicate(timeout=3)
        with self.assertRaisesRegex(ValueError, "worker leader exited"):
            phases.release(self.directory, self.nonce, 1, "transport", 1, [first.pid, second.pid])
        self.assertFalse((self.directory / "transport-release.json").exists())

    def test_python_phase_environment_is_all_or_none(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(phases, "worker") as wait:
            phases.wait_for_fixture_phase("transport")
            wait.assert_not_called()
        environment = {"NORTHSTAR_LISTENER_STRESS_PHASE_DIR": str(self.directory)}
        with patch.dict(os.environ, environment, clear=True), self.assertRaisesRegex(ValueError, "set together"):
            phases.wait_for_fixture_phase("transport")
        environment.update({
            "NORTHSTAR_LISTENER_STRESS_PHASE_NONCE": self.nonce,
            "NORTHSTAR_LISTENER_STRESS_PHASE_ROUND": "1",
            "NORTHSTAR_LISTENER_STRESS_PHASE_PAIR": "2",
        })
        with patch.dict(os.environ, environment, clear=True), patch.object(phases, "worker") as wait:
            phases.wait_for_fixture_phase("transport")
            wait.assert_called_once_with(self.directory, self.nonce, 1, "transport", 2, 900)

    def test_faster_transport_pair_cannot_register_before_slower_probes_finish(self):
        self.mark_live_release()
        slow_probe_release = Path(self.temporary.name) / "finish-slow-probe"
        probe_names = [
            "verify_starttls_failure_boundary", "verify_c2s_transport_boundaries",
            "verify_s2s_transport_boundaries", "verify_s2s_authentication_boundaries",
        ]
        program = r'''
import importlib.util, os, pathlib, sys, time
root, trace_path, slow_release = map(pathlib.Path, sys.argv[1:])
spec = importlib.util.spec_from_file_location("federation_transport_regression", root / "federation-wsl.py")
federation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(federation)
def trace(message):
    with trace_path.open("a") as output:
        output.write(message + "\n")
def probe(name):
    def run_probe():
        trace(name)
        if name == "verify_s2s_authentication_boundaries" and os.environ["NORTHSTAR_LISTENER_STRESS_PHASE_PAIR"] == "2":
            deadline = time.monotonic() + 5
            while not slow_release.exists():
                if time.monotonic() >= deadline:
                    raise AssertionError("slow probe was never released")
                time.sleep(0.01)
    return run_probe
for name in ("verify_starttls_failure_boundary", "verify_c2s_transport_boundaries", "verify_s2s_transport_boundaries", "verify_s2s_authentication_boundaries"):
    setattr(federation, name, probe(name))
def premature_authentication():
    raise AssertionError("authentication started before transport release")
federation.stress_admission.fixture_phase_auth_admission = premature_authentication
federation.stress_admission.authentication_attempt = premature_authentication
federation.endpoint = lambda *_: None
federation.required_test_port = lambda _: 40123
federation.fixture.wait_ready = lambda: None
def register(_username):
    trace("register")
    raise SystemExit(0)
federation.register = register
federation.run()
'''
        workers = []
        traces = []
        try:
            for pair in (1, 2):
                trace = Path(self.temporary.name) / f"pair-{pair}.trace"
                traces.append(trace)
                environment = {**os.environ,
                    "NORTHSTAR_LISTENER_STRESS_PHASE_DIR": str(self.directory),
                    "NORTHSTAR_LISTENER_STRESS_PHASE_NONCE": self.nonce,
                    "NORTHSTAR_LISTENER_STRESS_PHASE_ROUND": "1",
                    "NORTHSTAR_LISTENER_STRESS_PHASE_PAIR": str(pair),
                    "NORTHSTAR_CI_COMMAND_TIMEOUT_SECONDS": "5",
                }
                # Keep a real outer worker alive around the Python publisher,
                # mirroring the nested CI supervisor's ancestry relationship.
                workers.append(subprocess.Popen([
                    "bash", "-c", '"$@" & wait "$!"', "fixture-worker",
                    sys.executable, "-c", program, str(ROOT), str(trace), str(slow_probe_release),
                ], env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, start_new_session=True))
            deadline = time.monotonic() + 5
            while not (self.directory / "transport-1.json").exists():
                self.assertIsNone(workers[0].poll())
                if time.monotonic() >= deadline:
                    self.fail("faster fixture did not reach transport barrier")
                time.sleep(0.01)
            self.assertEqual(traces[0].read_text().splitlines(), probe_names)
            self.assertFalse((self.directory / "transport-2.json").exists())
            self.assertFalse(phases.all_prepared(self.directory, self.config, "transport", [worker.pid for worker in workers]))
            self.assertIsNone(workers[0].poll())
            slow_probe_release.touch()
            phases.release(self.directory, self.nonce, 1, "transport", 5, [worker.pid for worker in workers])
            for worker, trace in zip(workers, traces):
                _, error = worker.communicate(timeout=5)
                self.assertEqual(worker.returncode, 0, error)
                self.assertEqual(trace.read_text().splitlines(), [*probe_names, "register"])
        finally:
            for worker in workers:
                try:
                    os.killpg(worker.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            for worker in workers:
                worker.communicate(timeout=5)

    def test_fixture_preparation_precedes_server_startup(self):
        for name in ("federation-wsl.sh", "mix-federation-runtime-wsl.sh"):
            source = (ROOT / name).read_text()
            gate = source.index('fixture_stress_phase_barrier "$project_dir" prepared')
            self.assertLess(source.rindex("openssl req"), gate, name)
            self.assertEqual(source.count('fixture_stress_phase_barrier "$project_dir" prepared'), 1, name)
            self.assertEqual(source.count('fixture_start_tcp_relay "$project_dir"'), 4, name)
            self.assertLess(source.rindex('fixture_start_tcp_relay "$project_dir"'), gate, name)
            self.assertLess(source.index('[[ -x "$binary" ]]'), gate, name)
            self.assertLess(source.rindex('"$binary" migrate'), gate, name)
            self.assertLess(gate, source.index("\nstart_a\n"), name)
            # Hundreds of fixture processes must not share the maintainer's
            # default repository log file (or its cross-filesystem writer).
            for side in ("a", "b"):
                self.assertIn(f'LOG_DIR="$runtime_dir/logs-{side}"', source, name)
            self.assertEqual(source.count('startup_deadline="$(fixture_startup_deadline "$project_dir")"'), 2, name)
            self.assertEqual(source.count('fixture_wait_for_http_readiness "$project_dir"'), 2, name)
        federation = (ROOT / "federation-wsl.sh").read_text()
        self.assertLess(federation.index("\nstart_b\n"), federation.index('"$project_dir" live'))
        self.assertLess(federation.index('"$project_dir" live'), federation.index("python3 scripts/federation-wsl.py"))
        driver = (ROOT / "listener-readiness-stress-wsl.sh").read_text()
        self.assertIn('regular) [[ -n "$rounds" ]] || rounds=20', driver)
        self.assertIn('pairs="50"', driver)
        self.assertLess(driver.index('"fixture-preparation-release-r$round"'), driver.index('"all-pair-live-release-r$round"'))
        self.assertLess(driver.index('"all-pair-live-release-r$round"'), driver.index('"federation-transport-release-r$round"'))
        self.assertLess(driver.index('"federation-transport-release-r$round"'), driver.index('if ! await_mix_federation_setup_barrier'))

    def test_all_pair_relays_prepare_without_server_targets(self):
        relays = []
        try:
            for pair in (1, 2):
                for index in range(4):
                    record = Path(self.temporary.name) / f"relay-{pair}-{index}.json"
                    target = Path(self.temporary.name) / f"server-{pair}-{index}.target"
                    relay = subprocess.Popen([
                        sys.executable, str(ROOT / "test-listener-relay.py"),
                        "--readiness-file", str(record), "--nonce", self.nonce,
                        "--purpose", f"relay-{pair}-{index}", "--target-file", str(target),
                    ], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
                    relays.append(relay)
                    listeners = readiness.wait_for_record(record, self.nonce, relay.pid, 5)
                    self.assertIn(f"relay-{pair}-{index}", listeners)
                    self.assertFalse(target.exists(), "relay readiness must precede its server target")
            workers = [self.spawn_worker(pair) for pair in (1, 2)]
            phases.release(self.directory, self.nonce, 1, "prepared", 2, [worker.pid for worker in workers])
            for worker in workers:
                _, error = worker.communicate(timeout=3)
                self.assertEqual(worker.returncode, 0, error)
            self.assertTrue(all(relay.poll() is None for relay in relays))
        finally:
            for relay in relays:
                if relay.poll() is None:
                    relay.terminate()
            for relay in relays:
                relay.communicate(timeout=5)

    def test_cpu_budget_observes_process_affinity(self):
        allowed = sorted(os.sched_getaffinity(0))
        if len(allowed) < 2:
            self.skipTest("affinity regression needs two available processors")
        selected = set(allowed[:2])
        source = (ROOT / "listener-readiness-stress-wsl.sh").read_text()
        function = "effective_cpu_count() {" + source.split("effective_cpu_count() {", 1)[1].split("\n}", 1)[0] + "\n}"
        observed = subprocess.check_output(
            ["bash", "-c", function + "\neffective_cpu_count"], text=True,
            preexec_fn=lambda: os.sched_setaffinity(0, selected),
            env={**os.environ, "OMP_NUM_THREADS": "99", "OMP_THREAD_LIMIT": "99"},
        )
        self.assertGreaterEqual(int(observed), 1)
        self.assertLessEqual(int(observed), len(selected))

    def test_private_log_check_drains_large_child_environment(self):
        source = (ROOT / "mix-federation-runtime-wsl.sh").read_text()
        function = "fixture_assert_private_log_dir() {" + source.split(
            "fixture_assert_private_log_dir() {", 1
        )[1].split("\n}", 1)[0] + "\n}"
        runtime = Path(self.temporary.name) / "runtime"
        log_directory = runtime / "logs-a"
        log_directory.mkdir(parents=True)
        (log_directory / "server.log.test").write_text("fixture startup\n")
        # GitHub's environment can exceed a pipe buffer. Put the exact match
        # before a large tail so an early-exit consumer exposes SIGPIPE under
        # pipefail, without importing or printing any real CI credentials.
        padding = {f"FIXTURE_PADDING_{index}": "x" * 32000 for index in range(20)}
        for configured, expected_status in ((str(log_directory), 0), (str(log_directory) + "-wrong", 1)):
            with self.subTest(correct_directory=expected_status == 0):
                child = subprocess.Popen(["sleep", "30"], env={"LOG_DIR": configured, **padding})
                try:
                    result = subprocess.run([
                        "bash", "-c", "set -euo pipefail\n" + function
                        + '\nruntime_dir="$1"\nfixture_assert_private_log_dir a "$2"',
                        "fixture-log-check", str(runtime), str(child.pid),
                    ], capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, expected_status, result.stderr)
                    self.assertEqual(result.stdout, "")
                finally:
                    child.terminate()
                    child.wait(timeout=5)


class AuthenticationTests(unittest.TestCase):
    def test_federation_reuses_lane_before_strict_credential_deadline(self):
        federation = load_module("federation_phase_test", ROOT / "federation-wsl.py")
        active = False
        calls = []

        @contextmanager
        def lane():
            nonlocal active
            self.assertFalse(active)
            active = True
            try:
                yield
            finally:
                active = False

        def exchange(username, password, *args, deadline):
            self.assertTrue(active)
            self.assertGreater(deadline, time.monotonic())
            self.assertLessEqual(deadline - time.monotonic(), 10)
            calls.append((username, args))
            return (201, {}) if not args else "connected"

        with patch.object(federation.stress_admission, "fixture_phase_auth_admission", lane), \
                patch.object(federation.fixture, "register_account", exchange), \
                patch.object(federation.fixture, "XmppWebSocket", exchange):
            federation.register("alice")
            self.assertEqual(federation.connect("alice", "test-resource"), "connected")
        self.assertFalse(active)
        self.assertEqual(len(calls), 2)


class HttpReadinessTests(unittest.TestCase):
    @contextmanager
    def fixture(self, responses, *, slow_body=False):
        observed = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                status, body = responses[min(len(observed), len(responses) - 1)]
                observed.append(status)
                encoded = body.encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                try:
                    if slow_body:
                        for byte in encoded:
                            self.wfile.write(bytes([byte]))
                            self.wfile.flush()
                            time.sleep(0.05)
                    else:
                        self.wfile.write(encoded)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.005), daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix="northstar-startup-http-test-") as directory:
                path = Path(directory) / "ready.json"
                nonce = "0123456789abcdef"
                address = f"127.0.0.1:{server.server_port}"
                path.write_text(json.dumps({
                    "version": 1, "instance_nonce": nonce, "pid": os.getpid(),
                    "listeners": {"http": address},
                }))
                yield path, nonce, f"http://{address}/readyz", observed
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_listener_then_transient_http_health_share_one_deadline(self):
        with self.fixture([(503, "workers are starting"), (503, "workers are starting"), (200, "ready")]) as (path, nonce, url, observed):
            deadline = time.monotonic() + 1
            readiness.wait_for_record(path, nonce, os.getpid(), 15, deadline)
            output = io.StringIO()
            with redirect_stderr(output):
                readiness.wait_for_http_readiness(path, nonce, os.getpid(), deadline, [url, url])
            self.assertEqual(observed, [503, 503, 200, 200])
            self.assertEqual(output.getvalue().count("startup HTTP readiness pending:"), 1)
            self.assertIn("workers are starting", output.getvalue())

    def test_persistent_unhealthy_response_expires_without_budget_reset(self):
        with self.fixture([(503, "unused")]) as (path, nonce, url, _observed):
            clock = [100.0]
            def advance(seconds):
                clock[0] += seconds
            with patch.object(readiness.time, "monotonic", lambda: clock[0]), \
                    patch.object(readiness.time, "sleep", advance), \
                    patch.object(readiness, "probe_http_readiness", return_value=(503, "persisted authority is not ready")) as probe, \
                    redirect_stderr(io.StringIO()):
                with self.assertRaisesRegex(ValueError, "shared 15 second deadline"):
                    readiness.wait_for_http_readiness(path, nonce, os.getpid(), 100.15, [url])
                self.assertGreaterEqual(probe.call_count, 2)
                self.assertTrue(all(call.args[1] == 100.15 for call in probe.call_args_list))

    def test_non_ready_200_and_unbound_backend_cannot_pass(self):
        with self.fixture([(200, "starting")]) as (path, nonce, url, observed):
            clock = [100.0]
            def advance(seconds):
                clock[0] += seconds
            with patch.object(readiness.time, "monotonic", lambda: clock[0]), \
                    patch.object(readiness.time, "sleep", advance), \
                    patch.object(readiness, "probe_http_readiness", return_value=(200, "starting")), \
                    redirect_stderr(io.StringIO()):
                with self.assertRaisesRegex(ValueError, "status=200.*starting"):
                    readiness.wait_for_http_readiness(path, nonce, os.getpid(), 100.1, [url])
            with self.assertRaisesRegex(ValueError, "backend does not match"):
                readiness.wait_for_http_readiness(path, nonce, os.getpid(), time.monotonic() + 1, ["http://127.0.0.1:1/readyz"])
            self.assertEqual(observed, [])

    def test_expired_record_budget_never_starts_an_http_probe(self):
        with patch.object(readiness, "probe_http_readiness") as probe:
            with self.assertRaisesRegex(ValueError, "shared 15 second deadline"):
                readiness.wait_for_http_readiness("unused", "0123456789abcdef", os.getpid(), time.monotonic() - 0.01, ["http://127.0.0.1:12345/readyz"])
            probe.assert_not_called()

    def test_dead_child_or_wrong_nonce_cannot_pass_a_healthy_endpoint(self):
        with self.fixture([(200, "ready")]) as (path, nonce, url, observed):
            child = subprocess.Popen([sys.executable, "-c", "pass"])
            child.wait(timeout=2)
            with self.assertRaisesRegex(ValueError, "child exited"):
                readiness.wait_for_http_readiness(path, nonce, child.pid, time.monotonic() + 1, [url])
            with self.assertRaisesRegex(ValueError, "nonce did not match"):
                readiness.wait_for_http_readiness(path, "f" * 16, os.getpid(), time.monotonic() + 1, [url])
            self.assertEqual(observed, [])

    def test_slow_dribbling_response_cannot_extend_the_deadline(self):
        with self.fixture([(200, "ready" + " " * 50)], slow_body=True) as (path, nonce, url, _observed):
            started = time.monotonic()
            with redirect_stderr(io.StringIO()), self.assertRaisesRegex(ValueError, "shared 15 second deadline"):
                readiness.wait_for_http_readiness(path, nonce, os.getpid(), started + 0.5, [url])
            self.assertLess(time.monotonic() - started, 2)

    def test_oversized_or_special_record_cannot_block_startup(self):
        with tempfile.TemporaryDirectory(prefix="northstar-readiness-record-bounds-") as directory:
            path = Path(directory) / "record"
            path.write_text("x" * 8193)
            with self.assertRaisesRegex(ValueError, "8192 byte bound"):
                readiness.read_record(path)
            path.write_text("[]")
            with self.assertRaisesRegex(ValueError, "JSON object"):
                readiness.read_record(path)
            path.unlink()
            os.mkfifo(path)
            result = subprocess.run([
                sys.executable, str(ROOT / "wait-test-readiness.py"), "--http-ready", str(path),
                "0123456789abcdef", str(os.getpid()), str(time.monotonic() + 15),
                "http://127.0.0.1:12345/readyz",
            ], capture_output=True, text=True, timeout=3)
            self.assertEqual(result.returncode, 1)
            self.assertIn("regular file", result.stderr)

    def test_record_read_cannot_return_success_after_its_deadline(self):
        record = {"version": 1, "instance_nonce": "0123456789abcdef", "pid": os.getpid(), "listeners": {"http": "127.0.0.1:12345"}}
        with patch.object(readiness, "read_record", return_value=record), \
                patch.object(readiness.time, "monotonic", side_effect=[100.0, 100.0, 101.0]):
            with self.assertRaisesRegex(ValueError, "after the startup deadline"):
                readiness.wait_for_record("unused", "0123456789abcdef", os.getpid(), 15, 100.5)


if __name__ == "__main__":
    unittest.main()
