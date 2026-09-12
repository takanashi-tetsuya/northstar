#!/usr/bin/env python3
"""Bounded subprocess and privacy regressions for the observed regular CI entry."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("observed_listener", ROOT / "scripts/listener-readiness-observed-wsl.py")
ENTRY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ENTRY)

FAKE_OBSERVER = r"""
import json, os
from pathlib import Path
import signal, sys, time
os.umask(0o077)
out, marker, mode = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
if mode == 'unavailable':
    raise SystemExit(2)
out.mkdir(mode=0o700)
(out/'observations.jsonl').write_text('')
if mode == 'oversized':
    with (out/'observations.jsonl').open('wb') as stream:
        stream.truncate(8*1024*1024+1)
(out/'observer-ready.json').write_text(json.dumps(dict(observer_pid=os.getpid(),sample_count=1)))
stopped=False
def stop(_sig,_frame):
    global stopped
    stopped=True
signal.signal(signal.SIGTERM, signal.SIG_IGN if mode=='hang' else stop)
while not stopped:
    if mode == 'early':
        break
    if marker.exists() and mode != 'hang':
        break
    time.sleep(.01)
good = mode not in {'bad', 'early'}
(out/'observer-result.json').write_text(json.dumps(dict(
    observer_ok=good,truncated=False,observations_bytes=0,post_window_complete=True)))
raise SystemExit(0 if good else 2)
"""

RUNNER = r"""
import importlib.util,json,os,signal,sys
from pathlib import Path
root, control, driver_source, mode = sys.argv[1:]
sys.path.insert(0,str(Path(root)/'scripts'))
spec=importlib.util.spec_from_file_location('entry',Path(root)/'scripts/listener-readiness-observed-wsl.py')
entry=importlib.util.module_from_spec(spec)
spec.loader.exec_module(entry)
for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):
    signal.signal(sig,entry.stop_requested)
control=Path(control)
env=dict(os.environ)
env['GITHUB_OUTPUT']=str(control/'github-output')
if mode=='no_subreaper':entry.enable_linux_child_subreaper=lambda:False
env['NORTHSTAR_LISTENER_STRESS_OBSERVER_SALT_FILE']=str(control/'database-hash-salt')
env['NORTHSTAR_LISTENER_STRESS_OBSERVER_MAP_FILE']=str(control/'database-map.json')
status=entry.run_observed(
    [sys.executable,'-c',driver_source],
    [sys.executable,str(control/'fake-observer.py'),str(control/'observer'),str(control/'first-failure.json'),mode],
    control_dir=control,output_dir=control/'observer',environment=env,
    ready_wait=.4,post_wait=.2,stop_wait=1,driver_cancel_wait=0)
raise SystemExit(status)
"""


class ObservedEntryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="northstar-observed-entry.")
        self.addCleanup(self.temp.cleanup)
        self.control = Path(self.temp.name)
        self.control.chmod(0o700)
        self.salt = "1" * 32
        (self.control / "database-hash-salt").write_text(self.salt)
        (self.control / "database-hash-salt").chmod(0o600)
        self.environment = {
            "NORTHSTAR_LISTENER_STRESS_OBSERVER_SALT_FILE": str(self.control / "database-hash-salt"),
            "NORTHSTAR_LISTENER_STRESS_OBSERVER_MAP_FILE": str(self.control / "database-map.json"),
        }
        self.batch = "".join(f"{pair}\t{node}\tnorthstar_case_{pair}_{node.lower()}\n"
                             for pair in range(1, 51) for node in ("A", "B")).encode()
        ENTRY.publish_case_map(3, 50, self.batch, self.environment)
        (self.control / "fake-observer.py").write_text(FAKE_OBSERVER)

    def command(self, driver_source, mode="normal"):
        return [sys.executable, "-c", RUNNER, str(ROOT), str(self.control), driver_source, mode]

    def run_wrapper(self, source, mode="normal"):
        self.github_output = self.control / 'github-output'
        result = subprocess.run(self.command(source, mode), capture_output=True, text=True, timeout=8)
        record = json.loads((self.control / "wrapper-result.json").read_text())
        self.assertNotIn("xmpp-test-password", result.stdout + result.stderr)
        self.assertNotIn(self.salt, result.stdout + result.stderr)
        return result, record

    def test_success_requires_observer_and_keeps_driver_environment_contract(self):
        source = """import os
assert os.environ['NORTHSTAR_LISTENER_STRESS_OBSERVER_CONNECTIONS']=='1'
assert os.environ['NORTHSTAR_LISTENER_STRESS_FAILURE_MARKER'].endswith('/first-failure.json')
"""
        result, record = self.run_wrapper(source)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(record["diagnostic_ok"])
        self.assertEqual(record["driver_exit_status"], 0)
        self.assertTrue(record["case_map_ok"])
        self.assertEqual(self.github_output.read_text(), 'driver_succeeded=true\n')

    def test_driver_failure_is_preserved_when_observer_also_fails(self):
        result, record = self.run_wrapper("raise SystemExit(7)", "bad")
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual(record["driver_exit_status"], 7)
        self.assertFalse(record["diagnostic_ok"])
        self.assertTrue((self.control / "first-failure.json").exists())
        self.assertEqual(self.github_output.read_text(), 'driver_succeeded=false\n')

    def test_successful_driver_with_unavailable_or_failed_observer_fails_diagnostics(self):
        for mode in ("unavailable", "bad"):
            with self.subTest(mode=mode):
                if (self.control / "wrapper-result.json").exists():
                    (self.control / "wrapper-result.json").unlink()
                result, record = self.run_wrapper("raise SystemExit(0)", mode)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(record["driver_exit_status"], 0)
                self.assertFalse(record["diagnostic_ok"])
                self.assertTrue(self.github_output.read_text().endswith('driver_succeeded=true\n'))

    def test_output_write_failure_preserves_driver_failure(self):
        self.control.joinpath('github-output').mkdir()
        result, record = self.run_wrapper('raise SystemExit(7)')
        self.assertEqual(result.returncode, 7)
        self.assertEqual(record['error_code'], 'github_output_write_failed')
        self.assertFalse(record['diagnostic_ok'])

    def test_output_write_failure_fails_successful_driver(self):
        self.control.joinpath('github-output').mkdir()
        result, record = self.run_wrapper('raise SystemExit(0)')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(record['error_code'], 'github_output_write_failed')
        self.assertFalse(record['diagnostic_ok'])

    def test_unstarted_driver_cannot_skip_required_failure_logs(self):
        result, record = self.run_wrapper('raise SystemExit(0)', 'no_subreaper')
        self.assertEqual(result.returncode, 2)
        self.assertIsNone(record['driver_exit_status'])
        self.assertEqual(self.github_output.read_text(), 'driver_succeeded=false\n')

    def test_early_observer_exit_is_reported_once_and_driver_finishes(self):
        result, record = self.run_wrapper('import time;time.sleep(.3)', 'early')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(record['driver_exit_status'], 0)
        self.assertEqual(result.stdout.count('listener_observer_early_exit=2'), 1)

    def test_hung_observer_is_reaped_without_replacing_driver_failure(self):
        begin = time.monotonic()
        result, record = self.run_wrapper("raise SystemExit(9)", "hang")
        self.assertEqual(result.returncode, 9, result.stderr)
        self.assertLess(time.monotonic() - begin, 5)
        ready = json.loads((self.control / "observer/observer-ready.json").read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(ready["observer_pid"], 0)
        self.assertFalse(record["diagnostic_ok"])

    def test_oversized_evidence_cannot_turn_a_successful_driver_green(self):
        result, record = self.run_wrapper("raise SystemExit(0)", "oversized")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(record["evidence_bounds_ok"])
        self.assertFalse(record["diagnostic_ok"])

    def test_wrapper_result_write_failure_preserves_original_driver_failure(self):
        (self.control / "wrapper-result.json").mkdir()
        result = subprocess.run(self.command("raise SystemExit(11)"), capture_output=True,
                                text=True, timeout=8)
        self.assertEqual(result.returncode, 11)
        self.assertIn("wrapper_result_write_failed", result.stderr)

    def test_internal_single_pair_mapping_does_not_add_a_reduced_cli_mode(self):
        ENTRY.publish_case_map(1, 1, b"1\tA\tnorthstar_a\n1\tB\tnorthstar_b\n", self.environment)
        value = json.loads((self.control / "database-map.json").read_text())
        self.assertTrue(ENTRY.case_map_valid(value, 1))
        self.assertFalse(ENTRY.case_map_valid(value))
        result = subprocess.run([sys.executable, str(ROOT / "scripts/listener-readiness-observed-wsl.py"),
                                 "--mode", "regular", "--fixture", "federation",
                                 "--rounds", "1", "--pairs", "1"],
                                capture_output=True, text=True, timeout=2)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("observer", result.stdout)

    def test_marker_first_cause_is_not_overwritten_during_finalization(self):
        source = ("import sys;sys.path.insert(0," + repr(str(ROOT / "scripts")) + ");"
                  "from github_ci_supervisor import publish_failure_marker;"
                  "assert publish_failure_marker('deadline');raise SystemExit(124)")
        result, record = self.run_wrapper(source)
        self.assertEqual(result.returncode, 124)
        marker = json.loads((self.control / "first-failure.json").read_text())
        self.assertEqual(marker["cause"], "deadline")
        self.assertTrue(record["observer_ok"])

    def test_cancellation_reaps_detached_owned_descendants(self):
        child_file = self.control / "detached.pid"
        source = ("import subprocess,sys,time;"
                  "subprocess.Popen([sys.executable,'-c',"
                  + repr("import os,time;from pathlib import Path;"
                         f"Path({str(child_file)!r}).write_text(str(os.getpid()));time.sleep(60)")
                  + "],start_new_session=True);time.sleep(60)")
        process = subprocess.Popen(self.command(source), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 3
            while not child_file.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertTrue(child_file.exists())
            descendant = int(child_file.read_text())
            process.send_signal(signal.SIGTERM)
            _out, err = process.communicate(timeout=6)
            self.assertNotEqual(process.returncode, 0, err)
            with self.assertRaises(ProcessLookupError):
                os.kill(descendant, 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)

    def test_same_run_salt_correlates_exact_pair_and_side_without_retaining_names(self):
        path = self.control / "database-map.json"
        value = json.loads(path.read_text())
        self.assertTrue(ENTRY.case_map_valid(value))
        first = value["cases"][0]
        self.assertEqual(first, dict(round=3, pair=1, node="A",
                         database_hash=hashlib.md5((self.salt + ":northstar_case_1_a").encode()).hexdigest()))
        self.assertNotIn("northstar_case", path.read_text())
        self.assertNotIn(self.salt, path.read_text())
        ENTRY.publish_case_map(4, 50, self.batch, self.environment)
        self.assertEqual(json.loads(path.read_text())["round"], 4)
        self.assertLess(path.stat().st_size, 16384)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_case_map_rejects_partial_duplicate_unbounded_or_foreign_records(self):
        malformed = [
            self.batch.splitlines(keepends=True)[0],
            self.batch + self.batch.splitlines(keepends=True)[0],
            self.batch.replace(b"northstar_case_1_a", b"postgres://remote/secret"),
            b"x" * 16385,
        ]
        before = (self.control / "database-map.json").read_bytes()
        for data in malformed:
            with self.assertRaises(ValueError):
                ENTRY.publish_case_map(3, 50, data, self.environment)
            self.assertEqual((self.control / "database-map.json").read_bytes(), before)
        (self.control / "database-hash-salt").chmod(0o644)
        with self.assertRaises(ValueError):
            ENTRY.publish_case_map(3, 50, self.batch, self.environment)

    def test_fixture_endpoint_rejects_remote_uri_port_and_identity_overrides(self):
        for overrides in (
            {"NORTHSTAR_LISTENER_STRESS_DATABASE_HOST": "example.org"},
            {"NORTHSTAR_LISTENER_STRESS_DATABASE_HOST": "127.0.0.1?host=example.org"},
            {"NORTHSTAR_LISTENER_STRESS_DATABASE_PORT": "5432?host=example.org"},
            {"NORTHSTAR_LISTENER_STRESS_DATABASE_PORT": "05432"},
            {"NORTHSTAR_LISTENER_STRESS_DATABASE_PORT": "65536"},
            {"NORTHSTAR_LISTENER_STRESS_DATABASE_USER": ""},
            {"NORTHSTAR_LISTENER_STRESS_DATABASE_PASSWORD": "secret"},
        ):
            with self.subTest(overrides=list(overrides)), self.assertRaises(ValueError):
                ENTRY.observer_environment(overrides)
        value = ENTRY.observer_environment(dict(PGHOST="remote", PGPORT="1", PGSERVICE="foreign",
                        PGSERVICEFILE="foreign", PGOPTIONS="arbitrary", PGDATABASE="postgres://remote/db"))
        self.assertEqual(value["PGHOST"], "127.0.0.1")
        self.assertEqual(value["PGPORT"], "5432")
        self.assertEqual(value["PGDATABASE"], "postgres")
        self.assertNotIn("PGSERVICE", value)
        self.assertNotIn("PGOPTIONS", value)

    def test_regular_only_ci_keeps_original_load_and_allowlists_artifacts_without_salt(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        regular = workflow.split("  listener-readiness-stress-regular:", 1)[1].split(
            "  listener-readiness-stress-scheduled:", 1)[0]
        self.assertIn("python3 scripts/listener-readiness-observed-wsl.py", regular)
        self.assertIn('--mode regular --fixture "¤{{ matrix.fixture }}" --rounds 20 --pairs 50'.replace("¤", "$"), regular)
        self.assertIn('NORTHSTAR_LISTENER_STRESS_WORKER_TIMEOUT_SECONDS: "900"', regular)
        self.assertIn("timeout-minutes: 150", regular)
        artifact = regular.split("      - name: Upload bounded control observer evidence", 1)[1]
        self.assertIn("/database-map.json", artifact)
        self.assertNotIn("/database-hash-salt", artifact)
        self.assertNotIn("/listener-control-observer.*/**", artifact)
        driver = (ROOT / "scripts/listener-readiness-stress-wsl.sh").read_text()
        self.assertIn("fixture_control_connections + observer_connections))", driver)
        self.assertLess(driver.index("  if ! publish_observer_round_map; then"),
                        driver.index('run_parent_phase "fixture-preparation-release-r$round"'))


if __name__ == "__main__":
    unittest.main()
