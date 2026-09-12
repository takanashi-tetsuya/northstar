#!/usr/bin/env python3
"""Bounded startup scheduling regressions without Northstar or database load."""

from contextlib import ExitStack
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("listener_startup_phases", ROOT / "listener-stress-phases.py")
phases = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = phases
spec.loader.exec_module(phases)


class SchedulerFixture:
    """Real private records, a deterministic clock, and controlled process lives.

    The scheduler itself runs unchanged. Only operating-system observations and
    worker progress are supplied by the test, so 50 pairs need no 100 processes.
    """

    def __init__(self, testcase, pairs=6, concurrency=2):
        self.testcase = testcase
        self.stack = ExitStack()
        testcase.addCleanup(self.stack.close)
        temporary = self.stack.enter_context(tempfile.TemporaryDirectory(prefix="northstar-startup-scheduler-test-"))
        self.directory = Path(temporary) / "round"
        self.nonce = "a" * 64
        self.parent = os.getpid()
        self.leaders = [100000 + pair for pair in range(1, pairs + 1)]
        self.children = {pair: (200000 + pair * 2, 200001 + pair * 2) for pair in range(1, pairs + 1)}
        self.alive = {self.parent, *self.leaders, *(pid for pair in self.children.values() for pid in pair)}
        self.starts = {pid: pid * 10 for pid in self.alive}
        self.now = 0.0
        self.ticks = 0
        self.on_sleep = lambda: None
        self.stack.enter_context(patch.object(phases, "process_alive", side_effect=lambda pid: pid in self.alive))
        self.stack.enter_context(patch.object(phases, "process_start_time", side_effect=self.start_time))
        self.stack.enter_context(patch.object(phases, "belongs_to_worker", side_effect=self.belongs))
        self.stack.enter_context(patch.object(phases, "time", SimpleNamespace(monotonic=lambda: self.now, sleep=self.sleep)))
        phases.initialize(self.directory, self.nonce, 1, pairs, self.parent, concurrency)
        self.config = phases.configuration(self.directory, self.nonce, 1)

    def belongs(self, pid, leader):
        if leader not in self.leaders:
            return False
        pair = self.leaders.index(leader) + 1
        return pid == leader or pid in self.children[pair]

    def start_time(self, pid):
        if pid not in self.alive:
            raise ValueError("server child exited before phase release")
        return self.starts[pid]

    def sleep(self, duration):
        self.testcase.assertGreater(duration, 0)
        self.now += duration
        self.ticks += 1
        self.testcase.assertLess(self.ticks, 1000, "scheduler failed to honor its bounded polling budget")
        self.on_sleep()

    def record(self, phase, pair):
        return phases.ready_record(self.config, phase, pair, self.leaders[pair - 1],
                                   self.children[pair] if phase == "live" else ())

    def publish(self, phase, pair, mutate=None):
        record = self.record(phase, pair)
        if mutate is not None:
            mutate(record)
        phases.publish(self.directory / f"{phase}-{pair}.json", record)

    def prepare(self, pairs=None):
        for pair in pairs if pairs is not None else range(1, len(self.leaders) + 1):
            self.publish("prepared", pair)

    def permits(self):
        return sorted(int(path.stem.rsplit("-", 1)[1]) for path in self.directory.glob("prepared-start-*.json"))

    def live(self):
        return sorted(int(path.stem.rsplit("-", 1)[1]) for path in self.directory.glob("live-[0-9]*.json"))

    def release(self, phase="prepared", timeout=1):
        phases.release(self.directory, self.nonce, 1, phase, timeout, self.leaders)

    def assert_no_business_release(self):
        self.testcase.assertFalse((self.directory / "live-release.json").exists())


class StartupBudgetTests(unittest.TestCase):
    def test_cpu_tiers_cap_cold_start_pairs_without_reducing_total_pairs(self):
        for cpus, pairs, expected in (
            (1, 50, 1), (2, 50, 1), (3, 50, 1), (4, 50, 2),
            (7, 50, 3), (8, 50, 4), (64, 50, 4),
            (1, 1, 1), (4, 1, 1), (4, 2, 2), (64, 2, 2),
        ):
            with self.subTest(cpus=cpus, pairs=pairs):
                self.assertEqual(phases.startup_pair_concurrency(cpus, pairs), expected)

    def test_invalid_cpu_or_pair_dimensions_are_rejected(self):
        for cpus, pairs in ((0, 50), (-1, 50), (4, 0), (4, -1), (True, 50), (4, True), (2.5, 50)):
            with self.subTest(cpus=cpus, pairs=pairs), self.assertRaises((ValueError, TypeError)):
                phases.startup_pair_concurrency(cpus, pairs)


class StartupSchedulerTests(unittest.TestCase):
    def test_all_pairs_must_prepare_before_any_start_permission(self):
        fixture = SchedulerFixture(self)
        fixture.prepare(range(1, 6))
        with self.assertRaises(TimeoutError):
            fixture.release(timeout=0.1)
        self.assertEqual(fixture.permits(), [])
        fixture.assert_no_business_release()

    def test_fifty_pairs_respect_cold_start_cap_and_require_all_live_before_business(self):
        fixture = SchedulerFixture(self, pairs=50, concurrency=2)
        fixture.prepare()
        admissions = []
        last_permits = []

        def advance_workers():
            nonlocal last_permits
            permitted = fixture.permits()
            if permitted != last_permits:
                admitted = sorted(set(permitted) - set(last_permits))
                self.assertLessEqual(len(admitted), 2)
                self.assertTrue(set(last_permits).issubset(fixture.live()))
                self.assertEqual(admitted, list(range(len(last_permits) + 1, len(permitted) + 1)))
                admissions.append(admitted)
                last_permits = permitted
            self.assertLessEqual(len(set(permitted) - set(fixture.live())), 2)
            fixture.assert_no_business_release()
            for pair in permitted:
                if pair not in fixture.live():
                    fixture.publish("live", pair)

        fixture.on_sleep = advance_workers
        fixture.release()
        self.assertEqual(fixture.permits(), list(range(1, 51)))
        self.assertEqual(fixture.live(), list(range(1, 49)))
        fixture.assert_no_business_release()
        fixture.release("live")
        self.assertEqual(fixture.live(), list(range(1, 51)))
        self.assertEqual(len(admissions), 25)
        release = phases.read_record(fixture.directory / "live-release.json")
        self.assertEqual(release, {**fixture.config, "phase": "live", "released": True})

    def test_single_pair_and_two_pair_smoke_keep_every_pair(self):
        for pairs in (1, 2):
            with self.subTest(pairs=pairs):
                fixture = SchedulerFixture(self, pairs=pairs, concurrency=pairs)
                fixture.prepare()
                fixture.release()
                self.assertEqual(fixture.permits(), list(range(1, pairs + 1)))
                self.assertEqual(fixture.live(), [])
                fixture.assert_no_business_release()
                for pair in range(1, pairs + 1):
                    fixture.publish("live", pair)
                fixture.release("live")
                self.assertTrue((fixture.directory / "live-release.json").exists())

    def test_unready_first_batch_never_starts_later_pairs(self):
        fixture = SchedulerFixture(self)
        fixture.prepare()
        with self.assertRaises(TimeoutError):
            fixture.release(timeout=0.1)
        self.assertEqual(fixture.permits(), [1, 2])
        fixture.assert_no_business_release()

    def test_one_live_pair_is_insufficient_to_release_the_next_batch(self):
        fixture = SchedulerFixture(self)
        fixture.prepare()

        def one_ready():
            if 1 in fixture.permits() and 1 not in fixture.live():
                fixture.publish("live", 1)

        fixture.on_sleep = one_ready
        with self.assertRaises(TimeoutError):
            fixture.release(timeout=0.1)
        self.assertEqual(fixture.permits(), [1, 2])
        self.assertEqual(fixture.live(), [1])
        fixture.assert_no_business_release()

    def test_first_leader_exit_stops_all_later_start_permissions(self):
        fixture = SchedulerFixture(self)
        fixture.prepare()
        fixture.on_sleep = lambda: fixture.alive.discard(fixture.leaders[0])
        with self.assertRaises(ValueError):
            fixture.release()
        self.assertEqual(fixture.permits(), [1, 2])
        fixture.assert_no_business_release()

    def test_parent_cancellation_stops_all_later_start_permissions(self):
        fixture = SchedulerFixture(self)
        fixture.prepare()
        fixture.on_sleep = lambda: fixture.alive.discard(fixture.parent)
        with self.assertRaises(ValueError):
            fixture.release()
        self.assertEqual(fixture.permits(), [1, 2])
        fixture.assert_no_business_release()

    def test_interrupt_during_batch_wait_does_not_admit_more_pairs(self):
        fixture = SchedulerFixture(self)
        fixture.prepare()

        def interrupted():
            raise KeyboardInterrupt

        fixture.on_sleep = interrupted
        with self.assertRaises(KeyboardInterrupt):
            fixture.release()
        self.assertEqual(fixture.permits(), [1, 2])
        fixture.assert_no_business_release()

    def test_server_exit_or_pid_reuse_cannot_be_hidden_by_a_live_publisher(self):
        for reuse in (False, True):
            with self.subTest(pid_reused=reuse):
                fixture = SchedulerFixture(self)
                fixture.prepare()

                def lose_server():
                    for pair in fixture.permits():
                        if pair not in fixture.live():
                            fixture.publish("live", pair)
                    child = fixture.children[1][0]
                    if reuse:
                        fixture.starts[child] += 1
                    else:
                        fixture.alive.discard(child)

                fixture.on_sleep = lose_server
                with self.assertRaises(ValueError):
                    fixture.release()
                self.assertIn(fixture.leaders[0], fixture.alive)
                self.assertEqual(fixture.permits(), [1, 2])
                fixture.assert_no_business_release()

    def test_stale_live_nonce_and_other_workers_child_do_not_admit_next_batch(self):
        def stale_nonce(record):
            record["nonce"] = "b" * 64

        def foreign_child(record):
            record["children"][0] = {"pid": 200006, "start_time": 2000060}

        for mutate in (stale_nonce, foreign_child):
            with self.subTest(mutation=mutate.__name__):
                fixture = SchedulerFixture(self)
                fixture.prepare()

                def forged_ready():
                    if 1 not in fixture.live():
                        fixture.publish("live", 1, mutate)
                        fixture.publish("live", 2)

                fixture.on_sleep = forged_ready
                with self.assertRaises(ValueError):
                    fixture.release()
                self.assertEqual(fixture.permits(), [1, 2])
                fixture.assert_no_business_release()

    def test_live_receipt_without_its_exact_start_permission_is_rejected(self):
        fixture = SchedulerFixture(self)
        fixture.prepare()
        phases.publish(fixture.directory / "prepared-release.json", {
            **fixture.config, "phase": "prepared", "released": True,
        })
        with self.assertRaisesRegex(ValueError, "startup permission"):
            phases.worker(fixture.directory, fixture.nonce, 1, "live", 6, 0.1, fixture.children[6])
        self.assertFalse((fixture.directory / "live-6.json").exists())

    def test_finished_startup_does_not_hide_a_dead_early_server_at_business_release(self):
        fixture = SchedulerFixture(self, pairs=2, concurrency=2)
        fixture.prepare()
        fixture.release()
        for pair in (1, 2):
            fixture.publish("live", pair)
        fixture.alive.discard(fixture.children[1][0])
        with self.assertRaisesRegex(ValueError, "server child exited"):
            fixture.release("live")
        fixture.assert_no_business_release()

    def test_each_batch_uses_the_original_absolute_release_budget(self):
        fixture = SchedulerFixture(self, pairs=6, concurrency=1)
        fixture.prepare()

        def delayed_ready():
            fixture.now += 0.03
            for pair in fixture.permits():
                if pair not in fixture.live():
                    fixture.publish("live", pair)

        fixture.on_sleep = delayed_ready
        with self.assertRaises(TimeoutError):
            fixture.release(timeout=0.1)
        self.assertLess(len(fixture.permits()), 6)
        fixture.assert_no_business_release()


class RealChildIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="northstar-startup-child-test-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name) / "round"
        self.nonce = "c" * 64
        phases.initialize(self.directory, self.nonce, 1, 1, os.getpid(), 1)
        self.config = phases.configuration(self.directory, self.nonce, 1)
        self.children = []
        for _ in range(2):
            child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
            self.children.append(child)

            def cleanup(process=child):
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=5)

            self.addCleanup(cleanup)
        phases.publish(self.directory / "prepared-start-1.json", phases.startup_permission(self.config, 1))
        self.record = phases.ready_record(self.config, "live", 1, os.getpid(),
                                          tuple(child.pid for child in self.children))

    def test_actual_subprocess_start_times_are_stable_and_belong_to_their_worker(self):
        phases.verify_children(self.record, os.getpid())
        for child, identity in zip(self.children, self.record["children"]):
            self.assertIsNone(child.poll())
            self.assertEqual(identity["pid"], child.pid)
            self.assertGreater(identity["start_time"], 0)
            self.assertEqual(identity["start_time"], phases.process_start_time(child.pid))
        phases.publish(self.directory / "live-1.json", self.record)
        self.assertTrue(phases.all_prepared(self.directory, self.config, "live", [os.getpid()]))

    def test_actual_child_exit_invalidates_live_receipt_while_publisher_survives(self):
        phases.publish(self.directory / "live-1.json", self.record)
        self.children[0].terminate()
        self.children[0].wait(timeout=5)
        self.assertTrue(phases.process_alive(os.getpid()))
        with self.assertRaisesRegex(ValueError, "server child exited"):
            phases.all_prepared(self.directory, self.config, "live", [os.getpid()])
        self.assertFalse((self.directory / "live-release.json").exists())

    def test_forged_birth_time_cannot_match_a_still_live_subprocess(self):
        self.record["children"][0]["start_time"] += 1
        self.assertIsNone(self.children[0].poll())
        with self.assertRaisesRegex(ValueError, "identity changed"):
            phases.verify_children(self.record, os.getpid())


class StartupWiringTests(unittest.TestCase):
    def test_live_barrier_is_after_both_nonce_and_http_checks_in_both_families(self):
        for name in ("federation-wsl.sh", "mix-federation-runtime-wsl.sh"):
            with self.subTest(fixture=name):
                source = (ROOT / name).read_text()
                for side in ("a", "b"):
                    body = source.split(f"start_{side}() {{", 1)[1].split("\n}", 1)[0]
                    self.assertLess(body.index('startup_deadline="$(fixture_startup_deadline'), body.index('"$binary"'))
                    self.assertLess(body.index("fixture_wait_for_readiness"), body.index("fixture_wait_for_http_readiness"))
                    self.assertRegex(body, r'fixture_wait_for_readiness[^\n]+\|\| return 1')
                    self.assertRegex(body, r'fixture_wait_for_http_readiness[\s\S]+?\|\| return 1')
                initial = source.index('\nstart_a\nstart_b\n')
                barrier = ('python3 scripts/federation-wsl.py' if name == "federation-wsl.sh"
                           else 'fixture_stress_phase_barrier "$project_dir" live')
                live = source.index(barrier, initial)
                self.assertGreater(live, initial)
                self.assertIn('"$pid_a" "$pid_b"', source[live:source.index('\n', live)])

    def test_worker_budget_and_child_identities_are_forwarded_without_a_new_deadline(self):
        source = (ROOT / "lib/test-listener-readiness.sh").read_text()
        body = "fixture_stress_phase_barrier() {" + source.split("fixture_stress_phase_barrier() {", 1)[1].split("\n}", 1)[0] + "\n}"
        program = 'python3() { printf "%s\\0" "$@"; }\n' + body + '\nfixture_stress_phase_barrier /fixture live 101 102'
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith("NORTHSTAR_LISTENER_STRESS_PHASE_")
                       and key != "NORTHSTAR_CI_COMMAND_TIMEOUT_SECONDS"}
        environment.update({
            "NORTHSTAR_LISTENER_STRESS_PHASE_DIR": "/private-round",
            "NORTHSTAR_LISTENER_STRESS_PHASE_NONCE": "a" * 64,
            "NORTHSTAR_LISTENER_STRESS_PHASE_ROUND": "1",
            "NORTHSTAR_LISTENER_STRESS_PHASE_PAIR": "2",
        })
        actual = subprocess.check_output(["bash", "-c", program], env=environment).decode().split("\0")[:-1]
        self.assertEqual(actual, ["/fixture/scripts/listener-stress-phases.py", "worker", "/private-round",
                                  "a" * 64, "1", "live", "2", "900", "101", "102"])


if __name__ == "__main__":
    unittest.main()
