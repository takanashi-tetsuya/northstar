#!/usr/bin/env python3
"""MIX fixture coordination regressions using local sockets and private records."""

from collections import Counter
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("mix_coordination", ROOT / "mix-federation-runtime-wsl.py")
mix = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mix
SPEC.loader.exec_module(mix)


class CoordinationCase(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="northstar-mix-coordination-test-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name) / "phase"
        self.directory.mkdir(mode=0o700)
        self.nonce = "e" * 64
        self.pairs = 2
        self.configurations = []
        for pair in range(1, self.pairs + 1):
            key = self.directory / f"pair-{pair:03d}.key"
            key.write_text(f"{pair:064x}\n", encoding="ascii")
            key.chmod(0o600)
            self.configurations.append(mix.PhaseBarrierConfiguration(str(self.directory), self.nonce, 1, pair))

    def child(self, listeners=1, reuse_port=False):
        """The child reports real kernel socket inodes, then waits on its stdin."""
        program = """
import json, os, socket, sys
sockets = []
entries = []
for number in range(int(sys.argv[1])):
    listener = socket.socket()
    if sys.argv[2] == 'reuse':
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    listener.bind(('127.0.0.1', entries[0]['port'] if entries and sys.argv[2] == 'reuse' else 0))
    listener.listen(1)
    sockets.append(listener)
    entries.append({'port': listener.getsockname()[1], 'inode': os.fstat(listener.fileno()).st_ino})
print(json.dumps(entries), flush=True)
sys.stdin.buffer.read()
"""
        child = subprocess.Popen(
            [sys.executable, "-c", program, str(listeners), "reuse" if reuse_port else "unique"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

        def cleanup():
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=5)

        self.addCleanup(cleanup)
        self.assertTrue(select.select([child.stdout], [], [], 5)[0], "socket child did not publish readiness")
        raw = child.stdout.readline()
        self.assertTrue(raw, "socket child exited before readiness")
        return child, json.loads(raw)

    def ledger_path(self, pair=1):
        return self.directory / f"listeners-r001-p{pair:03d}.json"

    def assert_no_release(self):
        self.assertEqual(list(self.directory.glob("release-*.json")), [])

    def assert_signed(self, path, pair):
        record = json.loads(path.read_text(encoding="utf-8"))
        signature = record.pop("signature")
        key = bytes.fromhex((self.directory / f"pair-{pair:03d}.key").read_text().strip())
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        self.assertEqual(signature, hmac.new(key, canonical, hashlib.sha256).hexdigest())
        self.assertEqual(record["run_nonce"], self.nonce)
        self.assertEqual(record["round"], 1)
        self.assertEqual(record["pair"], pair)
        return record


@unittest.skipUnless(sys.platform == "linux", "requires Linux /proc listener ownership")
class ListenerSnapshotTests(CoordinationCase):
    def test_real_listeners_match_reported_pid_port_and_kernel_inode(self):
        children = [self.child(3), self.child(2)]
        expected = {}
        arguments = []
        for side, (child, sockets) in enumerate(children):
            for index, listener in enumerate(sockets):
                purpose = f"side-{side}-socket-{index}"
                expected[purpose] = (child.pid, listener["port"], listener["inode"])
                arguments.append(f"{purpose}={child.pid}:{listener['port']}")
        mix.record_listener_ledger(self.configurations[0], arguments)
        record = self.assert_signed(self.ledger_path(), 1)
        actual = {entry["purpose"]: (entry["pid"], entry["port"], entry["socket_inode"])
                  for entry in record["listeners"]}
        self.assertEqual(actual, expected)

    def test_eighteen_listeners_read_each_tcp_table_and_each_owner_fd_set_once(self):
        children = [self.child(3) for _ in range(6)]
        arguments = [f"owner-{number}-socket-{index}={child.pid}:{listener['port']}"
                     for number, (child, sockets) in enumerate(children)
                     for index, listener in enumerate(sockets)]
        table_reads = Counter()
        fd_reads = Counter()
        read_text = Path.read_text
        iterdir = Path.iterdir

        def observe_read(path, *args, **kwargs):
            if str(path) in ("/proc/net/tcp", "/proc/net/tcp6"):
                table_reads[str(path)] += 1
            return read_text(path, *args, **kwargs)

        def observe_directory(path):
            if str(path).startswith("/proc/") and path.name == "fd":
                fd_reads[str(path)] += 1
            return iterdir(path)

        with patch.object(Path, "read_text", observe_read), patch.object(Path, "iterdir", observe_directory):
            mix.record_listener_ledger(self.configurations[0], arguments)
        self.assertEqual(table_reads, {"/proc/net/tcp": 1, "/proc/net/tcp6": 1})
        self.assertEqual(fd_reads, {f"/proc/{child.pid}/fd": 1 for child, _ in children})
        self.assertEqual(len(self.assert_signed(self.ledger_path(), 1)["listeners"]), 18)

    def test_wrong_live_owner_cannot_claim_another_process_listener(self):
        owner, sockets = self.child()
        stranger, _ = self.child(0)
        self.assertIsNone(owner.poll())
        with self.assertRaisesRegex(RuntimeError, "owner|attribut"):
            mix.record_listener_ledger(self.configurations[0], [f"stolen={stranger.pid}:{sockets[0]['port']}"])
        self.assertFalse(self.ledger_path().exists())

    def test_duplicate_purpose_or_port_never_publishes_a_partial_ledger(self):
        child, sockets = self.child(2)
        first, second = (entry["port"] for entry in sockets)
        for arguments in (
            [f"same={child.pid}:{first}", f"same={child.pid}:{second}"],
            [f"first={child.pid}:{first}", f"second={child.pid}:{first}"],
        ):
            with self.subTest(arguments=arguments), self.assertRaisesRegex(RuntimeError, "duplicate"):
                mix.record_listener_ledger(self.configurations[0], arguments)
            self.assertFalse(self.ledger_path().exists())

    def test_multiple_owned_sockets_on_one_port_are_rejected_as_ambiguous(self):
        child, sockets = self.child(2, reuse_port=True)
        self.assertEqual(sockets[0]["port"], sockets[1]["port"])
        self.assertNotEqual(sockets[0]["inode"], sockets[1]["inode"])
        with self.assertRaisesRegex(RuntimeError, "unique|attribut"):
            mix.record_listener_ledger(self.configurations[0], [f"ambiguous={child.pid}:{sockets[0]['port']}"])
        self.assertFalse(self.ledger_path().exists())

    def test_exited_owner_is_rejected_even_when_its_pid_is_still_a_zombie(self):
        child, sockets = self.child()
        child.kill()
        # waitid WNOWAIT establishes exit without reaping the PID, unlike poll().
        os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT)
        with self.assertRaisesRegex(RuntimeError, "owner|process|exited|alive"):
            mix.record_listener_ledger(self.configurations[0], [f"dead={child.pid}:{sockets[0]['port']}"])
        self.assertFalse(self.ledger_path().exists())

    def test_later_snapshot_does_not_reuse_a_previous_owners_sockets(self):
        child, sockets = self.child()
        arguments = [f"original={child.pid}:{sockets[0]['port']}"]
        mix.record_listener_ledger(self.configurations[0], arguments)
        original = self.ledger_path().read_bytes()
        child.kill()
        child.wait(timeout=5)
        with self.assertRaises(RuntimeError):
            mix.record_listener_ledger(self.configurations[0], arguments)
        self.assertEqual(self.ledger_path().read_bytes(), original)

    def test_owner_dying_during_socket_sampling_cannot_publish_a_stale_ledger(self):
        child, sockets = self.child()
        original = mix._process_socket_inodes

        def exit_after_sample(pid):
            observed = original(pid)
            child.kill()
            child.wait(timeout=5)
            return observed

        with patch.object(mix, "_process_socket_inodes", side_effect=exit_after_sample):
            with self.assertRaises(RuntimeError):
                mix.record_listener_ledger(self.configurations[0], [f"dying={child.pid}:{sockets[0]['port']}"])
        self.assertFalse(self.ledger_path().exists())

    def test_pid_birth_time_change_during_sampling_is_rejected(self):
        child, sockets = self.child()
        original = mix._process_start_time
        observations = Counter()

        def replaced_pid(pid):
            observations[pid] += 1
            start = original(pid)
            return start if observations[pid] == 1 else start + 1

        with patch.object(mix, "_process_start_time", side_effect=replaced_pid):
            with self.assertRaisesRegex(RuntimeError, "changed|identity|reus"):
                mix.record_listener_ledger(self.configurations[0], [f"reused={child.pid}:{sockets[0]['port']}"])
        self.assertGreaterEqual(observations[child.pid], 2)
        self.assertIsNone(child.poll())
        self.assertFalse(self.ledger_path().exists())

    def test_invalid_last_entry_cannot_hide_behind_valid_snapshot_entries(self):
        owner, sockets = self.child(2)
        stranger, _ = self.child(0)
        arguments = [f"valid={owner.pid}:{sockets[0]['port']}",
                     f"invalid={stranger.pid}:{sockets[1]['port']}"]
        with self.assertRaisesRegex(RuntimeError, "owner|attribut"):
            mix.record_listener_ledger(self.configurations[0], arguments)
        self.assertFalse(self.ledger_path().exists())

    def test_quiescent_ledgers_share_one_tcp_snapshot_across_pairs(self):
        children = [self.child(2), self.child(2)]
        for configuration, (child, sockets) in zip(self.configurations, children):
            mix.record_listener_ledger(configuration, [
                f"listener-{number}={child.pid}:{entry['port']}" for number, entry in enumerate(sockets)
            ])
        for child, _ in children:
            child.kill()
            child.wait(timeout=5)
        reads = Counter()
        original = Path.read_text

        def observe(path, *args, **kwargs):
            if str(path) in ("/proc/net/tcp", "/proc/net/tcp6"):
                reads[str(path)] += 1
            return original(path, *args, **kwargs)

        with patch.object(Path, "read_text", observe):
            self.assertEqual(mix.verify_listener_ledger_after_quiescence(str(self.directory), self.nonce, 1, 2), (4, 0))
        self.assertEqual(reads, {"/proc/net/tcp": 1, "/proc/net/tcp6": 1})


@unittest.skipUnless(sys.platform == "linux", "requires Linux process identity and atomic phase records")
class PersistentParentTests(CoordinationCase):
    def setUp(self):
        super().setUp()
        self.leaders = [self.child(0)[0], self.child(0)[0]]
        self.now = 0.0
        self.ticks = 0
        self.on_sleep = lambda: None
        timer = SimpleNamespace(monotonic=lambda: self.now, sleep=self.sleep)
        clock_patch = patch.object(mix, "time", timer)
        clock_patch.start()
        self.addCleanup(clock_patch.stop)

    def sleep(self, duration):
        self.assertGreater(duration, 0)
        self.now += duration
        self.ticks += 1
        self.assertLess(self.ticks, 100, "persistent wait lost its deadline")
        self.on_sleep()

    def publish(self, pair):
        mix.publish_phase_ready(self.configurations[pair - 1])

    def wait(self, timeout=2, leaders=None):
        pids = [child.pid for child in self.leaders] if leaders is None else leaders
        mix.parent_await_release_phase(str(self.directory), self.nonce, 1, len(pids), timeout,
                                       pids, parent_pid=os.getpid())

    def assert_all_released(self, pairs=2):
        self.assertEqual(len(list(self.directory.glob("release-*.json"))), pairs)
        for pair in range(1, pairs + 1):
            record = self.assert_signed(self.directory / f"release-r001-p{pair:03d}.json", pair)
            self.assertEqual(record["kind"], "release")

    def test_unready_pair_blocks_every_release_until_its_signed_record_arrives(self):
        self.publish(1)

        def progress():
            self.assert_no_release()
            if self.ticks == 3:
                self.publish(2)

        self.on_sleep = progress
        self.wait()
        self.assertEqual(self.ticks, 3)
        self.assert_all_released()

    def test_all_signed_records_release_without_spawning_a_polling_subprocess(self):
        self.publish(1)
        self.publish(2)
        with patch.object(subprocess, "Popen", side_effect=AssertionError("parent wait spawned a subprocess")):
            self.wait()
        self.assertEqual(self.ticks, 0)
        self.assert_all_released()

    def test_one_pair_mode_keeps_the_same_signed_release_contract(self):
        self.publish(1)
        self.wait(leaders=[self.leaders[0].pid])
        self.assert_all_released(pairs=1)

    def test_forged_signature_fails_without_releasing_the_valid_pair(self):
        self.publish(1)
        self.publish(2)
        target = self.directory / "ready-r001-p002.json"
        record = json.loads(target.read_text())
        record["signature"] = "0" * 64
        target.write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "signature"):
            self.wait()
        self.assert_no_release()

    def test_ready_record_with_missing_key_is_a_failure_not_an_incomplete_poll(self):
        self.publish(1)
        self.publish(2)
        (self.directory / "pair-002.key").unlink()
        with self.assertRaises((RuntimeError, FileNotFoundError)):
            self.wait()
        self.assertEqual(self.ticks, 0)
        self.assert_no_release()

    def test_missing_earlier_pair_cannot_hide_a_later_forged_readiness_record(self):
        self.publish(2)
        target = self.directory / "ready-r001-p002.json"
        record = json.loads(target.read_text())
        record["signature"] = "0" * 64
        target.write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "signature"):
            self.wait()
        self.assertEqual(self.ticks, 0)
        self.assert_no_release()

    def test_real_leader_exit_during_wait_aborts_the_incomplete_barrier(self):
        self.publish(1)

        def exit_leader():
            self.leaders[1].kill()
            self.leaders[1].wait(timeout=5)

        self.on_sleep = exit_leader
        with self.assertRaises(RuntimeError):
            self.wait()
        self.assertEqual(self.ticks, 1)
        self.assert_no_release()

    def test_stale_signed_readiness_does_not_release_an_already_dead_leader(self):
        self.publish(1)
        self.publish(2)
        self.leaders[0].kill()
        self.leaders[0].wait(timeout=5)
        with self.assertRaises(RuntimeError):
            self.wait()
        self.assert_no_release()

    def test_reused_leader_pid_is_rejected_while_the_process_is_still_alive(self):
        self.publish(1)
        self.publish(2)
        original = mix._process_start_time
        observations = Counter()

        def reused(pid):
            observations[pid] += 1
            start = original(pid)
            return start + int(pid == self.leaders[1].pid and observations[pid] > 1)

        with patch.object(mix, "_process_start_time", side_effect=reused):
            with self.assertRaisesRegex(RuntimeError, "changed|identity|reus"):
                self.wait()
        self.assertIsNone(self.leaders[1].poll())
        self.assert_no_release()

    def test_parent_disappearance_cancels_wait_without_releasing_workers(self):
        original = mix._process_start_time
        observations = Counter()

        def parent_exits(pid):
            observations[pid] += 1
            if pid == os.getpid() and observations[pid] > 1:
                raise RuntimeError("test parent exited")
            return original(pid)

        with patch.object(mix, "_process_start_time", side_effect=parent_exits):
            with self.assertRaises(RuntimeError):
                self.wait()
        self.assert_no_release()

    def test_incomplete_barrier_uses_one_non_extending_deadline(self):
        self.publish(1)
        with self.assertRaisesRegex(RuntimeError, "deadline|timed out|timeout"):
            self.wait(timeout=1)
        self.assertGreaterEqual(self.now, 1)
        self.assertLessEqual(self.now, 1 + mix.PHASE_POLL_SECONDS)
        self.assert_no_release()

    def test_readiness_arriving_after_deadline_cannot_release_workers(self):
        self.publish(1)

        def too_late():
            self.now = 3.0
            self.publish(2)

        self.on_sleep = too_late
        with self.assertRaisesRegex(RuntimeError, "deadline|timed out|timeout"):
            self.wait(timeout=2)
        self.assert_no_release()

    def test_duplicate_leader_cannot_stand_in_for_two_ready_pairs(self):
        self.publish(1)
        self.publish(2)
        with self.assertRaises(RuntimeError):
            self.wait(leaders=[self.leaders[0].pid, self.leaders[0].pid])
        self.assert_no_release()

    def test_deadline_covers_release_publication_as_well_as_ready_waiting(self):
        self.publish(1)
        self.publish(2)
        original = mix._write_phase_record

        def deadline_after_first_release(directory, name, record, **kwargs):
            published = original(directory, name, record, **kwargs)
            if name == "release-r001-p001.json":
                self.now = 3.0
            return published

        with patch.object(mix, "_write_phase_record", side_effect=deadline_after_first_release):
            with self.assertRaisesRegex(RuntimeError, "deadline|timed out|timeout"):
                self.wait(timeout=2)
        self.assertTrue((self.directory / "release-r001-p001.json").exists())
        self.assertFalse((self.directory / "release-r001-p002.json").exists())

    def test_leader_dying_after_last_release_prevents_a_successful_result(self):
        self.publish(1)
        self.publish(2)
        original = mix._write_phase_record

        def exit_after_last_release(directory, name, record, **kwargs):
            published = original(directory, name, record, **kwargs)
            if name == "release-r001-p002.json":
                self.leaders[0].kill()
                self.leaders[0].wait(timeout=5)
            return published

        with patch.object(mix, "_write_phase_record", side_effect=exit_after_last_release):
            with self.assertRaises(RuntimeError):
                self.wait()
        self.assert_all_released()

    def test_cli_waits_and_releases_real_signed_records_with_real_worker_pids(self):
        self.publish(1)
        self.publish(2)
        result = subprocess.run(
            [sys.executable, str(ROOT / "mix-federation-runtime-wsl.py"),
             "--phase-parent-await-release", str(self.directory), self.nonce, "1", "2", "2",
             *(str(child.pid) for child in self.leaders)],
            capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr[-1500:])
        self.assert_all_released()


if __name__ == "__main__":
    unittest.main()
