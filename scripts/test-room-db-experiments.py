#!/usr/bin/env python3
"""Deterministic room DB fixture policy tests; no PostgreSQL or Cargo is run."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('room_db_experiments', ROOT / 'scripts/room-db-experiments.py')
DB = importlib.util.module_from_spec(spec)
spec.loader.exec_module(DB)
SOURCE = {'commit': 'test', 'source_files_sha256': 'abc', 'source_file_count': 1}


class EnvironmentTests(unittest.TestCase):
    def test_environment_excludes_ambient_database_and_application_configuration(self):
        ambient = {'PATH': '/tools/bin:/usr/bin', 'HOME': '/real-home', 'TMPDIR': '/ambient-tmp',
                   'DATABASE_URL': 'secret', 'TEST_DATABASE_URL': 'secret',
                   'MIGRATOR_DATABASE_URL': 'secret', 'REDIS_URL': 'secret',
                   'PGHOST': 'remote', 'PGPORT': '5432', 'PGHOSTADDR': 'remote',
                   'PGPASSWORD': 'secret', 'PGSERVICE': 'production', 'PGOPTIONS': 'secret',
                   'PGPASSFILE': '/private', 'PGSERVICEFILE': '/private',
                   'PSQLRC': '/private', 'BASH_ENV': '/private', 'ENV': '/private',
                   'XMPP_TEST_SCHEMA': 'production', 'RUST_LOG': 'trace',
                   'CARGO_BUILD_JOBS': '128', 'RUSTFLAGS': 'unrequested flags'}
        environment = DB.fixture_environment(ambient, Path('/owned'), 54321)
        self.assertEqual(environment['PGHOST'], '127.0.0.1')
        self.assertEqual(environment['PGPORT'], '54321')
        self.assertEqual(environment['PGPASSWORD'], 'xmpp-test-password')
        self.assertEqual(environment['PGDATABASE'], 'xmpp_test')
        self.assertEqual(environment['HOME'], '/owned/home')
        self.assertEqual(environment['TMPDIR'], '/owned/tmp')
        self.assertEqual(environment['PGPASSFILE'], '/owned/empty')
        self.assertEqual(environment['PSQLRC'], '/owned/empty')
        self.assertEqual(environment['CARGO_BUILD_JOBS'], '1')
        self.assertEqual(environment['RUST_TEST_THREADS'], '1')
        for key in ('DATABASE_URL', 'TEST_DATABASE_URL', 'MIGRATOR_DATABASE_URL', 'REDIS_URL',
                    'PGHOSTADDR', 'PGSERVICE', 'PGOPTIONS', 'BASH_ENV', 'ENV',
                    'XMPP_TEST_SCHEMA', 'RUST_LOG', 'RUSTFLAGS'):
            self.assertNotIn(key, environment)
        self.assertNotIn('secret', environment.values())

    def test_explicit_toolchain_cache_and_profiles_are_preserved(self):
        ambient = {'HOME': '/real-home', 'CARGO_HOME': '/cargo', 'RUSTUP_HOME': '/rustup',
                   'CARGO_TARGET_DIR': '/target', 'CARGO_PROFILE_DEV_DEBUG': '0',
                   'CARGO_PROFILE_TEST_DEBUG': '0', 'CARGO_INCREMENTAL': '0',
                   'LD_LIBRARY_PATH': '/postgres/lib'}
        environment = DB.fixture_environment(ambient, Path('/owned'), 54321)
        for key, value in ambient.items():
            if key != 'HOME':
                self.assertEqual(environment[key], value)
        self.assertEqual(environment['NORTHSTAR_DISABLE_DOTENV'], 'true')
        self.assertEqual(environment['XMPP_TEST_SYSTEM_TOOLCHAIN'], 'true')
        self.assertEqual(environment['CARGO_NET_OFFLINE'], 'true')

    def test_default_rustup_homes_are_resolved_before_isolating_home(self):
        environment = DB.fixture_environment({'HOME': '/real-home'}, Path('/owned'), 54321)
        self.assertEqual(environment['CARGO_HOME'], '/real-home/.cargo')
        self.assertEqual(environment['RUSTUP_HOME'], '/real-home/.rustup')


class PathAndPlanTests(unittest.TestCase):
    def test_fresh_evidence_is_private_and_previous_evidence_is_never_reused(self):
        with tempfile.TemporaryDirectory() as parent:
            output = DB.fresh_output(Path(parent) / 'new')
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            marker = output / 'result.json'
            marker.write_text('previous')
            with self.assertRaises(ValueError):
                DB.fresh_output(output)
            self.assertEqual(marker.read_text(), 'previous')

    def test_source_paths_and_symlink_aliases_are_rejected(self):
        with tempfile.TemporaryDirectory() as parent:
            parent = Path(parent)
            source = parent / 'source'
            source.mkdir()
            alias = parent / 'alias'
            alias.symlink_to(source, target_is_directory=True)
            with patch.object(DB, 'SOURCE', source):
                for path in (source / 'evidence', alias / 'evidence'):
                    with self.assertRaises(ValueError):
                        DB.fresh_output(path)
            dangling = parent / 'dangling'
            dangling.symlink_to(parent / 'absent')
            with self.assertRaises(ValueError):
                DB.fresh_output(dangling)

    def test_only_the_three_reviewed_suites_are_executable(self):
        self.assertEqual(DB.SUITES, (
            ('muc', 'scripts/muc-db-wsl.sh'),
            ('mix', 'scripts/mix-family-db-wsl.sh'),
            ('authentication', 'scripts/authentication-service-db-wsl.sh')))
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                DB.parse_arguments(['--suite', 'unreviewed.sh'])

    def test_timeout_must_be_finite_and_bounded(self):
        for value in ('nan', 'inf', '0', '-1', '7201'):
            with self.subTest(value=value), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    DB.parse_arguments(['--suite-timeout-seconds', value])
        self.assertEqual(DB.parse_arguments([]).suite_timeout_seconds, 1800)

    def test_runtime_data_is_outside_evidence_and_owned_cleanup_removes_it(self):
        with tempfile.TemporaryDirectory() as parent:
            output = DB.fresh_output(Path(parent) / 'evidence')
            with patch.object(DB.HELPERS, 'candidate_database_port', return_value=54321):
                fixture = DB.OwnedRoomDatabase(output, {})
            self.assertNotIn(output, fixture.runtime.parents)
            (fixture.runtime / 'password').write_text('synthetic')
            (fixture.runtime / 'data').mkdir()
            with patch.object(DB.HELPERS, 'listener_closed', return_value=True):
                report = fixture.stop()
            self.assertTrue(report['clean'])
            self.assertTrue(report['runtime_removed'])
            self.assertFalse(fixture.runtime.exists())
            self.assertEqual(list(output.iterdir()), [])


class LifecycleTests(unittest.TestCase):
    def make_fixture(self, output, statuses=('passed', 'passed', 'passed'), error=None):
        events = []

        def start():
            events.append('start')

        def suite(name, script, record):
            events.append(name)
            record.update(status=statuses[len(events) - 2], exit_code=0)
            if error is not None:
                raise error

        def stop():
            events.append('stop')
            return {'clean': True, 'errors': []}

        return SimpleNamespace(output=output, port=54321, start=start, run_suite=suite,
                               stop=stop), events

    def run_fixture(self, fixture):
        result = {'source_before': SOURCE}
        with patch.object(DB, 'source_snapshot', return_value=SOURCE):
            return DB.run_owned_suites(fixture, result)

    def test_suites_run_serially_and_success_requires_clean_stop(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture, events = self.make_fixture(Path(directory))
            result = self.run_fixture(fixture)
            self.assertEqual(events, ['start', 'muc', 'mix', 'authentication', 'stop'])
            self.assertEqual(result['status'], 'passed')
            self.assertEqual(json.loads((Path(directory) / 'result.json').read_text()), result)

    def test_first_failure_stops_new_suites_and_preserves_unrun_status(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture, events = self.make_fixture(Path(directory), ('failed',))
            result = self.run_fixture(fixture)
            self.assertEqual(events, ['start', 'muc', 'stop'])
            self.assertEqual([row['status'] for row in result['suites']],
                             ['failed', 'not_run', 'not_run'])
            self.assertEqual(result['status'], 'failed')

    def test_interrupt_always_closes_database_and_keeps_original_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture, events = self.make_fixture(Path(directory), error=KeyboardInterrupt())
            fixture.stop = Mock(return_value={'clean': False, 'errors': ['cleanup failed']})
            result = self.run_fixture(fixture)
            fixture.stop.assert_called_once()
            self.assertEqual(result['error_type'], 'KeyboardInterrupt')
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(events, ['start', 'muc'])

    def test_startup_failure_still_runs_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture, _events = self.make_fixture(Path(directory))
            fixture.start = Mock(side_effect=RuntimeError('not connected'))
            fixture.stop = Mock(return_value={'clean': True})
            result = self.run_fixture(fixture)
            fixture.stop.assert_called_once()
            self.assertEqual(result['error_type'], 'RuntimeError')
            self.assertEqual(result['status'], 'failed')
            self.assertTrue(all(row['status'] == 'not_run' for row in result['suites']))

    def test_missing_source_evidence_is_not_equal_even_twice(self):
        unavailable = {'unavailable': 'OSError'}
        self.assertFalse(DB.same_source(unavailable, unavailable))
        with patch.object(DB.HELPERS, 'source_identity', side_effect=OSError('private text')):
            self.assertEqual(DB.source_snapshot(), unavailable)

    def test_result_never_upgrades_failed_suites_source_change_or_cleanup(self):
        for suites, unchanged, clean in (('failed', True, True), ('passed', False, True),
                                          ('passed', True, False)):
            result = DB.finalize_result({'suites_status': suites, 'source_unchanged': unchanged},
                                        {'clean': clean})
            self.assertEqual(result['status'], 'failed')

    def test_source_change_invalidates_otherwise_successful_suite(self):
        with tempfile.TemporaryDirectory() as parent:
            output = DB.fresh_output(Path(parent) / 'evidence')
            with patch.object(DB.HELPERS, 'candidate_database_port', return_value=54321):
                fixture = DB.OwnedRoomDatabase(output, {})
            fixture.command = Mock(return_value=0)
            record = {}
            changed = {**SOURCE, 'source_files_sha256': 'different'}
            with patch.object(DB, 'source_snapshot', side_effect=[SOURCE, changed]), \
                    patch.object(DB, 'validate_suite_log', return_value={'complete': True}):
                fixture.run_suite(*DB.SUITES[0], record)
            self.assertEqual(record['status'], 'failed')
            self.assertEqual(record['exit_code'], 0)
            self.assertTrue(record['source_changed'])
            self.assertEqual(len(record['script_sha256']), 64)
            self.assertEqual(len(record['command_sha256']), 64)
            with patch.object(DB.HELPERS, 'listener_closed', return_value=True):
                fixture.stop()


class ProcessPolicyTests(unittest.TestCase):
    def setUp(self):
        self.groups = patch.object(DB, 'owned_group_exists', return_value=False)
        self.groups.start()
        self.addCleanup(self.groups.stop)

    def fixture(self, output):
        with patch.object(DB.HELPERS, 'candidate_database_port', return_value=54321):
            return DB.OwnedRoomDatabase(output, {})

    def test_postgres_binds_loopback_only_without_unix_sockets(self):
        with tempfile.TemporaryDirectory() as parent:
            fixture = self.fixture(DB.fresh_output(Path(parent) / 'evidence'))
            fixture.command = Mock(return_value=0)
            fixture.wait_for_owned_postgres = Mock()
            child = Mock(returncode=0)
            child.poll.return_value = 0
            with patch.object(DB, 'postgres_environment', side_effect=lambda env: env), \
                    patch.object(DB.subprocess, 'Popen', return_value=child) as popen:
                fixture.start()
            argv = popen.call_args.args[0]
            self.assertEqual(argv[argv.index('-h') + 1], '127.0.0.1')
            self.assertEqual(argv[argv.index('-k') + 1], '')
            self.assertEqual(argv[argv.index('-p') + 1], '54321')
            self.assertIn('max_connections=100', argv)
            self.assertTrue(popen.call_args.kwargs['start_new_session'])
            initdb = fixture.command.call_args_list[0].args[0]
            self.assertIn('--auth-local=reject', initdb)
            self.assertIn('--auth-host=scram-sha-256', initdb)
            self.assertEqual(initdb[initdb.index('-U') + 1], 'xmpp_test')
            self.assertEqual((fixture.runtime / 'password').stat().st_mode & 0o777, 0o600)
            with patch.object(DB.HELPERS, 'listener_closed', return_value=True):
                fixture.stop()

    def test_ready_listener_must_match_exact_owned_data_directory(self):
        with tempfile.TemporaryDirectory() as parent:
            fixture = self.fixture(DB.fresh_output(Path(parent) / 'evidence'))
            fixture.postgres = Mock(pid=1234, returncode=0)
            fixture.postgres.poll.return_value = None
            (fixture.runtime / 'data').mkdir()
            (fixture.runtime / 'data/postmaster.pid').write_text('1234\n')
            with patch.object(DB.subprocess, 'check_output', return_value='/another/database\n'):
                with self.assertRaisesRegex(RuntimeError, 'not fixture-owned'):
                    fixture.wait_for_owned_postgres()
            fixture.postgres.poll.return_value = 0
            with patch.object(DB.HELPERS, 'listener_closed', return_value=True):
                fixture.stop()

    def test_fast_shutdown_timeout_is_failure_even_after_immediate_exit(self):
        with tempfile.TemporaryDirectory() as parent:
            fixture = self.fixture(DB.fresh_output(Path(parent) / 'evidence'))
            child = Mock(returncode=0)
            child.poll.side_effect = [None, 0]
            child.wait.side_effect = [subprocess.TimeoutExpired('postgres', 10), 0]
            fixture.postgres = child
            with patch.object(DB.HELPERS, 'listener_closed', return_value=True):
                report = fixture.stop()
            self.assertFalse(report['clean'])
            self.assertEqual([call.args[0] for call in child.send_signal.call_args_list],
                             [signal.SIGINT, signal.SIGQUIT])
            self.assertFalse(report['runtime_removed'])
            self.assertFalse(report['postgres_fast_shutdown_confirmed'])

    def test_live_owned_child_or_listener_prevents_runtime_deletion(self):
        with tempfile.TemporaryDirectory() as parent:
            fixture = self.fixture(DB.fresh_output(Path(parent) / 'evidence'))
            child = Mock(returncode=None)
            child.poll.return_value = None
            child.wait.side_effect = subprocess.TimeoutExpired('postgres', 5)
            fixture.postgres = child
            with patch.object(DB.HELPERS, 'listener_closed', return_value=False), \
                    patch.object(DB, 'signal_owned_group') as signal_group, \
                    patch.object(DB, 'owned_group_exists', return_value=True), \
                    patch.object(DB, 'wait_owned_group_closed', return_value=False):
                report = fixture.stop()
            self.assertTrue(all(call.args == (child, signal.SIGKILL)
                                for call in signal_group.call_args_list))
            self.assertFalse(report['clean'])
            self.assertTrue(report['forced_kill'])
            self.assertFalse(report['runtime_removed'])
            self.assertTrue(fixture.runtime.exists())

    def test_unclean_postmaster_exit_retains_runtime_even_after_group_and_listener_close(self):
        with tempfile.TemporaryDirectory() as parent:
            fixture = self.fixture(DB.fresh_output(Path(parent) / 'evidence'))
            child = Mock(pid=54321, returncode=-signal.SIGKILL)
            child.poll.return_value = -signal.SIGKILL
            fixture.postgres = child
            with patch.object(DB.HELPERS, 'listener_closed', return_value=True):
                report = fixture.stop()
            self.assertFalse(report['clean'])
            self.assertTrue(report['postgres_group_closed'])
            self.assertTrue(report['postgres_listener_closed'])
            self.assertFalse(report['postgres_fast_shutdown_confirmed'])
            self.assertFalse(report['runtime_removed'])
            self.assertTrue(fixture.runtime.exists())

    def test_confirmed_clean_fast_shutdown_permits_runtime_removal(self):
        with tempfile.TemporaryDirectory() as parent:
            fixture = self.fixture(DB.fresh_output(Path(parent) / 'evidence'))
            child = Mock(pid=54321, returncode=0)
            child.poll.side_effect = [None, 0]
            child.wait.return_value = 0
            fixture.postgres = child
            with patch.object(DB.HELPERS, 'listener_closed', return_value=True):
                report = fixture.stop()
            self.assertTrue(report['clean'])
            self.assertTrue(report['postgres_fast_shutdown_confirmed'])
            self.assertTrue(report['runtime_removed'])
            self.assertFalse(fixture.runtime.exists())

    def test_command_cleanup_uses_only_its_owned_process_group_and_reaps(self):
        child = Mock(pid=54321, returncode=-signal.SIGKILL)
        child.poll.return_value = None
        child.wait.side_effect = [subprocess.TimeoutExpired('child', 5), -signal.SIGKILL]
        with patch.object(DB.os, 'killpg') as killpg:
            report = DB.stop_owned_command(child)
        self.assertTrue(report['forced_kill'])
        self.assertFalse(report['clean'])
        self.assertTrue(all(call.args[0] == 54321 for call in killpg.call_args_list))
        self.assertEqual(child.wait.call_count, 2)

    def test_normal_leader_exit_still_cleans_and_verifies_live_descendants(self):
        child = Mock(pid=54321, returncode=0)
        child.poll.return_value = 0
        with patch.object(DB, 'owned_group_exists', side_effect=[True, False]), \
                patch.object(DB, 'wait_owned_group_closed', side_effect=[False, True]), \
                patch.object(DB, 'signal_owned_group') as signal_group:
            report = DB.stop_owned_command(child)
        self.assertTrue(report['residual_group'])
        self.assertTrue(report['group_closed'])
        self.assertTrue(report['forced_kill'])
        self.assertFalse(report['clean'])
        self.assertEqual(signal_group.call_args_list[0].args, (child, signal.SIGTERM))
        self.assertEqual(signal_group.call_args_list[1].args, (child, signal.SIGKILL))

    def test_every_normal_command_exit_uses_the_group_cleanup_owner(self):
        with tempfile.TemporaryDirectory() as parent:
            fixture = self.fixture(DB.fresh_output(Path(parent) / 'evidence'))
            child = Mock(pid=54321, returncode=0)
            child.wait.return_value = 0
            child.poll.return_value = 0
            cleanup = {'clean': False, 'group_closed': True, 'forced_kill': True,
                       'errors': ['residual child']}
            with patch.object(DB.subprocess, 'Popen', return_value=child), \
                    patch.object(DB, 'stop_owned_command', return_value=cleanup) as stop:
                with self.assertRaisesRegex(RuntimeError, 'abnormal process-group'):
                    fixture.command(['bash', 'owned-suite'], 'suite.log', 1)
            stop.assert_called_once_with(child)
            self.assertIsNone(fixture.active_command)
            self.assertEqual(fixture.command_cleanup, [cleanup])
            self.assertEqual(fixture.last_command_exit, 0)
            with patch.object(DB.HELPERS, 'listener_closed', return_value=True):
                report = fixture.stop()
            self.assertFalse(report['clean'])

    def test_spawn_failure_does_not_reuse_a_previous_exit_code(self):
        with tempfile.TemporaryDirectory() as parent:
            fixture = self.fixture(DB.fresh_output(Path(parent) / 'evidence'))
            fixture.last_command_exit = 0
            with patch.object(DB.subprocess, 'Popen', side_effect=OSError('spawn failed')):
                with self.assertRaises(OSError):
                    fixture.command(['bash', 'owned-suite'], 'suite.log', 1)
            self.assertIsNone(fixture.last_command_exit)
            with patch.object(DB.HELPERS, 'listener_closed', return_value=True):
                fixture.stop()

    def test_cleanup_signal_mask_is_restored(self):
        before = {kind: signal.getsignal(kind) for kind in (signal.SIGINT, signal.SIGTERM)}
        with DB.cleanup_signals():
            self.assertTrue(all(signal.getsignal(kind) == signal.SIG_IGN for kind in before))
        self.assertEqual({kind: signal.getsignal(kind) for kind in before}, before)


class TestEvidenceTests(unittest.TestCase):
    def log(self, name):
        return ''.join(f'test {test} ... ok\n'
                       'test result: ok. 1 passed; 0 failed; 0 ignored; 20 filtered out\n'
                       'test result: ok. 0 passed; 0 failed; 0 ignored; 0 filtered out\n'
                       for test in DB.EXPECTED_TESTS[name])

    def validate(self, text, name='muc'):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'suite.log'
            path.write_text(text)
            return DB.validate_suite_log(name, path)

    def test_all_fixed_tests_need_exact_named_completions_and_matching_totals(self):
        for name, _script in DB.SUITES:
            result = self.validate(self.log(name), name)
            self.assertTrue(result['complete'])
            self.assertEqual(result['passed_exact_tests'], len(DB.EXPECTED_TESTS[name]))
        self.assertEqual(sum(len(tests) for tests in DB.EXPECTED_TESTS.values()), 27)

    def test_current_scripts_match_the_fixed_selector_manifest(self):
        for name, script in DB.SUITES:
            declared = DB.re.findall(r'^\s*((?:db|services)::[A-Za-z0-9_:]+)\s*\\?\s*$',
                                     (ROOT / script).read_text(), DB.re.MULTILINE)
            self.assertEqual(tuple(declared), DB.EXPECTED_TESTS[name])

    def test_zero_test_success_does_not_establish_suite_success(self):
        result = self.validate('test result: ok. 0 passed; 0 failed; 0 ignored\n')
        self.assertFalse(result['complete'])
        self.assertEqual(len(result['missing_tests']), 6)

    def test_missing_duplicate_ignored_failed_and_unknown_tests_are_rejected(self):
        good = self.log('muc')
        first = DB.EXPECTED_TESTS['muc'][0]
        mutations = [
            good.replace(f'test {first} ... ok\n', ''),
            good + f'test {first} ... ok\n',
            good.replace(f'test {first} ... ok', f'test {first} ... ignored'),
            good.replace(f'test {first} ... ok', f'test {first} ... FAILED'),
            good.replace(first, 'unknown::payload_not_reflected'),
            good.replace('1 passed;', '0 passed;', 1),
        ]
        for text in mutations:
            with self.subTest(text=text[:80]):
                self.assertFalse(self.validate(text)['complete'])

    def test_nocapture_diagnostics_can_split_name_and_ok_without_losing_identity(self):
        good = self.log('authentication')
        good = good.replace(' ... ok\n', ' ... isolated_schema=synthetic\nother diagnostic\nok\n')
        self.assertTrue(self.validate(good, 'authentication')['complete'])


if __name__ == '__main__':
    unittest.main()
