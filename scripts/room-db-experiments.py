#!/usr/bin/env python3
"""Run the fixed MUC, MIX and authentication DB suites on owned PostgreSQL.

Creates one private, loopback-TCP-only PostgreSQL child and a fresh xmpp_test
database. Never attaches to an existing database. Suites run serially with one
Cargo build job, retaining their existing isolated-schema ownership checks.
Evidence contains commands, hashes, timings and logs, never the database or
password file. Run as an ordinary user after loading the desired Rust/PG tools.
"""
from __future__ import annotations

import argparse
import collections
import contextlib
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
SOURCE = Path(__file__).resolve().parents[1]
SUITES = (
    ('muc', 'scripts/muc-db-wsl.sh'),
    ('mix', 'scripts/mix-family-db-wsl.sh'),
    ('authentication', 'scripts/authentication-service-db-wsl.sh'),
)
SUITE_TIMEOUT_SECONDS = 1800
PASSWORD = 'xmpp-test-password'  # Fixed disposable identity required by these suites.
EXPECTED_TESTS = {
    'muc': (
        'db::muc::tests::locked_room_configuration_is_atomic_restart_safe_and_bounded',
        'db::muc::tests::durable_invitation_admission_is_atomic_under_injected_failures',
        'db::muc::tests::history_identity_and_mutations_are_atomic_under_replay_and_failure',
        'db::cluster_muc::tests::postgres_outbox_maintenance_is_atomic_and_snapshot_is_complete',
        'db::cluster_muc::tests::postgres_admin_batch_is_atomic_under_replay_and_failure',
        'db::cluster_muc::tests::federated_rebind_is_atomic_and_fences_the_old_connection',
    ),
    'mix': (
        'db::mix::pam_durability_integration_tests::pam_restart_and_result_claims_preserve_authority_and_token_fencing',
        'db::mix::delivery_sequence_retention_integration_tests::sequence_gc_preserves_a_producer_committed_after_its_snapshot',
        'db::mix::delivery_sequence_retention_integration_tests::event_gc_preserves_a_requeue_committed_after_its_snapshot',
        'db::mix::delivery_sequence_retention_integration_tests::empty_delivery_claim_avoids_the_event_lock_and_recovers_after_insert',
        'db::mix::delivery_sequence_retention_integration_tests::empty_delivery_claim_preserves_database_authority_errors',
        'db::mix::delivery_route_wake_integration_tests::an_expired_unowned_head_blocks_until_terminalized',
        'db::mix::mam_integration_tests::mix_anon_misc_permissions_are_atomic_and_private',
        'db::mix::delivery_capacity_integration_tests::delivery_ack_is_independent_of_the_producer_fence_and_release_is_atomic',
        'db::mix::delivery_route_wake_integration_tests::leased_route_wake_defeats_defer_and_retry_but_not_unrelated_backoff',
        'db::mix::delivery_route_wake_integration_tests::attempt_limit_route_wake_gets_one_fresh_claim_before_dead_letter',
        'db::mix::delivery_route_wake_integration_tests::dead_letter_requeue_uses_tail_and_preserves_current_head_wake',
    ),
    'authentication': (
        'services::authentication::tests::authentication_service_fences_all_credential_and_inline_state_transitions',
        'services::authentication::tests::bind2_recovers_failed_pooled_transaction_before_preflight',
        'services::authentication::tests::bind2_resets_active_pooled_transaction_before_preflight',
        'services::authentication::tests::login_epoch_publication_is_fenced_invisible_and_atomic_with_binding',
        'services::authentication::tests::publication_lease_lock_blocks_reserve_release_and_fences_expiry_cleanup',
        'db::fast::tests::fast_derivation_integrity_failures_are_side_effect_free',
        'db::capacity::tests::postgres_capacity_audit_compares_complete_entity_and_counter_sets',
        'db::capacity::tests::postgres_capacity_fixture_is_atomic_leased_and_idempotent',
        'db::account_revocations::tests::committed_revocations_survive_lost_wakes_and_stale_acknowledgements',
        'db::passkeys::tests::ceremonies_are_single_use_and_key_removal_fences_sessions',
    ),
}


def load_soak_helpers():
    spec = importlib.util.spec_from_file_location(
        'room_db_soak_helpers', SOURCE / 'scripts/mixed-traffic-soak.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HELPERS = load_soak_helpers()


def source_snapshot():
    try:
        return HELPERS.source_identity()
    except Exception as error:
        return {'unavailable': type(error).__name__}


def same_source(before, after):
    return ('source_files_sha256' in before and 'source_files_sha256' in after
            and before == after)


def fresh_output(path):
    """Only create a new private evidence directory outside the checkout."""
    if path is None:
        output = Path(tempfile.mkdtemp(prefix='northstar-room-db-evidence-', dir='/tmp'))
    else:
        path = Path(path).expanduser()
        if os.path.lexists(path):
            raise ValueError('output directory must not already exist')
        parent = path.parent.resolve(strict=True)
        output = parent / path.name
        if output == SOURCE or SOURCE in output.parents:
            raise ValueError('output directory must be outside the source checkout')
        output.mkdir(mode=0o700)
    output.chmod(0o700)
    return output


def fixture_environment(environment, runtime, port):
    """Keep requested build tools/caches, never ambient application/libpq config."""
    allowed = {'PATH', 'LD_LIBRARY_PATH', 'LANG', 'LC_ALL', 'TZ',
               'CARGO_HOME', 'RUSTUP_HOME', 'CARGO_TARGET_DIR', 'CARGO_INCREMENTAL'}
    result = {key: value for key, value in environment.items()
              if key in allowed or re.fullmatch(
                  r'CARGO_PROFILE_(DEV|TEST)_(DEBUG|OPT_LEVEL|DEBUG_ASSERTIONS|'
                  r'OVERFLOW_CHECKS|LTO|PANIC|INCREMENTAL|CODEGEN_UNITS|STRIP|RPATH)', key)}
    # Resolve conventional toolchain homes before replacing HOME. This keeps
    # a normal rustup installation usable without exposing ~/.pgpass/.psqlrc.
    original_home = Path(environment.get('HOME', str(Path.home())))
    result.setdefault('CARGO_HOME', str(original_home / '.cargo'))
    result.setdefault('RUSTUP_HOME', str(original_home / '.rustup'))
    result.update(
        HOME=str(runtime / 'home'), TMPDIR=str(runtime / 'tmp'),
        PGHOST='127.0.0.1', PGPORT=str(port), PGUSER='xmpp_test',
        PGDATABASE='xmpp_test', PGPASSWORD=PASSWORD, PGCONNECT_TIMEOUT='2',
        PGPASSFILE=str(runtime / 'empty'), PGSERVICEFILE=str(runtime / 'empty'),
        PGSYSCONFDIR=str(runtime / 'home'), PSQLRC=str(runtime / 'empty'),
        CARGO_BUILD_JOBS='1', CARGO_NET_OFFLINE='true', RUST_TEST_THREADS='1',
        CARGO_TERM_COLOR='never',
        XMPP_TEST_SYSTEM_TOOLCHAIN='true', XMPP_TEST_OFFLINE='true',
        XMPP_TEST_DATABASE='xmpp_test', NORTHSTAR_DISABLE_DOTENV='true',
        PYTHONDONTWRITEBYTECODE='1',
    )
    return result


def postgres_environment(environment):
    result = dict(environment)
    path = result.get('PATH', os.defpath)
    if shutil.which('initdb', path=path) is None:
        config = shutil.which('pg_config', path=path)
        if config is not None:
            bindir = subprocess.check_output([config, '--bindir'], env=result,
                                            text=True, timeout=5).strip()
            if Path(bindir, 'initdb').is_file():
                result['PATH'] = bindir + os.pathsep + path
    for name in ('initdb', 'postgres', 'createdb', 'psql', 'bash', 'cargo'):
        if shutil.which(name, path=result.get('PATH', path)) is None:
            raise RuntimeError(f'required fixture tool is missing: {name}')
    return result


@contextlib.contextmanager
def cleanup_signals():
    previous = {kind: signal.signal(kind, signal.SIG_IGN)
                for kind in (signal.SIGINT, signal.SIGTERM)}
    try:
        yield
    finally:
        for kind, handler in previous.items():
            signal.signal(kind, handler)


def signal_owned_group(child, kind):
    # Every supplied child was created here with start_new_session=True.
    # Never discover or signal another process by executable name or port.
    try:
        os.killpg(child.pid, kind)
    except ProcessLookupError:
        pass


def owned_group_exists(child):
    try:
        os.killpg(child.pid, 0)
        return True
    except ProcessLookupError:
        return False


def wait_owned_group_closed(child, seconds):
    deadline = time.monotonic() + seconds
    while owned_group_exists(child):
        if time.monotonic() >= deadline:
            return False
        time.sleep(.05)
    return True


def stop_owned_command(child):
    report = {'clean': True, 'forced_kill': False, 'errors': []}
    if child.poll() is None:
        signal_owned_group(child, signal.SIGTERM)
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            report['forced_kill'] = True
            signal_owned_group(child, signal.SIGKILL)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                report['errors'].append('command child could not be reaped')
    else:
        child.wait()
    # A normally exited shell can also leave cargo/compiler descendants. The
    # leader's exit is not a group-completion proof, even with exit code zero.
    report['residual_group'] = owned_group_exists(child)
    if report['residual_group']:
        report['errors'].append('command leader left a residual process group')
        signal_owned_group(child, signal.SIGTERM)
        if not wait_owned_group_closed(child, 5):
            report['forced_kill'] = True
            signal_owned_group(child, signal.SIGKILL)
            if not wait_owned_group_closed(child, 5):
                report['errors'].append('command process group did not close')
    report['group_closed'] = not owned_group_exists(child)
    report['exit_code'] = child.returncode
    report['clean'] = not report['errors'] and not report['forced_kill']
    return report


def validate_suite_log(name, path):
    """Count exact reviewed test completions, never accept a zero-test filter."""
    expected = set(EXPECTED_TESTS[name])
    observed = collections.Counter()
    summaries = 0
    pending = None
    invalid = False
    total_bytes = 0
    with path.open(errors='replace') as stream:
        for line in stream:
            total_bytes += len(line)
            if total_bytes > 32 * 1024 * 1024 or len(line) > 64 * 1024:
                invalid = True
                break
            start = re.match(r'^test ([A-Za-z0-9_:]+) \.\.\.\s*(.*)', line)
            if start:
                if pending is not None:
                    invalid = True
                pending = start[1]
                tail = start[2].strip()
            else:
                tail = line.strip()
            # --nocapture may insert diagnostics between libtest's name and
            # its final outcome. RUST_TEST_THREADS=1 keeps that pair serial.
            if pending is not None and tail in ('ok', 'FAILED', 'ignored'):
                if pending not in expected or tail != 'ok':
                    invalid = True
                else:
                    observed[pending] += 1
                pending = None
            summary = re.match(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed;', line)
            if summary:
                summaries += int(summary[2])
                if summary[1] != 'ok' or int(summary[3]) != 0:
                    invalid = True
    missing = sorted(test for test in expected if observed[test] == 0)
    duplicate = sorted(test for test in expected if observed[test] > 1)
    complete = not invalid and pending is None and not missing and not duplicate
    complete = complete and summaries == len(expected)
    return {'complete': complete, 'expected_tests': len(expected),
            'passed_exact_tests': sum(observed.values()), 'summary_passed_tests': summaries,
            'missing_tests': missing, 'duplicate_tests': duplicate,
            'invalid_output': invalid or pending is not None}


def finalize_result(result, cleanup):
    result['cleanup'] = cleanup
    result['status'] = ('passed' if result.get('suites_status') == 'passed'
                        and result.get('source_unchanged') is True
                        and cleanup.get('clean') is True else 'failed')
    return result


class OwnedRoomDatabase:
    def __init__(self, output, environment, suite_timeout=SUITE_TIMEOUT_SECONDS):
        self.output = output
        # Runtime secrets/data are siblings, never evidence-directory contents.
        self.runtime = Path(tempfile.mkdtemp(prefix='northstar-room-db-runtime-',
                                             dir=output.parent))
        self.runtime.chmod(0o700)
        for name in ('home', 'tmp'):
            (self.runtime / name).mkdir(mode=0o700)
        (self.runtime / 'empty').touch(mode=0o600)
        self.port = HELPERS.candidate_database_port()
        self.environment = fixture_environment(environment, self.runtime, self.port)
        self.suite_timeout = suite_timeout
        self.postgres = None
        self.postgres_log = None
        self.active_command = None
        self.command_cleanup = []
        self.last_command_exit = None

    def command(self, argv, log_name, timeout):
        self.last_command_exit = None
        with (self.output / log_name).open('x') as log:
            child = subprocess.Popen([str(part) for part in argv], cwd=SOURCE,
                                     env=self.environment, stdout=log,
                                     stderr=subprocess.STDOUT, start_new_session=True)
            self.active_command = child
            try:
                code = child.wait(timeout=timeout)
            finally:
                with cleanup_signals():
                    try:
                        cleanup = stop_owned_command(child)
                    except Exception as error:
                        cleanup = {'clean': False, 'forced_kill': False, 'group_closed': False,
                                   'errors': [type(error).__name__]}
                    self.command_cleanup.append(cleanup)
                self.last_command_exit = child.returncode
                if child.poll() is not None and cleanup['group_closed']:
                    self.active_command = None
            if not cleanup['clean']:
                raise RuntimeError('command required abnormal process-group cleanup')
            return code

    def start(self):
        self.environment = postgres_environment(self.environment)
        password = self.runtime / 'password'
        password.write_text(PASSWORD + '\n')
        password.chmod(0o600)
        if self.command(['initdb', '-D', self.runtime / 'data', '-U', 'xmpp_test',
                         '--pwfile=' + str(password), '--auth-host=scram-sha-256',
                         '--auth-local=reject', '--no-locale', '--encoding=UTF8'],
                        'initdb.log', 120) != 0:
            raise RuntimeError('owned initdb failed; see initdb.log')
        self.postgres_log = (self.output / 'postgresql.log').open('x')
        self.postgres = subprocess.Popen(
            ['postgres', '-D', str(self.runtime / 'data'), '-h', '127.0.0.1',
             '-p', str(self.port), '-k', '', '-c', 'max_connections=100',
             '-c', 'shared_buffers=32MB'],
            cwd=self.runtime, env=self.environment, stdout=self.postgres_log,
            stderr=subprocess.STDOUT, start_new_session=True)
        self.wait_for_owned_postgres()
        if self.command(['createdb', '--host=127.0.0.1', f'--port={self.port}',
                         '--username=xmpp_test', '--maintenance-db=postgres',
                         '--encoding=UTF8', 'xmpp_test'],
                        'createdb.log', 30) != 0:
            raise RuntimeError('owned database creation failed; see createdb.log')

    def wait_for_owned_postgres(self):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.postgres.poll() is not None:
                raise RuntimeError('owned PostgreSQL exited during startup')
            try:
                pid = (self.runtime / 'data/postmaster.pid').read_text().splitlines()[0]
            except (OSError, IndexError):
                time.sleep(.1)
                continue
            if pid != str(self.postgres.pid):
                raise RuntimeError('owned PostgreSQL PID does not match its data directory')
            # Verify the listener is this child's exact data directory before
            # any createdb/schema mutation. A candidate port is not a lease.
            try:
                directory = subprocess.check_output(
                    ['psql', '-X', '--host=127.0.0.1', f'--port={self.port}',
                     '--username=xmpp_test', '--dbname=postgres', '-At',
                     '-v', 'ON_ERROR_STOP=1', '-c', "SHOW data_directory"],
                    env=self.environment, stderr=subprocess.DEVNULL,
                    text=True, timeout=3).strip()
            except (OSError, subprocess.SubprocessError):
                time.sleep(.1)
                continue
            if directory != str(self.runtime / 'data'):
                raise RuntimeError('candidate PostgreSQL listener is not fixture-owned')
            if self.postgres.poll() is not None:
                raise RuntimeError('owned PostgreSQL exited after readiness')
            return
        raise TimeoutError('owned PostgreSQL startup exceeded 30 seconds')

    def run_suite(self, name, script, record):
        declared = re.findall(r'^\s*((?:db|services)::[A-Za-z0-9_:]+)\s*\\?\s*$',
                              (SOURCE / script).read_text(), re.MULTILINE)
        if tuple(declared) != EXPECTED_TESTS[name]:
            raise RuntimeError('suite selectors differ from the reviewed experiment manifest')
        command = ['bash', str(SOURCE / script)]
        record.update(name=name, script=script, command=command,
                      command_sha256=hashlib.sha256(json.dumps(command).encode()).hexdigest(),
                      script_sha256=HELPERS.digest(SOURCE / script),
                      source_before=source_snapshot(), started_at=HELPERS.stamp(),
                      log=f'{name}.log', status='running')
        started = time.monotonic()
        try:
            record['exit_code'] = self.command(command, record['log'], self.suite_timeout)
            record['tests'] = validate_suite_log(name, self.output / record['log'])
            record['status'] = ('passed' if record['exit_code'] == 0
                                and record['tests']['complete'] else 'failed')
        except BaseException as error:
            record.update(status='failed', error_type=type(error).__name__)
            record['exit_code'] = self.last_command_exit
            raise
        finally:
            record.update(finished_at=HELPERS.stamp(), elapsed_seconds=time.monotonic() - started)
            record['source_after'] = source_snapshot()
            record['source_unchanged'] = same_source(record['source_before'], record['source_after'])
            if not record['source_unchanged']:
                record['status'] = 'failed'
                record['source_changed'] = True

    def stop(self):
        report = {'clean': True, 'forced_kill': False, 'errors': [],
                  'command_cleanup': self.command_cleanup,
                  'postgres_started': self.postgres is not None,
                  'postgres_fast_shutdown_confirmed': False}
        if self.active_command is not None:
            try:
                self.command_cleanup.append(stop_owned_command(self.active_command))
            except Exception as error:
                report['errors'].append(f'command cleanup: {type(error).__name__}')
        if any(not entry['clean'] for entry in self.command_cleanup):
            report['errors'].append('a command required forced or incomplete cleanup')
        if self.postgres is not None:
            try:
                if self.postgres.poll() is None:
                    # SIGINT is PostgreSQL fast shutdown, then SIGQUIT immediate.
                    self.postgres.send_signal(signal.SIGINT)
                    try:
                        self.postgres.wait(timeout=10)
                        report['postgres_fast_shutdown_confirmed'] = self.postgres.returncode == 0
                    except subprocess.TimeoutExpired:
                        report['errors'].append('PostgreSQL exceeded fast-shutdown budget')
                        self.postgres.send_signal(signal.SIGQUIT)
                        try:
                            self.postgres.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            report['forced_kill'] = True
                            signal_owned_group(self.postgres, signal.SIGKILL)
                            self.postgres.wait(timeout=5)
                else:
                    self.postgres.wait()
                    report['errors'].append('PostgreSQL exited before fixture shutdown')
                report['postgres_exit_code'] = self.postgres.returncode
                if self.postgres.returncode != 0:
                    report['errors'].append('PostgreSQL did not exit cleanly')
            except Exception as error:
                report['errors'].append(f'PostgreSQL cleanup: {type(error).__name__}')
            # Unexpected postmaster exit can leave non-listening descendants.
            # Retain ownership until the complete process group is absent.
            try:
                if owned_group_exists(self.postgres):
                    report['errors'].append('PostgreSQL left a residual process group')
                    report['forced_kill'] = True
                    signal_owned_group(self.postgres, signal.SIGKILL)
                    wait_owned_group_closed(self.postgres, 5)
                report['postgres_group_closed'] = not owned_group_exists(self.postgres)
            except Exception as error:
                report['postgres_group_closed'] = False
                report['errors'].append(f'PostgreSQL group cleanup: {type(error).__name__}')
        if self.postgres_log is not None:
            self.postgres_log.close()
        report['postgres_listener_closed'] = HELPERS.listener_closed(f'127.0.0.1:{self.port}')
        if not report['postgres_listener_closed']:
            report['errors'].append('candidate PostgreSQL listener remains open')
        # PostgreSQL backends can detach into separate process groups. Only a
        # confirmed clean fast shutdown proves their termination; a reaped or
        # SIGKILLed postmaster plus closed listener/group is insufficient.
        # Retain private runtime after every unclean PG exit for safe recovery.
        children_reaped = all(child is None or child.poll() is not None
                              for child in (self.active_command, self.postgres))
        groups_closed = (report.get('postgres_group_closed', True)
                         and all(entry.get('group_closed', False) for entry in self.command_cleanup))
        if (children_reaped and groups_closed and report['postgres_listener_closed']
                and (self.postgres is None or report['postgres_fast_shutdown_confirmed'])):
            try:
                shutil.rmtree(self.runtime)
                report['runtime_removed'] = True
            except OSError as error:
                report['errors'].append(f'runtime cleanup: {type(error).__name__}')
        else:
            report['runtime_removed'] = False
            report['runtime_retained'] = str(self.runtime)
        report['clean'] = not report['errors']
        return report


def save_result(output, result):
    (output / 'result.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')


def run_owned_suites(fixture, result):
    result['suites'] = [{'name': name, 'script': script, 'status': 'not_run'}
                        for name, script in SUITES]
    try:
        save_result(fixture.output, result)
        fixture.start()
        result['database_port'] = fixture.port
        for record in result['suites']:
            fixture.run_suite(record['name'], record['script'], record)
            save_result(fixture.output, result)
            if record['status'] != 'passed':
                # Preserve the first failure; do not launch more Cargo work.
                break
        result['suites_status'] = ('passed' if len(result['suites']) == len(SUITES)
                                   and all(row['status'] == 'passed' for row in result['suites'])
                                   else 'failed')
    except BaseException as error:
        result.update(suites_status='failed', error_type=type(error).__name__)
    finally:
        with cleanup_signals():
            try:
                cleanup = fixture.stop()
            except Exception as error:
                cleanup = {'clean': False, 'errors': [f'cleanup: {type(error).__name__}']}
            result['source_after'] = source_snapshot()
            result['source_unchanged'] = same_source(result['source_before'], result['source_after'])
            result['finished_at'] = HELPERS.stamp()
            finalize_result(result, cleanup)
            save_result(fixture.output, result)
    return result


def parse_arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, help='new evidence directory outside source')
    parser.add_argument('--suite-timeout-seconds', type=float, default=SUITE_TIMEOUT_SECONDS,
                        help='per-suite deadline, 1..7200 seconds; default: 1800')
    args = parser.parse_args(argv)
    if not math.isfinite(args.suite_timeout_seconds) or not 1 <= args.suite_timeout_seconds <= 7200:
        parser.error('--suite-timeout-seconds must be finite and in 1..7200')
    return args


def main(argv=None):
    args = parse_arguments(argv)
    os.umask(0o077)
    output = fresh_output(args.output_dir)
    fixture = OwnedRoomDatabase(output, os.environ, args.suite_timeout_seconds)
    result = {'harness': 'scripts/room-db-experiments.py', 'started_at': HELPERS.stamp(),
              'source_before': source_snapshot(), 'suites': [],
              'suite_timeout_seconds': args.suite_timeout_seconds,
              'evidence_directory': str(output), 'cargo_build_jobs': 1,
              'runtime_artifacts_in_evidence': False}

    def interrupted(_kind, _frame):
        raise KeyboardInterrupt('operator interrupted owned DB experiments')

    previous = {kind: signal.signal(kind, interrupted) for kind in (signal.SIGINT, signal.SIGTERM)}
    try:
        run_owned_suites(fixture, result)
    finally:
        for kind, handler in previous.items():
            signal.signal(kind, handler)
    print(json.dumps({'status': result['status'], 'evidence_directory': str(output)}), flush=True)
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
