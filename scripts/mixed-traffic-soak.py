#!/usr/bin/env python3
"""Bounded single-node mixed XMPP smoke soak with owned failure evidence.

Direct and MUC opaque OMEMO envelopes, exact live delivery, MAM contents/counts,
no-store exclusion, reconnects, readiness, and graceful shutdown are checked.
This is not endurance, production-load, or real-client cryptographic proof.
Requires an already-built binary, PostgreSQL tools and openssl on PATH. Creates
an isolated TCP-only PostgreSQL instance; never attaches to an existing DB.
The private output directory (including the disposable DB) is kept for review.
"""
from __future__ import annotations

import argparse
import collections
import datetime
import errno
import hashlib
import importlib.util
import json
import math
import os
import pathlib
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import traceback
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True
from lib.experiment_contract import InvalidScenario, mixed_workload, preflight_normal

SOURCE = pathlib.Path(__file__).resolve().parents[1]
NS = '{jabber:client}'
MAM = '{urn:xmpp:mam:2}'
RSM = '{http://jabber.org/protocol/rsm}'
FORWARD = '{urn:xmpp:forward:0}'
SID = '{urn:xmpp:sid:0}'
SM = '{urn:xmpp:sm:3}'
OMEMO = '{urn:xmpp:omemo:2}'
SHUTDOWN_SECONDS = 20
RESULT_SCHEMA = 'northstar-mixed-traffic-result-v1'


class OperatorCancelled(BaseException):
    """Only the explicit operator-signal handler creates this cancellation."""

    def __init__(self, signum):
        self.signum = int(signum)
        super().__init__(f'operator signal {self.signum}')


class DomainInvariantViolation(AssertionError):
    """An observed contract failure, distinct from setup/fixture assertions."""

    def __init__(self, code, location, message):
        self.code, self.location = code, location
        super().__init__(message)


def domain_check(value, code, location, message):
    if not value:
        raise DomainInvariantViolation(code, location, message)


def operator_interrupted(signum, _frame):
    raise OperatorCancelled(signum)


def interruption_origin(error):
    if isinstance(error, OperatorCancelled):
        return {'status': 'Cancelled', 'cause': 'OperatorSignal', 'signal': error.signum}
    if isinstance(error, InterruptedError) or (isinstance(error, OSError) and error.errno == errno.EINTR):
        return {'status': 'EnvironmentInterrupted', 'cause': 'EINTR'}
    return None


def retain_cleanup_interruption(report, error):
    origin = interruption_origin(error)
    if origin is not None:
        report.setdefault('interruption', origin)


def initialize_result(result):
    result.setdefault('experiment_schema', RESULT_SCHEMA)
    result.setdefault('execution', {'status': 'Running', 'phase': 'setup', 'cause': None})
    result.setdefault('domain', {'status': 'NotStarted', 'first_invariant': None})
    result.setdefault('evidence', {'workload_terminal': False, 'complete': False, 'gaps': []})
    result.setdefault('verdict', 'Inconclusive')
    result.setdefault('qualified', False)


def evidence_gap(result, code):
    result['evidence']['complete'] = False
    gaps = result['evidence']['gaps']
    if code not in gaps and len(gaps) < 16:
        gaps.append(code)


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def emit(kind, **values):
    print(json.dumps({'at': stamp(), 'event': kind, **values}), flush=True)


def check(value, message):
    if not value:
        raise AssertionError(message)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with pathlib.Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def minimum_rounds(seconds):
    # Preserve the original 200-round/600-second minimum, with the original
    # two-second pacing. An explicitly shorter run gets proportional coverage.
    return max(1, math.ceil(seconds / 3))


def fixture_environment(environment):
    # Do not inherit app configuration, Redis addresses, external credentials,
    # libpq service files or an ambient production DATABASE_URL.
    allowed = {'PATH', 'HOME', 'TMPDIR', 'LD_LIBRARY_PATH', 'LANG', 'LC_ALL', 'TZ'}
    return {key: value for key, value in environment.items() if key in allowed}


def source_identity():
    """Record an honest Git identity when available, and hash archive sources too."""
    try:
        if not (SOURCE / '.git').exists():
            raise FileNotFoundError('source archive has no Git metadata')
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=SOURCE,
                                         stderr=subprocess.DEVNULL, text=True, timeout=5).strip()
    except InterruptedError:
        raise
    except (OSError, subprocess.SubprocessError):
        commit = None
    roots = ('src', 'crates', 'services', 'migrations', 'scripts', 'tests', 'web',
             'contracts', 'catalog', 'tools', 'third_party', '.github')
    excluded = {'.git', 'target', 'node_modules', '__pycache__', '.pytest_cache'}
    paths = []
    for name in roots:
        for directory, subdirectories, files in os.walk(SOURCE / name):
            subdirectories[:] = [child for child in subdirectories
                                 if child not in excluded and not child.startswith('target-')]
            paths.extend(pathlib.Path(directory) / name for name in files
                         if not name.endswith(('.pyc', '.log')))
    paths.extend(path for path in SOURCE.iterdir() if path.is_file() and
                 (path.suffix in {'.toml', '.lock', '.md', '.yaml', '.yml'}
                  or path.name.endswith('.example')))
    fingerprint = hashlib.sha256()
    for path in sorted(set(paths)):
        fingerprint.update(path.relative_to(SOURCE).as_posix().encode() + b'\0')
        contents = (os.readlink(path).encode() if path.is_symlink()
                    else digest(path).encode())
        fingerprint.update(contents + b'\0')
    return {'commit': commit, 'source_files_sha256': fingerprint.hexdigest(),
            'source_file_count': len(set(paths))}


def fixture_log_filter(trace_frames):
    # Do not accept an arbitrary ambient filter: experiments opt in only to
    # the sanitized execution target, never XML/authentication payload logs.
    base = 'rust_xmpp_server=info'
    return base + ',rust_xmpp_server::xmpp::frame_execution=debug' if trace_frames else base


def candidate_database_port():
    # This selects a candidate, never a lease or proof of ownership. pg_ctl
    # must successfully bind the isolated data directory; a race fails startup.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
        stream.bind(('127.0.0.1', 0))
        return stream.getsockname()[1]


def finalize_result(result, cleanup):
    """Qualify structured runs without erasing prior failure or cancellation.

    Legacy callers supplying only workload_status retain their old passed/failed
    shape; that shape emits no structured Pass/qualification claim. The actual
    runner always initializes RESULT_SCHEMA before setup or workload execution.
    """
    result['cleanup'] = cleanup
    if result.get('experiment_schema') == RESULT_SCHEMA:
        if cleanup.get('interruption') is not None and result['execution']['status'] in ('Running', 'Completed'):
            result['execution'] = {**cleanup['interruption'], 'phase': 'cleanup'}
            evidence_gap(result, 'cleanup_interrupted')
        clean_claim = cleanup.get('clean') is True and not cleanup.get('errors')
        cleanup_status = cleanup.get('status')
        if (cleanup_status not in ('Clean', 'NotRequired', 'Incomplete')
                or (cleanup_status in ('Clean', 'NotRequired')) != clean_claim):
            evidence_gap(result, 'cleanup_report_inconsistent')
        clean = (clean_claim and cleanup.get('independent') is True
                 and cleanup_status in ('Clean', 'NotRequired'))
        execution, domain, evidence = result['execution'], result['domain'], result['evidence']
        if domain['first_invariant'] is not None:
            verdict = 'InvariantViolation'
        elif execution['status'] == 'Cancelled':
            verdict = 'Cancelled'
        elif execution['status'] == 'EnvironmentInterrupted':
            verdict = 'EnvironmentInterrupted'
        elif (execution['status'] == 'Completed' and domain['status'] == 'Verified'
              and result.get('workload_status') == 'passed' and evidence['workload_terminal'] is True
              and evidence['complete'] is True and not evidence['gaps'] and clean):
            verdict = 'Pass'
        else:
            verdict = 'Inconclusive'
        result.update(verdict=verdict, qualified=verdict == 'Pass',
                      status='passed' if verdict == 'Pass' else 'failed')
        return result
    result['status'] = ('passed' if result.get('workload_status') == 'passed'
                        and cleanup.get('clean') is True else 'failed')
    return result


class OwnedFixture:
    """Own every child and path; observation never owns the server lifecycle."""

    def __init__(self, binary, output, database_port, trace_frames=False):
        self.input_binary = binary
        self.output = output
        self.database_port = database_port
        self.trace_frames = trace_frames
        self.server = None
        self.server_log = None
        self.pg_attempted = False
        self.listeners = {}
        self.runtime = output / 'fixture'
        self.runtime.mkdir(mode=0o700)
        self.environment = fixture_environment(os.environ)
        self.pg_environment = {**self.environment, 'PGPASSWORD': 'short-soak-db-password',
                               'PGHOST': '127.0.0.1', 'PGPORT': str(database_port),
                               'PGUSER': 'short_soak', 'PGDATABASE': 'short_soak',
                               'PGCONNECT_TIMEOUT': '2'}
        self.diagnostics = load_module('soak_diagnostics', SOURCE / 'scripts/lib/soak-failure-diagnostics.py')

    def command(self, argv, name, env=None, timeout=120):
        # Commands and their output contain only disposable fixture values.
        emit('command', command=[str(value) for value in argv], log=name)
        with (self.output / name).open('w') as log:
            subprocess.run([str(value) for value in argv], env=env or self.environment,
                           cwd=SOURCE, stdout=log, stderr=subprocess.STDOUT,
                           check=True, timeout=timeout)

    def start(self):
        self.environment = postgres_environment(self.environment)
        self.pg_environment['PATH'] = self.environment.get('PATH', os.defpath)
        password_file = self.runtime / 'password'
        password_file.write_text('short-soak-db-password\n')
        password_file.chmod(0o600)
        self.command(['initdb', '-D', self.runtime / 'data', '-U', 'short_soak',
                      '--pwfile=' + str(password_file), '--auth-host=scram-sha-256',
                      '--auth-local=reject', '--no-locale', '--encoding=UTF8'], 'initdb.log')
        self.pg_attempted = True
        self.command(['pg_ctl', '-D', self.runtime / 'data', '-l', self.output / 'postgresql.log',
                      '-o', f"-h 127.0.0.1 -p {self.database_port} -k '' -c max_connections=50 -c shared_buffers=32MB",
                      '-w', 'start'], 'pgstart.log')
        self.command(['createdb', '--encoding=UTF8', 'short_soak'], 'createdb.log', self.pg_environment)
        self.command(['psql', '-X', '-v', 'ON_ERROR_STOP=1', '-c',
                      'CREATE SCHEMA short_soak AUTHORIZATION short_soak;'], 'schema.log', self.pg_environment)
        database = (f'postgres://short_soak:short-soak-db-password@127.0.0.1:{self.database_port}'
                    '/short_soak?options=-csearch_path%3Dshort_soak')
        base = {**self.environment, 'NORTHSTAR_DISABLE_DOTENV': 'true', 'XMPP_DOMAIN': 'localhost',
                'DATABASE_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT': 'true',
                'DATABASE_URL': database}
        binary = self.runtime / 'rust-xmpp-server'
        shutil.copy2(self.input_binary, binary)
        self.binary_sha256 = digest(binary)
        migration_environment = {**base, 'MIGRATOR_DATABASE_URL': database,
                                 'MIGRATOR_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT': 'true'}
        self.command([binary, 'migrate'], 'migrate.log', migration_environment)
        self.command(['openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-days', '1',
                      '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
                      '-addext', 'basicConstraints=critical,CA:FALSE', '-addext',
                      'keyUsage=critical,digitalSignature,keyEncipherment', '-addext',
                      'extendedKeyUsage=serverAuth', '-keyout', self.runtime / 'server.key',
                      '-out', self.runtime / 'server.crt'], 'certificate.log')
        (self.runtime / 'server.key').chmod(0o600)
        nonce = secrets.token_hex(16)
        environment = {**base, **{key: '127.0.0.1:0' for key in (
            'XMPP_BIND', 'XMPPS_BIND', 'S2S_BIND', 'S2S_TLS_BIND', 'HTTP_BIND',
            'WEB_ADMIN_BIND', 'METRICS_BIND', 'COMPONENT_BIND')}}
        environment.update(
            TEST_LISTENER_ACTIVATION='true', TEST_READINESS_FILE=str(self.runtime / 'ready.json'),
            TEST_READINESS_NONCE=nonce, PUBLIC_URL='http://127.0.0.1',
            FAST_TOKEN_ALLOW_EPHEMERAL_FOR_DEVELOPMENT='true',
            DUMMY_SCRAM_ALLOW_EPHEMERAL_FOR_DEVELOPMENT='true',
            ABUSE_STATE_ALLOW_EPHEMERAL='true', API_CONTROL_ALLOW_EPHEMERAL='true',
            TRUSTED_PROXY_IPS='127.0.0.1,::1', TLS_CERT_PATH=str(self.runtime / 'server.crt'),
            TLS_KEY_PATH=str(self.runtime / 'server.key'), UPLOAD_DIR=str(self.runtime / 'uploads'),
            OPEN_REGISTRATION='true', REQUIRE_ENCRYPTED_ARCHIVE='true', SCRAM_ITERATIONS='4096',
            REGISTRATION_RATE_PER_HOUR='100', COMPONENTS_ENABLED='false', DIALBACK_ENABLED='false',
            FEDERATION_ALLOW_PRIVATE_IPS='false', BOOTSTRAP_ADMIN_USERNAME='soak_admin',
            BOOTSTRAP_ADMIN_PASSWORD='Synthetic-short-soak-admin-123',
            LOG_DIR=str(self.runtime / 'logs'), LOG_FORMAT='json', RUST_LOG=fixture_log_filter(self.trace_frames))
        self.server_log = (self.output / 'server.log').open('w')
        self.server = subprocess.Popen([str(binary)], cwd=SOURCE, env=environment,
                                       stdout=self.server_log, stderr=subprocess.STDOUT)
        readiness = load_module('soak_readiness', SOURCE / 'scripts/wait-test-readiness.py')
        self.listeners = readiness.wait_for_record(str(self.runtime / 'ready.json'), nonce, self.server.pid, 30)
        check(all(address.startswith('127.0.0.1:') for address in self.listeners.values()),
              'fixture listeners must remain loopback-only')
        emit('server_ready', pid=self.server.pid, listeners=self.listeners, binary_sha256=self.binary_sha256)
        helpers = load_module('soak_protocol', SOURCE / 'scripts/integration-wsl.py')
        # The upstream helpers are imported unchanged. Configure only this
        # module instance; no parent environment or global fixture is altered.
        helpers.HTTP_HOST = '127.0.0.1'
        helpers.HTTP_PORT = int(self.listeners['http'].rsplit(':', 1)[1])
        helpers.WEB_ADMIN_PORT = int(self.listeners['web-admin'].rsplit(':', 1)[1])
        helpers.DOMAIN = 'localhost'
        status, health = helpers.api('GET', '/readyz')
        check(status == 200 and health.strip() == 'ready', f'bad startup readyz: {status} {health}')
        return helpers

    def capture(self, label):
        if self.server is None:
            return {'status': 'not_started'}
        return self.diagnostics.capture_failure(
            self.server.pid, self.listeners.get('metrics'), self.listeners.get('http'),
            self.database_port, self.output / f'{label}-diagnostics.jsonl', self.pg_environment)

    def stop(self):
        report = {'clean': True, 'independent': True, 'status': 'Clean',
                  'forced_kill': False, 'errors': []}
        if self.server is not None:
            try:
                if self.server.poll() is None:
                    emit('server_terminate', pid=self.server.pid)
                    self.server.terminate()
                    try:
                        self.server.wait(timeout=SHUTDOWN_SECONDS)
                    except subprocess.TimeoutExpired:
                        # The deadline is already a failure. Evidence cannot
                        # turn the late exit into a successful graceful stop.
                        report['forced_kill'] = True
                        try:
                            report['shutdown_diagnostics'] = self.capture('shutdown-timeout')
                        except Exception as error:
                            retain_cleanup_interruption(report, error)
                            report['shutdown_diagnostics'] = {'status': 'unavailable',
                                                              'error_type': type(error).__name__}
                        finally:
                            self.server.kill()
                            self.server.wait(timeout=5)
                report['server_exit_code'] = self.server.returncode
                if self.server.returncode != 0 or report['forced_kill']:
                    report['errors'].append('server did not exit cleanly inside the shutdown budget')
            except Exception as error:
                retain_cleanup_interruption(report, error)
                report['errors'].append(f'server cleanup failed: {type(error).__name__}')
        else:
            report['errors'].append('server was never started')
        if self.server_log is not None:
            self.server_log.close()
        report['shutdown_complete'] = shutdown_completed(self.output / 'server.log')
        if not report['shutdown_complete']:
            report['errors'].append('server did not confirm shutdown complete')
        if self.pg_attempted:
            try:
                self.command(['pg_ctl', '-D', self.runtime / 'data', '-m', 'fast', '-w', '-t', '10', 'stop'],
                             'pgstop.log', timeout=15)
            except Exception as error:
                retain_cleanup_interruption(report, error)
                report['errors'].append(f'PostgreSQL fast stop failed: {type(error).__name__}')
                try:
                    self.command(['pg_ctl', '-D', self.runtime / 'data', '-m', 'immediate', '-w', '-t', '5', 'stop'],
                                 'pgstop-immediate.log', timeout=10)
                except Exception as fallback:
                    retain_cleanup_interruption(report, fallback)
                    report['errors'].append(f'PostgreSQL immediate stop failed: {type(fallback).__name__}')
        report['listener_closed_checks'] = {name: listener_closed(address)
                                           for name, address in self.listeners.items()}
        report['listener_closed_checks']['postgres'] = listener_closed(f'127.0.0.1:{self.database_port}')
        if not all(report['listener_closed_checks'].values()):
            report['errors'].append('a fixture listener remains open')
        report['clean'] = not report['errors']
        report['status'] = 'Clean' if report['clean'] else 'Incomplete'
        return report


def shutdown_completed(path):
    try:
        with path.open() as log:
            for line in log:
                try:
                    event = json.loads(line)
                    if event.get('fields', {}).get('message') == 'shutdown complete':
                        return True
                except (ValueError, AttributeError):
                    continue
    except FileNotFoundError:
        pass
    return False


def listener_closed(address):
    host, port = address.rsplit(':', 1)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
        stream.settimeout(.3)
        return stream.connect_ex((host, int(port))) != 0


class MixedTraffic:
    """The existing protocol workload, detached from fixture/diagnostic policy."""

    def __init__(self, fixture, helpers, seconds, result):
        self.fixture, self.it, self.seconds, self.result = fixture, helpers, seconds, result
        self.counts = collections.Counter()
        self.samples, self.latencies, self.peers = [], [], []
        self.expected, self.observed = {}, collections.Counter()
        self.sm_enabled = result.get('stream_management', False)
        self.sm = {}
        self.run_id = secrets.token_hex(4)
        self.password = 'Synthetic-short-soak-password-123'
        self.soak_start = None

    def close(self):
        for peer in self.peers:
            try:
                peer.close()
            except (OperatorCancelled, InterruptedError):
                raise
            except Exception as error:
                if interruption_origin(error) is not None:
                    raise
                peer.abort()

    def proc_sample(self, label):
        check(self.fixture.server.poll() is None, f'server died: {self.fixture.server.returncode}')
        stat = pathlib.Path(f'/proc/{self.fixture.server.pid}/stat').read_text().rsplit(')', 1)[1].split()
        status = {k: v.strip() for k, v in (line.split(':', 1) for line in pathlib.Path(f'/proc/{self.fixture.server.pid}/status').read_text().splitlines() if ':' in line)}
        sample = {
            'elapsed_seconds': round(time.monotonic() - self.soak_start, 3),
            'label': label, 'pid': self.fixture.server.pid,
            'start_ticks': stat[19], 'state': stat[0],
            'rss_kib': int(status['VmRSS'].split()[0]),
            'fds': len(list(pathlib.Path(f'/proc/{self.fixture.server.pid}/fd').iterdir())),
            'threads': int(status['Threads']),
        }
        if self.samples:
            check(sample['start_ticks'] == self.samples[0]['start_ticks'], 'server process was replaced')
        self.samples.append(sample)
        with (self.fixture.output / 'resources.jsonl').open('a') as f:
            f.write(json.dumps(sample) + '\n')
        emit('resource', **sample)

    def observe(self, peer, frame, deadline=None):
        # Validate queued live messages even while waiting for IQ/presence.
        # MAM-forwarded messages have no top-level workload ID.
        try:
            root = ET.fromstring(frame)
        except ET.ParseError:
            return None
        if self.sm_enabled and peer in self.sm:
            state = self.sm[peer]
            if root.tag in {NS + 'message', NS + 'presence', NS + 'iq'}:
                state['handled'] = (state['handled'] + 1) % 2**32
                self.counts['sm_inbound_stanzas'] += 1
                self.acknowledge(peer, deadline)
            elif root.tag == SM + 'r':
                self.counts['sm_server_requests'] += 1
                self.acknowledge(peer, deadline)
            elif root.tag == SM + 'a':
                handled = root.get('h', '')
                domain_check(handled.isdecimal() and int(handled) < 2**32,
                             'sm_ack_range', 'observe.sm_ack', 'invalid server SM acknowledgement')
                self.counts['sm_server_ack_responses'] += 1
        mid = root.get('id')
        if root.tag == NS + 'message' and mid and mid.startswith('soak-'):
            key = (peer.username, mid)
            domain_check(key in self.expected, 'unexpected_live_delivery', 'observe.delivery', f'unexpected delivery {key}: {frame}')
            contract = self.expected[key]
            domain_check(root.get('type') == contract['type'], 'live_delivery_type', 'observe.delivery', f'wrong delivery type {key}: {frame}')
            domain_check(root.get('from', '').split('/')[0] == contract['from'], 'live_delivery_sender', 'observe.delivery', f'wrong delivery sender {key}: {frame}')
            domain_check(contract['payload'] in frame, 'live_delivery_payload', 'observe.delivery', f'wrong or missing payload {key}: {frame}')
            self.observed[key] += 1
            domain_check(self.observed[key] == 1, 'duplicate_live_delivery', 'observe.delivery', f'duplicate live delivery {key}')
            self.counts['live_deliveries'] += 1
        return root

    def acknowledge(self, peer, deadline=None):
        # Count all server stanzas, including MAM results and presence, never
        # stream-management nonzas. ACK exact per-stream state after observation.
        state = self.sm[peer]
        peer.send(f"<a xmlns='urn:xmpp:sm:3' h='{state['handled']}'/>", deadline=deadline)
        state['last_ack'] = state['handled']
        self.counts['sm_client_acks'] += 1

    def sm_barrier(self, peer):
        # The server handles this request after preceding client ACKs in FIFO
        # order. A response is protocol evidence, not application delivery ACK.
        deadline = time.monotonic() + 10
        peer.send("<r xmlns='urn:xmpp:sm:3'/>", deadline=deadline)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('SM acknowledgement barrier write exceeded deadline')
        self.receive(peer, lambda root, _: root is not None and root.tag == SM + 'a',
                     'SM acknowledgement barrier', timeout=remaining)
        check(self.sm[peer]['last_ack'] == self.sm[peer]['handled'], 'unacknowledged received stanzas')

    def receive(self, peer, predicate, label, timeout=10):
        deadline = time.monotonic() + timeout
        frames = []
        while time.monotonic() < deadline:
            try:
                frame = peer.receive(max(0.01, deadline - time.monotonic()))
            except (OperatorCancelled, InterruptedError):
                # Operator cancellation and ordinary EINTR have different
                # verdicts; neither may be rewritten as a receive timeout.
                raise
            except OSError as error:
                if error.errno == errno.EINTR:
                    raise
                raise TimeoutError(f'{label}; recipient={peer.username}; observed_frames={frames!r}; transport_error={error!r}') from error
            except Exception as error:
                raise TimeoutError(f'{label}; recipient={peer.username}; observed_frames={frames!r}; transport_error={error!r}') from error
            root = self.observe(peer, frame, deadline=deadline)
            if time.monotonic() >= deadline:
                raise TimeoutError(f'{label}: receive/observation deadline exceeded')
            frames.append(frame)
            if predicate(root, frame):
                return (root, frames)
        raise TimeoutError(f'{label}: {frames}')

    def iq(self, peer, query, identifier):
        peer.send(query)
        root, frames = self.receive(peer, lambda r, f: r is not None and r.tag == NS + 'iq' and (r.get('id') == identifier), identifier)
        check(root.get('type') == 'result', f'IQ {identifier} failed: {frames}')
        return (root, frames)

    def join(self, peer, nick):
        peer.send(f"<presence xmlns='jabber:client' to='{self.room}/{nick}'><x xmlns='http://jabber.org/protocol/muc'><history maxstanzas='0'/></x></presence>")
        root, frames = self.receive(peer, lambda r, f: r is not None and r.tag == NS + 'presence' and (r.get('from') == f'{self.room}/{nick}') and (r.find(".//{http://jabber.org/protocol/muc#user}status[@code='110']") is not None), 'MUC self presence')
        check(root.get('type') != 'error', f'MUC join failed: {frames}')
        self.counts['muc_joins'] += 1
        return root

    def login(self, username):
        status, body = self.it.api('POST', '/api/v1/login', {'username': username, 'password': self.password})
        check(status == 200 and body.get('token'), f'HTTP login failed {username}: {status} {body}')
        self.counts['http_auth_successes'] += 1
        return body['token']

    def new_peer(self, username, generation):
        p = self.it.XmppWebSocket(username, self.password, f'soak-{generation}',
                                 initial_presence=not self.sm_enabled)
        self.peers.append(p)
        self.counts['xmpp_auth_successes'] += 1
        if self.sm_enabled:
            p.send("<enable xmlns='urn:xmpp:sm:3' resume='false'/>")
            root, _ = self.receive(p, lambda root, _: root is not None and root.tag == SM + 'enabled', 'SM enable')
            # This comparison tests ACK ownership, never resumption. Legacy
            # SASL has no verified device identity under the strict policy.
            check(root.get('resume') in {None, 'false', '0'} and not root.get('id'),
                  'expected ordinary non-resumable SM enable')
            self.sm[p] = {'handled': 0, 'last_ack': 0}
            self.counts['sm_enabled_streams'] += 1
            p.send("<presence xmlns='jabber:client'/>")
        return p

    def message(self, sender, recipients, to, typ, mid, encrypted=True, store=True):
        marker = f'payload-{mid}'
        payload = self.it.omemo_payload_b64(marker) if encrypted else marker
        sender_from = self.room if typ == 'groupchat' else f'{sender.username}@localhost'
        for p in recipients:
            self.expected[p.username, mid] = {'type': typ, 'from': sender_from, 'payload': payload}
        envelope = self.it.omemo2_envelope(12345, [(f'{self.auser}@localhost', [12345]), (f'{self.buser}@localhost', [23456])], marker, store=store) if encrypted else f'<body>{marker}</body>'
        if not store:
            envelope += "<no-store xmlns='urn:xmpp:hints'/>"
        stanza = f"<message xmlns='jabber:client' to='{to}' type='{typ}' id='{mid}'>{envelope}</message>"
        t = time.monotonic()
        emit('message_send_begin', message_id=mid, sender=sender.username, recipients=[p.username for p in recipients])
        sender.send_with_pow(stanza, self.tokens[sender.username])
        emit('message_wire_sent', message_id=mid, pow_and_send_ms=round((time.monotonic() - t) * 1000, 3))
        self.counts['sent_stanzas'] += 1
        self.counts['encrypted_messages' if encrypted else 'plaintext_no_store_messages'] += 1
        for p in recipients:
            self.receive(p, lambda r, f: r is not None and r.tag == NS + 'message' and (r.get('id') == mid), mid)
        self.latencies.append((time.monotonic() - t) * 1000)
        return mid

    def history(self, peer, to, identifier, required_ids, total):
        toattr = f" to='{to}'" if to else ''
        form = '' if to else f"<x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>urn:xmpp:mam:2</value></field><field var='with'><value>{self.buser}@localhost</value></field></x>"
        root, frames = self.iq(peer, f"<iq xmlns='jabber:client' type='set' id='{identifier}'{toattr}><query xmlns='urn:xmpp:mam:2' queryid='{identifier}'>{form}<set xmlns='http://jabber.org/protocol/rsm'><max>10</max><before/></set></query></iq>", identifier)
        fin = root.find(MAM + 'fin')
        check(fin is not None, f'missing MAM fin {identifier}: {frames}')
        count = fin.find(RSM + 'set/' + RSM + 'count')
        check(count is not None and int(count.text) == total, f'wrong MAM count, expected {total}: {frames}')
        mids = set()
        result_ids = set()
        for frame in frames:
            element = ET.fromstring(frame)
            res = element.find(MAM + 'result')
            if res is None:
                continue
            check(res.get('queryid') == identifier, f'uncorrelated MAM result: {frame}')
            rid = res.get('id')
            check(rid and rid not in result_ids, f'duplicate MAM result id {rid}')
            result_ids.add(rid)
            msg = res.find(FORWARD + 'forwarded/' + NS + 'message')
            check(msg is not None, f'missing forwarded MAM message: {frame}')
            mid = msg.get('id')
            check(mid and mid not in mids, f'duplicate/absent MAM message id: {frame}')
            mids.add(mid)
            check(msg.find(OMEMO + 'encrypted') is not None, f'non-encrypted archive payload: {frame}')
            check(msg.find(NS + 'body') is None, f'plaintext body in encrypted archive: {frame}')
            ids = {node.get('id') for node in msg.findall(SID + 'stanza-id')}
            check(rid in ids, f'MAM result id not a stable stanza id: {frame}')
            check('nostore' not in mid, f'no-store message leaked to archive: {frame}')
        check(set(required_ids).issubset(mids), f'latest expected archive IDs missing: {required_ids}, got {mids}')
        self.counts['muc_history_queries' if to else 'direct_history_queries'] += 1
        self.counts['history_items_checked'] += len(mids)

    def run(self):
        self.auser, self.buser = (f'soak_a_{self.run_id}', f'soak_b_{self.run_id}')
        for user in [self.auser, self.buser]:
            status, body = self.it.register_account(user, self.password)
            check(status == 201, f'registration failed {status} {body}')
            self.counts['registrations'] += 1
        self.tokens = {user: self.login(user) for user in [self.auser, self.buser]}
        a, b = (self.new_peer(self.auser, 0), self.new_peer(self.buser, 0))
        self.room = f'soak_room_{self.run_id}@conference.localhost'
        selfpresence = self.join(a, 'Alice')
        check(selfpresence.find(".//{http://jabber.org/protocol/muc#user}status[@code='201']") is not None, 'new room creation flag missing')
        self.iq(a, f"<iq xmlns='jabber:client' type='set' id='configure-room' to='{self.room}'><query xmlns='http://jabber.org/protocol/muc#owner'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#roomconfig</value></field><field var='muc#roomconfig_persistentroom'><value>1</value></field><field var='muc#roomconfig_maxusers'><value>20</value></field></x></query></iq>", 'configure-room')
        self.join(b, 'Bob')
        self.soak_start = time.monotonic()
        self.result['soak_started_at'] = stamp()
        self.proc_sample('start')
        rounds = 0
        last_mids = []
        last_group = None
        while time.monotonic() - self.soak_start < self.seconds:
            rounds += 1
            check(self.fixture.server.poll() is None, 'server exited during soak')
            last_mids = [self.message(a, [b], f'{self.buser}@localhost', 'chat', f'soak-{self.run_id}-{rounds:05d}-ab'), self.message(b, [a], f'{self.auser}@localhost', 'chat', f'soak-{self.run_id}-{rounds:05d}-ba')]
            last_group = self.message(a, [a, b], self.room, 'groupchat', f'soak-{self.run_id}-{rounds:05d}-group')
            self.counts['rounds'] = rounds
            if rounds % 10 == 0:
                self.message(a, [b], f'{self.buser}@localhost', 'chat', f'soak-{self.run_id}-{rounds:05d}-nostore', encrypted=False, store=False)
                self.history(a, None, f'direct-mam-{rounds}', last_mids, rounds * 2)
                self.history(a, self.room, f'room-mam-{rounds}', [last_group], rounds)
                status, body = self.it.api('GET', '/readyz')
                check(status == 200 and body.strip() == 'ready', f'readyz failed: {status} {body}')
                self.counts['readyz_successes'] += 1
                self.proc_sample(f'round-{rounds}')
            if rounds % 15 == 0:
                b.send(f"<presence xmlns='jabber:client' to='{self.room}/Bob' type='unavailable'/>")
                self.receive(b, lambda r, f: r is not None and r.tag == NS + 'presence' and (r.get('from') == f'{self.room}/Bob') and (r.get('type') == 'unavailable'), 'leave self')
                self.counts['muc_leaves'] += 1
                if self.sm_enabled:
                    self.sm_barrier(b)
                b.close()
                self.tokens[self.buser] = self.login(self.buser)
                b = self.new_peer(self.buser, rounds)
                self.join(b, 'Bob')
                self.counts['reconnects'] += 1
            due = self.soak_start + rounds * 2.0
            time.sleep(max(0, min(due, self.soak_start + self.seconds) - time.monotonic()))
        elapsed = time.monotonic() - self.soak_start
        check(elapsed >= self.seconds, 'duration was shortened')
        check(rounds >= minimum_rounds(self.seconds), f'workload throughput below smoke threshold: {rounds} rounds')
        self.history(a, None, 'direct-mam-final', last_mids, rounds * 2)
        self.history(a, self.room, 'room-mam-final', [last_group], rounds)
        # Correlated per-stream pings drain queued deliveries through observe.
        for p in [a, b]:
            ident = 'terminal-ping-' + p.username
            self.iq(p, f"<iq xmlns='jabber:client' type='get' id='{ident}' to='localhost'><ping xmlns='urn:xmpp:ping'/></iq>", ident)
        if self.sm_enabled:
            for peer in [a, b]:
                self.sm_barrier(peer)
            check(self.counts['sm_enabled_streams'] == self.counts['xmpp_auth_successes'],
                  'every stream must negotiate SM')
            check(self.counts['sm_inbound_stanzas'] > self.counts['live_deliveries'],
                  'SM accounting must include IQ, MAM and presence stanzas')
        domain_check(set(self.expected) == set(self.observed), 'live_delivery_set', 'terminal.delivery', 'missing expected live deliveries')
        domain_check(all((value == 1 for value in self.observed.values())), 'live_delivery_cardinality', 'terminal.delivery', 'non-exact live delivery counts')
        domain_check(self.counts['live_deliveries'] == rounds * 4 + rounds // 10,
                     'live_delivery_aggregate', 'terminal.delivery', 'wrong aggregate live delivery count')
        self.proc_sample('terminal')
        ordered_latencies = sorted(self.latencies)
        self.result.update(
            actual_soak_seconds=round(elapsed, 3), soak_finished_at=stamp(),
            counters=dict(self.counts), server_restarts=0,
            latency_ms={
                'count': len(self.latencies),
                'p50': round(ordered_latencies[len(self.latencies) // 2], 3),
                'p95': round(ordered_latencies[int(len(self.latencies) * .95)], 3),
                'max': round(max(self.latencies), 3),
            },
            resources={
                'samples': len(self.samples),
                'rss_start_kib': self.samples[0]['rss_kib'],
                'rss_end_kib': self.samples[-1]['rss_kib'],
                'rss_peak_kib': max(sample['rss_kib'] for sample in self.samples),
                'fds_start': self.samples[0]['fds'],
                'fds_end': self.samples[-1]['fds'],
                'fds_peak': max(sample['fds'] for sample in self.samples),
            },
            expected_deliveries=len(self.expected),
            observed_deliveries=sum(self.observed.values()),
            unique_observed_deliveries=len(self.observed),
        )
        self.result['evidence'].update(workload_terminal=True, complete=True)


def record_workload_failure(result, workload, error, phase='workload'):
    # Record before touching clients, sending a signal or starting diagnostics.
    initialize_result(result)
    result['workload_status'] = 'failed'
    result.setdefault('error', f'{type(error).__name__}: {error}')
    result.setdefault('failed_at', stamp())
    previous_execution = result['execution']
    if isinstance(error, OperatorCancelled):
        result['execution'] = {'status': 'Cancelled', 'phase': phase, 'cause': 'OperatorSignal', 'signal': error.signum}
    elif isinstance(error, InterruptedError) or (isinstance(error, OSError) and error.errno == errno.EINTR):
        result['execution'] = {'status': 'EnvironmentInterrupted', 'phase': phase, 'cause': 'EINTR'}
    elif phase == 'setup':
        result['execution'] = {'status': 'EnvironmentInterrupted', 'phase': phase, 'cause': 'SetupFailure'}
    elif isinstance(error, DomainInvariantViolation):
        result['execution'] = {'status': 'Failed', 'phase': phase, 'cause': 'ObservedInvariant'}
        result['domain']['status'] = 'InvariantViolation'
        if result['domain']['first_invariant'] is None:
            result['domain']['first_invariant'] = {'code': error.code, 'class': 'ObservedContract', 'location': error.location}
    else:
        result['execution'] = {'status': 'Failed', 'phase': phase, 'cause': 'UnclassifiedWorkloadFailure'}
    if previous_execution['status'] not in ('Running', 'Completed'):
        # Secondary bootstrap/cleanup failures must not rewrite the originating
        # interruption/cancellation. A known invariant still wins the verdict.
        result['execution'] = previous_execution
    evidence_gap(result, 'workload_not_completed' if phase == 'workload' else 'setup_not_completed')
    if workload is not None:
        result['counters'] = dict(workload.counts)
        result['missing_deliveries'] = [
            {'recipient': key[0], 'message_id': key[1]}
            for key in workload.expected if not workload.observed[key]]
        result['actual_soak_seconds'] = (round(time.monotonic() - workload.soak_start, 3)
                                         if workload.soak_start is not None else 0)


def run_owned_fixture(fixture, seconds, result, workload_factory=MixedTraffic):
    initialize_result(result)
    workload = None
    phase = 'setup'
    try:
        helpers = fixture.start()
        result['binary_sha256'] = fixture.binary_sha256
        workload = workload_factory(fixture, helpers, seconds, result)
        phase = 'workload'
        result['execution']['phase'] = phase
        result['domain']['status'] = 'Unresolved'
        workload.run()
        result['workload_status'] = 'passed'
        result['execution'] = {'status': 'Completed', 'phase': phase, 'cause': None}
        if result['evidence']['workload_terminal'] is True and result['evidence']['complete'] is True:
            result['domain']['status'] = 'Verified'
        else:
            evidence_gap(result, 'missing_workload_terminal')
    except BaseException as error:
        record_workload_failure(result, workload, error, phase)
        emit('workload_failed', **result)
        traceback.print_exc()
        # Observation is best effort and never replaces the original error.
        try:
            result['failure_diagnostics'] = fixture.capture('workload-failure')
            if result['failure_diagnostics'].get('status') in ('unavailable', 'deadline', 'partial', 'not_started'):
                evidence_gap(result, 'failure_observation_incomplete')
        except BaseException as diagnostic_error:
            result['failure_diagnostics'] = {'status': 'unavailable',
                                             'error_type': type(diagnostic_error).__name__}
            evidence_gap(result, 'failure_observation_unavailable')
    finally:
        # One cleanup owner. Repeated operator signals cannot interrupt it
        # halfway and leave the owned database/server behind.
        old_handlers = {kind: signal.signal(kind, signal.SIG_IGN)
                        for kind in (signal.SIGINT, signal.SIGTERM)}
        try:
            peer_error = None
            peer_interruption = None
            if workload is not None:
                try:
                    workload.close()
                except BaseException as error:
                    peer_error = f'peer cleanup failed: {type(error).__name__}'
                    peer_interruption = interruption_origin(error)
            try:
                cleanup = fixture.stop()
            except BaseException as error:
                cleanup = {'clean': False, 'independent': True, 'status': 'Incomplete',
                           'errors': [f'fixture cleanup failed: {type(error).__name__}']}
                retain_cleanup_interruption(cleanup, error)
            if peer_error:
                cleanup['clean'] = False
                cleanup['status'] = 'Incomplete'
                cleanup.setdefault('errors', []).append(peer_error)
            if peer_interruption is not None:
                cleanup.setdefault('interruption', peer_interruption)
            finalize_result(result, cleanup)
        finally:
            for kind, handler in old_handlers.items():
                signal.signal(kind, handler)
    return result


def postgres_environment(environment):
    """Use distribution PostgreSQL tools without a platform-specific path."""
    environment = dict(environment)
    path = environment.get('PATH', os.defpath)
    if shutil.which('initdb', path=path) is None:
        config = shutil.which('pg_config', path=path)
        if config is not None:
            bindir = subprocess.check_output([config, '--bindir'], env=environment,
                                            text=True, timeout=5).strip()
            if pathlib.Path(bindir, 'initdb').is_file():
                environment['PATH'] = bindir + os.pathsep + path
    for name in ('initdb', 'pg_ctl', 'createdb', 'psql', 'openssl'):
        check(shutil.which(name, path=environment.get('PATH', path)) is not None,
              f'required fixture tool is missing: {name}')
    return environment


def parse_arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=pathlib.Path, required=True,
                        help='already-built rust-xmpp-server; copied into the owned fixture')
    parser.add_argument('--output-dir', type=pathlib.Path,
                        help='new private evidence directory, outside the checkout; default: unique temporary directory')
    parser.add_argument('--duration-seconds', type=float, default=600,
                        help='bounded smoke duration, 1..3600 seconds; default: 600')
    parser.add_argument('--stream-management', action='store_true',
                        help='enable SM on every stream and acknowledge every received stanza')
    parser.add_argument('--trace-frames', action='store_true',
                        help='opt in to sanitized per-frame stage/outcome events')
    parser.add_argument('--database-port', type=int,
                        help='unused loopback TCP PostgreSQL port; default: kernel-selected candidate')
    args = parser.parse_args(argv)
    if not math.isfinite(args.duration_seconds) or not 1 <= args.duration_seconds <= 3600:
        parser.error('--duration-seconds must be finite and in 1..3600')
    if args.database_port is not None and not 1 <= args.database_port <= 65535:
        parser.error('--database-port must be in 1..65535')
    try:
        args.binary = args.binary.resolve(strict=True)
    except OSError:
        parser.error('--binary must exist')
    if not args.binary.is_file() or not os.access(args.binary, os.X_OK):
        parser.error('--binary must be an executable file')
    if args.output_dir is not None:
        args.output_dir = args.output_dir.resolve()
        if args.output_dir == SOURCE or SOURCE in args.output_dir.parents:
            parser.error('--output-dir must be outside the source checkout')
        if args.output_dir.exists():
            parser.error('--output-dir must not exist; previous evidence is never overwritten')
    return args


def main(argv=None):
    args = parse_arguments(argv)
    # Must precede output creation, source_identity's Git invocation, port
    # selection, PostgreSQL tool discovery, signals and all fixture startup.
    # Accounts are freshly created in the owned database. This is an offered
    # workload upper bound, not supplied/observed admission outcomes.
    try:
        offered_workload = mixed_workload(args.duration_seconds)
        preflight = preflight_normal(offered_workload)
    except InvalidScenario as error:
        emit('preflight_rejected', experiment_schema=RESULT_SCHEMA, verdict='InvalidScenario',
             qualified=False, status='failed', reason=str(error),
             execution={'status': 'NotStarted', 'phase': 'preflight', 'cause': 'InvalidScenario'},
             domain={'status': 'NotStarted', 'first_invariant': None},
             cleanup={'status': 'NotRequired', 'clean': True, 'owned': [], 'remaining': [], 'independent': True})
        return 2
    started = time.monotonic()
    output, fixture, previous = None, None, {}
    output_owned = False
    result = {
        'harness': 'scripts/mixed-traffic-soak.py', 'requested_seconds': args.duration_seconds,
        'minimum_rounds': minimum_rounds(args.duration_seconds), 'started_at': stamp(),
        'trace_frames': args.trace_frames, 'stream_management': args.stream_management,
        'preflight': preflight,
        'limitations': [
            'Single node, two live users; bounded smoke, not production load or endurance',
            'WebSocket SASL PLAIN on trusted loopback; no direct TCP TLS coverage',
            'Synthetic opaque OMEMO envelopes; no real-client encryption/decryption interoperability',
            'Isolated development-only database-role and ephemeral-secret exceptions'],
    }
    initialize_result(result)
    try:
        for kind in (signal.SIGINT, signal.SIGTERM):
            previous[kind] = signal.signal(kind, operator_interrupted)
        output = args.output_dir
        if output is None:
            output = pathlib.Path(tempfile.mkdtemp(prefix='northstar-mixed-soak-'))
        else:
            output.mkdir(mode=0o700, parents=False)
        output_owned = True
        output.chmod(0o700)
        result['output_directory'] = str(output)
        (output / 'preflight.json').write_text(json.dumps({
            'input': offered_workload, 'result': preflight,
            'scope': 'Synthetic admission keys represent the offered upper bound, not production MACs or actual outcomes',
        }, indent=2) + '\n')
        result.update(source=source_identity(), source_helper_sha256=digest(SOURCE / 'scripts/integration-wsl.py'),
                      harness_sha256=digest(__file__))
        database_port = args.database_port or candidate_database_port()
        result['database_port'] = database_port
        fixture = OwnedFixture(args.binary, output, database_port, args.trace_frames)
        run_owned_fixture(fixture, args.duration_seconds, result)
    except BaseException as error:
        # Bootstrap (including tool discovery/source/port/constructor failures)
        # is environmental. A setup assertion is never product proof.
        record_workload_failure(result, None, error, phase='setup')
        if 'cleanup' not in result:
            if fixture is None:
                cleanup = {'clean': True, 'independent': True, 'status': 'NotRequired', 'errors': []}
            else:
                try:
                    cleanup = fixture.stop()
                except BaseException as cleanup_error:
                    cleanup = {'clean': False, 'independent': True, 'status': 'Incomplete',
                               'errors': [f'fixture cleanup failed: {type(cleanup_error).__name__}']}
                    retain_cleanup_interruption(cleanup, cleanup_error)
            finalize_result(result, cleanup)
    finally:
        for kind, handler in previous.items():
            try:
                signal.signal(kind, handler)
            except BaseException as error:
                evidence_gap(result, 'signal_handler_restore_failed')
                if result['execution']['status'] in ('Running', 'Completed'):
                    result['execution'] = {'status': 'EnvironmentInterrupted', 'phase': 'cleanup',
                                           'cause': type(error).__name__}
    if 'source' in result:
        try:
            result['source_unchanged_during_run'] = result['source'] == source_identity()
        except BaseException as error:
            result['source_unchanged_during_run'] = False
            result['source_verification_error'] = type(error).__name__
            if isinstance(error, (OperatorCancelled, InterruptedError)) and result['execution']['status'] == 'Completed':
                result['execution'] = {'status': 'Cancelled' if isinstance(error, OperatorCancelled) else 'EnvironmentInterrupted',
                                       'phase': 'provenance', 'cause': type(error).__name__}
        if not result['source_unchanged_during_run']:
            evidence_gap(result, 'source_identity_changed_or_unavailable')
            result['source_error'] = 'source changed or unavailable during qualification; binary provenance is ambiguous'
    result['finished_at'] = stamp()
    result['total_seconds'] = round(time.monotonic() - started, 3)
    finalize_result(result, result['cleanup'])
    if output_owned:
        try:
            with (output / 'result.json').open('x') as artifact:
                artifact.write(json.dumps(result, indent=2) + '\n')
        except OSError as error:
            evidence_gap(result, 'terminal_artifact_write_failed')
            result['result_write_error'] = type(error).__name__
            origin = interruption_origin(error)
            if origin is not None and result['execution']['status'] == 'Completed':
                result['execution'] = {**origin, 'phase': 'evidence'}
            finalize_result(result, result['cleanup'])
    emit('terminal_result', **result)
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
