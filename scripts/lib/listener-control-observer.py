#!/usr/bin/env python3
"""One-process/one-libpq-connection observer for listener stress diagnostics.
No application query text, role name, password, or raw database identity is collected.
An exit status of zero describes observer integrity only, never fixture success.
"""
import argparse
import collections
import ctypes
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import resource
import select
import signal
import stat
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from github_ci_supervisor import _rename_noreplace

INTERVAL = 0.5
PRE_SECONDS = 30.0
POST_SECONDS = 15.0
SLOW_MS = 1500
MAX_ROWS = 128
MAX_SAMPLE_BYTES = 256 * 1024
RING_BYTES = 2 * 1024 * 1024
TOTAL_BYTES = 8 * 1024 * 1024
LOG_BYTES = TOTAL_BYTES - 64 * 1024
AS_BYTES = 256 * 1024 * 1024
STOP_SIGNAL = None
ROW_KEYS = {'pid', 'backend_start', 'database_hash', 'state', 'wait_event_type',
            'wait_event', 'query_age_ms', 'state_age_ms', 'blocking_pids'}
STATES = {'active', 'idle', 'idle in transaction', 'idle in transaction (aborted)',
          'fastpath function call'}


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def encoded(value):
    return (json.dumps(value, separators=(',', ':'), ensure_ascii=True, allow_nan=False) + '\n').encode()


class ObserverError(Exception):
    def __init__(self, code, sqlstate=None):
        self.code = code
        self.sqlstate = sqlstate if sqlstate and re.fullmatch(r'[0-9A-Z]{5}', sqlstate) else None
        super().__init__(code)


class StopRequested(Exception):
    pass


FAILURE_CAUSES = {'command_exit', 'deadline', 'lifecycle', 'startup', 'parent_cancel'}


class PrivateFile:
    """Read only a bounded, same-user regular file in an anchored private directory."""
    def __init__(self, path, cap):
        self.path = Path(path)
        self.cap = cap
        self.directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(self.directory)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            self.close()
            raise ObserverError('private_directory_permissions')
        self.identity = (info.st_dev, info.st_ino)

    def read(self, optional=False):
        parent = os.stat(self.path.parent, follow_symlinks=False)
        if not stat.S_ISDIR(parent.st_mode) or (parent.st_dev, parent.st_ino) != self.identity:
            raise ObserverError('private_directory_replaced')
        if parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700:
            raise ObserverError('private_directory_permissions')
        try:
            fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=self.directory)
        except FileNotFoundError:
            if optional:
                return None
            raise ObserverError('private_file_missing') from None
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) != 0o600:
                raise ObserverError('private_file_permissions')
            if not 0 < before.st_size <= self.cap:
                raise ObserverError('private_file_byte_limit')
            data = os.read(fd, self.cap + 1)
            after = os.fstat(fd)
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ObserverError('private_file_changed')
            if len(data) != before.st_size or len(data) > self.cap:
                raise ObserverError('private_file_byte_limit')
            return data
        finally:
            os.close(fd)

    def close(self):
        if self.directory is not None:
            os.close(self.directory)
            self.directory = None


def database_hash(salt, database_name):
    """A per-run case pseudonym, never an authorization or backend identity."""
    if not isinstance(salt, str) or not re.fullmatch(r'[0-9a-f]{32}', salt):
        raise ObserverError('invalid_hash_salt')
    return hashlib.md5((salt + ':' + database_name).encode('utf-8')).hexdigest()


def read_hash_salt(path):
    source = PrivateFile(path, 64)
    try:
        salt = source.read().decode('ascii').strip()
        database_hash(salt, '')
        return salt
    finally:
        source.close()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ObserverError('duplicate_marker_field')
        result[key] = value
    return result


class FirstFailure:
    def __init__(self, path):
        self.source = PrivateFile(path, 1024)
        self.marker = None

    def poll(self):
        if self.marker is not None:
            return self.marker
        data = self.source.read(optional=True)
        if data is None:
            return None
        try:
            marker = json.loads(data, object_pairs_hook=unique_object)
        except (ValueError, UnicodeError):
            raise ObserverError('invalid_failure_marker') from None
        if not isinstance(marker, dict) or set(marker) != {'schema_version', 'cause', 'monotonic_ns', 'realtime_ns'}:
            raise ObserverError('invalid_failure_marker')
        if type(marker['schema_version']) is not int or marker['schema_version'] != 1 or not isinstance(marker['cause'], str) or marker['cause'] not in FAILURE_CAUSES:
            raise ObserverError('invalid_failure_marker')
        if any(type(marker[key]) is not int or not 0 < marker[key] < 2**63 for key in ('monotonic_ns', 'realtime_ns')):
            raise ObserverError('invalid_failure_marker')
        # All publishers and this process share the host monotonic clock. A
        # future marker must never buy a longer capture window.
        if marker['monotonic_ns'] > time.monotonic_ns():
            raise ObserverError('future_failure_marker')
        self.marker = marker
        return marker

    def close(self):
        self.source.close()

def parent_identity(pid):
    try:
        raw = Path(f'/proc/{pid}/stat').read_text()
        fields = raw.rsplit(')', 1)[1].split()
        if fields[0] in {'Z', 'X', 'x'}:
            return None
        return fields[19]
    except (OSError, IndexError):
        return None


class Limits:
    def __init__(self, seconds, parent_pid):
        self.started = time.monotonic()
        self.deadline = self.started + seconds
        self.parent_pid = parent_pid
        self.parent_start = parent_identity(parent_pid)
        if self.parent_start is None:
            raise ObserverError('parent_unavailable')

    def check(self):
        if STOP_SIGNAL is not None:
            raise StopRequested()
        if time.monotonic() >= self.deadline:
            raise ObserverError('overall_deadline')
        if parent_identity(self.parent_pid) != self.parent_start:
            raise ObserverError('parent_identity_lost')

    def wait(self, seconds):
        end = time.monotonic() + max(0, seconds)
        while time.monotonic() < end:
            self.check()
            time.sleep(min(0.1, max(0, end - time.monotonic())))


class Libpq:
    """Nonblocking libpq; exactly one connection, with no reconnect fallback."""
    def __init__(self, limits):
        self.limits = limits
        self.conn = None
        self.lib = ctypes.CDLL('libpq.so.5')
        p = ctypes.c_void_p
        s = ctypes.c_char_p
        i = ctypes.c_int
        self.bind('PQconnectStartParams', p, ctypes.POINTER(s), ctypes.POINTER(s), i)
        self.bind('PQconnectPoll', i, p)
        self.bind('PQsocket', i, p)
        self.bind('PQsetnonblocking', i, p, i)
        self.bind('PQsendQuery', i, p, s)
        self.bind('PQflush', i, p)
        self.bind('PQconsumeInput', i, p)
        self.bind('PQisBusy', i, p)
        self.bind('PQgetResult', p, p)
        self.bind('PQresultStatus', i, p)
        self.bind('PQresultErrorField', s, p, i)
        self.bind('PQntuples', i, p)
        self.bind('PQnfields', i, p)
        self.bind('PQgetisnull', i, p, i, i)
        self.bind('PQgetlength', i, p, i, i)
        self.bind('PQgetvalue', s, p, i, i)
        self.bind('PQclear', None, p)
        self.bind('PQfinish', None, p)
        self.bind('PQbackendPID', i, p)
        self.bind('PQlibVersion', i)

    def bind(self, name, result, *args):
        fn = getattr(self.lib, name)
        fn.restype = result
        fn.argtypes = list(args)

    def ready(self, writing, deadline):
        self.limits.check()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ObserverError('client_query_deadline')
        fd = self.lib.PQsocket(self.conn)
        if fd < 0:
            raise ObserverError('connection_socket_unavailable')
        select.select([] if writing else [fd], [fd] if writing else [], [], min(0.1, remaining))

    def connect(self):
        # Connection endpoint/credentials use libpq PG* environment variables.
        # The diagnostic connection never inherits application query options.
        if os.environ.get('PGSERVICE') or os.environ.get('PGSERVICEFILE'):
            raise ObserverError('service_fallback_not_allowed')
        host = os.environ.get('PGHOST', '')
        port = os.environ.get('PGPORT', '')
        if host != '127.0.0.1' or not re.fullmatch(r'[1-9][0-9]{0,4}', port) or not 1 <= int(port) <= 65535:
            raise ObserverError('explicit_loopback_endpoint_required')
        if not os.environ.get('PGDATABASE'):
            raise ObserverError('explicit_database_required')
        keys = (ctypes.c_char_p * 7)(b'application_name', b'connect_timeout', b'options',
                                     b'host', b'hostaddr', b'port', None)
        vals = (ctypes.c_char_p * 7)(b'northstar-control-observer', b'5',
            b'-c statement_timeout=2000 -c lock_timeout=500 -c default_transaction_read_only=on -c search_path=pg_catalog',
            host.encode('ascii'), host.encode('ascii'), port.encode('ascii'), None)
        self.conn = self.lib.PQconnectStartParams(keys, vals, 0)
        if not self.conn:
            raise ObserverError('connection_allocation_failed')
        deadline = time.monotonic() + 6.0
        while True:
            self.limits.check()
            status = self.lib.PQconnectPoll(self.conn)
            if status == 3:
                break
            if status == 0:
                raise ObserverError('connection_failed')
            if status not in {1, 2}:
                raise ObserverError('unexpected_connect_poll')
            self.ready(status == 2, deadline)
        if self.lib.PQsetnonblocking(self.conn, 1) != 0:
            raise ObserverError('nonblocking_setup_failed')

    def query(self, sql, validator=None):
        if self.lib.PQsendQuery(self.conn, sql.encode('ascii')) != 1:
            raise ObserverError('query_send_failed')
        deadline = time.monotonic() + 3.0
        # The sample is invalid after three seconds. Allow at most two more
        # seconds to drain the server's bounded statement-timeout response on
        # this same connection; never submit another query while it is busy.
        drain_deadline = deadline + 2.0
        while True:
            status = self.lib.PQflush(self.conn)
            if status == 0:
                break
            if status < 0:
                raise ObserverError('query_flush_failed')
            self.ready(True, deadline)
        payload = None
        failure = None
        expired = False
        results = 0
        while True:
            self.limits.check()
            expired = expired or time.monotonic() >= deadline
            # Consume available input before waiting. After a scheduling delay,
            # a complete response may already be in the socket. The deadline
            # permits no late sample, only bounded draining to ReadyForQuery.
            if self.lib.PQconsumeInput(self.conn) != 1:
                raise ObserverError('query_receive_failed')
            while self.lib.PQisBusy(self.conn):
                try:
                    self.ready(False, drain_deadline if expired else deadline)
                except ObserverError as exc:
                    if exc.code != 'client_query_deadline':
                        raise
                    if expired:
                        raise
                    expired = True
                if self.lib.PQconsumeInput(self.conn) != 1:
                    raise ObserverError('query_receive_failed')
                expired = expired or time.monotonic() >= deadline
            result = self.lib.PQgetResult(self.conn)
            if not result:
                break
            try:
                results += 1
                if results > 2:
                    raise ObserverError('unexpected_result_count')
                if self.lib.PQresultStatus(result) != 2:
                    state = self.lib.PQresultErrorField(result, ord('C'))
                    if failure is None:
                        failure = ObserverError('server_query_failed', state.decode('ascii') if state else None)
                elif payload is not None or self.lib.PQntuples(result) != 1 or self.lib.PQnfields(result) != 1:
                    failure = ObserverError('unexpected_result_shape')
                elif self.lib.PQgetisnull(result, 0, 0):
                    failure = ObserverError('null_result')
                elif self.lib.PQgetlength(result, 0, 0) > MAX_SAMPLE_BYTES:
                    failure = ObserverError('sample_byte_limit')
                else:
                    payload = self.lib.PQgetvalue(result, 0, 0)
            finally:
                self.lib.PQclear(result)
        if failure:
            raise failure
        if payload is None:
            raise ObserverError('missing_result')
        value = json.loads(payload)
        if validator is not None:
            validator(value)
        if expired or time.monotonic() >= deadline:
            # Discard this late sample. Only the fully drained connection can
            # be reused; a subsequent fresh valid sample must prove recovery.
            raise ObserverError('client_query_deadline_drained')
        return value

    def close(self):
        if self.conn:
            self.lib.PQfinish(self.conn)
            self.conn = None


def attestation_sql():
    # A boolean result only: no role, address, or database identity is emitted.
    # This is one standalone read on the same nonblocking connection.
    return """
SELECT pg_catalog.json_build_object('authorized',
    pg_catalog.host(pg_catalog.inet_server_addr()) = '127.0.0.1'
    AND current_user = 'xmpp_test'
    AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles
                WHERE rolname = current_user AND rolcreatedb))
"""

def activity_sql(salt):
    if not re.fullmatch(r'[0-9a-f]{32}', salt):
        raise ObserverError('invalid_hash_salt')
    # Two-phase CTE bounds both the JSON and expensive blocking-pid lookups.
    # Database identity is salted in the server; raw datname never leaves it. The shared run salt maps this pseudonym to
    # the driver-owned case map; only (pid, backend_start) identifies a backend.
    return f"""
WITH targets AS MATERIALIZED (
  SELECT pid,backend_start,datname,state,wait_event_type,wait_event,
         GREATEST(0,EXTRACT(EPOCH FROM (pg_catalog.clock_timestamp()-query_start))*1000)::double precision AS query_age_ms,
         GREATEST(0,EXTRACT(EPOCH FROM (pg_catalog.clock_timestamp()-state_change))*1000)::double precision AS state_age_ms,
         pg_catalog.count(*) OVER() AS total
    FROM pg_catalog.pg_stat_activity
   WHERE application_name='northstar-runtime-control'
   ORDER BY pid,backend_start LIMIT {MAX_ROWS}
)
SELECT pg_catalog.json_build_object(
 'at',pg_catalog.clock_timestamp(), 'total',COALESCE(pg_catalog.max(total),0),
 'rows',COALESCE(pg_catalog.json_agg(pg_catalog.json_build_object(
   'pid',pid, 'backend_start',backend_start,
   'database_hash',pg_catalog.md5('{salt}' || ':' || datname),
   'state',state, 'wait_event_type',wait_event_type, 'wait_event',wait_event,
   'query_age_ms',query_age_ms, 'state_age_ms',state_age_ms,
   'blocking_pids',CASE WHEN wait_event_type='Lock' OR (state='active' AND query_age_ms>={SLOW_MS})
                       THEN pg_catalog.pg_blocking_pids(pid) ELSE ARRAY[]::integer[] END
 ) ORDER BY pid,backend_start),'[]'::json)) FROM targets
"""


def validate_sample(sample):
    if not isinstance(sample, dict) or set(sample) != {'at', 'total', 'rows'}:
        raise ObserverError('unexpected_sample_fields')
    if not isinstance(sample['at'], str) or len(sample['at']) > 80:
        raise ObserverError('invalid_sample_time')
    if type(sample['total']) is not int or sample['total'] < 0 or sample['total'] > MAX_ROWS:
        raise ObserverError('backend_row_limit')
    rows = sample['rows']
    if not isinstance(rows, list) or len(rows) != sample['total']:
        raise ObserverError('incomplete_backend_rows')
    identities = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != ROW_KEYS:
            raise ObserverError('unexpected_backend_fields')
        if type(row['pid']) is not int or not 0 < row['pid'] < 2**31:
            raise ObserverError('invalid_backend_pid')
        if not isinstance(row['backend_start'], str) or not 1 <= len(row['backend_start']) <= 80:
            raise ObserverError('invalid_backend_identity')
        if not isinstance(row['database_hash'], str) or not re.fullmatch(r'[0-9a-f]{32}', row['database_hash']):
            raise ObserverError('invalid_database_hash')
        # PostgreSQL publishes STATE_UNDEFINED as NULL during backend startup.
        # backend_start above is also privilege-gated: without visibility it
        # is NULL too, so missing privileges cannot pass as a starting backend.
        if row['state'] is not None and (not isinstance(row['state'], str) or row['state'] not in STATES):
            raise ObserverError('activity_visibility_incomplete')
        for name in ('wait_event_type', 'wait_event'):
            if row[name] is not None and (not isinstance(row[name], str) or len(row[name]) > 128):
                raise ObserverError('invalid_wait_event')
        for name in ('query_age_ms', 'state_age_ms'):
            if type(row[name]) not in (int, float) or not math.isfinite(row[name]) or row[name] < 0:
                raise ObserverError('invalid_activity_age')
        if row['state'] is None and (row['query_age_ms'] != 0 or row['state_age_ms'] != 0):
            raise ObserverError('invalid_starting_backend')
        if not isinstance(row['blocking_pids'], list) or len(row['blocking_pids']) > MAX_ROWS or any(type(pid) is not int or pid <= 0 for pid in row['blocking_pids']):
            raise ObserverError('blocking_pid_limit')
        key = (row['pid'], row['backend_start'])
        if key in identities:
            raise ObserverError('duplicate_backend_identity')
        identities.add(key)
    if len(encoded(sample)) > MAX_SAMPLE_BYTES:
        raise ObserverError('sample_byte_limit')
    return sample


class Evidence:
    def __init__(self, stream, log_limit=LOG_BYTES, ring_limit=RING_BYTES):
        self.stream = stream
        self.log_limit = log_limit
        self.ring_limit = ring_limit
        self.written = 0
        self.ring = collections.deque()
        self.ring_bytes = 0
        self.seq = 0
        self.last_emitted = 0
        self.captured_samples = 0
        self.last_time_evicted = None
        self.pre_window_truncated = False
        self.marker = None
        self.capture_from = None
        self.capture_until = None
        self.previous = set()
        self.previous_slow = set()
        self.peak = 0
        self.slow_events = 0
        self.disappearances = 0
        self.ring_byte_evictions = 0
        self.sample_count = 0
        self.starting_observations = 0

    def write(self, record):
        data = record if isinstance(record, bytes) else encoded(record)
        # Reserve 2 KiB for a terminal record even when the observation cap fails.
        if self.written + len(data) > self.log_limit - 2048:
            raise ObserverError('evidence_byte_limit')
        self.stream.write(data)
        self.stream.flush()
        self.written += len(data)

    def terminal(self, record):
        data = encoded(record)
        if len(data) > 2048 or self.written + len(data) > self.log_limit:
            raise ObserverError('summary_byte_limit')
        self.stream.write(data)
        self.stream.flush()
        self.written += len(data)

    def flush_captured_ring(self):
        if self.marker is None:
            return
        for now, seq, data in self.ring:
            if self.capture_from <= now <= self.capture_until and seq > self.last_emitted:
                self.write(data)
                self.last_emitted = seq
                self.captured_samples += 1

    def capture(self, marker, now):
        if self.marker is not None:
            return
        self.marker = dict(marker)
        failure_time = marker['monotonic_ns'] / 1_000_000_000
        self.capture_from = failure_time - PRE_SECONDS
        self.capture_until = failure_time + POST_SECONDS
        self.pre_window_truncated = self.last_time_evicted is not None and self.last_time_evicted >= self.capture_from
        self.write({'type': 'first_failure', **marker,
                    'observed_monotonic': round(now, 6),
                    'marker_delay_ms': round(max(0, now - failure_time) * 1000, 3),
                    'capture_from_monotonic': self.capture_from,
                    'capture_until_monotonic': self.capture_until})
        self.flush_captured_ring()

    def complete(self, now):
        return self.capture_until is not None and now >= self.capture_until

    def sample(self, sample, now, duration_ms):
        validate_sample(sample)
        self.starting_observations += sum(row['state'] is None for row in sample['rows'])
        self.seq += 1
        self.sample_count += 1
        self.peak = max(self.peak, sample['total'])
        data = encoded({'type': 'sample', 'seq': self.seq, 'monotonic': round(now, 6),
                        'sample_duration_ms': round(duration_ms, 3), **sample})
        self.ring.append((now, self.seq, data))
        self.ring_bytes += len(data)
        while self.ring and (now - self.ring[0][0] > PRE_SECONDS or self.ring_bytes > self.ring_limit):
            due_to_bytes = self.ring_bytes > self.ring_limit and now - self.ring[0][0] <= PRE_SECONDS
            removed = self.ring.popleft()
            self.ring_bytes -= len(removed[2])
            if not due_to_bytes:
                self.last_time_evicted = removed[0]
            self.ring_byte_evictions += int(due_to_bytes)
        current = {(row['pid'], row['backend_start']) for row in sample['rows']}
        slow = {(row['pid'], row['backend_start']) for row in sample['rows']
                if row['state'] == 'active' and row['query_age_ms'] >= SLOW_MS}
        # These events are not evidence of a fixture failure. In particular,
        # round teardown legitimately removes every backend in a cohort.
        self.slow_events += len(slow - self.previous_slow)
        self.disappearances += len(self.previous - current)
        self.flush_captured_ring()
        self.previous = current
        self.previous_slow = slow

def write_small(path, record, cap=16*1024):
    data = encoded(record)
    if len(data) > cap:
        raise ObserverError('summary_byte_limit')
    path = Path(path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    temporary = None
    try:
        fd, temporary = tempfile.mkstemp(prefix='.observer-record.', dir=path.parent)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
        # The wrapper polls readiness concurrently. It must never observe an
        # empty/partial JSON file or a transient second hardlink.
        _rename_noreplace(directory, Path(temporary).name, path.name)
        temporary = None
    finally:
        try:
            if temporary is not None:
                os.unlink(Path(temporary).name, dir_fd=directory)
        finally:
            os.close(directory)


def on_signal(signum, _frame):
    global STOP_SIGNAL
    STOP_SIGNAL = signum


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', required=True, help='New private directory; must not already exist')
    parser.add_argument('--failure-marker', required=True)
    parser.add_argument('--database-hash-salt-file', required=True)
    parser.add_argument('--max-seconds', type=int, default=9000)
    parser.add_argument('--parent-pid', type=int, default=os.getppid())
    args = parser.parse_args()
    if not 1 <= args.max_seconds <= 9000 or args.parent_pid <= 1:
        parser.error('max-seconds must be 1..9000 and parent-pid must exceed 1')
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_AS, (AS_BYTES, AS_BYTES))
    resource.setrlimit(resource.RLIMIT_FSIZE, (TOTAL_BYTES, TOTAL_BYTES))
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, on_signal)
    out = Path(args.output_dir)
    try:
        out.mkdir(mode=0o700, parents=False, exist_ok=False)
        stream = open(out / 'observations.jsonl', 'xb', buffering=0)
    except OSError:
        print('observer_error=output_directory_unavailable', file=sys.stderr)
        return 2
    evidence = Evidence(stream)
    connection = None
    failure = None
    errors = 0
    consecutive_errors = 0
    recovered_errors = 0
    final_code = None
    sqlstate = None
    last_sample_error = None
    last_sample_sqlstate = None
    stopped = False
    completed = False
    started = utc()
    max_duration_ms = 0
    gaps = 0
    observer_backend_pid = None

    def capture_marker():
        marker = failure.poll()
        if marker is not None:
            evidence.capture(marker, time.monotonic())

    try:
        limits = Limits(args.max_seconds, args.parent_pid)
        failure = FirstFailure(args.failure_marker)
        salt = read_hash_salt(args.database_hash_salt_file)
        evidence.write({'type': 'metadata', 'schema_version': 1, 'started_at': started,
            'application_name_filter': 'northstar-runtime-control', 'interval_ms': 500,
            'slow_query_ms': SLOW_MS, 'pre_seconds': PRE_SECONDS, 'post_seconds': POST_SECONDS,
            'max_rows': MAX_ROWS, 'ring_bytes_limit': RING_BYTES, 'evidence_bytes_limit': TOTAL_BYTES,
            'address_space_bytes_limit': AS_BYTES, 'max_seconds': args.max_seconds,
            'blocking_pids_sampled_only_for_lock_or_slow_active': True,
            'database_hash_scope': 'md5_run_salt_colon_database_name',
            'backend_identity': ['pid', 'backend_start'],
            'disappearance_is_business_failure': False, 'capture_trigger': 'trusted_first_failure_marker'})
        connection = Libpq(limits)
        connection.connect()
        attested = connection.query(attestation_sql())
        if not isinstance(attested, dict) or set(attested) != {'authorized'} or attested['authorized'] is not True:
            raise ObserverError('observer_database_attestation_failed')
        observer_backend_pid = connection.lib.PQbackendPID(connection.conn)
        sql = activity_sql(salt)
        next_sample = time.monotonic()
        while True:
            limits.check()
            capture_marker()
            if evidence.complete(time.monotonic()):
                completed = True
                break
            wait_until = next_sample
            if evidence.capture_until is not None:
                wait_until = min(wait_until, evidence.capture_until)
            limits.wait(wait_until - time.monotonic())
            capture_marker()
            if evidence.complete(time.monotonic()):
                completed = True
                break
            begin = time.monotonic()
            try:
                sample = connection.query(sql, validate_sample)
                end = time.monotonic()
                duration_ms = (end - begin) * 1000
                # Poll before appending/evicting the ring, including when a
                # marker was published while libpq waited for a response.
                capture_marker()
                evidence.sample(sample, end, duration_ms)
                recovered_errors += consecutive_errors
                consecutive_errors = 0
                if evidence.sample_count == 1:
                    write_small(out / 'observer-ready.json', {'observer_pid': os.getpid(),
                        'observer_backend_pid': observer_backend_pid, 'at': utc(),
                        'sample_count': 1, 'libpq_version': connection.lib.PQlibVersion()}, 4096)
            except ObserverError as exc:
                errors += 1
                consecutive_errors += 1
                last_sample_error, last_sample_sqlstate = exc.code, exc.sqlstate
                # A drained error or discarded, validated late sample leaves
                # the same connection reusable. Pending/invalid responses fail
                # immediately; three consecutive recoverable errors also fail.
                if exc.code not in {'server_query_failed', 'client_query_deadline_drained'} or consecutive_errors >= 3:
                    raise
            finally:
                duration_ms = (time.monotonic() - begin) * 1000
                max_duration_ms = max(max_duration_ms, duration_ms)
                if duration_ms > INTERVAL * 1000:
                    gaps += 1
            after = time.monotonic()
            next_sample = begin + INTERVAL if after <= begin + INTERVAL else after + INTERVAL
    except StopRequested:
        stopped = True
    except ObserverError as exc:
        final_code, sqlstate = exc.code, exc.sqlstate
    except (OSError, MemoryError, ValueError, TypeError, KeyError, AttributeError):
        final_code = 'observer_internal_or_resource_failure'
    finally:
        if connection:
            connection.close()
        # A signal during the last query can coincide with first failure. Only
        # a valid marker can flush any rows; ordinary shutdown is summary-only.
        if failure:
            try:
                capture_marker()
            except (ObserverError, OSError, MemoryError, ValueError):
                final_code = final_code or 'failure_marker_unavailable'
            finally:
                failure.close()
        if consecutive_errors:
            final_code = final_code or 'sample_error_not_recovered'
            sqlstate = sqlstate or last_sample_sqlstate
        if evidence.ring_byte_evictions:
            final_code = final_code or 'ring_window_byte_limit'
        if evidence.pre_window_truncated:
            final_code = final_code or 'pre_window_unavailable'
        if evidence.marker is not None and evidence.captured_samples == 0:
            final_code = final_code or 'failure_window_unavailable'
        post_complete = evidence.complete(time.monotonic())
        if evidence.marker is not None and not post_complete:
            final_code = final_code or 'post_window_incomplete'
        ok = (stopped or completed) and final_code is None and evidence.sample_count > 0
        result = {'schema_version': 1, 'observer_ok': ok, 'fixture_status': 'not_determined_by_observer',
            'started_at': started, 'ended_at': utc(), 'stop_signal': STOP_SIGNAL,
            'observer_backend_pid': observer_backend_pid, 'samples': evidence.sample_count,
            'peak_runtime_backends': evidence.peak, 'slow_backend_events': evidence.slow_events,
            'starting_backend_observations': evidence.starting_observations,
            'backend_disappearances_unclassified': evidence.disappearances,
            'sample_overruns': gaps, 'max_sample_duration_ms': round(max_duration_ms, 3),
            'ring_byte_evictions': evidence.ring_byte_evictions, 'sample_errors': errors,
            'recovered_sample_errors': recovered_errors, 'consecutive_sample_errors': consecutive_errors,
            'last_sample_error_code': last_sample_error, 'last_sample_sqlstate': last_sample_sqlstate,
            'error_code': final_code, 'sqlstate': sqlstate,
            'truncated': bool(evidence.ring_byte_evictions or evidence.pre_window_truncated or final_code in
                {'evidence_byte_limit', 'sample_byte_limit', 'backend_row_limit', 'blocking_pid_limit'}),
            'failure_marker_seen': evidence.marker is not None,
            'captured_samples': evidence.captured_samples, 'pre_window_truncated': evidence.pre_window_truncated,
            'post_window_complete': post_complete if evidence.marker is not None else None,
            'post_window_end_reason': ('complete' if post_complete else 'stop_or_error') if evidence.marker is not None else 'not_requested'}
        try:
            evidence.terminal({'type': 'terminal', **result})
            result['observations_bytes'] = evidence.written
            stream.close()
            write_small(out / 'observer-result.json', result)
            print(json.dumps({'observer_ok': ok, 'samples': evidence.sample_count,
                              'error_code': final_code}, separators=(',', ':')))
        except (OSError, MemoryError, ObserverError):
            print('observer_error=final_evidence_write_failed', file=sys.stderr)
            ok = False
    return 0 if ok else 2


if __name__ == '__main__':
    sys.exit(main())
