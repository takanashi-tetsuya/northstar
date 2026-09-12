#!/usr/bin/env python3
"""Bounded observer regressions: fake libpq, real files/processes, no database."""
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parent / 'lib/listener-control-observer.py'
spec = importlib.util.spec_from_file_location('listener_control_observer', SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def row(pid=101, start='2026-09-11T00:00:00+00:00', state='idle', age=0):
    return {'pid': pid, 'backend_start': start, 'database_hash': 'a' * 32, 'state': state,
            'wait_event_type': 'Client', 'wait_event': 'ClientRead', 'query_age_ms': age,
            'state_age_ms': 0, 'blocking_pids': []}


def sample(*rows):
    return {'at': '2026-09-11T00:00:00+00:00', 'total': len(rows), 'rows': list(rows)}


def marker(now=100, cause='command_exit'):
    return {'schema_version': 1, 'cause': cause, 'monotonic_ns': int(now * 1e9),
            'realtime_ns': 1789123456000000000}


def records(stream):
    return [json.loads(line) for line in stream.getvalue().splitlines()]


class EvidenceTests(unittest.TestCase):
    def make(self, **kwargs):
        stream = io.BytesIO()
        return m.Evidence(stream, **kwargs), stream

    def test_idle_age_never_becomes_slow_query(self):
        e, stream = self.make()
        e.sample(sample(row(age=999999)), 100, 1)
        self.assertEqual(e.slow_events, 0)
        self.assertEqual(stream.getvalue(), b'')

    def test_slow_and_disappearance_only_count_without_marker(self):
        e, stream = self.make()
        e.sample(sample(row()), 100, 1)
        e.sample(sample(row(state='active', age=1800)), 101, 1)
        e.sample(sample(row(state='active', age=2000)), 102, 1)
        e.sample(sample(), 103, 1)
        self.assertEqual(e.slow_events, 1)
        self.assertEqual(e.disappearances, 1)
        self.assertIsNone(e.capture_until)
        self.assertEqual(stream.getvalue(), b'')

    def test_first_marker_captures_one_bounded_window_without_duplicates(self):
        e, stream = self.make()
        for now in (70, 90, 100):
            e.sample(sample(row()), now, 1)
        e.capture(marker(100), 102)
        e.sample(sample(row(state='active', age=4000)), 110, 1)
        e.capture(marker(110, 'deadline'), 111)
        e.sample(sample(), 115, 1)
        e.sample(sample(row()), 116, 1)
        self.assertEqual(e.capture_until, 115)
        self.assertTrue(e.complete(115))
        self.assertEqual(e.marker['cause'], 'command_exit')
        self.assertEqual([r['seq'] for r in records(stream) if r['type'] == 'sample'], [1, 2, 3, 4, 5])
        self.assertEqual(sum(r['type'] == 'first_failure' for r in records(stream)), 1)
        self.assertEqual(e.captured_samples, 5)

    def test_delayed_marker_filters_both_edges_and_never_extends_post(self):
        e, stream = self.make()
        for now in (75, 90, 100, 105, 116):
            e.sample(sample(row()), now, 1)
        e.capture(marker(100), 120)
        self.assertEqual(e.capture_until, 115)
        self.assertTrue(e.complete(120))
        self.assertEqual([r['monotonic'] for r in records(stream) if r['type'] == 'sample'], [90, 100, 105])
        self.assertTrue(e.pre_window_truncated)

    def test_marker_during_query_is_captured_before_ring_eviction(self):
        e, stream = self.make()
        e.sample(sample(row()), 70, 1)
        e.sample(sample(row()), 99, 1)
        e.capture(marker(100), 102)
        e.sample(sample(row()), 102, 3000)
        self.assertFalse(e.pre_window_truncated)
        self.assertEqual([r['monotonic'] for r in records(stream) if r['type'] == 'sample'], [70, 99, 102])

    def test_pid_reuse_counts_disappearance_and_retains_new_identity(self):
        e, _ = self.make()
        e.sample(sample(row()), 100, 1)
        e.sample(sample(row(start='2026-09-11T00:01:00+00:00')), 101, 1)
        self.assertEqual(e.disappearances, 1)
        self.assertEqual(e.previous, {(101, '2026-09-11T00:01:00+00:00')})

    def test_ring_is_bounded_and_reports_shortened_window(self):
        e, _ = self.make(ring_limit=1200)
        for i in range(20):
            e.sample(sample(row()), 100 + i / 2, 1)
        self.assertLessEqual(e.ring_bytes, 1200)
        self.assertGreater(e.ring_byte_evictions, 0)

    def test_normal_time_eviction_is_not_byte_truncation(self):
        e, _ = self.make()
        e.sample(sample(row()), 100, 1)
        e.sample(sample(row()), 131, 1)
        e.capture(marker(132), 132)
        self.assertEqual(len(e.ring), 1)
        self.assertEqual(e.ring_byte_evictions, 0)
        self.assertFalse(e.pre_window_truncated)

    def test_file_cap_reserves_terminal_and_terminal_cannot_silently_vanish(self):
        e, stream = self.make(log_limit=4096)
        with self.assertRaises(m.ObserverError) as failure:
            e.write({'untrusted': 'x' * 3000})
        self.assertEqual(failure.exception.code, 'evidence_byte_limit')
        e.terminal({'type': 'terminal', 'truncated': True})
        self.assertLessEqual(len(stream.getvalue()), 4096)
        with self.assertRaises(m.ObserverError):
            e.terminal({'too_large': 'x' * 3000})

    def test_sensitive_extra_field_rejected_before_any_output(self):
        e, stream = self.make()
        value = row()
        value['query'] = 'SECRET_MUST_NOT_LEAK'
        with self.assertRaises(m.ObserverError):
            e.sample(sample(value), 100, 1)
        self.assertNotIn(b'SECRET', stream.getvalue())
        self.assertEqual(e.sample_count, 0)

    def test_row_cap_duplicates_and_invalid_numbers_rejected(self):
        bad = [sample(*(row(i + 1) for i in range(129))), sample(row(), row()),
               sample(row(state=None)), sample(row(age=float('nan'))), sample(row(age=True))]
        for value in bad:
            with self.subTest(total=value['total']):
                with self.assertRaises(m.ObserverError):
                    m.validate_sample(value)

    def test_activity_sql_and_driver_hash_share_exact_pseudonym(self):
        import hashlib
        salt, name = 'a' * 32, 'private_case_name'
        sql = m.activity_sql(salt)
        self.assertNotIn('usename', sql)
        self.assertNotIn('query,', sql)
        self.assertNotIn('datid', sql)
        self.assertIn("md5('" + salt + "' || ':' || datname)", sql)
        self.assertEqual(m.database_hash(salt, name), hashlib.md5((salt + ':' + name).encode()).hexdigest())
        self.assertNotEqual(m.database_hash(salt, name), m.database_hash('b' * 32, name))
        self.assertIn("application_name='northstar-runtime-control'", sql)
        self.assertIn('LIMIT 128', sql)
        self.assertIn("wait_event_type='Lock' OR (state='active'", sql)
        with self.assertRaises(m.ObserverError):
            m.activity_sql("bad' injected")

    def test_parent_identity_and_absolute_deadline(self):
        with mock.patch.object(m, 'parent_identity', return_value='100'), mock.patch.object(m.time, 'monotonic', return_value=10):
            limits = m.Limits(2, 1234)
        with mock.patch.object(m, 'parent_identity', return_value='101'), mock.patch.object(m.time, 'monotonic', return_value=11):
            with self.assertRaises(m.ObserverError) as result:
                limits.check()
            self.assertEqual(result.exception.code, 'parent_identity_lost')
        with mock.patch.object(m.time, 'monotonic', return_value=13):
            with self.assertRaises(m.ObserverError) as result:
                limits.check()
            self.assertEqual(result.exception.code, 'overall_deadline')


class PrivateInputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='northstar-observer-input.')
        self.parent = Path(self.temp.name)
        self.path = self.parent / 'first-failure.json'
        self.reader = m.FirstFailure(self.path)
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.reader.close)

    def publish(self, value=None):
        m.write_small(self.path, value or marker())

    def test_missing_then_valid_first_marker_is_immutable(self):
        self.assertIsNone(self.reader.poll())
        self.publish()
        with mock.patch.object(m.time, 'monotonic_ns', return_value=101_000_000_000):
            self.assertEqual(self.reader.poll(), marker())
        self.path.unlink()
        self.publish(marker(105, 'deadline'))
        self.assertEqual(self.reader.poll(), marker())

    def test_actual_supervisor_publisher_protocol_matches(self):
        supervisor_spec = importlib.util.spec_from_file_location('observer_test_supervisor', SOURCE.parent.parent / 'github_ci_supervisor.py')
        supervisor = importlib.util.module_from_spec(supervisor_spec)
        sys.modules[supervisor_spec.name] = supervisor
        self.addCleanup(lambda: sys.modules.pop(supervisor_spec.name, None))
        supervisor_spec.loader.exec_module(supervisor)
        self.assertTrue(supervisor.publish_failure_marker('lifecycle', str(self.path)))
        observed = self.reader.poll()
        self.assertEqual(set(observed), {'schema_version', 'cause', 'monotonic_ns', 'realtime_ns'})
        self.assertEqual(observed['cause'], 'lifecycle')
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_invalid_fields_duplicates_future_and_values_rejected(self):
        cases = [dict(marker(), query='SECRET'), dict(marker(), schema_version=True),
                 dict(marker(), monotonic_ns=True), dict(marker(), monotonic_ns=0),
                 dict(marker(), cause='driver_failure'), dict(marker(), realtime_ns=-1),
                 dict(marker(), monotonic_ns=102_000_000_000)]
        for value in cases:
            with self.subTest(value=value):
                self.publish(value)
                with mock.patch.object(m.time, 'monotonic_ns', return_value=101_000_000_000):
                    with self.assertRaises(m.ObserverError):
                        self.reader.poll()
                self.path.unlink()
        self.path.write_bytes(b'{"schema_version":1,"schema_version":1}')
        self.path.chmod(0o600)
        with self.assertRaises(m.ObserverError):
            self.reader.poll()

    def test_world_readable_marker_and_wrong_owner_are_rejected(self):
        self.publish()
        self.path.chmod(0o644)
        with self.assertRaises(m.ObserverError):
            self.reader.poll()
        self.path.chmod(0o600)
        with mock.patch.object(m.os, 'getuid', return_value=os.getuid() + 1):
            with self.assertRaises(m.ObserverError):
                self.reader.poll()

    def test_symlink_fifo_oversize_and_mutation_are_rejected(self):
        target = self.parent / 'target'
        target.write_text(json.dumps(marker()))
        target.chmod(0o600)
        self.path.symlink_to(target)
        with self.assertRaises((m.ObserverError, OSError)):
            self.reader.poll()
        self.path.unlink()
        os.mkfifo(self.path, 0o600)
        with self.assertRaises(m.ObserverError):
            self.reader.poll()
        self.path.unlink()
        self.path.write_bytes(b'x' * 1025)
        self.path.chmod(0o600)
        with self.assertRaises(m.ObserverError):
            self.reader.poll()
        self.path.unlink()
        self.publish()
        original_read = os.read
        def mutate(fd, count):
            content = original_read(fd, count)
            with self.path.open('ab') as stream:
                stream.write(b' ')
            return content
        with mock.patch.object(m.os, 'read', side_effect=mutate):
            with self.assertRaises(m.ObserverError):
                self.reader.poll()

    def test_replaced_or_public_parent_cannot_supply_a_marker(self):
        self.parent.chmod(0o755)
        with self.assertRaises(m.ObserverError):
            self.reader.poll()
        self.parent.chmod(0o700)
        previous = self.parent.with_name(self.parent.name + '.moved')
        self.parent.rename(previous)
        self.parent.mkdir(mode=0o700)
        self.addCleanup(lambda: previous.rmdir())
        with self.assertRaises(m.ObserverError):
            self.reader.poll()

    def test_salt_is_private_and_never_in_output(self):
        salt = self.parent / 'database-hash-salt'
        salt.write_text('a' * 32 + '\n')
        salt.chmod(0o600)
        self.assertEqual(m.read_hash_salt(salt), 'a' * 32)
        salt.write_text('SECRET_INVALID_SALT')
        with self.assertRaises(m.ObserverError) as failure:
            m.read_hash_salt(salt)
        self.assertNotIn('SECRET', str(failure.exception))


class PublicationTests(unittest.TestCase):
    def test_readiness_is_complete_at_first_visibility_and_never_replaced(self):
        with tempfile.TemporaryDirectory(prefix='northstar-observer-publication.') as root:
            path = Path(root) / 'observer-ready.json'
            value = {'observer_pid': os.getpid(), 'sample_count': 1}
            rename = m._rename_noreplace

            def inspect(directory, source, destination):
                self.assertFalse(path.exists())
                self.assertEqual(json.loads((Path(root) / source).read_bytes()), value)
                rename(directory, source, destination)
                self.assertEqual(json.loads(path.read_bytes()), value)
                self.assertEqual(path.stat().st_nlink, 1)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

            with mock.patch.object(m, '_rename_noreplace', side_effect=inspect) as publication:
                m.write_small(path, value)
                publication.assert_called_once()
            with self.assertRaises(FileExistsError):
                m.write_small(path, {'replacement': True})
            self.assertEqual(json.loads(path.read_bytes()), value)
            self.assertEqual(list(Path(root).iterdir()), [path])

    def test_unavailable_publication_cleans_temporary_and_fails(self):
        with tempfile.TemporaryDirectory(prefix='northstar-observer-publication.') as root:
            path = Path(root) / 'observer-ready.json'
            with mock.patch.object(m, '_rename_noreplace', side_effect=OSError('unavailable')):
                with self.assertRaises(OSError):
                    m.write_small(path, {'observer_pid': os.getpid(), 'sample_count': 1})
            self.assertEqual(list(Path(root).iterdir()), [])


class LibpqTests(unittest.TestCase):
    def connection(self, library):
        connection = m.Libpq.__new__(m.Libpq)
        connection.conn = 7
        connection.lib = library
        connection.limits = mock.Mock()
        return connection

    def test_connect_pins_read_only_search_path_and_fixed_loopback(self):
        library = mock.Mock()
        library.PQconnectStartParams.return_value = 8
        library.PQconnectPoll.return_value = 3
        library.PQsetnonblocking.return_value = 0
        connection = self.connection(library)
        with mock.patch.dict(os.environ, {'PGHOST': '127.0.0.1', 'PGPORT': '5432', 'PGDATABASE': 'postgres'}, clear=True):
            connection.connect()
        keys, values, expand = library.PQconnectStartParams.call_args.args
        options = dict(zip(list(keys)[:-1], list(values)[:-1]))
        self.assertEqual(expand, 0)
        self.assertEqual(options[b'host'], b'127.0.0.1')
        self.assertEqual(options[b'hostaddr'], b'127.0.0.1')
        self.assertEqual(options[b'port'], b'5432')
        self.assertEqual(options[b'application_name'], b'northstar-control-observer')
        self.assertEqual(options[b'connect_timeout'], b'5')
        self.assertEqual(options[b'options'], b'-c statement_timeout=2000 -c lock_timeout=500 -c default_transaction_read_only=on -c search_path=pg_catalog')
        self.assertIn('pg_catalog.host(pg_catalog.inet_server_addr())', m.attestation_sql())
        self.assertIn("current_user = 'xmpp_test'", m.attestation_sql())
        self.assertIn('FROM pg_catalog.pg_roles', m.attestation_sql())

    def test_endpoint_or_service_override_is_rejected_before_connect(self):
        for override in ({'PGHOST': 'localhost'}, {'PGHOST': '::1'}, {'PGPORT': '05432'},
                         {'PGPORT': '65536'}, {'PGSERVICE': 'untrusted'}, {'PGSERVICEFILE': '/secret'}):
            with self.subTest(override=override):
                library = mock.Mock()
                connection = self.connection(library)
                values = {'PGHOST': '127.0.0.1', 'PGPORT': '5432', 'PGDATABASE': 'postgres', **override}
                with mock.patch.dict(os.environ, values, clear=True):
                    with self.assertRaises(m.ObserverError):
                        connection.connect()
                library.PQconnectStartParams.assert_not_called()
    def test_server_error_is_raised_only_after_full_response_drain(self):
        library = mock.Mock()
        library.PQsendQuery.return_value = 1
        library.PQflush.return_value = 0
        library.PQisBusy.return_value = 0
        library.PQgetResult.side_effect = [11, 12, None]
        library.PQresultStatus.return_value = 7
        library.PQresultErrorField.return_value = b'57014'
        connection = self.connection(library)
        with self.assertRaises(m.ObserverError) as result:
            connection.query('SELECT fixed')
        self.assertEqual(result.exception.code, 'server_query_failed')
        self.assertEqual(library.PQgetResult.call_count, 3)
        self.assertEqual(library.PQclear.call_args_list, [mock.call(11), mock.call(12)])

    def test_pending_response_deadline_never_becomes_reusable_server_error(self):
        library = mock.Mock()
        library.PQsendQuery.return_value = 1
        library.PQflush.return_value = 0
        library.PQisBusy.return_value = 1
        connection = self.connection(library)
        connection.ready = mock.Mock(side_effect=m.ObserverError('client_query_deadline'))
        with self.assertRaises(m.ObserverError) as result:
            connection.query('SELECT fixed')
        self.assertEqual(result.exception.code, 'client_query_deadline')
        library.PQgetResult.assert_not_called()
        connection.close()
        connection.close()
        library.PQfinish.assert_called_once_with(7)


SPY = r'''
import importlib.util,json,os,signal,sys,types
from pathlib import Path
source,out,control,case=sys.argv[1:]
spec=importlib.util.spec_from_file_location('observer',source)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
clock=[100.0]
m.time.monotonic=lambda:clock[0]
m.time.monotonic_ns=lambda:int(clock[0]*1e9)
def sleep(seconds):clock[0]+=max(seconds,0.000001)
m.time.sleep=sleep
control=Path(control); marker_path=control/'first-failure.json';salt=control/'database-hash-salt'
salt.write_text('a'*32);salt.chmod(0o600)
instances=[]
class Fake:
    def __init__(self,limits):
        self.conn=1;self.n=0;self.closed=0;instances.append(self)
        self.lib=types.SimpleNamespace(PQbackendPID=lambda c:987,PQlibVersion=lambda:160015)
    def connect(self):
        if case=='connect_failure':raise m.ObserverError('connection_failed')
    def query(self,sql):
        if sql==m.attestation_sql():return {'authorized':1 if case=='attestation_wrong_type' else case!='attestation_failure'}
        self.n+=1
        if case=='server_error':raise m.ObserverError('server_query_failed','57014')
        if case=='recovered' and self.n==1:raise m.ObserverError('server_query_failed','57014')
        if case=='pending_error':raise m.ObserverError('client_query_deadline')
        if case=='private_field':return {'at':'now','total':1,'rows':[{'query':'SENSITIVE'}]}
        if case=='unrecovered' and self.n==2:
            m.on_signal(signal.SIGTERM,None)
            raise m.ObserverError('server_query_failed','57014')
        if case in {'capture','incomplete','write_failure','late_marker'} and self.n==3:
            mono=clock[0]-(20 if case=='late_marker' else 0)
            m.write_small(marker_path,{'schema_version':1,'cause':'command_exit','monotonic_ns':int(mono*1e9),'realtime_ns':1789123456000000000})
            if case=='incomplete':m.on_signal(signal.SIGTERM,None)
        if case=='capture' and self.n==4:
            marker_path.unlink()
            m.write_small(marker_path,{'schema_version':1,'cause':'deadline','monotonic_ns':int(clock[0]*1e9),'realtime_ns':1789123456000000000})
        if case in {'ok','slow','recovered','parent_loss'} and self.n==3:
            if case=='parent_loss':m.parent_identity=lambda pid:None
            else:m.on_signal(signal.SIGTERM,None)
        clock[0]+=.05
        rows=[]
        if case in {'ok','slow','capture'}:
            rows=[{'pid':101,'backend_start':'2026-09-11T00:00:00+00:00','database_hash':'b'*32,'state':'active' if case=='slow' else 'idle','wait_event_type':'Client','wait_event':'ClientRead','query_age_ms':2000,'state_age_ms':0,'blocking_pids':[]}]
        return {'at':'now','total':len(rows),'rows':rows}
    def close(self):self.closed+=1;self.conn=None
m.Libpq=Fake
if case=='write_failure':
    original=m.Evidence.write
    def broken(self,record):
        if isinstance(record,dict) and record.get('type')=='first_failure':raise OSError('SENSITIVE')
        original(self,record)
    m.Evidence.write=broken
sys.argv=['observer','--output-dir',out,'--failure-marker',str(marker_path),'--database-hash-salt-file',str(salt),'--max-seconds','60']
code=m.main()
result=json.loads((Path(out)/'observer-result.json').read_text())
records=[json.loads(line) for line in (Path(out)/'observations.jsonl').read_text().splitlines()]
assert result['fixture_status']=='not_determined_by_observer'
assert len(instances)==1 and instances[0].closed==1
success=case in {'ok','slow','recovered','capture'}
assert (code==0)==success and result['observer_ok']==success, (case,code,result)
assert all('SENSITIVE' not in json.dumps(item) for item in records)
assert all('a'*32 not in json.dumps(item) for item in records)
if case in {'ok','slow','recovered'}:
    assert [record['type'] for record in records]==['metadata','terminal']
    assert result['captured_samples']==0 and not result['failure_marker_seen']
if case=='slow':assert result['slow_backend_events']==1
if case=='recovered':
    assert result['sample_errors']==1 and result['recovered_sample_errors']==1 and result['consecutive_sample_errors']==0 and result['error_code'] is None
if case=='unrecovered':assert result['error_code']=='sample_error_not_recovered'
if case=='server_error':assert instances[0].n==3 and result['consecutive_sample_errors']==3
if case=='pending_error':assert instances[0].n==1
if case=='parent_loss':assert result['error_code']=='parent_identity_lost'
if case=='capture':
    event=[r for r in records if r['type']=='first_failure']
    assert len(event)==1 and event[0]['cause']=='command_exit'
    assert result['post_window_complete'] and result['stop_signal'] is None
    assert event[0]['capture_until_monotonic']==event[0]['monotonic_ns']/1e9+15
    assert all(r['monotonic']<=event[0]['capture_until_monotonic'] for r in records if r['type']=='sample')
    assert clock[0]<=event[0]['capture_until_monotonic']+.001
if case=='incomplete':assert not result['post_window_complete']
if case=='late_marker':assert result['error_code']=='failure_window_unavailable'
assert sum(p.stat().st_size for p in Path(out).iterdir())<=m.TOTAL_BYTES
assert all((p.stat().st_mode&0o077)==0 for p in Path(out).iterdir())
'''


class MainTests(unittest.TestCase):
    def run_case(self, case):
        with tempfile.TemporaryDirectory(prefix='northstar-observer-main.') as directory:
            parent = Path(directory)
            control = parent / 'control'
            control.mkdir(mode=0o700)
            result = subprocess.run([sys.executable, '-c', SPY, str(SOURCE), str(parent / 'output'), str(control), case], capture_output=True, text=True, timeout=8)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_success_is_compact_even_with_slow_queries(self):
        for case in ('ok', 'slow'):
            with self.subTest(case=case): self.run_case(case)

    def test_recovered_server_error_and_unrecovered_shutdown(self):
        for case in ('recovered', 'unrecovered', 'server_error'):
            with self.subTest(case=case): self.run_case(case)

    def test_pending_connection_and_parent_failures_close_without_reconnect(self):
        for case in ('pending_error', 'connect_failure', 'parent_loss', 'attestation_failure', 'attestation_wrong_type', 'overall_deadline'):
            with self.subTest(case=case): self.run_case(case)

    def test_marker_capture_auto_exits_at_original_deadline(self):
        self.run_case('capture')

    def test_incomplete_or_unavailable_failure_window_is_not_success(self):
        for case in ('incomplete', 'late_marker'):
            with self.subTest(case=case): self.run_case(case)

    def test_malformed_or_unwritable_evidence_is_not_success(self):
        for case in ('private_field', 'write_failure'):
            with self.subTest(case=case): self.run_case(case)


if __name__ == '__main__':
    unittest.main(verbosity=2)
