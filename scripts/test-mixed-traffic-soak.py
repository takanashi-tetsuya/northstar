#!/usr/bin/env python3
"""Deterministic workload, fixture-lifecycle and failure-observer regressions.

No Northstar server or PostgreSQL is required. Real OS children/sockets only
exercise the observer's independent deadline and scoped process-group cleanup.
"""
import collections
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SOAK = load('mixed_soak', ROOT / 'scripts/mixed-traffic-soak.py')
DIAG = load('soak_diagnostics', ROOT / 'scripts/lib/soak-failure-diagnostics.py')


class LifecycleTests(unittest.TestCase):
    def test_cleanup_failure_never_passes_successful_workload(self):
        for errors in ('forced_kill', 'listener_open', 'nonzero_exit', 'missing_shutdown_marker'):
            with self.subTest(errors=errors):
                result = {'workload_status': 'passed'}
                SOAK.finalize_result(result, {'clean': False, 'errors': [errors]})
                self.assertEqual(result['status'], 'failed')
                self.assertEqual(result['workload_status'], 'passed')

    def test_success_requires_both_workload_and_cleanup(self):
        self.assertEqual(SOAK.finalize_result({'workload_status': 'passed'}, {'clean': True})['status'], 'passed')
        self.assertEqual(SOAK.finalize_result({'workload_status': 'failed', 'error': 'original'}, {'clean': True})['status'], 'failed')
        self.assertEqual(SOAK.finalize_result({}, {'clean': True})['status'], 'failed')

    def test_failure_is_recorded_then_observed_before_closing_peers_and_server(self):
        result, events = {}, []
        fixture = SimpleNamespace(binary_sha256='test', start=lambda: object())

        class Workload:
            def __init__(self, *_args):
                self.counts = {'rounds': 72}
                self.expected = {('alice', 'soak-00073-group'): {}}
                self.observed = collections.Counter()
                self.soak_start = None

            def run(self):
                raise TimeoutError('soak-00073-group')

            def close(self):
                events.append('peers_close')

        def capture(_label):
            self.assertEqual(result['workload_status'], 'failed')
            self.assertIn('soak-00073-group', result['error'])
            self.assertEqual(events, [])
            events.append('capture')
            raise RuntimeError('diagnostic failure must not mask the original')

        def stop():
            events.append('server_stop')
            return {'clean': True}

        fixture.capture, fixture.stop = capture, stop
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            SOAK.run_owned_fixture(fixture, 600, result, Workload)
        self.assertEqual(events, ['capture', 'peers_close', 'server_stop'])
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['error'], 'TimeoutError: soak-00073-group')
        self.assertEqual(result['missing_deliveries'], [{'recipient': 'alice', 'message_id': 'soak-00073-group'}])

    def fixture_without_tools(self, directory):
        output = Path(directory)
        binary = output / 'binary'
        binary.write_bytes(b'fixture binary')
        with patch.object(SOAK, 'postgres_environment', side_effect=lambda env: env):
            return SOAK.OwnedFixture(binary, output, 55435)

    def test_shutdown_timeout_kills_even_if_observation_raises(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture_without_tools(directory)
            server = Mock(returncode=-signal.SIGKILL, pid=123)
            server.poll.return_value = None
            server.wait.side_effect = [subprocess.TimeoutExpired('server', SOAK.SHUTDOWN_SECONDS), None]
            fixture.server = server
            fixture.capture = Mock(side_effect=RuntimeError('broken observer'))
            with patch.object(SOAK, 'listener_closed', return_value=True), contextlib.redirect_stdout(io.StringIO()):
                cleanup = fixture.stop()
            server.terminate.assert_called_once()
            server.kill.assert_called_once()
            self.assertEqual(server.wait.call_args_list[0].kwargs['timeout'], 20)
            self.assertTrue(cleanup['forced_kill'])
            self.assertFalse(cleanup['clean'])
            result = SOAK.finalize_result({'workload_status': 'passed'}, cleanup)
            self.assertEqual(result['status'], 'failed')

    def test_server_success_with_open_listener_still_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture_without_tools(directory)
            fixture.server = Mock(returncode=0)
            fixture.server.poll.return_value = 0
            fixture.listeners = {'http': '127.0.0.1:12345'}
            (Path(directory) / 'server.log').write_text(json.dumps({'fields': {'message': 'shutdown complete'}}) + '\n')
            with patch.object(SOAK, 'listener_closed', side_effect=lambda address: address.endswith('55435')):
                cleanup = fixture.stop()
            self.assertTrue(cleanup['shutdown_complete'])
            self.assertFalse(cleanup['listener_closed_checks']['http'])
            self.assertFalse(cleanup['clean'])

    def test_signal_interruption_still_runs_cleanup(self):
        fixture = SimpleNamespace(start=Mock(side_effect=InterruptedError('operator signal')), capture=Mock(return_value={}), stop=Mock(return_value={'clean': True}))
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            result = SOAK.run_owned_fixture(fixture, 600, {})
        fixture.capture.assert_called_once()
        fixture.stop.assert_called_once()
        self.assertEqual(result['status'], 'failed')
        self.assertIn('InterruptedError', result['error'])

    def test_migrations_precede_server_and_migrator_credentials_do_not_reach_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture_without_tools(directory)
            events = []

            def command(argv, name, env=None, **_kwargs):
                events.append((name, env))
                if name == 'certificate.log':
                    (fixture.runtime / 'server.key').write_bytes(b'private fixture key')

            fixture.command = command
            ready = SimpleNamespace(wait_for_record=lambda *_args: {'http': '127.0.0.1:12345', 'web-admin': '127.0.0.1:12346'})
            helpers = SimpleNamespace(api=lambda *_args: (200, 'ready'))

            def popen(*_args, **kwargs):
                self.assertIn('migrate.log', [name for name, _ in events])
                migration = next(env for name, env in events if name == 'migrate.log')
                self.assertIn('MIGRATOR_DATABASE_URL', migration)
                self.assertNotIn('MIGRATOR_DATABASE_URL', kwargs['env'])
                self.assertNotIn('MIGRATOR_DATABASE_URL_FILE', kwargs['env'])
                return SimpleNamespace(pid=123)

            with patch.object(SOAK, 'postgres_environment', side_effect=lambda env: env), patch.object(SOAK.subprocess, 'Popen', side_effect=popen), patch.object(SOAK, 'load_module', side_effect=[ready, helpers]), contextlib.redirect_stdout(io.StringIO()):
                self.assertIs(fixture.start(), helpers)
            fixture.server_log.close()

    def test_environment_is_hermetic(self):
        input_env = {'PATH': '/bin', 'LD_LIBRARY_PATH': '/lib', 'DATABASE_URL': 'secret',
                     'PGSERVICEFILE': 'secret', 'PGPASSWORD': 'secret', 'REDIS_URL': 'secret',
                     'SM_ENABLED': 'false', 'RUST_LOG': 'trace'}
        self.assertEqual(SOAK.fixture_environment(input_env), {'PATH': '/bin', 'LD_LIBRARY_PATH': '/lib'})

    def test_frame_tracing_is_explicit_and_cannot_enable_payload_targets(self):
        self.assertEqual(SOAK.fixture_log_filter(False), 'rust_xmpp_server=info')
        self.assertEqual(SOAK.fixture_log_filter(True),
                         'rust_xmpp_server=info,rust_xmpp_server::xmpp::frame_execution=debug')
        ordinary = SOAK.parse_arguments(['--binary', sys.executable])
        traced = SOAK.parse_arguments(['--binary', sys.executable, '--trace-frames'])
        self.assertFalse(ordinary.trace_frames)
        self.assertTrue(traced.trace_frames)

    def test_source_archives_have_null_commit_and_changed_bytes_change_fingerprint(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / 'src').mkdir()
            (source / 'src/main.rs').write_text('fn main() {}')
            with patch.object(SOAK, 'SOURCE', source), patch.object(SOAK.subprocess, 'check_output') as command:
                before = SOAK.source_identity()
                command.assert_not_called()
                self.assertIsNone(before['commit'])
                (source / 'src/main.rs').write_text('fn main() { println!("changed"); }')
                after = SOAK.source_identity()
            self.assertNotEqual(before['source_files_sha256'], after['source_files_sha256'])

    def test_duration_and_output_options_fail_closed(self):
        for seconds in ('nan', 'inf', '0', '-1', '3601'):
            with self.subTest(seconds=seconds), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                SOAK.parse_arguments(['--binary', sys.executable, '--duration-seconds', seconds])
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            SOAK.parse_arguments(['--binary', sys.executable, '--output-dir', directory])
        self.assertEqual(SOAK.minimum_rounds(600), 200)
        self.assertEqual(SOAK.minimum_rounds(90), 30)
        self.assertEqual(SOAK.minimum_rounds(1), 1)


class ProtocolChecks(unittest.TestCase):
    def workload(self):
        return SOAK.MixedTraffic(None, None, 600, {})

    def test_delivery_exactness_and_envelope_checks_are_retained(self):
        valid = "<message xmlns='jabber:client' type='groupchat' id='soak-1' from='room@conference.localhost/Alice'><encrypted>opaque-payload</encrypted></message>"
        peer = SimpleNamespace(username='alice')
        workload = self.workload()
        workload.expected[('alice', 'soak-1')] = {'type': 'groupchat', 'from': 'room@conference.localhost', 'payload': 'opaque-payload'}
        for text in (valid.replace('groupchat', 'chat'), valid.replace('opaque-payload', 'wrong'), valid.replace('room@', 'other@')):
            with self.subTest(text=text), self.assertRaises(AssertionError):
                workload.observe(peer, text)
        workload.observe(peer, valid)
        self.assertEqual(workload.counts['live_deliveries'], 1)
        with self.assertRaisesRegex(AssertionError, 'duplicate'):
            workload.observe(peer, valid)
        with self.assertRaisesRegex(AssertionError, 'unexpected delivery'):
            workload.observe(SimpleNamespace(username='bob'), valid)

    def test_receive_timeout_preserves_recipient_and_prior_frames(self):
        peer = SimpleNamespace(username='alice', receive=Mock(side_effect=["<presence xmlns='jabber:client'/>", TimeoutError('deadline')]))
        with self.assertRaises(TimeoutError) as raised:
            self.workload().receive(peer, lambda *_args: False, 'soak-73-group')
        message = str(raised.exception)
        self.assertIn('recipient=alice', message)
        self.assertIn('soak-73-group', message)
        self.assertIn('<presence', message)
        self.assertLessEqual(peer.receive.call_args_list[0].args[0], 10)
        self.assertLess(peer.receive.call_args_list[1].args[0], peer.receive.call_args_list[0].args[0])

    def test_history_requires_encrypted_payload_and_matching_counts(self):
        workload = self.workload()
        workload.buser = 'bob'
        fin = SOAK.ET.fromstring("<iq xmlns='jabber:client'><fin xmlns='urn:xmpp:mam:2'><set xmlns='http://jabber.org/protocol/rsm'><count>1</count></set></fin></iq>")
        frame = "<message xmlns='jabber:client'><result xmlns='urn:xmpp:mam:2' queryid='q1' id='stable'><forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:client' id='soak-1'><encrypted xmlns='urn:xmpp:omemo:2'/><stanza-id xmlns='urn:xmpp:sid:0' id='stable'/></message></forwarded></result></message>"
        workload.iq = Mock(return_value=(fin, [frame]))
        workload.history(None, 'room', 'q1', ['soak-1'], 1)
        with self.assertRaisesRegex(AssertionError, 'wrong MAM count'):
            workload.history(None, 'room', 'q1', ['soak-1'], 2)
        for malformed in (frame.replace('urn:xmpp:omemo:2', 'urn:wrong'), frame.replace("<encrypted", "<body>plaintext</body><encrypted"), frame.replace('soak-1', 'soak-nostore')):
            workload.iq.return_value = fin, [malformed]
            with self.subTest(malformed=malformed), self.assertRaises(AssertionError):
                workload.history(None, 'room', 'q1', ['soak-1'], 1)


class DiagnosticTests(unittest.TestCase):
    def test_errors_redact_exception_text_and_flush_stage(self):
        stream = io.StringIO()
        DIAG.write_stage('failure', lambda: (_ for _ in ()).throw(ValueError('PASSWORD-SECRET')), stream)
        value = json.loads(stream.getvalue())
        self.assertEqual(value['status'], 'unavailable')
        self.assertEqual(value['error_type'], 'ValueError')
        self.assertNotIn('PASSWORD-SECRET', stream.getvalue())

    def test_process_counters_and_missing_optional_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            process = root / '123'
            (process / 'task' / '123').mkdir(parents=True)
            fields = ['R'] + [str(i) for i in range(1, 50)]
            (process / 'stat').write_text('123 (name with ) parentheses) ' + ' '.join(fields))
            (process / 'status').write_text('VmRSS:\t123 kB\nName:\tSECRET\nSigPnd:\t0\n')
            snapshot = DIAG.process_snapshot(123, proc=root, cgroup_root=root)
            self.assertEqual(snapshot['start_ticks'], '19')
            self.assertEqual(snapshot['cpu_user_ticks'], 11)
            self.assertEqual(snapshot['major_faults'], 9)
            self.assertEqual(snapshot['cgroup']['status'], 'unavailable')
            self.assertEqual(snapshot['schedstat']['status'], 'unavailable')
            self.assertNotIn('SECRET', json.dumps(snapshot))

    def test_cgroup_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'cgroup').write_text('0::/../../outside\n')
            with self.assertRaisesRegex(ValueError, 'invalid_cgroup_path'):
                DIAG.cgroup_snapshot(root, root)

    def test_bounded_file_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'counter'
            path.write_bytes(b'x' * 9)
            with self.assertRaises(ValueError):
                DIAG.bounded_read(path, limit=8)

    def test_diagnostics_do_not_overwrite_existing_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'evidence.jsonl'
            path.write_text('original')
            result = DIAG.capture_failure(os.getpid(), None, None, 55435, path, os.environ)
            self.assertEqual(result['status'], 'unavailable')
            self.assertEqual(path.read_text(), 'original')

    def test_observer_deadline_keeps_partial_evidence_and_kills_its_child_group(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            worker = root / 'hung.py'
            worker.write_text("import json,os,subprocess,sys,time\nchild=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])\nprint(json.dumps({'stage':'started','pid':os.getpid(),'child_pid':child.pid}),flush=True)\ntime.sleep(60)\n")
            output = root / 'partial.jsonl'
            started = time.monotonic()
            result = DIAG.capture_failure(os.getpid(), None, None, 55435, output, os.environ, seconds=.4, worker=worker)
            self.assertEqual(result['status'], 'deadline')
            self.assertEqual(result['exit_code'], -signal.SIGKILL)
            self.assertLess(time.monotonic() - started, 3)
            evidence = json.loads(output.read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(evidence['pid'], 0)
            # The grandchild belongs to the observer, so its reaping belongs
            # to init after the observer is killed. It must no longer run.
            deadline = time.monotonic() + 2
            while True:
                try:
                    state = Path(f"/proc/{evidence['child_pid']}/stat").read_text().rsplit(')', 1)[1].split()[0]
                except FileNotFoundError:
                    break
                if state == 'Z':
                    break
                self.assertLess(time.monotonic(), deadline, 'observer descendant survived cleanup')
                time.sleep(.01)

    def serve_once(self, writer):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        def serve():
            try:
                stream, _ = listener.accept()
                with stream:
                    stream.recv(4096)
                    writer(stream)
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                listener.close()
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        return f'127.0.0.1:{port}', thread

    def test_http_snapshot_reads_chunked_reply(self):
        address, thread = self.serve_once(lambda stream: stream.sendall(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nready\r\n0\r\n\r\n'))
        self.assertEqual(DIAG.http_snapshot(address, '/readyz'), {'status_code': 200, 'body': 'ready'})
        thread.join(1)

    def test_http_total_deadline_covers_dribbled_headers(self):
        def dribble(stream):
            for byte in b'HTTP/1.1 200 OK\r\n':
                stream.sendall(bytes([byte]))
                time.sleep(.025)
        address, thread = self.serve_once(dribble)
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            DIAG.http_snapshot(address, '/readyz', seconds=.1)
        self.assertLess(time.monotonic() - started, .5)
        thread.join(1)

    def test_http_size_bound_and_loopback_restriction(self):
        address, thread = self.serve_once(lambda stream: stream.sendall(b'HTTP/1.1 200 OK\r\n\r\n' + b'x' * (DIAG.MAX_HTTP_BYTES + 1)))
        with self.assertRaises(ValueError):
            DIAG.http_snapshot(address, '/metrics')
        thread.join(1)
        for address, path in (('example.com:80', '/metrics'), ('127.0.0.1:80', '/api/v1/users'), ('127.0.0.1:0', '/metrics')):
            with self.subTest(address=address, path=path), self.assertRaises(ValueError):
                DIAG.http_snapshot(address, path)

    def test_catalog_evidence_survives_blocked_table_counts(self):
        stream = io.StringIO()
        write_stage = DIAG.write_stage
        calls = []

        def database(_port, counts=False):
            calls.append(counts)
            if counts:
                raise TimeoutError('table locked')
            return {'activity': [{'pid': 7, 'blocking_pids': [8]}], 'locks': []}

        with patch.object(sys, 'argv', ['diagnostics', '--pid', '123', '--database-port', '55435']), \
                patch.object(DIAG, 'process_snapshot', return_value={'pid': 123}), \
                patch.object(DIAG, 'database_snapshot', side_effect=database), \
                patch.object(DIAG, 'write_stage', side_effect=lambda name, operation: write_stage(name, operation, stream)):
            DIAG.main()
        stages = [json.loads(line) for line in stream.getvalue().splitlines()]
        self.assertEqual(calls, [False, True])
        activity = next(stage for stage in stages if stage['stage'] == 'postgres_activity')
        counts = next(stage for stage in stages if stage['stage'] == 'postgres_counts')
        self.assertEqual(activity['status'], 'ok')
        self.assertEqual(activity['value']['activity'][0]['blocking_pids'], [8])
        self.assertEqual(counts['status'], 'unavailable')
        self.assertEqual(counts['error_type'], 'TimeoutError')
        self.assertLess(stages.index(activity), stages.index(counts))

    def test_database_observer_is_read_only_and_excludes_query_contents(self):
        self.assertNotIn('left(query', DIAG.ACTIVITY_SQL)
        self.assertNotIn('usename', DIAG.ACTIVITY_SQL)
        self.assertNotIn('short_soak.muc_messages', DIAG.ACTIVITY_SQL)
        self.assertIn('short_soak.muc_messages', DIAG.COUNTS_SQL)
        self.assertIn('pg_blocking_pids', DIAG.ACTIVITY_SQL)
        self.assertIn('datname=current_database()', DIAG.ACTIVITY_SQL)
        with patch.object(DIAG.subprocess, 'run', return_value=SimpleNamespace(stdout=b'{}')) as run:
            self.assertEqual(DIAG.database_snapshot(55435), {})
        options = run.call_args.kwargs
        self.assertEqual(options['env']['PGHOST'], '127.0.0.1')
        self.assertEqual(options['timeout'], 2.5)
        self.assertIn('statement_timeout=1500', options['env']['PGOPTIONS'])



class StreamManagementTests(unittest.TestCase):
    def workload(self, enabled=True):
        return SOAK.MixedTraffic(None, None, 1, {'stream_management': enabled})

    def test_counts_all_stanzas_but_never_nonzas(self):
        workload, peer = self.workload(), Mock()
        workload.sm[peer] = {'handled': 0, 'last_ack': 0}
        for stanza in ["<message xmlns='jabber:client'/>",
                       "<iq xmlns='jabber:client' type='result'/>",
                       "<presence xmlns='jabber:client'/>"]:
            workload.observe(peer, stanza)
        workload.observe(peer, "<r xmlns='urn:xmpp:sm:3'/>")
        workload.observe(peer, "<a xmlns='urn:xmpp:sm:3' h='2'/>")
        self.assertEqual(workload.sm[peer], {'handled': 3, 'last_ack': 3})
        self.assertEqual(workload.counts['sm_inbound_stanzas'], 3)
        self.assertEqual(workload.counts['sm_client_acks'], 4)
        self.assertEqual(workload.counts['sm_server_ack_responses'], 1)
        self.assertEqual(peer.send.call_args.args[0], "<a xmlns='urn:xmpp:sm:3' h='3'/>")

    def test_mam_forwarded_content_counts_once(self):
        workload, peer = self.workload(), Mock()
        workload.sm[peer] = {'handled': 0, 'last_ack': 0}
        workload.observe(peer, "<message xmlns='jabber:client'><result xmlns='urn:xmpp:mam:2'><forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:client'/></forwarded></result></message>")
        self.assertEqual(workload.sm[peer]['handled'], 1)
        self.assertEqual(workload.counts['sm_inbound_stanzas'], 1)

    def test_ack_count_wraps_and_streams_are_independent(self):
        workload, first, second = self.workload(), Mock(), Mock()
        workload.sm[first] = {'handled': 2**32 - 1, 'last_ack': 2**32 - 1}
        workload.sm[second] = {'handled': 7, 'last_ack': 7}
        workload.observe(first, "<presence xmlns='jabber:client'/>")
        self.assertEqual(workload.sm[first]['handled'], 0)
        self.assertEqual(workload.sm[second]['handled'], 7)
        second.send.assert_not_called()

    def test_sm_enable_never_requests_or_accepts_resume_authority(self):
        for response in ("<enabled xmlns='urn:xmpp:sm:3' resume='true' id='unexpected'/>",
                         "<enabled xmlns='urn:xmpp:sm:3' resume='false' id='unexpected'/>"):
            peer = Mock(username='alice')
            peer.receive.return_value = response
            helpers = SimpleNamespace(XmppWebSocket=Mock(return_value=peer))
            workload = SOAK.MixedTraffic(None, helpers, 1, {'stream_management': True})
            with self.subTest(response=response), self.assertRaises(AssertionError):
                workload.new_peer('alice', 0)
            self.assertEqual(peer.send.call_args_list[0].args[0],
                             "<enable xmlns='urn:xmpp:sm:3' resume='false'/>")
            self.assertNotIn(peer, workload.sm)

    def test_non_sm_observation_sends_no_ack(self):
        workload, peer = self.workload(False), Mock()
        workload.observe(peer, "<presence xmlns='jabber:client'/>")
        peer.send.assert_not_called()
        self.assertNotIn('sm_inbound_stanzas', workload.counts)


    def test_sm_ack_shares_receive_deadline_and_late_result_is_rejected(self):
        workload, peer = self.workload(), Mock()
        workload.sm[peer] = {'handled': 0, 'last_ack': 0}
        peer.receive.return_value = "<presence xmlns='jabber:client'/>"
        with patch.object(SOAK.time, 'monotonic', side_effect=[0, 0, 9.8, 10.1]):
            with self.assertRaises(TimeoutError):
                workload.receive(peer, lambda *_: True, 'late stanza', timeout=10)
        self.assertEqual(peer.send.call_args.kwargs['deadline'], 10)

    def test_websocket_send_respects_optional_deadline_and_expiry(self):
        helpers = load('soak_send_deadline_helpers', ROOT / 'scripts/integration-wsl.py')
        peer = object.__new__(helpers.XmppWebSocket)
        peer._construction_deadline = None
        peer.sock = Mock()
        with patch.object(helpers.time, 'monotonic', return_value=9.8):
            peer.send("<a xmlns='urn:xmpp:sm:3' h='1'/>", deadline=10)
        self.assertAlmostEqual(peer.sock.settimeout.call_args.args[0], .2)
        peer.sock.reset_mock()
        with patch.object(helpers.time, 'monotonic', return_value=10):
            with self.assertRaises(TimeoutError):
                peer.send("<a xmlns='urn:xmpp:sm:3' h='1'/>", deadline=10)
        peer.sock.sendall.assert_not_called()
        peer.send("<presence xmlns='jabber:client'/>")
        peer.sock.settimeout.assert_called_with(10)

    def test_reconnected_stream_starts_its_own_zero_counter(self):
        first, second = Mock(username='alice'), Mock(username='alice')
        for peer in (first, second):
            peer.receive.return_value = "<enabled xmlns='urn:xmpp:sm:3' resume='false'/>"
        helpers = SimpleNamespace(XmppWebSocket=Mock(side_effect=[first, second]))
        workload = SOAK.MixedTraffic(None, helpers, 1, {'stream_management': True})
        workload.new_peer('alice', 0)
        workload.observe(first, "<presence xmlns='jabber:client'/>")
        workload.new_peer('alice', 15)
        self.assertEqual(workload.sm[first]['handled'], 1)
        self.assertEqual(workload.sm[second]['handled'], 0)
        self.assertEqual(workload.counts['sm_enabled_streams'], 2)

    def test_invalid_server_ack_is_not_success(self):
        for value in ('-1', '4294967296', 'secret', ''):
            workload, peer = self.workload(), Mock()
            workload.sm[peer] = {'handled': 0, 'last_ack': 0}
            with self.subTest(value=value), self.assertRaises(AssertionError):
                workload.observe(peer, f"<a xmlns='urn:xmpp:sm:3' h='{value}'/>")
            self.assertEqual(workload.counts['sm_server_ack_responses'], 0)

    def test_enable_precedes_initial_presence_on_every_new_stream(self):
        peer = Mock(username='alice')
        peer.receive.return_value = "<enabled xmlns='urn:xmpp:sm:3' resume='false'/>"
        helpers = SimpleNamespace(XmppWebSocket=Mock(return_value=peer))
        workload = SOAK.MixedTraffic(None, helpers, 1, {'stream_management': True})
        workload.new_peer('alice', 15)
        self.assertFalse(helpers.XmppWebSocket.call_args.kwargs['initial_presence'])
        self.assertEqual([call.args[0] for call in peer.send.call_args_list], [
            "<enable xmlns='urn:xmpp:sm:3' resume='false'/>", "<presence xmlns='jabber:client'/>"])
        self.assertEqual(workload.counts['sm_enabled_streams'], 1)
        self.assertEqual(workload.sm[peer]['handled'], 0)

if __name__ == '__main__':
    unittest.main()
