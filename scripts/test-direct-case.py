#!/usr/bin/env python3
"""Pure/mocked Stage3 plumbing regressions; no saved-case process execution.

All contracts, captures and inventories below are synthetic control fixtures.
The independent semantic oracle and actual Rust wire DTO remain incomplete.
"""
import copy
import importlib.util
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.dont_write_bytecode = True
from lib import controlled_admission_supervision as supervision
from lib import direct_case

_caller_spec = importlib.util.spec_from_file_location(
    'direct_case_caller', Path(__file__).with_name('capture-controlled-admission.py'))
caller = importlib.util.module_from_spec(_caller_spec)
_caller_spec.loader.exec_module(caller)


def reference(name, data=b''):
    return {'file': name, 'bytes': len(data), 'sha256': supervision.fingerprint(data)}


def synthetic_contract(profile_id=supervision.DIRECT_PROFILE):
    profile = supervision.fixed_profile(profile_id)
    helpers = {name: '1' * 64 for name in profile['helpers']}
    sources = dict(helpers, **{'Cargo.lock': '3' * 64})
    value = {
        'schema': supervision.CONTRACT_SCHEMA if profile['legacy'] else supervision.DIRECT_CONTRACT_SCHEMA,
        'run_id': 'synthetic-direct', 'mode': 'record', 'root': '/synthetic/root',
        'binary': '/synthetic/runner', 'evidence_dir': '/synthetic/record',
        'replay_dir': None, 'replay_authority': None,
        'provenance': {
            'schema': 'northstar-admission-controlled-provenance-v1' if profile['legacy'] else
                      'northstar-direct-controlled-provenance-v1',
            'model': 'admission-controlled-v1' if profile['legacy'] else 'direct-controlled-v1',
            'adapter': 'controlled_rust',
            'binding_version': 'synthetic-material-v1' if profile['legacy'] else 'project-local-build-material-v1',
            'source_files': sources, 'source_sha256': supervision.object_hash(sources),
            'binary_sha256': '2' * 64, 'cargo_lock_sha256': '3' * 64,
            'toolchain': 'rustc 1.97.1 (synthetic compiler)',
        },
        'helper_source_files': helpers, 'budgets': profile['budgets'], 'plan_counts': profile['counts'],
        'caller': {'schema': supervision.CALLER_SCHEMA, 'python': '/synthetic/python',
                   'python_sha256': '5' * 64, 'timeout_sha256': supervision.TIMEOUT_SHA256},
    }
    if not profile['legacy']:
        value.update(profile=profile_id, build_record='/synthetic/build-record.json')
        value['provenance'].update(compiler_sha256='6' * 64, build_record_file_sha256='7' * 64,
                                   artifact_role='baseline' if profile_id == supervision.DIRECT_PROFILE else 'no-flush')
        ids = [f'C{index:02d}' for index in range(1, 14)] + ['R01', 'R02', 'R03']
        cancelled = {'C02', 'C05', 'C06', 'C09', 'C11'}
        verdicts = ['Cancelled' if identity in cancelled else 'Pass' if identity.startswith('C') else
                    'InvalidScenario' for identity in ids]
        if profile_id == supervision.NO_FLUSH_PROFILE:
            ids, verdicts = ['M1', 'M2', 'M3', 'M4'], ['InvariantViolation', 'InvariantViolation', 'Pass', 'InvariantViolation']
        value['case_inventory'] = [
            {'id': identity, 'kind': profile['kinds'][index], 'bytes': 2,
             'sha256': supervision.fingerprint(b'{}'), 'expected_verdict': verdicts[index]}
            for index, identity in enumerate(ids)]
    return value


def synthetic_capture(contract):
    profile = supervision.contract_profile(contract)
    total = profile['counts']['total']
    receipt = {
        'schema': supervision.RECEIPT_SCHEMA, 'run_id': contract['run_id'],
        'contract_sha256': supervision.object_hash(contract), 'mode': contract['mode'],
        'owner_exit_status': 0, 'status': 'FixtureMatched', 'completed': total,
        'fixture_matched': total, 'launches': total, 'worker_exit_status': 0,
        'cleanup_complete': True, 'unexpected_children': 0,
        'prefix': reference(f'prefix-{total:03d}.json'), 'terminal': reference('corpus.json'),
        'stop': None, 'stop_kind': None, 'interruption_kind': None,
    }
    capture = {'schema': supervision.CAPTURE_SCHEMA, 'owner_exit_status': 0,
               'stdout_complete': True, 'receipt': receipt}
    authority = {
        'schema': supervision.CALLER_EVIDENCE_SCHEMA, 'invocation_id': 'synthetic-caller',
        'mechanism_sha256': supervision.caller_mechanism_hash(contract),
        'owner_exit_status': 0, 'timeout_exit_status': 0,
        'receipt_sha256': supervision.fingerprint(supervision.encoded(receipt)),
        'total_limit_ms': 617000, 'observed_total_ms': 100,
        'stdout_complete': True, 'stderr_complete': True,
    }
    return capture, authority


def synthetic_record(contract, index=0, stdout=b'{}'):
    entry = contract['case_inventory'][index]
    return {
        'schema': supervision.CASE_SCHEMA, 'run_id': contract['run_id'],
        'contract_sha256': supervision.object_hash(contract), 'index': index,
        'id': entry['id'], 'kind': entry['kind'], 'input': reference(f'{index:03d}.input.json', b'{}'),
        'stdout': {'reference': reference(f'{index:03d}.stdout.bin', stdout),
                   'observed_bytes': len(stdout), 'complete': True},
        'stderr': {'reference': reference(f'{index:03d}.stderr.bin'), 'observed_bytes': 0, 'complete': True},
        'process': {'pid': 123, 'identity': 'unreaped-direct-child-pidfd', 'registered': True,
                    'released': True, 'reaped': True, 'wait_status': 0, 'returncode': 0, 'wall_ms': 1},
        'observation': 'Complete', 'stop_kind': None,
    }


class ClosedProfileTests(unittest.TestCase):
    def test_legacy_counts_budgets_argv_and_mechanism_stay_exact(self):
        contract = synthetic_contract(supervision.LEGACY_PROFILE)
        supervision.validate_contract(contract)
        profile = supervision.contract_profile(contract)
        self.assertEqual(profile['counts'], {'normal': 44, 'rejection': 34, 'shrink': 4, 'total': 82})
        self.assertEqual(profile['budgets'], supervision.PROPOSED_BUDGETS)
        self.assertEqual(profile['helpers'], supervision.HELPER_FILES)
        self.assertEqual(profile['result_schema'], supervision.RESULT_SCHEMA)
        self.assertEqual(profile['corpus_schema'], supervision.CORPUS_SCHEMA)
        self.assertEqual(profile['shrink']['attempts'], [78, 79, 80, 81])
        self.assertEqual(supervision.child_arguments('/binary', '/input'), ['/binary', '/input'])
        self.assertNotIn('--profile', caller.fixed_arguments(contract))
        original_identity = {
            'caller': contract['caller'], 'source_sha256': contract['provenance']['source_sha256'],
            'timeout': supervision.TIMEOUT_PATH, 'timeout_arguments': supervision.TIMEOUT_ARGUMENTS,
            'owner': '/synthetic/root/scripts/run-controlled-admission.py', 'python_arguments': ['-I', '-S', '-B'],
        }
        self.assertEqual(supervision.caller_mechanism_hash(contract), supervision.object_hash(original_identity))

    def test_stage3_profiles_have_exact_finite_counts_roles_and_limits(self):
        for identity, count in ((supervision.DIRECT_PROFILE, 16), (supervision.NO_FLUSH_PROFILE, 4)):
            contract = supervision.validate_contract(synthetic_contract(identity))
            profile = supervision.contract_profile(contract)
            self.assertEqual(profile['counts']['total'], count)
            self.assertEqual(profile['budgets']['launches'], count)
            self.assertEqual(profile['budgets']['case_ms'], 5000)
            self.assertEqual(profile['budgets']['input_bytes'], 65536)
            self.assertEqual(profile['budgets']['stdout_bytes'], 262144)
            self.assertEqual(profile['budgets']['evidence_bytes'], 33554432)
            self.assertEqual(profile['budgets']['binary_bytes'], 134217728)
            self.assertEqual(caller.fixed_arguments(contract)[-2:], ['--profile', identity])
            self.assertEqual(supervision.child_arguments('/binary', '/ignored', identity),
                             ['/binary', '--exact', supervision.DIRECT_ENTRY, '--ignored', '--nocapture',
                              '--test-threads=1', '--color', 'never', '--format', 'pretty'])
        self.assertIsNone(supervision.fixed_profile(supervision.DIRECT_PROFILE)['shrink'])
        self.assertEqual(supervision.fixed_profile(supervision.NO_FLUSH_PROFILE)['shrink'], {
            'schema': 'northstar-direct-no-flush-shrink-v1', 'attempts': [0, 1, 2, 3],
            'original': 0, 'candidate': 1, 'positive_control': 2, 'reduced': 3})

    def test_versions_profiles_counts_and_artifact_roles_do_not_cross(self):
        contract = synthetic_contract()
        variants = []
        for field, value in (('schema', supervision.CONTRACT_SCHEMA), ('profile', 'custom'),
                             ('profile', supervision.NO_FLUSH_PROFILE), ('plan_counts', supervision.PLAN_COUNTS)):
            bad = copy.deepcopy(contract)
            bad[field] = value
            variants.append(bad)
        for field, value in (('launches', 17), ('case_ms', 30000), ('input_bytes', True)):
            bad = copy.deepcopy(contract)
            bad['budgets'][field] = value
            variants.append(bad)
        bad = copy.deepcopy(contract)
        bad['provenance']['artifact_role'] = 'no-flush'
        variants.append(bad)
        for bad in variants:
            with self.assertRaises(supervision.SupervisionError):
                supervision.validate_contract(bad)

    def test_only_v3_accepts_the_larger_individual_file_bound(self):
        for profile_id, limit in ((supervision.LEGACY_PROFILE, 512), (supervision.DIRECT_PROFILE, 1024)):
            contract = synthetic_contract(profile_id)
            sources = contract['provenance']['source_files']
            for index in range(limit - len(sources)):
                sources[f'synthetic/{index}.rs'] = '8' * 64
            contract['provenance']['source_sha256'] = supervision.object_hash(sources)
            supervision.validate_contract(contract)
            sources['synthetic/overflow.rs'] = '8' * 64
            contract['provenance']['source_sha256'] = supervision.object_hash(sources)
            with self.assertRaisesRegex(supervision.SupervisionError, 'source_scope'):
                supervision.validate_contract(contract)

    def test_literal_plan_and_case_references_are_bound_to_inventory(self):
        contract = synthetic_contract()
        plan = [dict(item, value=None, reason=None, **{'bytes': b'{}'}) for item in contract['case_inventory']]
        supervision.validate_fixture_inventory(plan, contract)
        plan[0]['bytes'] = b'{ }'
        with self.assertRaisesRegex(supervision.SupervisionError, 'fixed_inventory_binding'):
            supervision.validate_fixture_inventory(plan, contract)
        record = synthetic_record(contract)
        supervision.validate_case_record(record, contract, 0, 'C01', 'normal')
        record['input'] = reference('000.input.json', b'{ }')
        with self.assertRaisesRegex(supervision.SupervisionError, 'case_inventory_binding'):
            supervision.validate_case_record(record, contract, 0, 'C01', 'normal')

    def test_incomplete_oracle_stops_caller_and_worker_before_hello(self):
        contract = synthetic_contract()
        with patch.object(supervision, '_check_worker_sources'), patch.object(supervision, '_exchange') as exchange, \
                patch.object(supervision, 'EvidenceStore') as store, self.assertRaises(direct_case.DirectCaseIncomplete):
            supervision.worker_main(object(), supervision.encoded(contract), contract['run_id'], 'record',
                                    supervision.object_hash(contract), 10 ** 12, 128, supervision.DIRECT_PROFILE)
        exchange.assert_not_called()
        store.assert_not_called()
        with patch.object(supervision, '_check_worker_sources'), self.assertRaises(direct_case.DirectCaseIncomplete):
            supervision.direct_preflight(contract)
        with patch.object(caller, 'verify_material'), patch.object(supervision, '_check_worker_sources'), \
                patch.object(caller, 'collect') as collect, self.assertRaises(direct_case.DirectCaseIncomplete):
            caller.run(contract, 'synthetic-invocation')
        collect.assert_not_called()

    def test_worker_bootstrap_profile_must_match_external_contract(self):
        contract = synthetic_contract()
        with patch.object(supervision, '_check_worker_sources') as sources, \
                self.assertRaisesRegex(supervision.SupervisionError, 'external_profile_identity'):
            supervision.worker_main(object(), supervision.encoded(contract), contract['run_id'], 'record',
                                    supervision.object_hash(contract), 10 ** 12, 128)
        sources.assert_not_called()


class DirectFrameTests(unittest.TestCase):
    @staticmethod
    def frame(payload=b'{"fact":1}', before=b'libtest diagnostics\n', after=b'test result\n'):
        return before + supervision.DIRECT_FRAME_TAG + str(len(payload)).encode() + b'\n' + payload + \
            supervision.DIRECT_FRAME_END + after

    def test_one_bounded_frame_preserves_only_its_payload_for_the_dto_reader(self):
        self.assertEqual(supervision.decode_direct_frame(self.frame()), {'fact': 1})
        self.assertEqual(supervision.decode_direct_frame(self.frame(before=b'variable timing 99s\n', after=b'')), {'fact': 1})

    def test_frame_payload_is_utf8_text_without_bom_or_encoding_autodetection(self):
        text = '{"fact":"caf\u00e9"}'
        self.assertEqual(supervision.decode_direct_frame(self.frame(text.encode('utf-8'))), {'fact': 'caf\u00e9'})
        invalid = [b'\xef\xbb\xbf' + text.encode('utf-8')]
        invalid += ['{"fact":1}'.encode(encoding) for encoding in
                    ('utf-16', 'utf-16-le', 'utf-16-be', 'utf-32', 'utf-32-le', 'utf-32-be')]
        for payload in invalid:
            with self.subTest(payload=payload), self.assertRaises(supervision.SupervisionError):
                supervision.decode_direct_frame(self.frame(payload))

    def test_legacy_json_byte_decoder_behavior_is_unchanged(self):
        for payload in (b'\xef\xbb\xbf{"fact":1}', '{"fact":1}'.encode('utf-16')):
            self.assertEqual(supervision.strict_json(payload, 128), {'fact': 1})

    def test_missing_duplicate_truncated_extra_end_and_bad_json_frames_fail(self):
        malformed = [b'running 0 tests\ntest result: ok\n', self.frame() + self.frame(),
                     self.frame(after=b'')[:-1], self.frame() + b'\x1eEND\n',
                     self.frame(b'{"a":1,"a":2}'), self.frame(b'{"a":NaN}'),
                     supervision.DIRECT_FRAME_TAG + b'01\n{}' + supervision.DIRECT_FRAME_END,
                     supervision.DIRECT_FRAME_TAG + b'131073\n{}' + supervision.DIRECT_FRAME_END]
        for raw in malformed:
            with self.subTest(raw=raw[:80]), self.assertRaises(supervision.SupervisionError):
                supervision.decode_direct_frame(raw)

    def test_incomplete_process_never_calls_dto_or_oracle(self):
        controlled = SimpleNamespace(evaluate_fixture=Mock())
        record = synthetic_record(synthetic_contract())
        record['observation'] = 'EnvironmentInterrupted'
        result = supervision.evaluate_fixture(controlled, {}, record, self.frame(), supervision.DIRECT_PROFILE)
        self.assertEqual(result, (None, None, False, 'EnvironmentInterrupted'))
        controlled.evaluate_fixture.assert_not_called()

    def test_direct_rejection_requires_exit_zero_and_empty_complete_streams(self):
        contract = synthetic_contract()
        record = synthetic_record(contract, 13, self.frame(b'{"synthetic_rejection":true}'))
        supervision.validate_case_record(record, contract, 13, 'R01', 'rejection')
        for stream_field in ('stdout', 'stderr'):
            bad = copy.deepcopy(record)
            bad[stream_field]['complete'] = False
            with self.assertRaises(supervision.SupervisionError):
                supervision.validate_case_record(bad, contract, 13, 'R01', 'rejection')
        bad = copy.deepcopy(record)
        bad['process'].update(returncode=2, wait_status=512)
        with self.assertRaises(supervision.SupervisionError):
            supervision.validate_case_record(bad, contract, 13, 'R01', 'rejection')
        bad = copy.deepcopy(record)
        bad['stderr'] = {'reference': reference('013.stderr.bin', b'x'), 'observed_bytes': 1, 'complete': True}
        with self.assertRaises(supervision.SupervisionError):
            supervision.validate_case_record(bad, contract, 13, 'R01', 'rejection')


class DirectOwnerTests(unittest.TestCase):
    def hello(self, profile_id):
        state = supervision.OwnerProtocol('synthetic', 'record', '1' * 64, 0, profile_id)
        hello = {'type': 'Hello', 'run_id': 'synthetic', 'index': -1, 'role': 'worker',
                 'contract_sha256': '1' * 64, 'total': state.counts['total'],
                 'prefix': reference('prefix-000.json'), 'profile': profile_id}
        return state, hello

    def test_hello_requires_profile_count_and_begin_uses_its_kinds_and_deadline(self):
        state, hello = self.hello(supervision.DIRECT_PROFILE)
        for key, value in (('profile', supervision.NO_FLUSH_PROFILE), ('total', 82), ('total', True)):
            bad = dict(hello, **{key: value})
            with self.assertRaises(supervision.SupervisionError):
                state.accept(bad, [], 1)
        state.accept(hello, [], 1)
        state.completed = 13
        begin = {'type': 'Begin', 'run_id': 'synthetic', 'index': 13, 'role': 'worker', 'id': 'R01', 'kind': 'normal'}
        with self.assertRaises(supervision.SupervisionError):
            state.accept(begin, [], 100)
        begin['kind'] = 'rejection'
        state.accept(begin, [], 100)
        self.assertEqual(state.case_deadline, 5_000_000_100)

    def test_fixed16_done_needs_no_shrink_tail_and_fixed4_stops_at_four(self):
        for identity, count in ((supervision.DIRECT_PROFILE, 16), (supervision.NO_FLUSH_PROFILE, 4)):
            state, hello = self.hello(identity)
            state.accept(hello, [], 1)
            state.completed = state.matched = state.launches = count
            state.prefix = reference(f'prefix-{count:03d}.json')
            done = {'type': 'Done', 'run_id': 'synthetic', 'index': count, 'role': 'worker', 'complete': True,
                    'prefix': state.prefix, 'terminal': reference('corpus.json')}
            state.accept(done, [], 2)
            self.assertTrue(state.declared_complete)
            with self.assertRaises(supervision.SupervisionError):
                supervision.validate_prefix_reference(reference(f'prefix-{count + 1:03d}.json'), count + 1, identity)

    def test_caller_completion_uses_selected_total_and_profile_mechanism(self):
        for identity in (supervision.DIRECT_PROFILE, supervision.NO_FLUSH_PROFILE):
            contract = synthetic_contract(identity)
            capture, evidence = synthetic_capture(contract)
            self.assertTrue(supervision.validate_owner_capture(capture, contract, caller_evidence=evidence)['FixtureMatched'])
            capture['receipt']['completed'] = 82
            with self.assertRaises(supervision.SupervisionError):
                supervision.validate_owner_capture(capture, contract, caller_evidence=evidence)


class DirectInputDescriptorTests(unittest.TestCase):
    def test_hashes_and_rewinds_same_descriptor_and_closes_failures(self):
        contract = synthetic_contract()
        identity = (1, 2, stat.S_IFREG | 0o400, 1000, 1000, 2, 10, 10)
        with patch.object(supervision.os, 'open', return_value=21) as opened, \
                patch.object(supervision, '_input_identity', return_value=identity), \
                patch.object(supervision.os, 'read', side_effect=[b'{}', b'']) as read, \
                patch.object(supervision.os, 'lseek', return_value=0) as rewind, \
                patch.object(supervision.os, 'close') as close:
            self.assertEqual(supervision._verified_input(contract, '/synthetic/input', reference('input.json', b'{}')), 21)
        self.assertEqual([call.args[0] for call in read.call_args_list], [21, 21])
        self.assertTrue(opened.call_args.args[1] & supervision.os.O_NOFOLLOW)
        rewind.assert_called_once_with(21, 0, supervision.os.SEEK_SET)
        close.assert_not_called()
        with patch.object(supervision.os, 'open', return_value=21), \
                patch.object(supervision, '_input_identity', return_value=identity), \
                patch.object(supervision.os, 'read', side_effect=[b'[]', b'']), \
                patch.object(supervision.os, 'lseek') as rewind, patch.object(supervision.os, 'close') as close, \
                self.assertRaises(supervision.SupervisionError):
            supervision._verified_input(contract, '/synthetic/input', reference('input.json', b'{}'))
        rewind.assert_not_called()
        close.assert_called_once_with(21)

    def test_missing_descriptor_fails_before_pipe_or_launch(self):
        with patch.object(supervision.os, 'pipe2') as pipes, patch.object(supervision, '_exchange') as exchange, \
                self.assertRaises(supervision.SupervisionError):
            supervision.capture_child(object(), synthetic_contract(), 0, Path('/synthetic/input'), 21, 1000, 128)
        pipes.assert_not_called()
        exchange.assert_not_called()

    def test_stage3_keeps_input_through_gate_then_dups_it_to_stdin(self):
        calls = []
        with patch.object(supervision, '_parent_death'), patch.object(supervision, '_limits'), \
                patch.object(supervision.resource, 'setrlimit'), \
                patch.object(supervision, '_close_except', side_effect=lambda keep, _: calls.append(('keep', keep))), \
                patch.object(supervision.os, 'write', return_value=1), \
                patch.object(supervision.os, 'read', side_effect=lambda *_: calls.append(('gate',)) or b'G'), \
                patch.object(supervision.os, 'getppid', return_value=42), patch.object(supervision.os, 'close'), \
                patch.object(supervision.os, 'dup2', side_effect=lambda source, target: calls.append(('dup', source, target))), \
                patch.object(supervision.os, '_exit', side_effect=AssertionError('unexpected bootstrap exit')), \
                patch.object(supervision.os, 'execve') as execute:
            supervision._child_bootstrap(42, 128, 10, 11, 12, 13, '/binary', 21, '/input', supervision.DIRECT_PROFILE, 22)
        self.assertIn(22, calls[0][1])
        self.assertLess(calls.index(('gate',)), calls.index(('dup', 22, 0)))
        execute.assert_called_once_with(21, supervision.child_arguments('/binary', '/input', supervision.DIRECT_PROFILE),
                                        {'LANG': 'C', 'LC_ALL': 'C'})


class DirectReplayAuthorityTests(unittest.TestCase):
    def saved_metadata(self, profile_id=supervision.DIRECT_PROFILE):
        prior = synthetic_contract(profile_id)
        profile = supervision.contract_profile(prior)
        capture, caller_evidence = synthetic_capture(prior)
        cases = [{'index': index, 'id': item['id'], 'kind': item['kind'],
                  'observation': reference(f'{index:03d}.observation.json'),
                  'result': reference(f'{index:03d}.result.json'), 'fixture_status': 'FixtureMatched'}
                 for index, item in enumerate(prior['case_inventory'])]
        manifest = {'schema': profile['corpus_schema'], 'contract_sha256': supervision.object_hash(prior),
                    'cases': cases, 'shrink': profile['shrink'], 'first_invariant': None,
                    'first_unexpected_stop': None, 'complete': True}
        prefix = supervision._prefix(prior, cases, None, None)
        current = copy.deepcopy(prior)
        current.update(mode='replay', run_id='synthetic-replay', evidence_dir='/synthetic/replay', replay_dir=prior['evidence_dir'])
        current['replay_authority'] = {
            'prior_contract_file_sha256': supervision.fingerprint(supervision.encoded(prior)),
            'capture': capture, 'caller_evidence': caller_evidence,
        }
        files = {'contract.json': supervision.encoded(prior), 'caller-capture.json': supervision.encoded(capture),
                 'corpus.json': supervision.encoded(manifest), capture['receipt']['prefix']['file']: supervision.encoded(prefix)}
        return current, prior, manifest, files

    def read_saved(self, current, files):
        with patch.object(supervision, 'read_regular_bounded', side_effect=lambda path, _: files[Path(path).name]), \
                patch.object(supervision, 'read_bounded', side_effect=lambda path, _: files[Path(path).name]), \
                patch.object(supervision, 'read_reference', side_effect=lambda _directory, ref, _: files[ref['file']]):
            return supervision.replay_source(current['replay_dir'], current)

    def test_full_positive_metadata_controls_cover_no_shrink_and_exact_four_roles(self):
        for identity in (supervision.DIRECT_PROFILE, supervision.NO_FLUSH_PROFILE):
            current, prior, manifest, files = self.saved_metadata(identity)
            supervision.validate_contract(current)
            self.assertEqual(self.read_saved(current, files), (prior, manifest))
            self.assertNotEqual(current['replay_authority']['prior_contract_file_sha256'], supervision.object_hash(prior))
            manifest['shrink'] = supervision.fixed_profile()['shrink']
            files['corpus.json'] = supervision.encoded(manifest)
            with self.assertRaises(supervision.SupervisionError):
                self.read_saved(current, files)

    def test_prior_hash_is_checked_before_parsing_or_trusting_prior_fields(self):
        current, _prior, _manifest, files = self.saved_metadata()
        files['contract.json'] = b'not-json'
        with patch.object(supervision, 'strict_json') as parse, \
                self.assertRaisesRegex(supervision.SupervisionError, 'external_prior_contract_hash'):
            self.read_saved(current, files)
        parse.assert_not_called()

    def test_rehashed_noncanonical_and_wrong_profile_contracts_fail(self):
        current, prior, _manifest, files = self.saved_metadata()
        files['contract.json'] = supervision.canonical(prior).encode()  # Missing canonical LF.
        current['replay_authority']['prior_contract_file_sha256'] = supervision.fingerprint(files['contract.json'])
        with self.assertRaisesRegex(supervision.SupervisionError, 'noncanonical_prior_contract'):
            self.read_saved(current, files)
        prior = synthetic_contract(supervision.NO_FLUSH_PROFILE)
        files['contract.json'] = supervision.encoded(prior)
        current['replay_authority']['prior_contract_file_sha256'] = supervision.fingerprint(files['contract.json'])
        with self.assertRaisesRegex(supervision.SupervisionError, 'replay_profile_inventory'):
            self.read_saved(current, files)


class DirectPriorAggregateTests(unittest.TestCase):
    def aggregate(self, *, first_index=0, relation_error=None):
        contract = synthetic_contract(supervision.NO_FLUSH_PROFILE)
        plan = [dict(item, value={'synthetic_id': item['id']}) for item in contract['case_inventory']]
        evaluations = [{'invariant': {'class': 'Safety'}} if index != 2 else {'invariant': None}
                       for index in range(4)]
        entries = [{'observation': reference(f'{index:03d}.observation.json'),
                    'result': reference(f'{index:03d}.result.json')} for index in range(4)]
        manifest = {'cases': entries, 'first_invariant': {
            'index': first_index, 'evaluation': reference(f'{first_index:03d}.evaluation.json'), 'class': 'Safety'}}
        result = {'schema': supervision.fixed_profile(supervision.NO_FLUSH_PROFILE)['result_schema'],
                  'run_id': contract['run_id'], 'contract_sha256': supervision.object_hash(contract),
                  'index': 0, 'id': 'M1', 'kind': 'shrink', 'observation': entries[0]['observation'],
                  'observation_loss': None, 'evaluation': reference('000.evaluation.json'),
                  'fixture_status': 'FixtureMatched', 'stop': None, 'stop_kind': None, 'interruption_kind': None}
        controlled = SimpleNamespace(shrink_relations=Mock(side_effect=relation_error))
        with patch.object(supervision, 'verify_prior_case', side_effect=[({}, value) for value in evaluations]) as verify, \
                patch.object(supervision, 'read_reference', return_value=supervision.encoded(result)):
            supervision.validate_direct_prior(controlled, '/synthetic/record', (contract, manifest), plan)
        return controlled, verify

    def test_all_saved_cases_and_exact_prior_shrink_relation_are_rechecked(self):
        controlled, verify = self.aggregate()
        self.assertEqual(verify.call_count, 4)
        controlled.shrink_relations.assert_called_once()
        self.assertEqual(len(controlled.shrink_relations.call_args.args[0]), 4)

    def test_false_first_invariant_and_bad_prior_shrink_relation_stop_preflight(self):
        with self.assertRaisesRegex(supervision.SupervisionError, 'saved_first_invariant_changed'):
            self.aggregate(first_index=3)
        with self.assertRaisesRegex(ValueError, 'synthetic wrong shrink target'):
            self.aggregate(relation_error=ValueError('synthetic wrong shrink target'))


class DirectInventoryTests(unittest.TestCase):
    class Entries(list):
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

    def tree(self):
        return {'src': {'main.rs': stat.S_IFREG}, 'migrations': {'001.sql': stat.S_IFREG}}

    def check(self, tree, source_keys=None):
        contract = synthetic_contract()
        keys = source_keys or {'src/main.rs', 'migrations/001.sql', 'Cargo.toml'}
        contract['provenance']['source_files'] = dict.fromkeys(keys, '1' * 64)
        visited = []
        def scan(path):
            relative = str(Path(path).relative_to(contract['root']))
            visited.append(relative)
            return self.Entries(SimpleNamespace(name=name, stat=lambda *, follow_symlinks, kind=kind:
                                                SimpleNamespace(st_mode=kind))
                                for name, kind in tree[relative].items())
        def metadata(path, *, missing_ok=False):
            relative = str(Path(path).relative_to(contract['root']))
            if relative in ('build.rs',):
                return None
            return SimpleNamespace(st_mode=stat.S_IFDIR if relative in tree else stat.S_IFREG)
        with patch.object(supervision, 'DIRECT_SOURCE_ROOTS', ('src',)), \
                patch.object(supervision, 'DIRECT_FIXED_FILES', frozenset({'Cargo.toml'})), \
                patch.object(supervision, 'DIRECT_BUILD_ABSENCES', ('build.rs',)), \
                patch.object(supervision, 'check_direct_import_layout'), \
                patch.object(supervision, '_path_metadata', side_effect=metadata), \
                patch.object(supervision.os, 'scandir', side_effect=scan):
            supervision.check_direct_inventory(contract)
        return visited

    def test_audited_root_and_manifest_counts_are_source_fixed(self):
        self.assertEqual(len(supervision.DIRECT_SOURCE_ROOTS), 51)
        self.assertEqual(len(supervision.DIRECT_MANIFEST_FILES), 82)
        self.assertEqual(len(supervision.DIRECT_EMBEDDED_FILES), 8)
        self.assertEqual(len(supervision.DIRECT_BUILD_ABSENCES), 55)

    def test_exact_membership_rejects_added_missing_nonregular_and_omitted_inputs(self):
        self.assertEqual(self.check(self.tree()), ['src', 'migrations'])
        for root, name, kind in (('src', 'untracked.rs', stat.S_IFREG),
                                 ('src', 'unexpected_directory', stat.S_IFDIR),
                                 ('migrations', 'unrecognized.backup', stat.S_IFREG),
                                 ('migrations', 'new_directory', stat.S_IFDIR)):
            tree = self.tree()
            tree[root][name] = kind
            with self.subTest(root=root, name=name), self.assertRaises(supervision.SupervisionError):
                self.check(tree)
        tree = self.tree()
        tree['src']['main.rs'] = stat.S_IFLNK
        with self.assertRaises(supervision.SupervisionError):
            self.check(tree)
        tree = self.tree()
        del tree['migrations']['001.sql']
        with self.assertRaises(supervision.SupervisionError):
            self.check(tree)
        with self.assertRaises(supervision.SupervisionError):
            self.check(self.tree(), {'migrations/001.sql', 'Cargo.toml'})
        with self.assertRaisesRegex(supervision.SupervisionError, 'fixed_source_inventory_equality'):
            self.check(self.tree(), {'src/main.rs', 'migrations/001.sql', 'Cargo.toml', 'outside.rs'})

    def test_import_shadow_cache_and_native_alternatives_fail_before_import(self):
        root = Path('/synthetic/root')
        directories = {'scripts', 'scripts/lib'}
        absent_names = ('scripts/lib.py', 'scripts/lib.pyc', 'scripts/lib/__init__.py',
                        'scripts/lib/__init__.pyc', 'scripts/lib/__pycache__',
                        'scripts/lib/direct_case', 'scripts/lib/direct_case.pyc',
                        'scripts/xml', 'scripts/xml.py', 'scripts/xml.pyc',
                        'scripts/_elementtree', 'scripts/_elementtree.py', 'scripts/_elementtree.pyc',
                        'scripts/pyexpat', 'scripts/pyexpat.py', 'scripts/pyexpat.pyc',
                        'scripts/contextlib', 'scripts/contextlib.py', 'scripts/contextlib.pyc')
        def metadata(path, *, missing_ok=False):
            name = str(Path(path).relative_to(root))
            if missing_ok:
                return None
            return SimpleNamespace(st_mode=stat.S_IFDIR if name in directories else stat.S_IFREG)
        with patch.object(supervision, '_path_metadata', side_effect=metadata), \
                patch.object(supervision.os, 'scandir', return_value=self.Entries()):
            supervision.check_direct_import_layout(root)
        for injected in absent_names:
            def injected_metadata(path, *, missing_ok=False):
                if str(Path(path).relative_to(root)) == injected:
                    return SimpleNamespace(st_mode=stat.S_IFREG)
                return metadata(path, missing_ok=missing_ok)
            with self.subTest(injected=injected), \
                    patch.object(supervision, '_path_metadata', side_effect=injected_metadata), \
                    self.assertRaisesRegex(supervision.SupervisionError, 'helper_import_alternative'):
                supervision.check_direct_import_layout(root)
        with patch.object(supervision, '_path_metadata', side_effect=metadata), \
                patch.object(supervision.os, 'scandir', return_value=self.Entries([SimpleNamespace(name='lib.abi3.so')])), \
                self.assertRaisesRegex(supervision.SupervisionError, 'helper_native_import_alternative'):
            supervision.check_direct_import_layout(root)
        for stem in supervision.DIRECT_PARSER_IMPORTS:
            with self.subTest(parser_stem=stem), patch.object(supervision, '_path_metadata', side_effect=metadata), \
                    patch.object(supervision.os, 'scandir', return_value=self.Entries([SimpleNamespace(name=stem + '.abi3.so')])), \
                    self.assertRaisesRegex(supervision.SupervisionError, 'helper_native_import_alternative'):
                supervision.check_direct_import_layout(root)


class NativeLiteralAndLedgerTests(unittest.TestCase):
    def fixtures(self):
        return {item['id']: item for item in direct_case.native_fixtures()}

    def test_ten_native_literals_have_exact_ids_outcomes_and_rejection_reasons(self):
        fixtures = self.fixtures()
        self.assertEqual(list(fixtures), ['C01', 'C02', 'C03', 'C04', 'C05', 'C06', 'C07', 'R01', 'R02', 'R03'])
        for identity, fixture in fixtures.items():
            self.assertLessEqual(len(fixture['bytes']), 65536)
            if identity.startswith('C'):
                self.assertEqual(direct_case.parse_native_input(fixture['bytes']), fixture['value'])
                self.assertEqual(fixture['expected_verdict'], 'Cancelled' if identity in ('C02', 'C05', 'C06') else 'Pass')
            else:
                self.assertEqual(direct_case.rejection_reason(fixture['bytes']), fixture['reason'])
        self.assertEqual([fixtures[name]['reason'] for name in ('R01', 'R02', 'R03')],
                         ['DuplicateKey', 'UnknownField', 'IdentityBinding'])

    def test_uuid_literals_and_validator_have_exact_canonical_spelling(self):
        self.assertEqual(direct_case._uuid(101), '00000000-0000-0000-0000-000000000065')
        self.assertEqual(direct_case._uuid(20101), '00000000-0000-0000-0000-000000004e85')
        direct_case._id('00000000-0000-0000-0000-000000004e85')
        for invalid in ('00000000000000000000000000004e85', '00000000-0000-0000-0000-000000004E85',
                        '00000000-0000-0000-0000-000000004e8g', 101):
            with self.assertRaises(direct_case.DirectCaseInvalid):
                direct_case._id(invalid)

    def test_fixed_mutation_deletes_only_prefix_and_keeps_exact_target(self):
        original = self.fixtures()['C07']
        m1, m2, m3, m4 = direct_case.mutation_fixtures()
        self.assertEqual(m1['bytes'], original['bytes'])
        self.assertEqual(m2['bytes'], m4['bytes'])
        expected = copy.deepcopy(original['value'])
        expected['identities']['originals'].pop(0)
        for field in ('originals', 'policy', 'admission', 'direct_repository', 'route'):
            expected[field].pop(0)
        self.assertEqual(m2['value'], expected)
        expected['recipient_owner']['native']['write']['fail_after_accepted_bytes'] = 1
        self.assertEqual(m3['value'], expected)
        self.assertEqual([item['expected_verdict'] for item in (m1, m2, m3, m4)],
                         ['InvariantViolation', 'InvariantViolation', 'Pass', 'InvariantViolation'])
        for item in (m1, m2, m3, m4):
            value = direct_case.parse_native_input(item['bytes'])
            self.assertEqual(value['recipient_owner']['frame_id'], direct_case._uuid(702))
            self.assertEqual(value['recipient_owner']['native']['fence']['returned_source'],
                             direct_case._c2s(direct_case._uuid(20702), direct_case._uuid(6)))

    def test_health_remote_and_unused_role_literals_match_consumed_branches(self):
        fixtures = self.fixtures()
        for fixture in list(fixtures.values())[:7]:
            for original, policy in zip(fixture['value']['originals'], fixture['value']['policy']):
                self.assertEqual(policy['degraded_spool_eligible'], '/' not in original['target'])
        for name, slot, expected in (('C01', 0, 3), ('C02', 0, 3), ('C06', 0, 2), ('C07', 1, 3)):
            self.assertEqual(fixtures[name]['value']['route'][slot]['health_modes'], ['Live'] * expected)
        self.assertEqual(fixtures['C06']['value']['route'][0]['remote_primary_returns'], [False])
        for name in ('C03', 'C04', 'C05'):
            self.assertIsNone(fixtures[name]['value']['identities']['connection_id'])
            self.assertTrue(all(not item['health_modes'] for item in fixtures[name]['value']['route']))
        self.assertEqual(fixtures['C07']['value']['route'][0]['health_modes'], [])

    def test_c01_xml_ledger_matches_independent_literal_tree_and_archive_roles(self):
        ledger = direct_case.derive_native_ledger(self.fixtures()['C01']['value'])
        original = ledger['originals'][0]
        expected_live = (
            '<message xmlns="jabber:client" from="alice@example.test/device" type="chat" id="m" to="bob@example.test/phone">'
            '<body>x</body><origin-id xmlns="urn:xmpp:sid:0" id="o"/>'
            '<stanza-id xmlns="urn:xmpp:sid:0" id="00000000-0000-0000-0000-000000004e85" '
            'by="bob@example.test"/></message>')
        self.assertEqual(original['projection']['live_xml'], direct_case._tree(direct_case._xml(expected_live, projected=True)))
        stored = original['projection']['stored_xml']
        self.assertEqual(stored[3][-1][0], '{urn:xmpp:delay}delay')
        self.assertEqual(dict(stored[3][-1][1]), {'from': 'example.test', 'stamp': '1970-01-01T00:01:40Z'})
        self.assertEqual([item['peer_jid'] for item in original['projection']['archives']],
                         ['bob@example.test/phone', 'alice@example.test/device'])
        self.assertEqual([item['owner_id'] for item in original['projection']['archives']],
                         [direct_case._uuid(1), direct_case._uuid(2)])
        self.assertTrue(original['prepared']['mam_backed'])
        self.assertEqual(original['prepared']['eligibility'], 'LiveOnly')
        self.assertEqual(original['prepared']['identity']['actor_scope'], 'alice@example.test')
        self.assertIsNone(original['source']['claim_id'])
        self.assertEqual(ledger['native']['fenced_source']['claim_id'], direct_case._uuid(6))

    def test_projected_xml_requires_actual_client_namespace(self):
        original = self.fixtures()['C01']['value']['originals'][0]['xml']
        self.assertEqual(direct_case._xml(original).tag, 'message')
        qualified = '<message xmlns="jabber:client"><body>x</body><origin-id xmlns="urn:xmpp:sid:0" id="o"/></message>'
        actual = direct_case._xml(qualified, projected=True)
        self.assertEqual(actual.tag, '{jabber:client}message')
        self.assertEqual(actual[0].tag, '{jabber:client}body')
        self.assertEqual(actual[1].tag, '{urn:xmpp:sid:0}origin-id')
        for bad in (qualified.replace(' xmlns="jabber:client"', ''), qualified.replace('jabber:client', 'urn:wrong')):
            with self.assertRaisesRegex(direct_case.DirectCaseInvalid, 'projected_message_namespace'):
                direct_case._xml(bad, projected=True)

    def test_namespace_ledger_preserves_children_sid_hints_and_delay(self):
        originals = direct_case.derive_native_ledger(self.fixtures()['C07']['value'])['originals']
        self.assertEqual(originals[0]['projection']['live_xml'][0], '{jabber:client}message')
        self.assertEqual(originals[0]['projection']['live_xml'][3][0][0], '{urn:xmpp:hints}store')
        target = originals[1]['projection']
        self.assertEqual(target['live_xml'][3][0][0], '{jabber:client}body')
        self.assertEqual(target['live_xml'][3][1][0], '{urn:xmpp:sid:0}origin-id')
        self.assertEqual(target['live_xml'][3][2][0], '{urn:xmpp:sid:0}stanza-id')
        self.assertEqual(target['stored_xml'][3][-1][0], '{urn:xmpp:delay}delay')
        qualified = '<message xmlns="jabber:client"><body>x</body></message>'
        reset = '<message xmlns="jabber:client"><body xmlns="">x</body></message>'
        self.assertNotEqual(direct_case._tree(direct_case._xml(qualified, projected=True)),
                            direct_case._tree(direct_case._xml(reset, projected=True)))
        outside = copy.deepcopy(self.fixtures()['C01']['value'])
        outside['originals'][0]['xml'] = outside['originals'][0]['xml'].replace('<body>', '<body xmlns = "">')
        with self.assertRaisesRegex(direct_case.DirectCaseIncomplete, 'namespace_reset_outside_fixed_literal_subset'):
            direct_case.derive_native_ledger(outside)

    def test_ledger_separates_transactions_modes_unknowns_and_unrated_prefix(self):
        fixtures = self.fixtures()
        c02 = direct_case.derive_native_ledger(fixtures['C02']['value'])
        self.assertEqual(c02['originals'][0]['finalize']['commit'], 'Error')
        self.assertEqual(c02['native']['ack']['commit'], 'Pending')
        self.assertEqual(c02['originals'][0]['terminal'], 'Completed')
        first, second = direct_case.derive_native_ledger(fixtures['C03']['value'])['originals']
        self.assertEqual((first['prepared']['eligibility'], second['prepared']['eligibility']), ('Eligible', 'Eligible'))
        self.assertEqual((first['direct']['admitted_mode'], first['direct']['returned_mode'], first['route_action']),
                         ('SpoolOnly', 'SpoolOnly', 'None'))
        self.assertEqual((second['direct']['admitted_mode'], second['direct']['returned_mode'], second['route_action']),
                         ('Live', 'SpoolOnly', 'Rearm'))
        c04 = direct_case.derive_native_ledger(fixtures['C04']['value'])['originals'][0]
        self.assertIsNone(c04['direct']['returned_mode'])
        self.assertEqual(c04['direct']['preserved_transaction']['kind'], 'Stored')
        c05 = direct_case.derive_native_ledger(fixtures['C05']['value'])['originals'][0]
        self.assertIsNone(c05['finalize'])
        self.assertEqual(c05['terminal'], 'Cancelled')
        unrated = direct_case.derive_native_ledger(fixtures['C07']['value'])['originals'][0]
        self.assertIsNone(unrated['begin'])
        self.assertIsNone(unrated['finalize'])
        self.assertIsNone(unrated['prepared']['identity'])
        self.assertFalse(unrated['projection']['rated'])
        self.assertEqual(unrated['route_action'], 'None')

    def test_ledger_depends_on_input_semantics_not_case_name_or_output(self):
        value = self.fixtures()['C01']['value']
        expected = direct_case.derive_native_ledger(value)
        renamed = copy.deepcopy(value)
        renamed['case_id'] = 'some-other-label'
        self.assertEqual(direct_case.derive_native_ledger(renamed), expected)
        changed = copy.deepcopy(value)
        changed['originals'][0]['xml'] = changed['originals'][0]['xml'].replace('>x<', '>different body<')
        self.assertNotEqual(direct_case.derive_native_ledger(changed)['originals'][0]['projection'],
                            expected['originals'][0]['projection'])
        with self.assertRaises(direct_case.DirectCaseIncomplete):
            direct_case.fixture_plan(supervision.DIRECT_PROFILE)


class NativeEvidenceAndSafetyTests(unittest.TestCase):
    def synthetic(self, *, flush=True, accepted=None, ack=True):
        """Isolated synthetic facts, never an expected full Rust transcript."""
        value = direct_case.mutation_fixtures()[1]['value']
        native_input = value['recipient_owner']['native']
        frame = value['recipient_owner']['frame_id']
        source = copy.deepcopy(native_input['fence']['returned_source'])
        original_source = direct_case._c2s(direct_case._uuid(20702), direct_case._uuid(20702))
        raw = value['originals'][0]['xml'].encode('utf-8')
        retained = raw if accepted is None else raw[:accepted]
        counter = 0
        def seq():
            nonlocal counter
            counter += 1
            return counter
        original_state = {'begin': None, 'finalize': None, 'direct': None, 'handoff': None, 'terminal': 'Completed'}
        original = {'frame_id': frame, 'projection': None, 'prepared': None, 'begin': None, 'finalize': None,
                    'direct': None, 'continuation': None, 'terminal': 'Completed',
                    'prefixes': [{'seq': seq(), 'state': original_state}], 'polls': [{'seq': seq(), 'result': 'Ready'}],
                    'route': {'health_reads': [], 'enqueue': [],
                              'dequeued': [{'seq': seq(), 'source': original_source, 'xml': raw.decode('utf-8')}],
                              'queue_remaining': [], 'backpressure_disconnected': False,
                              'remote_calls': [], 'rearm_calls': [], 'handoff': None}}
        prepared = {'original': original_source, 'preparation': 'Prepared', 'managed_by_sm': False,
                    'fence_entered': True, 'returned_fence': source, 'writer_entered': False,
                    'writer_result': None, 'write_decision': None, 'ack': {'kind': 'NotRequested'},
                    'ack_returned': None, 'terminal': None}
        native = {'frame_id': frame, 'connection_id': native_input['connection_id'], **copy.deepcopy(prepared),
                  'prefixes': [{'seq': seq(), 'state': copy.deepcopy(prepared)}],
                  'write_calls': [{'seq': seq(), 'offered_len': len(raw), 'offered_sha256': direct_case._hash(raw),
                                   'accepted_bytes_hex': retained.hex(), 'result': 'Accepted'}],
                  'flush_calls': [], 'ack_calls': [], 'ownership_receipts': [], 'write_receipts': [], 'polls': []}
        if flush:
            native['flush_calls'].append({'seq': seq(), 'result': 'Ok'})
        native.update(writer_entered=True, writer_result='FullWrite', write_decision='Written')
        native['prefixes'].append({'seq': seq(), 'state': {name: copy.deepcopy(native[name])
                                                        for name in direct_case.NATIVE_STATE_FIELDS.split()}})
        if ack:
            native['ack_calls'].append({'seq': seq(), 'source': source, 'returned': True})
            native.update(ack={'kind': 'ReceiptKnown', 'fact': {'source': source, 'disposition': 'Deleted'}}, ack_returned=True)
        native['terminal'] = 'Returned'
        native['prefixes'].append({'seq': seq(), 'state': {name: copy.deepcopy(native[name])
                                                        for name in direct_case.NATIVE_STATE_FIELDS.split()}})
        native['polls'].append({'seq': seq(), 'result': 'Ready'})
        payload = {'schema': direct_case.EVIDENCE_SCHEMA, 'entry': direct_case.ENTRY,
                   'input_sha256': direct_case._hash(direct_case._encoded(value)), 'rejection': None,
                   'execution': 'Complete', 'originals': [original], 'recipient': {'kind': 'Native', 'native': native}}
        return value, payload

    def test_valid_synthetic_utf8_dto_is_closed_and_true_unsafe_facts_remain_decodable(self):
        value, payload = self.synthetic(flush=False)
        self.assertEqual(direct_case.validate_native_evidence(payload), payload)
        violations = direct_case.native_safety_findings(value, payload)
        self.assertEqual([item['id'] for item in violations], ['NativeAckWithoutSuccessfulFlush'])
        self.assertEqual(violations[0]['class'], 'Safety')
        self.assertEqual(violations[0]['target'], {'frame_id': direct_case._uuid(702),
                         'connection_id': direct_case._uuid(3), 'owner': 'Tcp', 'purpose': 'NativeSettlement',
                         'source': direct_case._c2s(direct_case._uuid(20702), direct_case._uuid(6))})

    def test_complete_write_with_prior_flush_and_short_write_without_ack_controls(self):
        value, payload = self.synthetic()
        self.assertEqual(direct_case.native_safety_findings(value, payload), [])
        value, payload = self.synthetic(flush=False, accepted=1, ack=False)
        payload['recipient']['native']['writer_result'] = 'Failed'
        payload['recipient']['native']['write_decision'] = 'Withhold'
        self.assertEqual(direct_case.native_safety_findings(value, payload), [])

    def test_missing_bytes_wrong_offered_hash_and_wrong_source_cannot_satisfy_ack(self):
        value, payload = self.synthetic(accepted=1)
        self.assertIn('NativeAckWithoutCompleteWrite', [item['id'] for item in direct_case.native_safety_findings(value, payload)])
        value, payload = self.synthetic()
        payload['recipient']['native']['write_calls'][0]['offered_sha256'] = '0' * 64
        self.assertIn('NativeAckWithoutCompleteWrite', [item['id'] for item in direct_case.native_safety_findings(value, payload)])
        value, payload = self.synthetic()
        payload['recipient']['native']['ack_calls'][0]['source'] = direct_case._c2s(direct_case._uuid(20702), direct_case._uuid(10))
        direct_case.validate_native_evidence(payload)
        self.assertIn('NativeAckWithoutMatchingFence', [item['id'] for item in direct_case.native_safety_findings(value, payload)])

    def test_flush_before_last_write_does_not_flush_the_dequeued_bytes(self):
        value, payload = self.synthetic()
        native = payload['recipient']['native']
        native['write_calls'][0]['seq'], native['flush_calls'][0]['seq'] = (
            native['flush_calls'][0]['seq'], native['write_calls'][0]['seq'])
        self.assertIn('NativeAckWithoutSuccessfulFlush', [item['id'] for item in direct_case.native_safety_findings(value, payload)])

    def test_dto_rejects_bool_float_unknown_missing_and_duplicate_sequence(self):
        _value, payload = self.synthetic()
        variants = []
        for bad_number in (True, 1.0):
            bad = copy.deepcopy(payload)
            bad['recipient']['native']['write_calls'][0]['offered_len'] = bad_number
            variants.append(bad)
        bad = copy.deepcopy(payload)
        bad['recipient']['native']['ack']['extra'] = True
        variants.append(bad)
        bad = copy.deepcopy(payload)
        del bad['recipient']['native']['ack_returned']
        variants.append(bad)
        bad = copy.deepcopy(payload)
        bad['recipient']['native']['ack_calls'][0]['seq'] = 1
        variants.append(bad)
        for bad in variants:
            with self.assertRaises(direct_case.DirectCaseInvalid):
                direct_case.validate_native_evidence(bad)

    def test_no_fixture_qualification_is_available_from_partial_predicates(self):
        value, payload = self.synthetic(flush=False)
        with self.assertRaises(direct_case.DirectCaseIncomplete):
            direct_case.evaluate_fixture({'value': value}, {}, payload, supervision.NO_FLUSH_PROFILE)
        with self.assertRaises(direct_case.DirectCaseIncomplete):
            direct_case.require_implemented()


class NativeFullMatcherTests(unittest.TestCase):
    @staticmethod
    def complete_record():
        return {'observation': 'Complete', 'process': {'returncode': 0}}

    def fixture(self, identity):
        values = direct_case.mutation_fixtures() if identity.startswith('M') else direct_case.native_fixtures()
        return next(item for item in values if item['id'] == identity)

    def supplied_facts(self, fixture, *, omit_flush=False, sender_cut=None, original_index=0, start_seq=0):
        """Hand-authored fixed-literal facts, independent of oracle predictions.

        Identifier and controlled-response constants come from the literal input;
        no derive/expected/evaluation helper builds these supplied observations.
        """
        value = fixture['value']
        original_input = value['originals'][original_index]
        roles, policy = value['identities'], value['policy'][original_index]
        identity = roles['originals'][original_index]
        frame = identity['frame_id']
        counter = start_seq
        def seq():
            nonlocal counter
            counter += 1
            return counter
        def correlation(effect):
            return {'operation_id': frame, 'effect': effect, 'generation': 0, 'attempt': 1}
        literal = original_input['xml']
        unrated = literal == "<message to='bob@example.test'><store xmlns='urn:xmpp:hints'/></message>"
        literals = {
            "<message type='chat' id='m' to='bob@example.test/phone'><body>x</body><origin-id xmlns='urn:xmpp:sid:0' id='o'/></message>": ('m', 'x', 'o'),
            "<message type='chat' id='m' to='bob@example.test'><body>x</body><origin-id xmlns='urn:xmpp:sid:0' id='o'/></message>": ('m', 'x', 'o'),
            "<message type='chat' id='m-c03-a' to='bob@example.test'><body>x-a</body><origin-id xmlns='urn:xmpp:sid:0' id='o-c03-a'/></message>": ('m-c03-a', 'x-a', 'o-c03-a'),
            "<message type='chat' id='m-c03-b' to='bob@example.test'><body>x-b</body><origin-id xmlns='urn:xmpp:sid:0' id='o-c03-b'/></message>": ('m-c03-b', 'x-b', 'o-c03-b'),
        }
        if unrated:
            stanza_id = origin_id = None
            attributes = ''
            content = '<store xmlns="urn:xmpp:hints"/>'
        else:
            stanza_id, body, origin_id = literals[literal]
            attributes = ' type="chat" id="' + stanza_id + '"'
            content = '<body>' + body + '</body><origin-id xmlns="urn:xmpp:sid:0" id="' + origin_id + '"/>'
        prefix = '<message xmlns="jabber:client"' + attributes + ' to="' + original_input['target'] + '" from="{}">'
        routed = prefix.format('alice@example.test/device') + content + '</message>'
        normalized = prefix.format('alice@example.test') + content + '</message>'
        sid = '<stanza-id xmlns="urn:xmpp:sid:0" id="{}" by="{}"/>'
        live = routed[:-10] + sid.format(identity['recipient_stable_id'], 'bob@example.test') + '</message>'
        sender_xml = routed[:-10] + sid.format(identity['sender_stable_id'], 'alice@example.test') + '</message>'
        stored = live[:-10] + '<delay xmlns="urn:xmpp:delay" from="example.test" stamp="1970-01-01T00:01:40Z"/></message>'
        archives = []
        if policy['sender_archive']:
            archives.append({'archive_id': identity['sender_stable_id'], 'owner_id': roles['actor_id'],
                             'peer_jid': 'bob@example.test/phone', 'stanza_id': 'm', 'encrypted': False, 'xml': sender_xml})
        if policy['recipient_archive']:
            archives.append({'archive_id': identity['recipient_stable_id'], 'owner_id': roles['recipient_id'],
                             'peer_jid': 'alice@example.test/device', 'stanza_id': 'm', 'encrypted': False, 'xml': live})
        projection = {'message_type': 'normal' if unrated else 'chat', 'origin_id': origin_id, 'rated': not unrated,
                      'normalized_payload': None if unrated else normalized,
                      'live_xml': live, 'stored_xml': stored, 'archives': archives}
        prepared = {'actor_id': roles['actor_id'], 'recipient_id': roles['recipient_id'],
                    'delivery_id': identity['recipient_stable_id'],
                    'eligibility': 'LiveOnly' if original_input['target'].endswith('/phone') else 'Eligible', 'encrypted': False,
                    'mam_backed': policy['recipient_archive'], 'archive_ids': [item['archive_id'] for item in archives],
                    'identity': {'authority': 'LocalOrigin', 'actor_scope_raw': 'alice@example.test',
                                 'actor_scope': 'alice@example.test', 'target_scope': 'bob@example.test',
                                 'value': origin_id, 'payload': routed} if not unrated else None}
        state = {'begin': None, 'finalize': None, 'direct': None, 'handoff': None, 'terminal': None}
        original = {'frame_id': frame, 'projection': projection, 'prepared': prepared, 'continuation': None,
                    'begin': None, 'finalize': None, 'direct': None, 'terminal': None, 'prefixes': [], 'polls': [],
                    'route': {'health_reads': [], 'enqueue': [], 'dequeued': [], 'queue_remaining': [],
                              'backpressure_disconnected': False, 'remote_calls': [], 'rearm_calls': [], 'handoff': None}}
        def snapshot():
            original['prefixes'].append({'seq': seq(), 'state': copy.deepcopy(state)})
        def sender_only(terminal, poll):
            original['polls'].append({'seq': seq(), 'result': poll})
            state['terminal'] = terminal
            if state['handoff'] is not None:
                state['handoff']['retired'] = True
            snapshot()
            for name in ('begin', 'finalize', 'direct', 'terminal'):
                original[name] = copy.deepcopy(state[name])
            original['route']['handoff'] = copy.deepcopy(state['handoff'])
            return {'schema': direct_case.EVIDENCE_SCHEMA, 'entry': direct_case.ENTRY,
                    'input_sha256': direct_case._hash(fixture['bytes']), 'rejection': None,
                    'execution': 'Cancelled' if terminal == 'Cancelled' else 'Complete',
                    'originals': [original], 'recipient': {'kind': 'None'}}
        admission = value['admission'][original_index]
        if not unrated:
            fence = {name: admission['fence'][name] for name in
                     ('admission_key_hex', 'payload_mac_hex', 'lease_token')}
            reservation = {'correlation': correlation(1), 'scope': 'RatedBeginNewReservation',
                           'fact': {'kind': 'Reserved', 'fence': copy.deepcopy(fence)}}
            state['begin'] = {'correlation': correlation(1), 'started': True,
                              'knowledge': {'kind': 'CommitCallEntered', 'prepared': reservation}, 'returned': None}
            snapshot()
            state['begin']['knowledge'] = {'kind': 'ReceiptKnown', 'receipt': reservation}
            snapshot()
            state['begin']['returned'] = {'kind': 'Proceed', 'fence': copy.deepcopy(fence)}
        repository = value['direct_repository'][original_index]
        transaction = copy.deepcopy(repository['transaction'])
        direct_prepared = {'correlation': correlation(3), 'transaction': transaction,
                           'admitted_mode': repository['admitted_mode']}
        state['direct'] = {'correlation': correlation(3), 'started': True,
                           'knowledge': {'kind': 'CommitCallEntered', 'prepared': direct_prepared},
                           'returned': None, 'preserved_transaction': None, 'application_error': False}
        snapshot()
        if sender_cut == 'direct_pending':
            return sender_only('Cancelled', 'Pending')
        state['direct']['knowledge'] = {'kind': 'ReceiptKnown', 'receipt': {'prepared': direct_prepared}}
        snapshot()
        if unrated:
            state['direct']['returned'] = {'commit': {'kind': 'Replay'}, 'mode': 'Live', 'live_claim_id': None}
            original['continuation'] = {'kind': 'Accepted', 'error_type': None, 'error_condition': None}
            return sender_only('Completed', 'Ready')
        returned_mode = repository['completion'].get('mode', 'Live')
        state['direct']['returned'] = {'commit': {'kind': 'Stored', 'archive_written': bool(archives),
                                                 'recipient_id': roles['recipient_id'],
                                                 'delivery_id': identity['recipient_stable_id']},
                                       'mode': returned_mode, 'live_claim_id': transaction['live_claim_id']}
        if sender_cut == 'receipt_preserved':
            state['direct'].update(returned=None, preserved_transaction=copy.deepcopy(transaction), application_error=True)
        finalization = {'correlation': correlation(2), 'scope': 'AdmissionFinalize',
                        'fact': {'kind': 'Finalized', 'fence': copy.deepcopy(fence), 'result': 'PendingAccepted'}}
        state['finalize'] = {'correlation': correlation(2), 'started': True,
                             'knowledge': {'kind': 'CommitCallEntered', 'prepared': finalization}, 'returned': None}
        snapshot()
        if admission['finalize_commit'] == 'Complete':
            state['finalize']['knowledge'] = {'kind': 'ReceiptKnown', 'receipt': finalization}
            snapshot()
            state['finalize']['returned'] = {'kind': 'AcceptPending'}
        else:
            state['finalize']['returned'] = {'kind': 'Error'}
        snapshot()
        source = {'kind': 'C2s', 'recipient_id': roles['recipient_id'], 'message_id': identity['recipient_stable_id'],
                  'claim_id': transaction['live_claim_id']}
        state['handoff'] = {'correlation': correlation(4), 'source': source, 'local_call': 'NotRequested',
                            'local_accepted': False, 'last_local_refusal': None, 'remote': 'NotRequested',
                            'prior_remote_uncertain': False, 'rearm': 'NotRequested', 'route_end': 'Running', 'retired': False}
        if sender_cut == 'receipt_preserved' or returned_mode == 'SpoolOnly':
            if source['claim_id'] is not None:
                state['handoff']['rearm'] = 'CallEntered'
                original['route']['rearm_calls'].append({'seq': seq(), 'source': source, 'returned': True})
                state['handoff']['rearm'] = 'CallReturned'
            state['handoff']['route_end'] = 'Returned'
            original['continuation'] = {'kind': 'Accepted', 'error_type': None, 'error_condition': None}
            return sender_only('Completed', 'Ready')
        for phase in ('PostFinalize', 'Router'):
            original['route']['health_reads'].append({'seq': seq(), 'phase': phase, 'mode': 'Live'})
        if sender_cut == 'rearm_pending':
            original['route']['enqueue'].append({'seq': seq(), 'source': source, 'xml': live, 'result': 'Full'})
            original['route']['backpressure_disconnected'] = True
            original['route']['queue_remaining'] = [{'xml': "<message id='plain'/>", 'source': None}]
            state['handoff'].update(local_call='Refused', last_local_refusal='Full')
            original['route']['remote_calls'].append({'seq': seq(), 'source': source, 'returned': False})
            state['handoff'].update(remote='NoPositiveReceipt', prior_remote_uncertain=True, rearm='CallEntered')
            original['route']['rearm_calls'].append({'seq': seq(), 'source': source, 'returned': False})
            state['handoff']['route_end'] = 'Dropped'
            original['continuation'] = {'kind': 'Live', 'error_type': None, 'error_condition': None}
            return sender_only('Cancelled', 'Pending')
        original['route']['enqueue'].append({'seq': seq(), 'source': source, 'xml': live, 'result': 'Accepted'})
        state['handoff'].update(local_call='Accepted', local_accepted=True)
        original['route']['health_reads'].append({'seq': seq(), 'phase': 'Router', 'mode': 'Live'})
        state['handoff']['route_end'] = 'Returned'
        original['continuation'] = {'kind': 'Live', 'error_type': None, 'error_condition': None}
        original['polls'].append({'seq': seq(), 'result': 'Ready'})
        state['handoff']['retired'] = True
        state['terminal'] = 'Completed'
        snapshot()
        for name in ('begin', 'finalize', 'direct', 'terminal'):
            original[name] = copy.deepcopy(state[name])
        original['route']['handoff'] = copy.deepcopy(state['handoff'])
        original['route']['dequeued'].append({'seq': seq(), 'source': source, 'xml': live})
        native_input = value['recipient_owner']['native']
        fenced = copy.deepcopy(native_input['fence']['returned_source'])
        native_state = {'original': source, 'preparation': 'Prepared', 'managed_by_sm': False, 'fence_entered': True,
                        'returned_fence': fenced, 'writer_entered': False, 'writer_result': None, 'write_decision': None,
                        'ack': {'kind': 'NotRequested'}, 'ack_returned': None, 'terminal': None}
        native = {'frame_id': frame, 'connection_id': native_input['connection_id'], 'prefixes': [], 'polls': [],
                  'write_calls': [], 'flush_calls': [], 'ack_calls': [], 'ownership_receipts': [], 'write_receipts': []}
        def native_snapshot():
            native['prefixes'].append({'seq': seq(), 'state': copy.deepcopy(native_state)})
        native_snapshot()
        native_state['writer_entered'] = True
        remaining = live.encode('utf-8')
        short = native_input['write']['fail_after_accepted_bytes']
        accepted = 0
        while remaining:
            count = min(native_input['write']['chunk_limit'], len(remaining))
            if short is not None:
                count = min(count, max(0, short - accepted))
            native['write_calls'].append({'seq': seq(), 'offered_len': len(remaining),
                                          'offered_sha256': direct_case._hash(remaining),
                                          'accepted_bytes_hex': remaining[:count].hex(), 'result': 'Accepted' if count else 'Error'})
            if not count:
                break
            remaining = remaining[count:]
            accepted += count
        if short is None and not omit_flush:
            native['flush_calls'].append({'seq': seq(), 'result': native_input['write']['flush']})
        successful = short is None and (omit_flush or native_input['write']['flush'] == 'Ok')
        native_state.update(writer_result='FullWrite' if successful else 'Failed',
                            write_decision='Written' if successful else 'Withhold')
        native_snapshot()
        pending = successful and native_input['ack']['commit'] == 'Pending'
        if successful:
            native['ack_calls'].append({'seq': seq(), 'source': fenced, 'returned': None})
            fact = {'source': fenced, 'disposition': 'Deleted'}
            native_state['ack'] = {'kind': 'CommitCallEntered', 'fact': fact}
            native_snapshot()
            if not pending:
                native_state['ack'] = {'kind': 'ReceiptKnown', 'fact': fact}
                native_snapshot()
                native['ack_calls'][0]['returned'] = True
                native_state['ack_returned'] = True
        native['polls'].append({'seq': seq(), 'result': 'Pending' if pending else 'Ready'})
        native_state['terminal'] = 'Cancelled' if pending else 'Returned'
        native_snapshot()
        native.update(copy.deepcopy(native_state))
        return {'schema': direct_case.EVIDENCE_SCHEMA, 'entry': direct_case.ENTRY, 'input_sha256': direct_case._hash(fixture['bytes']),
                'rejection': None, 'execution': 'Cancelled' if pending else 'Complete',
                'originals': [original], 'recipient': {'kind': 'Native', 'native': native}}

    def supplied_sequence(self, fixture, *, omit_flush=False):
        def last_seq(value):
            if type(value) is dict:
                return max([value.get('seq', 0)] + [last_seq(item) for item in value.values()])
            if type(value) is list:
                return max([0] + [last_seq(item) for item in value])
            return 0
        combined, counter = None, 0
        for index in range(len(fixture['value']['originals'])):
            part = self.supplied_facts(fixture, original_index=index, start_seq=counter, omit_flush=omit_flush)
            counter = last_seq(part)
            if combined is None:
                combined = part
            else:
                combined['originals'].extend(part['originals'])
                combined['recipient'] = part['recipient']
                combined['execution'] = part['execution']
        return combined

    def test_spool_only_pair_keeps_admitted_and_returned_modes_and_exact_rearm(self):
        fixture = self.fixture('C03')
        payload = self.supplied_sequence(fixture)
        _semantic, evaluation, matched, stop = direct_case._inspect_native_fixture(fixture, self.complete_record(), payload)
        self.assertTrue(matched)
        self.assertIsNone(stop)
        self.assertEqual(evaluation['verdict'], 'Pass')
        self.assertEqual([item['direct']['knowledge']['receipt']['prepared']['admitted_mode']
                          for item in payload['originals']], ['SpoolOnly', 'Live'])
        self.assertEqual([item['direct']['returned']['mode'] for item in payload['originals']], ['SpoolOnly', 'SpoolOnly'])
        self.assertEqual([len(item['route']['rearm_calls']) for item in payload['originals']], [0, 1])
        bad = copy.deepcopy(payload)
        bad['originals'][1]['direct']['returned']['mode'] = 'Live'
        self.assertFalse(direct_case._inspect_native_fixture(fixture, self.complete_record(), bad)[2])

    def test_full_queue_remote_uncertainty_and_pending_rearm_remain_cancelled(self):
        fixture = self.fixture('C06')
        payload = self.supplied_facts(fixture, sender_cut='rearm_pending')
        _semantic, evaluation, matched, stop = direct_case._inspect_native_fixture(fixture, self.complete_record(), payload)
        self.assertTrue(matched)
        self.assertIsNone(stop)
        self.assertEqual((evaluation['verdict'], evaluation['qualified']), ('Cancelled', False))
        original = payload['originals'][0]
        self.assertTrue(original['route']['handoff']['prior_remote_uncertain'])
        self.assertEqual(original['route']['handoff']['rearm'], 'CallEntered')
        self.assertEqual(original['route']['queue_remaining'], [{'xml': "<message id='plain'/>", 'source': None}])
        bad = copy.deepcopy(payload)
        bad['originals'][0]['route']['handoff']['prior_remote_uncertain'] = False
        self.assertFalse(direct_case._inspect_native_fixture(fixture, self.complete_record(), bad)[2])

    def test_unrated_prefix_and_mutation_pair_keep_exact_t_settlement_target(self):
        fixture = self.fixture('C07')
        payload = self.supplied_sequence(fixture)
        _semantic, evaluation, matched, stop = direct_case._inspect_native_fixture(fixture, self.complete_record(), payload)
        self.assertTrue(matched)
        self.assertIsNone(stop)
        self.assertEqual(evaluation['verdict'], 'Pass')
        first = payload['originals'][0]
        self.assertIsNone(first['begin'])
        self.assertIsNone(first['finalize'])
        self.assertIsNone(first['route']['handoff'])
        self.assertEqual(first['direct']['returned']['commit'], {'kind': 'Replay'})
        targets = []
        for identity in ('M1', 'M2', 'M4'):
            fixture = self.fixture(identity)
            payload = self.supplied_sequence(fixture, omit_flush=True)
            _semantic, evaluation, matched, _stop = direct_case._inspect_native_fixture(fixture, self.complete_record(), payload)
            self.assertTrue(matched)
            self.assertEqual(evaluation['verdict'], 'InvariantViolation')
            self.assertEqual(len(payload['recipient']['native']['ack_calls']), 1)
            targets.append(evaluation['invariant'])
        self.assertEqual(targets, [targets[0]] * 3)

    def test_complete_supplied_c01_matches_without_using_prediction_to_build_it(self):
        fixture = self.fixture('C01')
        with patch.object(direct_case, 'derive_native_ledger', side_effect=AssertionError('prediction is not observation')), \
                patch.object(direct_case, '_expected_native_state', side_effect=AssertionError('prediction is not observation')):
            payload = self.supplied_facts(fixture)
        _semantic, evaluation, matched, stop = direct_case._inspect_native_fixture(fixture, self.complete_record(), payload)
        self.assertTrue(matched)
        self.assertIsNone(stop)
        self.assertEqual((evaluation['verdict'], evaluation['qualified'], evaluation['invariant']), ('Pass', True, None))

    def test_no_flush_is_safety_before_fixture_matching_and_permission_never_changes_verdict(self):
        fixture = self.fixture('M2')
        payload = self.supplied_facts(fixture, omit_flush=True)
        _semantic, evaluation, matched, _stop = direct_case._inspect_native_fixture(fixture, self.complete_record(), payload)
        self.assertTrue(matched)
        self.assertEqual(evaluation['invariant'], fixture['expected_failure'])
        self.assertEqual(evaluation['verdict'], 'InvariantViolation')
        self.assertFalse(evaluation['qualified'])
        baseline_permission = copy.deepcopy(fixture)
        baseline_permission.update(expected_failure=None, expected_verdict='Pass')
        _semantic, baseline, matched, _stop = direct_case._inspect_native_fixture(baseline_permission, self.complete_record(), payload)
        self.assertFalse(matched)
        self.assertEqual(baseline['invariant'], evaluation['invariant'])
        self.assertEqual(baseline['verdict'], 'InvariantViolation')

    def test_short_write_control_is_pass_and_never_pollutes_expected_failure(self):
        fixture = self.fixture('M3')
        payload = self.supplied_facts(fixture, omit_flush=True)
        _semantic, evaluation, matched, _stop = direct_case._inspect_native_fixture(fixture, self.complete_record(), payload)
        self.assertTrue(matched)
        self.assertEqual(evaluation['verdict'], 'Pass')
        self.assertEqual(evaluation['violations'], [])
        self.assertEqual(payload['recipient']['native']['flush_calls'], [])
        self.assertEqual(payload['recipient']['native']['ack_calls'], [])

    def test_planned_two_unknowns_remain_cancelled_and_external_interruption_never_matches(self):
        fixture = self.fixture('C02')
        payload = self.supplied_facts(fixture)
        _semantic, evaluation, matched, _stop = direct_case._inspect_native_fixture(fixture, self.complete_record(), payload)
        self.assertTrue(matched)
        self.assertEqual(evaluation['verdict'], 'Cancelled')
        self.assertFalse(evaluation['qualified'])
        self.assertEqual(payload['originals'][0]['finalize']['knowledge']['kind'], 'CommitCallEntered')
        self.assertEqual(payload['recipient']['native']['ack']['kind'], 'CommitCallEntered')
        result = direct_case._inspect_native_fixture(fixture, {'observation': 'EnvironmentInterrupted'}, payload)
        self.assertEqual(result, (None, None, False, 'EnvironmentInterrupted'))
        payload['recipient']['native']['polls'][0]['result'] = 'Ready'
        self.assertFalse(direct_case._inspect_native_fixture(fixture, self.complete_record(), payload)[2])

    def test_duplicate_ack_is_decodable_and_never_deduplicated_into_expected_target(self):
        fixture = self.fixture('M2')
        payload = self.supplied_facts(fixture, omit_flush=True)
        native = payload['recipient']['native']
        first = native['ack_calls'][0]['seq']
        def shift(value):
            if type(value) is dict:
                if 'seq' in value and value['seq'] > first:
                    value['seq'] += 1
                for item in value.values():
                    shift(item)
            elif type(value) is list:
                for item in value:
                    shift(item)
        shift(payload)
        duplicate = copy.deepcopy(native['ack_calls'][0])
        duplicate['seq'] = first + 1
        native['ack_calls'].append(duplicate)
        direct_case.validate_native_evidence(payload)
        _semantic, evaluation, matched, _stop = direct_case._inspect_native_fixture(fixture, self.complete_record(), payload)
        self.assertFalse(matched)
        self.assertEqual([item['id'] for item in evaluation['violations']],
                         ['NativeAckWithoutSuccessfulFlush', 'NativeAckWithoutSuccessfulFlush'])

    def test_handoff_requires_prior_matching_receipt_and_retained_correlation(self):
        fixture = self.fixture('C01')
        payload = self.supplied_facts(fixture)
        original = payload['originals'][0]
        before = original['route']['enqueue'][0]['seq']
        for prefix in original['prefixes']:
            observed = prefix['state']['direct']
            if prefix['seq'] < before and observed is not None and observed['knowledge']['kind'] == 'ReceiptKnown':
                prepared = observed['knowledge']['receipt']['prepared']
                observed['knowledge'] = {'kind': 'CommitCallEntered', 'prepared': prepared}
        _semantic, evaluation, matched, _stop = direct_case._inspect_native_fixture(fixture, self.complete_record(), payload)
        self.assertFalse(matched)
        self.assertEqual(evaluation['invariant']['id'], 'HandoffWithoutStoredReceipt')
        payload = self.supplied_facts(fixture)
        payload['originals'][0]['begin']['correlation']['effect'] = 2
        self.assertFalse(direct_case._inspect_native_fixture(fixture, self.complete_record(), payload)[2])

    def test_bad_projected_xml_keeps_failed_observation_and_existing_safety(self):
        fixture = self.fixture('M2')
        payload = self.supplied_facts(fixture, omit_flush=True)
        payload['originals'][0]['projection']['live_xml'] = '<message><body>x</body></message>'
        semantic, evaluation, matched, stop = direct_case._inspect_native_fixture(fixture, self.complete_record(), payload)
        self.assertEqual(semantic, payload)
        self.assertFalse(matched)
        self.assertEqual(stop, 'FixtureMismatch')
        self.assertEqual(evaluation['invariant']['id'], 'NativeAckWithoutSuccessfulFlush')
        self.assertTrue(any(item.startswith('projected_xml:') for item in evaluation['mismatches']))

    def test_wrong_input_hash_cannot_supply_semantic_authority(self):
        fixture = self.fixture('M2')
        payload = self.supplied_facts(fixture, omit_flush=True)
        payload['input_sha256'] = '0' * 64
        semantic, evaluation, matched, stop = direct_case._inspect_native_fixture(fixture, self.complete_record(), payload)
        self.assertEqual(semantic, payload)
        self.assertFalse(matched)
        self.assertEqual(stop, 'InputBindingMismatch')
        self.assertIsNone(evaluation['invariant'])
        self.assertEqual(evaluation['verdict'], 'Inconclusive')
        invalid_status = {'observation': 'Complete', 'process': {'returncode': False}}
        self.assertEqual(direct_case._inspect_native_fixture(fixture, invalid_status, payload),
                         (None, None, False, 'ProcessFailure'))

    def test_fixed_rejections_require_exact_reason_input_binding_and_empty_execution(self):
        for identity in ('R01', 'R02', 'R03'):
            fixture = self.fixture(identity)
            payload = {'schema': direct_case.EVIDENCE_SCHEMA, 'entry': direct_case.ENTRY,
                       'input_sha256': direct_case._hash(fixture['bytes']),
                       'rejection': {'class': 'InvalidScenario', 'reason': fixture['reason']},
                       'execution': None, 'originals': [], 'recipient': None}
            _semantic, evaluation, matched, _stop = direct_case._inspect_native_fixture(fixture, self.complete_record(), payload)
            self.assertTrue(matched)
            self.assertEqual(evaluation['verdict'], 'InvalidScenario')
            self.assertFalse(evaluation['qualified'])
            payload['input_sha256'] = '0' * 64
            self.assertFalse(direct_case._inspect_native_fixture(fixture, self.complete_record(), payload)[2])

    def test_sender_commit_drop_is_cancelled_without_receipt_finalization_or_handoff(self):
        fixture = self.fixture('C05')
        payload = self.supplied_facts(fixture, sender_cut='direct_pending')
        _semantic, evaluation, matched, _stop = direct_case._inspect_native_fixture(fixture, self.complete_record(), payload)
        self.assertTrue(matched)
        self.assertEqual(evaluation['verdict'], 'Cancelled')
        self.assertFalse(evaluation['qualified'])
        self.assertIsNone(payload['originals'][0]['finalize'])
        self.assertIsNone(payload['originals'][0]['route']['handoff'])
        payload['originals'][0]['prefixes'].pop()
        self.assertFalse(direct_case._inspect_native_fixture(fixture, self.complete_record(), payload)[2])

    def test_receipt_preserved_error_has_no_returned_mode_and_only_recovery(self):
        fixture = self.fixture('C04')
        payload = self.supplied_facts(fixture, sender_cut='receipt_preserved')
        _semantic, evaluation, matched, _stop = direct_case._inspect_native_fixture(fixture, self.complete_record(), payload)
        self.assertTrue(matched)
        self.assertEqual(evaluation['verdict'], 'Pass')
        original = payload['originals'][0]
        self.assertIsNone(original['direct']['returned'])
        self.assertEqual(original['route']['health_reads'], [])
        self.assertEqual(original['route']['handoff']['rearm'], 'CallReturned')
        self.assertEqual(original['route']['dequeued'], [])

    def test_late_fence_or_full_write_knowledge_cannot_retroactively_authorize_ack(self):
        fixture = self.fixture('C01')
        for late in ('fence', 'writer'):
            payload = self.supplied_facts(fixture)
            native = payload['recipient']['native']
            boundary = native['write_calls'][0]['seq'] if late == 'fence' else native['ack_calls'][0]['seq']
            for prefix in native['prefixes']:
                if prefix['seq'] < boundary:
                    if late == 'fence':
                        prefix['state'].update(fence_entered=False, returned_fence=None)
                    else:
                        prefix['state'].update(writer_result=None, write_decision=None)
            direct_case.validate_native_evidence(payload)
            _semantic, evaluation, matched, _stop = direct_case._inspect_native_fixture(fixture, self.complete_record(), payload)
            self.assertFalse(matched)
            wanted = 'NativeAckWithoutMatchingFence' if late == 'fence' else 'NativeAckWithoutFullWrite'
            self.assertIn(wanted, [item['id'] for item in evaluation['violations']])
            self.assertEqual(evaluation['invariant']['class'], 'Safety')

    def test_returns_and_preserved_transactions_require_contemporaneous_receipts(self):
        for identity, cut in (('C01', None), ('C04', 'receipt_preserved')):
            fixture = self.fixture(identity)
            payload = self.supplied_facts(fixture, sender_cut=cut)
            original = payload['originals'][0]
            prefix = next(item for item in original['prefixes'] if item['state']['direct'] is not None and
                          item['state']['direct']['knowledge']['kind'] == 'CommitCallEntered')
            if identity == 'C01':
                prefix['state']['direct']['returned'] = copy.deepcopy(original['direct']['returned'])
            else:
                prefix['state']['direct'].update(preserved_transaction=copy.deepcopy(original['direct']['preserved_transaction']),
                                                 application_error=True)
            _semantic, evaluation, matched, _stop = direct_case._inspect_native_fixture(fixture, self.complete_record(), payload)
            self.assertFalse(matched)
            self.assertIn('direct_return_knowledge' if identity == 'C01' else 'direct_preserved_receipt_knowledge',
                          evaluation['mismatches'])

    def test_native_retained_knowledge_cannot_disappear_and_reappear(self):
        fixture = self.fixture('C01')
        for field in ('returned_fence', 'writer_result', 'write_decision', 'managed_by_sm'):
            payload = self.supplied_facts(fixture)
            prefixes = payload['recipient']['native']['prefixes']
            target = next(item for item in prefixes if item['state']['ack']['kind'] == 'CommitCallEntered')
            target['state'][field] = None
            _semantic, evaluation, matched, _stop = direct_case._inspect_native_fixture(fixture, self.complete_record(), payload)
            self.assertFalse(matched)
            self.assertIn('native_retained_' + field, evaluation['mismatches'])

    def test_handoff_sticky_facts_and_terminal_cannot_be_erased(self):
        expected = {'correlation': {'operation_id': direct_case._uuid(601), 'effect': 4, 'generation': 0, 'attempt': 1},
                    'source': direct_case._c2s(direct_case._uuid(20601), direct_case._uuid(20601)),
                    'local_call': 'Refused', 'local_accepted': False, 'last_local_refusal': 'Full',
                    'remote': 'NoPositiveReceipt', 'prior_remote_uncertain': True, 'rearm': 'CallEntered',
                    'route_end': 'Dropped', 'retired': True}
        for field, erased in (('prior_remote_uncertain', False), ('last_local_refusal', None), ('retired', False)):
            hidden = copy.deepcopy(expected)
            hidden[field] = erased
            prefixes = [{'seq': index + 1, 'state': {'handoff': value}} for index, value in
                        enumerate((expected, hidden, expected))]
            findings = []
            direct_case._retained_handoff_prefixes(prefixes, expected, findings)
            self.assertTrue(findings)

    def test_native_returns_and_writer_results_require_prior_actual_facts(self):
        fixture = self.fixture('C01')
        payload = self.supplied_facts(fixture)
        native = payload['recipient']['native']
        entered = next(item for item in native['prefixes'] if item['state']['ack']['kind'] == 'CommitCallEntered')
        entered['state']['ack_returned'] = True
        result = direct_case._inspect_native_fixture(fixture, self.complete_record(), payload)
        self.assertFalse(result[2])
        self.assertIn('native_ack_return_knowledge', result[1]['mismatches'])
        payload = self.supplied_facts(fixture)
        payload['recipient']['native']['prefixes'][0]['state'].update(
            writer_entered=True, writer_result='FullWrite', write_decision='Written')
        result = direct_case._inspect_native_fixture(fixture, self.complete_record(), payload)
        self.assertFalse(result[2])
        self.assertIn('native_writer_result_after_calls', result[1]['mismatches'])
        payload = self.supplied_facts(fixture)
        native = payload['recipient']['native']
        native['ack'] = {'kind': 'NoCommitRequested'}
        native['ack_returned'] = False
        native['ack_calls'][0]['returned'] = False
        direct_case.validate_native_evidence(payload)

    def test_owner_final_observation_cadence_and_native_call_before_poll_are_required(self):
        fixture = self.fixture('C01')
        for owner in ('sender', 'native'):
            payload = self.supplied_facts(fixture)
            prefixes = payload['originals'][0]['prefixes'] if owner == 'sender' else payload['recipient']['native']['prefixes']
            for prefix in prefixes:
                prefix['state']['terminal'] = 'Completed' if owner == 'sender' else 'Returned'
            result = direct_case._inspect_native_fixture(fixture, self.complete_record(), payload)
            self.assertFalse(result[2])
            self.assertIn(owner + '_terminal_after_poll', result[1]['mismatches'])
        payload = self.supplied_facts(fixture)
        native = payload['recipient']['native']
        native['ack_calls'][0]['seq'], native['polls'][0]['seq'] = native['polls'][0]['seq'], native['ack_calls'][0]['seq']
        direct_case.validate_native_evidence(payload)
        result = direct_case._inspect_native_fixture(fixture, self.complete_record(), payload)
        self.assertFalse(result[2])
        self.assertIn('native_calls_before_poll', result[1]['mismatches'])

    def test_handoff_result_and_retirement_prefixes_cannot_precede_actual_calls(self):
        for identity, cut, wanted in (('C01', None, 'handoff_acceptance_after_call'),
                                      ('C06', 'rearm_pending', 'handoff_uncertainty_after_call')):
            fixture = self.fixture(identity)
            payload = self.supplied_facts(fixture, sender_cut=cut)
            original = payload['originals'][0]
            original['prefixes'][0]['state']['handoff'] = copy.deepcopy(original['route']['handoff'])
            result = direct_case._inspect_native_fixture(fixture, self.complete_record(), payload)
            self.assertFalse(result[2])
            self.assertIn(wanted, result[1]['mismatches'])
            self.assertIn('handoff_retired_after_poll', result[1]['mismatches'])

    def test_receipt_preserved_rearm_waits_for_actual_finalization_return(self):
        fixture = self.fixture('C04')
        payload = self.supplied_facts(fixture, sender_cut='receipt_preserved')
        original = payload['originals'][0]
        rearm_seq = original['route']['rearm_calls'][0]['seq']
        for prefix in original['prefixes']:
            if prefix['seq'] < rearm_seq and prefix['state']['finalize'] is not None:
                prefix['state']['finalize']['returned'] = None
        result = direct_case._inspect_native_fixture(fixture, self.complete_record(), payload)
        self.assertFalse(result[2])
        self.assertIn('finalization_return_before_rearm', result[1]['mismatches'])


if __name__ == '__main__':
    unittest.main()
