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
                        'scripts/lib/direct_case', 'scripts/lib/direct_case.pyc')
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


if __name__ == '__main__':
    unittest.main()
