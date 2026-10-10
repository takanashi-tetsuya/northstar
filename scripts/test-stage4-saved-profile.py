#!/usr/bin/env python3
"""Authored, UNEXECUTED narrow Stage4 routing/build-reader controls.

Default tests are pure routing/framing or in-memory source-byte controls. Their
synthetic dictionaries are explicitly not actual build/process/frame evidence.
The separate actual_control_suite requires externally authenticated real corpora;
no fallback, skipped prerequisite or fabricated positive is supplied.
"""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
from lib import controlled_admission_supervision as s
from lib import stage4_build_record as build
from lib import stage4_saved_case as adapter
from lib import stage4_corpus_join as join
from lib import stage4_case as semantic


def metadata_contract(profile_id=s.COMPOSITION_PROFILE):
    """Synthetic STRUCTURAL contract only; cannot satisfy actual source checks."""
    profile = s.fixed_profile(profile_id)
    baseline = profile_id == s.COMPOSITION_PROFILE
    sources = {name: s.fingerprint(name.encode()) for name in profile['helpers']}
    sources['Cargo.lock'] = s.fingerprint(b'synthetic lock')
    sources.update(s.COMPOSITION_V2_SOURCE_HASHES)
    cases = []
    for index, occurrence in enumerate(profile['ids']):
        literal = occurrence if baseline else semantic.MUTANT_INPUTS[occurrence]
        size, digest, planned = semantic.FIXTURES[literal]
        cases.append({'id': occurrence, 'kind': profile['kinds'][index], 'bytes': size,
                      'sha256': digest, 'expected_verdict': planned if baseline else 'InvariantViolation'})
    return {'schema': s.COMPOSITION_CONTRACT_SCHEMA, 'profile': profile_id,
        'run_id': 'synthetic-metadata-only', 'mode': 'record', 'root': '/synthetic/source',
        'binary': '/synthetic/runnable', 'evidence_dir': '/synthetic/evidence',
        'replay_dir': None, 'replay_authority': None, 'build_record': '/synthetic/build-record.json',
        'provenance': {'schema': 'northstar-stage4-composition-controlled-provenance-v1',
            'model': 'stage4-composition-controlled-v1', 'adapter': semantic.ADAPTER,
            'binding_version': 'stage4-project-local-build-material-v1',
            'source_sha256': s.object_hash(sources), 'source_files': sources,
            'binary_sha256': s.fingerprint(b'synthetic artifact metadata'),
            'cargo_lock_sha256': sources['Cargo.lock'], 'toolchain': 'rustc 1.97.1 synthetic',
            'compiler_sha256': s.fingerprint(b'synthetic compiler'),
            'artifact_role': 'baseline' if baseline else 'auth-cache-bypass-mutant',
            'build_record_file_sha256': s.fingerprint(b'synthetic build record')},
        'helper_source_files': {key: sources[key] for key in profile['helpers']},
        'budgets': profile['budgets'], 'plan_counts': profile['counts'], 'case_inventory': cases,
        'release': {field: s.fingerprint(('synthetic review ' + field).encode())
                    for field in s.COMPOSITION_RELEASE_FIELDS.split()},
        'caller': {'schema': s.CALLER_SCHEMA, 'python': '/synthetic/python',
                   'python_sha256': s.fingerprint(b'synthetic python'), 'timeout_sha256': s.TIMEOUT_SHA256}}


class FixedRoutingControls(unittest.TestCase):
    def test_original_profile_shapes_unchanged(self):
        for profile_id, count in ((s.LEGACY_PROFILE, 82), (s.DIRECT_PROFILE, 16), (s.NO_FLUSH_PROFILE, 4)):
            profile = s.fixed_profile(profile_id)
            self.assertEqual(profile['counts']['total'], count)
            self.assertNotIn('release', profile)
            self.assertNotIn('composition', profile)
        self.assertEqual(s.fixed_profile(s.NO_FLUSH_PROFILE)['ids'], ('M1', 'M2', 'M3', 'M4'))
        self.assertEqual(s.fixed_profile(s.NO_FLUSH_PROFILE)['shrink']['positive_control'], 2)

    def test_exact_two_profiles_no_mutant_positive_or_shrink_tail(self):
        a, b = s.fixed_profile(s.COMPOSITION_PROFILE), s.fixed_profile(s.AUTH_CACHE_PROFILE)
        self.assertEqual(a['ids'], tuple(f'S{index:02d}' for index in range(1, 17)))
        self.assertEqual(b['ids'], ('M1', 'M2', 'M3'))
        self.assertIsNone(a['shrink']); self.assertIsNone(b['shrink'])
        self.assertEqual(a['counts']['shrink'], 0); self.assertEqual(b['counts']['shrink'], 0)
        self.assertEqual(2 * (a['counts']['total'] + b['counts']['total']), 38)

    def test_unchanged_nonlegacy_limits(self):
        old = s.fixed_profile(s.DIRECT_PROFILE)['budgets']
        for profile_id in s.COMPOSITION_PROFILES:
            new = s.fixed_profile(profile_id)['budgets']
            self.assertEqual({key: value for key, value in new.items() if key != 'launches'},
                             {key: value for key, value in old.items() if key != 'launches'})
            self.assertEqual((new['case_ms'], new['input_bytes'], new['stdout_bytes'],
                              new['evaluation_bytes'], new['evidence_bytes']),
                             (5000, 65536, 262144, 262144, 33554432))

    def test_structural_contracts_only(self):
        for profile_id in s.COMPOSITION_PROFILES:
            candidate = metadata_contract(profile_id)
            self.assertEqual(s.validate_contract(candidate), candidate)

    def test_v3_v4_profile_confusion_rejected(self):
        for schema, profile in ((s.DIRECT_CONTRACT_SCHEMA, s.COMPOSITION_PROFILE),
                                (s.COMPOSITION_CONTRACT_SCHEMA, s.DIRECT_PROFILE),
                                (s.COMPOSITION_CONTRACT_SCHEMA, s.NO_FLUSH_PROFILE)):
            value = metadata_contract(); value.update(schema=schema, profile=profile)
            with self.assertRaises(s.SupervisionError): s.validate_contract(value)

    def test_stage3_no_flush_role_rejected(self):
        for profile_id in s.COMPOSITION_PROFILES:
            value = metadata_contract(profile_id); value['provenance']['artifact_role'] = 'no-flush'
            with self.assertRaisesRegex(s.SupervisionError, 'composition_provenance_version'):
                s.validate_contract(value)

    def test_no_per_occurrence_binary_field(self):
        value = metadata_contract(s.AUTH_CACHE_PROFILE)
        value['case_inventory'][1]['binary'] = '/other/binary'
        with self.assertRaisesRegex(s.SupervisionError, 'direct_inventory_fields'): s.validate_contract(value)

    def test_changed_count_budget_and_release_rejected(self):
        for family, key in (('budgets', 'case_ms'), ('budgets', 'launches'), ('plan_counts', 'total')):
            value = metadata_contract(); value[family][key] += 1
            with self.assertRaises(s.SupervisionError): s.validate_contract(value)
        for field in s.COMPOSITION_RELEASE_FIELDS.split():
            value = metadata_contract(); del value['release'][field]
            with self.assertRaises(s.SupervisionError): s.validate_contract(value)

    def test_external_occurrence_repeat_bytes(self):
        a, b = metadata_contract(), metadata_contract(s.AUTH_CACHE_PROFILE)
        self.assertEqual(a['case_inventory'][10]['sha256'], b['case_inventory'][0]['sha256'])
        self.assertEqual(a['case_inventory'][12]['sha256'], b['case_inventory'][1]['sha256'])
        self.assertEqual(b['case_inventory'][1]['sha256'], b['case_inventory'][2]['sha256'])
        self.assertNotEqual(b['case_inventory'][1]['id'], b['case_inventory'][2]['id'])

    def test_single_fixed_entry_and_fd0(self):
        for profile_id in s.COMPOSITION_PROFILES:
            self.assertEqual(s.child_arguments('/selected', '/ignored-input-path', profile_id),
                             ['/selected', *s.COMPOSITION_ARGUMENTS])
            self.assertEqual(s.COMPOSITION_ARGUMENTS[1], 'stage4_replay::replay_saved_case')
        self.assertEqual(s.child_arguments('/selected', '/input', s.DIRECT_PROFILE),
                         ['/selected', *s.DIRECT_ARGUMENTS])

    def test_only_frozen_sixteen_non_rust_source_leaves(self):
        self.assertEqual(s.COMPOSITION_LITERAL_FILES, frozenset(
            f'src/stage4_replay/fixtures/S{index:02d}.json' for index in range(1, 17)))
        self.assertNotIn('src/stage4_replay/fixtures/M2.json', s.COMPOSITION_LITERAL_FILES)
        self.assertNotIn('src/stage4_replay/fixtures/extra.json', s.COMPOSITION_LITERAL_FILES)

    def test_no_in_contract_shrink_fallback(self):
        with self.assertRaisesRegex(s.SupervisionError, 'cross_contract'):
            adapter.shrink_relations([])

    def test_explicit_v2_identifiers_reject_historical_stage4_contracts(self):
        self.assertEqual(s.COMPOSITION_CONTRACT_SCHEMA, 'northstar-controlled-execution-contract-v5')
        self.assertEqual(s.COMPOSITION_PROFILE, 'stage4-composition-fixed16-v2')
        self.assertEqual(s.AUTH_CACHE_PROFILE, 'stage4-composition-auth-cache-bypass-fixed3-v2')
        self.assertEqual(s.CONTRACT_SCHEMA, 'northstar-controlled-execution-contract-v2')
        self.assertEqual(s.DIRECT_CONTRACT_SCHEMA, 'northstar-controlled-execution-contract-v3')
        candidate = metadata_contract()
        candidate['schema'] = 'northstar-controlled-execution-contract-v4'
        with self.assertRaisesRegex(s.SupervisionError, '^execution_contract_version_or_profile$'):
            s.validate_contract(candidate)
        for historical in ('stage4-composition-fixed16-v1', 'stage4-composition-auth-cache-bypass-fixed3-v1'):
            candidate = metadata_contract(); candidate['profile'] = historical
            with self.assertRaisesRegex(s.SupervisionError, '^composition_contract_profile$'):
                s.validate_contract(candidate)

    def test_current_v2_producer_reader_and_tables_are_exactly_pinned(self):
        for path in s.COMPOSITION_V2_SOURCE_HASHES:
            candidate = metadata_contract()
            candidate['provenance']['source_files'][path] = '0' * 64
            with self.subTest(path=path), self.assertRaisesRegex(s.SupervisionError, '^composition_v2_source_binding$'):
                s.validate_contract(candidate)
        self.assertEqual(semantic.CASE_SCHEMA, 'northstar-stage4-composition-case-v1')
        self.assertEqual(semantic.EVIDENCE_SCHEMA, 'northstar-stage4-composition-evidence-v1')
        self.assertEqual(semantic.stage4_compact.FRAME_TAG, s.COMPOSITION_FRAME_TAG)


class FrameBoundaryControls(unittest.TestCase):
    def frame(self, payload=b'{}'):
        # Structurally framed bytes, explicitly NOT a semantic positive envelope.
        return s.COMPOSITION_FRAME_TAG + str(len(payload)).encode() + b'\n' + payload + s.DIRECT_FRAME_END

    def test_exact_frame_preserved_with_diagnostics(self):
        value = self.frame()
        self.assertEqual(s.extract_composition_frame(b'libtest before\n' + value + b'libtest after\n'), value)

    def test_duplicate_missing_or_stage3_tag_rejected(self):
        for raw in (b'', self.frame() * 2, self.frame().replace(s.COMPOSITION_FRAME_TAG, s.DIRECT_FRAME_TAG)):
            with self.assertRaises(s.SupervisionError): s.extract_composition_frame(raw)

    def test_bad_size_or_trailer_rejected(self):
        for raw in (self.frame().replace(b'2\n', b'02\n', 1),
                    self.frame().replace(b'2\n', b'3\n', 1), self.frame()[:-1],
                    self.frame() + b'\x1eEND\n'):
            with self.assertRaises(s.SupervisionError): s.extract_composition_frame(raw)

    def test_whole_frame_and_stdout_caps(self):
        with self.assertRaisesRegex(s.SupervisionError, 'whole_frame_budget'):
            s.extract_composition_frame(self.frame(b'x' * 131072))
        with self.assertRaisesRegex(s.SupervisionError, 'stdout_budget'):
            s.extract_composition_frame(b'x' * 262145)

    def test_v2_route_rejects_old_stage4_and_mixed_frame_streams(self):
        self.assertEqual(s.COMPOSITION_FRAME_TAG, b'\x1eNORTHSTAR_STAGE4_COMPOSITION_V2 ')
        old = self.frame().replace(s.COMPOSITION_FRAME_TAG, b'\x1eNORTHSTAR_STAGE4_COMPOSITION_V1 ')
        for raw in (old, old + self.frame(), self.frame() + old):
            with self.assertRaisesRegex(s.SupervisionError, '^composition_frame_count$'):
                s.extract_composition_frame(raw)

    def test_codec_version_selection_is_explicit_in_both_directions(self):
        # Canonical named rejection used ONLY as a constructed codec control.
        # It is not an owner-produced or authenticated positive observation.
        envelope = {'schema': semantic.EVIDENCE_SCHEMA, 'entry': semantic.ENTRY,
            'input_sha256': '0' * 64, 'rejection': 'Json', 'execution': None,
            'resource_stop': None, 'identity_map': [], 'facts': [],
            'observation_status': {'kind': 'Complete', 'data': {}}}
        payload = semantic._canonical(envelope)
        old = b'\x1eNORTHSTAR_STAGE4_COMPOSITION_V1 ' + str(len(payload)).encode() + b'\n' + payload + s.DIRECT_FRAME_END
        with self.assertRaisesRegex(semantic.Stage4Invalid, '^Schema:CompactVersion$'):
            semantic.parse_frame(old, wire_version='V2')
        with self.assertRaisesRegex(semantic.Stage4Invalid, '^Encoding:FrameHeader$'):
            semantic.parse_frame(self.frame(), wire_version='V1')


class ExactMutationSourceControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Exact reviewed source bytes, not a built mutant or a saved observation.
        cls.owner = (Path(__file__).parent.parent / build.MUTATION_PATH).read_bytes()
        if s.fingerprint(cls.owner) != build.BASELINE_SOURCE_SHA256:
            raise AssertionError('Final source rebind required before source controls')

    def arguments(self, mutant):
        baseline = self.owner
        offset = baseline.index(build.FUNCTION_PREFIX) + len(build.FUNCTION_PREFIX)
        current = baseline[:offset] + build.MUTANT_BRANCH + baseline[offset + len(build.BASELINE_BRANCH):] if mutant else baseline
        source = {build.MUTATION_PATH: s.fingerprint(current)}
        baseline_map = {build.MUTATION_PATH: s.fingerprint(baseline)}
        contract = {'provenance': {'source_files': source, 'build_record_file_sha256': 'a' * 64},
                    'release': {'ordinary_acceptance_sha256': '1' * 64}}
        record = {'artifact_role': 'auth-cache-bypass-mutant' if mutant else 'baseline',
            'source': {'bytes': len(current), 'manifest_sha256': s.object_hash(source), 'patch_sha256': None},
            'original': {'sha256': 'b' * 64}, 'runnable': {'sha256': 'c' * 64}, 'ancestry': None}
        if mutant:
            ancestry = {'baseline_build_record_file_sha256': 'd' * 64,
                'baseline_source_sha256': s.object_hash(baseline_map), 'baseline_source_bytes': len(baseline),
                'baseline_original_sha256': 'e' * 64, 'baseline_runnable_sha256': 'f' * 64,
                'baseline_ordinary_acceptance_sha256': '1' * 64, 'path': build.MUTATION_PATH,
                'offset': offset, 'before_sha256': s.fingerprint(baseline), 'after_sha256': s.fingerprint(current),
                'removed': build.BASELINE_BRANCH.decode(), 'inserted': build.MUTANT_BRANCH.decode()}
            record['ancestry'] = ancestry
            record['source']['patch_sha256'] = s.object_hash({key: ancestry[key] for key in
                ('path', 'offset', 'before_sha256', 'after_sha256', 'removed', 'inserted')})
        return record, contract, current

    def test_exact_baseline_and_in_memory_branch_delta(self):
        for mutant in (False, True): build._ancestry(*self.arguments(mutant))

    def test_no_flush_or_callback_preserving_mutation_rejected(self):
        for key, value in (('path', 'src/xmpp/mod.rs'), ('inserted', '        Ok(())\n'),
                           ('removed', '            publish(owners).await,\n')):
            record, contract, current = self.arguments(True); record['ancestry'][key] = value
            with self.assertRaises(build.base.BuildRecordError): build._ancestry(record, contract, current)

    def test_offset_and_baseline_reference_rejected(self):
        for key, value in (('offset', 0), ('before_sha256', '0' * 64),
                           ('baseline_source_sha256', '0' * 64), ('baseline_source_bytes', 1)):
            record, contract, current = self.arguments(True); record['ancestry'][key] = value
            with self.assertRaises(build.base.BuildRecordError): build._ancestry(record, contract, current)

    def test_second_owner_edit_rejected_even_with_self_rehashed_source(self):
        record, contract, current = self.arguments(True)
        current += b'\n// unrelated source edit\n'
        record['source']['bytes'] = len(current)
        record['ancestry']['after_sha256'] = s.fingerprint(current)
        contract['provenance']['source_files'][build.MUTATION_PATH] = s.fingerprint(current)
        with self.assertRaisesRegex(build.base.BuildRecordError, 'reverse_exact_baseline'):
            build._ancestry(record, contract, current)

    def test_second_source_map_edit_rejected(self):
        record, contract, current = self.arguments(True)
        contract['provenance']['source_files']['src/other.rs'] = '0' * 64
        with self.assertRaisesRegex(build.base.BuildRecordError, 'sole_source_delta'):
            build._ancestry(record, contract, current)

    def test_missing_current_source_never_authenticates(self):
        record, contract, _ = self.arguments(True)
        with self.assertRaisesRegex(build.base.BuildRecordError, 'current_owner_source_required'):
            build._ancestry(record, contract, None)


class BuildRecordBoundaryControls(unittest.TestCase):
    def test_stage3_contract_rejected_before_record_decode(self):
        contract = metadata_contract(); contract['schema'] = s.DIRECT_CONTRACT_SCHEMA
        with self.assertRaisesRegex(build.base.BuildRecordError, 'stage4_build_contract'):
            build.validate_build_record(b'', contract, verified_source_summary={})

    def test_external_hash_precedes_record_parsing(self):
        contract = metadata_contract()
        with self.assertRaisesRegex(build.base.BuildRecordError, 'build_record_file_sha256'):
            build.validate_build_record(b'\xff not JSON', contract, verified_source_summary={})

    def test_postbuild_review_packet_is_not_a_build_record_field(self):
        contract = metadata_contract()
        acceptance = {'source_sha256': contract['provenance']['source_sha256'],
                      'binary_sha256': contract['provenance']['binary_sha256']}
        for key in ('ordinary_acceptance_sha256', 'source_review_sha256', 'effect_review_sha256'):
            acceptance[key] = contract['release'][key]
        record = {'acceptance': acceptance, 'runnable': {'sha256': acceptance['binary_sha256']}}
        build._acceptance(record, contract)
        record['acceptance']['allowed_starts_sha256'] = contract['release']['allowed_starts_sha256']
        with self.assertRaisesRegex(build.base.BuildRecordError, 'stage4_acceptance_fields'):
            build._acceptance(record, contract)

    def test_ordinary_acceptance_must_match_external_contract(self):
        contract = metadata_contract()
        record = {'acceptance': {'source_sha256': contract['provenance']['source_sha256'],
            'binary_sha256': contract['provenance']['binary_sha256'],
            'source_review_sha256': contract['release']['source_review_sha256'],
            'effect_review_sha256': contract['release']['effect_review_sha256'],
            'ordinary_acceptance_sha256': '0' * 64},
            'runnable': {'sha256': contract['provenance']['binary_sha256']}}
        with self.assertRaisesRegex(build.base.BuildRecordError, 'stage4_review_contract_binding'):
            build._acceptance(record, contract)


class OccurrenceGuardControls(unittest.TestCase):
    def detached_guard_inputs(self):
        """Guard-only synthetic values, never passed to the actual corpus reader."""
        out = []
        for position, count in enumerate((16, 3, 16, 3)):
            invocation = 'synthetic-' + str(position)
            tuples = [(invocation, 'contract-' + str(position), 'mode', index, 'occurrence-' + str(index),
                       100, 'synthetic-record-' + str(position) + '-' + str(index), 'same-input', 'same-frame')
                      for index in range(count)]
            out.append({'contract': {'run_id': invocation, 'evidence_dir': '/synthetic/' + invocation},
                        'authority': {'caller_evidence': {'invocation_id': invocation}}, 'tuples': tuples})
        return out

    def test_guard_allows_pid_and_literal_hash_reuse_with_distinct_occurrences(self):
        join._distinct_occurrences(self.detached_guard_inputs())

    def test_guard_rejects_duplicate_whole_tuple(self):
        values = self.detached_guard_inputs(); values[1]['tuples'][2] = values[1]['tuples'][1]
        with self.assertRaisesRegex(s.SupervisionError, 'reused_process_or_evidence_tuple'):
            join._distinct_occurrences(values)

    def test_guard_rejects_duplicate_record_hash_despite_new_ordinal(self):
        values = self.detached_guard_inputs(); value = list(values[1]['tuples'][2])
        value[6] = values[1]['tuples'][1][6]; values[1]['tuples'][2] = tuple(value)
        with self.assertRaisesRegex(s.SupervisionError, 'reused_process_or_evidence_tuple'):
            join._distinct_occurrences(values)

    def test_guard_rejects_missing_occurrence(self):
        values = self.detached_guard_inputs(); values[1]['tuples'].pop()
        with self.assertRaisesRegex(s.SupervisionError, 'reused_process_or_evidence_tuple'):
            join._distinct_occurrences(values)

    def test_guard_rejects_reused_external_invocation(self):
        values = self.detached_guard_inputs()
        values[1]['authority']['caller_evidence'] = values[0]['authority']['caller_evidence']
        with self.assertRaisesRegex(s.SupervisionError, 'distinct_external_invocations'):
            join._distinct_occurrences(values)


class DistinctRootSourceControls(unittest.TestCase):
    def test_saved_worker_still_rejects_foreign_executing_root(self):
        contract = metadata_contract()
        with patch.object(s, '_check_source_data', side_effect=AssertionError('data reader reached')) as read:
            with self.assertRaisesRegex(s.SupervisionError, '^executing_helper_root_changed$'):
                s._check_worker_sources(contract)
        read.assert_not_called()

    def test_retained_route_authenticates_unmodified_external_root_as_data(self):
        contract = metadata_contract(s.AUTH_CACHE_PROFILE)
        contract['root'] = '/synthetic/retained-mutant'
        marker = object()
        with patch.object(s, '_check_source_data', return_value=marker) as read:
            self.assertIs(s.check_retained_source_data(contract), marker)
        self.assertEqual(read.call_args.args[0]['root'], '/synthetic/retained-mutant')
        self.assertEqual(read.call_args.args[0], contract)

    def helper_contracts(self):
        values = [metadata_contract(profile) for profile in
                  (s.COMPOSITION_PROFILE, s.AUTH_CACHE_PROFILE, s.COMPOSITION_PROFILE, s.AUTH_CACHE_PROFILE)]
        root = Path(s.__file__).parent.parent.parent
        values[0]['root'] = str(root)
        values[1]['root'] = '/synthetic/retained-mutant'
        values[2]['root'] = str(root)
        values[3]['root'] = '/synthetic/retained-mutant'
        values[2]['mode'] = values[3]['mode'] = 'replay'
        # Isolated helper-routing inputs only. No saved authority is fabricated.
        # Mock read payloads are fixed relative-path bytes; these synthetic hash
        # maps are used only by the direct mocked guard, never the corpus API.
        for value in values:
            value['helper_source_files'] = {name: s.fingerprint(name.encode())
                                           for name in value['helper_source_files']}
        return tuple(values), root

    def test_join_rejects_foreign_executing_baseline_root_before_reads(self):
        values, _ = self.helper_contracts(); values[0]['root'] = '/synthetic/other-baseline'
        with patch.object(s, 'check_direct_import_layout', side_effect=AssertionError('layout reached')) as check:
            with self.assertRaisesRegex(s.SupervisionError,
                    '^composition_relation_loaded_helper_path:scripts/lib/controlled_admission_supervision.py$'):
                join._authenticate_executing_helpers(values)
        check.assert_not_called()

    def test_join_rejects_different_external_helper_map_before_reads(self):
        values, _ = self.helper_contracts()
        values[1]['helper_source_files']['scripts/lib/stage4_case.py'] = '0' * 64
        with patch.object(s, 'check_direct_import_layout', side_effect=AssertionError('layout reached')) as check:
            with self.assertRaisesRegex(s.SupervisionError, '^composition_relation_executing_helper_map$'):
                join._authenticate_executing_helpers(values)
        check.assert_not_called()

    def test_executing_helper_reads_stay_in_baseline_root(self):
        values, root = self.helper_contracts()
        with patch.object(s, 'check_direct_import_layout') as layout, \
             patch.object(s, '_path_metadata') as metadata, \
             patch.object(s, 'read_regular_bounded', side_effect=lambda path, cap:
                          str(path.relative_to(root)).encode()) as read:
            metadata.return_value.st_mode = 0o100644
            join._authenticate_executing_helpers(values)
        self.assertEqual(layout.call_count, 2)
        self.assertEqual(read.call_count, len(values[0]['helper_source_files']))
        self.assertTrue(all(call.args[0].is_relative_to(root) for call in read.call_args_list))

    def test_transitive_direct_build_module_must_be_from_baseline_root(self):
        values, _ = self.helper_contracts()
        with patch.object(build.base, '__file__', '/synthetic/retained-mutant/scripts/lib/direct_build_record.py'):
            with self.assertRaisesRegex(s.SupervisionError,
                    '^composition_relation_loaded_helper_path:scripts/lib/direct_build_record.py$'):
                join._authenticate_executing_helpers(values)

    def test_loaded_compact_codec_must_be_from_baseline_root(self):
        values, _ = self.helper_contracts()
        with patch.object(semantic.stage4_compact, '__file__', '/synthetic/retained-mutant/scripts/lib/stage4_compact.py'):
            with self.assertRaisesRegex(s.SupervisionError,
                    '^composition_relation_loaded_helper_path:scripts/lib/stage4_compact.py$'):
                join._authenticate_executing_helpers(values)


def _require_exact_supervision_rejection(action, expected_diagnostic):
    """Control helper, never an acceptance path or a generic exception catch."""
    try:
        action()
    except s.SupervisionError as error:
        if type(error) is not s.SupervisionError or str(error) != expected_diagnostic:
            raise AssertionError('Unexpected rejection type or diagnostic') from error
    else:
        raise AssertionError('Control accepted instead of rejecting: ' + expected_diagnostic)


class ExactNegativeDiagnosticControls(unittest.TestCase):
    def raise_error(self, error):
        raise error

    def test_exact_supervision_diagnostic_is_required(self):
        _require_exact_supervision_rejection(lambda: self.raise_error(s.SupervisionError('expected')), 'expected')
        with self.assertRaisesRegex(AssertionError, '^Unexpected rejection type or diagnostic$'):
            _require_exact_supervision_rejection(lambda: self.raise_error(s.SupervisionError('unrelated')), 'expected')

    def test_unrelated_file_failure_is_not_control_coverage(self):
        with self.assertRaisesRegex(OSError, '^unrelated read failure$'):
            _require_exact_supervision_rejection(lambda: self.raise_error(OSError('unrelated read failure')), 'expected')

    def test_subclass_is_not_the_exact_exception_type(self):
        class OtherFailure(s.SupervisionError):
            pass
        with self.assertRaisesRegex(AssertionError, '^Unexpected rejection type or diagnostic$'):
            _require_exact_supervision_rejection(lambda: self.raise_error(OtherFailure('expected')), 'expected')

    def test_unexpected_success_is_not_control_coverage(self):
        with self.assertRaisesRegex(AssertionError, '^Control accepted instead of rejecting: expected$'):
            _require_exact_supervision_rejection(lambda: None, 'expected')


class InventoriedRecordControls(unittest.TestCase):
    """Detached metadata controls only; no actual record or authority is minted.

    Small synthetic maps exercise comparisons with explicit test-local frozen
    constants. Routing mocks exercise delegation, not saved positive coverage.
    """
    def reject(self, diagnostic, action):
        try:
            action()
        except build.base.BuildRecordError as error:
            self.assertIs(type(error), build.base.BuildRecordError)
            self.assertEqual(str(error), diagnostic)
        else:
            self.fail('Expected exact build-record rejection: ' + diagnostic)

    def reference(self, name):
        return {'path': '/synthetic/receipts/' + name, 'bytes': 20,
                'sha256': s.fingerprint(name.encode())}

    def result(self):
        return {'termination': 'Exited', 'exit_code': 0,
                'merged': {'bytes': 0, 'sha256': s.fingerprint(b''), 'complete': True},
                'collector_receipt': self.reference('collector'),
                'owner_receipt': self.reference('owner'), 'postcheck': self.reference('postcheck')}

    def metadata(self):
        contract = metadata_contract()
        contract['provenance']['toolchain'] = build.INVENTORY_TOOLCHAIN_TAG
        helper = 'scripts/lib/stage4_build_record.py'
        sources = {'Cargo.lock': s.fingerprint(b'lock'), 'rust-toolchain.toml': s.fingerprint(b'toolchain'),
                   build.MUTATION_PATH: build.BASELINE_SOURCE_SHA256, helper: s.fingerprint(b'helper')}
        contract['provenance'].update(source_files=sources, source_sha256=s.object_hash(sources),
                                      cargo_lock_sha256=sources['Cargo.lock'])
        contract['helper_source_files'] = {helper: sources[helper]}
        summary = {'sha256': s.object_hash(sources), 'files': 4, 'bytes': 1000}
        projected = {key: value for key, value in sources.items() if key != helper}
        compilation_summary = {'sha256': s.object_hash(projected), 'files': 3, 'bytes': 900}
        compilation = {'root': '/synthetic/compiled-source', 'source_sha256': compilation_summary['sha256'],
            'file_count': 3, 'bytes': 900,
            'helper_overlay_review_sha256': contract['release']['effect_review_sha256']}
        for name in ('before_snapshot', 'after_snapshot', 'build_postcheck', 'runtime_tools',
                     'toolchain_manifest', 'public_correspondence'):
            compilation[name] = self.reference(name)
        compilation['public_correspondence']['sha256'] = build.PUBLIC_CORRESPONDENCE_SHA256
        tool_bin = '/synthetic/rustup/toolchains/' + build.base.TOOLCHAIN + '/bin'
        tool = lambda name: {'path': tool_bin + '/' + name, 'bytes': 80, 'mode': 0o755,
                             'sha256': s.fingerprint(('synthetic ' + name).encode())}
        tools = {'cargo': tool('cargo'), 'rustc': tool('rustc'), 'rustup_toolchain': build.base.TOOLCHAIN}
        contract['provenance']['compiler_sha256'] = tools['rustc']['sha256']
        exports = dict(build.base.BUILD_CONTROLS, PATH=tool_bin + ':/usr/bin:/bin',
            CARGO_HOME='/synthetic/cargo-home', CARGO_TARGET_DIR='/synthetic/target',
            RUSTUP_HOME='/synthetic/rustup', PYTHONDONTWRITEBYTECODE='1', PYTHONSAFEPATH='1',
            PYTHONNOUSERSITE='1')
        original = {'path': '/synthetic/preserved-original', 'sha256': s.fingerprint(b'original'),
                    'bytes': 200000000, 'mode': 0o755}
        runnable = {'path': contract['binary'], 'sha256': contract['provenance']['binary_sha256'],
                    'bytes': 100000000, 'mode': 0o755}
        result = self.result(); result['postcheck'] = compilation['build_postcheck']
        build_data = {'cwd': compilation['root'], 'argv': ['cargo', *build.INVENTORY_ARGUMENTS],
            'environment': {'driver_exports': exports, 'rustc_override_absent': True,
                'scrubbed_owner_environment_receipt': self.reference('preflight'),
                'driver_receipt': self.reference('driver')},
            'target': build.base.TARGET, 'profile': 'test', 'package': 'rust-xmpp-server',
            'bin': 'rust-xmpp-server', 'features': [], 'target_dir': '/synthetic/target',
            'cache_policy': 'fresh-target-dir', 'result': result,
            'selected_artifact': {'executable': '/synthetic/target/debug/deps/test',
                'sha256': original['sha256'], 'bytes': original['bytes'], 'test_count': 2175,
                'benchmark_count': 0, 'saved_entry': build.INVENTORY_ENTRY, 'matching_artifacts': 1,
                'inventory_receipt': self.reference('inventory'),
                'preservation_receipt': self.reference('preservation')}}
        strip = {'path': '/usr/bin/strip', 'sha256': s.fingerprint(b'synthetic strip'),
                 'bytes': 80, 'mode': 0o755}
        derivation = {'kind': 'gnu-strip-all-no-merge-notes-merged-v1', 'tool': strip,
            'version_verbose': 'GNU strip synthetic metadata only', 'tool_evidence': self.reference('tool'),
            'cwd': compilation['root'], 'argv': [strip['path'], '--strip-all', '--no-merge-notes',
                '-o', runnable['path'], original['path']],
            'environment': {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'},
            'result': self.result(), 'input_unchanged': True, 'tool_unchanged': True,
            'output_absent_before': True, 'elf_comparison_receipt': self.reference('postcheck'),
            'structural_equivalence_not_established': True, 'runtime_behavior_not_tested': True}
        acceptance = {key: contract['release'][key] for key in
                      ('ordinary_acceptance_sha256', 'source_review_sha256', 'effect_review_sha256')}
        acceptance.update(source_sha256=summary['sha256'], binary_sha256=runnable['sha256'])
        record = {'schema': build.INVENTORY_SCHEMA, 'scope': {'project_local_complete': True,
            'external_supply_chain_complete': False, 'reproducible_build_claimed': False},
            'artifact_role': 'baseline', 'source': {'manifest_sha256': summary['sha256'],
                'file_count': 4, 'bytes': 1000, 'patch_sha256': None, 'cargo_lock_sha256': sources['Cargo.lock'],
                'toolchain_file_sha256': sources['rust-toolchain.toml'],
                'after_preparation': build.base.INVENTORY_OBSERVATION},
            'compilation': compilation, 'tools': tools, 'build': build_data, 'original': original,
            'runnable': runnable, 'derivation': derivation, 'ancestry': None, 'acceptance': acceptance}
        return record, contract, summary, compilation_summary

    def source_check(self, record, contract, summary, measured):
        # This seam only scales the frozen source set for a detached unit input.
        # Real validation keeps the separate exact941/18,596,296/SHA control below.
        sources = contract['provenance']['source_files']
        projected = {key: value for key, value in sources.items() if key not in contract['helper_source_files']}
        with patch.multiple(build, COMPILATION_FILES=3, COMPILATION_BASELINE_BYTES=900,
                            COMPILATION_BASELINE_SHA256=s.object_hash(projected)):
            return build._inventory_source(record, contract, summary, measured)

    def decode_route(self, record, contract, summary=None, measured=None):
        raw = build.base._canonical(record) + b'\n'
        contract = copy.deepcopy(contract)
        contract['provenance']['build_record_file_sha256'] = s.fingerprint(raw)
        return build.validate_build_record(raw, contract, verified_source_summary=summary,
                                           verified_compilation_summary=measured)

    def test_exact_current_projection_and_ack_pins(self):
        self.assertEqual((build.COMPILATION_FILES, build.COMPILATION_BASELINE_BYTES), (941, 18596296))
        self.assertEqual(build.COMPILATION_BASELINE_SHA256,
                         '26342ca7654011d6fa9e94aa514220a1d9614f18d670cd2ec0fc3a758369f611')
        self.assertEqual(s.COMPOSITION_V2_SOURCE_HASHES['scripts/lib/stage4_case.py'],
                         'aa7daefd7265c6804443fcf44c94ffb9c63a7561e6da1577c1e31fe2e94095c0')
        self.assertEqual(s.COMPOSITION_V2_SOURCE_HASHES['scripts/test-stage4-compact-semantic-controls.py'],
                         'dc81c763531cbf178936920830a4751d5ca9abeaa3aee62216f4b80cfe13f968')

    def test_explicit_inventory_toolchain_tag(self):
        value = metadata_contract(); value['provenance']['toolchain'] = build.INVENTORY_TOOLCHAIN_TAG
        self.assertEqual(s.validate_contract(value), value)
        self.assertEqual(adapter.validate_provenance(value['provenance']), value['provenance'])

    def test_unknown_toolchain_tag_rejected(self):
        value = metadata_contract(); value['provenance']['toolchain'] = 'rustup-toolchain:other'
        with self.assertRaisesRegex(s.SupervisionError, '^provenance_toolchain_adapter$'):
            s.validate_contract(value)

    def test_inventory_hash_still_precedes_parse(self):
        _, contract, _, _ = self.metadata()
        self.reject('build_record_file_sha256', lambda: build.validate_build_record(
            b'\xff', contract, verified_source_summary={}, verified_compilation_summary={}))

    def test_schema_and_toolchain_pairs_are_closed(self):
        for schema, tag in ((build.SCHEMA, build.INVENTORY_TOOLCHAIN_TAG),
                            (build.INVENTORY_SCHEMA, 'rustc 1.97.1 synthetic')):
            record, contract, _, _ = self.metadata(); record['schema'] = schema
            contract['provenance']['toolchain'] = tag
            self.reject('stage4_record_toolchain_mode', lambda: self.decode_route(record, contract))

    def test_unknown_record_schema_rejected(self):
        record, contract, _, _ = self.metadata(); record['schema'] += '-unknown'
        self.reject('stage4_build_record_schema', lambda: self.decode_route(record, contract))

    def test_old_route_delegates_only_unchanged_validators(self):
        record, contract, summary, measured = self.metadata()
        record['schema'] = build.SCHEMA; del record['compilation']
        contract['provenance']['toolchain'] = 'rustc 1.97.1 synthetic'
        with patch.object(build.base, '_source') as source, patch.object(build.base, '_build') as cargo, \
             patch.object(build.base, '_derivation') as derivative, patch.object(build, '_ancestry'), \
             patch.object(build, '_inventory_source', side_effect=AssertionError('new route reached')):
            self.decode_route(record, contract, summary, measured)
        self.assertEqual(source.call_args.args[2], summary)
        cargo.assert_called_once(); derivative.assert_called_once()

    def test_new_route_delegates_only_inventory_validators(self):
        record, contract, summary, measured = self.metadata()
        with patch.object(build, '_inventory_source') as source, patch.object(build, '_inventory_build') as cargo, \
             patch.object(build, '_inventory_derivation') as derivative, patch.object(build, '_ancestry'), \
             patch.object(build.base, '_source', side_effect=AssertionError('old route reached')):
            self.decode_route(record, contract, summary, measured)
        self.assertEqual(source.call_args.args[2:], (summary, measured))
        cargo.assert_called_once(); derivative.assert_called_once()

    def test_mixed_record_ancestry_rejected_before_role_or_source(self):
        for a, b in ((build.SCHEMA, build.INVENTORY_SCHEMA), (build.INVENTORY_SCHEMA, build.SCHEMA)):
            self.reject('stage4_relation_record_variants', lambda: build.validate_baseline_ancestry(
                {}, {'schema': a}, {}, {'schema': b}))

    def test_compilation_summary_uses_same_reads_and_fixed_helper_set(self):
        contract = metadata_contract()
        sources = {name: s.fingerprint(name.encode()) for name in contract['provenance']['source_files']}
        contract['provenance'].update(source_files=sources, source_sha256=s.object_hash(sources))
        root = Path(contract['root'])
        with patch.object(s, 'check_direct_inventory') as inventory, \
             patch.object(s, 'read_regular_bounded', side_effect=lambda path, cap:
                          str(path.relative_to(root)).encode()) as read:
            result = s._check_source_data(contract)
        projected = {key: value for key, value in sources.items() if key not in s.COMPOSITION_HELPER_FILES}
        self.assertEqual(result['compilation_summary'], {'sha256': s.object_hash(projected),
            'files': len(projected), 'bytes': sum(len(key.encode()) for key in projected)})
        self.assertEqual(inventory.call_count, 2)
        self.assertEqual(read.call_count, len(sources))
        self.assertEqual(len({call.args[0] for call in read.call_args_list}), len(sources))

    def test_stage3_source_return_shape_unchanged(self):
        profile = s.fixed_profile(s.DIRECT_PROFILE)
        sources = {name: s.fingerprint(name.encode()) for name in profile['helpers']}
        contract = {'schema': s.DIRECT_CONTRACT_SCHEMA, 'profile': s.DIRECT_PROFILE,
            'root': '/synthetic/stage3', 'helper_source_files': sources,
            'provenance': {'source_files': sources, 'source_sha256': s.object_hash(sources)},
            'budgets': profile['budgets']}
        with patch.object(s, 'check_direct_inventory'), patch.object(s, 'read_regular_bounded',
                side_effect=lambda path, cap: str(path.relative_to(contract['root'])).encode()):
            self.assertEqual(set(s._check_source_data(contract)), {'summary', 'mutation_bytes'})

    def test_compilation_summary_forwarding_is_stage4_only(self):
        for profile_id in (s.COMPOSITION_PROFILE, s.DIRECT_PROFILE):
            contract = metadata_contract(); contract['profile'] = profile_id
            if profile_id == s.DIRECT_PROFILE: contract['schema'] = s.DIRECT_CONTRACT_SCHEMA
            verified = {'summary': {}, 'mutation_bytes': b'source'}
            if profile_id == s.COMPOSITION_PROFILE: verified['compilation_summary'] = {'measured': True}
            with patch.object(s, '_path_metadata') as metadata, \
                 patch.object(s, 'read_regular_bounded', return_value=b'record'), \
                 patch.object(adapter, 'check_current_provenance') as check:
                metadata.return_value.st_mode = 0o100644
                s._current_build_record(adapter, contract, verified)
            self.assertEqual('verified_compilation_summary' in check.call_args.kwargs,
                             profile_id == s.COMPOSITION_PROFILE)

    def test_independent_compilation_summary_required(self):
        record, contract, summary, measured = self.metadata()
        self.source_check(record, contract, summary, measured)
        self.reject('verified_compilation_fields', lambda: self.source_check(record, contract, summary, None))
        measured['sha256'] = '0' * 64
        self.reject('inventory_compilation_projection', lambda: self.source_check(record, contract, summary, measured))

    def test_record_cannot_replace_measured_compilation_summary(self):
        record, contract, summary, measured = self.metadata()
        record['compilation']['bytes'] += 1
        self.reject('inventory_compilation_summary_binding',
                    lambda: self.source_check(record, contract, summary, measured))

    def test_source_record_summary_rejects_float_and_bool(self):
        for key, diagnostic in (('file_count', 'inventory_source_record_files'),
                                ('bytes', 'inventory_source_record_bytes')):
            for convert in (float, bool):
                record, contract, summary, measured = self.metadata()
                record['source'][key] = convert(record['source'][key])
                self.reject(diagnostic, lambda: self.source_check(record, contract, summary, measured))

    def test_compilation_record_summary_rejects_float_and_bool(self):
        for key, diagnostic in (('file_count', 'inventory_compilation_record_files'),
                                ('bytes', 'inventory_compilation_record_bytes')):
            for convert in (float, bool):
                record, contract, summary, measured = self.metadata()
                record['compilation'][key] = convert(record['compilation'][key])
                self.reject(diagnostic, lambda: self.source_check(record, contract, summary, measured))

    def test_helper_overlay_requires_external_effect_review(self):
        record, contract, summary, measured = self.metadata()
        record['compilation']['helper_overlay_review_sha256'] = '0' * 64
        self.reject('inventory_helper_overlay_review_binding',
                    lambda: self.source_check(record, contract, summary, measured))

    def test_public_correspondence_requires_exact_reviewed_receipt(self):
        record, contract, summary, measured = self.metadata()
        record['compilation']['public_correspondence']['sha256'] = '0' * 64
        self.reject('inventory_public_correspondence',
                    lambda: self.source_check(record, contract, summary, measured))

    def test_inventory_build_accepts_only_detached_list_metadata(self):
        record, contract, _, _ = self.metadata()
        build._inventory_build(record, contract)
        self.assertNotEqual(record['compilation']['root'], contract['root'])

    def test_no_run_recipe_cannot_claim_list_variant(self):
        record, contract, _, _ = self.metadata()
        record['build']['argv'] = [record['tools']['cargo']['path'], *build.base.BUILD_ARGUMENTS]
        self.reject('inventory_build_argv', lambda: build._inventory_build(record, contract))

    def test_build_root_is_compilation_root_not_loaded_helper_root(self):
        record, contract, _, _ = self.metadata(); record['build']['cwd'] = contract['root']
        self.reject('inventory_build_root_binding', lambda: build._inventory_build(record, contract))

    def test_recorded_path_and_absent_rustc_override_are_required(self):
        for changed, diagnostic in (('PATH', 'inventory_path_tool_binding'), ('RUSTC', 'inventory_driver_exports')):
            record, contract, _, _ = self.metadata()
            record['build']['environment']['driver_exports'][changed] = '/other/compiler'
            self.reject(diagnostic, lambda: build._inventory_build(record, contract))
        record, contract, _, _ = self.metadata()
        record['build']['environment']['rustc_override_absent'] = False
        self.reject('inventory_rustc_override', lambda: build._inventory_build(record, contract))

    def test_inventory_selection_stays_bound_to_original_and_entry(self):
        for key, value, diagnostic in (('sha256', '0' * 64, 'selected_original_binding'),
                ('benchmark_count', 1, 'inventory_benchmark_count'),
                ('saved_entry', 'other::entry', 'inventory_saved_entry')):
            record, contract, _, _ = self.metadata(); record['build']['selected_artifact'][key] = value
            self.reject(diagnostic, lambda: build._inventory_build(record, contract))

    def test_merged_result_rejects_incomplete_failed_or_split_claims(self):
        good = self.result(); build._merged_result(good, 'test')
        bad = copy.deepcopy(good); bad['merged']['complete'] = False
        self.reject('test_merged_incomplete', lambda: build._merged_result(bad, 'test'))
        bad = copy.deepcopy(good); bad['exit_code'] = 1
        self.reject('test_exit_code', lambda: build._merged_result(bad, 'test'))
        bad = copy.deepcopy(good); bad['stdout'] = bad.pop('merged')
        self.reject('test_fields', lambda: build._merged_result(bad, 'test'))

    def test_derivative_detached_metadata_keeps_static_only_limit(self):
        record, contract, _, _ = self.metadata()
        build._inventory_derivation(record, contract)
        self.assertTrue(record['derivation']['runtime_behavior_not_tested'])

    def test_derivative_recipe_and_compilation_cwd_are_closed(self):
        record, contract, _, _ = self.metadata(); record['derivation']['argv'][1] = '--strip-debug'
        self.reject('derivation_argv', lambda: build._inventory_derivation(record, contract))
        record, contract, _, _ = self.metadata(); record['derivation']['cwd'] = contract['root']
        self.reject('inventory_derivation_root_binding', lambda: build._inventory_derivation(record, contract))
        record, contract, _, _ = self.metadata(); record['derivation']['kind'] = 'gnu-strip-all-no-merge-notes-v1'
        self.reject('inventory_derivation_kind', lambda: build._inventory_derivation(record, contract))

    def test_derivative_cannot_relax_existing_runnable_cap(self):
        record, contract, _, _ = self.metadata(); record['runnable']['bytes'] = build.base.MAX_BINARY_BYTES + 1
        self.reject('runnable_byte_cap', lambda: build._inventory_derivation(record, contract))

    def test_derivative_cannot_claim_runtime_or_structural_equivalence(self):
        for key in ('runtime_behavior_not_tested', 'structural_equivalence_not_established'):
            record, contract, _, _ = self.metadata(); record['derivation'][key] = False
            self.reject('inventory_derivation_observations', lambda: build._inventory_derivation(record, contract))

    def test_old_stream_reader_stays_strict(self):
        self.reject('old_fields', lambda: build.base._result(self.result(), 'old'))
        record, contract, _, _ = self.metadata()
        self.reject('derivation_fields', lambda: build.base._derivation(record, contract))


def actual_control_suite(authorities):
    """Later real-material controls; caller must supply the ORIGINAL four authorities.

    This function is deliberately not in the default ordinary unittest suite.
    It never creates, edits, starts or simulates a saved corpus. Each negative
    uses detached authority metadata; pristine actual files are re-read before
    AND after every rejection. Missing prerequisites raise, never skip/pass.
    """
    names = ('baseline_record', 'mutant_record', 'baseline_replay', 'mutant_replay')
    s.exact(authorities, ' '.join(names), 'actual_four_authorities_required')
    original = copy.deepcopy(authorities)
    results = []

    def accepted():
        return join.authenticate_four_role_relation(**copy.deepcopy(original))

    def reject(label, expected_diagnostic, change):
        accepted()
        try:
            changed = copy.deepcopy(original)
            change(changed)
            _require_exact_supervision_rejection(
                lambda: join.authenticate_four_role_relation(**changed), expected_diagnostic)
        finally:
            # Also re-read pristine facts when an unexpected failure aborts the
            # negative; that failure is never recorded as target coverage.
            accepted()
        results.append({'id': label, 'exception_type': 'SupervisionError',
                        'diagnostic': expected_diagnostic})

    accepted()
    for name in names:
        reject(name + ':wrong_contract_hash', 'composition_relation_external_contract_bytes', lambda data, name=name:
               data[name].__setitem__('contract_file_sha256', '0' * 64))
        reject(name + ':missing_capture', 'capture_fields', lambda data, name=name: data[name].__setitem__('capture', {}))
        reject(name + ':missing_external_caller', 'external_caller_evidence_required', lambda data, name=name:
               data[name].__setitem__('caller_evidence', {}))
        reject(name + ':wrong_role', 'composition_provenance_version', lambda data, name=name:
               data[name]['contract']['provenance'].__setitem__('artifact_role', 'no-flush'))
    reject('ordinary_or_semantic_result_cannot_replace_actual_corpus', 'composition_relation_external_authority',
           lambda data: data.__setitem__('baseline_record', {'category': 'Pass'}))
    reject('reused_mutant_record_as_replay', 'composition_relation_profile_mode',
           lambda data: data.__setitem__('mutant_replay', copy.deepcopy(data['mutant_record'])))
    reject('reused_baseline_record_as_replay', 'composition_relation_profile_mode',
           lambda data: data.__setitem__('baseline_replay', copy.deepcopy(data['baseline_record'])))
    reject('mutant_cannot_supply_reduced_baseline', 'composition_relation_profile_mode',
           lambda data: data.__setitem__('baseline_record', copy.deepcopy(data['mutant_record'])))
    return {'pristine': accepted(), 'negative_controls': results,
            'scope': 'ActualAuthenticatedMetadataCopiesOnly'}


if __name__ == '__main__':
    unittest.main()
