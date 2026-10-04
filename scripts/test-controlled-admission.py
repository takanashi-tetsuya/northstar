#!/usr/bin/env python3
"""Pure oracle tests or explicitly supplied controlled Rust record/replay. No build."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
from lib import controlled_admission as controlled


class IndependentOracleTests(unittest.TestCase):
    def test_stage1_bridge_matches_accepted_independent_goldens(self):
        for old, golden in controlled.stage1_cases():
            with self.subTest(scenario=old['scenario_id']):
                with patch.object(controlled.stage1, 'predict', side_effect=AssertionError('prediction cannot be observation')):
                    value = controlled.bridge_case(old)
                    self.assertEqual(controlled.predict(value)['compatibility_projection'], golden)

    def test_native_4097_counterexample_and_4096_positive_are_exact(self):
        value = controlled.late_candidate()
        controlled.verify_late_premise(value)
        output = controlled.expected_output(value)
        expected = controlled.expected_counterexample(value)
        event = output['projection'][1]
        self.assertEqual((event['world']['active'], event['world']['result']), (4097, 'Accepted'))
        self.assertFalse(event['caller']['reservation_receipt'])
        self.assertEqual(expected['invariant']['location'], 'op-2')
        result = controlled.evaluate(value, output, expected_failure=expected)
        self.assertEqual(result['verdict'], 'InvariantViolation')
        self.assertTrue(result['replay_matched'])
        self.assertFalse(result['qualified'])
        positive = controlled.late_candidate(positive=True)
        result = controlled.evaluate(positive, controlled.expected_output(positive))
        self.assertEqual(result['verdict'], 'Pass')
        self.assertEqual(controlled.predict(positive)['projection'][1]['world']['active'], 4096)

    def test_4097_cannot_be_replaced_by_4096_or_zero(self):
        value = controlled.late_candidate()
        expected = controlled.expected_counterexample(value)
        for count in (4096, 0):
            output = controlled.expected_output(value)
            output['projection'][1]['world']['active'] = count
            result = controlled.evaluate(value, output, expected_failure=expected)
            self.assertFalse(result['replay_matched'])
            self.assertEqual(result['invariant']['class'], 'ReplayDivergence')
            fake = copy.deepcopy(expected)
            fake['projection'][1]['world']['active'] = count
            fake['invariant']['output']['world']['active'] = count
            with self.assertRaises(controlled.InvalidScenario):
                controlled.evaluate(value, output, expected_failure=fake)

    def test_counterexample_rejects_wrong_invariant_class_location_cut_and_output(self):
        value = controlled.late_candidate()
        output = controlled.expected_output(value)
        expected = controlled.expected_counterexample(value)
        for key, replacement in (('id', 'other'), ('class', 'Responsibility'), ('location', 'op-1'), ('cut', 'commit_unknown')):
            fake = copy.deepcopy(expected)
            fake['invariant'][key] = replacement
            with self.assertRaises(controlled.InvalidScenario):
                controlled.evaluate(value, output, expected_failure=fake)

    def test_no_valid_completion_keeps_receipt_but_is_inconclusive(self):
        command = controlled.controlled_command(1)
        command['schedule']['completions'][0]['attempt'] += 1
        value = controlled.scenario('missing-valid', [command])
        output = controlled.expected_output(value)
        event = output['projection'][0]
        self.assertEqual(event['domain'], 'AwaitingCompletion')
        self.assertTrue(event['caller']['reservation_receipt'])
        self.assertTrue(event['completion']['pending'])
        self.assertEqual(event['coordinator'], {'state': 'Waiting', 'outcome': None, 'result': None, 'cause': None, 'knowledge': None})
        self.assertEqual(event['witness']['fact']['kind'], 'Reserved')
        self.assertEqual(event['execution'], 'Inconclusive')
        self.assertFalse(output['coordinators_finished'])
        self.assertEqual(controlled.evaluate(value, output)['verdict'], 'Inconclusive')

    def test_explicit_cancellation_is_distinct_from_actual_unknown_and_retained_receipt(self):
        for cut, knowledge, receipt in [('before_effect_cancel', 'NoCommitRequested', False),
                                        ('commit_cancel', 'CommitCallEntered', False),
                                        ('receipt_before_cancel', 'ReceiptKnown', True)]:
            with self.subTest(cut=cut):
                value = controlled.scenario('cancel-separation', [controlled.controlled_command(1, cut=cut)])
                output = controlled.expected_output(value)
                event = output['projection'][0]
                self.assertEqual(event['domain'], 'AwaitingCompletion')
                self.assertTrue(event['cancellation'])
                self.assertEqual(event['coordinator']['state'], 'Waiting')
                self.assertIsNone(event['coordinator']['outcome'])
                self.assertIsNone(event['coordinator']['knowledge'])
                self.assertEqual(event['witness']['kind'], knowledge)
                self.assertEqual(event['caller']['reservation_receipt'], receipt)
                self.assertEqual(output['execution'], 'Cancelled')
                self.assertTrue(output['terminal'])
                self.assertFalse(output['coordinators_finished'])
                self.assertEqual(controlled.evaluate(value, output)['verdict'], 'Cancelled')
        value = controlled.scenario('returned-unknown', [controlled.controlled_command(1, cut='commit_unknown')])
        output = controlled.expected_output(value)
        event = output['projection'][0]
        self.assertEqual(event['domain'], 'Unknown')
        self.assertEqual(event['coordinator']['outcome'], 'Unknown')
        self.assertEqual(event['coordinator']['knowledge'], event['witness'])
        self.assertFalse(event['cancellation'])
        self.assertTrue(output['coordinators_finished'])

    def test_cut_cannot_supply_an_outcome_for_a_rejected_completion(self):
        for cut in ('commit_unknown', 'precommit_error'):
            command = controlled.controlled_command(1, cut=cut)
            command['schedule']['completions'][0]['attempt'] += 1
            value = controlled.scenario('undelivered-failure', [command])
            output = controlled.expected_output(value)
            event = output['projection'][0]
            self.assertEqual(event['domain'], 'AwaitingCompletion')
            self.assertIsNone(event['coordinator']['outcome'])
            self.assertEqual(event['caller']['unresolved'], cut == 'commit_unknown')
            self.assertEqual(controlled.evaluate(value, output)['verdict'], 'Inconclusive')

    def test_coordinator_classification_and_result_mismatch_are_not_masked_by_schedule(self):
        value = controlled.scenario('actual-classification', [controlled.controlled_command(1)])
        expected = controlled.expected_output(value)
        variants = []
        changed = copy.deepcopy(expected)
        event = changed['projection'][0]
        event['coordinator'].update(outcome='ReceiptPreserved', result=None, cause='Cancelled')
        event['domain'] = 'ReceiptPreserved'
        variants.append(changed)
        changed = copy.deepcopy(expected)
        changed['projection'][0]['coordinator']['result'].update(kind='Begin.ReplayAccepted', fence=None)
        variants.append(changed)
        changed = copy.deepcopy(expected)
        changed['projection'][0]['coordinator']['knowledge']['fact'] = {'kind': 'ReplayAccepted', 'fence': None}
        variants.append(changed)
        changed = copy.deepcopy(expected)
        changed['projection'][0]['witness']['fact']['fence']['lease'] = 'other-bound-identity'
        variants.append(changed)
        changed = copy.deepcopy(expected)
        changed['projection'][0]['cancellation'] = True
        variants.append(changed)
        for changed in variants:
            result = controlled.evaluate(value, changed)
            self.assertEqual(result['verdict'], 'InvariantViolation')
            self.assertEqual(result['invariant']['class'], 'ReplayDivergence')
            self.assertFalse(result['replay_matched'])

    def test_actual_correlation_values_outside_input_bounds_are_replay_divergence(self):
        value = controlled.scenario('actual-correlation', [controlled.controlled_command(1)])
        for key, actual in [('effect_number', 0), ('effect_number', 2**64-1),
                            ('generation', 20001), ('generation', 2**64-1), ('attempt', 0), ('attempt', 2**32-1)]:
            changed = controlled.expected_output(value)
            changed['projection'][0]['coordinator']['knowledge']['correlation'][key] = actual
            result = controlled.evaluate(value, changed)
            self.assertEqual(result['invariant']['class'], 'ReplayDivergence')
            self.assertFalse(result['qualified'])

    def test_unmapped_observation_failure_survives_empty_or_trimmed_detail(self):
        value = controlled.scenario('unmapped', [controlled.controlled_command(1)])
        for keep_detail in (True, False):
            changed = controlled.expected_output(value)
            fence = changed['projection'][0]['coordinator']['result']['fence']
            fence.update(mapped=False, key=None)
            if not keep_detail:
                changed['projection'] = []
            changed.update(execution='Inconclusive', terminal=False, coordinators_finished=False, evidence_complete=False,
                           observation_failure={'class': 'UnmappedMaterial', 'index': 0, 'operation_id': 'op-1'})
            result = controlled.evaluate(value, changed)
            self.assertEqual(result['verdict'], 'InvariantViolation')
            self.assertEqual(result['invariant']['class'], 'ReplayDivergence')
            self.assertEqual(result['invariant']['location'], 'op-1')
            self.assertFalse(result['replay_matched'])

    def test_undelivered_reconcile_does_not_publish_its_observation(self):
        first = controlled.controlled_command(1, cut='commit_unknown')
        second = controlled.controlled_command(2, first['key'], action='reconcile', lease=first['lease'], reconcile_of='op-1')
        second['schedule']['completions'][0]['attempt'] += 1
        value = controlled.scenario('undelivered-reconcile', [first, second])
        output = controlled.expected_output(value)
        event = output['projection'][1]
        self.assertEqual(event['world']['result'], 'ReconcileExactPending')
        self.assertIsNone(event['reconcile'])
        self.assertIsNone(event['coordinator']['result'])
        self.assertEqual(controlled.evaluate(value, output)['verdict'], 'Inconclusive')

    def test_output_v2_refuses_legacy_and_invalid_variant_shapes(self):
        value = controlled.scenario('output-version', [controlled.controlled_command(1)])
        changed = controlled.expected_output(value)
        changed['schema'] = 'northstar-admission-controlled-output-v1'
        with self.assertRaises(controlled.InvalidScenario):
            controlled.validate_output(value, changed)
        changed = controlled.expected_output(value)
        changed['projection'][0]['coordinator']['state'] = 'Waiting'
        with self.assertRaises(controlled.InvalidScenario):
            controlled.validate_output(value, changed)
        changed = controlled.expected_output(value)
        changed['projection'][0]['witness']['kind'] = 'NoCommitRequested'
        with self.assertRaises(controlled.InvalidScenario):
            controlled.validate_output(value, changed)

    def test_root_coordinator_completion_is_independently_compared(self):
        value = controlled.scenario('root-state', [controlled.controlled_command(1, cut='commit_cancel')])
        changed = controlled.expected_output(value)
        changed['coordinators_finished'] = True
        result = controlled.evaluate(value, changed)
        self.assertFalse(result['qualified'])
        self.assertFalse(result['replay_matched'])

    def test_all_saved_completion_records_are_concrete_and_rejections_preserve_pending(self):
        value = next(v for v in controlled.native_cases() if v['scenario_id'] == 'native-malformed-stale-duplicate-completions')
        self.assertTrue(all(type(c) is dict for c in value['commands'][0]['schedule']['completions']))
        event = controlled.predict(value)['projection'][0]
        reasons = [r['reason'] for r in event['completion']['rejections']]
        self.assertEqual(reasons[:5], ['Correlation']*4 + ['Kind'])
        self.assertEqual(reasons[5:-1], ['Request']*8)
        self.assertEqual(reasons[-1], 'AlreadyCompleted')
        self.assertTrue(event['completion']['accepted'])
        self.assertTrue(all(r['pending_preserved'] and r['receipt_preserved'] for r in event['completion']['rejections']))

    def test_unknown_world_does_not_collapse_caller_interval(self):
        for committed in (False, True):
            value = controlled.scenario('unknown', [controlled.controlled_command(1, cut='commit_unknown', world_commit=committed)])
            event = controlled.predict(value)['projection'][0]
            self.assertEqual(event['world']['active'], int(committed))
            self.assertEqual((event['caller']['active_min'], event['caller']['active_max']), (0, 1))
            self.assertEqual(event['knowledge'], 'CommitCallEntered')
            self.assertFalse(event['caller']['reservation_receipt'])

    def test_observation_gap_never_qualifies(self):
        value = controlled.scenario('gap', [controlled.controlled_command(1), controlled.controlled_command(2)])
        value['budgets']['events'] = 2
        output = controlled.expected_output(value)
        self.assertEqual(len(output['projection']), 1)
        self.assertEqual(controlled.evaluate(value, output)['verdict'], 'Inconclusive')
        self.assertFalse(output['terminal'])
        self.assertFalse(output['coordinators_finished'])
        output['projection'][0]['world']['active'] = 0
        self.assertEqual(controlled.evaluate(value, output)['verdict'], 'InvariantViolation')

    def test_schema_rejections_are_not_target_counterexamples(self):
        for case in controlled.rejection_cases():
            with self.subTest(case=case['id']), self.assertRaises((controlled.InvalidScenario, TypeError)):
                controlled.parse_scenario(controlled.loads(case['bytes']))
        value = controlled.scenario('good', [controlled.controlled_command(1)])
        with self.assertRaises(controlled.InvalidScenario):
            controlled.evaluate(value, {'schema': controlled.REJECTION_SCHEMA, 'class': 'InvalidScenario', 'reason': 'schema'})

    def test_source_declared_case_ids_are_unique_and_all_inputs_validate(self):
        cases = controlled.controlled_cases()
        self.assertEqual(len({c['scenario_id'] for c in cases}), len(cases))
        for value in cases:
            controlled.parse_scenario(value)

    def test_projection_contains_no_concrete_authority_material(self):
        value = controlled.scenario('privacy', [controlled.controlled_command(1)])
        output = controlled.canonical(controlled.expected_output(value))
        for category in value['bindings'].values():
            for entry in category:
                self.assertNotIn(entry.get('uuid', entry.get('hex')), output)
        self.assertNotIn(value['commands'][0]['guard']['normalized_payload'], output)


class ShrinkReaderTests(unittest.TestCase):
    """Reader contract regressions with explicitly mocked executions, not Rust evidence."""

    def setUp(self):
        files = {'source.rs': '1' * 64}
        self.provenance = {'schema': 'northstar-admission-controlled-provenance-v1', 'model': controlled.MODEL,
                           'adapter': controlled.ADAPTER, 'binding_version': controlled.BINDING_VERSION,
                           'source_sha256': controlled.digest(files), 'source_files': files,
                           'binary_sha256': '2' * 64, 'cargo_lock_sha256': '3' * 64,
                           'toolchain': 'rustc 1.97.1 (mock reader identity only)'}
        original = controlled.late_candidate()
        reduced = controlled.late_candidate(noise=False)
        positive = copy.deepcopy(reduced)
        positive['initial']['rows'].pop(0)
        positive = controlled.prune_bindings(positive)
        attempts = [self.record(original, 'original'), self.record(reduced, 'candidate-1'),
                    self.record(positive, 'positive-control'), self.record(reduced, 'reduced')]
        self.shrink = {'schema': 'northstar-controlled-shrink-v1', 'original': attempts[0],
                       'attempts': attempts, 'positive_control': attempts[2], 'reduced': attempts[3],
                       'scope': controlled.SHRINK_SCOPE}

    def record(self, value, name):
        output = controlled.expected_output(value)
        execution = {'command': ['/mock/controlled-admission', '/mock/' + name + '.input.json'],
                     'returncode': 0, 'wall_ms': 0,
                     'input_file_sha256': hashlib.sha256((controlled.canonical(value) + '\n').encode()).hexdigest(),
                     'stdout_sha256': hashlib.sha256((controlled.canonical(output) + '\n').encode()).hexdigest(),
                     'output': output, 'provenance': copy.deepcopy(self.provenance)}
        return {'input': copy.deepcopy(value), 'execution': execution,
                'evaluation': controlled.evaluate(value, output, expected_failure=controlled.expected_counterexample(value))}

    def replay_mocked(self, shrink):
        observed = []
        def reexecute(path, _binary, **_kwargs):
            value = controlled.read_json(path)
            observed.append(value)
            return self.record(value, 'mock-reexecution')['execution']
        with patch.object(controlled, 'run_saved_input', side_effect=reexecute):
            count = controlled.replay_shrink(shrink, '/mock/controlled-admission', expected_provenance=self.provenance)
        return count, observed

    def replace_reduction(self, value):
        self.shrink['attempts'][1] = self.record(value, 'candidate-1')
        self.shrink['reduced'] = self.record(value, 'reduced')
        self.shrink['attempts'][-1] = self.shrink['reduced']

    def test_canonical_history_reexecutes_original_candidate_control_and_selected_reduction(self):
        count, observed = self.replay_mocked(self.shrink)
        self.assertEqual(count, 4)
        self.assertEqual(observed, [attempt['input'] for attempt in self.shrink['attempts']])
        self.assertEqual(len(observed[0]['commands']), 3)
        self.assertEqual(len(observed[-1]['commands']), 2)
        self.assertEqual(self.shrink['reduced']['evaluation']['invariant']['location'], 'op-2')
        self.assertEqual(self.shrink['positive_control']['evaluation']['verdict'], 'Pass')

    def test_selfconsistent_reduced_guard_denial_pass_does_not_preserve_target(self):
        correct_candidates = copy.deepcopy(self.shrink)
        reduced = copy.deepcopy(self.shrink['reduced']['input'])
        begin = reduced['commands'][0]
        begin['guard']['allowed'] = False
        begin['schedule']['completions'] = [controlled.completion_for(begin)]
        controlled.verify_late_premise(reduced)
        self.replace_reduction(reduced)
        saved = self.shrink['reduced']
        self.assertEqual(saved['evaluation']['verdict'], 'Pass')
        self.assertTrue(saved['evaluation']['replay_matched'])
        self.assertEqual(saved['execution']['output']['projection'][1]['world']['active'], 4096)
        self.assertIsNone(controlled.shrink_target(reduced, saved['execution']['output'], saved['evaluation']))
        with self.assertRaisesRegex(controlled.InvalidScenario, 'shrink_candidate_history'):
            self.replay_mocked(self.shrink)
        correct_candidates['reduced'] = saved
        correct_candidates['attempts'][-1] = saved
        with self.assertRaisesRegex(controlled.InvalidScenario, 'shrink_selected_reduction'):
            self.replay_mocked(correct_candidates)

    def test_causal_cut_clock_and_used_material_mutations_are_not_deletions(self):
        original = copy.deepcopy(self.shrink)
        def change_cut(value):
            value['commands'][1]['schedule'].update(cut='commit_unknown', world_commit=True)
        def change_causal(value):
            value['commands'][1]['causal_id'] = None
        def change_time(value):
            value['commands'][1]['times']['finalize_us'] = 2
        def change_material(value):
            value['bindings']['payloads'][0]['hex'] = 'a' * 64
        for mutate in (change_cut, change_causal, change_time, change_material):
            with self.subTest(mutation=mutate.__name__):
                self.shrink = copy.deepcopy(original)
                reduced = copy.deepcopy(self.shrink['reduced']['input'])
                mutate(reduced)
                self.replace_reduction(reduced)
                with self.assertRaisesRegex(controlled.InvalidScenario, 'shrink_candidate_history'):
                    self.replay_mocked(self.shrink)

    def test_target_rejects_other_invariant_class_location_cut_and_violating_fact(self):
        saved = self.shrink['reduced']
        value, output = saved['input'], saved['execution']['output']
        for field, replacement in (('id', 'other-invariant'), ('class', 'ReplayDivergence'),
                                    ('location', 'op-1'), ('cut', 'commit_unknown')):
            evaluation = copy.deepcopy(saved['evaluation'])
            evaluation['invariant'][field] = replacement
            self.assertIsNone(controlled.shrink_target(value, output, evaluation))
        changed = copy.deepcopy(output)
        changed['projection'][1]['world']['active'] = 4098
        evaluation = controlled.evaluate(value, changed, expected_failure=controlled.expected_counterexample(value))
        self.assertEqual(evaluation['invariant']['class'], 'ReplayDivergence')
        self.assertIsNone(controlled.shrink_target(value, changed, evaluation))
        evaluation = copy.deepcopy(saved['evaluation'])
        evaluation['invariant']['output']['world']['active'] = 4096
        self.assertIsNone(controlled.shrink_target(value, output, evaluation))

    def test_missing_malformed_or_orphaned_role_members_are_rejected_before_reexecution(self):
        variants = []
        for role, index in (('original', 0), ('reduced', -1), ('positive_control', -2)):
            missing = copy.deepcopy(self.shrink)
            missing.pop(role)
            variants.append(missing)
            malformed = copy.deepcopy(self.shrink)
            malformed[role] = None
            variants.append(malformed)
            orphan = copy.deepcopy(self.shrink)
            orphan[role] = copy.deepcopy(orphan[role])
            orphan[role]['execution']['command'][1] = '/orphan.input.json'
            variants.append(orphan)
            removed = copy.deepcopy(self.shrink)
            removed['attempts'].pop(index)
            variants.append(removed)
        for bad_attempts in (None, {}, [], [None] * 4):
            malformed = copy.deepcopy(self.shrink)
            malformed['attempts'] = bad_attempts
            variants.append(malformed)
        for malformed in variants:
            with patch.object(controlled, 'run_saved_input', side_effect=AssertionError('malformed member must not run')):
                with self.assertRaises(controlled.InvalidScenario):
                    controlled.replay_shrink(malformed, '/mock/controlled-admission', expected_provenance=self.provenance)

    def test_missing_extra_or_reordered_candidate_attempts_are_not_a_reducer_history(self):
        variants = []
        missing = copy.deepcopy(self.shrink)
        missing['attempts'].pop(1)
        variants.append(missing)
        extra = copy.deepcopy(self.shrink)
        extra['attempts'].insert(1, copy.deepcopy(extra['attempts'][1]))
        variants.append(extra)
        swapped = copy.deepcopy(self.shrink)
        swapped['attempts'][0], swapped['attempts'][-1] = swapped['attempts'][-1], swapped['attempts'][0]
        variants.append(swapped)
        for malformed in variants:
            with self.assertRaises(controlled.InvalidScenario):
                self.replay_mocked(malformed)

    def test_saved_execution_shape_provenance_status_and_input_hash_are_required(self):
        def missing_field(record):
            record['execution'].pop('provenance')
        def wrong_provenance(record):
            record['execution']['provenance']['binary_sha256'] = '4' * 64
        def rejected_status(record):
            record['execution']['returncode'] = 2
        def boolean_status(record):
            record['execution']['returncode'] = False
        def wrong_input_hash(record):
            record['execution']['input_file_sha256'] = '4' * 64
        def malformed_hash(record):
            record['execution']['stdout_sha256'] = 'not-a-hash'
        def malformed_evaluation(record):
            record['evaluation'] = {'verdict': 'InvariantViolation'}
        for mutate in (missing_field, wrong_provenance, rejected_status, boolean_status,
                       wrong_input_hash, malformed_hash, malformed_evaluation):
            malformed = copy.deepcopy(self.shrink)
            mutate(malformed['original'])
            with self.subTest(mutation=mutate.__name__), \
                    patch.object(controlled, 'run_saved_input', side_effect=AssertionError('invalid execution must not run')):
                with self.assertRaises(controlled.InvalidScenario):
                    controlled.replay_shrink(malformed, '/mock/controlled-admission', expected_provenance=self.provenance)

    def test_actual_reexecution_hash_and_evaluation_must_match_saved_records(self):
        malformed = copy.deepcopy(self.shrink)
        malformed['original']['execution']['stdout_sha256'] = '4' * 64
        with self.assertRaisesRegex(controlled.InvalidScenario, 'shrink_reexecution_identity'):
            self.replay_mocked(malformed)
        malformed = copy.deepcopy(self.shrink)
        malformed['reduced']['evaluation']['invariant']['class'] = 'Responsibility'
        with self.assertRaisesRegex(controlled.InvalidScenario, 'shrink_evaluation_changed'):
            self.replay_mocked(malformed)

    def test_positive_control_must_be_exact_first_row_removal_from_selected_reduction(self):
        positive = copy.deepcopy(self.shrink['reduced']['input'])
        positive['initial']['rows'].pop(1)
        positive = controlled.prune_bindings(positive)
        control = self.record(positive, 'positive-control')
        self.assertEqual(control['evaluation']['verdict'], 'Pass')
        self.assertEqual(control['execution']['output']['projection'][1]['world']['active'], 4096)
        self.shrink['positive_control'] = control
        self.shrink['attempts'][-2] = control
        with self.assertRaisesRegex(controlled.InvalidScenario, 'shrink_positive_relation'):
            self.replay_mocked(self.shrink)
        self.shrink['positive_control'] = self.record(
            controlled.scenario('unrelated-pass', [controlled.controlled_command(1)]), 'positive-control')
        self.shrink['attempts'][-2] = self.shrink['positive_control']
        with self.assertRaisesRegex(controlled.InvalidScenario, 'shrink_positive_relation'):
            self.replay_mocked(self.shrink)

    def test_legal_deletion_can_change_index_and_actor_diagnostics_but_preserve_target(self):
        # This exercises the shared relation helper, not an expanded corpus:
        # replay_shrink still requires the exact source late_candidate original.
        original = controlled.late_candidate()
        noise = original['commands'].pop()
        noise.update(action='guard_persistent', actor='actor-a')
        noise['guard']['actor_sequence_delta'] = 1
        noise['schedule']['completions'] = [controlled.completion_for(noise)]
        original['commands'].insert(0, noise)
        reduced = controlled.shrink_deletion(original, noise['operation_id'])
        before, after = self.record(original, 'before'), self.record(reduced, 'after')
        before_fact = before['evaluation']['invariant']['output']
        after_fact = after['evaluation']['invariant']['output']
        self.assertEqual((before_fact['index'], after_fact['index']), (2, 1))
        self.assertEqual((before_fact['world']['actor_sequence'], after_fact['world']['actor_sequence']), (1, 0))
        target = controlled.shrink_target(original, before['execution']['output'], before['evaluation'])
        self.assertIsNotNone(target)
        self.assertEqual(target, controlled.shrink_target(reduced, after['execution']['output'], after['evaluation']))
        self.shrink['original'] = before
        self.shrink['attempts'][0] = before
        with self.assertRaisesRegex(controlled.InvalidScenario, 'shrink_original'):
            self.replay_mocked(self.shrink)


class DriverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'source.rs').write_text('source bytes')
        (self.root / 'Cargo.lock').write_text('lock bytes')
        self.binary = self.root / 'controlled-admission'
        self.binary.write_text('not executable; subprocess explicitly mocked')
        files = {'source.rs': controlled.sha256_file(self.root / 'source.rs')}
        self.provenance = {'schema': 'northstar-admission-controlled-provenance-v1', 'model': controlled.MODEL,
                           'adapter': controlled.ADAPTER, 'binding_version': controlled.BINDING_VERSION,
                           'source_sha256': controlled.digest(files), 'source_files': files,
                           'binary_sha256': controlled.sha256_file(self.binary),
                           'cargo_lock_sha256': controlled.sha256_file(self.root / 'Cargo.lock'),
                           'toolchain': 'rustc 1.97.1 (test identity only)'}
        self.value = controlled.scenario('driver-input', [controlled.controlled_command(1)])
        self.path = self.root / 'input.json'
        self.path.write_text(controlled.canonical(self.value))

    def test_driver_invokes_saved_binary_input_and_never_predicts(self):
        fixture_output = {'schema': controlled.REJECTION_SCHEMA, 'class': 'InvalidScenario', 'reason': 'schema'}
        mocked = SimpleNamespace(returncode=2, stdout=controlled.canonical(fixture_output).encode(), stderr=b'')
        with patch.object(controlled.subprocess, 'run', return_value=mocked) as run, \
                patch.object(controlled, 'predict', side_effect=AssertionError('must not substitute prediction')):
            result = controlled.run_saved_input(self.path, self.binary, expected_provenance=self.provenance, root=self.root)
        run.assert_called_once_with([str(self.binary), str(self.path)], capture_output=True, check=False)
        self.assertEqual(result['output'], fixture_output)
        self.assertEqual(result['returncode'], 2)

    def test_wrong_source_binary_lock_refuses_before_execution(self):
        for name in ('source.rs', 'controlled-admission', 'Cargo.lock'):
            with self.subTest(name=name):
                path = self.root / name
                original = path.read_bytes()
                path.write_bytes(original + b'changed')
                with patch.object(controlled.subprocess, 'run', side_effect=AssertionError('must not launch')):
                    with self.assertRaises(controlled.InvalidScenario):
                        controlled.run_saved_input(self.path, self.binary, expected_provenance=self.provenance, root=self.root)
                path.write_bytes(original)

    def test_source_or_input_change_during_execution_invalidates_result(self):
        for path in (self.root / 'source.rs', self.path, self.binary):
            original = path.read_bytes()
            def mutate(*_args, **_kwargs):
                path.write_bytes(original + b'changed')
                return SimpleNamespace(returncode=0, stdout=b'{}', stderr=b'')
            with patch.object(controlled.subprocess, 'run', side_effect=mutate), self.assertRaises(controlled.InvalidScenario):
                controlled.run_saved_input(self.path, self.binary, expected_provenance=self.provenance, root=self.root)
            path.write_bytes(original)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--trusted-provenance', type=Path)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--evidence-dir', type=Path)
    group.add_argument('--replay', type=Path)
    args, remaining = parser.parse_known_args(argv)
    if args.evidence_dir or args.replay:
        parser.error('--binary and --trusted-provenance are required') if not args.binary or not args.trusted_provenance else None
        trusted = controlled.read_json(args.trusted_provenance)
        try:
            result = controlled.record_corpus(args.evidence_dir, args.binary, expected_provenance=trusted) if args.evidence_dir else \
                controlled.replay_corpus(args.replay, args.binary, expected_provenance=trusted)
        except (controlled.InvalidScenario, OSError) as error:
            print(json.dumps({'verdict': 'InvalidScenario', 'reason': str(error)}))
            return 2
        print(json.dumps(result, sort_keys=True))
        return 0
    if args.binary or args.trusted_provenance:
        parser.error('record or replay mode required with binary/provenance')
    return 0 if unittest.main(argv=[sys.argv[0]] + remaining, exit=False).result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
