#!/usr/bin/env python3
"""Pure/mocked regression source. Dedicated Rust execution has a separate owner."""
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
from lib import controlled_admission_supervision as supervision


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

    def test_output_v4_refuses_legacy_and_invalid_variant_shapes(self):
        value = controlled.scenario('output-version', [controlled.controlled_command(1)])
        changed = controlled.expected_output(value)
        for version in ('v1', 'v2', 'v3'):
            changed['schema'] = 'northstar-admission-controlled-output-' + version
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

    def test_reconcile_time_and_effect_observations_are_independently_compared(self):
        first = controlled.controlled_command(1, cut='commit_unknown')
        second = controlled.controlled_command(2, first['key'], action='reconcile', lease=first['lease'],
                                               now=123456, reconcile_of='op-1')
        value = controlled.scenario('reconcile-returned-sample', [first, second])
        changes = [(('observed_at_us',), time) for time in
                   (-2**63, -1, 0, 123457, controlled.MAX_TIME + 1, 2**63 - 1)]
        for field in ('correlation', 'unresolved'):
            changes.extend([((field, 'operation_id'), 'different-operation'),
                            ((field, 'effect_number'), 2**64 - 1),
                            ((field, 'generation'), 2**64 - 1),
                            ((field, 'attempt'), 2**32 - 1)])
        changes.extend([(('fence', key), 'different-bound-material') for key in ('key', 'payload_tag', 'lease')])
        for location in ('event', 'result'):
            for path, actual in changes:
                with self.subTest(location=location, path=path, actual=actual):
                    changed = controlled.expected_output(value)
                    event = changed['projection'][1]
                    target = event['reconcile'] if location == 'event' else event['coordinator']['result']['reconcile']
                    for part in path[:-1]:
                        target = target[part]
                    target[path[-1]] = actual
                    verdict = controlled.evaluate(value, changed)
                    self.assertEqual(verdict['invariant']['class'], 'ReplayDivergence')
                    self.assertFalse(verdict['replay_matched'])
                    self.assertFalse(verdict['qualified'])

    def test_reconcile_v4_requires_sample_provenance_and_effect_fields(self):
        first = controlled.controlled_command(1, cut='commit_unknown')
        second = controlled.controlled_command(2, first['key'], action='reconcile', lease=first['lease'], reconcile_of='op-1')
        value = controlled.scenario('reconcile-required-fields', [first, second])
        for location in ('event', 'result'):
            for field in ('observed_at_us', 'observed_at_source', 'correlation', 'unresolved', 'fence'):
                changed = controlled.expected_output(value)
                event = changed['projection'][1]
                target = event['reconcile'] if location == 'event' else event['coordinator']['result']['reconcile']
                del target[field]
                with self.subTest(location=location, missing=field), self.assertRaises(controlled.InvalidScenario):
                    controlled.validate_output(value, changed)
            for invalid in (True, 1.5, -(2**63)-1, 2**63):
                changed = controlled.expected_output(value)
                event = changed['projection'][1]
                target = event['reconcile'] if location == 'event' else event['coordinator']['result']['reconcile']
                target['observed_at_us'] = invalid
                with self.assertRaises(controlled.InvalidScenario):
                    controlled.validate_output(value, changed)
            changed = controlled.expected_output(value)
            event = changed['projection'][1]
            target = event['reconcile'] if location == 'event' else event['coordinator']['result']['reconcile']
            target['observed_at_source'] = 'PostgreSQL'
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


class BoundedKnowledgeTests(unittest.TestCase):
    """Manual epistemic expectations, separate from controlled Rust evidence."""

    def assert_bounds(self, event, active, retained, states):
        caller = event['caller']
        self.assertTrue(caller['knowledge_complete'])
        self.assertEqual((caller['active_min'], caller['active_max']), active)
        self.assertEqual((caller['retained_min'], caller['retained_max']), retained)
        self.assertEqual(caller['possible_states'], states)

    def test_unknown_then_unrelated_receipt_preserves_both_worlds(self):
        for committed in (False, True):
            with self.subTest(committed=committed):
                first = controlled.controlled_command(1, cut='commit_unknown', world_commit=committed)
                value = controlled.scenario('unknown-then-known', [first, controlled.controlled_command(2)])
                events = controlled.predict(value)['projection']
                self.assert_bounds(events[0], (0, 1), (0, 1), 2)
                self.assert_bounds(events[1], (1, 2), (1, 2), 2)
                self.assertEqual(events[1]['world']['active'], 1 + int(committed))
                self.assertTrue(events[1]['caller']['reservation_receipt'])

    def test_two_independent_unknowns_keep_four_states_for_every_world(self):
        for first_world in (False, True):
            for second_world in (False, True):
                with self.subTest(first=first_world, second=second_world):
                    commands = [controlled.controlled_command(1, cut='commit_unknown', world_commit=first_world),
                                controlled.controlled_command(2, cut='commit_unknown', world_commit=second_world)]
                    events = controlled.predict(controlled.scenario('two-unknowns', commands))['projection']
                    self.assert_bounds(events[1], (0, 2), (0, 2), 4)
                    self.assertEqual(events[1]['world']['active'], int(first_world) + int(second_world))
                    self.assertTrue(events[0]['caller']['unresolved'])

    def test_ttl_expiry_changes_active_bounds_but_keeps_retained_uncertainty(self):
        for committed in (False, True):
            commands = [controlled.controlled_command(1, cut='commit_unknown', world_commit=committed),
                        controlled.controlled_command(2, action='guard_memory', now=1800 * controlled.SECOND)]
            events = controlled.predict(controlled.scenario('uncertain-expiry', commands))['projection']
            self.assert_bounds(events[1], (0, 0), (0, 1), 2)
            self.assert_bounds(events[0], (0, 1), (0, 1), 2)

    def test_delivered_reconcile_filters_exact_missing_and_expired_observations(self):
        cases = [(False, 0, 'Missing', None, None, (0, 0), (0, 0)),
                 (True, 0, 'ExactPending', 'Current', 'Current', (1, 1), (1, 1)),
                 (True, 60 * controlled.SECOND, 'ExactPending', 'Expired', 'Current', (1, 1), (1, 1)),
                 (True, 1800 * controlled.SECOND, 'ExactPending', 'Expired', 'Expired', (0, 0), (1, 1))]
        for committed, now, observation, lease, retention, active, retained in cases:
            with self.subTest(committed=committed, now=now):
                first = controlled.controlled_command(1, cut='commit_unknown', world_commit=committed)
                second = controlled.controlled_command(2, first['key'], action='reconcile', lease=first['lease'],
                                                       now=now, reconcile_of='op-1')
                events = controlled.predict(controlled.scenario('reconcile-knowledge', [first, second]))['projection']
                self.assert_bounds(events[1], active, retained, 1)
                self.assertEqual(events[1]['coordinator']['result']['reconcile'],
                                 {'observation': observation, 'lease': lease, 'retention': retention,
                                  'observed_at_us': now, 'observed_at_source': 'Scripted',
                                  'correlation': {'mapped': True, 'operation_id': 'op-2', 'effect_number': 2, 'generation': 1, 'attempt': 1},
                                  'unresolved': {'mapped': True, 'operation_id': 'op-1', 'effect_number': 1, 'generation': 1, 'attempt': 1},
                                  'fence': {'mapped': True, 'key': 'key-1', 'payload_tag': 'payload-a', 'lease': 'lease-1'}})
                self.assert_bounds(events[0], (0, 1), (0, 1), 2)
                self.assertTrue(events[0]['caller']['unresolved'])

    def test_delivered_accepted_reconcile_preserves_retention_validity(self):
        for now, validity, active in [(0, 'Current', (1, 1)),
                                      (21600 * controlled.SECOND, 'Expired', (0, 0))]:
            first = controlled.controlled_command(1, 'pending', action='finalize', lease='pending-lease', cut='commit_unknown')
            second = controlled.controlled_command(2, 'pending', action='reconcile', lease='pending-lease',
                                                   now=now, reconcile_of='op-1')
            initial = [controlled.row('pending', state='pending', lease='pending-lease', expiry=100 * controlled.SECOND)]
            events = controlled.predict(controlled.scenario('accepted-reconcile', [first, second], initial))['projection']
            self.assert_bounds(events[1], active, (1, 1), 1)
            self.assertEqual(events[1]['coordinator']['result']['reconcile'],
                             {'observation': 'ExactAccepted', 'lease': None, 'retention': validity,
                              'observed_at_us': now, 'observed_at_source': 'Scripted',
                              'correlation': {'mapped': True, 'operation_id': 'op-2', 'effect_number': 2, 'generation': 1, 'attempt': 1},
                              'unresolved': {'mapped': True, 'operation_id': 'op-1', 'effect_number': 1, 'generation': 1, 'attempt': 1},
                              'fence': {'mapped': True, 'key': 'pending', 'payload_tag': 'payload-a', 'lease': 'pending-lease'}})
            self.assertTrue(events[0]['caller']['unresolved'])

    def test_reconcile_filter_uses_delivered_instant_instead_of_requested_clock(self):
        first = controlled.controlled_command(1, cut='commit_unknown')
        second = controlled.controlled_command(2, first['key'], action='reconcile', lease=first['lease'], reconcile_of='op-1')
        value = controlled.scenario('returned-as-of', [first, second])
        maps = controlled.parse_scenario(value)
        maps['operations'] = {command['operation_id']: command for command in value['commands']}
        event = controlled.expected_output(value)['projection'][1]
        coordinator = event['coordinator']
        actual = coordinator['result']['reconcile']
        actual.update(observed_at_us=1800 * controlled.SECOND, lease='Expired', retention='Expired')
        empty = {'rows': {}, 'sequences': {'actor-a': 0}, 'proofs': set()}
        pending = {'rows': {'key-1': controlled.row('key-1', state='pending', lease='lease-1',
                                                   expiry=1800 * controlled.SECOND, lease_until=60 * controlled.SECOND)},
                   'sequences': {'actor-a': 0}, 'proofs': set()}
        views = [empty, pending]
        unchanged, reason = controlled._knowledge_advance(views, second, maps, 0, event['witness'],
                                                         {'outcome': None, 'result': None})
        self.assertIs(unchanged, views)
        self.assertIsNone(reason)
        narrowed, reason = controlled._knowledge_advance(views, second, maps, 0, event['witness'], coordinator)
        self.assertIsNone(reason)
        self.assertEqual(narrowed, [pending])
        self.assertEqual(second['times']['reconcile_us'], 0)

    def test_undelivered_reconcile_cannot_filter_any_alternative(self):
        for committed in (False, True):
            first = controlled.controlled_command(1, cut='commit_unknown', world_commit=committed)
            second = controlled.controlled_command(2, first['key'], action='reconcile', lease=first['lease'], reconcile_of='op-1')
            second['schedule']['completions'][0]['attempt'] += 1
            events = controlled.predict(controlled.scenario('undelivered-knowledge', [first, second]))['projection']
            self.assert_bounds(events[1], (0, 1), (0, 1), 2)
            self.assertIsNone(events[1]['reconcile'])
            self.assertIsNone(events[1]['coordinator']['result'])

    def test_delivered_no_commit_storage_result_can_filter_old_alternatives(self):
        for committed, result, count in [(False, 'Finalize.Missing', 0), (True, 'Finalize.LostFence', 1)]:
            first = controlled.controlled_command(1, cut='commit_unknown', world_commit=committed)
            second = controlled.controlled_command(2, first['key'], action='finalize', lease='wrong-lease')
            events = controlled.predict(controlled.scenario('no-commit-storage-read', [first, second]))['projection']
            self.assertEqual(events[1]['witness']['kind'], 'NoCommitRequested')
            self.assertEqual(events[1]['coordinator']['result']['kind'], result)
            self.assert_bounds(events[1], (count, count), (count, count), 1)

    def test_no_commit_failure_cancel_and_memory_guard_preserve_all_old_views(self):
        missing = {'challenge_id': '00000000-0000-0000-0000-000000000099', 'nonce': 'synthetic-nonce'}
        for committed in (False, True):
            for action, cut in [('reserve', 'precommit_error'), ('reserve', 'before_effect_cancel'), ('guard_memory', 'none')]:
                with self.subTest(committed=committed, action=action, cut=cut):
                    first = controlled.controlled_command(1, cut='commit_unknown', world_commit=committed)
                    second = controlled.controlled_command(2, action=action, cut=cut,
                                                           guard=controlled.synthetic_guard(proof=missing, delta=1))
                    output = controlled.expected_output(controlled.scenario('no-storage-observation', [first, second]))
                    self.assert_bounds(output['projection'][1], (0, 1), (0, 1), 2)
                    self.assertIsNone(output['knowledge_stop'])

    def test_equal_counts_do_not_merge_proof_or_sequence_alternatives(self):
        proof = {'challenge_id': '00000000-0000-0000-0000-000000000001', 'nonce': 'synthetic-nonce'}
        for guard, initial_proofs in [(controlled.synthetic_guard(delta=1), []),
                                      (controlled.synthetic_guard(proof=proof), [proof['challenge_id']])]:
            commands = [controlled.controlled_command(1, action='guard_persistent', cut='commit_unknown', guard=guard),
                        controlled.controlled_command(2, action='guard_memory')]
            events = controlled.predict(controlled.scenario('equal-count-authority', commands, proofs=initial_proofs))['projection']
            self.assert_bounds(events[0], (0, 0), (0, 0), 2)
            self.assert_bounds(events[1], (0, 0), (0, 0), 2)

    def test_equal_counts_do_not_merge_row_fences(self):
        for committed in (False, True):
            first = controlled.controlled_command(1, 'pending', lease='new-lease', cut='commit_unknown', world_commit=committed)
            second = controlled.controlled_command(2, action='guard_memory')
            third = controlled.controlled_command(3, 'pending', action='reconcile', lease='new-lease', reconcile_of='op-1')
            rows = [controlled.row('pending', state='pending', lease='old-lease', lease_until=0)]
            events = controlled.predict(controlled.scenario('equal-count-fences', [first, second, third], rows))['projection']
            self.assert_bounds(events[0], (1, 1), (1, 1), 2)
            self.assert_bounds(events[1], (1, 1), (1, 1), 2)
            self.assert_bounds(events[2], (1, 1), (1, 1), 1)
            self.assertEqual(events[2]['reconcile']['observation'], 'ExactPending' if committed else 'Superseded')

    def test_allowed_missing_proof_in_an_alternative_stops_without_pruning_it(self):
        proof = {'challenge_id': '00000000-0000-0000-0000-000000000001', 'nonce': 'synthetic-nonce'}
        guard = controlled.synthetic_guard(proof=proof, delta=1)
        commands = [controlled.controlled_command(1, action='guard_persistent', cut='commit_unknown', world_commit=False, guard=guard),
                    controlled.controlled_command(2, action='guard_persistent', guard=guard),
                    controlled.controlled_command(3)]
        value = controlled.scenario('unsupported-proof-alternative', commands, proofs=[proof['challenge_id']])
        output = controlled.expected_output(value)
        self.assertEqual(len(output['projection']), 2)
        self.assert_bounds(output['projection'][0], (0, 0), (0, 0), 2)
        self.assertEqual(output['knowledge_stop'], {'index': 1, 'phase': 'AfterCommand',
                                                  'reason': 'KnowledgeModelIncomplete'})
        event = output['projection'][1]
        self.assertEqual(event['coordinator']['outcome'], 'Completed')
        self.assertEqual(event['witness']['kind'], 'ReceiptKnown')
        self.assertEqual(event['world']['actor_sequence'], 1)
        self.assertFalse(event['world']['proof_present'])
        self.assertFalse(event['caller']['knowledge_complete'])
        self.assertTrue(all(event['caller'][key] is None for key in
                            ('active_min', 'active_max', 'retained_min', 'retained_max', 'possible_states')))
        self.assertEqual(controlled.evaluate(value, output)['verdict'], 'Inconclusive')

    def test_seventh_independent_unknown_stops_before_attempting_128_views(self):
        commands = [controlled.controlled_command(index, cut='commit_unknown') for index in range(1, 8)]
        commands.append(controlled.controlled_command(8))
        value = controlled.scenario('view-limit', commands)
        output = controlled.expected_output(value)
        self.assertEqual(len(output['projection']), 7)
        self.assert_bounds(output['projection'][5], (0, 6), (0, 6), 64)
        self.assertEqual(output['knowledge_stop'], {'index': 6, 'phase': 'AfterCommand', 'reason': 'ViewBudget'})
        self.assertEqual(output['projection'][6]['world']['active'], 7)
        self.assertEqual(output['projection'][6]['coordinator']['outcome'], 'Unknown')
        self.assertIsNone(output['projection'][6]['caller']['possible_states'])
        self.assertEqual(output['execution'], 'Inconclusive')
        self.assertFalse(output['evidence_complete'])
        self.assertFalse(output['terminal'])
        self.assertFalse(output['coordinators_finished'])

    def test_attempt_budget_is_checked_before_predicates_or_deduplication(self):
        view = {'rows': {}, 'sequences': {'actor-a': 0}, 'proofs': set()}
        views = [view] * 64
        command = controlled.controlled_command(1, cut='commit_unknown')
        witness = {'kind': 'CommitCallEntered', 'scope': 'RatedBegin.NewReservation', 'fact': None}
        coordinator = {'outcome': 'Unknown', 'result': None}
        with patch.object(controlled, '_knowledge_transaction', side_effect=AssertionError('must reserve first')):
            unchanged, reason = controlled._knowledge_advance(views, command, {}, 0, witness, coordinator)
        self.assertIs(unchanged, views)
        self.assertEqual(reason, 'ViewBudget')

    def test_modeled_copy_and_byte_envelope_boundaries_are_inclusive(self):
        item = {'actor': 'a', 'key': 'k', 'payload_tag': 'p', 'state': 'pending',
                'expires_at_us': 1, 'lease': 'l', 'lease_until_us': 1}
        views = [{'rows': {'k': item}, 'sequences': {'a': 0}, 'proofs': set()}]
        command = controlled.controlled_command(1, 'n', actor='a', payload='p', lease='l')
        # Known world: 525 bytes. Prospective accepted row: 205 bytes.
        # Two successors, both scratch envelopes and sixteen candidate/row
        # slots need 19829 bytes and 25 rows.
        with patch.object(controlled, 'MAX_KNOWLEDGE_ROWS', 24):
            self.assertEqual(controlled._knowledge_reserve(views, command, 2), 'RowBudget')
        with patch.object(controlled, 'MAX_KNOWLEDGE_ROWS', 25), patch.object(controlled, 'MAX_KNOWLEDGE_BYTES', 19828):
            self.assertEqual(controlled._knowledge_reserve(views, command, 2), 'ByteBudget')
        with patch.object(controlled, 'MAX_KNOWLEDGE_ROWS', 25), patch.object(controlled, 'MAX_KNOWLEDGE_BYTES', 19829):
            self.assertIsNone(controlled._knowledge_reserve(views, command, 2))

    def test_initial_budget_stop_does_not_process_even_the_first_command(self):
        initial = [controlled.row('k', actor='a', state='pending', lease='l', payload='p')]
        command = controlled.controlled_command(1, 'n', actor='a', payload='p', lease='l')
        value = controlled.scenario('initial-budget', [command], initial, actors=('a',))
        for constant, maximum, reason in [('MAX_KNOWLEDGE_ROWS', 0, 'RowBudget'),
                                           ('MAX_KNOWLEDGE_BYTES', 524, 'ByteBudget')]:
            with self.subTest(reason=reason), patch.object(controlled, constant, maximum):
                output = controlled.expected_output(value)
                self.assertEqual(output['projection'], [])
                self.assertEqual(output['knowledge_stop'], {'index': 0, 'phase': 'BeforeInitialState', 'reason': reason})
                self.assertIsNone(output['safety_failure'])
                self.assertFalse(output['evidence_complete'])
                self.assertEqual(controlled.evaluate(value, output)['verdict'], 'Inconclusive')

    def test_no_storage_observation_bypasses_every_expansion_budget(self):
        views = [{'rows': {}, 'sequences': {'actor-a': 0}, 'proofs': set()}]
        command = controlled.controlled_command(1, cut='precommit_error')
        witness = {'kind': 'NoCommitRequested', 'scope': None, 'fact': None}
        coordinator = {'outcome': 'PreCommitFailure', 'result': None}
        with patch.object(controlled, 'MAX_KNOWLEDGE_VIEWS', 0), \
             patch.object(controlled, 'MAX_KNOWLEDGE_ROWS', 0), \
             patch.object(controlled, 'MAX_KNOWLEDGE_BYTES', 0), \
             patch.object(controlled, '_knowledge_transaction', side_effect=AssertionError('no observable storage')):
            unchanged, reason = controlled._knowledge_advance(views, command, {}, 0, witness, coordinator)
        self.assertIs(unchanged, views)
        self.assertIsNone(reason)

    def test_empty_observation_filter_is_inconsistent_and_preserves_old_states(self):
        command = controlled.controlled_command(1)
        value = controlled.scenario('inconsistent-observation', [command])
        maps = controlled.parse_scenario(value)
        views = [{'rows': {}, 'sequences': {'actor-a': 0}, 'proofs': set()}]
        # An empty store cannot supply a retained replay receipt.
        witness = {'kind': 'ReceiptKnown', 'scope': 'RatedBegin.ReplayRead',
                   'fact': {'kind': 'ReplayAccepted', 'fence': None}}
        unchanged, reason = controlled._knowledge_advance(views, command, maps, 0, witness,
                                                         {'outcome': None, 'result': None})
        self.assertIs(unchanged, views)
        self.assertEqual(reason, 'InconsistentObservation')
        self.assertEqual(views[0]['rows'], {})
        empty = []
        unchanged, reason = controlled._knowledge_advance(empty, command, {}, 0,
                                                         {'kind': 'NoCommitRequested'}, {'outcome': None, 'result': None})
        self.assertIs(unchanged, empty)
        self.assertEqual(reason, 'InconsistentObservation')

    def test_reconcile_filters_lease_validity_even_when_the_fence_is_identical(self):
        first = controlled.controlled_command(1, 'pending', lease='same-lease', cut='commit_unknown')
        second = controlled.controlled_command(2, 'pending', action='reconcile', lease='same-lease', reconcile_of='op-1')
        initial = [controlled.row('pending', state='pending', lease='same-lease', lease_until=0)]
        events = controlled.predict(controlled.scenario('lease-validity', [first, second], initial))['projection']
        self.assert_bounds(events[0], (1, 1), (1, 1), 2)
        self.assert_bounds(events[1], (1, 1), (1, 1), 1)
        self.assertEqual(events[1]['reconcile']['lease'], 'Current')

    def test_previous_safety_failure_survives_later_knowledge_exhaustion(self):
        value = controlled.late_candidate(noise=False)
        commands = value['commands'] + [controlled.controlled_command(number, actor='actor-b', now=1, cut='commit_unknown')
                                         for number in range(3, 10)]
        value['commands'] = commands
        value['bindings'] = controlled.materialize_bindings(value['initial']['rows'], commands, ('actor-a', 'actor-b'))
        value['initial']['actor_sequences']['actor-b'] = 0
        output = controlled.expected_output(value)
        self.assertEqual(output['safety_failure'], {'index': 1, 'active': 4097})
        # The retained 4097-row alternatives hit the byte envelope before the
        # small empty-store example's seventh-Unknown view limit.
        self.assertEqual(output['knowledge_stop'], {'index': 7, 'phase': 'AfterCommand', 'reason': 'ByteBudget'})
        result = controlled.evaluate(value, output)
        self.assertEqual(result['verdict'], 'InvariantViolation')
        self.assertEqual(result['invariant']['class'], 'Safety')
        self.assertEqual(result['invariant']['location'], 'op-2')
        self.assertFalse(result['replay_matched'])

    def test_safety_summary_survives_event_and_byte_evidence_exhaustion(self):
        value = controlled.late_candidate(noise=False)
        value['budgets']['events'] = 2
        output = controlled.expected_output(value)
        self.assertEqual(len(output['projection']), 1)
        self.assertEqual(output['safety_failure'], {'index': 1, 'active': 4097})
        result = controlled.evaluate(value, output)
        self.assertEqual(result['invariant']['class'], 'Safety')
        self.assertFalse(result['replay_matched'])
        self.assertIsNone(controlled.shrink_target(value, output, result))

        initial = [controlled.row('accepted-' + str(index)) for index in range(4097)]
        value = controlled.scenario('first-event-safety', [controlled.controlled_command(1, action='guard_memory')], initial)
        value['budgets']['evidence_bytes'] = 2048
        output = controlled.expected_output(value)
        self.assertEqual(output['projection'], [])
        self.assertEqual(output['safety_failure'], {'index': 0, 'active': 4097})
        result = controlled.evaluate(value, output)
        self.assertEqual(result['verdict'], 'InvariantViolation')
        self.assertEqual(result['invariant']['class'], 'Safety')
        self.assertEqual(result['invariant']['location'], 'op-1')
        self.assertFalse(result['complete'])

    def test_tampered_compact_safety_count_location_and_presence_are_divergent(self):
        value = controlled.late_candidate()
        value['budgets']['events'] = 2
        for summary in (None, {'index': 1, 'active': 0}, {'index': 1, 'active': 4096},
                        {'index': 1, 'active': 4098}, {'index': 0, 'active': 4097}, {'index': 2, 'active': 4097}):
            with self.subTest(summary=summary):
                output = controlled.expected_output(value)
                output['safety_failure'] = summary
                result = controlled.evaluate(value, output)
                self.assertEqual(result['verdict'], 'InvariantViolation')
                self.assertEqual(result['invariant']['class'], 'ReplayDivergence')
                self.assertFalse(result['replay_matched'])

    def test_summaries_never_claim_commands_after_the_first_evidence_overflow(self):
        value = controlled.late_candidate()
        # Event one exceeds the cap; the violating finalize is never processed.
        value['budgets']['events'] = 1
        output = controlled.expected_output(value)
        self.assertEqual(output['projection'], [])
        self.assertIsNone(output['safety_failure'])
        self.assertIsNone(controlled.expected_counterexample(value))
        commands = [controlled.controlled_command(index, cut='commit_unknown') for index in range(1, 8)]
        value = controlled.scenario('unprocessed-knowledge-stop', commands)
        value['budgets']['events'] = 2
        output = controlled.expected_output(value)
        self.assertIsNone(output['knowledge_stop'])
        self.assertEqual(len(output['projection']), 1)

    def test_knowledge_stopping_event_can_itself_exhaust_evidence(self):
        commands = [controlled.controlled_command(index, cut='commit_unknown') for index in range(1, 9)]
        value = controlled.scenario('knowledge-event-overflow', commands)
        value['budgets']['events'] = 12
        output = controlled.expected_output(value)
        self.assertEqual(len(output['projection']), 6)
        self.assertEqual(output['knowledge_stop'], {'index': 6, 'phase': 'AfterCommand', 'reason': 'ViewBudget'})
        self.assert_bounds(output['projection'][-1], (0, 6), (0, 6), 64)

    def test_stage1_omits_only_incomplete_event_and_retains_prefix_during_trim(self):
        old, golden = controlled.stage1_cases()[0]
        value = controlled.bridge_case(old)
        # First reserve needs19 rows, finalize20, next reserve23.
        with patch.object(controlled, 'MAX_KNOWLEDGE_ROWS', 20):
            output = controlled.expected_output(value)
            self.assertEqual(len(output['projection']), 3)
            self.assertEqual(output['compatibility_projection'], golden[:2])
            self.assertEqual(output['knowledge_stop'], {'index': 2, 'phase': 'AfterCommand', 'reason': 'RowBudget'})
            self.assertIsNone(output['projection'][2]['caller']['active_min'])
            # Force the final root-size pass to remove native detail only.
            value['budgets']['evidence_bytes'] = len(controlled.canonical(output).encode()) - 1
            trimmed = controlled.expected_output(value)
            self.assertEqual(len(trimmed['projection']), 2)
            self.assertEqual(trimmed['compatibility_projection'], golden[:2])
            self.assertEqual(trimmed['knowledge_stop'], output['knowledge_stop'])
            self.assertEqual(controlled.evaluate(value, trimmed)['verdict'], 'Inconclusive')

    def test_all_compact_root_facts_fit_the_minimum_evidence_budget(self):
        # The three summaries can coexist. Both projected labels are maximal;
        # all numeric fields use their longest valid representations.
        root = {'schema': controlled.OUTPUT_SCHEMA, 'adapter': controlled.ADAPTER, 'model': controlled.MODEL,
                'scenario_id': 's' * 128, 'input_sha256': 'f' * 64, 'execution': 'EnvironmentInterrupted',
                'terminal': False, 'coordinators_finished': False, 'evidence_complete': False,
                'projection': [], 'compatibility_projection': None,
                'observation_failure': {'class': 'UnmappedMaterial', 'index': 255, 'operation_id': 'o' * 128},
                'knowledge_stop': {'index': 255, 'phase': 'BeforeInitialState', 'reason': 'KnowledgeModelIncomplete'},
                'safety_failure': {'index': 255, 'active': 40256}, 'limitations': controlled.LIMITATIONS.copy()}
        self.assertLessEqual(len(controlled.canonical(root).encode()), 2048)

    def test_unexpected_root_growth_does_not_replace_safety_with_invalid_scenario(self):
        value = controlled.scenario('root-growth', [controlled.controlled_command(1, action='guard_memory')],
                                    [controlled.row('r-' + str(index)) for index in range(4097)])
        value['budgets']['evidence_bytes'] = 2048
        # This intentionally violates the static root bound to check fail-safe
        # bookkeeping; it is not an admissible output or runtime resource claim.
        with patch.object(controlled, 'LIMITATIONS', ['x' * 3000]):
            output = controlled.expected_output(value)
        self.assertEqual(output['safety_failure'], {'index': 0, 'active': 4097})
        self.assertEqual(output['projection'], [])
        self.assertFalse(output['evidence_complete'])


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

    def test_independent_unknown_deletion_can_change_view_count_but_preserve_target(self):
        original = controlled.late_candidate()
        noise = original['commands'].pop()
        noise.update(action='guard_persistent', actor='actor-a')
        noise['guard']['actor_sequence_delta'] = 1
        noise['schedule'].update(cut='commit_unknown', world_commit=True)
        noise['schedule']['completions'] = [controlled.completion_for(noise)]
        original['commands'].insert(0, noise)
        reduced = controlled.shrink_deletion(original, noise['operation_id'])
        before, after = self.record(original, 'unknown-before'), self.record(reduced, 'unknown-after')
        self.assertEqual(before['execution']['output']['projection'][1]['caller']['possible_states'], 2)
        self.assertEqual(after['execution']['output']['projection'][0]['caller']['possible_states'], 1)
        target = controlled.shrink_target(original, before['execution']['output'], before['evaluation'])
        self.assertIsNotNone(target)
        self.assertEqual(target, controlled.shrink_target(reduced, after['execution']['output'], after['evaluation']))


class DriverTests(unittest.TestCase):
    def test_legacy_unbounded_execution_is_closed_before_any_launch(self):
        with patch.object(controlled.subprocess, 'run', side_effect=AssertionError('legacy launch is forbidden')):
            with self.assertRaisesRegex(controlled.InvalidScenario, 'supervised_entry_required'):
                controlled.run_saved_input('/unused/input', '/unused/binary', expected_provenance={})

    def test_regression_cli_cannot_select_dedicated_record_or_replay(self):
        for option in ('--evidence-dir', '--replay'):
            with self.subTest(option=option), patch.object(controlled, 'record_corpus') as record, \
                    patch.object(controlled, 'replay_corpus') as replay, self.assertRaises(SystemExit):
                main([option, '/unused', '--binary', '/unused/binary', '--trusted-provenance', '/unused/provenance'])
            record.assert_not_called()
            replay.assert_not_called()


class SupervisionSchemaTests(unittest.TestCase):
    """Source-only mocked regressions; no subprocess, resource or fault experiment."""
    def setUp(self):
        helpers = {name: '1' * 64 for name in supervision.HELPER_FILES}
        self.contract = {
            'schema': supervision.CONTRACT_SCHEMA, 'run_id': 'mock-run', 'mode': 'record',
            'root': '/mock/root', 'binary': '/mock/runner', 'evidence_dir': '/mock/new-evidence',
            'replay_dir': None, 'replay_authority': None,
            'provenance': {'schema': 'northstar-admission-controlled-provenance-v1', 'model': controlled.MODEL,
                           'adapter': controlled.ADAPTER, 'binding_version': controlled.BINDING_VERSION,
                           'source_files': helpers.copy(), 'source_sha256': supervision.object_hash(helpers),
                           'binary_sha256': '2' * 64, 'cargo_lock_sha256': '3' * 64,
                           'toolchain': 'rustc 1.97.1 (mock identity)'},
            'helper_source_files': helpers, 'budgets': supervision.PROPOSED_BUDGETS.copy(),
            'plan_counts': supervision.PLAN_COUNTS.copy(),
        }

    @staticmethod
    def reference(name='mock.json', data=b''):
        return {'file': name, 'bytes': len(data), 'sha256': supervision.fingerprint(data)}

    def record(self, stdout=b'{}', *, kind='normal', status=0):
        return {'schema': supervision.CASE_SCHEMA, 'run_id': self.contract['run_id'],
                'contract_sha256': supervision.object_hash(self.contract), 'index': 0, 'id': 'mock-case', 'kind': kind,
                'input': self.reference('input.json'),
                'stdout': {'reference': self.reference('stdout.bin', stdout), 'observed_bytes': len(stdout), 'complete': True},
                'stderr': {'reference': self.reference('stderr.bin'), 'observed_bytes': 0, 'complete': True},
                'process': {'pid': 123, 'identity': 'unreaped-direct-child-pidfd', 'registered': True,
                            'released': True, 'reaped': True, 'wait_status': status,
                            'returncode': supervision.os.waitstatus_to_exitcode(status), 'wall_ms': 1},
                'observation': 'Complete', 'stop_kind': None}

    def test_contract_rejects_boolean_limits_missing_helpers_extra_budget_and_combined_modes(self):
        supervision.validate_contract(self.contract)
        variants = []
        for key, value in (('launches', True), ('launches', 164), ('case_ms', 0), ('whole_work_ms', 600001)):
            bad = copy.deepcopy(self.contract)
            bad['budgets'][key] = value
            variants.append(bad)
        bad = copy.deepcopy(self.contract)
        bad['helper_source_files'].pop(next(iter(bad['helper_source_files'])))
        variants.append(bad)
        bad = copy.deepcopy(self.contract)
        bad['budgets']['rss_hard_cap'] = 1024 ** 3
        variants.append(bad)
        bad = copy.deepcopy(self.contract)
        bad['mode'] = 'record-and-replay'
        variants.append(bad)
        for bad in variants:
            with self.assertRaises(supervision.SupervisionError):
                supervision.validate_contract(bad)

    def test_common_case_validator_applies_to_rejection_and_all_shrink_records(self):
        for kind in ('normal', 'rejection', 'shrink'):
            value = self.record(kind=kind, status=512 if kind == 'rejection' else 0)
            supervision.validate_case_record(value, self.contract, 0, 'mock-case', kind)
            for key, bad_value in (('wall_ms', True), ('returncode', True), ('wait_status', 0x7f), ('registered', False)):
                malformed = copy.deepcopy(value)
                malformed['process'][key] = bad_value
                with self.subTest(kind=kind, field=key), self.assertRaises(supervision.SupervisionError):
                    supervision.validate_case_record(malformed, self.contract, 0, 'mock-case', kind)

    def test_complete_capture_wall_boundary_is_contract_bounded(self):
        value = self.record()
        value['process']['wall_ms'] = self.contract['budgets']['case_ms']
        supervision.validate_case_record(value, self.contract, 0, 'mock-case', 'normal')
        value['process']['wall_ms'] += 1
        with self.assertRaisesRegex(supervision.SupervisionError, 'complete_capture_exceeds_case_deadline'):
            supervision.validate_case_record(value, self.contract, 0, 'mock-case', 'normal')

    def test_historical_seven_field_execution_never_becomes_supervised(self):
        historical = {'command': ['/old/runner', '/old/input'], 'returncode': 0, 'wall_ms': 1,
                      'input_file_sha256': '1' * 64, 'stdout_sha256': '2' * 64, 'output': {}, 'provenance': {}}
        with self.assertRaises(supervision.SupervisionError):
            supervision.validate_case_record(historical, self.contract, 0, 'mock-case', 'normal')
        with self.assertRaises(supervision.SupervisionError):
            supervision.validate_owner_capture({'schema': 'northstar-admission-controlled-corpus-v1'}, self.contract)

    def test_prefix_output_cannot_be_parsed_into_an_invariant(self):
        record = self.record(b'{"apparently":"valid"}')
        record['observation'] = 'OutputLimit'
        record['stop_kind'] = 'ResourceInterrupted'
        record['stdout']['complete'] = False
        fixture = {'kind': 'normal', 'value': None}
        with patch.object(controlled, 'loads', side_effect=AssertionError('truncated prefix must not be parsed')):
            output, evaluation, matched, reason = supervision.evaluate_fixture(controlled, fixture, record, b'{}')
        self.assertIsNone(output)
        self.assertIsNone(evaluation)
        self.assertFalse(matched)
        self.assertEqual(reason, 'OutputLimit')

    def test_stream_cap_plus_one_is_a_lower_bound_not_full_length(self):
        stream = {'reference': self.reference('prefix.bin', b'abc'), 'observed_bytes': 4, 'complete': False}
        supervision.validate_stream(stream, 3)
        for changes in ({'observed_bytes': 5}, {'complete': True}, {'observed_bytes': True}):
            with self.assertRaises(supervision.SupervisionError):
                supervision.validate_stream(dict(stream, **changes), 3)

    def test_expected_domain_negatives_still_match_the_entire_fixed_fixture(self):
        cancelled = controlled.scenario('cancelled-fixture', [controlled.controlled_command(1, cut='commit_cancel')])
        missing = controlled.controlled_command(1)
        missing['schedule']['completions'][0]['attempt'] += 1
        inconclusive = controlled.scenario('inconclusive-fixture', [missing])
        for value, verdict in ((cancelled, 'Cancelled'), (inconclusive, 'Inconclusive'),
                               (controlled.late_candidate(), 'InvariantViolation'),
                               (controlled.late_candidate(positive=True), 'Pass')):
            output = controlled.expected_output(value)
            raw = controlled.canonical(output).encode()
            record = self.record(raw)
            fixture = {'kind': 'normal', 'value': value}
            actual, evaluation, matched, reason = supervision.evaluate_fixture(controlled, fixture, record, raw)
            self.assertEqual(actual, output)
            self.assertEqual(evaluation['verdict'], verdict)
            self.assertTrue(matched)
            self.assertIsNone(reason)
            self.assertEqual(evaluation['qualified'], verdict == 'Pass')

    def test_rejection_requires_exact_reason_output_and_actual_exit_two(self):
        expected = {'schema': controlled.REJECTION_SCHEMA, 'class': 'InvalidScenario', 'reason': 'fields'}
        fixture = {'kind': 'rejection', 'reason': 'fields'}
        for code, output, match in ((512, expected, True), (0, expected, False),
                                     (512, dict(expected, reason='schema'), False),
                                     (512, dict(expected, extra=True), False)):
            raw = controlled.canonical(output).encode()
            result = supervision.evaluate_fixture(controlled, fixture, self.record(raw, kind='rejection', status=code), raw)
            self.assertEqual(result[2], match)

    def test_malformed_complete_output_is_saved_as_an_unexpected_stop(self):
        output, evaluation, matched, reason = supervision.evaluate_fixture(
            controlled, {'kind': 'normal', 'value': None}, self.record(b'{'), b'{')
        self.assertIsNone(output)
        self.assertIsNone(evaluation)
        self.assertFalse(matched)
        self.assertTrue(reason.startswith('MalformedOrUnexpectedOutput:'))

    def test_not_started_observation_has_no_invented_pid_or_wait_status(self):
        record = self.record(b'')
        record['process'].update(pid=None, identity=None, registered=False, released=False,
                                 reaped=False, wait_status=None, returncode=None)
        record['observation'] = 'NotStarted'
        record['stop_kind'] = 'EnvironmentInterrupted'
        supervision.validate_case_record(record, self.contract, 0, 'mock-case', 'normal')
        record['process']['pid'] = 123
        with self.assertRaises(supervision.SupervisionError):
            supervision.validate_case_record(record, self.contract, 0, 'mock-case', 'normal')


class OwnerProtocolTests(unittest.TestCase):
    def setUp(self):
        self.state = supervision.OwnerProtocol('mock-run', 'record', '1' * 64, 0)
        self.state.worker_pid = 100
        self.prefix = SupervisionSchemaTests.reference('prefix-000.json')

    def send(self, packet_type, *, role='worker', index=-1, now=1, descriptors=(), **data):
        return self.state.accept(dict(type=packet_type, run_id='mock-run', role=role, index=index, **data), list(descriptors), now)

    def begin(self):
        self.send('Hello', contract_sha256='1' * 64, total=82, prefix=self.prefix)
        return self.send('Begin', index=0, id='fixed-case', kind='normal')

    def register(self):
        self.begin()
        self.send('Launch', index=0, role='rust')
        with patch.object(supervision.signal, 'pidfd_send_signal') as probe, \
                patch.object(supervision.select, 'select', return_value=([], [], [])), \
                patch.object(supervision.os, 'getpid', return_value=99):
            response = self.send('Register', index=0, role='rust', pid=101, descriptors=[20])
        probe.assert_called_once_with(20, 0)
        return response

    def test_registration_ack_binds_ordinal_role_and_exact_run(self):
        response = self.register()
        self.assertEqual((response['type'], response['run_id'], response['index'], response['role']),
                         ('Registered', 'mock-run', 0, 'rust'))
        self.assertEqual(self.state.child_fd, 20)
        for changes in ({'index': 1}, {'role': 'worker'}, {'run_id': 'another-run'}):
            response = dict(response, **changes)
            with patch.object(supervision, '_send_packet'), patch.object(supervision, '_remaining', return_value=0.01), \
                    patch.object(supervision.select, 'select', return_value=([object()], [], [])), \
                    patch.object(supervision, '_receive_packet', return_value=(response, [])), \
                    self.assertRaises(supervision.SupervisionError):
                supervision._exchange(object(), 'mock-run', {'type': 'Register', 'index': 0, 'role': 'rust', 'pid': 101},
                                      'Registered', 100)

    def test_case_deadline_covers_preparation_and_clips_to_remaining_whole_work(self):
        response = self.begin()
        self.assertEqual(response['deadline_ns'], 30_000_000_001)
        with self.assertRaises(supervision.SupervisionError):
            self.send('Launch', index=0, role='rust', now=response['deadline_ns'])
        self.state = supervision.OwnerProtocol('mock-run', 'record', '1' * 64, 0)
        self.state.phase = 'idle'
        response = self.send('Begin', index=0, id='last-window', kind='normal', now=599_000_000_000)
        self.assertEqual(response['deadline_ns'], 600_000_000_000)

    def test_no_launch_at_cap_no_second_child_and_no_reap_without_kernel_exit(self):
        self.begin()
        self.state.launches = 128
        with self.assertRaises(supervision.SupervisionError):
            self.send('Launch', index=0, role='rust')
        self.state = supervision.OwnerProtocol('mock-run', 'record', '1' * 64, 0)
        self.state.worker_pid = 100
        self.register()
        with self.assertRaises(supervision.SupervisionError):
            self.send('Register', index=0, role='rust', pid=102, descriptors=[21])
        with patch.object(supervision.select, 'select', return_value=([], [], [])), self.assertRaises(supervision.SupervisionError):
            self.send('Reaped', index=0, role='rust', pid=101, wait_status=0)

    def test_signal_sent_never_means_reaped_and_json_alone_cannot_finish_a_case(self):
        self.register()
        with patch.object(supervision, '_signal_owned') as kill:
            self.send('AbortChild', index=0, role='rust')
        kill.assert_called_once_with(20)
        self.assertEqual(self.state.phase, 'running')
        with self.assertRaises(supervision.SupervisionError):
            self.send('CaseReady', index=0, fixture_status='FixtureMatched', prefix=SupervisionSchemaTests.reference('prefix-001.json'),
                      observation=SupervisionSchemaTests.reference('000.observation.json'),
                      result=SupervisionSchemaTests.reference('000.result.json'), stop=None, stop_kind=None, interruption_kind=None)

    def test_before_registration_worker_death_is_incomplete_even_when_bootstrap_reaped(self):
        self.begin()
        self.send('Launch', index=0, role='rust')
        with patch.object(supervision.os, 'waitpid', side_effect=[(100, 9), (101, 9), ChildProcessError()]):
            self.assertTrue(self.state.reap())
        self.assertEqual(self.state.worker_exit_status, -9)
        self.assertEqual(self.state.unexpected_children, 1)
        self.assertEqual(self.state.stop, 'WorkerExitedBeforeTerminal')
        self.assertFalse(self.state.done)

    def test_registered_worker_death_keeps_exact_child_handle_for_cleanup(self):
        self.register()
        with patch.object(supervision.os, 'waitpid', side_effect=[(100, 9), (0, 0)]):
            self.assertFalse(self.state.reap())
        self.assertEqual(self.state.child_fd, 20)
        with patch.object(supervision, '_signal_owned') as signal_handle, \
                patch.object(self.state, 'reap', return_value=True), \
                patch.object(supervision, '_now', return_value=0):
            self.assertTrue(supervision._cleanup(self.state, 19))
        self.assertEqual([call.args[0] for call in signal_handle.call_args_list], [20, 19])

    def test_typed_resource_stop_survives_case_ready_and_clean_terminal(self):
        self.register()
        with patch.object(supervision.select, 'select', return_value=([20], [], [])), patch.object(supervision.os, 'close'):
            self.send('Reaped', index=0, role='rust', pid=101, wait_status=9)
        self.send('CaseReady', index=0, fixture_status='UnexpectedStop',
                  prefix=SupervisionSchemaTests.reference('prefix-001.json'),
                  observation=SupervisionSchemaTests.reference('000.observation.json'),
                  result=SupervisionSchemaTests.reference('000.result.json'), stop='OutputLimit',
                  stop_kind='ResourceInterrupted', interruption_kind='ResourceInterrupted')
        self.send('Done', index=1, complete=False, prefix=self.state.prefix,
                  terminal=SupervisionSchemaTests.reference('corpus.json'))
        with patch.object(supervision.os, 'waitpid', side_effect=[(100, 512), ChildProcessError()]):
            self.assertTrue(self.state.reap())
        self.assertEqual(self.state.worker_exit_status, 2)
        self.assertEqual(self.state.interruption_kind, 'ResourceInterrupted')
        self.assertTrue(self.state.done)

    def test_no_terminal_ack_after_wrong_run_extra_fields_or_missing_tail(self):
        self.begin()
        self.state.phase = 'idle'
        for completed in (0, 78, 81):
            self.state.completed = self.state.matched = self.state.launches = completed
            self.state.case_index = self.state.case_deadline = None
            with self.assertRaises(supervision.SupervisionError):
                self.send('Done', index=completed, complete=True, prefix=self.prefix,
                          terminal=SupervisionSchemaTests.reference('corpus.json'))


class SupervisionPersistenceTests(unittest.TestCase):
    def test_new_private_directory_fsyncs_parent_entry_before_its_own_contents(self):
        with patch.object(Path, 'mkdir') as mkdir, patch.object(supervision.os, 'open', side_effect=[30, 31]) as opened, \
                patch.object(supervision.os, 'fsync') as fsync, patch.object(supervision.os, 'close'):
            supervision.EvidenceStore('/mock/new-evidence', supervision.PROPOSED_BUDGETS)
        mkdir.assert_called_once_with(mode=0o700, parents=False, exist_ok=False)
        self.assertEqual([call.args[0] for call in opened.call_args_list], [Path('/mock'), Path('/mock/new-evidence')])
        self.assertEqual([call.args[0] for call in fsync.call_args_list], [30, 31])

    def test_reservation_preserves_terminal_reserve_and_prefix_temp_peak(self):
        store = object.__new__(supervision.EvidenceStore)
        store.budgets = supervision.PROPOSED_BUDGETS.copy()
        store.reservation = 0
        request = 3 + store.budgets['stdout_bytes'] + store.budgets['stderr_bytes'] + store.budgets['evaluation_bytes'] + \
            2 * supervision.MAX_CASE_METADATA + 2 * supervision.MAX_PREFIX
        store.used = store.budgets['evidence_bytes'] - store.budgets['terminal_reserve_bytes'] - request
        store.reserve_case(3)
        self.assertEqual(store.reservation, request)
        store.release_case()
        store.used += 1
        with self.assertRaisesRegex(supervision.SupervisionError, 'evidence_reservation_exhausted'):
            store.reserve_case(3)

    def test_unacknowledged_prefix_generation_preserves_previous_exact_bytes(self):
        store = object.__new__(supervision.EvidenceStore)
        store.directory = Path('/mock/evidence')
        store.budgets = supervision.PROPOSED_BUDGETS.copy()
        store.used, store.reservation, store.prefix_generation = 0, 1024 ** 2, 0
        pending, installed = {}, {}
        stream = unittest.mock.MagicMock()
        stream.__enter__.return_value = stream
        stream.write.side_effect = lambda data: pending.update(data=data) or len(data)
        def install(_source, destination):
            self.assertNotIn(destination.name, installed)
            installed[destination.name] = pending['data']
        with patch.object(Path, 'open', return_value=stream), patch.object(Path, 'unlink'), \
                patch.object(supervision.os, 'fsync'), patch.object(store, '_sync_directory'), \
                patch.object(supervision.os, 'link', side_effect=install), \
                patch.object(supervision.os, 'replace', side_effect=AssertionError('acknowledged snapshots are immutable')):
            acknowledged = store.prefix({'cases': []}, terminal=True)
            pending_reference = store.prefix({'cases': [{'index': 0}]})
        self.assertEqual((acknowledged['file'], pending_reference['file']), ('prefix-000.json', 'prefix-001.json'))
        self.assertEqual(supervision.fingerprint(installed[acknowledged['file']]), acknowledged['sha256'])
        self.assertEqual(store.used, sum(len(data) for data in installed.values()))
        self.assertEqual(store.prefix_generation, 2)
        # Worker death before CaseReady cannot change the owner's old reference.
        state = supervision.OwnerProtocol('mock', 'record', '1' * 64, 0)
        state.accept({'type': 'Hello', 'run_id': 'mock', 'index': -1, 'role': 'worker',
                      'contract_sha256': '1' * 64, 'total': 82, 'prefix': acknowledged}, [], 1)
        self.assertEqual(state.prefix, acknowledged)
        self.assertEqual(supervision.fingerprint(installed[state.prefix['file']]), state.prefix['sha256'])

    def test_prefix_generation_bound_is_initial_plus_82_cases(self):
        store = object.__new__(supervision.EvidenceStore)
        store.prefix_generation = 83
        with patch.object(Path, 'open', side_effect=AssertionError('no extra generation')), \
                self.assertRaises(supervision.SupervisionError):
            store.prefix({'cases': [{}] * 83})

    def test_unsupported_resource_installation_is_not_a_soft_fallback(self):
        with patch.object(supervision.resource, 'setrlimit', side_effect=OSError('unsupported')), \
                patch.object(supervision.os, 'fork', side_effect=AssertionError('must not fork')):
            with self.assertRaises(OSError):
                supervision._limits(60, 60)

    def test_parent_check_occurs_after_parent_death_setup(self):
        sequence = []
        with patch.object(supervision, '_prctl', side_effect=lambda *_: sequence.append('parent-death')) as parent_death, \
                patch.object(supervision.os, 'getppid', side_effect=lambda: sequence.append('parent-check') or 42):
            supervision._parent_death(42)
        self.assertEqual(sequence, ['parent-death', 'parent-check'])
        parent_death.assert_called_once_with(1, supervision.signal.SIGKILL)
        with patch.object(supervision, '_prctl'), patch.object(supervision.os, 'getppid', return_value=43):
            with self.assertRaises(supervision.SupervisionError):
                supervision._parent_death(42)

    def test_raw_malformed_bytes_are_committed_before_any_oracle_call(self):
        fixture_case = SupervisionSchemaTests()
        fixture_case.setUp()
        contract = fixture_case.contract
        record = fixture_case.record(b'{')
        capture = {'process': record['process'], 'observation': 'Complete', 'stop_kind': None,
                   'bytes': {'stdout': b'{', 'stderr': b''}, 'observed': {'stdout': 1, 'stderr': 0},
                   'complete': {'stdout': True, 'stderr': True}}
        calls = []
        store = SimpleNamespace(
            immutable=lambda name, data: calls.append(('raw', name, data)) or fixture_case.reference(name, data),
            json=lambda name, value: calls.append(('observation', name, value)) or fixture_case.reference(name))
        fixture = {'id': 'mock-case', 'kind': 'normal', 'value': None}
        with patch.object(controlled, 'loads', side_effect=AssertionError('save must precede parse')):
            saved, reference = supervision.save_observation(store, contract, fixture, 0, record['input'], capture)
        self.assertEqual([call[0] for call in calls], ['raw', 'raw', 'observation'])
        self.assertEqual(calls[0][2], b'{')
        self.assertEqual(reference['file'], '000.observation.json')
        result = supervision.evaluate_fixture(controlled, fixture, saved, b'{')
        self.assertFalse(result[2])
        self.assertIsNone(result[1])

    def test_failed_fsync_never_returns_a_durable_reference(self):
        store = object.__new__(supervision.EvidenceStore)
        store.directory = Path('/mock/evidence')
        store.budgets = supervision.PROPOSED_BUDGETS.copy()
        store.used, store.reservation = 0, 100
        stream = unittest.mock.MagicMock()
        with patch.object(Path, 'open', return_value=stream), \
                patch.object(supervision.os, 'fsync', side_effect=OSError('storage failure')):
            with self.assertRaises(OSError):
                store.immutable('failed.bin', b'bytes')
        self.assertEqual(store.used, 5)
        self.assertEqual(store.reservation, 95)

    def test_binary_metadata_refuses_privileged_exec_and_unsupported_capability_checks(self):
        metadata = SimpleNamespace(st_mode=supervision.stat.S_IFREG | 0o755, st_dev=1, st_ino=2,
                                   st_uid=1000, st_gid=1000, st_size=100, st_mtime_ns=1, st_ctime_ns=1)
        for mode, capability, error in ((metadata.st_mode | supervision.stat.S_ISUID, b'', None),
                                         (metadata.st_mode | supervision.stat.S_ISGID, b'', None),
                                         (metadata.st_mode, b'file-capabilities', None),
                                         (metadata.st_mode, b'', OSError(supervision.errno.ENOTSUP, 'unsupported'))):
            variant = copy.copy(metadata)
            variant.st_mode = mode
            with patch.object(supervision.os, 'fstat', return_value=variant), \
                    patch.object(supervision.os, 'getxattr', return_value=capability, side_effect=error), \
                    self.assertRaises(supervision.SupervisionError):
                supervision._binary_identity(21)
        with patch.object(supervision.os, 'fstat', return_value=metadata), \
                patch.object(supervision.os, 'getxattr', side_effect=OSError(supervision.errno.ENODATA, 'no capability')):
            self.assertEqual(supervision._binary_identity(21)[5], 100)


class CaptureLifecycleTests(unittest.TestCase):
    def capture(self, reads, readiness, reaps, *, limit=None, pidfd_error=None):
        fixture = SupervisionSchemaTests()
        fixture.setUp()
        if limit is not None:
            fixture.contract['budgets']['stdout_bytes'] = limit
        packets = []
        def exchange(_channel, _run_id, message, _reply, deadline, descriptor=None):
            packets.append((message['type'], descriptor))
            return deadline
        with patch.object(supervision.os, 'pipe2', side_effect=[(10, 11), (12, 13), (14, 15), (16, 17)]), \
                patch.object(supervision.os, 'getpid', return_value=42), \
                patch.object(supervision.os, 'fork', return_value=99), \
                patch.object(supervision.os, 'pidfd_open', side_effect=pidfd_error, return_value=20), \
                patch.object(supervision.os, 'read', side_effect=reads), \
                patch.object(supervision.os, 'write', return_value=1) as release, \
                patch.object(supervision.os, 'waitpid', side_effect=reaps) as wait, \
                patch.object(supervision.os, 'set_blocking'), patch.object(supervision.os, 'close'), \
                patch.object(supervision.os, 'kill', side_effect=AssertionError('numeric PID signal forbidden')), \
                patch.object(supervision.select, 'select', side_effect=readiness), \
                patch.object(supervision, '_now', return_value=0), patch.object(supervision, '_remaining', return_value=0.01), \
                patch.object(supervision, '_exchange', side_effect=exchange):
            result = supervision.capture_child(object(), fixture.contract, 0, Path('/mock/input'), 21, 1000, 128)
        return result, packets, release, wait

    def test_complete_json_and_eof_wait_for_actual_terminal_reap(self):
        result, packets, release, wait = self.capture(
            [b'R', b'{}', b'', b''], [([14], [], []), ([10, 12], [], []), ([10], [], []), ([], [], [])],
            [(0, 0), (0, 0), (99, 0)])
        self.assertEqual(wait.call_count, 3)
        self.assertEqual(packets, [('Launch', None), ('Register', 20), ('Reaped', None)])
        release.assert_called_once_with(17, b'G')
        self.assertEqual(result['observation'], 'Complete')
        self.assertTrue(result['process']['reaped'])

    def test_overflow_keeps_only_prefix_plus_observed_sentinel_then_requires_reap(self):
        result, packets, _release, wait = self.capture(
            [b'R', b'abcd', b''], [([14], [], []), ([10, 12], [], [])], [(99, 9)], limit=3)
        self.assertEqual(result['bytes']['stdout'], b'abc')
        self.assertEqual(result['observed']['stdout'], 4)
        self.assertFalse(result['complete']['stdout'])
        self.assertEqual(result['observation'], 'OutputLimit')
        self.assertEqual(result['stop_kind'], 'ResourceInterrupted')
        self.assertEqual(packets[-2:], [('AbortChild', None), ('Reaped', None)])
        self.assertEqual(wait.call_count, 1)

    def test_pidfd_failure_never_releases_gate_or_claims_reap(self):
        result, packets, release, wait = self.capture([b'R'], [([14], [], [])], [], pidfd_error=OSError('unsupported'))
        release.assert_not_called()
        wait.assert_not_called()
        self.assertEqual(packets, [('Launch', None)])
        self.assertFalse(result['process']['registered'])
        self.assertFalse(result['process']['released'])
        self.assertFalse(result['process']['reaped'])
        self.assertEqual(result['observation'], 'EnvironmentInterrupted')
        self.assertEqual(result['stop_kind'], 'EnvironmentInterrupted')

    def test_child_bootstrap_orders_parent_limits_and_private_gate_before_exec(self):
        calls = []
        with patch.object(supervision, '_parent_death', side_effect=lambda *_: calls.append('parent-death/check')), \
                patch.object(supervision, '_limits', side_effect=lambda *_: calls.append('limits')), \
                patch.object(supervision.resource, 'setrlimit'), \
                patch.object(supervision, '_close_except', side_effect=lambda *_: calls.append('close-unrelated')), \
                patch.object(supervision.os, 'write', side_effect=lambda *_: calls.append('bootstrap-ready') or 1), \
                patch.object(supervision.os, 'read', side_effect=lambda *_: calls.append('private-gate') or b'G'), \
                patch.object(supervision.os, 'getppid', return_value=42), patch.object(supervision.os, 'close'), \
                patch.object(supervision.os, 'dup2'), \
                patch.object(supervision.os, 'execve', side_effect=lambda *_: calls.append('exec')):
            supervision._child_bootstrap(42, 128, 10, 11, 12, 13, '/mock/binary', 21, '/mock/input')
        self.assertEqual(calls, ['parent-death/check', 'limits', 'close-unrelated', 'bootstrap-ready', 'private-gate', 'exec'])


class CallerReceiptTests(unittest.TestCase):
    def setUp(self):
        fixture = SupervisionSchemaTests()
        fixture.setUp()
        self.contract = fixture.contract
        self.receipt = {'schema': supervision.RECEIPT_SCHEMA, 'run_id': self.contract['run_id'],
                        'contract_sha256': supervision.object_hash(self.contract), 'mode': 'record',
                        'owner_exit_status': 0, 'status': 'FixtureMatched', 'completed': 82,
                        'fixture_matched': 82, 'launches': 82, 'worker_exit_status': 0,
                        'cleanup_complete': True, 'unexpected_children': 0,
                        'prefix': fixture.reference('prefix-082.json'), 'terminal': fixture.reference('corpus.json'),
                        'stop': None, 'stop_kind': None, 'interruption_kind': None}

    def capture(self):
        return {'schema': supervision.CAPTURE_SCHEMA, 'owner_exit_status': self.receipt['owner_exit_status'],
                'stdout_complete': True, 'receipt': copy.deepcopy(self.receipt)}

    def authority(self):
        return {'schema': 'northstar-controlled-external-caller-v1', 'invocation_id': 'mock-executor-run',
                'mechanism_sha256': '4' * 64, 'owner_exit_status': self.receipt['owner_exit_status'],
                'receipt_sha256': supervision.fingerprint(supervision.encoded(self.receipt)),
                'startup_limit_ms': 10000, 'total_limit_ms': 617000, 'observed_total_ms': 1234, 'stdout_complete': True}

    def test_caller_receipt_requires_separate_trusted_mechanism_and_actual_exit(self):
        self.assertEqual(supervision.validate_owner_capture(self.capture(), self.contract, caller_evidence=self.authority()),
                         {'FixtureMatched': True, 'supervision_complete': True})
        with self.assertRaises(supervision.SupervisionError):
            supervision.validate_owner_capture(self.capture(), self.contract)
        for field, value in (('owner_exit_status', 2), ('stdout_complete', False)):
            capture = self.capture()
            capture[field] = value
            with self.assertRaises(supervision.SupervisionError):
                supervision.validate_owner_capture(capture, self.contract, caller_evidence=self.authority())
        caller = self.authority()
        caller['receipt_sha256'] = '0' * 64
        with self.assertRaises(supervision.SupervisionError):
            supervision.validate_owner_capture(self.capture(), self.contract, caller_evidence=caller)

    def test_known_clean_mismatch_keeps_lifecycle_separate_from_fixture_match(self):
        self.receipt.update(owner_exit_status=2, worker_exit_status=2, status='UnexpectedStop', completed=1,
                            fixture_matched=0, launches=1, stop='FixtureMismatch', stop_kind='FixtureMismatch',
                            prefix=SupervisionSchemaTests.reference('prefix-001.json'))
        result = supervision.validate_owner_capture(self.capture(), self.contract, caller_evidence=self.authority())
        self.assertEqual(result, {'FixtureMatched': False, 'supervision_complete': True})
        replay = copy.deepcopy(self.contract)
        replay.update(mode='replay', replay_dir='/mock/prior',
                      replay_authority={'contract': self.contract, 'capture': self.capture(), 'caller_evidence': self.authority()})
        with self.assertRaisesRegex(supervision.SupervisionError, 'prior_fixture_unmatched'):
            supervision.validate_contract(replay)

    def test_resource_environment_and_storage_stops_stay_incomplete_after_clean_reap(self):
        original = copy.deepcopy(self.receipt)
        for kind in supervision.INTERRUPTION_KINDS:
            self.receipt = dict(original, owner_exit_status=2, worker_exit_status=2,
                                status='EnvironmentInterrupted', completed=1, fixture_matched=0, launches=1,
                                prefix=SupervisionSchemaTests.reference('prefix-001.json'),
                                stop='bounded actual interruption', stop_kind=kind, interruption_kind=kind)
            self.assertEqual(supervision.validate_owner_capture(self.capture(), self.contract, caller_evidence=self.authority()),
                             {'FixtureMatched': False, 'supervision_complete': False})
            self.receipt['status'] = 'UnexpectedStop'
            with self.assertRaisesRegex(supervision.SupervisionError, 'interruption_is_not_clean_mismatch'):
                supervision.validate_owner_capture(self.capture(), self.contract, caller_evidence=self.authority())

    def test_later_owner_interruption_does_not_replace_first_fixture_stop(self):
        state = supervision.OwnerProtocol('mock', 'record', '1' * 64, 0)
        state.fail('first mismatch', 'FixtureMismatch')
        state.fail('later deadline', 'ResourceInterrupted')
        self.assertEqual((state.stop, state.stop_kind, state.interruption_kind),
                         ('first mismatch', 'FixtureMismatch', 'ResourceInterrupted'))

    def test_missing_tail_cleanup_or_worker_terminal_never_qualifies(self):
        original = copy.deepcopy(self.receipt)
        for changes in ({'completed': 78, 'fixture_matched': 78, 'launches': 78},
                        {'cleanup_complete': False}, {'worker_exit_status': None},
                        {'terminal': None}, {'unexpected_children': 1}, {'owner_exit_status': True}):
            self.receipt = dict(original, **changes)
            with self.subTest(changes=changes), self.assertRaises(supervision.SupervisionError):
                supervision.validate_owner_capture(self.capture(), self.contract, caller_evidence=self.authority())


class OwnerSetupTests(unittest.TestCase):
    def test_sigchld_default_and_receipt_setup_precede_first_fork(self):
        order = []
        def forbid_real_fork():
            order.append('fork-boundary')
            raise OSError('mocked stop before process creation')
        with patch.object(supervision, '_limits'), patch.object(supervision, '_prctl'), \
                patch.object(supervision, '_prepare_receipt', side_effect=lambda: order.append('receipt-ready')), \
                patch.object(supervision.signal, 'signal', side_effect=lambda sig, _handler: order.append(('signal', sig))), \
                patch.object(supervision.resource, 'getrlimit', return_value=(128, 128)), \
                patch.object(supervision.resource, 'setrlimit'), patch.object(supervision, '_close_except'), \
                patch.object(supervision.socket, 'socketpair', return_value=(unittest.mock.MagicMock(), unittest.mock.MagicMock())), \
                patch.object(supervision.os, 'pipe2', return_value=(30, 31)), patch.object(supervision.os, 'close'), \
                patch.object(supervision.os, 'fork', side_effect=forbid_real_fork), \
                patch.object(supervision, '_cleanup', return_value=True), patch.object(supervision, '_receipt_write'), \
                patch.object(supervision, '_now', return_value=0):
            self.assertEqual(supervision.owner_main(b'{}', run_id='mock', mode='record', contract_sha256='1' * 64), 2)
        self.assertLess(order.index('receipt-ready'), order.index('fork-boundary'))
        self.assertLess(order.index(('signal', supervision.signal.SIGCHLD)), order.index('fork-boundary'))

    def test_receipt_capability_failure_prevents_process_creation(self):
        with patch.object(supervision, '_limits'), \
                patch.object(supervision, '_prepare_receipt', side_effect=supervision.SupervisionError('unsupported receipt')), \
                patch.object(supervision.os, 'fork') as fork, patch.object(supervision, '_cleanup', return_value=True), \
                patch.object(supervision, '_receipt_write'):
            self.assertEqual(supervision.owner_main(b'{}', run_id='mock', mode='record', contract_sha256='1' * 64), 2)
        fork.assert_not_called()


class WorkerFailurePersistenceTests(unittest.TestCase):
    class MemoryStore:
        def __init__(self, budgets, *, fail_stderr=False):
            self.budgets, self.fail_stderr = budgets, fail_stderr
            self.directory = Path('/mock/new-evidence')
            self.reservation = 0
            self.data, self.writes = {}, []

        def reserve_case(self, _size):
            self.reservation = 100 * 1024 ** 2

        def release_case(self):
            self.reservation = 0

        def immutable(self, name, data, *, terminal=False):
            self.writes.append(name)
            if name in self.data:
                raise FileExistsError(name)
            if self.fail_stderr and name.endswith('.stderr.bin'):
                raise OSError('mocked stderr persistence failure')
            self.data[name] = data
            return SupervisionSchemaTests.reference(name, data)

        def json(self, name, value, *, maximum=supervision.MAX_CASE_METADATA, terminal=False):
            data = supervision.encoded(value)
            supervision.need(len(data) <= maximum, 'mock metadata bound')
            return self.immutable(name, data, terminal=terminal)

        def prefix(self, value, *, terminal=False):
            return self.json(f'prefix-{len(value["cases"]):03d}.json', value,
                             maximum=supervision.MAX_PREFIX, terminal=terminal)

    def run_mocked_case(self, *, wall_ms, fail_stderr=False):
        fixtures = SupervisionSchemaTests()
        fixtures.setUp()
        contract = fixtures.contract
        fixture = {'id': 'mock-case', 'kind': 'normal', 'value': None, 'bytes': b'{}', 'reason': None}
        record = fixtures.record(b'{}')
        record['process']['wall_ms'] = wall_ms
        captured = {'process': record['process'], 'observation': 'Complete', 'stop_kind': None,
                    'bytes': {'stdout': b'{}', 'stderr': b''}, 'observed': {'stdout': 2, 'stderr': 0},
                    'complete': {'stdout': True, 'stderr': True}}
        store = self.MemoryStore(contract['budgets'], fail_stderr=fail_stderr)
        packets = []
        def exchange(_channel, _run_id, packet, _reply, _deadline, descriptor=None):
            packets.append(packet)
            return 10 ** 12
        with patch.object(supervision, '_check_worker_sources'), \
                patch.object(controlled, 'check_current_provenance'), \
                patch.object(supervision, 'fixture_plan', return_value=[fixture]), \
                patch.object(supervision, 'EvidenceStore', return_value=store), \
                patch.object(supervision, '_verified_binary', return_value=21), \
                patch.object(supervision, '_binary_identity', return_value=('stable-metadata',)), \
                patch.object(supervision, 'capture_child', return_value=captured), \
                patch.object(supervision, '_exchange', side_effect=exchange), \
                patch.object(supervision, 'read_reference', return_value=b'{}'), patch.object(supervision.os, 'close'), \
                patch.object(controlled, 'loads', side_effect=AssertionError('invalid observation must stop before oracle')):
            status = supervision.worker_main(object(), supervision.encoded(contract), contract['run_id'], 'record',
                                             supervision.object_hash(contract), 10 ** 12, 128)
        self.assertEqual(status, 2)
        return store, packets

    def test_actual_invalid_observation_is_saved_once_before_validation_failure(self):
        store, packets = self.run_mocked_case(wall_ms=30001)
        saved = supervision.strict_json(store.data['000.observation.json'], supervision.MAX_CASE_METADATA)
        self.assertEqual(saved['process']['wall_ms'], 30001)
        self.assertEqual(saved['process']['pid'], 123)
        self.assertEqual(store.writes.count('000.stdout.bin'), 1)
        result = supervision.strict_json(store.data['000.result.json'], supervision.MAX_CASE_METADATA)
        self.assertEqual(result['observation']['file'], '000.observation.json')
        self.assertEqual(result['stop_kind'], 'EnvironmentInterrupted')
        self.assertEqual(result['interruption_kind'], 'EnvironmentInterrupted')
        ready = next(packet for packet in packets if packet['type'] == 'CaseReady')
        self.assertEqual(ready['stop_kind'], 'EnvironmentInterrupted')

    def test_partial_raw_save_never_retries_names_or_manufactures_empty_observation(self):
        store, _packets = self.run_mocked_case(wall_ms=1, fail_stderr=True)
        self.assertEqual(store.data['000.stdout.bin'], b'{}')
        self.assertEqual(store.writes.count('000.stdout.bin'), 1)
        self.assertNotIn('000.observation.json', store.data)
        result = supervision.strict_json(store.data['000.result.json'], supervision.MAX_CASE_METADATA)
        self.assertIsNone(result['observation'])
        self.assertEqual(result['stop_kind'], 'StorageInterrupted')
        self.assertEqual(result['observation_loss']['phase'], 'observation_persistence')
        self.assertTrue(result['observation_loss']['capture_available'])
        terminal = supervision.strict_json(store.data['corpus.json'], supervision.MAX_PREFIX)
        self.assertEqual(terminal['first_unexpected_stop']['phase'], 'observation_persistence')
        self.assertIn('mocked stderr persistence failure', terminal['first_unexpected_stop']['reason'])

    def test_cleanup_uses_existing_absolute_deadline_without_restarting_budget(self):
        state = supervision.OwnerProtocol('mock', 'record', '1' * 64, 0)
        with patch.object(supervision, '_now', return_value=100), patch.object(supervision, '_signal_owned'), \
                patch.object(state, 'reap') as reap:
            self.assertFalse(supervision._cleanup(state, 19, deadline=100))
        reap.assert_not_called()
        self.assertEqual(state.stop, 'CleanupDeadline')

    def test_resource_failure_has_no_unsupervised_launch_fallback(self):
        with patch.object(supervision, '_limits', side_effect=OSError('resource enforcement unavailable')), \
                patch.object(supervision.os, 'fork') as fork, patch.object(supervision, '_cleanup', return_value=True), \
                patch.object(supervision, '_receipt_write'):
            self.assertEqual(supervision.owner_main(b'{}', run_id='mock', mode='record', contract_sha256='1' * 64), 2)
        fork.assert_not_called()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--trusted-provenance', type=Path)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--evidence-dir', type=Path)
    group.add_argument('--replay', type=Path)
    args, remaining = parser.parse_known_args(argv)
    if args.evidence_dir or args.replay or args.binary or args.trusted_provenance:
        parser.error('dedicated execution requires scripts/run-controlled-admission.py and an external execution contract')
    return 0 if unittest.main(argv=[sys.argv[0]] + remaining, exit=False).result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
