#!/usr/bin/env python3
"""Pure Stage 1 tests and synthetic replay artifacts. Never starts a service/child/listener."""
import argparse
import builtins
import collections
import contextlib
import copy
import errno
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import platform
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.dont_write_bytecode = True
from lib import experiment_contract as contract

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATHS = (
    'scripts/lib/experiment_contract.py', 'scripts/test-experiment-contract.py',
    'scripts/mixed-traffic-soak.py', 'scripts/check-runtime-experiments.mjs',
    'scripts/test-runtime-experiments.mjs', 'catalog/runtime-experiments.json',
    'catalog/runtime-experiments.schema.json', '.github/workflows/ci.yml',
    'src/db/message_admission_repository.rs', 'crates/northstar-abuse-policy/src/model.rs',
)
S = contract.SECOND


def source_provenance():
    files = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCE_PATHS}
    return {'source_sha256': contract.digest(files), 'files': files,
            'base_commit': 'd9eb2e2dfa948f6a9d3e16b4ce0c08eca4f9c671',
            'scope': 'Exact listed dirty/untracked bytes only; not a full-tree or binary qualification',
            'python': platform.python_version(), 'adapter': 'synthetic_fixture'}


def golden_event(c, domain, active, retained=None, state='Absent', expiry=None, lease=None,
                 effect='Confirmed', execution='Completed', upper=None):
    """Independent fixture expectations: no call to predict or transition code."""
    return {'schema_version': 1, 'operation_id': c.operation_id, 'effect_id': c.effect_id,
            'causal_id': c.causal_id, 'attempt': c.attempt, 'time_us': c.time_us,
            'transition': c.action, 'actor': c.actor, 'key': c.key, 'kind': c.kind,
            'execution': execution, 'domain': domain, 'effect_status': effect,
            'active_min': active, 'active_max': active if upper is None else upper,
            'retained_min': active if retained is None else retained,
            'retained_max': (active if retained is None else retained) if upper is None else upper,
            'row_state': state, 'expires_at_us': expiry, 'lease': lease}


def synthetic_cases():
    """Concrete case corpus, materialized in full by --evidence-dir (never seed-only)."""
    cases = []
    commands, expected = [], []
    for index, kind in enumerate(('direct', 'muc', 'mix'), 1):
        reserve = contract.command(index * 2 - 1, f'key-{index}', kind=kind)
        finalize = contract.command(index * 2, f'key-{index}', action='finalize', kind=kind,
                                    lease=reserve.lease, causal_id=reserve.operation_id)
        commands += [reserve, finalize]
        expected += [golden_event(reserve, 'Proceed', index, state='pending', expiry=1800*S, lease=reserve.lease),
                     golden_event(finalize, 'Accepted', index, state='accepted', expiry=21600*S, lease=reserve.lease)]
    cases.append((contract.scenario('normal-mixed', commands), expected))

    rows = [contract.Row('actor-a', f'retained-{i}', 'payload-a', 'accepted', 21600*S, f'old-lease-{i}', 0)
            for i in range(4095)]
    commands = [contract.command(1, 'key-4096', kind='muc'), contract.command(2, 'key-4097', kind='mix')]
    cases.append((contract.scenario('capacity-4095-4096-4097', commands, rows, purpose='capacity'),
                  [golden_event(commands[0], 'Proceed', 4096, state='pending', expiry=1800*S, lease='lease-1'),
                   golden_event(commands[1], 'CapacityLimited', 4096)]))

    row = contract.Row('actor-a', 'key-existing', 'payload-a', 'accepted', 21600*S, 'old-lease', 0)
    commands = [contract.command(1, row.key), contract.command(2, row.key, payload='payload-other'),
                contract.command(3, row.key, actor='actor-b'),
                contract.command(4, row.key, action='finalize', lease='different-lease')]
    cases.append((contract.scenario('replay-payload-actor-conflict', commands, [row],
                                    actors=('actor-a', 'actor-b'), purpose='replay'),
                  [golden_event(c, outcome, 0 if c.actor == 'actor-b' else 1,
                                state='accepted', expiry=21600*S, lease='old-lease')
                   for c, outcome in zip(commands, ('ReplayAccepted', 'Conflict', 'Conflict', 'AlreadyAccepted'))]))

    for suffix, now, outcome in (('before', 10*S-1, 'ReplayAccepted'), ('at', 10*S, 'Proceed'),
                                  ('after', 10*S+1, 'Proceed')):
        row = contract.Row('actor-a', 'ttl-key', 'payload-a', 'accepted', 10*S, 'old-lease', 0)
        c = contract.command(1, row.key, time_us=now)
        cases.append((contract.scenario('ttl-' + suffix, [c], [row], purpose='ttl'),
                      [golden_event(c, outcome, 1, state='accepted' if suffix == 'before' else 'pending',
                                    expiry=10*S if suffix == 'before' else now+1800*S,
                                    lease='old-lease' if suffix == 'before' else 'lease-1')]))

    row = contract.Row('actor-a', 'pending-key', 'payload-a', 'pending', 1800*S, 'old-lease', 60*S)
    commands = [contract.command(1, row.key, time_us=60*S-1), contract.command(2, row.key, time_us=60*S),
                contract.command(3, row.key, action='finalize', time_us=60*S, lease='old-lease'),
                contract.command(4, row.key, action='finalize', time_us=60*S, lease='lease-2')]
    cases.append((contract.scenario('pending-lease-reclaim', commands, [row], purpose='lease'),
                  [golden_event(c, outcome, 1, state='accepted' if i == 3 else 'pending',
                                expiry=(21600+60)*S if i == 3 else 1800*S,
                                lease='old-lease' if i == 0 else 'lease-2')
                   for i, (c, outcome) in enumerate(zip(commands, ('InProgress', 'Proceed', 'LeaseLost', 'Accepted')))]))

    row = contract.Row('actor-a', 'expired-pending', 'payload-a', 'pending', 0, 'old-lease', 0)
    c = contract.command(1, row.key, action='finalize', time_us=1, lease='old-lease')
    cases.append((contract.scenario('late-finalize-source-semantics', [c], [row], purpose='lease'),
                  [golden_event(c, 'Accepted', 1, state='accepted', expiry=21600*S+1, lease='old-lease')]))

    # Source-predicate constructibility only. This does not establish ordinary
    # caller reachability, a live product bug, or a changed retention policy.
    rows = [contract.Row('actor-a', f'accepted-{i}', 'payload-a', 'accepted', 21600*S, f'lease-{i}', 0)
            for i in range(4096)] + [row]
    cases.append((contract.scenario('late-finalize-4097-candidate', [c], rows, purpose='lease'),
                  [golden_event(c, 'Accepted', 4097, state='accepted', expiry=21600*S+1, lease='old-lease')]))

    c = contract.command(1, cut='reservation_commit_unknown')
    cases.append((contract.scenario('reservation-unknown', [c], purpose='unknown'),
                  [golden_event(c, 'Unknown', 0, state='Unconfirmed', effect='Unknown', upper=1)]))
    c = contract.command(1, cut='before_effect_cancel')
    cases.append((contract.scenario('cancel-before-reservation', [c]),
                  [golden_event(c, 'NotRequested', 0, effect='NotRequested', execution='Cancelled')]))
    return cases


def supplied_evidence(value, projection):
    return {'schema': contract.EVIDENCE_SCHEMA, 'origin': 'supplied_synthetic',
            'scenario_sha256': contract.digest(value), 'projection': copy.deepcopy(projection),
            'invariant': None, 'execution': 'Completed', 'terminal': True, 'evidence_complete': True,
            'wall_ms': 0, 'peak_memory_bytes': 0, 'files': 0,
            'cleanup': {'status': 'NotRequired', 'independent': True, 'owned': [], 'remaining': []},
            'provenance': {'source_sha256': source_provenance()['source_sha256'],
                           'runner': 'pure-contract-test', 'model': contract.MODEL, 'adapter': 'synthetic_fixture'}}


def evaluate(value, actual, expected_failure=None):
    trusted = {'source_sha256': source_provenance()['source_sha256'],
               'runner': 'pure-contract-test', 'model': contract.MODEL, 'adapter': 'synthetic_fixture'}
    return contract.evaluate(value, actual, expected_failure, expected_provenance=trusted)


def saved_counterexample():
    """A manually reduced oracle probe, not production-shared Rust minimization."""
    original, golden = synthetic_cases()[0]
    original = copy.deepcopy(original)
    reduced = copy.deepcopy(original)
    reduced['scenario_id'] = 'minimal-finalize-projection-probe'
    reduced['commands'] = reduced['commands'][:2]
    outputs = []
    invariant = {'id': 'projection-mismatch', 'class': 'ReplayDivergence', 'location': 'op-2'}
    for value, expected in ((original, golden), (reduced, golden[:2])):
        actual = supplied_evidence(value, expected)
        actual['projection'][1]['domain'] = 'Conflict'
        actual['invariant'] = invariant.copy()
        failure = {'projection': copy.deepcopy(actual['projection']), 'invariant': invariant.copy()}
        outputs.append({'input': value, 'actual': actual, 'expected_failure': failure,
                        'evaluation': evaluate(value, actual, failure),
                        'positive_control': evaluate(value, supplied_evidence(value, expected))})
    return {'scope': 'Manual reduction of deliberate synthetic oracle divergence only; no production-shared replay claim',
            'preserved': 'same op-2 finalize domain mismatch after causally required op-1 reservation',
            'original': outputs[0], 'reduced': outputs[1]}


def replay_corpus(corpus):
    """Replay the fixed positive/cancellation baseline, never arbitrary negatives.

    Saved evaluations are untrusted. Recomputing a corrupted observation's
    evaluation cannot turn that observation into the source's golden fixture.
    Deliberate negative probes belong in saved-counterexample.json instead.
    """
    contract.fields(corpus, 'schema limitations provenance cases', 'corpus')
    contract.require(corpus['schema'] == 'northstar-stage1-synthetic-corpus-v1', 'unsupported corpus')
    contract.require(corpus['limitations'] == contract.LIMITATIONS, 'saved corpus scope differs')
    contract.require(corpus['provenance'] == source_provenance(), 'saved scoped source identity does not match current sources')
    cases = contract.array(corpus['cases'], 'cases', 128)
    source_cases = synthetic_cases()
    contract.require(len(cases) == len(source_cases), 'saved corpus must contain the exact source-declared case set')
    for case, (source_input, golden_projection) in zip(cases, source_cases):
        contract.fields(case, 'input actual evaluation', 'saved case')
        contract.require(case['input'] == source_input, 'saved concrete input differs from source-declared fixture')
        result = evaluate(case['input'], case['actual'])
        actual = case['actual']
        contract.require(actual['projection'] == golden_projection,
                         'baseline observation differs from independent source golden projection')
        contract.require(actual['invariant'] is None and actual['execution'] == 'Completed'
                         and actual['terminal'] and actual['evidence_complete'],
                         'baseline execution/evidence contract differs')
        contract.require(actual['cleanup'] == {'status': 'NotRequired', 'independent': True, 'owned': [], 'remaining': []},
                         'baseline no-resource cleanup contract differs')
        expected_verdict = 'Cancelled' if any(event['execution'] == 'Cancelled' for event in golden_projection) else 'Pass'
        contract.require(result['verdict'] == expected_verdict and result['replay_matched']
                         and result['qualified'] == (expected_verdict == 'Pass'),
                         'baseline expected verdict or replay/cleanup qualification differs')
        contract.require(result == case['evaluation'], 'saved replay result differs')
    return {'replay_matched': True, 'cases': len(cases), 'scope': 'synthetic fixture contract only'}


class ContractCases(unittest.TestCase):
    def test_concrete_cases_match_independent_golden_projections(self):
        for value, expected in synthetic_cases():
            with self.subTest(case=value['scenario_id']):
                self.assertEqual(contract.predict(value)['projection'], expected)
                result = evaluate(value, supplied_evidence(value, expected))
                self.assertEqual(result['verdict'], 'Cancelled' if value['scenario_id'].startswith('cancel-') else 'Pass')

    def test_catalog_references_exact_materialized_case_ids(self):
        catalog = json.loads((ROOT / 'catalog/runtime-experiments.json').read_text())
        self.assertEqual(catalog['executable_contract']['scenarios'], [value['scenario_id'] for value, _ in synthetic_cases()])

    def test_capacity_refusal_rolls_back_expired_exact_key_deletion(self):
        rows = [contract.Row('actor-a', f'active-{i}', 'payload-a', 'accepted', 21600*S, f'old-{i}', 0)
                for i in range(4096)]
        rows.append(contract.Row('actor-a', 'expired', 'payload-a', 'pending', 0, 'expired-lease', 0))
        value = contract.scenario('rollback-expired-delete', [contract.command(1, 'expired')], rows, purpose='capacity')
        event = contract.predict(value)['projection'][0]
        self.assertEqual((event['domain'], event['active_min'], event['retained_min'], event['row_state']),
                         ('CapacityLimited', 4096, 4097, 'pending'))
        self.assertEqual(event['lease'], 'expired-lease')

    def test_unknown_expired_key_does_not_confirm_delete(self):
        row = contract.Row('actor-a', 'expired', 'payload-a', 'pending', 0, 'expired-lease', 0)
        value = contract.scenario('unknown-expired-delete', [contract.command(1, 'expired', cut='reservation_commit_unknown')],
                                  [row], purpose='unknown')
        event = contract.predict(value)['projection'][0]
        self.assertEqual((event['active_min'], event['active_max'], event['retained_min'], event['retained_max']), (0, 1, 1, 1))
        self.assertEqual(event['row_state'], 'Unconfirmed')

    def test_late_finalize_4097_projection_cannot_be_silently_reduced(self):
        value, expected = next(case for case in synthetic_cases() if case[0]['scenario_id'] == 'late-finalize-4097-candidate')
        for wrong in (4096, 0):
            actual = supplied_evidence(value, expected)
            actual['projection'][0]['active_min'] = wrong
            actual['projection'][0]['active_max'] = wrong
            self.assertEqual(evaluate(value, actual)['verdict'], 'InvariantViolation')

    def test_expiry_is_not_background_gc(self):
        row = contract.Row('actor-a', 'unrelated', 'payload-a', 'accepted', 1, 'old', 0)
        value = contract.scenario('physical-versus-active', [contract.command(1, time_us=1)], [row], purpose='ttl')
        event = contract.predict(value)['projection'][0]
        self.assertEqual((event['active_min'], event['retained_min']), (1, 2))

    def test_pending_exact_key_cleanup_prevents_later_finalize(self):
        row = contract.Row('actor-a', 'key', 'payload-a', 'pending', 1, 'old', 0)
        commands = [contract.command(1, 'key', time_us=1),
                    contract.command(2, 'key', time_us=1, action='finalize', lease='old')]
        result = contract.predict(contract.scenario('cleanup-before-finalize', commands, [row], purpose='lease'))
        self.assertEqual([x['domain'] for x in result['projection']], ['Proceed', 'LeaseLost'])

    def test_missing_and_payload_conflict_finalization(self):
        row = contract.Row('actor-a', 'key', 'payload-a', 'pending', 100, 'old', 1)
        commands = [contract.command(1, 'missing', action='finalize'),
                    contract.command(2, 'key', action='finalize', payload='payload-other')]
        result = contract.predict(contract.scenario('missing-finalize', commands, [row], purpose='lease'))
        self.assertEqual([x['domain'] for x in result['projection']], ['Missing', 'Conflict'])


class PreflightTests(unittest.TestCase):
    def test_existing_mixed_bounds_include_no_store_and_muc(self):
        for seconds, a, b in ((600, 630, 300), (3600, 3780, 1800)):
            result = contract.preflight_normal(contract.mixed_workload(seconds))
            self.assertEqual(result['maximum_held_per_actor'], {'actor-a': a, 'actor-b': b})

    def test_historical_single_sender_over_cap_is_invalid(self):
        commands = [contract.command(i+1, kind=('direct', 'muc', 'mix')[i % 3], time_us=i*S)
                    for i in range(4097)]
        with self.assertRaisesRegex(contract.InvalidScenario, r'4097>4096'):
            contract.preflight_normal(contract.scenario('historical-invalid-single-sender', commands))

    def test_retained_pending_is_held_even_after_expiry(self):
        rows = [contract.Row('actor-a', f'pending-{i}', 'payload-a', 'pending', 1, f'old-{i}', 0)
                for i in range(4096)]
        value = contract.scenario('retained-pending', [contract.command(1, time_us=1801*S)], rows)
        with self.assertRaisesRegex(contract.InvalidScenario, 'actor capacity'):
            contract.preflight_normal(value)
        self.assertEqual(contract.predict(value)['projection'][0]['active_min'], 1)

    def test_accepted_expiry_before_exact_after_and_burst(self):
        rows = [contract.Row('actor-a', f'accepted-{i}', 'payload-a', 'accepted', 10*S, f'old-{i}', 0)
                for i in range(4096)]
        for now, accepted in ((10*S-1, False), (10*S, True), (10*S+1, True)):
            value = contract.scenario('accepted-expiry', [contract.command(1, time_us=now)], rows)
            if accepted:
                self.assertEqual(contract.preflight_normal(value)['verdict'], 'Pass')
            else:
                with self.assertRaises(contract.InvalidScenario):
                    contract.preflight_normal(value)
        with self.assertRaises(contract.InvalidScenario):
            contract.preflight_normal(contract.scenario('burst', [contract.command(i+1) for i in range(4097)]))

    def test_exact_replay_does_not_add_but_conflict_is_rejected(self):
        value = contract.scenario('offered-replay', [contract.command(1, 'same'), contract.command(2, 'same', kind='mix')])
        self.assertEqual(contract.preflight_normal(value)['maximum_held_per_actor'], {'actor-a': 1})
        value['commands'][1]['payload_tag'] = 'other'
        with self.assertRaisesRegex(contract.InvalidScenario, 'conflict'):
            contract.preflight_normal(value)

    def test_preflight_never_trusts_declared_finalization(self):
        value, _ = synthetic_cases()[0]
        with self.assertRaisesRegex(contract.InvalidScenario, 'offered reserves only'):
            contract.preflight_normal(value)

    def test_new_unobserved_pending_is_not_freed_after_its_ttl(self):
        commands = [contract.command(i+1, time_us=i*10*S) for i in range(4097)]
        with self.assertRaises(contract.InvalidScenario):
            contract.preflight_normal(contract.scenario('no-assumed-finalization', commands))


class SchemaTests(unittest.TestCase):
    def setUp(self):
        self.value = contract.scenario('schema-test', [contract.command(1)])

    def test_unknown_fields_rejected_at_every_input_layer(self):
        row = contract.Row('actor-a', 'initial', 'payload-a', 'accepted', 1, 'lease', 0)
        self.value['initial_rows'] = [contract.asdict(row)]
        for select in (lambda x: x, lambda x: x['policy'], lambda x: x['clock'],
                       lambda x: x['budgets'], lambda x: x['termination'],
                       lambda x: x['initial_rows'][0], lambda x: x['commands'][0]):
            value = copy.deepcopy(self.value)
            select(value)['invented'] = True
            with self.assertRaises(contract.InvalidScenario):
                contract.parse_scenario(value)

    def test_boolean_never_counts_as_integer(self):
        for select, key in ((lambda x: x['policy'], 'actor_capacity'), (lambda x: x['clock'], 'start_us'),
                            (lambda x: x['budgets'], 'steps'), (lambda x: x['commands'][0], 'time_us'),
                            (lambda x: x['commands'][0], 'attempt')):
            value = copy.deepcopy(self.value)
            select(value)[key] = True
            with self.assertRaises(contract.InvalidScenario):
                contract.parse_scenario(value)

    def test_schema_policy_identity_and_effect_schedule_rejections(self):
        mutations = [lambda x: x.update(schema='old'), lambda x: x.update(model='unproven'),
                     lambda x: x['policy'].update(actor_capacity=4097), lambda x: x['actors'].append('actor-a'),
                     lambda x: x['commands'].append(copy.deepcopy(x['commands'][0])),
                     lambda x: x['commands'][0].update(causal_id='future'),
                     lambda x: x['commands'][0].update(time_us=-1),
                     lambda x: x['commands'][0].update(time_us=float('nan')),
                     lambda x: x['commands'][0].update(cut='durable_commit_unknown'),
                     lambda x: x['commands'][0].update(action='finalize', cut='reservation_commit_unknown'),
                     lambda x: x['budgets'].update(events=0), lambda x: x['termination'].update(terminal_required=1)]
        for mutate in mutations:
            value = copy.deepcopy(self.value)
            mutate(value)
            with self.assertRaises(contract.InvalidScenario):
                contract.parse_scenario(value)

    def test_unknown_cannot_be_followed_by_blind_retry(self):
        value = contract.scenario('unknown-retry', [contract.command(1, cut='reservation_commit_unknown'), contract.command(2)])
        with self.assertRaisesRegex(contract.InvalidScenario, 'never blind retry'):
            contract.predict(value)

    def test_file_parser_rejects_duplicate_fields_and_nonfinite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'case.json'
            for text in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}'):
                path.write_text(text)
                with self.assertRaises(contract.InvalidScenario):
                    contract.read_json(path)

    def test_saved_corpus_rejects_empty_missing_duplicate_or_changed_cases(self):
        corpus = {'schema': 'northstar-stage1-synthetic-corpus-v1', 'limitations': contract.LIMITATIONS.copy(),
                  'provenance': source_provenance(), 'cases': []}
        for value, expected in synthetic_cases():
            actual = supplied_evidence(value, expected)
            corpus['cases'].append({'input': value, 'actual': actual, 'evaluation': evaluate(value, actual)})
        self.assertEqual(replay_corpus(corpus)['cases'], 11)
        for mutate in (lambda x: x.update(cases=[]), lambda x: x['cases'].pop(),
                       lambda x: x['cases'].__setitem__(1, copy.deepcopy(x['cases'][0])),
                       lambda x: x['cases'][0]['input']['commands'][0].update(key='substituted'),
                       lambda x: x.update(limitations=[])):
            changed = copy.deepcopy(corpus)
            mutate(changed)
            with self.assertRaises(contract.InvalidScenario):
                replay_corpus(changed)

    def test_baseline_rejects_corrupted_actual_even_with_regenerated_evaluation(self):
        corpus = {'schema': 'northstar-stage1-synthetic-corpus-v1', 'limitations': contract.LIMITATIONS.copy(),
                  'provenance': source_provenance(), 'cases': []}
        for value, expected in synthetic_cases():
            actual = supplied_evidence(value, expected)
            corpus['cases'].append({'input': value, 'actual': actual, 'evaluation': evaluate(value, actual)})
        mutations = [
            ('normal-mixed', lambda actual: actual['projection'][0].update(domain='Conflict')),
            ('normal-mixed', lambda actual: actual.update(cleanup={
                'status': 'Incomplete', 'independent': True, 'owned': ['leftover'], 'remaining': ['leftover']})),
            ('normal-mixed', lambda actual: actual.update(cleanup={
                'status': 'NotRequired', 'independent': False, 'owned': [], 'remaining': []})),
            ('normal-mixed', lambda actual: actual.update(execution='Cancelled')),
            ('normal-mixed', lambda actual: actual.update(execution='EnvironmentInterrupted')),
            ('normal-mixed', lambda actual: actual.update(terminal=False)),
            ('normal-mixed', lambda actual: actual.update(evidence_complete=False)),
            ('cancel-before-reservation', lambda actual: actual['projection'][0].update(execution='Completed')),
            ('cancel-before-reservation', lambda actual: actual['projection'][0].update(domain='Proceed')),
            ('reservation-unknown', lambda actual: actual['projection'][0].update(domain='Proceed', effect_status='Confirmed')),
            ('reservation-unknown', lambda actual: actual['projection'][0].update(domain='NotRequested', effect_status='NotRequested')),
        ]
        for case_id, mutate in mutations:
            with self.subTest(case=case_id, mutation=mutate):
                changed = copy.deepcopy(corpus)
                case = next(case for case in changed['cases'] if case['input']['scenario_id'] == case_id)
                mutate(case['actual'])
                # Reproduce the attack: a correct evaluator summary of corrupt
                # evidence is still not a correct baseline replay.
                case['evaluation'] = evaluate(case['input'], case['actual'])
                with self.assertRaises(contract.InvalidScenario):
                    replay_corpus(changed)


class OracleTests(unittest.TestCase):
    def setUp(self):
        self.value, self.expected = synthetic_cases()[0]
        self.actual = supplied_evidence(self.value, self.expected)

    def test_actual_is_never_filled_from_prediction(self):
        self.actual['projection'] = []
        result = evaluate(self.value, self.actual)
        self.assertEqual(result['verdict'], 'Inconclusive')
        self.assertEqual(result['actual']['projection'], [])
        self.assertEqual(result['first_mismatch']['index'], 0)

    def test_first_mismatch_is_preserved(self):
        self.actual['projection'][1]['domain'] = 'Conflict'
        self.actual['projection'][3]['domain'] = 'Missing'
        self.actual['execution'] = 'EnvironmentInterrupted'
        self.actual['evidence_complete'] = False
        result = evaluate(self.value, self.actual)
        self.assertEqual(result['verdict'], 'InvariantViolation')
        self.assertEqual(result['first_mismatch']['index'], 1)

    def test_expected_invariant_requires_exact_projection_id_class_location(self):
        expected = {'id': 'projection-mismatch', 'class': 'ReplayDivergence', 'location': 'op-1'}
        self.actual['projection'][0]['domain'] = 'Conflict'
        self.actual['invariant'] = expected.copy()
        failure = {'projection': copy.deepcopy(self.actual['projection']), 'invariant': expected}
        result = evaluate(self.value, self.actual, failure)
        self.assertEqual(result['verdict'], 'InvariantViolation')
        self.assertTrue(result['replay_matched'])
        self.assertFalse(result['qualified'])
        for key, value in (('id', 'unrelated'), ('class', 'Responsibility'), ('location', 'op-2')):
            actual = copy.deepcopy(self.actual)
            actual['invariant'][key] = value
            self.assertFalse(evaluate(self.value, actual, failure)['replay_matched'])
        self.actual['projection'][1]['domain'] = 'Missing'
        self.assertFalse(evaluate(self.value, self.actual, failure)['replay_matched'])
        fake = {'projection': self.expected, 'invariant': expected}
        with self.assertRaisesRegex(contract.InvalidScenario, 'independently derived'):
            evaluate(self.value, self.actual, fake)

    def test_source_runner_and_adapter_are_bound_to_trusted_provenance(self):
        for key, value in (('source_sha256', '0'*64), ('runner', 'untrusted-runner'), ('adapter', 'real_adapter')):
            actual = copy.deepcopy(self.actual)
            actual['provenance'][key] = value
            with self.assertRaises(contract.InvalidScenario):
                evaluate(self.value, actual)

    def test_runtime_evidence_overflow_is_inconclusive_preserving_known_prefix_failure(self):
        # Six commands fit the declared budget. Extra runtime events overflow it.
        self.value['budgets']['events'] = len(self.value['commands'])
        self.actual['scenario_sha256'] = contract.digest(self.value)
        self.actual['projection'].append(copy.deepcopy(self.expected[-1]))
        self.assertEqual(evaluate(self.value, self.actual)['verdict'], 'Inconclusive')
        self.actual['projection'][0]['domain'] = 'Conflict'
        self.assertEqual(evaluate(self.value, self.actual)['verdict'], 'InvariantViolation')


    def test_extra_reordered_or_mutated_event_is_not_expected_failure(self):
        for mutate in (lambda x: x['projection'].reverse(),
                       lambda x: x['projection'].append(copy.deepcopy(x['projection'][0])),
                       lambda x: x['projection'][0].update(lease='invented-lease')):
            actual = copy.deepcopy(self.actual)
            mutate(actual)
            self.assertEqual(evaluate(self.value, actual)['verdict'], 'InvariantViolation')

    def test_execution_and_gaps_have_distinct_verdicts(self):
        for status in ('EnvironmentInterrupted', 'Cancelled'):
            actual = copy.deepcopy(self.actual)
            actual['execution'] = status
            actual['projection'] = actual['projection'][:1]
            actual['terminal'] = False
            self.assertEqual(evaluate(self.value, actual)['verdict'], status)
        for key, value in (('terminal', False), ('evidence_complete', False), ('wall_ms', 10001),
                           ('peak_memory_bytes', 256*1024*1024+1), ('files', 1)):
            actual = copy.deepcopy(self.actual)
            actual[key] = value
            self.assertEqual(evaluate(self.value, actual)['verdict'], 'Inconclusive')

    def test_cleanup_is_separate_and_never_qualifies_failed_cleanup(self):
        self.actual['cleanup'] = {'status': 'Incomplete', 'independent': True, 'owned': ['fixture-file'], 'remaining': ['fixture-file']}
        result = evaluate(self.value, self.actual)
        self.assertEqual(result['verdict'], 'Pass')
        self.assertFalse(result['qualified'])
        self.actual['projection'][0]['domain'] = 'Conflict'
        self.assertEqual(evaluate(self.value, self.actual)['verdict'], 'InvariantViolation')

    def test_strict_evidence_fields_and_types(self):
        mutations = [lambda x: x.update(invented=1), lambda x: x.update(origin='prediction'),
                     lambda x: x.update(scenario_sha256='0'*64), lambda x: x.update(terminal=1),
                     lambda x: x.update(wall_ms=True), lambda x: x['projection'][0].update(active_min=True),
                     lambda x: x['projection'][0].update(schema_version=True),
                     lambda x: x['projection'][0].update(extra=1), lambda x: x['cleanup'].update(extra=1),
                     lambda x: x['provenance'].update(extra=1), lambda x: x['provenance'].update(adapter='real_adapter')]
        for mutate in mutations:
            actual = copy.deepcopy(self.actual)
            mutate(actual)
            with self.assertRaises(contract.InvalidScenario):
                evaluate(self.value, actual)

    def test_evidence_budget_fails_closed(self):
        self.value['budgets']['evidence_bytes'] = 50
        with self.assertRaises(contract.InvalidScenario):
            contract.predict(self.value)
        self.value['budgets']['evidence_bytes'] = contract.MAX_BYTES
        self.value['budgets']['events'] = 1
        with self.assertRaises(contract.InvalidScenario):
            contract.predict(self.value)

    def test_reduced_probe_preserves_cause_location_and_positive_control(self):
        counterexample = saved_counterexample()
        for item in (counterexample['original'], counterexample['reduced']):
            self.assertEqual(item['evaluation']['verdict'], 'InvariantViolation')
            self.assertTrue(item['evaluation']['replay_matched'])
            self.assertEqual(item['evaluation']['first_mismatch']['index'], 1)
            self.assertEqual(item['positive_control']['verdict'], 'Pass')
        reduced = counterexample['reduced']['input']['commands']
        self.assertEqual(len(reduced), 2)
        self.assertEqual(reduced[1]['causal_id'], reduced[0]['operation_id'])


class HarnessPreflightTests(unittest.TestCase):
    def test_helper_import_disables_bytecode_before_preflight(self):
        source = ROOT / 'scripts/mixed-traffic-soak.py'
        original_import = builtins.__import__
        observed = []

        def check_import(name, *args, **kwargs):
            if name == 'lib.experiment_contract':
                observed.append(sys.dont_write_bytecode)
            return original_import(name, *args, **kwargs)

        # Compile/exec definitions directly so this test's loader never writes
        # bytecode; __name__ prevents the real main/fixture from being invoked.
        with patch.object(sys, 'dont_write_bytecode', False), patch.object(builtins, '__import__', side_effect=check_import):
            exec(compile(source.read_bytes(), str(source), 'exec'),
                 {'__file__': str(source), '__name__': 'pure_bytecode_order_probe'})
        self.assertEqual(observed, [True])

    def test_invalid_plan_returns_before_any_fixture_tool_listener_or_output(self):
        spec = importlib.util.spec_from_file_location('mixed_contract_preflight', ROOT / 'scripts/mixed-traffic-soak.py')
        soak = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(soak)
        invalid = contract.scenario('over-cap', [contract.command(i+1) for i in range(4097)])
        with patch.object(soak, 'mixed_workload', return_value=invalid), \
                patch.object(soak, 'source_identity', side_effect=AssertionError('Git/tool started')), \
                patch.object(soak, 'candidate_database_port', side_effect=AssertionError('listener started')), \
                patch.object(soak, 'OwnedFixture', side_effect=AssertionError('fixture started')), \
                patch.object(soak.tempfile, 'mkdtemp', side_effect=AssertionError('output created')), \
                patch.object(soak.subprocess, 'Popen', side_effect=AssertionError('child started')), \
                patch.object(soak, 'emit') as emit:
            self.assertEqual(soak.main(['--binary', sys.executable]), 2)
        result = emit.call_args.kwargs
        self.assertEqual(result['verdict'], 'InvalidScenario')
        self.assertEqual(result['cleanup']['status'], 'NotRequired')


class HarnessTaxonomyTests(unittest.TestCase):
    """Only fake owners/transports and mocked signal registration; no OS work."""

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('mixed_taxonomy', ROOT / 'scripts/mixed-traffic-soak.py')
        cls.soak = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.soak)

    def run_case(self, error=None, *, setup_error=None, terminal=True, complete=True,
                 cleanup=None, diagnostic_error=None, close_error=None, stop_error=None):
        result = {}
        fixture = SimpleNamespace(binary_sha256='synthetic-binary', start=Mock(side_effect=setup_error),
                                  capture=Mock(side_effect=diagnostic_error, return_value={'status': 'complete'}),
                                  stop=Mock(side_effect=stop_error, return_value=copy.deepcopy(cleanup) if cleanup is not None else
                                            {'clean': True, 'independent': True, 'status': 'Clean', 'errors': []}))

        class Workload:
            def __init__(self, *_args):
                self.counts, self.expected, self.observed = {}, {}, collections.Counter()
                self.soak_start = None

            def run(self):
                if error is not None:
                    raise error
                result['evidence'].update(workload_terminal=terminal, complete=complete)

            def close(self):
                if close_error is not None:
                    raise close_error

        with patch.object(self.soak.signal, 'signal', return_value='synthetic-old-handler'), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.soak.run_owned_fixture(fixture, 1, result, Workload)
        fixture.stop.assert_called_once()
        return result

    def test_completed_workload_needs_terminal_complete_evidence_and_independent_clean_cleanup(self):
        result = self.run_case()
        self.assertEqual((result['execution']['status'], result['domain']['status'], result['verdict'], result['status']),
                         ('Completed', 'Verified', 'Pass', 'passed'))
        self.assertTrue(result['qualified'])
        for options in ({'terminal': False}, {'complete': False},
                        {'cleanup': {'clean': True, 'errors': []}},
                        {'cleanup': {'clean': False, 'independent': True, 'errors': ['owned-resource-remains']}}):
            with self.subTest(options=options):
                result = self.run_case(**options)
                self.assertEqual(result['verdict'], 'Inconclusive')
                self.assertEqual(result['status'], 'failed')
                self.assertFalse(result['qualified'])

    def test_setup_assertions_are_environmental_even_if_the_exception_is_typed(self):
        for error in (AssertionError('missing fixture tool'),
                      self.soak.DomainInvariantViolation('setup-only', 'fixture.start', 'not product proof')):
            result = self.run_case(setup_error=error)
            self.assertEqual(result['verdict'], 'EnvironmentInterrupted')
            self.assertEqual(result['execution']['phase'], 'setup')
            self.assertIsNone(result['domain']['first_invariant'])
            self.assertEqual(result['domain']['status'], 'NotStarted')

    def test_operator_signal_and_ordinary_interruption_have_different_origins(self):
        result = self.run_case(self.soak.OperatorCancelled(self.soak.signal.SIGTERM))
        self.assertEqual(result['verdict'], 'Cancelled')
        self.assertEqual(result['execution']['cause'], 'OperatorSignal')
        self.assertEqual(result['execution']['signal'], int(self.soak.signal.SIGTERM))
        for error in (InterruptedError('ordinary interruption'), OSError(errno.EINTR, 'ordinary EINTR')):
            result = self.run_case(error)
            self.assertEqual(result['verdict'], 'EnvironmentInterrupted')
            self.assertEqual(result['execution']['cause'], 'EINTR')
        with self.assertRaises(self.soak.OperatorCancelled) as caught:
            self.soak.operator_interrupted(self.soak.signal.SIGINT, None)
        self.assertEqual(caught.exception.signum, int(self.soak.signal.SIGINT))

    def test_unclassified_workload_failure_is_inconclusive(self):
        for error in (AssertionError('fixture assumption'), TimeoutError('missing observation'), RuntimeError('unknown')):
            result = self.run_case(error)
            self.assertEqual(result['verdict'], 'Inconclusive')
            self.assertEqual(result['execution']['cause'], 'UnclassifiedWorkloadFailure')
            self.assertIsNone(result['domain']['first_invariant'])

    def test_known_first_invariant_survives_later_observation_and_cleanup_failures(self):
        first = self.soak.DomainInvariantViolation('duplicate_live_delivery', 'observe.delivery', 'first known failure')
        later = self.soak.DomainInvariantViolation('later_failure', 'cleanup', 'later')
        result = self.run_case(first, diagnostic_error=RuntimeError('observation failed'),
                               close_error=later, stop_error=RuntimeError('stop failed'))
        self.assertEqual(result['verdict'], 'InvariantViolation')
        self.assertEqual(result['domain']['first_invariant']['code'], 'duplicate_live_delivery')
        self.assertEqual(result['error'], 'DomainInvariantViolation: first known failure')
        self.assertFalse(result['cleanup']['clean'])
        self.assertIn('failure_observation_unavailable', result['evidence']['gaps'])
        self.assertFalse(result['qualified'])

    def test_cancelled_run_remains_cancelled_if_observation_and_cleanup_fail(self):
        result = self.run_case(self.soak.OperatorCancelled(self.soak.signal.SIGINT),
                               diagnostic_error=InterruptedError('observer EINTR'), stop_error=RuntimeError('stop failed'))
        self.assertEqual(result['verdict'], 'Cancelled')
        self.assertFalse(result['cleanup']['clean'])

    def test_secondary_setup_failure_cannot_reclassify_operator_cancellation(self):
        result = {}
        self.soak.record_workload_failure(result, None, self.soak.OperatorCancelled(self.soak.signal.SIGINT))
        self.soak.record_workload_failure(result, None, RuntimeError('later cleanup setup failure'), phase='setup')
        self.soak.finalize_result(result, {'clean': False, 'independent': True, 'errors': ['cleanup failed']})
        self.assertEqual(result['verdict'], 'Cancelled')
        self.assertEqual(result['execution']['cause'], 'OperatorSignal')

    def test_cleanup_only_eintr_keeps_environment_origin(self):
        for options in ({'close_error': InterruptedError('peer cleanup EINTR')},
                        {'stop_error': InterruptedError('fixture cleanup EINTR')}):
            result = self.run_case(**options)
            self.assertEqual(result['verdict'], 'EnvironmentInterrupted')
            self.assertEqual(result['execution']['cause'], 'EINTR')
            self.assertEqual(result['execution']['phase'], 'cleanup')
            self.assertEqual(result['domain']['status'], 'Verified')

    def test_structured_cleanup_rejects_contradictory_clean_status(self):
        for cleanup in ({'clean': True, 'independent': True, 'status': 'Incomplete', 'errors': []},
                        {'clean': False, 'independent': True, 'status': 'Clean', 'errors': ['failed']}):
            result = self.run_case(cleanup=cleanup)
            self.assertEqual(result['verdict'], 'Inconclusive')
            self.assertIn('cleanup_report_inconsistent', result['evidence']['gaps'])
        result = self.run_case(close_error=RuntimeError('peer close failed'))
        self.assertFalse(result['cleanup']['clean'])
        self.assertEqual(result['cleanup']['status'], 'Incomplete')

    def test_bootstrap_does_not_overwrite_directory_it_failed_to_create(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            original = output / 'result.json'
            original.write_text('existing evidence')
            args = SimpleNamespace(binary=Path(sys.executable), duration_seconds=1, output_dir=output,
                                   trace_frames=False, stream_management=False, database_port=None)
            # Simulate a directory appearing after argument validation.
            with patch.object(self.soak, 'parse_arguments', return_value=args), \
                    patch.object(self.soak.signal, 'signal', return_value='synthetic-old-handler'), \
                    patch.object(self.soak, 'emit') as emit:
                self.assertEqual(self.soak.main([]), 1)
            self.assertEqual(original.read_text(), 'existing evidence')
            self.assertEqual(emit.call_args.kwargs['verdict'], 'EnvironmentInterrupted')

    def test_peer_close_cannot_swallow_eintr_into_abort_success(self):
        workload = self.soak.MixedTraffic(None, None, 1, {})
        error = InterruptedError('peer close EINTR')
        peer = SimpleNamespace(close=Mock(side_effect=error), abort=Mock())
        workload.peers = [peer]
        with self.assertRaises(InterruptedError) as caught:
            workload.close()
        self.assertIs(caught.exception, error)
        peer.abort.assert_not_called()

    def test_receive_preserves_interruptions_and_wraps_only_other_failures(self):
        workload = self.soak.MixedTraffic(None, None, 1, {})
        for error in (self.soak.OperatorCancelled(self.soak.signal.SIGTERM),
                      InterruptedError('EINTR'), OSError(errno.EINTR, 'EINTR')):
            peer = SimpleNamespace(username='synthetic-peer', receive=Mock(side_effect=error))
            with self.assertRaises(type(error)) as caught:
                workload.receive(peer, lambda *_args: False, 'synthetic-receive')
            self.assertIs(caught.exception, error)
        error = ConnectionResetError('synthetic disconnect')
        peer = SimpleNamespace(username='synthetic-peer', receive=Mock(side_effect=error))
        with self.assertRaises(TimeoutError) as caught:
            workload.receive(peer, lambda *_args: False, 'synthetic-receive')
        self.assertIs(caught.exception.__cause__, error)

    def test_actual_observed_delivery_checks_raise_typed_invariant(self):
        workload = self.soak.MixedTraffic(None, None, 1, {})
        peer = SimpleNamespace(username='synthetic-peer')
        workload.expected[peer.username, 'soak-1'] = {'type': 'chat', 'from': 'sender@localhost', 'payload': 'marker'}
        frame = "<message xmlns='jabber:client' type='groupchat' from='sender@localhost' id='soak-1'><body>marker</body></message>"
        with self.assertRaises(self.soak.DomainInvariantViolation) as caught:
            workload.observe(peer, frame)
        self.assertEqual(caught.exception.code, 'live_delivery_type')

    def test_main_bootstrap_failure_is_structured_before_any_fixture_start(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(self.soak, 'source_identity', side_effect=AssertionError('fixture bootstrap')), \
                patch.object(self.soak, 'OwnedFixture') as fixture, \
                patch.object(self.soak, 'candidate_database_port') as listener, \
                patch.object(self.soak.signal, 'signal', return_value='synthetic-old-handler') as register, \
                patch.object(self.soak, 'emit') as emit:
            code = self.soak.main(['--binary', sys.executable, '--duration-seconds', '1',
                                   '--output-dir', str(Path(directory) / 'output')])
        self.assertEqual(code, 1)
        fixture.assert_not_called()
        listener.assert_not_called()
        self.assertIs(register.call_args_list[0].args[1], self.soak.operator_interrupted)
        result = emit.call_args.kwargs
        self.assertEqual(result['verdict'], 'EnvironmentInterrupted')
        self.assertIsNone(result['domain']['first_invariant'])
        self.assertEqual(result['cleanup']['status'], 'NotRequired')

    def test_legacy_finalize_shape_never_emits_structured_pass(self):
        result = self.soak.finalize_result({'workload_status': 'passed'}, {'clean': True})
        self.assertEqual(result['status'], 'passed')
        self.assertNotIn('verdict', result)
        self.assertNotIn('qualified', result)

    def test_main_source_change_prevents_pass_but_keeps_known_invariant(self):
        for known_violation in (False, True):
            def fake_run(_fixture, _seconds, result):
                result.update(workload_status='passed')
                result['execution'] = {'status': 'Completed', 'phase': 'workload', 'cause': None}
                result['domain'] = {'status': 'Verified', 'first_invariant': None}
                if known_violation:
                    result['domain'] = {'status': 'InvariantViolation', 'first_invariant': {
                        'code': 'duplicate_live_delivery', 'class': 'ObservedContract', 'location': 'observe.delivery'}}
                result['evidence'].update(workload_terminal=True, complete=True)
                self.soak.finalize_result(result, {'clean': True, 'independent': True, 'status': 'Clean', 'errors': []})

            with tempfile.TemporaryDirectory() as directory, \
                    patch.object(self.soak, 'source_identity', side_effect=[{'source': 'before'}, {'source': 'after'}]), \
                    patch.object(self.soak, 'OwnedFixture', return_value=object()), \
                    patch.object(self.soak, 'candidate_database_port', return_value=12345), \
                    patch.object(self.soak, 'run_owned_fixture', side_effect=fake_run), \
                    patch.object(self.soak.signal, 'signal', return_value='synthetic-old-handler'), \
                    patch.object(self.soak, 'emit') as emit:
                code = self.soak.main(['--binary', sys.executable, '--duration-seconds', '1',
                                       '--output-dir', str(Path(directory) / 'output')])
            self.assertEqual(code, 1)
            result = emit.call_args.kwargs
            self.assertEqual(result['verdict'], 'InvariantViolation' if known_violation else 'Inconclusive')
            self.assertIn('source_identity_changed_or_unavailable', result['evidence']['gaps'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-dir', type=Path, help='new directory for exact synthetic cases and ordinary test result')
    parser.add_argument('--replay-corpus', type=Path, help='recheck a saved concrete synthetic corpus against current scoped source hashes')
    args = parser.parse_args()
    if args.replay_corpus is not None:
        if args.evidence_dir is not None:
            parser.error('choose replay or a new evidence directory')
        print(json.dumps(replay_corpus(contract.read_json(args.replay_corpus))))
        return 0
    if args.evidence_dir is not None and args.evidence_dir.exists():
        parser.error('evidence directory already exists; never overwrite prior evidence')
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))
    sys.stdout.write(stream.getvalue())
    if args.evidence_dir is not None:
        args.evidence_dir.mkdir(parents=False)
        provenance = source_provenance()
        cases = []
        for value, expected in synthetic_cases():
            actual = supplied_evidence(value, expected)
            cases.append({'input': value, 'actual': actual, 'evaluation': evaluate(value, actual)})
        (args.evidence_dir / 'synthetic-cases.json').write_text(json.dumps({
            'schema': 'northstar-stage1-synthetic-corpus-v1', 'limitations': contract.LIMITATIONS,
            'provenance': provenance, 'cases': cases}, indent=2) + '\n')
        (args.evidence_dir / 'ordinary-tests.log').write_text(stream.getvalue())
        (args.evidence_dir / 'saved-counterexample.json').write_text(json.dumps(saved_counterexample(), indent=2) + '\n')
        invalid = contract.scenario('historical-invalid-single-sender',
                                    [contract.command(i+1, time_us=i*S) for i in range(4097)])
        try:
            contract.preflight_normal(invalid)
            rejection = {'verdict': 'unexpected-preflight-acceptance'}
        except contract.InvalidScenario as error:
            rejection = {'verdict': 'InvalidScenario', 'reason': str(error),
                         'cleanup': 'NotRequired', 'actual': None}
        (args.evidence_dir / 'rejected-normal-input.json').write_text(json.dumps({
            'input': invalid, 'result': rejection, 'provenance': provenance}, indent=2) + '\n')
        (args.evidence_dir / 'ordinary-result.json').write_text(json.dumps({
            'command': 'python3 scripts/test-experiment-contract.py --evidence-dir ' + str(args.evidence_dir),
            'tests': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
            'skipped': len(result.skipped), 'success': result.wasSuccessful(), 'provenance': provenance,
            'not_run': ['existing OS/listener tests', 'server', 'PostgreSQL', 'wire', 'soak', 'fault injection'],
            'integration_helper': 'integration-wsl.py is outside this model source scope; the mixed fixture separately hashes it'}, indent=2) + '\n')
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())
