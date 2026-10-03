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
        self.assertEqual(controlled.evaluate(value, output)['verdict'], 'Inconclusive')

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
