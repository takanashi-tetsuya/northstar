#!/usr/bin/env python3
"""No-server checks for bounded, payload-free frame trace interpretation."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('frame_trace', Path(__file__).with_name('summarize-frame-trace.py'))
TRACE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(TRACE)


def event(message=TRACE.START, **extra):
    fields = dict(message=message, operation_id='00000000-0000-4000-8000-000000000001',
                  sequence=1, transport='websocket', operation='stream_frame', phase='frame',
                  stage='validation')
    fields.update(extra)
    return (json.dumps({'target': TRACE.TARGET, 'fields': fields}) + '\n').encode()


class TraceTests(unittest.TestCase):
    def test_complete_trace_is_not_a_delivery_assertion(self):
        report = TRACE.summarize([event(), event(TRACE.FINISH, outcome='completed', elapsed_ms=1.2)])
        self.assertTrue(report['complete_observation'])
        self.assertEqual(report['outcomes'], {'completed': 1})
        self.assertIn('not wire delivery', report['interpretation'])

    def test_no_events_is_unavailable_not_complete(self):
        self.assertFalse(TRACE.summarize([b'{}\n'])['complete_observation'])

    def test_missing_terminal_stays_unfinished(self):
        report = TRACE.summarize([event()])
        self.assertFalse(report['complete_observation'])
        self.assertEqual(report['unfinished_count'], 1)

    def test_incomplete_trace_retains_last_observed_stage(self):
        report = TRACE.summarize([event(), event(TRACE.ADVANCE, stage='sm_checkpoint')])
        self.assertEqual(report['unfinished_sample'][0]['stage'], 'sm_checkpoint')
        self.assertFalse(report['complete_observation'])

    def test_warn_only_completion_does_not_establish_complete_observation(self):
        report = TRACE.summarize([event(TRACE.FINISH, outcome='timed_out', elapsed_ms=5000)])
        self.assertFalse(report['complete_observation'])
        self.assertEqual(report['counts']['completions_without_start'], 1)

    def test_timeout_cancel_and_failure_are_observed_not_converted_to_success(self):
        for outcome in ('timed_out', 'cancelled', 'backend_failure'):
            with self.subTest(outcome=outcome):
                report = TRACE.summarize([event(), event(TRACE.FINISH, outcome=outcome, elapsed_ms=2)])
                self.assertTrue(report['complete_observation'])
                self.assertEqual(report['outcomes'], {outcome: 1})

    def test_unknown_and_payload_fields_are_never_reflected(self):
        for field in ('stage', 'operation', 'operation_id', 'transport'):
            report = TRACE.summarize([event(**{field: 'secret@private.test'})])
            self.assertNotIn('secret', json.dumps(report))
            self.assertFalse(report['complete_observation'])
        report = TRACE.summarize([event(xml='<message>SECRET</message>'),
            event(TRACE.FINISH, outcome='completed', elapsed_ms=1, password='SECRET')])
        self.assertNotIn('SECRET', json.dumps(report))

    def test_typed_publication_results_remain_distinct_in_complete_evidence(self):
        for outcome in ('completed', 'backend_failure', 'integrity_rejected',
                        'credential_rejected', 'route_rejected',
                        'completed_with_deferred_notification', 'rejected'):
            with self.subTest(outcome=outcome):
                report = TRACE.summarize([
                    event(phase='publication', stage='auth_publication'),
                    event(TRACE.FINISH, phase='publication', stage='auth_publication',
                          outcome=outcome, elapsed_ms=12000)])
                self.assertEqual(report['schema'], 'northstar-c2s-execution-summary-v1')
                self.assertTrue(report['complete_observation'])
                self.assertEqual(report['outcomes'], {outcome: 1})

    def test_room_stages_localize_unfinished_and_failed_operations(self):
        for stage in ('muc_policy', 'muc_gate_wait', 'muc_authority', 'muc_admission',
                      'muc_cluster_fanout', 'muc_local_fanout', 'mix_policy', 'mix_admission'):
            with self.subTest(stage=stage):
                started = [event(), event(TRACE.ADVANCE, stage=stage)]
                self.assertEqual(TRACE.summarize(started)['unfinished_sample'][0]['stage'], stage)
                report = TRACE.summarize(started + [event(TRACE.FINISH, stage=stage,
                    outcome='backend_failure', elapsed_ms=5)])
                self.assertTrue(report['complete_observation'])
                self.assertEqual(report['terminal_stages'], {stage: 1})

    def test_unknown_publication_result_is_incomplete_and_never_echoed(self):
        report = TRACE.summarize([event(), event(TRACE.FINISH,
            outcome='private-user@secret.example', elapsed_ms=1)])
        self.assertFalse(report['complete_observation'])
        self.assertNotIn('secret.example', json.dumps(report))

    def test_duplicate_terminal_is_invalid_evidence(self):
        finish = event(TRACE.FINISH, outcome='completed', elapsed_ms=1)
        report = TRACE.summarize([event(), finish, finish])
        self.assertFalse(report['complete_observation'])
        self.assertEqual(report['counts']['duplicate_completions'], 1)

    def test_negative_and_nonfinite_durations_rejected(self):
        for elapsed in (-1, float('nan'), float('inf'), True):
            report = TRACE.summarize([event(), event(TRACE.FINISH, outcome='completed', elapsed_ms=elapsed)])
            self.assertFalse(report['complete_observation'])

    def test_malformed_event_shapes_cannot_crash_or_echo_unknown_values(self):
        for message in ({'secret': 'DO_NOT_COPY'}, ['DO_NOT_COPY'], None):
            report = TRACE.summarize([event(message=message)])
            self.assertFalse(report['complete_observation'])
            self.assertNotIn('DO_NOT_COPY', json.dumps(report))
        report = TRACE.summarize([event(), event(TRACE.FINISH, outcome={}, elapsed_ms=1)])
        self.assertFalse(report['complete_observation'])

    def test_input_and_operation_limits_remain_visible(self):
        with patch.object(TRACE, 'MAX_BYTES', 1):
            self.assertEqual(TRACE.summarize([event()])['counts']['input_limit_exceeded'], 1)
        with patch.object(TRACE, 'MAX_OPERATIONS', 1):
            report = TRACE.summarize([event(), event(sequence=2)])
            self.assertEqual(report['counts']['operation_limit_exceeded'], 1)
            self.assertFalse(report['complete_observation'])


if __name__ == '__main__':
    unittest.main()
