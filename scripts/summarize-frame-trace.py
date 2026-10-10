#!/usr/bin/env python3
"""Summarize sanitized C2S execution events without reading payload fields.

This observer never retries traffic or upgrades workload failures to success.
Use --require-complete only on an opt-in complete debug trace: a production
warn-only log cannot establish that every operation started or completed.
"""
import argparse
import collections
import json
import math
from pathlib import Path
import sys
import uuid

TARGET = 'rust_xmpp_server::xmpp::frame_execution'
START = 'C2S execution started'
FINISH = 'C2S execution finished'
ADVANCE = 'C2S execution advanced'
MAX_BYTES = 128 * 1024 * 1024
MAX_LINE_BYTES = 64 * 1024
MAX_OPERATIONS = 50000
# Fixed vocabulary is copied from the production typed boundary. Unknown
# values invalidate evidence; they are never reflected into report text.
TRANSPORTS = {'tcp', 'websocket', 'bosh'}
OPERATIONS = {'stream_frame', 'sasl2_inline_auth'}
PHASES = {'frame', 'publication'}
STAGES = {'validation', 'handler', 'sm_checkpoint', 'auth_publication',
          'caps_publication', 'replacement_notification', 'message_policy',
          'message_admission', 'message_routing', 'message_followup',
          'muc_policy', 'muc_gate_wait', 'muc_authority', 'muc_admission',
          'muc_cluster_fanout', 'muc_local_fanout', 'mix_policy', 'mix_admission'}
# Additive vocabulary within summary-v1; historical bool publication traces
# remain readable as `rejected`, but cannot establish a more precise reason.
OUTCOMES = {'completed', 'backend_failure', 'timed_out', 'cancelled', 'panicked', 'rejected',
            'integrity_rejected', 'credential_rejected', 'route_rejected',
            'completed_with_deferred_notification'}


def normalized(fields):
    try:
        ident = str(uuid.UUID(fields['operation_id']))
        sequence = fields['sequence']
        if isinstance(sequence, bool) or not isinstance(sequence, int) or not 0 <= sequence <= 2**64 - 1:
            return None
        for key, vocabulary in (('transport', TRANSPORTS), ('operation', OPERATIONS),
                                ('phase', PHASES), ('stage', STAGES)):
            if fields.get(key) not in vocabulary:
                return None
        result = {key: fields[key] for key in ('transport', 'operation', 'phase', 'stage')}
        result.update(operation_id=ident, sequence=sequence)
        return result
    except (KeyError, ValueError, TypeError, AttributeError):
        return None


def summarize(lines):
    active, seen = {}, set()
    outcomes, stages, transports = collections.Counter(), collections.Counter(), collections.Counter()
    counts = collections.Counter()
    total_bytes = 0
    maximum_elapsed_ms = 0.0
    for raw in lines:
        total_bytes += len(raw)
        if total_bytes > MAX_BYTES:
            counts['input_limit_exceeded'] += 1
            break
        if len(raw) > MAX_LINE_BYTES:
            counts['oversized_lines'] += 1
            continue
        try:
            record = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            counts['non_json_lines'] += 1
            continue
        if not isinstance(record, dict) or record.get('target') != TARGET:
            continue
        fields = record.get('fields')
        if (not isinstance(fields, dict) or not isinstance(fields.get('message'), str)
                or fields.get('message') not in {START, FINISH, ADVANCE}):
            counts['other_execution_events'] += 1
            continue
        value = normalized(fields)
        if value is None:
            counts['invalid_execution_events'] += 1
            continue
        key = (value['operation_id'], value['sequence'], value['phase'])
        if fields['message'] == START:
            counts['started'] += 1
            if key in seen or key in active:
                counts['duplicate_starts'] += 1
            elif len(seen) + len(active) >= MAX_OPERATIONS:
                counts['operation_limit_exceeded'] += 1
                break
            else:
                active[key] = value
            continue
        if fields['message'] == ADVANCE:
            if key not in active:
                counts['advances_without_start'] += 1
            else:
                active[key] = value
            continue
        outcome = fields.get('outcome')
        elapsed = fields.get('elapsed_ms')
        if (not isinstance(outcome, str) or outcome not in OUTCOMES or isinstance(elapsed, bool)
                or not isinstance(elapsed, (float, int)) or not math.isfinite(elapsed) or elapsed < 0):
            counts['invalid_execution_events'] += 1
            continue
        if key in seen:
            counts['duplicate_completions'] += 1
            continue
        if len(seen) + len(active) >= MAX_OPERATIONS and key not in active:
            counts['operation_limit_exceeded'] += 1
            break
        if key not in active:
            counts['completions_without_start'] += 1
        else:
            active.pop(key)
        seen.add(key)
        counts['finished'] += 1
        outcomes[outcome] += 1
        stages[value['stage']] += 1
        transports[value['transport']] += 1
        maximum_elapsed_ms = max(maximum_elapsed_ms, elapsed)
    invalid = sum(counts[key] for key in ('input_limit_exceeded', 'oversized_lines',
                  'invalid_execution_events', 'duplicate_starts', 'duplicate_completions',
                  'operation_limit_exceeded', 'completions_without_start', 'advances_without_start'))
    return {
        'schema': 'northstar-c2s-execution-summary-v1', 'counts': dict(counts),
        'outcomes': dict(outcomes), 'terminal_stages': dict(stages),
        'transports': dict(transports), 'maximum_elapsed_ms': maximum_elapsed_ms,
        'unfinished_count': len(active), 'unfinished_sample': list(active.values())[:50],
        'complete_observation': bool(counts['started']) and not active and not invalid,
        'limits': {'input_bytes': MAX_BYTES, 'line_bytes': MAX_LINE_BYTES,
                   'operations': MAX_OPERATIONS, 'unfinished_sample': 50},
        'interpretation': 'Execution completion is not wire delivery, SM acknowledgement, or workload success. Missing events can mean log loss; an unfinished start alone is not proof of deadlock.',
    }


def bounded_lines(source):
    # Consume oversized lines in chunks without retaining arbitrary input.
    while True:
        line = source.readline(MAX_LINE_BYTES + 1)
        if not line:
            break
        yield line
        if len(line) > MAX_LINE_BYTES and not line.endswith(b'\n'):
            while line and not line.endswith(b'\n'):
                line = source.readline(MAX_LINE_BYTES + 1)
                # A suffix of an oversized line is never a new event.
                yield b' ' * max(MAX_LINE_BYTES + 1, len(line))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path)
    parser.add_argument('--require-complete', action='store_true')
    args = parser.parse_args(argv)
    with args.log.open('rb') as source:
        report = summarize(bounded_lines(source))
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 1 if args.require_complete and not report['complete_observation'] else 0


if __name__ == '__main__':
    sys.exit(main())
