"""Narrow Linux supervision for the source-fixed controlled-admission corpus.

SOURCE IMPLEMENTATION; not evidence of execution or resource qualification.
The owner imports only this stdlib module. The killable worker owns every file,
hash, fsync and oracle operation. A caller must capture the final owner receipt
and actual exit status; worker artifacts alone never establish supervision.
"""
from __future__ import annotations

import array
import copy
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import select
import signal
import socket
import sys
import time


CONTRACT_SCHEMA = 'northstar-controlled-execution-contract-v1'
CASE_SCHEMA = 'northstar-controlled-case-v2'
RESULT_SCHEMA = 'northstar-controlled-case-result-v2'
CORPUS_SCHEMA = 'northstar-admission-controlled-corpus-v2'
SHRINK_SCHEMA = 'northstar-controlled-shrink-v2'
PREFIX_SCHEMA = 'northstar-controlled-prefix-v2'
RECEIPT_SCHEMA = 'northstar-controlled-owner-receipt-v1'
CAPTURE_SCHEMA = 'northstar-controlled-caller-capture-v1'
MAX_CONTROL = 4096
MAX_CONTRACT = 128 * 1024
MAX_PREFIX = 64 * 1024
MAX_CASE_METADATA = 32 * 1024
HASH = re.compile(r'[a-f0-9]{64}\Z')
HELPER_FILES = frozenset({
    'scripts/lib/controlled_admission_supervision.py',
    'scripts/lib/controlled_admission.py', 'scripts/lib/experiment_contract.py',
    'scripts/run-controlled-admission.py', 'scripts/test-controlled-admission.py',
    'scripts/test-experiment-contract.py',
})
PLAN_COUNTS = {'normal': 44, 'rejection': 34, 'shrink': 4, 'total': 82}
# Declared finite proposals, not measured safe or calibrated resource budgets.
PROPOSED_BUDGETS = {
    'launches': 128, 'whole_work_ms': 600000, 'case_ms': 30000,
    'startup_ms': 10000, 'cleanup_ms': 5000, 'receipt_ms': 2000,
    'caller_startup_ms': 10000, 'owner_cpu_s': 60, 'worker_cpu_s': 60,
    'rust_cpu_soft_s': 9, 'rust_cpu_hard_s': 10,
    'address_space_bytes': 1024 ** 3, 'input_bytes': 32 * 1024 ** 2,
    'stdout_bytes': 8 * 1024 ** 2, 'stderr_bytes': 4096,
    'evidence_bytes': 512 * 1024 ** 2, 'terminal_reserve_bytes': 1024 ** 2,
    'evaluation_bytes': 8 * 1024 ** 2,
    'source_bytes': 64 * 1024 ** 2,
}


class SupervisionError(ValueError):
    """Invalid, interrupted or unsupported supervision; never a domain Pass."""


def need(condition, reason):
    if not condition:
        raise SupervisionError(reason)


def exact(value, names, reason):
    need(type(value) is dict and set(value) == set(names.split()), reason)


def number(value, low=0, high=2 ** 63 - 1):
    need(type(value) is int and low <= value <= high, 'bounded_integer')
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def encoded(value):
    return (canonical(value) + '\n').encode()


def fingerprint(data):
    return hashlib.sha256(data).hexdigest()


def object_hash(value):
    return fingerprint(canonical(value).encode())


def strict_json(data, maximum):
    need(type(data) is bytes and len(data) <= maximum, 'json_byte_budget')
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate_field')
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(SupervisionError('nonfinite_json')))
    except (UnicodeError, ValueError, RecursionError) as error:
        raise SupervisionError('malformed_json') from error


def valid_hash(value):
    need(type(value) is str and HASH.fullmatch(value) is not None, 'sha256')


def validate_contract(value):
    """Validate an externally trusted contract; saved evidence is not authority."""
    exact(value, 'schema run_id mode root binary evidence_dir replay_dir provenance helper_source_files budgets plan_counts',
          'execution_contract_fields')
    need(value['schema'] == CONTRACT_SCHEMA, 'execution_contract_version')
    need(type(value['run_id']) is str and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}', value['run_id']), 'run_id')
    need(value['mode'] in ('record', 'replay'), 'exclusive_mode')
    for name in ('root', 'binary', 'evidence_dir'):
        need(type(value[name]) is str and Path(value[name]).is_absolute() and
             '..' not in Path(value[name]).parts, 'absolute_' + name)
    need((value['mode'] == 'record' and value['replay_dir'] is None) or
         (value['mode'] == 'replay' and type(value['replay_dir']) is str and
          Path(value['replay_dir']).is_absolute() and '..' not in Path(value['replay_dir']).parts and
          value['replay_dir'] != value['evidence_dir']), 'replay_destination')
    need(type(value['plan_counts']) is dict and value['plan_counts'] == PLAN_COUNTS and
         all(type(item) is int for item in value['plan_counts'].values()), 'fixed_plan_counts')
    exact(value['budgets'], ' '.join(PROPOSED_BUDGETS), 'budget_fields')
    # Version 1 deliberately supports this single reviewed finite proposal only.
    for name, proposed in PROPOSED_BUDGETS.items():
        need(type(value['budgets'][name]) is int and value['budgets'][name] == proposed, 'budget:' + name)
    helpers = value['helper_source_files']
    need(type(helpers) is dict and set(helpers) == HELPER_FILES, 'helper_source_scope')
    provenance = value['provenance']
    exact(provenance, 'schema model adapter binding_version source_sha256 source_files binary_sha256 cargo_lock_sha256 toolchain',
          'provenance_fields')
    need(type(provenance['source_files']) is dict and len(provenance['source_files']) <= 512, 'source_scope')
    for name, value_hash in helpers.items():
        valid_hash(value_hash)
        need(provenance['source_files'].get(name) == value_hash, 'helper_provenance_binding')
    need(len(encoded(value)) <= MAX_CONTRACT, 'contract_byte_budget')
    return copy.deepcopy(value)


def validate_reference(value):
    exact(value, 'file bytes sha256', 'reference_fields')
    need(type(value['file']) is str and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,159}', value['file']), 'reference_file')
    number(value['bytes'], 0, PROPOSED_BUDGETS['evidence_bytes'])
    valid_hash(value['sha256'])
    return value


def validate_stream(value, maximum):
    exact(value, 'reference observed_bytes complete', 'stream_fields')
    validate_reference(value['reference'])
    # A truncated file hashes only its retained prefix. The length is only the
    # bytes actually observed (at most one over the cap), not total child output.
    number(value['observed_bytes'], value['reference']['bytes'], maximum + 1)
    need(type(value['complete']) is bool and value['reference']['bytes'] <= maximum, 'stream_bound')
    need(not value['complete'] or value['observed_bytes'] == value['reference']['bytes'], 'complete_stream_length')


def validate_case_record(value, contract, index, case_id, kind):
    """One strict validator for normal, rejection and all four shrink records."""
    exact(value, 'schema run_id contract_sha256 index id kind input stdout stderr process observation', 'case_fields')
    need(value['schema'] == CASE_SCHEMA and value['run_id'] == contract['run_id'] and
         value['contract_sha256'] == object_hash(contract), 'case_contract')
    number(value['index'], 0, PLAN_COUNTS['total'] - 1)
    need(value['index'] == index and value['id'] == case_id and value['kind'] == kind and
         kind in ('normal', 'rejection', 'shrink'), 'case_identity')
    validate_reference(value['input'])
    need(value['input']['bytes'] <= contract['budgets']['input_bytes'], 'input_bound')
    validate_stream(value['stdout'], contract['budgets']['stdout_bytes'])
    validate_stream(value['stderr'], contract['budgets']['stderr_bytes'])
    process = value['process']
    exact(process, 'pid identity registered released reaped wait_status returncode wall_ms', 'process_fields')
    need(process['identity'] in (None, 'unreaped-direct-child-pidfd'), 'process_identity')
    if process['pid'] is not None:
        number(process['pid'], 1, 2 ** 31 - 1)
    need(not process['registered'] or (process['pid'] is not None and
         process['identity'] == 'unreaped-direct-child-pidfd'), 'registered_identity')
    for key in ('registered', 'released', 'reaped'):
        need(type(process[key]) is bool, 'process_boolean')
    need(not process['released'] or process['registered'], 'release_without_registration')
    number(process['wall_ms'])
    if process['reaped']:
        number(process['wait_status'], 0, 65535)
        need(os.WIFEXITED(process['wait_status']) or os.WIFSIGNALED(process['wait_status']), 'nonterminal_wait_status')
        need(type(process['returncode']) is int and
             process['returncode'] == os.waitstatus_to_exitcode(process['wait_status']), 'process_exit_status')
    else:
        need(process['returncode'] is None and process['wait_status'] is None, 'unreaped_status')
    need(value['observation'] in ('Complete', 'NotStarted', 'OutputLimit', 'ProcessFailure', 'EnvironmentInterrupted'), 'observation_class')
    need(value['observation'] != 'NotStarted' or
         (process['pid'] is None and not process['registered'] and not process['released'] and not process['reaped']),
         'not_started_process')
    if value['observation'] == 'Complete':
        need(process['registered'] and process['released'] and process['reaped'] and
             process['returncode'] in (0, 2) and value['stdout']['complete'] and
             value['stderr']['complete'] and value['stderr']['reference']['bytes'] == 0, 'complete_observation')
    return value


def validate_owner_capture(capture, expected_contract):
    """Caller-side check. Never promote a bare worker manifest or old v1 record."""
    contract = validate_contract(expected_contract)
    exact(capture, 'schema owner_exit_status stdout_complete receipt', 'capture_fields')
    need(capture['schema'] == CAPTURE_SCHEMA and capture['stdout_complete'] is True and
         type(capture['owner_exit_status']) is int, 'caller_capture')
    receipt = capture['receipt']
    exact(receipt, 'schema run_id contract_sha256 mode owner_exit_status status completed fixture_matched launches '
          'worker_exit_status cleanup_complete unexpected_children prefix terminal stop', 'receipt_fields')
    need(receipt['schema'] == RECEIPT_SCHEMA and receipt['run_id'] == contract['run_id'] and
         receipt['mode'] == contract['mode'] and receipt['contract_sha256'] == object_hash(contract), 'receipt_contract')
    need(type(receipt['owner_exit_status']) is int and receipt['owner_exit_status'] == capture['owner_exit_status'],
         'actual_owner_exit_status')
    for name in ('completed', 'fixture_matched', 'launches'):
        number(receipt[name], 0, contract['budgets']['launches'])
    number(receipt['unexpected_children'], 0, contract['budgets']['launches'] + 1)
    need(type(receipt['cleanup_complete']) is bool, 'cleanup_boolean')
    need(receipt['worker_exit_status'] is None or type(receipt['worker_exit_status']) is int, 'worker_exit_status')
    for name in ('prefix', 'terminal'):
        if receipt[name] is not None:
            validate_reference(receipt[name])
    need(receipt['status'] in ('FixtureMatched', 'UnexpectedStop', 'Cancelled', 'EnvironmentInterrupted'), 'receipt_status')
    need(receipt['stop'] is None or (type(receipt['stop']) is str and len(receipt['stop']) <= 128), 'receipt_stop')
    supervised = (receipt['status'] in ('FixtureMatched', 'UnexpectedStop') and
                  receipt['owner_exit_status'] in (0, 2) and receipt['worker_exit_status'] == receipt['owner_exit_status'] and
                  receipt['cleanup_complete'] is True and receipt['unexpected_children'] == 0 and
                  receipt['prefix'] is not None and receipt['terminal'] is not None)
    complete = (supervised and receipt['status'] == 'FixtureMatched' and receipt['owner_exit_status'] == 0 and
                receipt['worker_exit_status'] == 0 and receipt['cleanup_complete'] is True and
                receipt['unexpected_children'] == 0 and receipt['completed'] == PLAN_COUNTS['total'] and
                receipt['fixture_matched'] == PLAN_COUNTS['total'] and receipt['launches'] == PLAN_COUNTS['total'] and
                receipt['prefix'] is not None and receipt['terminal'] is not None and receipt['stop'] is None)
    need(receipt['status'] != 'FixtureMatched' or complete, 'false_supervision_completion')
    return {'FixtureMatched': complete, 'supervision_complete': supervised}


class EvidenceStore:
    """Single worker writer. Reservations include prefix replacement temp peaks.

    An immutable partial file is never referenced as a completed observation.
    Failed fsync/rename is a storage interruption, not durable success. Space
    means bytes written here, not a filesystem-wide or memory reservation.
    """
    def __init__(self, directory, budgets):
        self.directory = Path(directory)
        self.directory.mkdir(parents=False, exist_ok=False)
        self.budgets = budgets
        self.used = 0
        self.reservation = 0
        self.prefix_bytes = 0
        self._sync_directory()

    def _sync_directory(self):
        descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def reserve_case(self, input_bytes):
        need(self.reservation == 0, 'overlapping_reservation')
        number(input_bytes, 0, self.budgets['input_bytes'])
        requested = (input_bytes + self.budgets['stdout_bytes'] + self.budgets['stderr_bytes'] +
                     self.budgets['evaluation_bytes'] + 2 * MAX_CASE_METADATA + 2 * MAX_PREFIX)
        need(self.used + requested + self.budgets['terminal_reserve_bytes'] <= self.budgets['evidence_bytes'],
             'evidence_reservation_exhausted')
        self.reservation = requested

    def release_case(self):
        self.reservation = 0

    def _admit(self, size, terminal=False):
        number(size)
        if terminal:
            need(size <= self.budgets['terminal_reserve_bytes'] and
                 self.used + size <= self.budgets['evidence_bytes'], 'terminal_reserve_exhausted')
        else:
            need(size <= self.reservation, 'case_reservation_exhausted')
            self.reservation -= size
        self.used += size  # Count attempted bytes conservatively after a failed write.

    def immutable(self, name, data, *, terminal=False):
        validate_reference({'file': name, 'bytes': len(data), 'sha256': '0' * 64})
        self._admit(len(data), terminal)
        path = self.directory / name
        with path.open('xb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        self._sync_directory()
        return {'file': name, 'bytes': len(data), 'sha256': fingerprint(data)}

    def json(self, name, value, *, maximum=MAX_CASE_METADATA, terminal=False):
        data = encoded(value)
        need(len(data) <= maximum, 'metadata_byte_budget')
        return self.immutable(name, data, terminal=terminal)

    def prefix(self, value, *, terminal=False):
        data = encoded(value)
        need(len(data) <= MAX_PREFIX, 'prefix_byte_budget')
        self._admit(len(data), terminal)
        temporary = self.directory / '.prefix.next'
        with temporary.open('xb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.directory / 'prefix.json')
        self._sync_directory()
        self.used -= self.prefix_bytes
        self.prefix_bytes = len(data)
        return {'file': 'prefix.json', 'bytes': len(data), 'sha256': fingerprint(data)}


def read_bounded(path, maximum):
    with Path(path).open('rb') as stream:
        value = stream.read(maximum + 1)
    need(len(value) <= maximum, 'saved_file_byte_budget')
    return value


def read_reference(directory, reference, maximum):
    validate_reference(reference)
    need(reference['bytes'] <= maximum, 'reference_byte_budget')
    path = Path(directory) / reference['file']
    need(not path.is_symlink() and path.is_file(), 'reference_regular_file')
    data = read_bounded(path, maximum)
    need(len(data) == reference['bytes'] and fingerprint(data) == reference['sha256'], 'saved_reference_changed')
    return data


def fixture_plan(controlled):
    """One source-fixed mode: 44 normal + 34 negatives + the full four-run tail."""
    cases, rejections = controlled.controlled_cases(), controlled.rejection_cases()
    need(len(cases) == PLAN_COUNTS['normal'] and len(rejections) == PLAN_COUNTS['rejection'], 'source_plan_count_changed')
    result = [{'id': value['scenario_id'], 'kind': 'normal', 'value': value,
               'bytes': encoded(value), 'reason': None} for value in cases]
    result += [{'id': 'reject-' + value['id'], 'kind': 'rejection', 'value': None,
                'bytes': value['bytes'].encode(), 'reason': value['reason']} for value in rejections]
    original = controlled.late_candidate()
    noise = [command for command in original['commands'] if command['operation_id'] not in ('op-1', 'op-2')]
    need(len(noise) == 1, 'fixed_shrink_deletion_count')
    reduced = controlled.shrink_deletion(original, noise[0]['operation_id'])
    positive = controlled.shrink_positive_control(reduced)
    for name, value in (('original', original), ('candidate-1', reduced), ('positive-control', positive), ('reduced', reduced)):
        result.append({'id': 'shrink-' + name, 'kind': 'shrink', 'value': value,
                       'bytes': encoded(value), 'reason': None})
    need(len(result) == PLAN_COUNTS['total'] and len({item['id'] for item in result}) == len(result), 'fixed_launch_plan')
    return result


def evaluate_fixture(controlled, fixture, record, stdout):
    """Called only after the bounded observation is durably saved.

    FixtureMatched includes intentional Cancelled/Inconclusive and the exact
    4097 counterexample. It never modifies the domain evaluation's semantics.
    """
    if record['observation'] != 'Complete':
        return None, None, False, record['observation']
    try:
        actual = controlled.loads(stdout, PROPOSED_BUDGETS['stdout_bytes'])
        if fixture['kind'] == 'rejection':
            expected = {'schema': controlled.REJECTION_SCHEMA, 'class': 'InvalidScenario', 'reason': fixture['reason']}
            evaluation = {'verdict': 'InvalidScenario', 'reason': fixture['reason']}
            matched = record['process']['returncode'] == 2 and actual == expected
        else:
            value = fixture['value']
            expected = controlled.expected_output(value)
            evaluation = controlled.evaluate(value, actual, expected_failure=controlled.expected_counterexample(value))
            expected_evaluation = controlled.evaluate(value, expected, expected_failure=controlled.expected_counterexample(value))
            matched = record['process']['returncode'] == 0 and actual == expected and evaluation == expected_evaluation
        return actual, evaluation, matched, None if matched else 'FixtureMismatch'
    except (ValueError, TypeError, KeyError, RecursionError) as error:
        return None, None, False, 'MalformedOrUnexpectedOutput:' + type(error).__name__


def shrink_relations(controlled, observations):
    need(len(observations) == 4, 'shrink_tail_incomplete')
    original, candidate, positive, reduced = observations
    target = controlled.shrink_target(*original)
    need(target is not None and controlled.shrink_target(*candidate) == target and
         controlled.shrink_target(*reduced) == target, 'shrink_fixed_target')
    need(candidate[0] == reduced[0] and positive[0] == controlled.shrink_positive_control(reduced[0]) and
         controlled._shrink_positive_pass(positive[1], positive[2]), 'shrink_positive_relation')


def validate_result(value, record_reference, contract, fixture, index):
    exact(value, 'schema run_id contract_sha256 index id kind observation evaluation fixture_status stop', 'result_fields')
    need(value['schema'] == RESULT_SCHEMA and value['run_id'] == contract['run_id'] and
         value['contract_sha256'] == object_hash(contract) and type(value['index']) is int and
         value['index'] == index and value['id'] == fixture['id'] and value['kind'] == fixture['kind'], 'result_identity')
    need(value['observation'] == record_reference, 'result_observation_binding')
    if value['observation'] is not None:
        validate_reference(value['observation'])
    if value['evaluation'] is not None:
        validate_reference(value['evaluation'])
    need(value['fixture_status'] in ('FixtureMatched', 'UnexpectedStop'), 'fixture_status')
    need(value['stop'] is None or (type(value['stop']) is str and len(value['stop']) <= 128), 'result_stop')
    need(value['fixture_status'] != 'FixtureMatched' or
         (value['observation'] is not None and value['evaluation'] is not None and value['stop'] is None), 'false_fixture_match')


def replay_source(directory, current_contract):
    """Read strict v2 metadata; v1 and seven-field historical executions fail."""
    contract = validate_contract(strict_json(read_bounded(Path(directory) / 'contract.json', MAX_CONTRACT), MAX_CONTRACT))
    need(contract['mode'] == 'record' and contract['provenance'] == current_contract['provenance'] and
         contract['helper_source_files'] == current_contract['helper_source_files'] and
         contract['budgets'] == current_contract['budgets'], 'replay_source_contract')
    capture = strict_json(read_bounded(Path(directory) / 'caller-capture.json', MAX_CONTROL * 2), MAX_CONTROL * 2)
    need(validate_owner_capture(capture, contract)['supervision_complete'], 'prior_owner_capture_incomplete')
    manifest_ref = capture['receipt']['terminal']
    manifest = strict_json(read_reference(directory, manifest_ref, MAX_PREFIX), MAX_PREFIX)
    exact(manifest, 'schema contract_sha256 cases shrink first_invariant first_unexpected_stop complete', 'corpus_fields')
    need(manifest['schema'] == CORPUS_SCHEMA and manifest['contract_sha256'] == object_hash(contract) and
         manifest['complete'] is True and manifest['first_unexpected_stop'] is None and
         type(manifest['cases']) is list and len(manifest['cases']) == PLAN_COUNTS['total'], 'corpus_completion')
    need(manifest['shrink'] == {'schema': SHRINK_SCHEMA, 'attempts': [78, 79, 80, 81],
                               'original': 78, 'candidate': 79, 'positive_control': 80, 'reduced': 81}, 'shrink_v2_roles')
    for index, entry in enumerate(manifest['cases']):
        exact(entry, 'index id kind observation result fixture_status', 'corpus_entry_fields')
        need(type(entry['index']) is int and entry['index'] == index and entry['fixture_status'] == 'FixtureMatched', 'corpus_entry_order')
        validate_reference(entry['observation'])
        validate_reference(entry['result'])
    return contract, manifest


def verify_prior_case(controlled, directory, prior, fixture, index):
    contract, manifest = prior
    entry = manifest['cases'][index]
    need(entry['id'] == fixture['id'] and entry['kind'] == fixture['kind'], 'saved_fixture_identity')
    record = strict_json(read_reference(directory, entry['observation'], MAX_CASE_METADATA), MAX_CASE_METADATA)
    validate_case_record(record, contract, index, fixture['id'], fixture['kind'])
    need(read_reference(directory, record['input'], contract['budgets']['input_bytes']) == fixture['bytes'], 'source_fixed_input_changed')
    stdout = read_reference(directory, record['stdout']['reference'], contract['budgets']['stdout_bytes'])
    stderr = read_reference(directory, record['stderr']['reference'], contract['budgets']['stderr_bytes'])
    need(not stderr, 'saved_stderr')
    result = strict_json(read_reference(directory, entry['result'], MAX_CASE_METADATA), MAX_CASE_METADATA)
    validate_result(result, entry['observation'], contract, fixture, index)
    need(result['fixture_status'] == 'FixtureMatched', 'saved_fixture_unmatched')
    saved_evaluation = strict_json(read_reference(directory, result['evaluation'], contract['budgets']['evaluation_bytes']),
                                  contract['budgets']['evaluation_bytes'])
    output, evaluation, matched, _ = evaluate_fixture(controlled, fixture, record, stdout)
    need(matched and evaluation == saved_evaluation, 'saved_evaluation_changed')
    return output, evaluation


def _prctl(option, value):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(ctypes.c_int(option), ctypes.c_ulong(value), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'required_prctl_failed')


def _parent_death(expected_parent):
    _prctl(1, signal.SIGKILL)  # PR_SET_PDEATHSIG before any workload.
    need(os.getppid() == expected_parent, 'parent_changed_during_bootstrap')


def _limits(cpu_soft, cpu_hard):
    for kind, requested in ((resource.RLIMIT_CPU, (cpu_soft, cpu_hard)),
                            (resource.RLIMIT_AS, (PROPOSED_BUDGETS['address_space_bytes'],) * 2),
                            (resource.RLIMIT_CORE, (0, 0))):
        resource.setrlimit(kind, requested)
        need(resource.getrlimit(kind) == requested, 'resource_enforcement_unsupported')


def _close_except(keep, ceiling):
    need(type(ceiling) is int and 3 <= ceiling <= 1024 * 1024, 'inherited_fd_bound')
    previous = 3
    for descriptor in sorted(fd for fd in keep if fd >= 3):
        os.closerange(previous, descriptor)
        previous = descriptor + 1
    os.closerange(previous, ceiling)


def _now():
    return time.monotonic_ns()


def _remaining(deadline):
    remaining = (deadline - _now()) / 1_000_000_000
    need(remaining > 0, 'operation_deadline')
    return min(remaining, 0.05)


def _send_packet(channel, message, deadline, descriptor=None):
    data = encoded(message)
    need(len(data) <= MAX_CONTROL, 'control_byte_budget')
    ancillary = [] if descriptor is None else [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [descriptor]))]
    while True:
        try:
            count = channel.sendmsg([data], ancillary, socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
            need(count == len(data), 'partial_control_packet')
            return
        except (BlockingIOError, InterruptedError):
            select.select([], [channel], [], _remaining(deadline))


def _receive_packet(channel):
    descriptors = []
    try:
        data, ancillary, flags, _ = channel.recvmsg(MAX_CONTROL, socket.CMSG_SPACE(2 * array.array('i').itemsize),
                                                  socket.MSG_DONTWAIT | socket.MSG_CMSG_CLOEXEC)
        for level, kind, payload in ancillary:
            need(level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS, 'unexpected_ancillary')
            values = array.array('i')
            need(len(payload) % values.itemsize == 0, 'malformed_rights')
            values.frombytes(payload)
            descriptors.extend(values)
        need(data and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC), 'control_closed_or_truncated')
        return strict_json(data, MAX_CONTROL), descriptors
    except BaseException:
        for descriptor in descriptors:
            os.close(descriptor)
        raise


def _exchange(channel, run_id, message, reply_kind, deadline, descriptor=None):
    _send_packet(channel, dict(message, run_id=run_id), deadline, descriptor)
    while True:
        if not select.select([channel], [], [], _remaining(deadline))[0]:
            continue
        response, received = _receive_packet(channel)
        try:
            need(not received and type(response) is dict and response.get('run_id') == run_id and
                 response.get('type') == reply_kind, 'owner_ack_protocol')
            exact(response, 'type run_id deadline_ns', 'owner_ack_fields')
            number(response['deadline_ns'], 1)
            return response['deadline_ns']
        finally:
            for received_fd in received:
                os.close(received_fd)


def _check_worker_sources(contract):
    """Hashes execute only in the limited worker, before dynamic project import."""
    source_files = contract['provenance']['source_files']
    need(set(contract['helper_source_files']).issubset(source_files), 'helper_scope')
    used = 0
    # Helpers first. No controlled-admission/project module has been imported yet.
    for name in list(sorted(HELPER_FILES)) + sorted(set(source_files) - HELPER_FILES):
        path = Path(name)
        need(type(name) is str and not path.is_absolute() and '..' not in path.parts and
             str(path) == name and '\\' not in name, 'source_path')
        data = read_bounded(Path(contract['root']) / path, contract['budgets']['source_bytes'] - used)
        used += len(data)
        need(fingerprint(data) == source_files[name], 'source_identity_changed')
    need(object_hash(source_files) == contract['provenance']['source_sha256'], 'source_manifest_hash')


def _child_bootstrap(expected_parent, ceiling, ready_write, gate_read, stdout_write, stderr_write, binary, input_path):
    try:
        _parent_death(expected_parent)
        _limits(PROPOSED_BUDGETS['rust_cpu_soft_s'], PROPOSED_BUDGETS['rust_cpu_hard_s'])
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        _close_except({ready_write, gate_read, stdout_write, stderr_write}, ceiling)
        need(os.write(ready_write, b'R') == 1, 'bootstrap_ready_write')
        os.close(ready_write)
        need(os.read(gate_read, 1) == b'G', 'registration_gate_closed')
        os.close(gate_read)
        need(os.getppid() == expected_parent, 'parent_changed_before_exec')
        os.dup2(stdout_write, 1)
        os.dup2(stderr_write, 2)
        os.close(stdout_write)
        os.close(stderr_write)
        os.close(0)
        # exec is the one fixed trusted binary, with exactly one saved input.
        os.execve(binary, [binary, input_path], {'LANG': 'C', 'LC_ALL': 'C'})
    except BaseException:
        os._exit(125)


def capture_child(channel, contract, index, input_path, deadline, ceiling):
    """Register while our direct child is unreaped; release only after owner ACK.

    EOF/complete JSON does not mean exit. Both stream EOFs and a terminal reap
    are required. Collector stops at cap+one observed byte and asks the owner to
    kill the exact pidfd, then reaps within the same case deadline.
    """
    started = _now()
    pipes = [os.pipe2(os.O_CLOEXEC) for _ in range(4)]
    (out_read, out_write), (err_read, err_write), (ready_read, ready_write), (gate_read, gate_write) = pipes
    process = {'pid': None, 'identity': None, 'registered': False, 'released': False,
               'reaped': False, 'wait_status': None, 'returncode': None, 'wall_ms': 0}
    chunks = {'stdout': bytearray(), 'stderr': bytearray()}
    observed = {'stdout': 0, 'stderr': 0}
    complete = {'stdout': False, 'stderr': False}
    pidfd = None
    owned = {fd for pair in pipes for fd in pair}
    child_pid = None
    failure = None
    try:
        expected_parent = os.getpid()
        child_pid = os.fork()
        if child_pid == 0:
            _child_bootstrap(expected_parent, ceiling, ready_write, gate_read, out_write, err_write,
                             contract['binary'], str(input_path))
            os._exit(125)
        process['pid'] = child_pid
        for fd in (out_write, err_write, ready_write, gate_read):
            os.close(fd)
            owned.remove(fd)
        os.set_blocking(ready_read, False)
        while not select.select([ready_read], [], [], _remaining(deadline))[0]:
            pass
        need(os.read(ready_read, 1) == b'R', 'child_bootstrap_failed')
        # No wait/reap may occur before pidfd_open: the direct-child PID cannot
        # be reused while unreaped. SCM_RIGHTS retains exactly this kernel handle.
        pidfd = os.pidfd_open(child_pid, 0)
        process['identity'] = 'unreaped-direct-child-pidfd'
        _exchange(channel, contract['run_id'], {'type': 'Register', 'index': index, 'role': 'rust', 'pid': child_pid},
                  'Registered', deadline, pidfd)
        process['registered'] = True
        need(os.write(gate_write, b'G') == 1, 'gate_release_failed')
        process['released'] = True
        os.close(gate_write)
        owned.remove(gate_write)
        streams = {out_read: 'stdout', err_read: 'stderr'}
        for fd in streams:
            os.set_blocking(fd, False)
        aborted = False
        while streams or not process['reaped']:
            ready = select.select(list(streams), [], [], _remaining(deadline))[0]
            for fd in ready:
                name = streams[fd]
                maximum = contract['budgets'][name + '_bytes']
                data = os.read(fd, min(65536, maximum + 1 - observed[name]))
                if not data:
                    complete[name] = True
                    del streams[fd]
                    continue
                observed[name] += len(data)
                chunks[name].extend(data[:maximum - len(chunks[name])])
                if observed[name] > maximum:
                    failure = 'OutputLimit'
                    del streams[fd]
                    os.close(fd)
                    owned.remove(fd)
                    if not aborted:
                        _exchange(channel, contract['run_id'], {'type': 'AbortChild', 'index': index}, 'ChildAborted', deadline)
                        aborted = True
            if not process['reaped']:
                reaped, status = os.waitpid(child_pid, os.WNOHANG)
                if reaped:
                    need(reaped == child_pid and (os.WIFEXITED(status) or os.WIFSIGNALED(status)), 'nonterminal_child_status')
                    process.update(reaped=True, wait_status=status, returncode=os.waitstatus_to_exitcode(status))
        _exchange(channel, contract['run_id'], {'type': 'Reaped', 'index': index, 'pid': child_pid,
                                              'wait_status': process['wait_status']}, 'ChildReaped', deadline)
    except (OSError, SupervisionError) as error:
        failure = 'EnvironmentInterrupted'
        # Closing the gate prevents an unregistered child from starting. Owner
        # cleanup owns registered handles and adopts/reaps any bootstrap orphan.
        # Do not guess success or signal a numeric PID in this failure path.
    finally:
        for fd in owned:
            os.close(fd)
        if pidfd is not None:
            os.close(pidfd)
        process['wall_ms'] = max(0, (_now() - started) // 1_000_000)
    if child_pid is None:
        failure = 'NotStarted'
    if failure is None and (process['returncode'] not in (0, 2) or observed['stderr']):
        failure = 'ProcessFailure'
    return {'process': process, 'observation': failure or 'Complete',
            'bytes': {name: bytes(data) for name, data in chunks.items()}, 'observed': observed, 'complete': complete}
