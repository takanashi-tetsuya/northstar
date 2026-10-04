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
import stat
import sys
import time


CONTRACT_SCHEMA = 'northstar-controlled-execution-contract-v2'
CASE_SCHEMA = 'northstar-controlled-case-v2'
RESULT_SCHEMA = 'northstar-controlled-case-result-v2'
CORPUS_SCHEMA = 'northstar-admission-controlled-corpus-v2'
SHRINK_SCHEMA = 'northstar-controlled-shrink-v2'
PREFIX_SCHEMA = 'northstar-controlled-prefix-v2'
RECEIPT_SCHEMA = 'northstar-controlled-owner-receipt-v1'
CAPTURE_SCHEMA = 'northstar-controlled-caller-capture-v2'
CALLER_SCHEMA = 'northstar-controlled-timeout-caller-v1'
CALLER_EVIDENCE_SCHEMA = 'northstar-controlled-external-caller-v2'
TIMEOUT_PATH = '/usr/bin/timeout'
TIMEOUT_SHA256 = '6ca1891dfc0b05d7680770c2884c0391b92467c7bb6500a5c84677e6481739f1'
TIMEOUT_ARGUMENTS = ('--signal=TERM', '--kill-after=5s', '612s')
MAX_CONTROL = 4096
MAX_CONTRACT = 128 * 1024
MAX_PREFIX = 64 * 1024
MAX_CASE_METADATA = 32 * 1024
HASH = re.compile(r'[a-f0-9]{64}\Z')
HELPER_FILES = frozenset({
    'scripts/lib/controlled_admission_supervision.py',
    'scripts/lib/controlled_admission.py', 'scripts/lib/experiment_contract.py',
    'scripts/run-controlled-admission.py', 'scripts/test-controlled-admission.py',
    'scripts/capture-controlled-admission.py',
    'scripts/test-experiment-contract.py',
})
PLAN_COUNTS = {'normal': 44, 'rejection': 34, 'shrink': 4, 'total': 82}
STOP_KINDS = ('FixtureMismatch', 'EnvironmentInterrupted', 'ResourceInterrupted',
              'StorageInterrupted', 'ProtocolInterrupted', 'InvalidArtifact', 'Cancelled')
INTERRUPTION_KINDS = tuple(kind for kind in STOP_KINDS if kind != 'FixtureMismatch')
# Declared finite proposals, not measured safe or calibrated resource budgets.
PROPOSED_BUDGETS = {
    'launches': 128, 'whole_work_ms': 600000, 'case_ms': 30000,
    'startup_ms': 10000, 'cleanup_ms': 5000, 'receipt_ms': 2000,
    'caller_total_ms': 617000, 'caller_artifact_bytes': 64 * 1024,
    'owner_cpu_s': 60, 'worker_cpu_s': 60,
    'rust_cpu_soft_s': 9, 'rust_cpu_hard_s': 10,
    'address_space_bytes': 1024 ** 3, 'input_bytes': 32 * 1024 ** 2,
    'stdout_bytes': 8 * 1024 ** 2, 'stderr_bytes': 4096,
    'evidence_bytes': 512 * 1024 ** 2, 'terminal_reserve_bytes': 1024 ** 2,
    'evaluation_bytes': 8 * 1024 ** 2,
    'source_bytes': 64 * 1024 ** 2,
    'binary_bytes': 128 * 1024 ** 2,
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
    exact(value, 'schema run_id mode root binary evidence_dir replay_dir replay_authority provenance helper_source_files budgets plan_counts caller',
          'execution_contract_fields')
    need(value['schema'] == CONTRACT_SCHEMA, 'execution_contract_version')
    need(type(value['run_id']) is str and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}', value['run_id']), 'run_id')
    need(value['mode'] in ('record', 'replay'), 'exclusive_mode')
    for name in ('root', 'binary', 'evidence_dir'):
        need(type(value[name]) is str and Path(value[name]).is_absolute() and
             '..' not in Path(value[name]).parts, 'absolute_' + name)
    need(bool(Path(value['evidence_dir']).name), 'evidence_destination_root')
    need((value['mode'] == 'record' and value['replay_dir'] is None) or
         (value['mode'] == 'replay' and type(value['replay_dir']) is str and
          Path(value['replay_dir']).is_absolute() and '..' not in Path(value['replay_dir']).parts and
          bool(Path(value['replay_dir']).name) and
          Path(value['replay_dir']) != Path(value['evidence_dir'])), 'replay_destination')
    if value['mode'] == 'record':
        need(value['replay_authority'] is None, 'unexpected_replay_authority')
    else:
        authority = value['replay_authority']
        exact(authority, 'contract capture caller_evidence', 'external_replay_authority')
        need(type(authority['contract']) is dict and authority['contract'].get('mode') == 'record', 'prior_record_contract')
        need(validate_owner_capture(authority['capture'], authority['contract'],
                                    caller_evidence=authority['caller_evidence'])['FixtureMatched'], 'prior_fixture_unmatched')
    need(type(value['plan_counts']) is dict and value['plan_counts'] == PLAN_COUNTS and
         all(type(item) is int for item in value['plan_counts'].values()), 'fixed_plan_counts')
    exact(value['budgets'], ' '.join(PROPOSED_BUDGETS), 'budget_fields')
    # Version 2 deliberately supports this single reviewed finite proposal only.
    for name, proposed in PROPOSED_BUDGETS.items():
        need(type(value['budgets'][name]) is int and value['budgets'][name] == proposed, 'budget:' + name)
    helpers = value['helper_source_files']
    need(type(helpers) is dict and set(helpers) == HELPER_FILES, 'helper_source_scope')
    provenance = value['provenance']
    exact(provenance, 'schema model adapter binding_version source_sha256 source_files binary_sha256 cargo_lock_sha256 toolchain',
          'provenance_fields')
    need(type(provenance['source_files']) is dict and len(provenance['source_files']) <= 512, 'source_scope')
    need(provenance['schema'] == 'northstar-admission-controlled-provenance-v1' and
         provenance['model'] == 'admission-controlled-v1' and provenance['adapter'] == 'controlled_rust' and
         provenance['binding_version'] == 'synthetic-material-v1' and type(provenance['toolchain']) is str and
         provenance['toolchain'].startswith('rustc 1.97.1 '), 'provenance_version')
    for name, value_hash in provenance['source_files'].items():
        need(type(name) is str and not Path(name).is_absolute() and '..' not in Path(name).parts and
             str(Path(name)) == name and '\\' not in name, 'source_path')
        valid_hash(value_hash)
    for name in ('source_sha256', 'binary_sha256', 'cargo_lock_sha256'):
        valid_hash(provenance[name])
    need(object_hash(provenance['source_files']) == provenance['source_sha256'], 'source_manifest_hash')
    for name, value_hash in helpers.items():
        valid_hash(value_hash)
        need(provenance['source_files'].get(name) == value_hash, 'helper_provenance_binding')
    caller = value['caller']
    exact(caller, 'schema python python_sha256 timeout_sha256', 'caller_contract_fields')
    need(caller['schema'] == CALLER_SCHEMA and type(caller['python']) is str and
         Path(caller['python']).is_absolute() and '..' not in Path(caller['python']).parts,
         'fixed_caller_contract')
    valid_hash(caller['python_sha256'])
    need(caller['timeout_sha256'] == TIMEOUT_SHA256, 'reviewed_timeout_identity')
    need(len(encoded(value)) <= MAX_CONTRACT, 'contract_byte_budget')
    return copy.deepcopy(value)


def caller_mechanism_hash(contract):
    """Identity of this fixed caller composition, never an executable command DSL."""
    return object_hash({'caller': contract['caller'], 'source_sha256': contract['provenance']['source_sha256'],
                        'timeout': TIMEOUT_PATH, 'timeout_arguments': TIMEOUT_ARGUMENTS,
                        'owner': str(Path(contract['root']) / 'scripts/run-controlled-admission.py'),
                        'python_arguments': ['-I', '-S', '-B']})


def caller_directory(evidence_directory):
    """Caller is a separate writer, including when worker liveness is unknown."""
    directory = Path(evidence_directory)
    need(directory.is_absolute() and '..' not in directory.parts, 'caller_destination_ambiguous')
    need(bool(directory.name), 'caller_destination_root')
    return directory.with_name(directory.name + '.caller')


def validate_reference(value):
    exact(value, 'file bytes sha256', 'reference_fields')
    need(type(value['file']) is str and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,159}', value['file']), 'reference_file')
    number(value['bytes'], 0, PROPOSED_BUDGETS['evidence_bytes'])
    valid_hash(value['sha256'])
    return value


def validate_prefix_reference(value, completed):
    validate_reference(value)
    number(completed, 0, PLAN_COUNTS['total'])
    need(value['file'] == f'prefix-{completed:03d}.json' and value['bytes'] <= MAX_PREFIX, 'prefix_generation_reference')


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
    exact(value, 'schema run_id contract_sha256 index id kind input stdout stderr process observation stop_kind', 'case_fields')
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
    need((not process['reaped'] and process['identity'] is None) or process['pid'] is not None, 'process_pid_missing')
    number(process['wall_ms'])
    if process['reaped']:
        number(process['wait_status'], 0, 65535)
        need(os.WIFEXITED(process['wait_status']) or os.WIFSIGNALED(process['wait_status']), 'nonterminal_wait_status')
        need(type(process['returncode']) is int and
             process['returncode'] == os.waitstatus_to_exitcode(process['wait_status']), 'process_exit_status')
    else:
        need(process['returncode'] is None and process['wait_status'] is None, 'unreaped_status')
    need(value['observation'] in ('Complete', 'NotStarted', 'OutputLimit', 'ProcessFailure', 'EnvironmentInterrupted'), 'observation_class')
    expected_stop = None if value['observation'] == 'Complete' else \
        'ResourceInterrupted' if value['observation'] == 'OutputLimit' else 'EnvironmentInterrupted'
    need(value['stop_kind'] == expected_stop, 'observation_stop_kind')
    need(value['observation'] != 'NotStarted' or
         (process['pid'] is None and not process['registered'] and not process['released'] and not process['reaped']),
         'not_started_process')
    if value['observation'] == 'Complete':
        need(process['registered'] and process['released'] and process['reaped'] and
             process['returncode'] in (0, 2) and value['stdout']['complete'] and
             value['stderr']['complete'] and value['stderr']['reference']['bytes'] == 0, 'complete_observation')
        need(process['wall_ms'] <= contract['budgets']['case_ms'], 'complete_capture_exceeds_case_deadline')
    if value['observation'] == 'OutputLimit':
        need(any(value[name]['observed_bytes'] == contract['budgets'][name + '_bytes'] + 1 and
                 value[name]['complete'] is False for name in ('stdout', 'stderr')), 'output_limit_without_sentinel')
    if value['observation'] == 'ProcessFailure':
        need(process['registered'] and process['released'] and process['reaped'] and
             value['stdout']['complete'] and value['stderr']['complete'], 'process_failure_incomplete')
    return value


def validate_owner_capture(capture, expected_contract, *, caller_evidence=None):
    """Caller-side check with separately trusted invocation evidence.

    The consumer, not saved corpus JSON, supplies caller_evidence from its actual
    reviewed invoking executor. Shape checking a boolean is not enforcement.
    Missing that external evidence deliberately prevents qualification.
    """
    contract = validate_contract(expected_contract)
    exact(capture, 'schema owner_exit_status stdout_complete receipt', 'capture_fields')
    need(capture['schema'] == CAPTURE_SCHEMA and capture['stdout_complete'] is True and
         type(capture['owner_exit_status']) is int, 'caller_capture')
    receipt = capture['receipt']
    exact(receipt, 'schema run_id contract_sha256 mode owner_exit_status status completed fixture_matched launches '
          'worker_exit_status cleanup_complete unexpected_children prefix terminal stop stop_kind interruption_kind', 'receipt_fields')
    need(receipt['schema'] == RECEIPT_SCHEMA and receipt['run_id'] == contract['run_id'] and
         receipt['mode'] == contract['mode'] and receipt['contract_sha256'] == object_hash(contract), 'receipt_contract')
    need(type(receipt['owner_exit_status']) is int and receipt['owner_exit_status'] == capture['owner_exit_status'],
         'actual_owner_exit_status')
    for name in ('completed', 'fixture_matched', 'launches'):
        number(receipt[name], 0, contract['budgets']['launches'])
    need(receipt['fixture_matched'] <= receipt['completed'] <= PLAN_COUNTS['total'] and
         receipt['completed'] <= receipt['launches'] + 1, 'receipt_counts')
    number(receipt['unexpected_children'], 0, contract['budgets']['launches'] + 1)
    need(type(receipt['cleanup_complete']) is bool, 'cleanup_boolean')
    need(receipt['worker_exit_status'] is None or type(receipt['worker_exit_status']) is int, 'worker_exit_status')
    for name in ('prefix', 'terminal'):
        if receipt[name] is not None:
            validate_reference(receipt[name])
            if name == 'prefix':
                validate_prefix_reference(receipt[name], receipt['completed'])
            else:
                need(receipt[name]['file'] == 'corpus.json' and receipt[name]['bytes'] <= MAX_PREFIX, 'receipt_reference')
    need(receipt['status'] in ('FixtureMatched', 'UnexpectedStop', 'Cancelled', 'EnvironmentInterrupted'), 'receipt_status')
    need(receipt['stop'] is None or (type(receipt['stop']) is str and len(receipt['stop']) <= 128), 'receipt_stop')
    need(receipt['status'] == 'FixtureMatched' or receipt['stop'] is not None, 'missing_receipt_stop')
    need(receipt['stop_kind'] in (None,) + STOP_KINDS and
         (receipt['stop'] is None) == (receipt['stop_kind'] is None), 'receipt_stop_kind')
    need(receipt['interruption_kind'] in (None,) + INTERRUPTION_KINDS, 'receipt_interruption_kind')
    need(receipt['stop_kind'] not in INTERRUPTION_KINDS or receipt['interruption_kind'] == receipt['stop_kind'],
         'receipt_first_interruption_kind')
    need(receipt['status'] != 'UnexpectedStop' or
         (receipt['stop_kind'] == 'FixtureMismatch' and receipt['interruption_kind'] is None), 'interruption_is_not_clean_mismatch')
    supervised = (receipt['status'] in ('FixtureMatched', 'UnexpectedStop') and
                  receipt['owner_exit_status'] in (0, 2) and receipt['worker_exit_status'] == receipt['owner_exit_status'] and
                  receipt['cleanup_complete'] is True and receipt['unexpected_children'] == 0 and
                  receipt['prefix'] is not None and receipt['terminal'] is not None and receipt['interruption_kind'] is None)
    complete = (supervised and receipt['status'] == 'FixtureMatched' and receipt['owner_exit_status'] == 0 and
                receipt['worker_exit_status'] == 0 and receipt['cleanup_complete'] is True and
                receipt['unexpected_children'] == 0 and receipt['completed'] == PLAN_COUNTS['total'] and
                receipt['fixture_matched'] == PLAN_COUNTS['total'] and receipt['launches'] == PLAN_COUNTS['total'] and
                receipt['prefix'] is not None and receipt['terminal'] is not None and receipt['stop'] is None and
                receipt['stop_kind'] is None)
    need(receipt['status'] != 'FixtureMatched' or complete, 'false_supervision_completion')
    exact(caller_evidence, 'schema invocation_id mechanism_sha256 owner_exit_status timeout_exit_status receipt_sha256 '
          'total_limit_ms observed_total_ms stdout_complete stderr_complete', 'external_caller_evidence_required')
    need(caller_evidence['schema'] == CALLER_EVIDENCE_SCHEMA and
         type(caller_evidence['invocation_id']) is str and
         re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}', caller_evidence['invocation_id']), 'caller_invocation_identity')
    valid_hash(caller_evidence['mechanism_sha256'])
    valid_hash(caller_evidence['receipt_sha256'])
    need(caller_evidence['mechanism_sha256'] == caller_mechanism_hash(contract), 'external_caller_mechanism_binding')
    need(type(caller_evidence['timeout_exit_status']) is int and caller_evidence['timeout_exit_status'] in (0, 2) and
         type(caller_evidence['owner_exit_status']) is int and
         caller_evidence['owner_exit_status'] == caller_evidence['timeout_exit_status'] and
         caller_evidence['owner_exit_status'] == capture['owner_exit_status'] and
         caller_evidence['receipt_sha256'] == fingerprint(encoded(receipt)) and
         caller_evidence['stdout_complete'] is True and caller_evidence['stderr_complete'] is True,
         'external_caller_terminal_binding')
    number(caller_evidence['total_limit_ms'], contract['budgets']['caller_total_ms'], contract['budgets']['caller_total_ms'])
    number(caller_evidence['observed_total_ms'], 0, caller_evidence['total_limit_ms'])
    return {'FixtureMatched': complete, 'supervision_complete': supervised}


class EvidenceStore:
    """Single worker writer. Reservations include immutable prefix install peaks.

    An immutable partial file is never referenced as a completed observation.
    Failed fsync/rename is a storage interruption, not durable success. Space
    means bytes written here, not a filesystem-wide or memory reservation.
    """
    def __init__(self, directory, budgets):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=False, exist_ok=False)
        self.budgets = budgets
        self.used = 0
        self.reservation = 0
        self.prefix_generation = 0
        self._sync_directory(self.directory.parent)  # Persist the newly created directory entry.
        self._sync_directory()

    def _sync_directory(self, directory=None):
        descriptor = os.open(self.directory if directory is None else directory, os.O_RDONLY | os.O_DIRECTORY)
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
        # The separate caller packet is part of the same evidence budget. Every
        # worker write, including failed attempts and prefix temp peaks, leaves it.
        need(self.used + size <= self.budgets['evidence_bytes'] - self.budgets['caller_artifact_bytes'],
             'worker_evidence_ceiling')
        if terminal:
            need(size <= self.budgets['terminal_reserve_bytes'] - self.budgets['caller_artifact_bytes'],
                 'terminal_reserve_exhausted')
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
        number(self.prefix_generation, 0, PLAN_COUNTS['total'])
        need(len(value['cases']) == self.prefix_generation, 'prefix_generation_sequence')
        name = f'prefix-{self.prefix_generation:03d}.json'
        # Count both temporary/final names during installation conservatively.
        # All prior generations remain counted and readable; at most 83 total.
        self._admit(2 * len(data), terminal)
        temporary = self.directory / '.prefix.next'
        with temporary.open('xb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, self.directory / name)  # Atomic installation; never overwrite an acknowledged generation.
        self._sync_directory()
        temporary.unlink()
        self._sync_directory()
        self.used -= len(data)
        self.prefix_generation += 1
        return {'file': name, 'bytes': len(data), 'sha256': fingerprint(data)}


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
    exact(value, 'schema run_id contract_sha256 index id kind observation observation_loss evaluation fixture_status stop stop_kind interruption_kind', 'result_fields')
    need(value['schema'] == RESULT_SCHEMA and value['run_id'] == contract['run_id'] and
         value['contract_sha256'] == object_hash(contract) and type(value['index']) is int and
         value['index'] == index and value['id'] == fixture['id'] and value['kind'] == fixture['kind'], 'result_identity')
    need(value['observation'] == record_reference, 'result_observation_binding')
    if value['observation'] is not None:
        validate_reference(value['observation'])
        need(value['observation_loss'] is None, 'saved_observation_loss')
    else:
        loss = value['observation_loss']
        exact(loss, 'phase reason stop_kind capture_available', 'observation_loss_fields')
        need(type(loss['phase']) is str and re.fullmatch(r'[a-z_]{1,64}', loss['phase']) and
             type(loss['reason']) is str and len(loss['reason']) <= 128 and loss['stop_kind'] in INTERRUPTION_KINDS and
             type(loss['capture_available']) is bool, 'observation_loss_identity')
    if value['evaluation'] is not None:
        validate_reference(value['evaluation'])
    need(value['fixture_status'] in ('FixtureMatched', 'UnexpectedStop'), 'fixture_status')
    need(value['stop'] is None or (type(value['stop']) is str and len(value['stop']) <= 128), 'result_stop')
    need(value['stop_kind'] in (None,) + STOP_KINDS and
         (value['stop'] is None) == (value['stop_kind'] is None), 'result_stop_kind')
    need(value['interruption_kind'] in (None,) + INTERRUPTION_KINDS and
         (value['stop_kind'] not in INTERRUPTION_KINDS or value['interruption_kind'] == value['stop_kind']),
         'result_interruption_kind')
    need(value['stop_kind'] != 'FixtureMismatch' or value['interruption_kind'] is not None or
         value['observation'] is not None, 'clean_mismatch_without_observation')
    need(value['fixture_status'] != 'FixtureMatched' or
         (value['observation'] is not None and value['evaluation'] is not None and value['stop'] is None and
          value['stop_kind'] is None and value['interruption_kind'] is None), 'false_fixture_match')


def replay_source(directory, current_contract):
    """Read strict v2 metadata; v1 and seven-field historical executions fail."""
    authority = current_contract['replay_authority']
    contract = validate_contract(authority['contract'])
    need(strict_json(read_bounded(Path(directory) / 'contract.json', MAX_CONTRACT), MAX_CONTRACT) == contract,
         'saved_contract_differs_from_external_authority')
    need(contract['mode'] == 'record' and contract['provenance'] == current_contract['provenance'] and
         contract['helper_source_files'] == current_contract['helper_source_files'] and
         contract['budgets'] == current_contract['budgets'], 'replay_source_contract')
    capture = strict_json(read_bounded(caller_directory(directory) / 'caller-capture.json', MAX_CONTROL * 2), MAX_CONTROL * 2)
    need(capture == authority['capture'] and validate_owner_capture(capture, contract,
         caller_evidence=authority['caller_evidence'])['FixtureMatched'], 'prior_owner_capture_incomplete')
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
    prefix = strict_json(read_reference(directory, capture['receipt']['prefix'], MAX_PREFIX), MAX_PREFIX)
    exact(prefix, 'schema run_id contract_sha256 cases first_invariant first_unexpected_stop', 'prefix_fields')
    need(prefix['schema'] == PREFIX_SCHEMA and prefix['run_id'] == contract['run_id'] and
         prefix['contract_sha256'] == object_hash(contract) and prefix['cases'] == manifest['cases'] and
         prefix['first_invariant'] == manifest['first_invariant'] and prefix['first_unexpected_stop'] is None,
         'prefix_terminal_consistency')
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
    # The separately reviewed caller starts with a clean FD table. An inherited
    # hard limit alone cannot prove absence of old descriptors above that limit.
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
            exact(response, 'type run_id index role deadline_ns', 'owner_ack_fields')
            need(type(response['index']) is int and response['index'] == message['index'] and
                 response['role'] == message['role'], 'owner_ack_correlation')
            number(response['deadline_ns'], 1)
            return response['deadline_ns']
        finally:
            for received_fd in received:
                os.close(received_fd)


def _check_worker_sources(contract):
    """Hashes execute only in the limited worker, before dynamic project import."""
    need(Path(__file__).resolve() == Path(contract['root']) / 'scripts/lib/controlled_admission_supervision.py',
         'executing_helper_root_changed')
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


def _child_bootstrap(expected_parent, ceiling, ready_write, gate_read, stdout_write, stderr_write, binary, binary_fd, input_path):
    try:
        _parent_death(expected_parent)
        _limits(PROPOSED_BUDGETS['rust_cpu_soft_s'], PROPOSED_BUDGETS['rust_cpu_hard_s'])
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        _close_except({ready_write, gate_read, stdout_write, stderr_write, binary_fd}, ceiling)
        need(os.write(ready_write, b'R') == 1, 'bootstrap_ready_write')
        os.close(ready_write)
        need(os.read(gate_read, 1) == b'G', 'registration_gate_closed')
        os.close(gate_read)
        need(os.getppid() == expected_parent, 'parent_changed_before_exec')
        os.dup2(stdout_write, 1)
        os.dup2(stderr_write, 2)
        os.close(stdout_write)
        os.close(stderr_write)
        # The retained descriptor prevents pathname substitution, not writes to
        # the same inode. Frozen workspace plus before/after hashes remain required.
        os.execve(binary_fd, [binary, input_path], {'LANG': 'C', 'LC_ALL': 'C'})
    except BaseException:
        os._exit(125)


def capture_child(channel, contract, index, input_path, binary_fd, deadline, ceiling):
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
        _exchange(channel, contract['run_id'], {'type': 'Launch', 'index': index, 'role': 'rust'}, 'LaunchAllowed', deadline)
        expected_parent = os.getpid()
        child_pid = os.fork()
        if child_pid == 0:
            _child_bootstrap(expected_parent, ceiling, ready_write, gate_read, out_write, err_write,
                             contract['binary'], binary_fd, str(input_path))
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
                        _exchange(channel, contract['run_id'], {'type': 'AbortChild', 'index': index, 'role': 'rust'}, 'ChildAborted', deadline)
                        aborted = True
            if not process['reaped']:
                reaped, status = os.waitpid(child_pid, os.WNOHANG)
                if reaped:
                    need(reaped == child_pid and (os.WIFEXITED(status) or os.WIFSIGNALED(status)), 'nonterminal_child_status')
                    process.update(reaped=True, wait_status=status, returncode=os.waitstatus_to_exitcode(status))
        _exchange(channel, contract['run_id'], {'type': 'Reaped', 'index': index, 'role': 'rust', 'pid': child_pid,
                                              'wait_status': process['wait_status']}, 'ChildReaped', deadline)
    except (OSError, SupervisionError) as error:
        failure = failure or 'EnvironmentInterrupted'
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
            'stop_kind': None if failure is None else 'ResourceInterrupted' if failure == 'OutputLimit' else 'EnvironmentInterrupted',
            'bytes': {name: bytes(data) for name, data in chunks.items()}, 'observed': observed, 'complete': complete}


def _signal_owned(descriptor):
    if descriptor is not None:
        try:
            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
        except ProcessLookupError:
            pass  # Exit still requires reap; this is not cleanup success.


class OwnerProtocol:
    """Bounded control state for exactly one worker and one gated Rust child.

    No oracle, file/hash work, generic process executor, or process-tree scan.
    Numeric PIDs are diagnostic/correlation values only, never signal targets.
    """
    def __init__(self, run_id, mode, contract_sha256, started):
        self.run_id, self.mode, self.contract_sha256 = run_id, mode, contract_sha256
        self.started = started
        self.work_deadline = started + PROPOSED_BUDGETS['whole_work_ms'] * 1_000_000
        self.startup_deadline = min(self.work_deadline, started + PROPOSED_BUDGETS['startup_ms'] * 1_000_000)
        self.case_deadline = None
        self.finalization_deadline = None
        self.case_index = None
        self.phase = 'bootstrap'
        self.worker_pid = None
        self.worker_exit_status = None
        self.child_pid = None
        self.child_fd = None
        self.completed = self.matched = self.launches = self.controls = self.unexpected_children = 0
        self.prefix = self.terminal = self.stop = self.stop_kind = self.interruption_kind = None
        self.done = self.declared_complete = False

    def deadline(self):
        if self.phase == 'bootstrap':
            return self.startup_deadline
        return min(self.work_deadline, self.case_deadline or self.work_deadline,
                   self.finalization_deadline or self.work_deadline)

    def fail(self, reason, stop_kind='EnvironmentInterrupted'):
        need(stop_kind in STOP_KINDS, 'owner_stop_kind')
        if self.stop is None:
            self.stop = reason[:128]
            self.stop_kind = stop_kind
        if stop_kind in INTERRUPTION_KINDS and self.interruption_kind is None:
            self.interruption_kind = stop_kind

    def _reference(self, value, file_name, maximum):
        validate_reference(value)
        need(value['file'] == file_name and value['bytes'] <= maximum, 'control_reference')

    def accept(self, message, descriptors, now):
        self.controls += 1
        need(self.controls <= 8 * PROPOSED_BUDGETS['launches'] + 16 and now < self.deadline(), 'owner_control_deadline_or_budget')
        need(type(message) is dict and message.get('run_id') == self.run_id and not self.done, 'control_run_identity')
        kind = message.get('type')
        need(kind in ('Hello', 'Begin', 'Launch', 'Register', 'AbortChild', 'Reaped', 'CaseReady', 'Done'), 'control_type')
        need(type(message.get('index')) is int, 'control_index')
        role = 'rust' if kind in ('Launch', 'Register', 'AbortChild', 'Reaped') else 'worker'
        need(message.get('role') == role, 'control_role')
        need(len(descriptors) == (1 if kind == 'Register' else 0), 'control_rights_count')
        if kind == 'Hello':
            exact(message, 'type run_id index role contract_sha256 total prefix', 'hello_fields')
            need(self.phase == 'bootstrap' and message['index'] == -1 and
                 message['contract_sha256'] == self.contract_sha256 and type(message['total']) is int and
                 message['total'] == PLAN_COUNTS['total'], 'hello_identity')
            validate_prefix_reference(message['prefix'], 0)
            self.prefix, self.phase = message['prefix'], 'idle'
            reply = 'Ready'
        elif kind == 'Begin':
            exact(message, 'type run_id index role id kind', 'begin_fields')
            need(self.phase == 'idle' and self.stop is None and self.child_fd is None and
                 message['index'] == self.completed and self.completed < PLAN_COUNTS['total'], 'case_sequence')
            expected_kind = 'normal' if self.completed < 44 else 'rejection' if self.completed < 78 else 'shrink'
            need(message['kind'] == expected_kind and type(message['id']) is str and
                 re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}', message['id']), 'case_kind_identity')
            self.case_index = message['index']
            self.case_deadline = min(self.work_deadline, now + PROPOSED_BUDGETS['case_ms'] * 1_000_000)
            self.phase, reply = 'preparing', 'CaseStarted'
        elif kind == 'Launch':
            exact(message, 'type run_id index role', 'launch_fields')
            need(self.phase == 'preparing' and message['index'] == self.case_index and
                 self.launches < PROPOSED_BUDGETS['launches'], 'launch_budget_or_sequence')
            self.launches += 1  # A reserved start counts even if fork/setup fails.
            self.phase, reply = 'registering', 'LaunchAllowed'
        elif kind == 'Register':
            exact(message, 'type run_id index role pid', 'register_fields')
            number(message['pid'], 1, 2 ** 31 - 1)
            need(self.phase == 'registering' and message['index'] == self.case_index and
                 self.child_fd is None and message['pid'] not in (self.worker_pid, os.getpid()), 'registration_sequence')
            # The trusted worker obtained this handle while its direct child was
            # unreaped. This signal-zero operation verifies a live pidfd type.
            signal.pidfd_send_signal(descriptors[0], 0)
            need(not select.select([descriptors[0]], [], [], 0)[0], 'bootstrap_exited_before_registration')
            self.child_fd, self.child_pid = descriptors[0], message['pid']
            self.phase, reply = 'running', 'Registered'
        elif kind == 'AbortChild':
            exact(message, 'type run_id index role', 'abort_fields')
            need(self.phase == 'running' and message['index'] == self.case_index and self.child_fd is not None, 'abort_sequence')
            _signal_owned(self.child_fd)
            reply = 'ChildAborted'
        elif kind == 'Reaped':
            exact(message, 'type run_id index role pid wait_status', 'reaped_fields')
            need(self.phase == 'running' and message['index'] == self.case_index and
                 type(message['pid']) is int and message['pid'] == self.child_pid, 'reap_identity')
            number(message['wait_status'], 0, 65535)
            need(os.WIFEXITED(message['wait_status']) or os.WIFSIGNALED(message['wait_status']), 'nonterminal_wait_status')
            need(select.select([self.child_fd], [], [], 0)[0], 'pidfd_exit_not_observed')
            os.close(self.child_fd)
            self.child_fd = self.child_pid = None
            self.phase, reply = 'observed', 'ChildReaped'
        elif kind == 'CaseReady':
            exact(message, 'type run_id index role fixture_status prefix observation result stop stop_kind interruption_kind', 'case_ready_fields')
            need(self.phase in ('preparing', 'registering', 'running', 'observed') and
                 message['index'] == self.case_index, 'case_ready_sequence')
            need(message['fixture_status'] in ('FixtureMatched', 'UnexpectedStop'), 'case_ready_status')
            need(message['interruption_kind'] in (None,) + INTERRUPTION_KINDS and
                 (message['stop_kind'] not in INTERRUPTION_KINDS or message['interruption_kind'] == message['stop_kind']),
                 'case_ready_interruption_kind')
            validate_prefix_reference(message['prefix'], self.completed + 1)
            self._reference(message['result'], f'{self.case_index:03d}.result.json', MAX_CASE_METADATA)
            if message['observation'] is not None:
                self._reference(message['observation'], f'{self.case_index:03d}.observation.json', MAX_CASE_METADATA)
            if message['fixture_status'] == 'FixtureMatched':
                need(self.phase == 'observed' and self.child_fd is None and message['observation'] is not None and
                     message['stop'] is None and message['stop_kind'] is None and message['interruption_kind'] is None,
                     'case_match_without_complete_process')
                self.matched += 1
            else:
                need(type(message['stop']) is str and 0 < len(message['stop']) <= 128 and
                     message['stop_kind'] in STOP_KINDS, 'case_stop_reason')
                if message['stop_kind'] == 'FixtureMismatch' and message['interruption_kind'] is None:
                    need(self.phase == 'observed' and self.child_fd is None and message['observation'] is not None,
                         'clean_mismatch_without_complete_process')
                self.fail(message['stop'], message['stop_kind'])
                if self.interruption_kind is None:
                    self.interruption_kind = message['interruption_kind']
                self.finalization_deadline = min(self.work_deadline, now + PROPOSED_BUDGETS['cleanup_ms'] * 1_000_000)
                _signal_owned(self.child_fd)
            self.completed += 1
            self.prefix = message['prefix']
            self.phase, self.case_index, self.case_deadline, reply = 'idle', None, None, 'CaseSaved'
        else:
            exact(message, 'type run_id index role complete prefix terminal', 'done_fields')
            need(self.phase == 'idle' and message['index'] == self.completed and
                 type(message['complete']) is bool and message['prefix'] == self.prefix, 'done_sequence')
            self._reference(message['terminal'], 'corpus.json', MAX_PREFIX)
            if message['complete']:
                need(self.completed == self.matched == self.launches == PLAN_COUNTS['total'] and
                     self.stop is None and self.child_fd is None, 'done_plan_incomplete')
            else:
                need(self.stop is not None, 'done_missing_stop')
            self.done, self.declared_complete, self.terminal = True, message['complete'], message['terminal']
            reply = 'TerminalReceived'
        return {'type': reply, 'run_id': self.run_id, 'index': message['index'], 'role': role,
                'deadline_ns': self.deadline()}

    def reap(self):
        """At most the two owned roles; wait never blocks and never signals PIDs."""
        for _ in range(3):
            try:
                pid, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                return True
            if pid == 0:
                return False
            need(os.WIFEXITED(status) or os.WIFSIGNALED(status), 'owner_nonterminal_wait')
            if pid == self.worker_pid:
                self.worker_exit_status = os.waitstatus_to_exitcode(status)
                if not self.done:
                    self.fail('WorkerExitedBeforeTerminal')
            elif pid == self.child_pid:
                # Reparented after worker loss. The actual reap is known, but a
                # missing worker observation stays incomplete.
                self.fail('WorkerLostWithRegisteredChild')
            else:
                self.unexpected_children += 1
                self.fail('UnregisteredOrUnexpectedChild')
        self.fail('ClosedTopologyExceeded')
        return False


def _owner_ack(channel, message):
    data = encoded(message)
    need(len(data) <= MAX_CONTROL and
         channel.send(data, socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL) == len(data), 'owner_ack_not_delivered')


def _cleanup(state, worker_fd, deadline=None):
    if deadline is None:
        deadline = _now() + PROPOSED_BUDGETS['cleanup_ms'] * 1_000_000
    signalled = True
    for descriptor in (state.child_fd, worker_fd):
        try:
            _signal_owned(descriptor)
        except OSError:
            signalled = False
            state.fail('OwnedHandleSignalFailed')
    while _now() < deadline:
        try:
            if state.reap():
                return signalled
        except (OSError, SupervisionError):
            state.fail('CleanupReapFailed')
            return False
        select.select([], [], [], min(0.05, max(0, (deadline - _now()) / 1_000_000_000)))
    state.fail('CleanupDeadline', 'ResourceInterrupted')
    return False


def _prepare_receipt():
    kind = os.fstat(1).st_mode
    need(stat.S_ISFIFO(kind) or stat.S_ISSOCK(kind), 'caller_receipt_pipe_required')
    os.set_blocking(1, False)
    need(os.get_blocking(1) is False, 'caller_receipt_nonblocking_required')


def _receipt_write(receipt):
    """Only a nonblocking pipe/socket to the caller, never an evidence file."""
    data = encoded(receipt)
    need(len(data) <= MAX_CONTROL, 'receipt_byte_budget')
    _prepare_receipt()
    deadline = _now() + PROPOSED_BUDGETS['receipt_ms'] * 1_000_000
    offset = 0
    while offset < len(data):
        need(_now() < deadline, 'receipt_deadline')
        try:
            count = os.write(1, data[offset:])
            need(count > 0, 'receipt_pipe_closed')
            offset += count
        except (BlockingIOError, InterruptedError):
            select.select([], [1], [], _remaining(deadline))


def owner_main(contract_bytes, *, run_id, mode, contract_sha256):
    """Fresh dedicated interpreter only. No filesystem/hash/project work here."""
    state = OwnerProtocol(run_id, mode, contract_sha256, _now())
    channel = worker_channel = None
    worker_fd = gate_read = gate_write = None
    cleanup_deadline = None
    cleanup_complete = False
    cancellation = []
    try:
        need(sys.platform == 'linux' and hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal') and
             os.execve in os.supports_fd, 'required_linux_enforcement_unavailable')
        need(type(contract_bytes) is bytes and len(contract_bytes) <= MAX_CONTRACT and
             type(run_id) is str and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}', run_id) and
             mode in ('record', 'replay'), 'owner_bootstrap_identity')
        valid_hash(contract_sha256)
        # -I -S -B is checked by the entry point. The caller checks total elapsed
        # time; this internal startup timer does not cover interpreter bootstrap.
        _limits(PROPOSED_BUDGETS['owner_cpu_s'], PROPOSED_BUDGETS['owner_cpu_s'])
        _prepare_receipt()  # Unsupported receipt setup must fail before any fork.
        _prctl(36, 1)  # PR_SET_CHILD_SUBREAPER, before the sole worker fork.
        # Ignored SIGCHLD / SA_NOCLDWAIT would destroy the unreaped-child PID
        # guarantee used by pidfd_open. The dedicated interpreter has no other
        # reaper; install the default disposition before either role can fork.
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        ceiling = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
        _close_except(set(), ceiling)
        resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
        ceiling = 128
        for value in (signal.SIGINT, signal.SIGTERM):
            signal.signal(value, lambda signum, _frame: cancellation.append(signum) if not cancellation else None)
        channel, worker_channel = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        channel.setblocking(False)
        worker_channel.setblocking(False)
        gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
        expected_parent = os.getpid()
        worker_pid = os.fork()
        if worker_pid == 0:
            _worker_bootstrap(expected_parent, worker_channel, gate_read, contract_bytes,
                              run_id, mode, contract_sha256, state.startup_deadline, ceiling)
            os._exit(125)
        state.worker_pid = worker_pid
        worker_channel.close()
        worker_channel = None
        os.close(gate_read)
        gate_read = None
        worker_fd = os.pidfd_open(worker_pid, 0)
        need(os.write(gate_write, b'G') == 1, 'worker_gate_release')
        os.close(gate_write)
        gate_write = None
        while True:
            if cancellation:
                state.fail('OwnerSignal:' + str(cancellation[0]), 'Cancelled')
                break
            now = _now()
            deadline = cleanup_deadline or state.deadline()
            if now >= deadline:
                state.fail('OwnerDeadline', 'ResourceInterrupted')
                break
            no_children = state.reap()
            if state.worker_exit_status is not None:
                expected_status = 0 if state.declared_complete else 2
                if not state.done or state.worker_exit_status != expected_status:
                    state.fail('WorkerTerminalExitMismatch')
                if no_children:
                    cleanup_complete = True
                break
            if state.unexpected_children:
                break
            readable = [worker_fd] + ([] if state.done else [channel])
            ready = select.select(readable, [], [], min(0.05, (deadline - now) / 1_000_000_000))[0]
            if not state.done and channel in ready:
                message, descriptors = _receive_packet(channel)
                try:
                    reply = state.accept(message, descriptors, _now())
                    _owner_ack(channel, reply)
                    if state.done:
                        cleanup_deadline = _now() + PROPOSED_BUDGETS['cleanup_ms'] * 1_000_000
                finally:
                    for descriptor in descriptors:
                        if descriptor != state.child_fd:
                            os.close(descriptor)
    except (OSError, ValueError, TypeError, OverflowError) as error:
        state.fail('OwnerFailure:' + type(error).__name__)
    finally:
        for descriptor in (gate_read, gate_write):
            if descriptor is not None:
                os.close(descriptor)
        if not cleanup_complete:
            cleanup_complete = _cleanup(state, worker_fd, cleanup_deadline)
        for descriptor in (state.child_fd, worker_fd):
            if descriptor is not None:
                os.close(descriptor)
        for endpoint in (channel, worker_channel):
            if endpoint is not None:
                endpoint.close()
    lifecycle = (state.done and state.worker_exit_status == (0 if state.declared_complete else 2) and
                 cleanup_complete and state.unexpected_children == 0)
    matched = lifecycle and state.declared_complete and state.stop is None and state.interruption_kind is None
    clean_mismatch = (lifecycle and not state.declared_complete and state.stop_kind == 'FixtureMismatch' and
                      state.interruption_kind is None)
    exit_status = 0 if matched else 2
    receipt = {'schema': RECEIPT_SCHEMA, 'run_id': run_id, 'contract_sha256': contract_sha256, 'mode': mode,
               'owner_exit_status': exit_status, 'status': 'FixtureMatched' if matched else
               'UnexpectedStop' if clean_mismatch else 'Cancelled' if cancellation else 'EnvironmentInterrupted',
               'completed': state.completed, 'fixture_matched': state.matched, 'launches': state.launches,
               'worker_exit_status': state.worker_exit_status, 'cleanup_complete': cleanup_complete,
               'unexpected_children': state.unexpected_children, 'prefix': state.prefix, 'terminal': state.terminal,
               'stop': state.stop, 'stop_kind': state.stop_kind, 'interruption_kind': state.interruption_kind}
    try:
        _receipt_write(receipt)
    except (OSError, ValueError):
        return 2  # Missing/partial receipt is explicitly unqualified at the caller.
    return exit_status


def _binary_identity(descriptor):
    metadata = os.fstat(descriptor)
    need(stat.S_ISREG(metadata.st_mode) and not metadata.st_mode & (stat.S_ISUID | stat.S_ISGID),
         'privileged_or_nonregular_binary')
    try:
        capabilities = os.getxattr(descriptor, 'security.capability')
    except OSError as error:
        need(error.errno == errno.ENODATA, 'binary_capability_check_unsupported')
        capabilities = b''
    need(not capabilities, 'file_capability_binary_forbidden')
    return tuple(getattr(metadata, name) for name in
                 ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def _verified_binary(contract):
    descriptor = os.open(contract['binary'], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        identity = _binary_identity(descriptor)
        need(0 < identity[5] <= contract['budgets']['binary_bytes'], 'binary_file_bound')
        value, size = hashlib.sha256(), 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, contract['budgets']['binary_bytes'] + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            need(size <= contract['budgets']['binary_bytes'], 'binary_grew_beyond_bound')
            value.update(chunk)
        need(value.hexdigest() == contract['provenance']['binary_sha256'], 'retained_binary_identity')
        need(_binary_identity(descriptor) == identity, 'binary_metadata_changed_during_hash')
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def save_observation(store, contract, fixture, index, input_reference, capture):
    """Commit raw bounded observations before any output parser/oracle/assertion."""
    record = {'schema': CASE_SCHEMA, 'run_id': contract['run_id'], 'contract_sha256': object_hash(contract),
              'index': index, 'id': fixture['id'], 'kind': fixture['kind'], 'input': input_reference,
              'process': capture['process'], 'observation': capture['observation'], 'stop_kind': capture['stop_kind']}
    for name in ('stdout', 'stderr'):
        reference = store.immutable(f'{index:03d}.{name}.bin', capture['bytes'][name])
        record[name] = {'reference': reference, 'observed_bytes': capture['observed'][name],
                        'complete': capture['complete'][name]}
    # Raw bytes and actual bounded process metadata precede all strict semantic
    # validation. A rejected observation remains available with its real facts.
    reference = store.json(f'{index:03d}.observation.json', record)
    return record, reference


def _empty_capture(started=False):
    return {'process': {'pid': None, 'identity': None, 'registered': False, 'released': False,
                        'reaped': False, 'wait_status': None, 'returncode': None, 'wall_ms': 0},
            'observation': 'EnvironmentInterrupted' if started else 'NotStarted',
            'stop_kind': 'EnvironmentInterrupted',
            'bytes': {'stdout': b'', 'stderr': b''}, 'observed': {'stdout': 0, 'stderr': 0},
            'complete': {'stdout': False, 'stderr': False}}


def _prefix(contract, cases, first_invariant, first_stop):
    return {'schema': PREFIX_SCHEMA, 'run_id': contract['run_id'], 'contract_sha256': object_hash(contract),
            'cases': cases, 'first_invariant': first_invariant, 'first_unexpected_stop': first_stop}


def worker_main(channel, contract_bytes, run_id, mode, contract_sha256, startup_deadline, ceiling):
    """Limited worker: all project imports, fixture work and persistence live here."""
    contract = validate_contract(strict_json(contract_bytes, MAX_CONTRACT))
    need(contract['run_id'] == run_id and contract['mode'] == mode and object_hash(contract) == contract_sha256,
         'external_contract_identity')
    _check_worker_sources(contract)
    from . import controlled_admission as controlled
    controlled.validate_provenance(contract['provenance'])
    controlled.check_current_provenance(contract['binary'], contract['provenance'], contract['root'])
    plan = fixture_plan(controlled)
    prior = replay_source(contract['replay_dir'], contract) if mode == 'replay' else None
    store = EvidenceStore(contract['evidence_dir'], contract['budgets'])
    store.json('contract.json', contract, maximum=MAX_CONTRACT, terminal=True)
    cases, shrink_observations = [], []
    first_invariant = first_stop = None
    prefix_reference = store.prefix(_prefix(contract, cases, first_invariant, first_stop), terminal=True)
    work_deadline = _exchange(channel, run_id, {'type': 'Hello', 'index': -1, 'role': 'worker',
                                              'contract_sha256': contract_sha256, 'total': len(plan), 'prefix': prefix_reference},
                              'Ready', startup_deadline)
    for index, fixture in enumerate(plan):
        deadline = _exchange(channel, run_id, {'type': 'Begin', 'index': index, 'role': 'worker',
                                              'id': fixture['id'], 'kind': fixture['kind']}, 'CaseStarted', work_deadline)
        input_reference = observation_reference = evaluation_reference = None
        record = output = evaluation = capture = None
        observation_loss = None
        matched, stop, launched = False, None, False
        stop_kind, interruption_kind, stop_phase = None, None, None
        failure_kind, phase = 'ResourceInterrupted', 'reservation'
        persistence_started = False
        try:
            store.reserve_case(len(fixture['bytes']))
            failure_kind, phase = 'StorageInterrupted', 'input_persistence'
            input_reference = store.immutable(f'{index:03d}.input.json', fixture['bytes'])
            failure_kind, phase = 'InvalidArtifact', 'prior_validation'
            prior_semantics = verify_prior_case(controlled, contract['replay_dir'], prior, fixture, index) if prior else None
            failure_kind, phase = 'EnvironmentInterrupted', 'provenance_validation'
            _check_worker_sources(contract)
            controlled.check_current_provenance(contract['binary'], contract['provenance'], contract['root'])
            binary_fd = _verified_binary(contract)
            binary_identity = _binary_identity(binary_fd)
            try:
                launched = True
                failure_kind, phase = 'EnvironmentInterrupted', 'capture'
                capture = capture_child(channel, contract, index, store.directory / input_reference['file'], binary_fd, deadline, ceiling)
                if capture['stop_kind'] is not None:
                    stop, stop_kind, stop_phase = capture['observation'], capture['stop_kind'], 'capture'
                    interruption_kind = capture['stop_kind']
                # Persist first even when the subsequently checked executable
                # metadata/source/input identity has changed.
                failure_kind, phase, persistence_started = 'StorageInterrupted', 'observation_persistence', True
                record, observation_reference = save_observation(store, contract, fixture, index, input_reference, capture)
                failure_kind, phase = 'EnvironmentInterrupted', 'observation_validation'
                validate_case_record(record, contract, index, fixture['id'], fixture['kind'])
                need(_binary_identity(binary_fd) == binary_identity, 'binary_metadata_changed_during_execution')
            finally:
                os.close(binary_fd)
            # This immutable commit precedes all semantic checks, including a
            # source/input-change failure following an otherwise valid process.
            failure_kind, phase = 'EnvironmentInterrupted', 'post_execution_provenance'
            _check_worker_sources(contract)
            controlled.check_current_provenance(contract['binary'], contract['provenance'], contract['root'])
            need(read_reference(store.directory, input_reference, contract['budgets']['input_bytes']) == fixture['bytes'], 'input_changed')
            failure_kind, phase = 'EnvironmentInterrupted', 'oracle'
            output, evaluation, matched, stop = evaluate_fixture(controlled, fixture, record, capture['bytes']['stdout'])
            stop_kind = None if matched else 'FixtureMismatch' if record['observation'] == 'Complete' else record['stop_kind']
            if not matched:
                stop_phase = 'oracle' if record['observation'] == 'Complete' else 'capture'
                interruption_kind = stop_kind if stop_kind in INTERRUPTION_KINDS else None
            if matched and prior_semantics is not None:
                need((output, evaluation) == prior_semantics, 'replay_semantics_changed')
            if evaluation is not None:
                failure_kind, phase = 'StorageInterrupted', 'evaluation_persistence'
                evaluation_reference = store.json(f'{index:03d}.evaluation.json', evaluation,
                                                  maximum=contract['budgets']['evaluation_bytes'])
                if type(evaluation.get('invariant')) is dict and first_invariant is None:
                    first_invariant = {'index': index, 'evaluation': evaluation_reference,
                                       'class': evaluation['invariant']['class']}
            if matched and fixture['kind'] == 'shrink':
                failure_kind, phase = 'FixtureMismatch', 'shrink_relation'
                shrink_observations.append((fixture['value'], output, evaluation))
                if len(shrink_observations) == PLAN_COUNTS['shrink']:
                    shrink_relations(controlled, shrink_observations)
            if matched and index == len(plan) - 1 and prior is not None:
                failure_kind, phase = 'InvalidArtifact', 'first_invariant_validation'
                need(first_invariant == prior[1]['first_invariant'], 'saved_first_invariant_changed')
        except (OSError, ValueError, TypeError, KeyError, MemoryError, RecursionError) as error:
            matched = False
            category = 'ResourceInterrupted' if isinstance(error, MemoryError) else failure_kind
            if stop is None:
                stop = ('WorkerCaseFailure:' + type(error).__name__ + ':' + str(error))[:128]
                stop_kind, stop_phase = category, phase
            if interruption_kind is None and category in INTERRUPTION_KINDS:
                interruption_kind = category
            if observation_reference is None:
                observation_loss = {'phase': phase, 'reason': (type(error).__name__ + ':' + str(error))[:128],
                                    'stop_kind': category, 'capture_available': capture is not None}
            if capture is None and not persistence_started and input_reference is not None and not launched:
                # Only a genuine pre-observation failure may get a NotStarted
                # record. Never rewrite raw names after any captured save began.
                try:
                    persistence_started = True
                    record, observation_reference = save_observation(
                        store, contract, fixture, index, input_reference, _empty_capture())
                    observation_loss = None
                except (OSError, ValueError, MemoryError) as persistence_error:
                    # Keep the original stop/phase. Missing actual metadata is
                    # explicit in the result's null observation reference.
                    observation_loss = {'phase': 'not_started_persistence',
                                        'reason': (type(persistence_error).__name__ + ':' + str(persistence_error))[:128],
                                        'stop_kind': 'StorageInterrupted', 'capture_available': False}
        if not matched:
            stop = stop or 'UnexpectedStop'
            stop_kind = stop_kind or 'EnvironmentInterrupted'
            if stop_kind in INTERRUPTION_KINDS and interruption_kind is None:
                interruption_kind = stop_kind
            first_stop = {'index': index, 'reason': stop, 'stop_kind': stop_kind,
                          'interruption_kind': interruption_kind, 'phase': stop_phase or phase}
        result = {'schema': RESULT_SCHEMA, 'run_id': run_id, 'contract_sha256': contract_sha256,
                  'index': index, 'id': fixture['id'], 'kind': fixture['kind'], 'observation': observation_reference,
                  'observation_loss': observation_loss,
                  'evaluation': evaluation_reference, 'fixture_status': 'FixtureMatched' if matched else 'UnexpectedStop',
                  'stop': stop, 'stop_kind': stop_kind, 'interruption_kind': interruption_kind}
        validate_result(result, observation_reference, contract, fixture, index)
        # If reservation failed before writing, the small failed-case result and
        # terminal use the separately retained reserve. Never launch without space.
        emergency = store.reservation == 0
        result_reference = store.json(f'{index:03d}.result.json', result, terminal=emergency)
        cases.append({'index': index, 'id': fixture['id'], 'kind': fixture['kind'],
                      'observation': observation_reference, 'result': result_reference, 'fixture_status': result['fixture_status']})
        prefix_reference = store.prefix(_prefix(contract, cases, first_invariant, first_stop), terminal=emergency)
        store.release_case()
        work_deadline = _exchange(channel, run_id, {'type': 'CaseReady', 'index': index, 'role': 'worker',
                                                  'fixture_status': result['fixture_status'], 'prefix': prefix_reference,
                                                  'observation': observation_reference, 'result': result_reference,
                                                  'stop': stop, 'stop_kind': stop_kind,
                                                  'interruption_kind': interruption_kind},
                                  'CaseSaved', deadline)
        if not matched:
            break
    complete = len(cases) == len(plan) and first_stop is None and len(shrink_observations) == PLAN_COUNTS['shrink']
    terminal = {'schema': CORPUS_SCHEMA, 'contract_sha256': contract_sha256, 'cases': cases,
                'shrink': {'schema': SHRINK_SCHEMA, 'attempts': [78, 79, 80, 81],
                           'original': 78, 'candidate': 79, 'positive_control': 80, 'reduced': 81},
                'first_invariant': first_invariant, 'first_unexpected_stop': first_stop, 'complete': complete}
    terminal_reference = store.json('corpus.json', terminal, maximum=MAX_PREFIX, terminal=True)
    _exchange(channel, run_id, {'type': 'Done', 'index': len(cases), 'role': 'worker', 'complete': complete,
                              'prefix': prefix_reference, 'terminal': terminal_reference}, 'TerminalReceived', work_deadline)
    return 0 if complete else 2


def _worker_bootstrap(expected_parent, channel, gate_read, contract_bytes, run_id, mode, contract_sha256, deadline, ceiling):
    try:
        _parent_death(expected_parent)
        _limits(PROPOSED_BUDGETS['worker_cpu_s'], PROPOSED_BUDGETS['worker_cpu_s'])
        for signum in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, signal.SIG_DFL)
        _close_except({channel.fileno(), gate_read}, ceiling)
        need(os.read(gate_read, 1) == b'G', 'worker_registration_gate_closed')
        os.close(gate_read)
        # Keep 0/1/2 occupied so future pipes cannot alias the child's stdio.
        null = os.open('/dev/null', os.O_RDWR | os.O_CLOEXEC)
        try:
            for descriptor in (0, 1, 2):
                os.dup2(null, descriptor)
        finally:
            if null > 2:
                os.close(null)
        status = worker_main(channel, contract_bytes, run_id, mode, contract_sha256, deadline, ceiling)
    except BaseException:
        status = 2  # The owner records missing terminal, then bounded cleanup.
    os._exit(status)
