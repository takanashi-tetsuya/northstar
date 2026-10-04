#!/usr/bin/env python3
"""Bounded actual-v2 reader tampering on private byte copies, never a Rust run.

Execution requires a separate release and an external 300-second timeout. The
internal clock checks cannot interrupt filesystem or Python stalls. The audit
guard is a regression tripwire, not OS isolation. Existing bound sources and
original evidence remain read-only; this script is deliberately outside them.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
MAX_FILES = 640
MAX_COPY_BYTES = 48 * 1024 ** 2
MAX_ALLOCATED_BYTES = 64 * 1024 ** 2
MAX_REPORT = 64 * 1024
MAX_SOURCE = 64 * 1024 ** 2
MAX_CONTRACT = 128 * 1024
SECONDS = 300
CASES = (
    ('missing_input', 0, 'verify_prior_case', 'reference_regular_file'),
    ('changed_input', 0, 'verify_prior_case', 'saved_reference_changed'),
    ('missing_output', 0, 'verify_prior_case', 'reference_regular_file'),
    ('changed_output', 0, 'verify_prior_case', 'saved_reference_changed'),
    ('truncated_output', 0, 'verify_prior_case', 'saved_reference_changed'),
    ('missing_evaluation', 0, 'verify_prior_case', 'reference_regular_file'),
    ('changed_evaluation', 0, 'verify_prior_case', 'saved_reference_changed'),
    ('legacy_observation_schema', 0, 'verify_prior_case', 'saved_reference_changed'),
    ('observation_run_correlation', 0, 'verify_prior_case', 'saved_reference_changed'),
    ('result_index_correlation', 0, 'verify_prior_case', 'saved_reference_changed'),
    ('rejection_reason', 44, 'verify_prior_case', 'saved_reference_changed'),
    ('shrink_target', 81, 'verify_prior_case', 'saved_reference_changed'),
    ('saved_provenance', 0, 'replay_source', 'saved_contract_differs_from_external_authority'),
    ('missing_tail_observation', 81, 'verify_prior_case', 'reference_regular_file'),
    ('shortened_manifest_tail', 81, 'replay_source', 'saved_reference_changed'),
    ('missing_final_prefix', 81, 'replay_source', 'reference_regular_file'),
    ('legacy_corpus_schema', 0, 'replay_source', 'saved_reference_changed'),
    ('caller_capture_run', 0, 'replay_source', 'prior_owner_capture_incomplete'),
    ('rehashed_input_output_evaluation', 11, 'replay_source', 'prior_owner_capture_incomplete'),
    ('rehashed_output_evaluation', 0, 'replay_source', 'prior_owner_capture_incomplete'),
    ('rehashed_shrink_target_evaluation', 81, 'replay_source', 'prior_owner_capture_incomplete'),
    ('rehashed_short_tail', 81, 'replay_source', 'prior_owner_capture_incomplete'),
)


class CheckFailure(RuntimeError):
    pass


class BoundaryAttempt(BaseException):
    pass


def require(condition, reason):
    if not condition:
        raise CheckFailure(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def read(path, maximum):
    require(not path.is_symlink() and stat.S_ISREG(path.stat().st_mode), 'nonregular_read')
    with path.open('rb') as stream:
        data = stream.read(maximum + 1)
    require(len(data) <= maximum, 'read_byte_limit')
    return data


def install_tripwire():
    blocked = {'os.fork', 'os.forkpty', 'os.exec', 'os.posix_spawn', 'os.spawn', 'os.system',
               'subprocess.Popen', 'os.kill', 'os.killpg', 'os.link', 'os.symlink',
               'resource.setrlimit', 'resource.prlimit', 'signal.pthread_kill', '_thread.start_new_thread'}
    state = {'ready': False, 'blocked_attempts': {}}
    def stop(event):
        counts = state['blocked_attempts']
        label = event[:80] if event[:80] in counts or len(counts) < 32 else 'OtherBlockedBoundary'
        counts[label] = min(counts.get(label, 0) + 1, 1000)
        raise BoundaryAttempt('UnpermittedBoundary:' + event)
    def audit(event, args):
        if event == 'builtins.id':  # deepcopy's hot path; not a denied boundary.
            return
        if event == 'northstar.v2_reader_tripwire_ready':
            state['ready'] = True
        elif event in blocked or event.startswith('socket.') or (
            event in ('ctypes.dlsym', 'ctypes.dlsym/handle') and len(args) > 1 and args[1] == 'prctl'
        ):
            stop(event)
    sys.addaudithook(audit)
    sys.audit('northstar.v2_reader_tripwire_ready')
    require(state['ready'], 'audit_hook_not_installed')
    os._exit = lambda *_args, **_kwargs: stop('os._exit')
    return state


def evidence_snapshot(directory, check):
    values, identities = {}, set()
    for label, source in (('record', directory), ('record.caller', directory.with_name(directory.name + '.caller'))):
        require(source.is_dir() and not source.is_symlink(), 'original_directory')
        for path in sorted(source.iterdir()):
            check()
            require(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,159}', path.name) is not None, 'original_filename')
            require(len(values) < MAX_FILES, 'original_file_count')
            data = read(path, MAX_COPY_BYTES)
            values[label + '/' + path.name] = data
            require(sum(map(len, values.values())) <= MAX_COPY_BYTES, 'original_byte_count')
            metadata = path.stat()
            identities.add((metadata.st_dev, metadata.st_ino))
    return values, identities


def map_hash(values):
    return digest(encoded({name: {'bytes': len(data), 'sha256': digest(data)} for name, data in values.items()}))


class PrivateCopy:
    """One flat byte-copy pair. No hardlinks, temporary clones or generic DSL."""
    def __init__(self, root, baseline, original_identities, check):
        self.root, self.baseline, self.original_identities, self.check = root, baseline, original_identities, check
        self.current, self.touched, self.allocated = {}, set(), 0
        root.mkdir(mode=0o700, parents=False, exist_ok=False)
        for name in ('record', 'record.caller'):
            (root / name).mkdir(mode=0o700)
        for name, data in baseline.items():
            self.put(name, data)
        self.touched.clear()
        self.verify_baseline()

    def put(self, name, data):
        self.check()
        require(name in self.baseline and type(data) is bytes, 'copy_write_scope')
        require(sum(map(len, self.current.values())) - len(self.current.get(name, b'')) + len(data) <= MAX_COPY_BYTES,
                'copy_byte_limit')
        path = self.root / name
        old_blocks = path.stat().st_blocks * 512 if name in self.current else 0
        self.touched.add(name)  # Retain the attempted path even if its write fails.
        with path.open('wb' if name in self.current else 'xb') as stream:
            stream.write(data)
        self.current[name] = data
        metadata = path.stat()
        require(metadata.st_nlink == 1 and (metadata.st_dev, metadata.st_ino) not in self.original_identities,
                'copy_must_not_alias_original')
        self.allocated += metadata.st_blocks * 512 - old_blocks
        require(self.allocated + MAX_REPORT + 64 * 1024 <= MAX_ALLOCATED_BYTES, 'copy_allocated_limit')

    def delete(self, name):
        require(name in self.current, 'copy_delete_scope')
        path = self.root / name
        self.allocated -= path.stat().st_blocks * 512
        path.unlink()
        del self.current[name]
        self.touched.add(name)

    def value(self, name):
        return json.loads(self.current[name])

    def json(self, name, value):
        self.put(name, encoded(value))

    def check_allocated(self):
        paths = [self.root, self.root / 'record', self.root / 'record.caller'] + [self.root / name for name in self.current]
        require(sum(path.stat().st_blocks * 512 for path in paths) + MAX_REPORT <= MAX_ALLOCATED_BYTES,
                'copy_allocated_limit')

    def restore(self):
        for name in sorted(self.touched):
            self.put(name, self.baseline[name])
        self.touched.clear()
        self.verify_baseline()

    def verify_baseline(self):
        self.check()
        require(self.current == self.baseline, 'copy_baseline_map')
        actual = {label + '/' + path.name: read(path, MAX_COPY_BYTES)
                  for label in ('record', 'record.caller') for path in (self.root / label).iterdir()}
        require(actual == self.baseline, 'copy_baseline_bytes')
        self.check_allocated()


def reference(store, name):
    data = store.current['record/' + name]
    return {'file': name, 'bytes': len(data), 'sha256': digest(data)}


def rehash_local_chain(store, index, controlled, tail=False):
    """Repair local hashes only. External authority is never supplied here."""
    manifest = store.value('record/corpus.json')
    recomputed = False
    if tail:
        manifest['cases'].pop()
    else:
        stem = f'{index:03d}'
        record = store.value(f'record/{stem}.observation.json')
        value = store.value(f'record/{stem}.input.json')
        output = store.value(f'record/{stem}.stdout.bin')
        evaluation = controlled.evaluate(value, output, expected_failure=controlled.expected_counterexample(value))
        store.json(f'record/{stem}.evaluation.json', evaluation)
        require(store.value(f'record/{stem}.evaluation.json') == evaluation, 'replacement_evaluation_write')
        recomputed = True
        record['input'] = reference(store, f'{stem}.input.json')
        record['stdout']['reference'] = reference(store, f'{stem}.stdout.bin')
        record['stdout']['observed_bytes'] = record['stdout']['reference']['bytes']
        store.json(f'record/{stem}.observation.json', record)
        result = store.value(f'record/{stem}.result.json')
        result['observation'] = reference(store, f'{stem}.observation.json')
        result['evaluation'] = reference(store, f'{stem}.evaluation.json')
        store.json(f'record/{stem}.result.json', result)
        manifest['cases'][index]['observation'] = reference(store, f'{stem}.observation.json')
        manifest['cases'][index]['result'] = reference(store, f'{stem}.result.json')
    store.json('record/corpus.json', manifest)
    prefix = store.value('record/prefix-082.json')
    prefix['cases'] = manifest['cases']
    store.json('record/prefix-082.json', prefix)
    capture = store.value('record.caller/caller-capture.json')
    capture['receipt']['terminal'] = reference(store, 'corpus.json')
    capture['receipt']['prefix'] = reference(store, 'prefix-082.json')
    store.json('record.caller/caller-capture.json', capture)
    store.put('record.caller/owner.stdout.bin', encoded(capture['receipt']))
    authority = store.value('record.caller/caller-evidence.json')
    authority['receipt_sha256'] = digest(encoded(capture['receipt']))
    store.json('record.caller/caller-evidence.json', authority)
    diagnostics = store.value('record.caller/caller-result.json')
    stdout = diagnostics['streams']['stdout']
    stdout['reference'].update(bytes=len(encoded(capture['receipt'])), sha256=authority['receipt_sha256'])
    stdout['observed_bytes'] = stdout['reference']['bytes']
    store.json('record.caller/caller-result.json', diagnostics)
    # Explicitly establish the local hash-chain premise without bypassing the
    # real reader's immutable external authority. This is not qualification.
    def check_ref(value):
        require(value == reference(store, value['file']), 'local_reference_inconsistent')
        data = read(store.root / 'record' / value['file'], MAX_COPY_BYTES)
        require(len(data) == value['bytes'] and digest(data) == value['sha256'], 'local_reference_bytes')
    check_ref(capture['receipt']['terminal'])
    check_ref(capture['receipt']['prefix'])
    require(prefix['cases'] == manifest['cases'] and authority['receipt_sha256'] == digest(encoded(capture['receipt'])),
            'local_terminal_chain')
    raw_receipt = read(store.root / 'record.caller/owner.stdout.bin', 4096)
    require(raw_receipt == encoded(capture['receipt']) and
            stdout['reference']['bytes'] == len(raw_receipt) and stdout['reference']['sha256'] == digest(raw_receipt),
            'local_caller_chain')
    if manifest['first_invariant'] is not None:
        check_ref(manifest['first_invariant']['evaluation'])
    require(prefix['first_invariant'] == manifest['first_invariant'], 'local_invariant_pointer')
    for entry in manifest['cases']:
        check_ref(entry['observation'])
        check_ref(entry['result'])
        record = store.value('record/' + entry['observation']['file'])
        result = store.value('record/' + entry['result']['file'])
        require(result['observation'] == entry['observation'], 'local_result_chain')
        for ref in (record['input'], record['stdout']['reference'], record['stderr']['reference'], result['evaluation']):
            check_ref(ref)
    return {'local_hash_chain_consistent': True,
            'local_hash_chain_scope': 'corpus/final-prefix/caller-receipt reachable graph; historical prefixes unchanged',
            'replacement_evaluation_recomputed': recomputed,
            'semantic_qualification_claimed': False}


def mutate(name, index, store, controlled):
    stem = f'{index:03d}'
    names = {'input': f'record/{stem}.input.json', 'output': f'record/{stem}.stdout.bin',
             'evaluation': f'record/{stem}.evaluation.json', 'observation': f'record/{stem}.observation.json',
             'result': f'record/{stem}.result.json'}
    missing = {'missing_input': names['input'], 'missing_output': names['output'],
               'missing_evaluation': names['evaluation'], 'missing_tail_observation': names['observation'],
               'missing_final_prefix': 'record/prefix-082.json'}
    if name in missing:
        store.delete(missing[name])
    elif name == 'changed_input':
        store.put(names['input'], store.current[names['input']] + b' ')
    elif name == 'truncated_output':
        store.put(names['output'], store.current[names['output']][:-1])
    elif name in ('changed_output', 'shrink_target', 'rehashed_output_evaluation', 'rehashed_shrink_target_evaluation'):
        value = store.value(names['output'])
        value['projection'][-1 if index == 81 else 0]['world']['active'] += -1 if index == 81 else 1
        if name == 'rehashed_output_evaluation':
            value['projection'][0]['world']['retained'] = 2
        store.json(names['output'], value)
    elif name == 'rehashed_input_output_evaluation':
        value = store.value(names['input'])
        require(value['stage1'] is None, 'replacement_requires_native_fixture')
        value['scenario_id'] = 'tampered-native-guard'
        store.json(names['input'], value)
        store.json(names['output'], controlled.expected_output(value))
    elif name == 'changed_evaluation':
        value = store.value(names['evaluation'])
        value['qualified'] = not value['qualified']
        store.json(names['evaluation'], value)
    elif name in ('legacy_observation_schema', 'observation_run_correlation'):
        value = store.value(names['observation'])
        value['schema' if name.startswith('legacy') else 'run_id'] = 'tampered-v1'
        store.json(names['observation'], value)
    elif name == 'result_index_correlation':
        value = store.value(names['result'])
        value['index'] = 1
        store.json(names['result'], value)
    elif name == 'rejection_reason':
        value = store.value(names['output'])
        value['reason'] = 'tampered-rejection'
        store.json(names['output'], value)
    elif name == 'saved_provenance':
        value = store.value('record/contract.json')
        value['provenance']['source_sha256'] = '0' * 64
        store.json('record/contract.json', value)
    elif name in ('shortened_manifest_tail', 'legacy_corpus_schema'):
        value = store.value('record/corpus.json')
        if name == 'shortened_manifest_tail':
            value['cases'].pop()
        else:
            value['schema'] = 'northstar-admission-controlled-corpus-v1'
        store.json('record/corpus.json', value)
    elif name == 'caller_capture_run':
        value = store.value('record.caller/caller-capture.json')
        value['receipt']['run_id'] = 'tampered-run'
        store.json('record.caller/caller-capture.json', value)
    else:
        require(name == 'rehashed_short_tail', 'unknown_fixed_mutation')
    detail = rehash_local_chain(store, index, controlled, tail=name == 'rehashed_short_tail') if name.startswith('rehashed_') else {}
    return {**detail, 'changed_files': sorted(store.touched),
            'deleted_files': sorted(item for item in store.touched if item not in store.current)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--replay-contract', required=True)
    parser.add_argument('--contract-sha256', required=True)
    parser.add_argument('--work-dir', required=True, help='new private directory outside the checkout and original evidence')
    args = parser.parse_args(argv)
    require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode, 'requires_python_I_S_B')
    started = time.monotonic_ns()
    def check():
        require(time.monotonic_ns() - started < SECONDS * 1_000_000_000, 'reader_time_budget')
    report = {'schema': 'northstar-controlled-v2-reader-tamper-v1', 'status': 'Incomplete', 'scenarios': [],
              'expected_scenarios': 24, 'time_budget_s': SECONDS, 'copy_byte_limit': MAX_COPY_BYTES,
              'allocated_byte_limit': MAX_ALLOCATED_BYTES, 'report_byte_limit': MAX_REPORT,
              'active_scenario': None, 'active_phase': 'preflight', 'restoration_status': 'NotCreated',
              'syscall_sandbox': False, 'scope': 'saved authenticity chain; no Rust reexecution or new supervised qualification'}
    guard, work, store = None, None, None
    code = 1
    try:
        guard = install_tripwire()
        contract_path = Path(args.replay_contract).resolve()
        contract_bytes = read(contract_path, MAX_CONTRACT)
        require(digest(contract_bytes) == args.contract_sha256, 'external_contract_file_hash')
        current = json.loads(contract_bytes)
        require(current['mode'] == 'replay' and Path(current['root']) == ROOT, 'external_replay_root')
        authority_bytes = encoded(current['replay_authority'])
        source_hashes = current['provenance']['source_files']
        require(len(source_hashes) == 41 and 'scripts/test-controlled-admission-v2-readers.py' not in source_hashes,
                'unchanged_bound_source_scope')
        source_total = 0
        for name, expected in source_hashes.items():
            check()
            require(not Path(name).is_absolute() and '..' not in Path(name).parts, 'bound_source_path')
            data = read(ROOT / name, MAX_SOURCE)
            source_total += len(data)
            require(source_total <= MAX_SOURCE and digest(data) == expected, 'bound_source_changed')
        sys.path.insert(0, str(ROOT / 'scripts'))
        from lib import controlled_admission as controlled
        from lib import controlled_admission_supervision as supervision
        supervision.validate_contract(current)
        original = Path(current['replay_dir']).resolve()
        baseline, identities = evidence_snapshot(original, check)
        report['original_evidence_map_sha256'] = map_hash(baseline)
        report['source_manifest_sha256'] = supervision.object_hash(source_hashes)
        report['script_sha256'] = digest(read(Path(__file__).resolve(), MAX_SOURCE))
        report['external_contract_sha256'] = digest(contract_bytes)
        candidate = Path(args.work_dir).resolve()
        require(not candidate.exists() and not candidate.is_relative_to(ROOT) and
                not candidate.is_relative_to(original) and
                not candidate.is_relative_to(original.with_name(original.name + '.caller')), 'private_work_destination')
        store = PrivateCopy(candidate, baseline, identities, check)
        work = candidate
        report['restoration_status'] = 'BaselineVerified'
        fixtures = supervision.fixture_plan(controlled)
        require(len(fixtures) == 82 and len(CASES) == 22, 'fixed_scenario_count')
        def fixed_authority():
            check()
            require(encoded(current['replay_authority']) == authority_bytes and read(contract_path, MAX_CONTRACT) == contract_bytes,
                    'external_authority_changed')
        def positive(name):
            report.update(active_scenario=name, active_phase='replay_source')
            fixed_authority()
            prior = supervision.replay_source(work / 'record', current)
            tail = []
            for index, fixture in enumerate(fixtures):
                report['active_phase'] = 'verify_prior_case:' + str(index)
                check()
                output, evaluation = supervision.verify_prior_case(controlled, work / 'record', prior, fixture, index)
                if index >= 78:
                    tail.append((fixture['value'], output, evaluation))
            report['active_phase'] = 'shrink_relations'
            supervision.shrink_relations(controlled, tail)
            fixed_authority()
            report['scenarios'].append({'name': name, 'outcome': 'Accepted', 'cases': 82, 'shrink_relations': True})
        positive('clean_before')
        for name, index, expected_phase, expected_reason in CASES:
            report.update(active_scenario=name, active_phase='mutation_setup', restoration_status='NotAttempted')
            fixed_authority()
            detail = mutate(name, index, store, controlled)
            phase = 'replay_source'
            try:
                report['active_phase'] = phase
                prior = supervision.replay_source(work / 'record', current)
                phase = 'verify_prior_case'
                report['active_phase'] = phase
                supervision.verify_prior_case(controlled, work / 'record', prior, fixtures[index], index)
            except supervision.SupervisionError as error:
                reason = str(error)
                require(phase == expected_phase and reason == expected_reason, 'unexpected_rejection:' + name + ':' + phase + ':' + reason)
                report['scenarios'].append({'name': name, 'outcome': 'Rejected', 'phase': phase, 'reason': reason,
                                            'evidence_scope': 'authenticity_chain', **detail})
            else:
                raise CheckFailure('tampering_accepted:' + name)
            finally:
                if guard['blocked_attempts'] or time.monotonic_ns() - started >= SECONDS * 1_000_000_000:
                    report['restoration_status'] = 'SkippedAfterTimeOrBoundaryStop'
                else:
                    report['active_phase'] = 'restoration'
                    report['restoration_status'] = 'InProgress'
                    store.restore()
                    fixed_authority()
                    report['restoration_status'] = 'Verified'
        positive('clean_after')
        report.update(active_scenario=None, active_phase='original_and_source_verification')
        restored, _ = evidence_snapshot(original, check)
        require(restored == baseline, 'original_evidence_changed')
        for name, expected in source_hashes.items():
            check()
            require(digest(read(ROOT / name, MAX_SOURCE)) == expected, 'bound_source_changed_after')
        require(not guard['blocked_attempts'] and len(report['scenarios']) == 24, 'incomplete_reader_scenarios')
        report.update(status='Passed', original_evidence_unchanged=True, bound_sources_unchanged=True,
                      external_authority_unchanged=True, private_copy_restored=True, active_phase='complete')
        code = 0
    except BaseException as error:
        # An audit boundary, interruption, budget overrun or programming error
        # is an overall failure, never an expected negative-test rejection.
        report['failure'] = {'class': type(error).__name__, 'reason': str(error)[:512]}
        if store is not None:
            report['failure']['touched_files'] = sorted(store.touched)[:32]
            report['failure']['deleted_files'] = sorted(name for name in store.touched if name not in store.current)[:32]
        if report['restoration_status'] == 'InProgress':
            report['restoration_status'] = 'FailedOrInterrupted'
    finally:
        report['guard'] = guard
        report['observed_ms'] = (time.monotonic_ns() - started + 999999) // 1_000_000
        data = encoded(report)
        require(len(data) <= MAX_REPORT, 'report_byte_limit')
        if work is not None:
            with (work / 'result.json').open('xb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        sys.stdout.write(data.decode())
    return code


if __name__ == '__main__':
    raise SystemExit(main())
