#!/usr/bin/env python3
"""Fixed total-only GNU timeout caller for the controlled-admission owner.

Source only until execution is separately authorized. The observed launch/capture
interval must fit 617 seconds. Preflight, Popen/exec bootstrap stalls and final
filesystem writes have no universal hard wall guarantee. GNU timeout's timer
starts after its fork. Unknown wrapper/owner liveness is never cleanup success.
"""
import argparse
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import controlled_admission_supervision as supervision


STREAM_LIMIT = 4096
PACKET_LIMIT = 8192
RESULT_SCHEMA = 'northstar-controlled-caller-result-v1'


def fixed_arguments(contract):
    arguments = [supervision.TIMEOUT_PATH, *supervision.TIMEOUT_ARGUMENTS, contract['caller']['python'],
                 '-I', '-S', '-B', str(Path(contract['root']) / 'scripts/run-controlled-admission.py'),
                 '--contract-json', supervision.canonical(contract),
                 '--contract-sha256', supervision.object_hash(contract), '--run-id', contract['run_id'],
                 '--mode', contract['mode']]
    profile = supervision.contract_profile(contract)
    if not profile['legacy']:
        arguments.extend(('--profile', profile['id']))
    return arguments


def verify_material(contract):
    """Outside monitoring. Trusted frozen files remain an explicit prerequisite."""
    supervision.need(str(Path(__file__).resolve()) ==
                     str(Path(contract['root']) / 'scripts/capture-controlled-admission.py'), 'caller_source_root')
    supervision.need(str(Path(sys.executable).resolve()) == contract['caller']['python'], 'caller_python_path')
    if not supervision.contract_profile(contract)['legacy']:
        verified_sources = supervision._check_worker_sources(contract)
        # Source/import-layout checks precede this oracle/helper import. The
        # caller repeats the same preparation-record/runnable binding after
        # capture; its preflight gate still stops before any timeout launch.
        from lib import direct_case
        supervision.check_current_material(direct_case, contract, verified_sources)
    identities = {}
    materials = [(Path(supervision.TIMEOUT_PATH), contract['caller']['timeout_sha256'],
                  contract['budgets']['binary_bytes']),
                 (Path(contract['caller']['python']), contract['caller']['python_sha256'],
                  contract['budgets']['binary_bytes'])]
    source_bytes = 0
    for name, expected in contract['helper_source_files'].items():
        data = supervision.read_bounded(Path(contract['root']) / name, contract['budgets']['source_bytes'])
        source_bytes += len(data)
        supervision.need(source_bytes <= contract['budgets']['source_bytes'] and
                         supervision.fingerprint(data) == expected, 'caller_helper_source_changed')
    for path, expected, maximum in materials:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            before = supervision._binary_identity(descriptor)
            with os.fdopen(os.dup(descriptor), 'rb') as stream:
                data = stream.read(maximum + 1)
            after = supervision._binary_identity(descriptor)
            supervision.need(len(data) <= maximum and before == after and
                             supervision.fingerprint(data) == expected, 'caller_executable_changed')
            identities[str(path)] = after
        finally:
            os.close(descriptor)
    return identities


def collect(contract):
    """One fixed launch; bounded capture, no descendant signals or extra reaper."""
    # A dedicated fresh single-thread caller has no competing waitpid consumer.
    # Reset inherited auto-reap before Popen so poll reports an actual terminal.
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    streams = {name: {'data': bytearray(), 'observed_bytes': 0, 'complete': False}
               for name in ('stdout', 'stderr')}
    endpoints = {}
    process = None
    status = None
    stop = None
    started = time.monotonic_ns()
    deadline = started + contract['budgets']['caller_total_ms'] * 1_000_000
    try:
        process = subprocess.Popen(fixed_arguments(contract), stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
                                   restore_signals=True, shell=False, bufsize=0,
                                   env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        for name in streams:
            endpoint = getattr(process, name)
            endpoints[endpoint.fileno()] = (name, endpoint)
            os.set_blocking(endpoint.fileno(), False)
        while True:
            status = process.poll()
            now = time.monotonic_ns()
            if status is not None and not endpoints:
                break
            if now >= deadline:
                stop = stop or 'CallerDeadlineOrMissingEOF'
                break
            try:
                readable = select.select(list(endpoints), [], [], min(0.05, (deadline - now) / 1_000_000_000))[0]
            except InterruptedError:
                continue
            for descriptor in readable:
                name, endpoint = endpoints[descriptor]
                stream = streams[name]
                try:
                    data = os.read(descriptor, STREAM_LIMIT - len(stream['data']) + 1)
                except (BlockingIOError, InterruptedError):
                    continue
                stream['observed_bytes'] += len(data)
                if not data:
                    stream['complete'] = True
                else:
                    stream['data'].extend(data[:STREAM_LIMIT - len(stream['data'])])
                if not data or stream['observed_bytes'] > STREAM_LIMIT:
                    if data:
                        stop = stop or name + 'Limit'
                    endpoint.close()  # Only this stream; the other remains bounded.
                    del endpoints[descriptor]
    except (OSError, ValueError, OverflowError) as error:
        stop = stop or 'CaptureFailure:' + type(error).__name__
    finally:
        for _name, endpoint in endpoints.values():
            endpoint.close()
        if process is not None:
            # Never use Popen's context manager or wait(), both may block here.
            for name in streams:
                endpoint = getattr(process, name, None)
                if endpoint is not None and not endpoint.closed:
                    endpoint.close()
            try:
                status = process.poll()
            except (OSError, ValueError):
                status = None
                stop = stop or 'WrapperTerminalUnknown'
    elapsed_ns = time.monotonic_ns() - started
    for stream in streams.values():
        stream['data'] = bytes(stream['data'])
    return {'streams': streams, 'timeout_exit_status': status, 'elapsed_ns': elapsed_ns, 'stop': stop}


def make_packet(contract, invocation_id, observation, material_stable):
    """Raw prefixes are diagnostics, never a partial receipt or cleanup proof."""
    output, errors = observation['streams']['stdout'], observation['streams']['stderr']
    elapsed_ns = observation['elapsed_ns']
    duration_valid = type(elapsed_ns) is int and 0 <= elapsed_ns <= contract['budgets']['caller_total_ms'] * 1_000_000
    measured_ms = (max(0, elapsed_ns) + 999999) // 1_000_000
    status = observation['timeout_exit_status']
    capture = {'schema': supervision.CAPTURE_SCHEMA, 'owner_exit_status': None,
               'stdout_complete': output['complete'], 'receipt': None}
    authority = {'schema': supervision.CALLER_EVIDENCE_SCHEMA, 'invocation_id': invocation_id,
                 'mechanism_sha256': supervision.caller_mechanism_hash(contract), 'owner_exit_status': None,
                 'timeout_exit_status': status, 'receipt_sha256': None,
                 'total_limit_ms': contract['budgets']['caller_total_ms'], 'observed_total_ms': measured_ms,
                 'stdout_complete': output['complete'], 'stderr_complete': errors['complete']}
    qualification = {'FixtureMatched': False, 'supervision_complete': False}
    stop = observation['stop']
    if not material_stable:
        stop = stop or 'CallerMaterialChanged'
    if not duration_valid:
        stop = stop or 'CallerTotalExceeded'
    if type(status) is not int or status not in (0, 2):
        stop = stop or 'WrapperTerminalUnqualified'
    if not output['complete'] or not errors['complete']:
        stop = stop or 'CallerStreamIncomplete'
    if stop is None:
        try:
            receipt = supervision.strict_json(output['data'], STREAM_LIMIT)
            supervision.need(supervision.encoded(receipt) == output['data'], 'noncanonical_receipt_bytes')
            capture.update(owner_exit_status=status, receipt=receipt)
            authority.update(owner_exit_status=status, receipt_sha256=supervision.fingerprint(output['data']))
            qualification = supervision.validate_owner_capture(capture, contract, caller_evidence=authority)
        except (ValueError, TypeError, OverflowError) as error:
            stop = 'ReceiptInvalid:' + type(error).__name__
            capture.update(owner_exit_status=None, receipt=None)
            authority.update(owner_exit_status=None, receipt_sha256=None)
    references = {}
    for name, stream in observation['streams'].items():
        references[name] = {'reference': {'file': 'owner.stdout.bin' if name == 'stdout' else 'timeout.stderr.bin',
                                         'bytes': len(stream['data']), 'sha256': supervision.fingerprint(stream['data'])},
                            'observed_bytes': stream['observed_bytes'], 'complete': stream['complete']}
    result = {'schema': RESULT_SCHEMA, 'run_id': contract['run_id'], 'contract_sha256': supervision.object_hash(contract),
              'invocation_id': invocation_id, 'timeout_exit_status': status, 'timeout_reaped': status is not None,
              'observed_total_ms': measured_ms, 'stop': stop, 'streams': references,
              'qualification': qualification}
    return capture, authority, result


def save_packet(contract, observation, capture, authority, result):
    """Post-work only. A failed fsync/save cannot return usable caller authority."""
    directory = supervision.caller_directory(contract['evidence_dir'])
    files = [('owner.stdout.bin', observation['streams']['stdout']['data']),
             ('timeout.stderr.bin', observation['streams']['stderr']['data']),
             ('caller-capture.json', supervision.encoded(capture)),
             ('caller-result.json', supervision.encoded(result)),
             ('caller-evidence.json', supervision.encoded(authority))]
    # Immutable create-only files need no extra temporary copy. No full contract
    # or argv is duplicated in this finite packet; authority is published last.
    supervision.need(all(len(data) <= (STREAM_LIMIT if name.endswith('.bin') else PACKET_LIMIT)
                         for name, data in files) and
                     sum(len(data) for _name, data in files) <= contract['budgets']['caller_artifact_bytes'],
                     'caller_artifact_budget')
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    def sync(path):
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    sync(directory.parent)
    for name, data in files:
        with (directory / name).open('xb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        sync(directory)


def run(contract, invocation_id):
    supervision.need(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}', invocation_id) is not None,
                     'caller_invocation_identity')
    directory = supervision.caller_directory(contract['evidence_dir'])
    supervision.need(not directory.exists() and not directory.is_symlink(), 'caller_destination_exists')
    before = verify_material(contract)
    if not supervision.contract_profile(contract)['legacy']:
        supervision.direct_preflight(contract)
    observation = collect(contract)
    try:
        stable = verify_material(contract) == before
    except (OSError, ValueError):
        stable = False
    capture, authority, result = make_packet(contract, invocation_id, observation, stable)
    save_packet(contract, observation, capture, authority, result)
    return 0 if result['qualification']['FixtureMatched'] else 2


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--contract-json', required=True)
    parser.add_argument('--contract-sha256', required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--mode', required=True, choices=('record', 'replay'))
    parser.add_argument('--invocation-id', required=True)
    args = parser.parse_args(argv)
    if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode):
        parser.error('the dedicated caller requires python3 -I -S -B')
    try:
        contract = supervision.validate_contract(supervision.strict_json(args.contract_json.encode(), supervision.MAX_CONTRACT))
        supervision.need(supervision.object_hash(contract) == args.contract_sha256 and
                         contract['run_id'] == args.run_id and contract['mode'] == args.mode, 'external_contract_binding')
        return run(contract, args.invocation_id)
    except (OSError, ValueError, TypeError, OverflowError) as error:
        # Do not turn partial persistence into a positive receipt. A separately
        # trusted invoker must observe this caller's actual terminal outcome.
        print('CallerUnqualified:' + type(error).__name__, file=sys.stderr)
        return 3


if __name__ == '__main__':
    raise SystemExit(main())
