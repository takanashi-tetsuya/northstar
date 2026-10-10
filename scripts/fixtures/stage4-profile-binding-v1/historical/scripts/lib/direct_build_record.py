"""Pure Stage3 preparation-record binding; no file reads or command execution.

The externally trusted v3 contract authenticates the exact record bytes. The
record describes reviewed preparation, not a reproducible build or a complete
external supply chain. Existing bounded caller/worker readers verify source
inventory first, then this helper authenticates the record. Actual runnable
descriptor verification follows, before the pure runnable-tuple comparison.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import PurePosixPath
import re


SCHEMA = 'northstar-direct-build-record-v1'
MAX_METADATA_BYTES = 128 * 1024  # Existing complete-contract metadata bound.
MAX_SOURCE_BYTES = 64 * 1024 ** 2
MAX_BINARY_BYTES = 128 * 1024 ** 2
MUTATION_PATH = 'src/xmpp/mod.rs'
BASELINE_LINE = b'        io.flush().await\n'
MUTANT_LINE = b'        Ok::<(), std::io::Error>(())\n'
HASH = re.compile(r'[0-9a-f]{64}\Z')
GIT_HASH = re.compile(r'[0-9a-f]{40}\Z')
TARGET = 'x86_64-unknown-linux-gnu'
TOOLCHAIN = '1.97.1-' + TARGET
BUILD_ARGUMENTS = ('test', '--locked', '--offline', '-p', 'rust-xmpp-server',
                   '--bin', 'rust-xmpp-server', '--no-run', '--message-format=json')
BUILD_CONTROLS = {
    'RUSTUP_TOOLCHAIN': TOOLCHAIN, 'CARGO_BUILD_JOBS': '1',
    'CARGO_PROFILE_DEV_DEBUG': '0', 'CARGO_PROFILE_TEST_DEBUG': '0',
    'CARGO_INCREMENTAL': '0', 'CARGO_TERM_COLOR': 'never', 'SQLX_OFFLINE': 'true',
    'RUSTFLAGS': '', 'CARGO_ENCODED_RUSTFLAGS': '',
}
INVENTORY_OBSERVATION = 'ExactManifestMembershipAndAbsences'


class BuildRecordError(ValueError):
    """Unauthenticated or inconsistent build material; never qualification."""


def _need(condition, reason):
    if not condition:
        raise BuildRecordError(reason)


def _fields(value, names, reason):
    _need(type(value) is dict and set(value) == set(names.split()), reason)


def _integer(value, reason, low=0, high=2 ** 63 - 1):
    _need(type(value) is int and low <= value <= high, reason)
    return value


def _text(value, reason):
    _need(type(value) is str and value and '\x00' not in value and
          not any(0xd800 <= ord(char) <= 0xdfff for char in value), reason)
    return value


def _sha(value, reason):
    _need(type(value) is str and HASH.fullmatch(value) is not None, reason)
    return value


def _path(value, reason):
    _text(value, reason)
    path = PurePosixPath(value)
    _need(path.is_absolute() and str(path) == value and '..' not in path.parts and
          '\\' not in value and not value.startswith('//') and value != '/' and
          not any(ord(char) < 32 or ord(char) == 127 for char in value), reason)
    return value


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def _decode(raw_bytes, expected_sha256):
    _need(type(raw_bytes) is bytes and len(raw_bytes) <= MAX_METADATA_BYTES,
          'build_record_byte_budget')
    _sha(expected_sha256, 'external_build_record_sha256')
    # This comparison must precede decoding, JSON parsing and all record fields.
    _need(_hash(raw_bytes) == expected_sha256, 'build_record_file_sha256')

    def pairs(items):
        result = {}
        for key, value in items:
            _need(key not in result, 'duplicate_build_record_field')
            result[key] = value
        return result

    def nonfinite(_):
        raise BuildRecordError('nonfinite_build_record_json')

    try:
        text = raw_bytes.decode('utf-8')
        _need(not text.startswith('\ufeff'), 'build_record_utf8_bom')
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=nonfinite)
        _need(_canonical(value) + b'\n' == raw_bytes, 'build_record_canonical_lf')
    except BuildRecordError:
        raise
    except (UnicodeError, ValueError, RecursionError) as error:
        raise BuildRecordError('malformed_build_record_json') from error
    return value


def _file(value, reason):
    _fields(value, 'path sha256 bytes mode', reason + '_fields')
    _path(value['path'], reason + '_path')
    _sha(value['sha256'], reason + '_sha256')
    _integer(value['bytes'], reason + '_bytes', 1)
    _integer(value['mode'], reason + '_mode', 0, 0o777)
    _need(value['mode'] in (0o644, 0o755), reason + '_ordinary_mode')


def _summary(value, reason):
    _fields(value, 'sha256 files bytes', reason + '_fields')
    _sha(value['sha256'], reason + '_sha256')
    _integer(value['files'], reason + '_files', 1, 1024)
    _integer(value['bytes'], reason + '_bytes', 1, MAX_SOURCE_BYTES)


def _tool(value, reason):
    _fields(value, 'path sha256 bytes version_verbose', reason + '_fields')
    _path(value['path'], reason + '_path')
    _sha(value['sha256'], reason + '_sha256')
    _integer(value['bytes'], reason + '_bytes', 1)
    _text(value['version_verbose'], reason + '_version')


def _rust_version(value, name):
    lines = value.splitlines()
    _need(lines and lines[0].startswith(name + ' 1.97.1 '), name + '_version')
    for field, expected in (('release', '1.97.1'), ('host', TARGET)):
        matches = [line for line in lines if line.startswith(field + ': ')]
        _need(matches == [field + ': ' + expected], name + '_' + field)
    revisions = [line[len('commit-hash: '):] for line in lines if line.startswith('commit-hash: ')]
    _need(len(revisions) == 1 and GIT_HASH.fullmatch(revisions[0]) is not None,
          name + '_commit_hash')


def _result(value, reason):
    _fields(value, 'termination exit_code stdout stderr', reason + '_fields')
    _need(value['termination'] == 'Exited', reason + '_termination')
    _integer(value['exit_code'], reason + '_exit_code', 0, 0)
    for stream in ('stdout', 'stderr'):
        log = value[stream]
        _fields(log, 'sha256 bytes complete', reason + '_' + stream + '_fields')
        _sha(log['sha256'], reason + '_' + stream + '_sha256')
        _integer(log['bytes'], reason + '_' + stream + '_bytes')
        _need(log['complete'] is True, reason + '_' + stream + '_incomplete')


def _source(record, contract, verified_source_summary):
    provenance = contract['provenance']
    source_files = provenance['source_files']
    _need(type(source_files) is dict, 'external_source_map')
    _summary(verified_source_summary, 'verified_source')
    _need(verified_source_summary['sha256'] == provenance['source_sha256'] ==
          _hash(_canonical(source_files)) and
          verified_source_summary['files'] == len(source_files), 'verified_source_binding')
    source = record['source']
    _fields(source, 'commit tree patch_sha256 manifest_sha256 file_count bytes cargo_lock_sha256 '
            'toolchain_file_sha256 before_build after_preparation', 'source_fields')
    for field in ('commit', 'tree'):
        _need(type(source[field]) is str and GIT_HASH.fullmatch(source[field]) is not None,
              'source_' + field)
    if source['patch_sha256'] is not None:
        _sha(source['patch_sha256'], 'source_patch_sha256')
    _sha(source['manifest_sha256'], 'source_manifest_sha256')
    _integer(source['file_count'], 'source_file_count', 1, 1024)
    _integer(source['bytes'], 'source_bytes', 1, MAX_SOURCE_BYTES)
    _need({'sha256': source['manifest_sha256'], 'files': source['file_count'],
           'bytes': source['bytes']} == verified_source_summary, 'source_summary_binding')
    for field, path in (('cargo_lock_sha256', 'Cargo.lock'),
                        ('toolchain_file_sha256', 'rust-toolchain.toml')):
        _sha(source[field], 'source_' + field)
        _need(source[field] == source_files.get(path), 'source_' + field + '_binding')
    _need(source['cargo_lock_sha256'] == provenance['cargo_lock_sha256'], 'external_lock_binding')
    _need(source['before_build'] == source['after_preparation'] == INVENTORY_OBSERVATION,
          'source_preparation_membership')


def _build(record, contract):
    _fields(record['tools'], 'cargo rustc', 'tools_fields')
    for name in ('cargo', 'rustc'):
        _tool(record['tools'][name], name)
        _rust_version(record['tools'][name]['version_verbose'], name)
    cargo, rustc = record['tools']['cargo'], record['tools']['rustc']
    _need(rustc['sha256'] == contract['provenance']['compiler_sha256'], 'compiler_binding')
    _need(rustc['version_verbose'].splitlines()[0] == contract['provenance']['toolchain'],
          'toolchain_binding')
    build = record['build']
    _fields(build, 'cwd argv environment target profile package bin features target_dir cache_policy '
            'selected_artifact result', 'build_fields')
    _path(build['cwd'], 'build_cwd')
    _need(build['cwd'] == contract['root'], 'build_root_binding')
    _need(type(build['argv']) is list and build['argv'] == [cargo['path'], *BUILD_ARGUMENTS],
          'build_argv')
    _need(build['target'] == TARGET and build['profile'] == 'test' and
          build['package'] == build['bin'] == 'rust-xmpp-server' and
          type(build['features']) is list and build['features'] == [], 'build_selection')
    _path(build['target_dir'], 'build_target_dir')
    _need(build['cache_policy'] in ('reuse-allowed', 'fresh-target-dir'), 'build_cache_policy')
    environment = build['environment']
    _fields(environment, 'explicit_inputs inherited_environment', 'build_environment_fields')
    _need(environment['inherited_environment'] == 'unrecorded', 'build_environment_scope')
    inputs = environment['explicit_inputs']
    required = set(BUILD_CONTROLS) | {'PATH', 'CARGO_HOME', 'RUSTUP_HOME', 'RUSTC'}
    _need(type(inputs) is dict and required.issubset(inputs), 'build_environment_inputs')
    for key, value in inputs.items():
        _need(type(key) is str and re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', key) is not None and
              type(value) is str and '\x00' not in value and
              not any(0xd800 <= ord(char) <= 0xdfff for char in value), 'build_environment_value')
    for key, expected in BUILD_CONTROLS.items():
        _need(inputs[key] == expected, 'build_environment_control:' + key)
    for key in ('CARGO_HOME', 'RUSTUP_HOME', 'RUSTC'):
        _path(inputs[key], 'build_environment_path:' + key)
    _text(inputs['PATH'], 'build_environment_path')
    _need(inputs['RUSTC'] == rustc['path'], 'build_environment_compiler')
    _need(build['target_dir'] == inputs.get('CARGO_TARGET_DIR', contract['root'] + '/target'),
          'build_environment_target_dir')
    selected = build['selected_artifact']
    _fields(selected, 'executable sha256 bytes test fresh matching_artifacts', 'selected_artifact_fields')
    _path(selected['executable'], 'selected_executable')
    _sha(selected['sha256'], 'selected_sha256')
    _integer(selected['bytes'], 'selected_bytes', 1)
    # Retained result of actual preparation-time Cargo JSON selection. This
    # pure reader cannot recreate that selection without reading its log.
    _integer(selected['matching_artifacts'], 'selected_unique_artifact', 1, 1)
    _need(selected['test'] is True and type(selected['fresh']) is bool, 'selected_test_artifact')
    _need(PurePosixPath(build['target_dir']) in PurePosixPath(selected['executable']).parents,
          'selected_target_directory')
    _need((selected['sha256'], selected['bytes']) ==
          (record['original']['sha256'], record['original']['bytes']), 'selected_original_binding')
    _result(build['result'], 'build_result')


def _derivation(record, contract):
    original, runnable = record['original'], record['runnable']
    _file(original, 'original')
    _file(runnable, 'runnable')
    _need(runnable['path'] == contract['binary'] and
          runnable['sha256'] == contract['provenance']['binary_sha256'], 'runnable_contract_binding')
    _need(runnable['bytes'] <= MAX_BINARY_BYTES, 'runnable_byte_cap')
    _need(runnable['mode'] == 0o755, 'runnable_mode')
    derivation = record['derivation']
    if derivation is None:
        # A preserved copy can have another path/mode; content must be identical.
        _need((original['sha256'], original['bytes']) == (runnable['sha256'], runnable['bytes']),
              'underived_content_binding')
        return
    _fields(derivation, 'kind tool cwd argv environment result input_unchanged tool_unchanged '
            'output_absent_before', 'derivation_fields')
    _need(derivation['kind'] == 'gnu-strip-all-no-merge-notes-v1', 'derivation_kind')
    _tool(derivation['tool'], 'strip')
    _need(derivation['tool']['version_verbose'].splitlines()[0].startswith('GNU strip '),
          'strip_version')
    _path(derivation['cwd'], 'derivation_cwd')
    _need(derivation['cwd'] == contract['root'], 'derivation_root_binding')
    _need(original['path'] != runnable['path'], 'derivation_distinct_output')
    _need(type(derivation['argv']) is list and derivation['argv'] == [
        derivation['tool']['path'], '--strip-all', '--no-merge-notes',
        '-o', runnable['path'], original['path']], 'derivation_argv')
    _need(type(derivation['environment']) is dict and derivation['environment'] ==
          {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}, 'derivation_environment')
    _need(all(derivation[key] is True for key in
              ('input_unchanged', 'tool_unchanged', 'output_absent_before')), 'derivation_observations')
    _result(derivation['result'], 'derivation_result')


def _ancestry(record, contract, current_mutation_bytes):
    ancestry = record['ancestry']
    if record['artifact_role'] == 'baseline':
        _need(ancestry is None, 'baseline_has_ancestry')
        return
    _fields(ancestry, 'baseline_build_record_file_sha256 baseline_source_sha256 baseline_source_bytes '
            'baseline_original_sha256 baseline_runnable_sha256 path offset before_sha256 after_sha256 '
            'removed inserted', 'ancestry_fields')
    for key in ('baseline_build_record_file_sha256', 'baseline_source_sha256',
                'baseline_original_sha256', 'baseline_runnable_sha256', 'before_sha256', 'after_sha256'):
        _sha(ancestry[key], 'ancestry_' + key)
    _integer(ancestry['baseline_source_bytes'], 'baseline_source_bytes', 1, MAX_SOURCE_BYTES)
    _integer(ancestry['offset'], 'mutation_offset', 0, MAX_SOURCE_BYTES)
    _need(ancestry['path'] == MUTATION_PATH and
          ancestry['removed'] == BASELINE_LINE.decode() and ancestry['inserted'] == MUTANT_LINE.decode(),
          'exact_flush_replacement')
    _need(type(current_mutation_bytes) is bytes and
          0 < len(current_mutation_bytes) <= record['source']['bytes'], 'current_mutation_bytes')
    _need(_hash(current_mutation_bytes) == ancestry['after_sha256'] ==
          contract['provenance']['source_files'].get(MUTATION_PATH), 'current_mutation_binding')
    offset = ancestry['offset']
    _need((offset == 0 or current_mutation_bytes[offset - 1:offset] == b'\n') and
          current_mutation_bytes[offset:offset + len(MUTANT_LINE)] == MUTANT_LINE and
          current_mutation_bytes.count(MUTANT_LINE) == 1 and BASELINE_LINE not in current_mutation_bytes,
          'mutation_exact_line_offset')
    baseline_bytes = (current_mutation_bytes[:offset] + BASELINE_LINE +
                      current_mutation_bytes[offset + len(MUTANT_LINE):])
    _need(_hash(baseline_bytes) == ancestry['before_sha256'], 'mutation_reverse_source')
    baseline_map = dict(contract['provenance']['source_files'])
    baseline_map[MUTATION_PATH] = ancestry['before_sha256']
    _need(_hash(_canonical(baseline_map)) == ancestry['baseline_source_sha256'],
          'mutation_baseline_manifest')
    _need(ancestry['baseline_source_bytes'] == record['source']['bytes'] -
          len(MUTANT_LINE) + len(BASELINE_LINE), 'mutation_baseline_bytes')
    patch = {key: ancestry[key] for key in
             ('path', 'offset', 'before_sha256', 'after_sha256', 'removed', 'inserted')}
    _need(_hash(_canonical(patch)) == record['source']['patch_sha256'], 'mutation_patch_binding')
    _need(ancestry['baseline_build_record_file_sha256'] !=
          contract['provenance']['build_record_file_sha256'] and
          ancestry['baseline_source_sha256'] != record['source']['manifest_sha256'] and
          ancestry['baseline_original_sha256'] != record['original']['sha256'] and
          ancestry['baseline_runnable_sha256'] != record['runnable']['sha256'], 'mutation_distinct_ancestry')


def validate_build_record(raw_bytes, contract, *, verified_source_summary, current_mutation_bytes=None):
    """Authenticate preparation metadata before the caller opens the runnable.

    ``contract`` is the externally trusted, already validated v3 contract, never
    one supplied by a saved corpus. ``verified_source_summary`` is the exact
    {sha256, files, bytes} current summary obtained from actual bounded source
    hashing and fixed inventory/absence checks; it is not copied from this
    record. ``current_mutation_bytes`` is the bounded current src/xmpp/mod.rs
    content for no-flush, already read by that same source verifier.

    Return a detached validated dict, including the expected runnable tuple.
    Only then may the existing caller verify the actual executable descriptor
    and pass its facts to validate_runnable. Neither function opens files,
    validates historical log contents, executes argv, or qualifies a saved run.
    Baseline ancestry references gain authority transitively from the external
    hash of these exact bytes, not from internal self-consistency alone.
    """
    _need(type(contract) is dict and contract.get('schema') ==
          'northstar-controlled-execution-contract-v3', 'build_record_contract_version')
    provenance = contract['provenance']
    record = _decode(raw_bytes, provenance['build_record_file_sha256'])
    _fields(record, 'schema scope artifact_role source tools build original runnable derivation ancestry',
            'build_record_fields')
    _need(record['schema'] == SCHEMA, 'build_record_schema')
    _fields(record['scope'], 'project_local_complete external_supply_chain_complete reproducible_build_claimed',
            'build_record_scope_fields')
    _need(record['scope']['project_local_complete'] is True and
          record['scope']['external_supply_chain_complete'] is False and
          record['scope']['reproducible_build_claimed'] is False, 'build_record_scope')
    roles = {'stage3-direct-fixed16-v1': 'baseline', 'stage3-direct-no-flush-fixed4-v1': 'no-flush'}
    _need(contract.get('profile') in roles and record['artifact_role'] ==
          provenance['artifact_role'] == roles[contract['profile']], 'build_record_artifact_role')
    _source(record, contract, verified_source_summary)
    _derivation(record, contract)
    _build(record, contract)
    _ancestry(record, contract, current_mutation_bytes)
    return copy.deepcopy(record)


def validate_runnable(record, verified_runnable):
    """Compare a validated record with actual descriptor-derived file facts.

    ``verified_runnable`` has {path, sha256, bytes, mode}, from the existing
    regular/no-follow, unchanged-identity, no-capability binary verifier. Never
    construct it by copying record fields. This helper performs no I/O and does
    not replace that verifier or its descriptor lifetime/recheck obligations.
    """
    _file(verified_runnable, 'verified_runnable')
    _need(verified_runnable == record['runnable'], 'verified_runnable_binding')
