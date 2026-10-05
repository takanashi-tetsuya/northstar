#!/usr/bin/env python3
"""Finite in-process build-record regressions using synthetic preparation data.

No build, strip, binary, saved profile, service or project source is executed.
These tests establish reader rejection behavior, not artifact qualification.
"""
import copy
import hashlib
import json
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
from lib import direct_build_record as records


def fingerprint(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def encoded(value):
    return canonical(value) + b'\n'


def file_identity(path, data=b'synthetic file', mode=0o755):
    return {'path': path, 'sha256': fingerprint(data), 'bytes': len(data), 'mode': mode}


def result():
    log = {'sha256': fingerprint(b''), 'bytes': 0, 'complete': True}
    return {'termination': 'Exited', 'exit_code': 0, 'stdout': dict(log), 'stderr': dict(log)}


def tool(name):
    revision = ('a' if name == 'rustc' else 'b') * 40
    return {
        'path': '/tools/' + name, 'sha256': fingerprint(name.encode()), 'bytes': 400,
        'version_verbose': name + ' 1.97.1 (' + revision[:9] + ' 2026-09-01)\n' +
                           'commit-hash: ' + revision + '\nhost: x86_64-unknown-linux-gnu\n' +
                           'release: 1.97.1\n',
    }


def fixture(*, derived=False, mutant=False):
    """Return synthetic trusted facts; never inspect a checkout or artifact."""
    root = '/synthetic/root'
    baseline = b'async fn send() {\n' + records.BASELINE_LINE + b'}\n'
    current = baseline.replace(records.BASELINE_LINE, records.MUTANT_LINE) if mutant else baseline
    contents = {'Cargo.lock': b'lock', 'rust-toolchain.toml': b'toolchain',
                'scripts/lib/oracle.py': b'fixed oracle', records.MUTATION_PATH: current}
    source_files = {name: fingerprint(data) for name, data in contents.items()}
    summary = {'sha256': fingerprint(canonical(source_files)), 'files': len(source_files),
               'bytes': sum(map(len, contents.values()))}
    original = file_identity('/saved/original', b'mutant original' if mutant else b'baseline original', 0o644)
    runnable = dict(original, path='/saved/runnable', mode=0o755)
    if derived:
        original['bytes'] = records.MAX_BINARY_BYTES + 1000
        runnable = file_identity('/saved/runnable', b'mutant stripped' if mutant else b'baseline stripped')
    tools = {'cargo': tool('cargo'), 'rustc': tool('rustc')}
    controls = dict(records.BUILD_CONTROLS, PATH='/tools:/usr/bin:/bin', CARGO_HOME='/cargo',
                    RUSTUP_HOME='/rustup', RUSTC=tools['rustc']['path'])
    value = {
        'schema': records.SCHEMA,
        'scope': {'project_local_complete': True, 'external_supply_chain_complete': False,
                  'reproducible_build_claimed': False},
        'artifact_role': 'no-flush' if mutant else 'baseline',
        'source': {
            'commit': 'c' * 40, 'tree': 'd' * 40, 'patch_sha256': None,
            'manifest_sha256': summary['sha256'], 'file_count': summary['files'], 'bytes': summary['bytes'],
            'cargo_lock_sha256': source_files['Cargo.lock'],
            'toolchain_file_sha256': source_files['rust-toolchain.toml'],
            'before_build': records.INVENTORY_OBSERVATION, 'after_preparation': records.INVENTORY_OBSERVATION,
        },
        'tools': tools,
        'build': {
            'cwd': root, 'argv': [tools['cargo']['path'], *records.BUILD_ARGUMENTS],
            'environment': {'explicit_inputs': controls, 'inherited_environment': 'unrecorded'},
            'target': records.TARGET, 'profile': 'test', 'package': 'rust-xmpp-server',
            'bin': 'rust-xmpp-server', 'features': [], 'target_dir': root + '/target',
            'cache_policy': 'reuse-allowed',
            'selected_artifact': {
                'executable': root + '/target/debug/deps/rust_xmpp_server-abcdef',
                'sha256': original['sha256'], 'bytes': original['bytes'],
                'test': True, 'fresh': False, 'matching_artifacts': 1,
            },
            'result': result(),
        },
        'original': original, 'runnable': runnable, 'derivation': None, 'ancestry': None,
    }
    if derived:
        value['derivation'] = {
            'kind': 'gnu-strip-all-no-merge-notes-v1',
            'tool': {'path': '/usr/bin/strip', 'sha256': fingerprint(b'strip'), 'bytes': 400,
                     'version_verbose': 'GNU strip (GNU Binutils for Debian) 2.44\n'},
            'cwd': root,
            'argv': ['/usr/bin/strip', '--strip-all', '--no-merge-notes',
                     '--output=' + runnable['path'], original['path']],
            'environment': {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'},
            'result': result(), 'input_unchanged': True, 'tool_unchanged': True, 'output_absent_before': True,
        }
    if mutant:
        baseline_map = dict(source_files, **{records.MUTATION_PATH: fingerprint(baseline)})
        value['ancestry'] = {
            'baseline_build_record_file_sha256': fingerprint(b'reviewed baseline record bytes'),
            'baseline_source_sha256': fingerprint(canonical(baseline_map)),
            'baseline_source_bytes': summary['bytes'] - len(records.MUTANT_LINE) + len(records.BASELINE_LINE),
            'baseline_original_sha256': fingerprint(b'baseline original'),
            'baseline_runnable_sha256': fingerprint(b'baseline stripped' if derived else b'baseline original'),
            'path': records.MUTATION_PATH, 'offset': len(b'async fn send() {\n'),
            'before_sha256': fingerprint(baseline), 'after_sha256': fingerprint(current),
            'removed': records.BASELINE_LINE.decode(), 'inserted': records.MUTANT_LINE.decode(),
        }
        patch_value = {key: value['ancestry'][key] for key in
                       ('path', 'offset', 'before_sha256', 'after_sha256', 'removed', 'inserted')}
        value['source']['patch_sha256'] = fingerprint(canonical(patch_value))
    contract = {
        'schema': 'northstar-controlled-execution-contract-v3',
        'profile': 'stage3-direct-no-flush-fixed4-v1' if mutant else 'stage3-direct-fixed16-v1',
        'mode': 'record', 'root': root, 'binary': runnable['path'], 'build_record': '/saved/build-record.json',
        'provenance': {
            'artifact_role': value['artifact_role'], 'source_files': source_files,
            'source_sha256': summary['sha256'], 'binary_sha256': runnable['sha256'],
            'compiler_sha256': tools['rustc']['sha256'], 'cargo_lock_sha256': source_files['Cargo.lock'],
            'toolchain': tools['rustc']['version_verbose'].splitlines()[0],
            'build_record_file_sha256': fingerprint(encoded(value)),
        },
    }
    return value, contract, summary, current


class BuildRecordTests(unittest.TestCase):
    def validate(self, value, contract, summary, current, *, refresh_authority=True):
        raw = encoded(value)
        authority = copy.deepcopy(contract)
        if refresh_authority:
            authority['provenance']['build_record_file_sha256'] = fingerprint(raw)
        return records.validate_build_record(raw, authority, verified_source_summary=summary,
                                             current_mutation_bytes=current)

    def invalid(self, value, contract, summary, current, reason=None):
        with self.assertRaisesRegex(records.BuildRecordError, reason or '.'):
            self.validate(value, contract, summary, current)

    def test_underived_preserved_copy_can_differ_in_path_and_mode(self):
        value, contract, summary, current = fixture()
        validated = self.validate(value, contract, summary, current)
        records.validate_runnable(validated, copy.deepcopy(value['runnable']))
        self.assertNotEqual(value['original']['path'], value['runnable']['path'])
        self.assertNotEqual(value['original']['mode'], value['runnable']['mode'])

    def test_derived_baseline_allows_oversized_original_metadata(self):
        value, contract, summary, current = fixture(derived=True)
        self.assertGreater(value['original']['bytes'], records.MAX_BINARY_BYTES)
        self.assertEqual(self.validate(value, contract, summary, current), value)

    def test_no_flush_derivation_reverses_exact_single_line(self):
        value, contract, summary, current = fixture(derived=True, mutant=True)
        self.assertEqual(self.validate(value, contract, summary, current), value)

    def test_record_and_replay_use_identical_material_authority(self):
        value, contract, summary, current = fixture(derived=True)
        baseline = self.validate(value, contract, summary, current)
        contract['mode'] = 'replay'
        self.assertEqual(self.validate(value, contract, summary, current), baseline)

    def test_hash_mismatch_precedes_utf8_and_json_parser(self):
        _, contract, summary, current = fixture()
        with patch.object(records.json, 'loads', side_effect=AssertionError('parser reached')) as parse:
            with self.assertRaisesRegex(records.BuildRecordError, 'build_record_file_sha256'):
                records.validate_build_record(b'\xff not json', contract, verified_source_summary=summary,
                                               current_mutation_bytes=current)
        parse.assert_not_called()

    def test_self_rehashed_candidate_does_not_replace_external_authority(self):
        value, contract, summary, current = fixture(derived=True)
        value['tools']['cargo']['sha256'] = 'f' * 64
        with self.assertRaisesRegex(records.BuildRecordError, 'build_record_file_sha256'):
            self.validate(value, contract, summary, current, refresh_authority=False)

    def test_strict_raw_json_encodings_and_canonical_lf(self):
        value, contract, summary, _ = fixture()
        valid = encoded(value)
        candidates = [b'{"x":1,"x":2}\n', b'{"x":NaN}\n', b'{"x":Infinity}\n',
                      b'{"x":1e999}\n', b'\xff', b'\xef\xbb\xbf' + valid,
                      valid.decode().encode('utf-16'), valid[:-1], valid + b'\n',
                      valid[:-1] + b'\r\n', b' ' + valid]
        for raw in candidates:
            with self.subTest(raw=raw[:35]):
                contract['provenance']['build_record_file_sha256'] = fingerprint(raw)
                with self.assertRaises(records.BuildRecordError):
                    records.validate_build_record(raw, contract, verified_source_summary=summary)

    def test_existing_metadata_bound_applies_before_parser(self):
        _, contract, summary, _ = fixture()
        raw = b' ' * (records.MAX_METADATA_BYTES + 1)
        contract['provenance']['build_record_file_sha256'] = fingerprint(raw)
        with patch.object(records.json, 'loads', side_effect=AssertionError('parser reached')):
            with self.assertRaisesRegex(records.BuildRecordError, 'build_record_byte_budget'):
                records.validate_build_record(raw, contract, verified_source_summary=summary)

    def test_closed_shapes_reject_missing_and_unknown_fields(self):
        original, contract, summary, current = fixture(derived=True, mutant=True)
        paths = [(), ('scope',), ('source',), ('tools',), ('tools', 'rustc'), ('build',),
                 ('build', 'environment'), ('build', 'selected_artifact'), ('build', 'result'),
                 ('build', 'result', 'stdout'), ('original',), ('runnable',), ('derivation',),
                 ('derivation', 'tool'), ('ancestry',)]
        for path in paths:
            for operation in ('missing', 'unknown'):
                with self.subTest(path=path, operation=operation):
                    value = copy.deepcopy(original)
                    node = value
                    for key in path:
                        node = node[key]
                    if operation == 'missing':
                        node.pop(next(iter(node)))
                    else:
                        node['unreviewed'] = True
                    self.invalid(value, contract, summary, current)

    def test_booleans_do_not_satisfy_integer_or_scope_fields(self):
        original, contract, summary, current = fixture(derived=True)
        cases = [(('source', 'file_count'), True), (('original', 'bytes'), True),
                 (('runnable', 'mode'), True), (('build', 'result', 'exit_code'), False),
                 (('build', 'selected_artifact', 'matching_artifacts'), True),
                 (('scope', 'project_local_complete'), 1)]
        for path, replacement in cases:
            with self.subTest(path=path):
                value = copy.deepcopy(original)
                node = value
                for key in path[:-1]:
                    node = node[key]
                node[path[-1]] = replacement
                self.invalid(value, contract, summary, current)

    def test_hash_path_and_text_formats_are_strict(self):
        original, contract, summary, current = fixture(derived=True)
        for bad_path in ('relative', '/saved/../original', '/saved//original', '//saved/original',
                         '/saved/./original', '/saved/original\n', '/saved\\original'):
            with self.subTest(path=bad_path):
                value = copy.deepcopy(original)
                value['original']['path'] = bad_path
                self.invalid(value, contract, summary, current, 'original_path')
        value = copy.deepcopy(original)
        value['tools']['cargo']['sha256'] = 'F' * 64
        self.invalid(value, contract, summary, current, 'cargo_sha256')
        value = copy.deepcopy(original)
        value['tools']['cargo']['version_verbose'] = '\ud800'
        self.invalid(value, contract, summary, current, 'cargo_version')

    def test_source_summary_must_match_independently_verified_facts(self):
        original, contract, summary, current = fixture(derived=True)
        for key, replacement in (('manifest_sha256', 'f' * 64), ('file_count', summary['files'] + 1),
                                 ('bytes', summary['bytes'] + 1)):
            with self.subTest(field=key):
                value = copy.deepcopy(original)
                value['source'][key] = replacement
                self.invalid(value, contract, summary, current, 'source_summary_binding')
        bad_summary = dict(summary, bytes=summary['bytes'] + 1)
        self.invalid(original, contract, bad_summary, current, 'source_summary_binding')
        bad_summary = dict(summary, sha256='e' * 64)
        self.invalid(original, contract, bad_summary, current, 'verified_source_binding')

    def test_source_inventory_and_lock_toolchain_bindings(self):
        original, contract, summary, current = fixture()
        for key in ('cargo_lock_sha256', 'toolchain_file_sha256', 'before_build', 'after_preparation'):
            with self.subTest(field=key):
                value = copy.deepcopy(original)
                value['source'][key] = 'f' * 64
                self.invalid(value, contract, summary, current)
        contract['provenance']['cargo_lock_sha256'] = 'e' * 64
        self.invalid(original, contract, summary, current, 'external_lock_binding')

    def test_compiler_and_version_are_bound(self):
        original, contract, summary, current = fixture()
        for key, replacement in (('sha256', 'e' * 64),
                                 ('version_verbose', tool('rustc')['version_verbose'].replace('1.97.1', '1.98.0')),
                                 ('version_verbose', tool('rustc')['version_verbose'].replace(records.TARGET, 'other-host'))):
            with self.subTest(field=key, replacement=replacement):
                value = copy.deepcopy(original)
                value['tools']['rustc'][key] = replacement
                self.invalid(value, contract, summary, current)
        contract['provenance']['toolchain'] += ' altered'
        self.invalid(original, contract, summary, current, 'toolchain_binding')

    def test_exact_build_command_selection_and_root(self):
        original, contract, summary, current = fixture()
        for key, replacement in (('argv', original['build']['argv'] + ['--release']),
                                 ('cwd', '/other/root'), ('target', 'other-target'),
                                 ('profile', 'release'), ('features', ['extra']), ('bin', 'other-bin')):
            with self.subTest(field=key):
                value = copy.deepcopy(original)
                value['build'][key] = replacement
                self.invalid(value, contract, summary, current)

    def test_explicit_environment_is_recorded_without_sanitized_claim(self):
        original, contract, summary, current = fixture()
        for key in ('RUSTUP_HOME', 'RUSTC', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'SQLX_OFFLINE'):
            with self.subTest(missing=key):
                value = copy.deepcopy(original)
                del value['build']['environment']['explicit_inputs'][key]
                self.invalid(value, contract, summary, current, 'build_environment_inputs')
        for key, replacement in (('RUSTC', '/different/rustc'), ('RUSTFLAGS', '-C extra'),
                                 ('CARGO_BUILD_JOBS', '2'), ('RUSTUP_TOOLCHAIN', 'stable')):
            with self.subTest(field=key):
                value = copy.deepcopy(original)
                value['build']['environment']['explicit_inputs'][key] = replacement
                self.invalid(value, contract, summary, current)
        value = copy.deepcopy(original)
        value['build']['environment']['inherited_environment'] = 'fully-sanitized'
        self.invalid(value, contract, summary, current, 'build_environment_scope')

    def test_target_directory_and_actual_cargo_selection(self):
        original, contract, summary, current = fixture()
        for key, replacement in (('matching_artifacts', 2), ('test', False), ('fresh', 1),
                                 ('executable', '/unrelated/stale-file'), ('sha256', 'f' * 64),
                                 ('bytes', original['original']['bytes'] + 1)):
            with self.subTest(field=key):
                value = copy.deepcopy(original)
                value['build']['selected_artifact'][key] = replacement
                self.invalid(value, contract, summary, current)
        value = copy.deepcopy(original)
        value['build']['environment']['explicit_inputs']['CARGO_TARGET_DIR'] = '/other/target'
        self.invalid(value, contract, summary, current, 'build_environment_target_dir')

    def test_cache_policy_is_separate_from_cargo_fresh(self):
        value, contract, summary, current = fixture()
        for fresh in (False, True):
            value['build']['selected_artifact']['fresh'] = fresh
            self.assertEqual(self.validate(value, contract, summary, current)['build']['cache_policy'],
                             'reuse-allowed')
        value['build']['cache_policy'] = 'clean-everything'
        self.invalid(value, contract, summary, current, 'build_cache_policy')

    def test_build_and_strip_require_successful_complete_results(self):
        original, contract, summary, current = fixture(derived=True)
        for owner in ('build', 'derivation'):
            for field, replacement in (('termination', 'Signaled'), ('exit_code', 1)):
                with self.subTest(owner=owner, field=field):
                    value = copy.deepcopy(original)
                    value[owner]['result'][field] = replacement
                    self.invalid(value, contract, summary, current)
            value = copy.deepcopy(original)
            value[owner]['result']['stdout']['complete'] = False
            self.invalid(value, contract, summary, current)

    def test_runnable_external_identity_size_and_mode(self):
        original, contract, summary, current = fixture(derived=True)
        for key, replacement in (('path', '/different/runnable'), ('sha256', 'e' * 64),
                                 ('bytes', records.MAX_BINARY_BYTES + 1), ('mode', 0o644), ('mode', 0o4755)):
            with self.subTest(field=key):
                value = copy.deepcopy(original)
                value['runnable'][key] = replacement
                self.invalid(value, contract, summary, current)

    def test_null_derivation_requires_equal_hash_and_bytes(self):
        original, contract, summary, current = fixture()
        for field, replacement in (('sha256', 'f' * 64), ('bytes', original['original']['bytes'] + 1)):
            with self.subTest(field=field):
                value = copy.deepcopy(original)
                value['original'][field] = replacement
                self.invalid(value, contract, summary, current, 'underived_content_binding')

    def test_strip_command_tool_environment_and_fresh_output(self):
        original, contract, summary, current = fixture(derived=True)
        for field, replacement in (('argv', ['/usr/bin/strip', '--strip-debug']),
                                   ('cwd', '/other/root'), ('environment', {'LANG': 'C'}),
                                   ('kind', 'other-strip'), ('input_unchanged', False),
                                   ('tool_unchanged', False), ('output_absent_before', False)):
            with self.subTest(field=field):
                value = copy.deepcopy(original)
                value['derivation'][field] = replacement
                self.invalid(value, contract, summary, current)
        value = copy.deepcopy(original)
        value['derivation']['tool']['path'] = '/other/strip'
        self.invalid(value, contract, summary, current, 'derivation_argv')
        value = copy.deepcopy(original)
        value['original']['path'] = value['runnable']['path']
        self.invalid(value, contract, summary, current, 'derivation_distinct_output')

    def test_actual_runnable_metadata_is_a_separate_comparison(self):
        value, contract, summary, current = fixture(derived=True)
        validated = self.validate(value, contract, summary, current)
        for field, replacement in (('path', '/swapped/file'), ('sha256', 'f' * 64),
                                   ('bytes', value['runnable']['bytes'] + 1), ('mode', 0o644)):
            with self.subTest(field=field):
                actual = dict(value['runnable'], **{field: replacement})
                with self.assertRaisesRegex(records.BuildRecordError, 'verified_runnable_binding'):
                    records.validate_runnable(validated, actual)

    def test_ancestry_is_required_only_for_mutant_role(self):
        value, contract, summary, current = fixture(derived=True, mutant=True)
        value['ancestry'] = None
        self.invalid(value, contract, summary, current, 'ancestry_fields')
        value, contract, summary, current = fixture()
        value['ancestry'] = {}
        self.invalid(value, contract, summary, current, 'baseline_has_ancestry')
        value['ancestry'] = None
        contract['profile'] = 'stage3-direct-no-flush-fixed4-v1'
        self.invalid(value, contract, summary, current, 'build_record_artifact_role')

    def test_mutation_requires_actual_current_source_bytes(self):
        value, contract, summary, current = fixture(derived=True, mutant=True)
        for candidate in (None, b'', b'changed source', current + b'\n'):
            with self.subTest(candidate=candidate):
                self.invalid(value, contract, summary, candidate)
        value['ancestry']['after_sha256'] = 'e' * 64
        self.invalid(value, contract, summary, current, 'current_mutation_binding')

    def test_mutation_path_statement_offset_and_reverse_hash(self):
        original, contract, summary, current = fixture(derived=True, mutant=True)
        for field, replacement in (('path', 'src/other.rs'), ('offset', 0), ('offset', True),
                                   ('removed', 'io.flush().await\n'), ('inserted', 'Ok(())\n'),
                                   ('before_sha256', 'e' * 64)):
            with self.subTest(field=field):
                value = copy.deepcopy(original)
                value['ancestry'][field] = replacement
                self.invalid(value, contract, summary, current)

    def test_mutation_rejects_two_insertions_even_with_new_current_hash(self):
        value, contract, summary, current = fixture(derived=True, mutant=True)
        current += records.MUTANT_LINE
        contract['provenance']['source_files'][records.MUTATION_PATH] = fingerprint(current)
        summary = dict(summary, sha256=fingerprint(canonical(contract['provenance']['source_files'])),
                       bytes=summary['bytes'] + len(records.MUTANT_LINE))
        contract['provenance']['source_sha256'] = summary['sha256']
        value['source'].update(manifest_sha256=summary['sha256'], bytes=summary['bytes'])
        value['ancestry']['after_sha256'] = fingerprint(current)
        self.invalid(value, contract, summary, current, 'mutation_exact_line_offset')

    def test_mutation_baseline_manifest_bytes_and_patch_are_bound(self):
        original, contract, summary, current = fixture(derived=True, mutant=True)
        for field, replacement in (('baseline_source_sha256', 'e' * 64),
                                   ('baseline_source_bytes', original['ancestry']['baseline_source_bytes'] + 1)):
            with self.subTest(field=field):
                value = copy.deepcopy(original)
                value['ancestry'][field] = replacement
                self.invalid(value, contract, summary, current)
        value = copy.deepcopy(original)
        value['source']['patch_sha256'] = 'e' * 64
        self.invalid(value, contract, summary, current, 'mutation_patch_binding')

    def test_mutation_second_source_drift_cannot_match_baseline(self):
        value, contract, summary, current = fixture(derived=True, mutant=True)
        contract['provenance']['source_files']['scripts/lib/oracle.py'] = fingerprint(b'other oracle')
        summary = dict(summary, sha256=fingerprint(canonical(contract['provenance']['source_files'])))
        contract['provenance']['source_sha256'] = summary['sha256']
        value['source']['manifest_sha256'] = summary['sha256']
        self.invalid(value, contract, summary, current, 'mutation_baseline_manifest')

    def test_mutation_baseline_and_mutant_artifacts_must_be_distinct(self):
        original, contract, summary, current = fixture(derived=True, mutant=True)
        for field, replacement in (('baseline_original_sha256', original['original']['sha256']),
                                   ('baseline_runnable_sha256', original['runnable']['sha256'])):
            with self.subTest(field=field):
                value = copy.deepcopy(original)
                value['ancestry'][field] = replacement
                self.invalid(value, contract, summary, current, 'mutation_distinct_ancestry')

    def test_external_baseline_tuple_cannot_be_replaced_by_self_consistency(self):
        value, contract, summary, current = fixture(derived=True, mutant=True)
        value['ancestry']['baseline_build_record_file_sha256'] = fingerprint(b'attacker baseline')
        with self.assertRaisesRegex(records.BuildRecordError, 'build_record_file_sha256'):
            self.validate(value, contract, summary, current, refresh_authority=False)

    def test_scope_claims_and_v2_are_not_silently_widened(self):
        original, contract, summary, current = fixture()
        for field in ('external_supply_chain_complete', 'reproducible_build_claimed'):
            with self.subTest(field=field):
                value = copy.deepcopy(original)
                value['scope'][field] = True
                self.invalid(value, contract, summary, current, 'build_record_scope')
        contract['schema'] = 'northstar-controlled-execution-contract-v2'
        self.invalid(original, contract, summary, current, 'build_record_contract_version')

    def test_reader_never_opens_files_or_executes_recorded_commands(self):
        value, contract, summary, current = fixture(derived=True, mutant=True)
        with patch('builtins.open', side_effect=AssertionError('unexpected file read')), \
             patch('os.open', side_effect=AssertionError('unexpected descriptor open')), \
             patch('subprocess.run', side_effect=AssertionError('unexpected command execution')):
            validated = self.validate(value, contract, summary, current)
            records.validate_runnable(validated, dict(value['runnable']))
        validated['source']['bytes'] += 1
        self.assertEqual(value['source']['bytes'], summary['bytes'])


if __name__ == '__main__':
    unittest.main()
