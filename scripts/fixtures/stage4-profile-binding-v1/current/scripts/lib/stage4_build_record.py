"""Pure Stage4 build/ancestry binding using the proven preparation primitives.

Source only. No file access, compilation, command execution or artifact minted
here. External release hashes describe independently accepted packets; shape
validation is not a substitute for that external review. Stage3 is unchanged.
"""
import copy

from . import direct_build_record as base

SCHEMA = 'northstar-stage4-composition-build-record-v1'
INVENTORY_SCHEMA = 'northstar-stage4-inventoried-build-record-v1'
INVENTORY_TOOLCHAIN_TAG = 'rustup-toolchain:' + base.TOOLCHAIN
INVENTORY_ARGUMENTS = ('test', '--locked', '--offline', '-p', 'rust-xmpp-server',
                       '--bin', 'rust-xmpp-server', '--', '--list')
INVENTORY_ENTRY = 'stage4_replay::replay_saved_case'
# Reviewed same-key projection of current and actual cold before/after maps.
# This is not either whole source tree; workers independently measure it below.
COMPILATION_BASELINE_SHA256 = '23f4e5fb67e85a7154a2472799b671b691e0c3b604da3acda88f75143a2d0b98'
COMPILATION_FILES = 941
COMPILATION_BASELINE_BYTES = 18606272
PUBLIC_CORRESPONDENCE_SHA256 = '7a94f05d2af5e2193d4ca25ad2847ee466897961e7a1c9383058cc5c2ad3a12c'
MAX_EVIDENCE_BYTES = 32 * 1024 ** 2  # Existing evidence budget, not a new cap.
CONTRACT_SCHEMA = 'northstar-controlled-execution-contract-v5'
ROLES = {'stage4-composition-fixed16-v2': 'baseline',
         'stage4-composition-auth-cache-bypass-fixed3-v2': 'auth-cache-bypass-mutant'}
MUTATION_PATH = 'src/bosh/response_owner.rs'
# Preserve the pre-V2 freeze as history, not current whole-source authority.
# The already-validated v5 contract binds the current producer/reader closure
# through supervision's exact V2 source map and external current review packets.
# The owner bytes/whole-branch locator stayed unchanged. Actual preparation,
# baseline/mutant artifacts and ordinary acceptance still require new bindings.
HISTORICAL_SOURCE_FREEZE_SHA256 = '2a1c5a618d6dfd7ccbb101fdac074267f4e9243e8323026e704f94667e4c1269'
V2_CORRESPONDENCE_PLAN_SHA256 = '9fff729cb31f9779c37ba50e7e55736081e04d2f4e73e12b79675995b3a1d548'
BASELINE_SOURCE_SHA256 = '6c346f097c60ea3cc6e50a4e931becb1f03ea2b587d32894995da692bba6fccb'
BASELINE_BRANCH_OFFSET = 15315
BASELINE_BRANCH = b'''        if self.auth_control_selected {
            anyhow::ensure!(self.accepted, "BOSH authentication control was not exposed");
            let selected = std::mem::replace(&mut self.auth_controls, SelectedControls::empty());
            let observations = selected.observations();
            let owners = selected.take_all()?;
            anyhow::ensure!(
                publish(owners).await,
                "BOSH authentication publication failed"
            );
            anyhow::ensure!(
                observations
                    .iter()
                    .all(|observation| observation.completed()),
                "BOSH auth callback did not complete its selected owners"
            );
        }
'''
MUTANT_BRANCH = b'        // Stage4 test artifact: selected-owner publication branch bypassed.\n'
FUNCTION_PREFIX = b'''    pub(super) async fn publish_authentication<F: Future<Output = bool>>(
        mut self,
        publish: impl FnOnce(Vec<OwnedPublication>) -> F,
    ) -> Result<PublicationReadyResponse> {
'''
FUNCTION_SUFFIX = b'        Ok(PublicationReadyResponse { exposed: self })\n'


def _acceptance(record, contract):
    acceptance = record['acceptance']
    base._fields(acceptance, 'source_sha256 binary_sha256 ordinary_acceptance_sha256 '
                 'source_review_sha256 effect_review_sha256', 'stage4_acceptance_fields')
    base._need(acceptance['source_sha256'] == contract['provenance']['source_sha256'] and
               acceptance['binary_sha256'] == record['runnable']['sha256'], 'stage4_acceptance_binding')
    # Post-build profile/budget/allowed-start reviews are deliberately NOT in
    # this record: those later packets may bind this exact record hash.
    for field in ('ordinary_acceptance_sha256', 'source_review_sha256', 'effect_review_sha256'):
        base._sha(acceptance[field], 'stage4_external_review_hash')
        base._need(acceptance[field] == contract['release'][field], 'stage4_review_contract_binding')


def _ancestry(record, contract, current):
    base._need(type(current) is bytes and 0 < len(current) <= record['source']['bytes'],
               'stage4_current_owner_source_required')
    base._need(base._hash(current) == contract['provenance']['source_files'].get(MUTATION_PATH),
               'stage4_current_owner_source_binding')
    ancestry = record['ancestry']
    if record['artifact_role'] == 'baseline':
        base._need(ancestry is None and base._hash(current) == BASELINE_SOURCE_SHA256 and
            current.count(FUNCTION_PREFIX + BASELINE_BRANCH + FUNCTION_SUFFIX) == 1 and
            MUTANT_BRANCH not in current, 'stage4_baseline_exact_publication_owner')
        return
    base._fields(ancestry, 'baseline_build_record_file_sha256 baseline_source_sha256 baseline_source_bytes '
        'baseline_original_sha256 baseline_runnable_sha256 baseline_ordinary_acceptance_sha256 '
        'path offset before_sha256 after_sha256 removed inserted', 'stage4_ancestry_fields')
    for key in ('baseline_build_record_file_sha256', 'baseline_source_sha256',
                'baseline_original_sha256', 'baseline_runnable_sha256',
                'baseline_ordinary_acceptance_sha256', 'before_sha256', 'after_sha256'):
        base._sha(ancestry[key], 'stage4_ancestry_' + key)
    base._integer(ancestry['baseline_source_bytes'], 'stage4_baseline_source_bytes', 1, base.MAX_SOURCE_BYTES)
    offset = base._integer(ancestry['offset'], 'stage4_mutation_offset', 0, base.MAX_SOURCE_BYTES)
    base._need(offset == BASELINE_BRANCH_OFFSET and ancestry['path'] == MUTATION_PATH and
        ancestry['removed'] == BASELINE_BRANCH.decode() and ancestry['inserted'] == MUTANT_BRANCH.decode(),
        'stage4_exact_whole_selected_owner_branch')
    base._need(ancestry['before_sha256'] == BASELINE_SOURCE_SHA256 and
        ancestry['baseline_ordinary_acceptance_sha256'] == contract['release']['ordinary_acceptance_sha256'] and
        ancestry['after_sha256'] == base._hash(current) and
        current.count(FUNCTION_PREFIX + MUTANT_BRANCH + FUNCTION_SUFFIX) == 1 and
        current.count(MUTANT_BRANCH) == 1 and BASELINE_BRANCH not in current and
        current[offset:offset + len(MUTANT_BRANCH)] == MUTANT_BRANCH and
        current[max(0, offset - len(FUNCTION_PREFIX)):offset] == FUNCTION_PREFIX and
        current[offset + len(MUTANT_BRANCH):offset + len(MUTANT_BRANCH) + len(FUNCTION_SUFFIX)] == FUNCTION_SUFFIX,
        'stage4_exact_mutation_location')
    restored = current[:offset] + BASELINE_BRANCH + current[offset + len(MUTANT_BRANCH):]
    base._need(base._hash(restored) == BASELINE_SOURCE_SHA256,
               'stage4_reverse_exact_baseline_source')
    baseline_map = dict(contract['provenance']['source_files'])
    baseline_map[MUTATION_PATH] = BASELINE_SOURCE_SHA256
    base._need(base._hash(base._canonical(baseline_map)) == ancestry['baseline_source_sha256'] and
        ancestry['baseline_source_bytes'] == record['source']['bytes'] - len(MUTANT_BRANCH) + len(BASELINE_BRANCH),
        'stage4_sole_source_delta')
    patch = {key: ancestry[key] for key in ('path', 'offset', 'before_sha256', 'after_sha256', 'removed', 'inserted')}
    base._need(base._hash(base._canonical(patch)) == record['source']['patch_sha256'], 'stage4_patch_binding')
    base._need(ancestry['baseline_build_record_file_sha256'] != contract['provenance']['build_record_file_sha256'] and
        ancestry['baseline_source_sha256'] != record['source']['manifest_sha256'] and
        ancestry['baseline_original_sha256'] != record['original']['sha256'] and
        ancestry['baseline_runnable_sha256'] != record['runnable']['sha256'], 'stage4_distinct_artifacts')


def _reference(value, reason):
    """A bounded historical evidence reference; this pure reader never opens it.

    The trusted preparation reviewer authenticates these actual receipts before
    releasing the enclosing raw-record hash. A reference alone grants nothing.
    """
    base._fields(value, 'path sha256 bytes', reason + '_fields')
    base._path(value['path'], reason + '_path')
    base._sha(value['sha256'], reason + '_sha256')
    base._integer(value['bytes'], reason + '_bytes', 0, MAX_EVIDENCE_BYTES)


def _merged_result(value, reason):
    base._fields(value, 'termination exit_code merged collector_receipt owner_receipt postcheck',
                 reason + '_fields')
    base._need(value['termination'] == 'Exited', reason + '_termination')
    base._integer(value['exit_code'], reason + '_exit_code', 0, 0)
    merged = value['merged']
    base._fields(merged, 'sha256 bytes complete', reason + '_merged_fields')
    base._sha(merged['sha256'], reason + '_merged_sha256')
    base._integer(merged['bytes'], reason + '_merged_bytes', 0, MAX_EVIDENCE_BYTES)
    base._need(merged['complete'] is True, reason + '_merged_incomplete')
    for key in ('collector_receipt', 'owner_receipt', 'postcheck'):
        _reference(value[key], reason + '_' + key)


def _inventory_source(record, contract, summary, compilation_summary):
    provenance = contract['provenance']
    sources = provenance['source_files']
    base._summary(summary, 'verified_source')
    base._need(summary['sha256'] == provenance['source_sha256'] == base._hash(base._canonical(sources)) and
        summary['files'] == len(sources), 'verified_source_binding')
    source = record['source']
    base._fields(source, 'manifest_sha256 file_count bytes patch_sha256 cargo_lock_sha256 '
                 'toolchain_file_sha256 after_preparation', 'inventory_source_fields')
    base._summary({'sha256': source['manifest_sha256'], 'files': source['file_count'],
                   'bytes': source['bytes']}, 'inventory_source_record')
    base._need({'sha256': source['manifest_sha256'], 'files': source['file_count'],
                'bytes': source['bytes']} == summary, 'source_summary_binding')
    if source['patch_sha256'] is not None:
        base._sha(source['patch_sha256'], 'source_patch_sha256')
    for key, path in (('cargo_lock_sha256', 'Cargo.lock'),
                      ('toolchain_file_sha256', 'rust-toolchain.toml')):
        base._sha(source[key], 'source_' + key)
        base._need(source[key] == sources.get(path), 'source_' + key + '_binding')
    base._need(source['cargo_lock_sha256'] == provenance['cargo_lock_sha256'], 'external_lock_binding')
    base._need(source['after_preparation'] == base.INVENTORY_OBSERVATION, 'source_preparation_membership')

    # Exact closed helper membership is checked by the enclosing fixed profile.
    # A self-reported summary from the record never substitutes for same-read data.
    base._summary(compilation_summary, 'verified_compilation')
    projected = {key: value for key, value in sources.items() if key not in contract['helper_source_files']}
    base._need(compilation_summary['sha256'] == base._hash(base._canonical(projected)) and
        compilation_summary['files'] == len(projected) == COMPILATION_FILES,
        'inventory_compilation_projection')
    projected[MUTATION_PATH] = BASELINE_SOURCE_SHA256
    delta = len(MUTANT_BRANCH) - len(BASELINE_BRANCH) if record['artifact_role'] != 'baseline' else 0
    base._need(base._hash(base._canonical(projected)) == COMPILATION_BASELINE_SHA256 and
        compilation_summary['bytes'] == COMPILATION_BASELINE_BYTES + delta,
        'inventory_frozen_compilation_projection')
    compilation = record['compilation']
    base._fields(compilation, 'root source_sha256 file_count bytes before_snapshot after_snapshot '
        'build_postcheck runtime_tools toolchain_manifest helper_overlay_review_sha256 public_correspondence',
        'inventory_compilation_fields')
    base._path(compilation['root'], 'inventory_compilation_root')
    base._summary({'sha256': compilation['source_sha256'], 'files': compilation['file_count'],
                   'bytes': compilation['bytes']}, 'inventory_compilation_record')
    base._need({'sha256': compilation['source_sha256'], 'files': compilation['file_count'],
        'bytes': compilation['bytes']} == compilation_summary, 'inventory_compilation_summary_binding')
    for key in ('before_snapshot', 'after_snapshot', 'build_postcheck', 'runtime_tools', 'toolchain_manifest',
                'public_correspondence'):
        _reference(compilation[key], 'inventory_compilation_' + key)
    base._need(compilation['public_correspondence']['sha256'] == PUBLIC_CORRESPONDENCE_SHA256,
        'inventory_public_correspondence')
    base._sha(compilation['helper_overlay_review_sha256'], 'inventory_helper_overlay_review')
    base._need(compilation['helper_overlay_review_sha256'] == contract['release']['effect_review_sha256'],
        'inventory_helper_overlay_review_binding')


def _inventory_build(record, contract):
    tools = record['tools']
    base._fields(tools, 'cargo rustc rustup_toolchain', 'inventory_tools_fields')
    for key in ('cargo', 'rustc'):
        base._file(tools[key], 'inventory_' + key)
        base._need(tools[key]['mode'] == 0o755, 'inventory_tool_mode')
    cargo, rustc = tools['cargo'], tools['rustc']
    base._need(tools['rustup_toolchain'] == base.TOOLCHAIN and
        contract['provenance']['toolchain'] == INVENTORY_TOOLCHAIN_TAG, 'inventory_toolchain_binding')
    base._need(rustc['sha256'] == contract['provenance']['compiler_sha256'], 'compiler_binding')
    build = record['build']
    base._fields(build, 'cwd argv environment target profile package bin features target_dir cache_policy '
        'selected_artifact result', 'inventory_build_fields')
    base._path(build['cwd'], 'inventory_build_cwd')
    base._need(build['cwd'] == record['compilation']['root'], 'inventory_build_root_binding')
    base._need(type(build['argv']) is list and build['argv'] == ['cargo', *INVENTORY_ARGUMENTS],
        'inventory_build_argv')
    base._need(build['target'] == base.TARGET and build['profile'] == 'test' and
        build['package'] == build['bin'] == 'rust-xmpp-server' and build['features'] == [] and
        type(build['features']) is list, 'build_selection')
    base._path(build['target_dir'], 'build_target_dir')
    base._need(build['cache_policy'] == 'fresh-target-dir', 'inventory_build_cache_policy')
    environment = build['environment']
    base._fields(environment, 'driver_exports scrubbed_owner_environment_receipt driver_receipt '
        'rustc_override_absent', 'inventory_build_environment_fields')
    for key in ('scrubbed_owner_environment_receipt', 'driver_receipt'):
        _reference(environment[key], 'inventory_' + key)
    exports = environment['driver_exports']
    base._fields(exports, ' '.join(base.BUILD_CONTROLS) +
        ' PATH CARGO_HOME CARGO_TARGET_DIR RUSTUP_HOME PYTHONDONTWRITEBYTECODE PYTHONSAFEPATH PYTHONNOUSERSITE',
        'inventory_driver_exports')
    base._need(environment['rustc_override_absent'] is True, 'inventory_rustc_override')
    for key, expected in base.BUILD_CONTROLS.items():
        base._need(exports[key] == expected, 'build_environment_control:' + key)
    for key in ('PYTHONDONTWRITEBYTECODE', 'PYTHONSAFEPATH', 'PYTHONNOUSERSITE'):
        base._need(exports[key] == '1', 'inventory_python_environment:' + key)
    for key in ('CARGO_HOME', 'CARGO_TARGET_DIR', 'RUSTUP_HOME'):
        base._path(exports[key], 'build_environment_path:' + key)
    base._text(exports['PATH'], 'build_environment_path')
    entries = exports['PATH'].split(':')
    for entry in entries:
        base._path(entry, 'inventory_path_entry')
    tool_bin = exports['RUSTUP_HOME'] + '/toolchains/' + base.TOOLCHAIN + '/bin'
    base._need(entries[0] == tool_bin and cargo['path'] == tool_bin + '/cargo' and
        rustc['path'] == tool_bin + '/rustc', 'inventory_path_tool_binding')
    base._need(build['target_dir'] == exports['CARGO_TARGET_DIR'], 'build_environment_target_dir')
    selected = build['selected_artifact']
    base._fields(selected, 'executable sha256 bytes test_count benchmark_count saved_entry '
        'matching_artifacts inventory_receipt preservation_receipt', 'inventory_selected_fields')
    base._path(selected['executable'], 'selected_executable')
    base._sha(selected['sha256'], 'selected_sha256')
    base._integer(selected['bytes'], 'selected_bytes', 1)
    base._integer(selected['matching_artifacts'], 'selected_unique_artifact', 1, 1)
    base._integer(selected['test_count'], 'inventory_test_count', 1, 32768)
    base._integer(selected['benchmark_count'], 'inventory_benchmark_count', 0, 0)
    base._need(selected['saved_entry'] == INVENTORY_ENTRY, 'inventory_saved_entry')
    base._need(base.PurePosixPath(build['target_dir']) in base.PurePosixPath(selected['executable']).parents,
        'selected_target_directory')
    base._need((selected['sha256'], selected['bytes']) ==
        (record['original']['sha256'], record['original']['bytes']), 'selected_original_binding')
    for key in ('inventory_receipt', 'preservation_receipt'):
        _reference(selected[key], 'inventory_' + key)
    _merged_result(build['result'], 'inventory_build_result')
    base._need(build['result']['postcheck'] == record['compilation']['build_postcheck'],
        'inventory_build_postcheck_binding')


def _inventory_derivation(record, contract):
    original, runnable = record['original'], record['runnable']
    base._file(original, 'original')
    base._file(runnable, 'runnable')
    base._need(runnable['path'] == contract['binary'] and
        runnable['sha256'] == contract['provenance']['binary_sha256'], 'runnable_contract_binding')
    base._need(runnable['bytes'] <= base.MAX_BINARY_BYTES, 'runnable_byte_cap')
    base._need(runnable['mode'] == 0o755, 'runnable_mode')
    derivation = record['derivation']
    if derivation is None:
        base._need((original['sha256'], original['bytes']) == (runnable['sha256'], runnable['bytes']),
            'underived_content_binding')
        return
    base._fields(derivation, 'kind tool version_verbose tool_evidence cwd argv environment result '
        'input_unchanged tool_unchanged output_absent_before elf_comparison_receipt '
        'structural_equivalence_not_established runtime_behavior_not_tested', 'inventory_derivation_fields')
    base._need(derivation['kind'] == 'gnu-strip-all-no-merge-notes-merged-v1', 'inventory_derivation_kind')
    base._file(derivation['tool'], 'inventory_strip')
    base._text(derivation['version_verbose'], 'strip_version')
    base._need(derivation['tool']['mode'] == 0o755 and
        derivation['version_verbose'].splitlines()[0].startswith('GNU strip '), 'strip_version')
    for key in ('tool_evidence', 'elf_comparison_receipt'):
        _reference(derivation[key], 'inventory_derivation_' + key)
    base._path(derivation['cwd'], 'derivation_cwd')
    base._need(derivation['cwd'] == record['compilation']['root'], 'inventory_derivation_root_binding')
    base._need(original['path'] != runnable['path'], 'derivation_distinct_output')
    base._need(type(derivation['argv']) is list and derivation['argv'] == [
        derivation['tool']['path'], '--strip-all', '--no-merge-notes',
        '-o', runnable['path'], original['path']], 'derivation_argv')
    base._need(type(derivation['environment']) is dict and derivation['environment'] ==
        {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}, 'derivation_environment')
    base._need(all(derivation[key] is True for key in ('input_unchanged', 'tool_unchanged',
        'output_absent_before', 'structural_equivalence_not_established', 'runtime_behavior_not_tested')),
        'inventory_derivation_observations')
    _merged_result(derivation['result'], 'inventory_derivation_result')
    base._need(derivation['result']['postcheck'] == derivation['elf_comparison_receipt'],
        'inventory_derivation_postcheck_binding')


def validate_build_record(raw_bytes, contract, *, verified_source_summary, current_mutation_bytes=None,
                          verified_compilation_summary=None):
    """Pure check of externally pinned bytes plus independently observed source."""
    base._need(type(contract) is dict and contract.get('schema') == CONTRACT_SCHEMA and
               contract.get('profile') in ROLES, 'stage4_build_contract')
    record = base._decode(raw_bytes, contract['provenance']['build_record_file_sha256'])
    base._need(type(record) is dict and record.get('schema') in (SCHEMA, INVENTORY_SCHEMA),
               'stage4_build_record_schema')
    inventoried = record['schema'] == INVENTORY_SCHEMA
    base._need((contract['provenance']['toolchain'] == INVENTORY_TOOLCHAIN_TAG) == inventoried,
               'stage4_record_toolchain_mode')
    base._fields(record, 'schema scope artifact_role source tools build original runnable derivation ancestry acceptance' +
                 (' compilation' if inventoried else ''),
                 'stage4_build_record_fields')
    base._need(record['artifact_role'] == contract['provenance']['artifact_role'] == ROLES[contract['profile']],
        'stage4_artifact_role')
    base._fields(record['scope'], 'project_local_complete external_supply_chain_complete reproducible_build_claimed',
                 'stage4_build_scope_fields')
    base._need(record['scope'] == {'project_local_complete': True,
        'external_supply_chain_complete': False, 'reproducible_build_claimed': False} and
        all(type(value) is bool for value in record['scope'].values()), 'stage4_build_scope')
    if inventoried:
        _inventory_source(record, contract, verified_source_summary, verified_compilation_summary)
        _inventory_derivation(record, contract)
        _inventory_build(record, contract)
    else:
        base._source(record, contract, verified_source_summary)
        base._derivation(record, contract)
        base._build(record, contract)
    _acceptance(record, contract)
    _ancestry(record, contract, current_mutation_bytes)
    return copy.deepcopy(record)


def validate_runnable(record, verified_runnable):
    return base.validate_runnable(record, verified_runnable)


def validate_baseline_ancestry(baseline_contract, baseline_record, mutant_contract, mutant_record):
    """Both records already authenticated against their separate external contracts."""
    base._need(baseline_record.get('schema') == mutant_record.get('schema') and
        baseline_record.get('schema') in (SCHEMA, INVENTORY_SCHEMA), 'stage4_relation_record_variants')
    base._need(baseline_record['artifact_role'] == 'baseline' and
        mutant_record['artifact_role'] == 'auth-cache-bypass-mutant', 'stage4_relation_roles')
    ancestry = mutant_record['ancestry']
    expected = {
        'baseline_build_record_file_sha256': baseline_contract['provenance']['build_record_file_sha256'],
        'baseline_source_sha256': baseline_record['source']['manifest_sha256'],
        'baseline_source_bytes': baseline_record['source']['bytes'],
        'baseline_original_sha256': baseline_record['original']['sha256'],
        'baseline_runnable_sha256': baseline_record['runnable']['sha256'],
        'baseline_ordinary_acceptance_sha256': baseline_contract['release']['ordinary_acceptance_sha256']}
    base._need(all(ancestry[key] == value for key, value in expected.items()), 'stage4_relation_baseline_ancestry')
    actual_delta = {key for key in set(baseline_contract['provenance']['source_files']) |
                   set(mutant_contract['provenance']['source_files']) if
                   baseline_contract['provenance']['source_files'].get(key) !=
                   mutant_contract['provenance']['source_files'].get(key)}
    base._need(actual_delta == {MUTATION_PATH} and baseline_record['tools'] == mutant_record['tools'] and
               baseline_contract['helper_source_files'] == mutant_contract['helper_source_files'],
               'stage4_relation_source_toolchain_delta')
