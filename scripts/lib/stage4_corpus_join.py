"""Read-only Stage4 join over FOUR externally authenticated completed corpora.

No CLI, launcher, fork, exec, binary selection, writer or semantic-role token.
The trusted caller supplies the four original contracts and actual external
caller evidence, not fields promoted from saved JSON. Run only in a separately
released bounded review context. This module creates zero child-process starts.
Its authentication boundary is the existing supervisor's external-authority
boundary; these Python objects are not cryptographic capabilities.
"""
from pathlib import Path
import stat

from . import controlled_admission_supervision as s
from . import stage4_saved_case as adapter
from . import stage4_build_record as builds
from . import stage4_case as semantic


def _reference(directory, reference, cap):
    s.validate_reference(reference)
    s.need(reference['bytes'] <= cap, 'composition_relation_reference_budget')
    path = Path(directory) / reference['file']
    s.need(stat.S_ISREG(s._path_metadata(path).st_mode), 'composition_relation_regular_file')
    raw = s.read_regular_bounded(path, cap)
    s.need(len(raw) == reference['bytes'] and s.fingerprint(raw) == reference['sha256'],
           'composition_relation_reference_identity')
    return raw


def _json_reference(directory, reference, cap):
    raw = _reference(directory, reference, cap)
    value = s.strict_json(raw, cap)
    s.need(s.encoded(value) == raw, 'composition_relation_canonical_metadata')
    return value


def _authority_contract(authority, profile_id, mode):
    s.exact(authority, 'contract contract_file_sha256 capture caller_evidence',
            'composition_relation_external_authority')
    contract = s.validate_contract(authority['contract'])
    s.need(contract['profile'] == profile_id and contract['mode'] == mode,
           'composition_relation_profile_mode')
    return contract


def _authenticate_executing_helpers(contracts):
    """Pin the fixed loaded closure to the external BASELINE-record root once.

    Before-first-import verification remains the trusted invoker's obligation.
    This repeat hashes the full common helper map and pins every loaded project
    module in this API's closure. It neither trusts nor imports mutant-root code.
    """
    s.need(type(contracts) is tuple and len(contracts) == 4 and
        contracts[0]['profile'] == s.COMPOSITION_PROFILE and contracts[0]['mode'] == 'record',
        'composition_relation_executing_baseline_contract')
    baseline = contracts[0]
    helpers = baseline['helper_source_files']
    s.need(all(contract['helper_source_files'] == helpers for contract in contracts),
           'composition_relation_executing_helper_map')
    root = Path(baseline['root'])
    loaded = (
        (s.__file__, 'scripts/lib/controlled_admission_supervision.py'),
        (__file__, 'scripts/lib/stage4_corpus_join.py'),
        (adapter.__file__, 'scripts/lib/stage4_saved_case.py'),
        (builds.__file__, 'scripts/lib/stage4_build_record.py'),
        (builds.base.__file__, 'scripts/lib/direct_build_record.py'),
        (semantic.__file__, 'scripts/lib/stage4_case.py'),
        (semantic.stage4_compact.__file__, 'scripts/lib/stage4_compact.py'))
    for actual, relative in loaded:
        s.need(type(actual) is str and Path(actual) == root / relative,
               'composition_relation_loaded_helper_path:' + relative)
    s.check_direct_import_layout(root, s.COMPOSITION_PROFILE)
    used = 0
    for relative in sorted(helpers):
        path = root / relative
        s.need(stat.S_ISREG(s._path_metadata(path).st_mode), 'composition_relation_executing_helper_regular')
        raw = s.read_regular_bounded(path, baseline['budgets']['source_bytes'] - used)
        used += len(raw)
        s.need(s.fingerprint(raw) == helpers[relative], 'composition_relation_executing_helper_identity')
    s.check_direct_import_layout(root, s.COMPOSITION_PROFILE)


def _completed(authority, profile_id, mode):
    """Private: call only after the fixed executing helper closure is authenticated."""
    contract = _authority_contract(authority, profile_id, mode)
    profile = s.contract_profile(contract)
    directory = Path(contract['evidence_dir'])
    s.need(stat.S_ISDIR(s._path_metadata(directory).st_mode), 'composition_relation_directory')
    raw = s.read_regular_bounded(directory / 'contract.json', s.MAX_CONTRACT)
    s.valid_hash(authority['contract_file_sha256'])
    s.need(s.fingerprint(raw) == authority['contract_file_sha256'] and raw == s.encoded(contract),
           'composition_relation_external_contract_bytes')
    s.need(s.validate_owner_capture(authority['capture'], contract,
        caller_evidence=authority['caller_evidence'])['FixtureMatched'],
        'composition_relation_external_caller_incomplete')
    caller_path = s.caller_directory(directory) / 'caller-capture.json'
    s.need(stat.S_ISREG(s._path_metadata(caller_path).st_mode), 'composition_relation_capture_file')
    capture_bytes = s.read_regular_bounded(caller_path, s.MAX_CONTROL * 2)
    s.need(s.strict_json(capture_bytes, s.MAX_CONTROL * 2) == authority['capture'],
           'composition_relation_saved_caller_differs')
    verified_sources = s.check_retained_source_data(contract)
    build_record = s._current_build_record(adapter, contract, verified_sources)
    s.check_current_material(adapter, contract, verified_sources)
    receipt = authority['capture']['receipt']
    manifest = _json_reference(directory, receipt['terminal'], s.MAX_PREFIX)
    s.exact(manifest, 'schema contract_sha256 cases shrink first_invariant first_unexpected_stop complete',
            'composition_relation_corpus_fields')
    s.need(manifest['schema'] == profile['corpus_schema'] and
        manifest['contract_sha256'] == s.object_hash(contract) and manifest['complete'] is True and
        manifest['first_unexpected_stop'] is None and manifest['shrink'] is None and
        type(manifest['cases']) is list and len(manifest['cases']) == profile['counts']['total'],
        'composition_relation_corpus_complete')
    prefix = _json_reference(directory, receipt['prefix'], s.MAX_PREFIX)
    s.exact(prefix, 'schema run_id contract_sha256 cases first_invariant first_unexpected_stop',
            'composition_relation_prefix_fields')
    s.need(prefix == {'schema': s.PREFIX_SCHEMA, 'run_id': contract['run_id'],
        'contract_sha256': s.object_hash(contract), 'cases': manifest['cases'],
        'first_invariant': manifest['first_invariant'], 'first_unexpected_stop': None},
        'composition_relation_prefix_consistency')
    plan = adapter.fixture_plan(profile_id)
    s.validate_fixture_inventory(plan, contract)
    observations, tuples, first_invariant = {}, [], None
    for index, (fixture, entry) in enumerate(zip(plan, manifest['cases'])):
        s.exact(entry, 'index id kind observation result fixture_status', 'composition_relation_entry_fields')
        s.need(type(entry['index']) is int and entry['index'] == index and
            entry['id'] == fixture['id'] and entry['kind'] == fixture['kind'] and
            entry['fixture_status'] == 'FixtureMatched', 'composition_relation_entry_order')
        record = _json_reference(directory, entry['observation'], s.MAX_CASE_METADATA)
        s.validate_case_record(record, contract, index, fixture['id'], fixture['kind'])
        s.need(record['observation'] == 'Complete', 'composition_relation_incomplete_capture')
        raw_input = _reference(directory, record['input'], contract['budgets']['input_bytes'])
        s.need(raw_input == fixture['bytes'], 'composition_relation_literal_changed')
        stdout = _reference(directory, record['stdout']['reference'], contract['budgets']['stdout_bytes'])
        s.need(_reference(directory, record['stderr']['reference'], contract['budgets']['stderr_bytes']) == b'',
               'composition_relation_stderr')
        result = _json_reference(directory, entry['result'], s.MAX_CASE_METADATA)
        s.validate_result(result, entry['observation'], contract, fixture, index)
        s.need(result['fixture_status'] == 'FixtureMatched', 'composition_relation_unmatched_result')
        saved = _json_reference(directory, result['evaluation'], contract['budgets']['evaluation_bytes'])
        frame, evaluation, matched, stop = s.evaluate_fixture(adapter, fixture, record, stdout, profile_id)
        s.need(matched and stop is None and evaluation == saved, 'composition_relation_reevaluation')
        if evaluation['invariant'] is not None and first_invariant is None:
            first_invariant = {'index': index, 'evaluation': result['evaluation'],
                               'class': evaluation['invariant']['class']}
        # Numeric PIDs may legitimately be reused AFTER reap. Identity is the
        # actual external invocation plus owner-registered occurrence and its
        # authenticated immutable process/evidence record, not PID alone.
        actual_tuple = (authority['caller_evidence']['invocation_id'], s.object_hash(contract),
            mode, index, fixture['id'], record['process']['pid'], entry['observation']['sha256'],
            record['input']['sha256'], record['stdout']['reference']['sha256'])
        tuples.append(actual_tuple)
        observations[fixture['id']] = (raw_input, frame)
    s.need(first_invariant == manifest['first_invariant'], 'composition_relation_first_invariant')
    return {'contract': contract, 'build': build_record, 'observations': observations,
            'tuples': tuples, 'authority': authority, 'manifest': manifest}


def _replay_pair(record, replay):
    a, b = record['contract'], replay['contract']
    authority = b['replay_authority']
    s.need(authority['prior_contract_file_sha256'] == record['authority']['contract_file_sha256'] and
        authority['capture'] == record['authority']['capture'] and
        authority['caller_evidence'] == record['authority']['caller_evidence'] and
        b['replay_dir'] == a['evidence_dir'] and a['provenance'] == b['provenance'] and
        a['helper_source_files'] == b['helper_source_files'] and a['case_inventory'] == b['case_inventory'] and
        a['budgets'] == b['budgets'] and a['plan_counts'] == b['plan_counts'] and
        {key: value for key, value in a['release'].items() if key != 'allowed_starts_sha256'} ==
        {key: value for key, value in b['release'].items() if key != 'allowed_starts_sha256'},
        'composition_relation_exact_record_replay_authority')
    for occurrence, original in record['observations'].items():
        repeated = replay['observations'][occurrence]
        relation = semantic.compare_replay_semantics(*original, *repeated, wire_version='V2')
        s.need(relation.category == 'Equivalent' and not relation.findings,
               'composition_relation_complete_canonical_replay')


def _distinct_occurrences(corpora):
    """Internal guard; inputs must be outputs of _completed, never user DTOs."""
    s.need(len(corpora) == 4, 'composition_relation_four_corpora')
    for field in ('run_id', 'evidence_dir'):
        s.need(len({item['contract'][field] for item in corpora}) == 4,
               'composition_relation_distinct_' + field)
    s.need(len({item['authority']['caller_evidence']['invocation_id'] for item in corpora}) == 4,
           'composition_relation_distinct_external_invocations')
    tuples = [value for item in corpora for value in item['tuples']]
    s.need(len(tuples) == len(set(tuples)) == 38 and
        len({(value[0], value[3]) for value in tuples}) == 38 and
        len({value[6] for value in tuples}) == 38, 'composition_relation_reused_process_or_evidence_tuple')


def authenticate_four_role_relation(*, baseline_record, mutant_record, baseline_replay, mutant_replay):
    """Require all 38 separately authenticated saved starts; create none.

    Each argument is ORIGINAL trusted executor authority for that one actual
    invocation. A caller-supplied role string, ordinary measurement, handcrafted
    envelope, saved contract with no external authority, or missing corpus fails.
    """
    contracts = (
        _authority_contract(baseline_record, s.COMPOSITION_PROFILE, 'record'),
        _authority_contract(mutant_record, s.AUTH_CACHE_PROFILE, 'record'),
        _authority_contract(baseline_replay, s.COMPOSITION_PROFILE, 'replay'),
        _authority_contract(mutant_replay, s.AUTH_CACHE_PROFILE, 'replay'))
    _authenticate_executing_helpers(contracts)
    br = _completed(baseline_record, s.COMPOSITION_PROFILE, 'record')
    mr = _completed(mutant_record, s.AUTH_CACHE_PROFILE, 'record')
    bp = _completed(baseline_replay, s.COMPOSITION_PROFILE, 'replay')
    mp = _completed(mutant_replay, s.AUTH_CACHE_PROFILE, 'replay')
    corpora = (br, mr, bp, mp)
    _distinct_occurrences(corpora)
    _replay_pair(br, bp)
    _replay_pair(mr, mp)
    for baseline, mutant in ((br, mr), (bp, mp)):
        builds.validate_baseline_ancestry(baseline['contract'], baseline['build'],
                                         mutant['contract'], mutant['build'])
        roles = (mutant['observations']['M1'], mutant['observations']['M2'],
                 baseline['observations']['S13'], mutant['observations']['M3'])
        # No identity is obtained from these semantic argument positions.
        # The exact occurrences above were already authenticated independently.
        relation = semantic.shrink_semantics(*roles, wire_version='V2')
        s.need(relation.category == 'Related' and not relation.findings,
               'composition_authenticated_four_role_relation')
    return {'schema': 'northstar-stage4-composition-authenticated-shrink-v1',
            'status': 'Matched', 'saved_child_process_starts': 38,
            'ordinary_measurements_included': False,
            'contract_sha256': [s.object_hash(item['contract']) for item in corpora],
            'roles': ['M1', 'M2', 'S13', 'M3'],
            'claim': 'FiniteSourceBoundSavedCompositionOnly'}
