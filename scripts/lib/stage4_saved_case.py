"""Stage4 adapter for the EXISTING fixed supervisor. Source only, not executed.

The supervisor authenticates all current material, fd0, actual start/exit and
saved streams before calling this semantic routing layer. No verdict or role
argument in this module establishes that authority. No process is created here.
"""
import copy
from pathlib import Path

from . import controlled_admission_supervision as supervision
from . import stage4_build_record
from . import stage4_case as semantic


def validate_provenance(provenance):
    supervision.exact(provenance,
        'schema model adapter binding_version source_sha256 source_files binary_sha256 '
        'cargo_lock_sha256 toolchain compiler_sha256 artifact_role build_record_file_sha256',
        'composition_provenance_fields')
    supervision.need(provenance['schema'] == 'northstar-stage4-composition-controlled-provenance-v1' and
        provenance['model'] == 'stage4-composition-controlled-v1' and
        provenance['adapter'] == semantic.ADAPTER and
        provenance['binding_version'] == 'stage4-project-local-build-material-v1' and
        provenance['artifact_role'] in ('baseline', 'auth-cache-bypass-mutant'),
        'composition_provenance_version')
    for name in ('source_sha256', 'binary_sha256', 'cargo_lock_sha256',
                 'compiler_sha256', 'build_record_file_sha256'):
        supervision.valid_hash(provenance[name])
    sources = provenance['source_files']
    supervision.need(type(sources) is dict and 0 < len(sources) <= 1024,
                     'composition_source_count')
    for name, digest in sources.items():
        supervision.need(type(name) is str and name and
            all(part not in ('', '.', '..') for part in name.split('/')) and
            '\\' not in name and not any(ord(char) < 32 or ord(char) == 127 for char in name),
            'composition_source_path')
        supervision.valid_hash(digest)
    supervision.need(supervision.object_hash(sources) == provenance['source_sha256'] and
        sources.get('Cargo.lock') == provenance['cargo_lock_sha256'] and
        type(provenance['toolchain']) is str and
        (provenance['toolchain'].startswith('rustc 1.97.1 ') or
         provenance['toolchain'] == supervision.COMPOSITION_TOOLCHAIN_TAG),
        'composition_source_toolchain_binding')
    return copy.deepcopy(provenance)


def check_current_provenance(contract, *, record_bytes, verified_source_summary,
                             current_mutation_bytes=None, verified_compilation_summary=None):
    return stage4_build_record.validate_build_record(record_bytes, contract,
        verified_source_summary=verified_source_summary,
        current_mutation_bytes=current_mutation_bytes,
        verified_compilation_summary=verified_compilation_summary)


def validate_runnable(record, verified_runnable):
    return stage4_build_record.validate_runnable(record, verified_runnable)


def fixture_plan(profile_id):
    """Read only fixed source-bound literal leaves; no generator or supplied path."""
    profile = supervision.composition_profile(profile_id)
    baseline = profile_id == supervision.COMPOSITION_PROFILE
    root = Path(__file__).parent.parent.parent / 'src/stage4_replay/fixtures'
    plan = []
    for ordinal, occurrence in enumerate(profile['ids']):
        literal = occurrence if baseline else semantic.MUTANT_INPUTS[occurrence]
        size, digest, planned = semantic.FIXTURES[literal]
        raw = supervision.read_regular_bounded(root / (literal + '.json'), 65536)
        supervision.need((len(raw), supervision.fingerprint(raw)) == (size, digest),
                         'composition_fixed_literal_identity')
        plan.append({'id': occurrence, 'kind': profile['kinds'][ordinal],
                     'bytes': raw, 'value': None, 'reason': None,
                     'expected_verdict': planned if baseline else 'InvariantViolation'})
    return plan


def evaluate_fixture(fixture, record, frame, profile_id):
    """Return exact canonical frame bytes and semantic result, not qualification."""
    profile = supervision.composition_profile(profile_id)
    supervision.need(record['observation'] == 'Complete' and
        record['process']['returncode'] == 0 and fixture['id'] in profile['ids'],
        'composition_complete_capture_required')
    index = profile['ids'].index(fixture['id'])
    baseline = profile_id == supervision.COMPOSITION_PROFILE
    literal = fixture['id'] if baseline else semantic.MUTANT_INPUTS[fixture['id']]
    size, digest, planned = semantic.FIXTURES[literal]
    expected = planned if baseline else 'InvariantViolation'
    supervision.need(fixture['kind'] == profile['kinds'][index] and
        fixture['expected_verdict'] == expected and type(fixture['bytes']) is bytes and
        (len(fixture['bytes']), supervision.fingerprint(fixture['bytes'])) == (size, digest),
        'composition_prepared_fixture_binding')
    # Safety and incompleteness precede fixture/outcome/callback matching.
    inspected = semantic.inspect_semantics(fixture['bytes'], frame, wire_version='V2')
    compared = semantic.evaluate_fixture_semantics(fixture['id'], fixture['bytes'], frame,
        artifact_role='baseline' if baseline else 'auth-cache-bypass-mutant', wire_version='V2')
    matched = inspected.category == expected and compared.category == expected
    if not baseline:
        matched = matched and inspected.findings == (semantic.TARGET,) and \
            compared.findings == (semantic.TARGET,)
    invariant = ({'class': inspected.findings[0]} if
                 inspected.category == 'InvariantViolation' and inspected.findings else None)
    evaluation = {'schema': 'northstar-stage4-composition-evaluation-v1',
                  'verdict': inspected.category, 'qualified': False,
                  'invariant': invariant, 'findings': list(inspected.findings),
                  'fixture_category': compared.category,
                  'fixture_findings': list(compared.findings),
                  'input_sha256': inspected.input_sha256,
                  'frame_sha256': inspected.evidence_sha256}
    return frame, evaluation, bool(matched), None if matched else 'FixtureMismatch'


def shrink_relations(_observations):
    raise supervision.SupervisionError('composition_requires_authenticated_cross_contract_join')
