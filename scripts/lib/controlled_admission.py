"""Independent oracle and source-bound replay for the controlled Rust adapter.

This module never treats prediction as observation. run_saved_input invokes the
supplied Rust executable on a complete saved input; no build or service starts.
Inputs and projections use synthetic labels only. SQL/MVCC, crypto, durable
message commit, process loss and real signals are outside this adapter's scope.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid

from . import experiment_contract as stage1

SCHEMA = 'northstar-admission-controlled-input-v1'
OUTPUT_SCHEMA = 'northstar-admission-controlled-output-v2'
REJECTION_SCHEMA = 'northstar-admission-controlled-rejection-v1'
CORPUS_SCHEMA = 'northstar-admission-controlled-corpus-v1'
MODEL = 'admission-controlled-v1'
ADAPTER = 'controlled_rust'
BINDING_VERSION = 'synthetic-material-v1'
MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_ROWS = 40000
MAX_STEPS = 256
MAX_EVENTS = 4096
MAX_TIME = stage1.MAX_TIME
CAPACITY = 4096
SHARD_CAPACITY = 32768
SECOND = 1_000_000
ROOT = Path(__file__).resolve().parents[2]
InvalidScenario = stage1.InvalidScenario
require = stage1.require
fields = stage1.fields
integer = stage1.integer
label = stage1.label
canonical = stage1.canonical
digest = stage1.digest


def loads(data, maximum=MAX_INPUT_BYTES):
    if isinstance(data, str):
        data = data.encode()
    require(type(data) is bytes and len(data) <= maximum, 'byte_budget')
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, 'duplicate_field')
            value[key] = item
        return value
    try:
        return json.loads(data, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(InvalidScenario('nonfinite_json')))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise InvalidScenario('malformed_json') from error


def read_json(path):
    with Path(path).open('rb') as stream:
        return loads(stream.read(MAX_INPUT_BYTES + 1))


def bounded(value, maximum=MAX_INPUT_BYTES):
    try:
        require(len(canonical(value).encode()) <= maximum, 'byte_budget')
    except (TypeError, ValueError, RecursionError) as error:
        raise InvalidScenario('malformed_json') from error


def array(value, name, maximum):
    require(type(value) is list and len(value) <= maximum, name + '_budget')
    return value


def boolean(value, name):
    require(type(value) is bool, name + '_boolean')
    return value


def canonical_uuid(value):
    require(type(value) is str, 'invalid_uuid')
    try:
        require(str(uuid.UUID(value)) == value, 'invalid_uuid')
    except (ValueError, AttributeError) as error:
        raise InvalidScenario('invalid_uuid') from error
    return value


def sha256_file(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def validate_provenance(value):
    """Validate a separately supplied driver identity, never trust a saved corpus."""
    fields(value, 'schema model adapter binding_version source_sha256 source_files binary_sha256 cargo_lock_sha256 toolchain',
           'trusted provenance')
    require(value['schema'] == 'northstar-admission-controlled-provenance-v1' and
            value['model'] == MODEL and value['adapter'] == ADAPTER and
            value['binding_version'] == BINDING_VERSION, 'provenance_version')
    require(type(value['source_files']) is dict and value['source_files'], 'source_files')
    for name, fingerprint in value['source_files'].items():
        path = Path(name)
        require(type(name) is str and not path.is_absolute() and '..' not in path.parts and
                str(path) == name and '\\' not in name, 'source_path')
        require(type(fingerprint) is str and re.fullmatch('[a-f0-9]{64}', fingerprint), 'source_hash')
    for key in ('source_sha256', 'binary_sha256', 'cargo_lock_sha256'):
        require(type(value[key]) is str and re.fullmatch('[a-f0-9]{64}', value[key]), 'provenance_hash')
    require(value['source_sha256'] == digest(value['source_files']), 'source_manifest_hash')
    require(type(value['toolchain']) is str and value['toolchain'].startswith('rustc 1.97.1 '), 'toolchain_version')
    return copy.deepcopy(value)


def check_current_provenance(binary, expected, root=ROOT):
    validate_provenance(expected)
    observed = {name: sha256_file(Path(root) / name) for name in expected['source_files']}
    require(observed == expected['source_files'], 'source_changed')
    require(sha256_file(binary) == expected['binary_sha256'], 'binary_changed')
    require(sha256_file(Path(root) / 'Cargo.lock') == expected['cargo_lock_sha256'], 'cargo_lock_changed')
    return observed


def run_saved_input(path, binary, *, expected_provenance, root=ROOT):
    """Run only the externally built Rust binary, rechecking exact bytes afterward.

    The runner's input and event hard bounds are checked before its work. Wall
    duration is measured; this driver does not inject cancellation or OS signals.
    Rejection fixtures intentionally bypass Python semantic input validation so
    the actual Rust parser has to reject the concrete malformed bytes itself.
    """
    path, binary = Path(path).resolve(), Path(binary).resolve()
    require(path.is_file() and binary.is_file(), 'missing_input_or_binary')
    require(path.stat().st_size <= MAX_INPUT_BYTES, 'byte_budget')
    before_input = sha256_file(path)
    check_current_provenance(binary, expected_provenance, root)
    started = time.monotonic_ns()
    completed = subprocess.run([str(binary), str(path)], capture_output=True, check=False)
    elapsed = (time.monotonic_ns() - started) // 1_000_000
    check_current_provenance(binary, expected_provenance, root)
    require(sha256_file(path) == before_input, 'input_changed')
    require(len(completed.stdout) <= MAX_OUTPUT_BYTES and len(completed.stderr) <= 4096, 'output_budget')
    require(completed.returncode in (0, 2), 'unexpected_runner_exit')
    require(not completed.stderr, 'unexpected_runner_stderr')
    output = loads(completed.stdout, MAX_OUTPUT_BYTES)
    if completed.returncode == 2:
        fields(output, 'schema class reason', 'rejection')
        require(output['schema'] == REJECTION_SCHEMA and output['class'] == 'InvalidScenario', 'rejection_class')
        label(output['reason'], 'rejection_reason')
    return {'command': [str(binary), str(path)], 'returncode': completed.returncode,
            'wall_ms': elapsed, 'input_file_sha256': before_input,
            'stdout_sha256': hashlib.sha256(completed.stdout).hexdigest(), 'output': output,
            'provenance': copy.deepcopy(expected_provenance)}


def materialize_bindings(rows, commands, actors=()):
    """Deterministic fixture construction only; replay consumes the saved material."""
    categories = {'actors': set(actors), 'keys': set(), 'payloads': set(), 'leases': set()}
    for item in list(rows) + list(commands):
        for category, key in (('actors', 'actor'), ('keys', 'key'), ('payloads', 'payload_tag'), ('leases', 'lease')):
            categories[category].add(item[key])
        categories['keys'].update(item.get('candidates', []))
    bindings = {}
    for category, labels in categories.items():
        entries = []
        for name in sorted(labels):
            hashed = hashlib.sha256((category + ':' + name).encode()).digest()
            entry = {'label': name}
            if category in ('actors', 'leases'):
                entry['uuid'] = str(uuid.UUID(bytes=hashed[:16]))
            else:
                entry['hex'] = hashed.hex()
                if category == 'keys':
                    entry['key_id'] = 'controlled-fixture-v1'
            entries.append(entry)
        bindings[category] = entries
    return bindings


def binding_maps(value):
    fields(value, 'actors keys payloads leases', 'bindings')
    maps = {}
    for category in ('actors', 'keys', 'payloads', 'leases'):
        entries = array(value[category], category, {'actors': 64, 'keys': 40512, 'payloads': 512, 'leases': 40512}[category])
        require(entries, 'empty_bindings')
        labels, materials, mapped = set(), set(), {}
        for item in entries:
            fields(item, 'label key_id hex' if category == 'keys' else
                   'label hex' if category == 'payloads' else 'label uuid', category)
            name = label(item['label'], category + '.label')
            material = item.get('hex', item.get('uuid'))
            if category in ('keys', 'payloads'):
                require(type(material) is str and re.fullmatch('[a-f0-9]{64}', material), 'invalid_hex')
            else:
                canonical_uuid(material)
            if category == 'keys':
                label(item['key_id'], 'key_id')
            require(name not in labels and material not in materials, 'duplicate_binding')
            labels.add(name)
            materials.add(material)
            mapped[name] = copy.deepcopy(item)
        maps[category] = mapped
    return maps


def shard(maps, key):
    return bytes.fromhex(maps['keys'][key]['hex'])[8] % 64


def stage1_cases():
    """Load accepted independent golden constructors, never stage1.predict()."""
    path = ROOT / 'scripts/test-experiment-contract.py'
    spec = importlib.util.spec_from_file_location('stage1_golden_contract', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.synthetic_cases()


ROOT_FIELDS = 'schema model adapter binding_version scenario_id scope initial bindings commands budgets stage1'
COMMAND_FIELDS = ('operation_id effect_id operation_uuid effect_number causal_id attempt generation action kind actor key payload_tag lease '
                  'candidates times guard schedule reconcile_of')
CUTS = ('none', 'before_effect_cancel', 'precommit_error', 'commit_unknown', 'commit_cancel', 'receipt_before_cancel')
ACTIONS = ('reserve', 'finalize', 'reconcile', 'guard_memory', 'guard_persistent')
TIMES = ('admission_us', 'actor_policy_us', 'finalize_us', 'reconcile_us')


def validate_bridge(value):
    if value['stage1'] is None:
        require(all(c['schedule']['cleanup'] == 'bounded_skip_locked' for c in value['commands']), 'native_cleanup')
        return
    bridge = value['stage1']
    fields(bridge, 'scenario sha256', 'stage1 bridge')
    original = bridge['scenario']
    parsed = stage1.parse_scenario(original)
    require(bridge['sha256'] == digest(original), 'stage1_hash')
    require(value['scenario_id'] == original['scenario_id'], 'stage1_scenario_id')
    require(value['initial']['rows'] == original['initial_rows'], 'stage1_rows')
    require(set(value['initial']['actor_sequences']) == set(original['actors']), 'stage1_actors')
    require(len(value['commands']) == len(parsed.commands), 'stage1_command_count')
    for command, old in zip(value['commands'], original['commands']):
        for key in ('operation_id', 'effect_id', 'causal_id', 'attempt', 'action', 'kind', 'actor', 'key', 'payload_tag', 'lease'):
            require(command[key] == old[key], 'stage1_command_binding')
        require(command['generation'] == 1 and command['candidates'] == [old['key']] and
                command['reconcile_of'] is None, 'stage1_command_scope')
        require(all(now == old['time_us'] for now in command['times'].values()), 'stage1_time_binding')
        expected_cut = {'none': 'none', 'before_effect_cancel': 'before_effect_cancel',
                        'reservation_commit_unknown': 'commit_unknown'}[old['cut']]
        require(command['schedule']['cut'] == expected_cut and
                command['schedule']['cleanup'] == 'exact_key_only' and
                command['schedule']['locked_keys'] == [], 'stage1_schedule')
        require(command['schedule']['completions'] == ([] if expected_cut == 'before_effect_cancel' else [completion_for(command)]),
                'stage1_completions')
        require(command['guard']['allowed'] is True, 'stage1_guard')


def parse_scenario(value):
    bounded(value)
    fields(value, ROOT_FIELDS, 'controlled input')
    for key, expected in (('schema', SCHEMA), ('model', MODEL), ('adapter', ADAPTER),
                          ('binding_version', BINDING_VERSION), ('scope', 'reservation_finalization_only')):
        require(value[key] == expected, key + '_version')
    label(value['scenario_id'], 'scenario_id')
    maps = binding_maps(value['bindings'])
    fields(value['initial'], 'rows actor_sequences proofs', 'initial')
    initial = value['initial']
    require(type(initial['actor_sequences']) is dict and set(initial['actor_sequences']) == set(maps['actors']),
            'actor_sequences')
    for sequence in initial['actor_sequences'].values():
        integer(sequence, 'actor_sequence', 0, 1_000_000)
    proof_set = set()
    for proof in array(initial['proofs'], 'proofs', MAX_ROWS):
        canonical_uuid(proof)
        require(proof not in proof_set, 'duplicate_proof')
        proof_set.add(proof)
    keys = set()
    for row in array(initial['rows'], 'rows', MAX_ROWS):
        fields(row, stage1.ROW_FIELDS, 'initial row')
        for category, key in (('actors', 'actor'), ('keys', 'key'), ('payloads', 'payload_tag'), ('leases', 'lease')):
            require(row[key] in maps[category], 'unbound_row_material')
        require(row['key'] not in keys, 'duplicate_row')
        keys.add(row['key'])
        require(row['state'] in ('pending', 'accepted'), 'row_state')
        integer(row['expires_at_us'], 'row_expiry', -MAX_TIME)
        integer(row['lease_until_us'], 'row_lease_expiry', -MAX_TIME)
    fields(value['budgets'], 'steps events evidence_bytes', 'budgets')
    for key, maximum in (('steps', MAX_STEPS), ('events', MAX_EVENTS), ('evidence_bytes', MAX_OUTPUT_BYTES)):
        integer(value['budgets'][key], key, 2048 if key == 'evidence_bytes' else 1, maximum)
    commands = array(value['commands'], 'commands', MAX_STEPS)
    require(commands and len(commands) <= value['budgets']['steps'], 'step_budget')
    operations, effects, unresolved, operation_uuids, effect_numbers = {}, set(), set(), set(), set()
    previous = {key: 0 for key in TIMES}
    for command in commands:
        fields(command, COMMAND_FIELDS, 'command')
        for key in ('operation_id', 'effect_id'):
            label(command[key], key)
        require(command['operation_id'] not in operations and command['effect_id'] not in effects, 'duplicate_correlation')
        require(command['causal_id'] is None or command['causal_id'] in operations, 'causal_identity')
        integer(command['attempt'], 'attempt', 1, 20000)
        integer(command['generation'], 'generation', 0, 20000)
        canonical_uuid(command['operation_uuid'])
        integer(command['effect_number'], 'effect_number', 1, MAX_TIME)
        require(command['operation_uuid'] not in operation_uuids, 'duplicate_material_correlation')
        operation_uuids.add(command['operation_uuid'])
        effect_numbers.add(command['effect_number'])
        require(command['action'] in ACTIONS and command['kind'] in ('direct', 'muc', 'mix'), 'command_kind')
        for category, key in (('actors', 'actor'), ('keys', 'key'), ('payloads', 'payload_tag'), ('leases', 'lease')):
            require(command[key] in maps[category], 'unbound_command_material')
        candidates = array(command['candidates'], 'candidates', 8)
        require(candidates and candidates[0] == command['key'] and len(set(candidates)) == len(candidates) and
                all(key in maps['keys'] for key in candidates), 'candidate_binding')
        fields(command['times'], ' '.join(TIMES), 'authority times')
        for key, now in command['times'].items():
            integer(now, key)
            require(now >= previous[key], 'authority_time_order')
            previous[key] = now
        validate_guard(command['guard'])
        schedule = command['schedule']
        fields(schedule, 'cut world_commit cleanup locked_keys completions', 'schedule')
        require(schedule['cut'] in CUTS, 'cut')
        boolean(schedule['world_commit'], 'world_commit')
        require(schedule['cut'] in ('commit_unknown', 'commit_cancel') or
                schedule['world_commit'] == (schedule['cut'] in ('none', 'receipt_before_cancel')), 'world_commit_cut')
        require(schedule['cleanup'] in ('exact_key_only', 'bounded_skip_locked'), 'cleanup_schedule')
        locked = array(schedule['locked_keys'], 'locked_keys', MAX_ROWS)
        require(len(set(locked)) == len(locked) and all(key in maps['keys'] for key in locked), 'locked_keys')
        completions = array(schedule['completions'], 'completions', 16)
        if schedule['cut'] in ('before_effect_cancel', 'commit_cancel', 'receipt_before_cancel'):
            require(completions == [], 'cancelled_completion_schedule')
        else:
            require(completions, 'missing_completion_schedule')
        for completion in completions:
            fields(completion, COMPLETION_FIELDS, 'completion')
            canonical_uuid(completion['operation_uuid'])
            integer(completion['effect_number'], 'completion_effect', 1, MAX_TIME)
            integer(completion['generation'], 'completion_generation', 0, 20000)
            integer(completion['attempt'], 'completion_attempt', 1, 20000)
            require(completion['action'] in ACTIONS, 'completion_action')
            for category, key in (('actors', 'actor'), ('keys', 'key'), ('payloads', 'payload_tag'), ('leases', 'lease')):
                require(completion[key] in maps[category], 'unbound_completion_material')
            validate_guard(completion['guard'])
            require((completion['action'] == 'reconcile') == (completion['reconcile_of'] is not None) and
                    (completion['reconcile_of'] is None or completion['reconcile_of'] in operations), 'completion_reconcile_target')
        if command['action'] == 'reconcile':
            require(command['reconcile_of'] in unresolved, 'reconcile_target')
            prior = operations[command['reconcile_of']]
            require(all(command[key] == prior[key] for key in ('actor', 'key', 'payload_tag', 'lease')), 'reconcile_identity')
            require(schedule['cut'] in ('none', 'precommit_error'), 'reconcile_cut')
        else:
            require(command['reconcile_of'] is None, 'unexpected_reconcile_target')
        if command['action'] == 'guard_memory':
            require(schedule['cut'] in ('none', 'before_effect_cancel', 'precommit_error'), 'memory_cut')
        if command['action'] == 'reserve':
            require(not any(p['schedule']['cut'] in ('commit_unknown', 'commit_cancel') and
                            p['actor'] == command['actor'] and p['key'] == command['key'] for p in operations.values()), 'blind_retry')
        if schedule['cut'] in ('commit_unknown', 'commit_cancel'):
            unresolved.add(command['operation_id'])
        operations[command['operation_id']] = command
        effects.add(command['effect_id'])
    validate_bridge(value)
    return maps


GUARD_FIELDS = ('account_bare normalized_target origin_id normalized_payload pow_intent_payload subject '
                'actors proof allowed actor_sequence_delta')
COMPLETION_FIELDS = ('operation_uuid effect_number generation attempt action actor key payload_tag lease guard reconcile_of')


def validate_guard(value):
    fields(value, GUARD_FIELDS, 'guard')
    for key in ('account_bare', 'normalized_target', 'normalized_payload', 'pow_intent_payload', 'subject'):
        require(type(value[key]) is str and value[key].isascii() and 1 <= len(value[key]) <= 1024, 'guard_text')
    if value['origin_id'] is not None:
        label(value['origin_id'], 'origin_id')
    actors = array(value['actors'], 'guard_actors', 16)
    require(actors and len(set(actors)) == len(actors), 'guard_actors')
    for actor in actors:
        label(actor, 'guard_actor')
    if value['proof'] is not None:
        fields(value['proof'], 'challenge_id nonce', 'guard proof')
        canonical_uuid(value['proof']['challenge_id'])
        nonce = value['proof']['nonce']
        require(type(nonce) is str and nonce.isascii() and 1 <= len(nonce) <= 128, 'proof_nonce')
    boolean(value['allowed'], 'guard_allowed')
    integer(value['actor_sequence_delta'], 'actor_sequence_delta', 0, 10)


def completion_for(command):
    return {key: copy.deepcopy(command[key]) for key in COMPLETION_FIELDS.split()}


def synthetic_guard(*, allowed=True, delta=0, proof=None):
    return {'account_bare': 'controlled@example.invalid', 'normalized_target': 'target@example.invalid',
            'origin_id': 'synthetic-origin', 'normalized_payload': 'synthetic-payload',
            'pow_intent_payload': 'synthetic-intent', 'subject': 'synthetic-subject',
            'actors': ['synthetic-actor'], 'proof': copy.deepcopy(proof),
            'allowed': allowed, 'actor_sequence_delta': delta}


def controlled_command(number, key=None, *, action='reserve', actor='actor-a', payload='payload-a',
                       lease=None, now=0, kind='direct', causal_id=None, cut='none', world_commit=None,
                       guard=None, candidates=None, locked_keys=(), reconcile_of=None):
    operation = f'op-{number}'
    command = {'operation_id': operation, 'effect_id': f'effect-{number}',
               'operation_uuid': str(uuid.UUID(bytes=hashlib.sha256(('operation:' + operation).encode()).digest()[:16])),
               'effect_number': number, 'causal_id': causal_id, 'attempt': 1, 'generation': 1,
               'action': action, 'kind': kind, 'actor': actor, 'key': key or f'key-{number}',
               'payload_tag': payload, 'lease': lease or f'lease-{number}',
               'candidates': list(candidates or [key or f'key-{number}']),
               'times': {name: now for name in TIMES}, 'guard': copy.deepcopy(guard or synthetic_guard()),
               'schedule': {'cut': cut, 'world_commit': world_commit if world_commit is not None else
                            cut not in ('before_effect_cancel', 'precommit_error'),
                            'cleanup': 'bounded_skip_locked', 'locked_keys': list(locked_keys), 'completions': []},
               'reconcile_of': reconcile_of}
    if cut not in ('before_effect_cancel', 'commit_cancel', 'receipt_before_cancel'):
        command['schedule']['completions'] = [completion_for(command)]
    return command


def scenario(name, commands, rows=(), *, actors=('actor-a',), proofs=(), stage1_input=None):
    rows = [copy.deepcopy(row) for row in rows]
    commands = copy.deepcopy(commands)
    material_commands = commands + [entry for c in commands for entry in c['schedule']['completions']]
    bindings = materialize_bindings(rows, material_commands, actors)
    value = {'schema': SCHEMA, 'model': MODEL, 'adapter': ADAPTER, 'binding_version': BINDING_VERSION,
             'scenario_id': name, 'scope': 'reservation_finalization_only',
             'initial': {'rows': rows, 'actor_sequences': {a['label']: 0 for a in bindings['actors']}, 'proofs': list(proofs)},
             'bindings': bindings, 'commands': commands,
             'budgets': {'steps': MAX_STEPS, 'events': MAX_EVENTS, 'evidence_bytes': MAX_OUTPUT_BYTES},
             'stage1': None if stage1_input is None else {'scenario': copy.deepcopy(stage1_input), 'sha256': digest(stage1_input)}}
    if stage1_input is not None:
        for command in value['commands']:
            command['schedule']['cleanup'] = 'exact_key_only'
    return value


def bridge_case(old):
    commands = []
    for index, item in enumerate(old['commands'], 1):
        cut = {'none': 'none', 'before_effect_cancel': 'before_effect_cancel',
               'reservation_commit_unknown': 'commit_unknown'}[item['cut']]
        command = controlled_command(index, item['key'], action=item['action'], actor=item['actor'],
                                     payload=item['payload_tag'], lease=item['lease'], now=item['time_us'],
                                     kind=item['kind'], causal_id=item['causal_id'], cut=cut)
        command.update(operation_id=item['operation_id'], effect_id=item['effect_id'], attempt=item['attempt'])
        command['schedule']['completions'] = [] if cut == 'before_effect_cancel' else [completion_for(command)]
        commands.append(command)
    return scenario(old['scenario_id'], commands, old['initial_rows'], actors=old['actors'], stage1_input=old)


def _counts(rows, actor, now):
    owned = [row for row in rows.values() if row['actor'] == actor]
    return sum(row['expires_at_us'] > now for row in owned), len(owned)


def _kind(action):
    return action if action in ('finalize', 'reconcile') else 'begin'


def _completion_reason(command, completion, already_finished):
    if already_finished:
        return 'AlreadyCompleted'
    if any(command[key] != completion[key] for key in ('operation_uuid', 'effect_number', 'generation', 'attempt')):
        return 'Correlation'
    if _kind(command['action']) != _kind(completion['action']):
        return 'Kind'
    if _kind(command['action']) == 'begin':
        guard_fields = set(GUARD_FIELDS.split()) - {'allowed', 'actor_sequence_delta'}
        if command['actor'] != completion['actor'] or any(command['guard'][key] != completion['guard'][key] for key in guard_fields):
            return 'Request'
    elif any(command[key] != completion[key] for key in ('key', 'payload_tag', 'lease')):
        return 'Request'
    elif command['action'] == 'reconcile' and command['reconcile_of'] != completion['reconcile_of']:
        return 'Request'
    return None


def _fence_labels(command, *, row=None):
    source = command if row is None else row
    return {'mapped': True, **{key: source[key] for key in ('key', 'payload_tag', 'lease')}}


def _retained_knowledge(command, result, scope, staged, selected_key):
    """Authority contract: preparation retains its exact prospective fact;
    only a delivered repository receipt establishes confirmed knowledge.
    This prediction is independent of Rust's outcome classification.
    """
    if scope is None:
        return {'kind': 'NoCommitRequested', 'correlation': None, 'scope': None, 'fact': None}
    kind = 'CommitCallEntered' if command['schedule']['cut'] in ('commit_unknown', 'commit_cancel') else 'ReceiptKnown'
    fact_kind = {'Proceed': 'Reserved', 'Accepted': 'Finalized.PendingAccepted',
                 'AlreadyAccepted': 'Finalized.AlreadyAccepted'}.get(result, result)
    fence = _fence_labels(command, row=staged[selected_key]) if result == 'Proceed' else \
        _fence_labels(command) if result in ('Accepted', 'AlreadyAccepted') else None
    return {'kind': kind, 'correlation': {'mapped': True, 'operation_id': command['operation_id'],
                                         'effect_number': command['effect_number'], 'generation': command['generation'],
                                         'attempt': command['attempt']},
            'scope': scope, 'fact': {'kind': fact_kind, 'fence': fence}}


def _declared_result(command, result, staged, selected_key, reconciliation):
    """The completion payload follows declared adapter effects, not its cut's
    desired domain label. A missing reply is handled separately by delivery.
    """
    failed = command['schedule']['cut'] in ('before_effect_cancel', 'precommit_error', 'commit_unknown', 'commit_cancel') or result == 'IntegrityFailure'
    if failed:
        return {'kind': 'Failed', 'fence': None, 'reconcile': None, 'cause': 'Backend'}
    action = command['action']
    if action == 'reconcile':
        kind = 'Reconcile'
    elif action == 'finalize':
        kind = 'Finalize.' + {'Conflict': 'PayloadConflict', 'LeaseLost': 'LostFence',
                              'Accepted': 'AcceptPending'}.get(result, result)
    else:
        kind = 'Begin.' + ('Reserved' if result == 'Proceed' else result)
    return {'kind': kind, 'fence': _fence_labels(command, row=staged[selected_key]) if result == 'Proceed' else None,
            'reconcile': None if reconciliation is None else
            {key: reconciliation[key] for key in ('observation', 'lease', 'retention')}, 'cause': None}


def _expected_coordinator(accepted, delivered, retained):
    """Independently apply the contract for a validated delivered completion.
    Cancellation is an external action and cannot supply an outcome here.
    """
    if not accepted:
        return {'state': 'Waiting', 'outcome': None, 'result': None, 'cause': None, 'knowledge': None}
    if delivered['kind'] != 'Failed':
        return {'state': 'Finished', 'outcome': 'Completed', 'result': copy.deepcopy(delivered),
                'cause': None, 'knowledge': copy.deepcopy(retained)}
    outcome = {'NoCommitRequested': 'PreCommitFailure', 'CommitCallEntered': 'Unknown',
               'ReceiptKnown': 'ReceiptPreserved'}[retained['kind']]
    return {'state': 'Finished', 'outcome': outcome, 'result': None,
            'cause': delivered['cause'], 'knowledge': copy.deepcopy(retained)}


def predict(value):
    """Independent Python predicates; outputs are explicitly predictions only."""
    maps = parse_scenario(value)
    rows = {row['key']: copy.deepcopy(row) for row in value['initial']['rows']}
    sequences = copy.deepcopy(value['initial']['actor_sequences'])
    proofs = set(value['initial']['proofs'])
    projection, compatibility, prior = [], [], {}
    for index, command in enumerate(value['commands']):
        action, cut = command['action'], command['schedule']['cut']
        now = command['times'][{'finalize': 'finalize_us', 'reconcile': 'reconcile_us'}.get(action, 'admission_us')]
        before = copy.deepcopy(rows)
        staged = copy.deepcopy(rows)
        stage_sequences, stage_proofs = sequences.copy(), proofs.copy()
        scope, reconciliation = None, None
        guard = command['guard']
        proof = guard['proof']['challenge_id'] if guard['proof'] else None
        selected_key = command['key']
        row = staged.get(selected_key)
        if cut in ('before_effect_cancel', 'precommit_error'):
            result = 'NotRequested' if cut == 'before_effect_cancel' else 'BackendFailure'
        elif action in ('guard_memory', 'guard_persistent'):
            result = 'GuardOnlyAllowed' if guard['allowed'] else 'GuardOnlyDenied'
            if action == 'guard_persistent':
                require(proof is None or not guard['allowed'] or proof in stage_proofs, 'command')
                scope = 'GuardOnlyVerification'
                stage_sequences[command['actor']] += guard['actor_sequence_delta']
                stage_proofs.discard(proof)
        elif action == 'reserve':
            for key in command['candidates']:
                if key in staged and staged[key]['expires_at_us'] <= now:
                    del staged[key]
            candidates = [staged[key] for key in command['candidates'] if key in staged]
            if len(candidates) > 1:
                result = 'IntegrityFailure'
            elif candidates:
                row = candidates[0]
                selected_key = row['key']
                if row['actor'] != command['actor'] or row['payload_tag'] != command['payload_tag']:
                    result = 'Conflict'
                elif row['state'] == 'accepted':
                    result, scope = 'ReplayAccepted', 'RatedBegin.ReplayRead'
                elif row['lease_until_us'] > now:
                    result, scope = 'InProgress', 'RatedBegin.PendingRequirement'
                    stage_sequences[command['actor']] += guard['actor_sequence_delta']
                else:
                    result, scope = 'Proceed', 'RatedBegin.Reclaim'
                    row.update(lease=command['lease'], lease_until_us=now + 60 * SECOND)
                    stage_sequences[command['actor']] += guard['actor_sequence_delta']
            else:
                require(proof is None or not guard['allowed'] or proof in stage_proofs, 'command')
                stage_sequences[command['actor']] += guard['actor_sequence_delta']
                stage_proofs.discard(proof)
                if not guard['allowed']:
                    result, scope = 'Denied', 'RatedBegin.GuardDenial'
                else:
                    if command['schedule']['cleanup'] == 'bounded_skip_locked':
                        removable = sorted((row for row in staged.values()
                                            if row['expires_at_us'] <= now and
                                            shard(maps, row['key']) == shard(maps, command['key']) and
                                            row['key'] not in command['schedule']['locked_keys']),
                                           key=lambda row: (row['expires_at_us'], maps['keys'][row['key']]['hex']))[:128]
                        for expired in removable:
                            del staged[expired['key']]
                    actor_full = _counts(staged, command['actor'], now)[0] >= CAPACITY
                    shard_full = sum(shard(maps, key) == shard(maps, command['key']) for key in staged) >= SHARD_CAPACITY
                    if actor_full or shard_full:
                        result = 'CapacityLimited'
                    else:
                        result, scope = 'Proceed', 'RatedBegin.NewReservation'
                        staged[command['key']] = {'actor': command['actor'], 'key': command['key'],
                                                  'payload_tag': command['payload_tag'], 'state': 'pending',
                                                  'expires_at_us': now + 1800 * SECOND, 'lease': command['lease'],
                                                  'lease_until_us': now + 60 * SECOND}
        elif action == 'finalize':
            if row is None:
                result = 'Missing'
            elif row['payload_tag'] != command['payload_tag']:
                result = 'Conflict'
            elif row['state'] == 'accepted':
                result, scope = 'AlreadyAccepted', 'AdmissionFinalize'
            elif row['lease'] != command['lease']:
                result = 'LeaseLost'
            else:
                result, scope = 'Accepted', 'AdmissionFinalize'
                row.update(state='accepted', expires_at_us=now + 21600 * SECOND)
        else:
            if row is None:
                observed = 'Missing'
            elif row['payload_tag'] != command['payload_tag']:
                observed = 'Conflicting'
            elif row['state'] == 'accepted':
                observed = 'ExactAccepted'
            elif row['lease'] != command['lease']:
                observed = 'Superseded'
            else:
                observed = 'ExactPending'
            result = 'Reconcile' + observed
            reconciliation = {'observation': observed,
                              'lease': ('Current' if row['lease_until_us'] > now else 'Expired') if observed == 'ExactPending' else None,
                              'retention': ('Current' if row['expires_at_us'] > now else 'Expired') if observed in ('ExactPending', 'ExactAccepted') else None,
                              'unresolved_operation_preserved': True}
        commit = scope is not None
        if not commit:
            staged, stage_sequences, stage_proofs = copy.deepcopy(before), sequences.copy(), proofs.copy()
        committed = commit and command['schedule']['world_commit']
        if committed:
            rows, sequences, proofs = staged, stage_sequences, stage_proofs
        witness = _retained_knowledge(command, result, scope, staged, selected_key)
        knowledge = witness['kind']
        delivered = _declared_result(command, result, staged, selected_key, reconciliation)
        accepted, rejections = False, []
        for completion_index, completion in enumerate(command['schedule']['completions']):
            reason = _completion_reason(command, completion, accepted)
            if reason is None:
                accepted = True
            else:
                rejections.append({'index': completion_index, 'reason': reason,
                                   'pending_preserved': True, 'receipt_preserved': True})
        cancelled = cut in ('before_effect_cancel', 'commit_cancel', 'receipt_before_cancel')
        coordinator = _expected_coordinator(accepted, delivered, witness)
        domain = 'AwaitingCompletion' if not accepted else result if coordinator['outcome'] == 'Completed' else \
            'BackendFailure' if coordinator['outcome'] == 'PreCommitFailure' else coordinator['outcome']
        if not accepted:
            reconciliation = None
        old_counts, staged_counts = _counts(before, command['actor'], now), _counts(staged, command['actor'], now)
        active, retained = _counts(rows, command['actor'], now)
        uncertain = knowledge == 'CommitCallEntered'
        ranges = [(min(a, b), max(a, b)) if uncertain else (observed, observed)
                  for a, b, observed in zip(old_counts, staged_counts, (active, retained))]
        reservation = None
        if knowledge == 'ReceiptKnown' and result == 'Proceed':
            owned = staged[selected_key]
            reservation = {'operation_id': command['operation_id'], 'effect_id': command['effect_id'],
                           'key': selected_key, 'payload_tag': owned['payload_tag'], 'lease': owned['lease']}
        causal_id = command['causal_id']
        while reservation is None and causal_id is not None:
            causal = prior[causal_id]
            causal_command = value['commands'][causal['index']]
            existing = causal['caller']['reservation']
            if existing is not None and existing['key'] == command['key']:
                reservation = {key: existing[key] for key in ('operation_id', 'effect_id', 'key', 'payload_tag', 'lease')}
            causal_id = causal_command['causal_id']
        if reservation is not None:
            reservation['applies_to_command'] = (reservation['key'] in (command['candidates'] if action == 'reserve' else [command['key']]) and
                                                reservation['payload_tag'] == command['payload_tag'] and reservation['lease'] == command['lease'])
        reservation_receipt = reservation is not None
        finalization_receipt = knowledge == 'ReceiptKnown' and result in ('Accepted', 'AlreadyAccepted')
        world_row = rows.get(command['key'])
        event = {'index': index, 'operation_id': command['operation_id'], 'effect_id': command['effect_id'],
                 'causal_id': command['causal_id'], 'attempt': command['attempt'], 'generation': command['generation'],
                 'action': action, 'kind': command['kind'], 'times': copy.deepcopy(command['times']),
                 'domain': domain, 'execution': 'Cancelled' if cancelled else 'Completed' if accepted else 'Inconclusive',
                 'cancellation': cancelled, 'coordinator': coordinator, 'witness': witness, 'knowledge': knowledge,
                 'scope': scope,
                 'world': {'committed': committed, 'result': result, 'active': active, 'retained': retained,
                           'row_state': world_row['state'] if world_row else 'Absent',
                           'expires_at_us': world_row['expires_at_us'] if world_row else None,
                           'lease': world_row['lease'] if world_row else None,
                           'actor_sequence': sequences[command['actor']], 'proof_present': proof in proofs if proof else None},
                 'caller': {'active_min': ranges[0][0], 'active_max': ranges[0][1],
                            'retained_min': ranges[1][0], 'retained_max': ranges[1][1],
                            'reservation_receipt': reservation_receipt, 'reservation': reservation, 'finalization_receipt': finalization_receipt,
                            'unresolved': uncertain},
                 'completion': {'accepted': accepted, 'pending': not accepted, 'rejections': rejections},
                 'reconcile': reconciliation}
        projection.append(event)
        prior[command['operation_id']] = event
        if value['stage1'] is not None:
            old = value['stage1']['scenario']['commands'][index]
            old_row = before.get(command['key']) if uncertain else world_row
            cancelled_before_effect = (event['cancellation'] and coordinator['state'] == 'Waiting' and
                                       witness['kind'] == 'NoCommitRequested')
            compatibility_domain = 'NotRequested' if cancelled_before_effect else domain
            compatibility.append({'schema_version': 1, 'operation_id': old['operation_id'], 'effect_id': old['effect_id'],
                                  'causal_id': old['causal_id'], 'attempt': old['attempt'], 'time_us': old['time_us'],
                                  'transition': old['action'], 'actor': old['actor'], 'key': old['key'], 'kind': old['kind'],
                                  'execution': event['execution'], 'domain': compatibility_domain,
                                  'effect_status': 'Unknown' if domain == 'Unknown' else 'NotRequested' if cancelled_before_effect else 'Confirmed',
                                  **{key: event['caller'][key] for key in ('active_min', 'active_max', 'retained_min', 'retained_max')},
                                  'row_state': 'Unconfirmed' if uncertain else old_row['state'] if old_row else 'Absent',
                                  'expires_at_us': None if uncertain or old_row is None else old_row['expires_at_us'],
                                  'lease': None if uncertain or old_row is None else old_row['lease']})
    unfinished = any(event['completion']['pending'] and event['execution'] != 'Cancelled' for event in projection)
    execution = 'Inconclusive' if unfinished else 'Cancelled' if any(event['execution'] == 'Cancelled' for event in projection) else 'Completed'
    return {'origin': 'prediction', 'projection': projection, 'compatibility_projection': compatibility if value['stage1'] else None,
            'execution': execution, 'terminal': not unfinished,
            'coordinators_finished': all(event['coordinator']['state'] == 'Finished' for event in projection)}


EVENT_FIELDS = ('index operation_id effect_id causal_id attempt generation action kind times domain execution knowledge '
                'scope world caller completion reconcile cancellation coordinator witness')
WORLD_FIELDS = 'committed result active retained row_state expires_at_us lease actor_sequence proof_present'
CALLER_FIELDS = 'active_min active_max retained_min retained_max reservation_receipt reservation finalization_receipt unresolved'
DOMAINS = ('Proceed', 'ReplayAccepted', 'InProgress', 'Denied', 'Conflict', 'CapacityLimited', 'Missing', 'AlreadyAccepted',
           'LeaseLost', 'Accepted', 'GuardOnlyAllowed', 'GuardOnlyDenied', 'ReconcileExactPending', 'ReconcileExactAccepted',
           'ReconcileMissing', 'ReconcileSuperseded', 'ReconcileConflicting', 'NotRequested', 'BackendFailure', 'Unknown',
           'ReceiptPreserved', 'AwaitingCompletion', 'IntegrityFailure', 'ActorBusy', 'CancelledFailure')
SCOPES = (None, 'RatedBegin.NewReservation', 'RatedBegin.Reclaim', 'RatedBegin.ReplayRead',
          'RatedBegin.PendingRequirement', 'RatedBegin.GuardDenial', 'AdmissionFinalize', 'GuardOnlyVerification')
FACT_KINDS = ('Reserved', 'ReplayAccepted', 'InProgress', 'Denied', 'Finalized.PendingAccepted',
              'Finalized.AlreadyAccepted', 'GuardOnlyAllowed', 'GuardOnlyDenied')
RESULT_KINDS = ('Begin.GuardOnlyAllowed', 'Begin.GuardOnlyDenied', 'Begin.Reserved', 'Begin.ReplayAccepted',
                'Begin.InProgress', 'Begin.Denied', 'Begin.Conflict', 'Begin.CapacityLimited', 'Finalize.Missing',
                'Finalize.PayloadConflict', 'Finalize.LostFence', 'Finalize.AlreadyAccepted', 'Finalize.AcceptPending',
                'Reconcile', 'Failed')
CAUSES = ('Backend', 'ActorBusy', 'Cancelled')


def _validate_fence(value):
    fields(value, 'mapped key payload_tag lease', 'projected_fence')
    boolean(value['mapped'], 'fence_mapped')
    for key in ('key', 'payload_tag', 'lease'):
        if value[key] is not None:
            label(value[key], 'fence_' + key)
    require(value['mapped'] == all(value[key] is not None for key in ('key', 'payload_tag', 'lease')), 'fence_mapping')


def _validate_knowledge(value):
    fields(value, 'kind correlation scope fact', 'projected_knowledge')
    require(value['kind'] in ('NoCommitRequested', 'CommitCallEntered', 'ReceiptKnown'), 'knowledge_kind')
    if value['kind'] == 'NoCommitRequested':
        require(all(value[key] is None for key in ('correlation', 'scope', 'fact')), 'no_commit_shape')
        return
    correlation = value['correlation']
    fields(correlation, 'mapped operation_id effect_number generation attempt', 'projected_correlation')
    boolean(correlation['mapped'], 'correlation_mapped')
    require(correlation['mapped'] == (correlation['operation_id'] is not None), 'correlation_mapping')
    if correlation['operation_id'] is not None:
        label(correlation['operation_id'], 'correlation_operation')
    # Observed typed values may diverge from valid input bounds. Preserve them
    # for ReplayDivergence instead of misclassifying the saved input as invalid.
    integer(correlation['effect_number'], 'correlation_effect', 0, 2**64 - 1)
    integer(correlation['generation'], 'correlation_generation', 0, 2**64 - 1)
    integer(correlation['attempt'], 'correlation_attempt', 0, 2**32 - 1)
    require(value['scope'] in SCOPES[1:], 'knowledge_scope')
    fact = value['fact']
    fields(fact, 'kind fence', 'projected_fact')
    require(fact['kind'] in FACT_KINDS, 'fact_kind')
    if fact['kind'] in ('Reserved', 'Finalized.PendingAccepted', 'Finalized.AlreadyAccepted'):
        _validate_fence(fact['fence'])
    else:
        require(fact['fence'] is None, 'fact_fence_shape')


def _validate_reconcile(value):
    fields(value, 'observation lease retention', 'result_reconcile')
    require(value['observation'] in ('ExactPending', 'ExactAccepted', 'Missing', 'Superseded', 'Conflicting'), 'reconcile_observation')
    for key in ('lease', 'retention'):
        require(value[key] in (None, 'Current', 'Expired'), 'reconcile_validity')
    require((value['lease'] is not None) == (value['observation'] == 'ExactPending') and
            (value['retention'] is not None) == (value['observation'] in ('ExactPending', 'ExactAccepted')), 'reconcile_shape')


def _validate_coordinator(value):
    fields(value, 'state outcome result cause knowledge', 'projected_coordinator')
    require(value['state'] in ('Waiting', 'Finished'), 'coordinator_state')
    if value['state'] == 'Waiting':
        require(all(value[key] is None for key in ('outcome', 'result', 'cause', 'knowledge')), 'waiting_shape')
        return
    _validate_knowledge(value['knowledge'])
    if value['outcome'] == 'Completed':
        require(value['cause'] is None, 'completed_cause')
        result = value['result']
        fields(result, 'kind fence reconcile cause', 'projected_result')
        require(result['kind'] in RESULT_KINDS, 'result_kind')
        if result['kind'] == 'Begin.Reserved':
            _validate_fence(result['fence'])
        else:
            require(result['fence'] is None, 'result_fence_shape')
        if result['kind'] == 'Reconcile':
            _validate_reconcile(result['reconcile'])
        else:
            require(result['reconcile'] is None, 'result_reconcile_shape')
        require(result['cause'] in CAUSES if result['kind'] == 'Failed' else result['cause'] is None, 'result_cause_shape')
    else:
        require(value['outcome'] in ('PreCommitFailure', 'Unknown', 'ReceiptPreserved') and
                value['result'] is None and value['cause'] in CAUSES, 'failed_outcome_shape')
        require(value['knowledge']['kind'] == {'PreCommitFailure': 'NoCommitRequested', 'Unknown': 'CommitCallEntered',
                                              'ReceiptPreserved': 'ReceiptKnown'}[value['outcome']], 'outcome_knowledge_shape')


def validate_output(value, output):
    fields(output, 'schema adapter model scenario_id input_sha256 execution terminal coordinators_finished observation_failure evidence_complete projection compatibility_projection limitations',
           'controlled output')
    require(output['schema'] == OUTPUT_SCHEMA and output['adapter'] == ADAPTER and output['model'] == MODEL,
            'output_version')
    require(output['scenario_id'] == value['scenario_id'] and output['input_sha256'] == digest(value), 'output_input_identity')
    require(output['execution'] in ('Completed', 'Cancelled', 'Inconclusive', 'EnvironmentInterrupted'), 'output_execution')
    boolean(output['terminal'], 'terminal')
    boolean(output['evidence_complete'], 'evidence_complete')
    boolean(output['coordinators_finished'], 'coordinators_finished')
    if output['observation_failure'] is not None:
        failure = output['observation_failure']
        fields(failure, 'class index operation_id', 'observation_failure')
        require(failure['class'] == 'UnmappedMaterial', 'observation_failure_class')
        integer(failure['index'], 'observation_failure_index', 0, len(value['commands'])-1)
        require(failure['operation_id'] == value['commands'][failure['index']]['operation_id'], 'observation_failure_identity')
        require(not output['evidence_complete'] and not output['terminal'] and not output['coordinators_finished'], 'observation_failure_incomplete')
    for limitation in array(output['limitations'], 'limitations', 32):
        require(type(limitation) is str and 0 < len(limitation) <= 1024, 'limitation_text')
    require(output['limitations'], 'missing_limitations')
    for event in array(output['projection'], 'projection', MAX_EVENTS):
        fields(event, EVENT_FIELDS, 'event')
        integer(event['index'], 'event_index', 0, MAX_STEPS-1)
        for key in ('operation_id', 'effect_id'):
            label(event[key], key)
        if event['causal_id'] is not None:
            label(event['causal_id'], 'causal_id')
        integer(event['attempt'], 'attempt', 1, 20000)
        integer(event['generation'], 'generation', 0, 20000)
        require(event['action'] in ACTIONS and event['kind'] in ('direct', 'muc', 'mix'), 'event_kind')
        fields(event['times'], ' '.join(TIMES), 'event_times')
        for now in event['times'].values():
            integer(now, 'event_time')
        require(event['domain'] in DOMAINS and event['execution'] in ('Completed', 'Cancelled', 'Inconclusive') and
                event['knowledge'] in ('NoCommitRequested', 'CommitCallEntered', 'ReceiptKnown') and
                event['scope'] in SCOPES, 'event_semantics')
        boolean(event['cancellation'], 'external_cancellation')
        _validate_coordinator(event['coordinator'])
        _validate_knowledge(event['witness'])
        world = event['world']
        fields(world, WORLD_FIELDS, 'world')
        boolean(world['committed'], 'committed')
        require(world['result'] in DOMAINS and world['row_state'] in ('Absent', 'pending', 'accepted'), 'world_semantics')
        for key in ('active', 'retained'):
            integer(world[key], key, 0, MAX_ROWS + MAX_STEPS)
        integer(world['actor_sequence'], 'actor_sequence', 0, 1_000_000 + 10 * MAX_STEPS)
        require(world['active'] <= world['retained'], 'world_counts')
        if world['expires_at_us'] is not None:
            integer(world['expires_at_us'], 'world_expiry', -MAX_TIME, MAX_TIME + 21600 * SECOND)
        if world['lease'] is not None:
            label(world['lease'], 'world_lease')
        if world['proof_present'] is not None:
            boolean(world['proof_present'], 'proof_present')
        caller = event['caller']
        fields(caller, CALLER_FIELDS, 'caller')
        for key in ('active_min', 'active_max', 'retained_min', 'retained_max'):
            integer(caller[key], key, 0, MAX_ROWS + MAX_STEPS)
        require(caller['active_min'] <= caller['active_max'] <= caller['retained_max'] and
                caller['retained_min'] <= caller['retained_max'], 'caller_counts')
        for key in ('reservation_receipt', 'finalization_receipt', 'unresolved'):
            boolean(caller[key], key)
        if caller['reservation'] is not None:
            fields(caller['reservation'], 'operation_id effect_id key payload_tag lease applies_to_command', 'reservation_receipt')
            for key in ('operation_id', 'effect_id', 'key', 'payload_tag', 'lease'):
                label(caller['reservation'][key], 'reservation_' + key)
            boolean(caller['reservation']['applies_to_command'], 'reservation_applies')
        require(caller['reservation_receipt'] == (caller['reservation'] is not None), 'reservation_receipt_flag')
        fields(event['completion'], 'accepted pending rejections', 'completion_observation')
        boolean(event['completion']['accepted'], 'completion_accepted')
        boolean(event['completion']['pending'], 'completion_pending')
        for rejection in array(event['completion']['rejections'], 'rejections', 16):
            fields(rejection, 'index reason pending_preserved receipt_preserved', 'completion_rejection')
            integer(rejection['index'], 'rejection_index', 0, 15)
            require(rejection['reason'] in ('Correlation', 'Kind', 'Request', 'Knowledge', 'AlreadyCompleted'), 'rejection_reason')
            boolean(rejection['pending_preserved'], 'pending_preserved')
            boolean(rejection['receipt_preserved'], 'receipt_preserved')
        if event['reconcile'] is not None:
            fields(event['reconcile'], 'observation lease retention unresolved_operation_preserved', 'reconcile')
            require(event['reconcile']['observation'] in ('ExactPending', 'ExactAccepted', 'Missing', 'Superseded', 'Conflicting'),
                    'reconcile_observation')
            for key in ('lease', 'retention'):
                require(event['reconcile'][key] in (None, 'Current', 'Expired'), 'reconcile_validity')
            boolean(event['reconcile']['unresolved_operation_preserved'], 'unresolved_operation_preserved')
    if value['stage1'] is None:
        require(output['compatibility_projection'] is None, 'unexpected_compatibility_projection')
    else:
        stage1.validate_projection(output['compatibility_projection'], stage1.parse_scenario(value['stage1']['scenario']))
    bounded(output, MAX_OUTPUT_BYTES)


def derive_invariant(value, projection):
    """Evaluate the proposed all-times cap; no runner-supplied label is trusted."""
    for event in projection:
        if event['world']['active'] > CAPACITY:
            command = value['commands'][event['index']]
            return {'id': 'actor-active-cap-4096', 'class': 'Safety',
                    'location': event['operation_id'], 'cut': command['schedule']['cut'],
                    'output': copy.deepcopy(event)}
    return None


def expected_counterexample(value):
    predicted = predict(value)
    invariant = derive_invariant(value, predicted['projection'])
    return None if invariant is None else {'invariant': invariant, 'projection': predicted['projection'],
                                          'compatibility_projection': predicted['compatibility_projection']}


def evaluate(value, output, *, expected_failure=None):
    predicted = predict(value)
    validate_output(value, output)
    expected = expected_counterexample(value)
    if expected_failure is not None:
        fields(expected_failure, 'invariant projection compatibility_projection', 'expected_counterexample')
        require(expected is not None and expected_failure == expected, 'counterexample_must_match_independent_oracle')
    actual = output['projection']
    prefix_mismatch = stage1.first_mismatch(predicted['projection'][:len(actual)], actual)
    first_mismatch = stage1.first_mismatch(predicted['projection'], actual)
    compatibility_mismatch = None
    if value['stage1'] is not None:
        # Accepted fixture golden observations are separate from this oracle.
        golden = next((golden for old, golden in stage1_cases() if old == value['stage1']['scenario']), None)
        require(golden is not None, 'undeclared_stage1_fixture')
        compatibility_mismatch = stage1.first_mismatch(golden[:len(output['compatibility_projection'])],
                                                       output['compatibility_projection'])
    derived = derive_invariant(value, actual)
    overflow = len(actual) > value['budgets']['events'] or len(canonical(output).encode()) > value['budgets']['evidence_bytes']
    complete = (output['terminal'] and output['evidence_complete'] and not overflow and
                len(actual) == len(predicted['projection']) and
                (value['stage1'] is None or len(output['compatibility_projection']) == len(predicted['compatibility_projection'])))
    expected_output_value = expected_output(value)
    execution_matches = all(output[key] == expected_output_value[key] for key in ('execution', 'terminal', 'coordinators_finished', 'observation_failure', 'evidence_complete', 'limitations'))
    if prefix_mismatch is not None or compatibility_mismatch is not None:
        mismatch = prefix_mismatch or compatibility_mismatch
        at = min(mismatch['index'], len(value['commands'])-1)
        derived = {'id': 'controlled-projection-mismatch', 'class': 'ReplayDivergence',
                   'location': value['commands'][at]['operation_id'], 'cut': value['commands'][at]['schedule']['cut'],
                   'output': mismatch['actual']}
        verdict = 'InvariantViolation'
    elif output['observation_failure'] is not None:
        failure = output['observation_failure']
        derived = {'id': 'controlled-projection-mismatch', 'class': 'ReplayDivergence',
                   'location': failure['operation_id'], 'cut': value['commands'][failure['index']]['schedule']['cut'],
                   'output': copy.deepcopy(failure)}
        verdict = 'InvariantViolation'
    elif derived is not None:
        verdict = 'InvariantViolation'
    elif output['execution'] in ('Cancelled', 'EnvironmentInterrupted'):
        verdict = output['execution']
    elif not complete or not execution_matches or predicted['execution'] == 'Inconclusive':
        verdict = 'Inconclusive'
    else:
        verdict = 'Pass'
    replay_matched = (complete and execution_matches and first_mismatch is None and compatibility_mismatch is None and
                      derived == (expected_failure['invariant'] if expected_failure is not None else None))
    return {'verdict': verdict, 'qualified': verdict == 'Pass', 'replay_matched': replay_matched,
            'complete': complete, 'evidence_overflow': overflow, 'first_mismatch': first_mismatch,
            'compatibility_mismatch': compatibility_mismatch, 'invariant': derived}


def row(key, *, actor='actor-a', state='accepted', expiry=21600*SECOND, lease=None, lease_until=0, payload='payload-a'):
    return {'actor': actor, 'key': key, 'payload_tag': payload, 'state': state,
            'expires_at_us': expiry, 'lease': lease or 'old-' + key, 'lease_until_us': lease_until}


def late_candidate(*, noise=True, positive=False):
    rows = [row(f'accepted-{index}') for index in range(4094 if positive else 4095)]
    rows.append(row('expired-pending', state='pending', expiry=0, lease='expired-lease'))
    commands = []
    commands.append(controlled_command(1, 'new-reservation', now=1, locked_keys=['expired-pending']))
    commands.append(controlled_command(2, 'expired-pending', action='finalize', now=1,
                                       lease='expired-lease', causal_id='op-1'))
    if noise:
        commands.append(controlled_command(7, 'unrelated', actor='actor-b', now=1))
    value = scenario('native-late-finalize-positive' if positive else 'native-late-finalize-4097', commands, rows,
                     actors=('actor-a', 'actor-b') if noise else ('actor-a',))
    # Both rows share the same shard, so explicit SKIP LOCKED survival matters.
    by_label = {entry['label']: entry for entry in value['bindings']['keys']}
    new_key = bytearray.fromhex(by_label['new-reservation']['hex'])
    old_key = bytes.fromhex(by_label['expired-pending']['hex'])
    new_key[8] = old_key[8]
    by_label['new-reservation']['hex'] = new_key.hex()
    return value


def native_cases():
    cases = []
    challenge = str(uuid.UUID('00000000-0000-0000-0000-000000000123'))
    proof = {'challenge_id': challenge, 'nonce': 'synthetic-proof'}
    for allowed in (True, False):
        command = controlled_command(1, guard=synthetic_guard(allowed=allowed, delta=1, proof=proof))
        cases.append(scenario('native-guard-' + ('allowed' if allowed else 'denial'), [command], proofs=[challenge]))
    rows = [row(f'capacity-{index}') for index in range(CAPACITY)]
    rows.append(row('expired-exact', state='pending', expiry=0))
    command = controlled_command(1, 'expired-exact', guard=synthetic_guard(delta=1, proof=proof))
    cases.append(scenario('native-capacity-rollback-proof', [command], rows, proofs=[challenge]))
    for action in ('guard_memory', 'guard_persistent'):
        for allowed in (True, False):
            command = controlled_command(1, action=action, guard=synthetic_guard(allowed=allowed, delta=1, proof=proof))
            cases.append(scenario(f'native-{action}-' + ('allowed' if allowed else 'denied'), [command], proofs=[challenge]))
    for committed in (False, True):
        command = controlled_command(1, cut='commit_unknown', world_commit=committed,
                                     guard=synthetic_guard(delta=1, proof=proof))
        cases.append(scenario(f'native-reservation-unknown-{str(committed).lower()}', [command], proofs=[challenge]))
        guard = controlled_command(1, action='guard_persistent', cut='commit_unknown', world_commit=committed,
                                   guard=synthetic_guard(delta=1, proof=proof))
        cases.append(scenario(f'native-guard-unknown-{str(committed).lower()}', [guard], proofs=[challenge]))
    for cut in ('before_effect_cancel', 'precommit_error', 'commit_cancel', 'receipt_before_cancel'):
        command = controlled_command(1, cut=cut, guard=synthetic_guard(delta=1, proof=proof))
        cases.append(scenario('native-' + cut.replace('_', '-'), [command], proofs=[challenge]))
    for suffix, lease, payload, cut in (('unknown', 'lease-1', 'payload-a', 'commit_unknown'),
                                       ('lost-fence', 'other-lease', 'payload-a', 'none'),
                                       ('wrong-payload', 'lease-1', 'other-payload', 'none'),
                                       ('receipt-cancel', 'lease-1', 'payload-a', 'receipt_before_cancel')):
        commands = [controlled_command(1), controlled_command(2, 'key-1', action='finalize', lease=lease,
                                                             payload=payload, cut=cut, causal_id='op-1')]
        cases.append(scenario('native-finalize-' + suffix, commands))
    for committed in (False, True):
        commands = [controlled_command(1, cut='commit_unknown', world_commit=committed),
                    controlled_command(2, 'independent-key'),
                    controlled_command(3, 'key-1', action='reconcile', lease='lease-1', reconcile_of='op-1')]
        cases.append(scenario('native-reconcile-' + ('pending' if committed else 'missing'), commands))
    for suffix, now in (('before', 21600*SECOND-1), ('at', 21600*SECOND), ('after', 21600*SECOND+1)):
        commands = [controlled_command(1, 'key-1', lease='lease-1', cut='commit_unknown'),
                    controlled_command(2, 'key-1', action='reconcile', lease='lease-1', reconcile_of='op-1', now=now)]
        cases.append(scenario('native-reconcile-accepted-' + suffix, commands, [row('key-1', lease='lease-1')]))
    commands = [controlled_command(1), controlled_command(2, 'key-1', action='finalize', lease='lease-1', causal_id='op-1')]
    commands[0]['times'].update(admission_us=1, actor_policy_us=101)
    commands[1]['times'].update(admission_us=1, actor_policy_us=101, finalize_us=201)
    cases.append(scenario('native-independent-authority-clocks', commands))
    command = controlled_command(1)
    valid = completion_for(command)
    mutations = []
    for key, replacement in (('operation_uuid', str(uuid.UUID(int=1))), ('effect_number', 999),
                             ('generation', 2), ('attempt', 2), ('action', 'finalize')):
        item = copy.deepcopy(valid)
        item[key] = replacement
        mutations.append(item)
    for key in ('account_bare', 'normalized_target', 'origin_id', 'normalized_payload',
                'pow_intent_payload', 'subject', 'actors', 'proof'):
        item = copy.deepcopy(valid)
        item['guard'][key] = ['other-actor'] if key == 'actors' else proof if key == 'proof' else 'other-value'
        mutations.append(item)
    command['schedule']['completions'] = mutations + [valid, copy.deepcopy(valid)]
    cases.append(scenario('native-malformed-stale-duplicate-completions', [command]))
    command = controlled_command(1)
    command['schedule']['completions'][0]['attempt'] += 1
    cases.append(scenario('native-no-valid-completion', [command]))
    command = controlled_command(1, 'key-existing', action='finalize', lease='new-lease')
    wrong = completion_for(command)
    wrong['lease'] = 'wrong-lease'
    command['schedule']['completions'].insert(0, wrong)
    cases.append(scenario('native-finalize-fence-and-accepted-idempotency', [command], [row('key-existing')]))
    command = controlled_command(1, 'new-key')
    expired = row('expired-cleanup', expiry=0)
    value = scenario('native-bounded-cleanup-charge-release', [command], [expired])
    keymap = {entry['label']: entry for entry in value['bindings']['keys']}
    material = bytearray.fromhex(keymap['new-key']['hex'])
    material[8] = bytes.fromhex(keymap['expired-cleanup']['hex'])[8]
    keymap['new-key']['hex'] = material.hex()
    cases.append(value)
    cases += [late_candidate(), late_candidate(positive=True)]
    # A lower event budget is legal input but cannot qualify complete evidence.
    budget_case = scenario('native-evidence-event-gap', [controlled_command(1), controlled_command(2)])
    budget_case['budgets']['events'] = 1
    cases.append(budget_case)
    owners = [f'shard-actor-{i}' for i in range(8)]
    rows = [row(f'shard-row-{i}', actor=owners[i // CAPACITY]) for i in range(SHARD_CAPACITY)]
    physical = scenario('native-physical-shard-capacity', [controlled_command(1, 'new-shard-key')], rows,
                        actors=['actor-a'] + owners)
    for entry in physical['bindings']['keys']:
        material = bytearray.fromhex(entry['hex'])
        material[8] = 1
        entry['hex'] = material.hex()
    cases.append(physical)
    return cases


def controlled_cases():
    return [bridge_case(old) for old, _ in stage1_cases()] + native_cases()


def rejection_cases():
    """Fixed concrete parser negatives, distinct from target safety evidence."""
    base = scenario('parser-baseline', [controlled_command(1)])
    cases = []
    def add(name, reason, mutate):
        value = copy.deepcopy(base)
        mutate(value)
        cases.append({'id': name, 'bytes': canonical(value), 'reason': reason})
    add('wrong-schema', 'schema', lambda x: x.update(schema='wrong-v9'))
    add('wrong-model', 'schema', lambda x: x.update(model='other'))
    add('wrong-adapter', 'schema', lambda x: x.update(adapter='real_adapter'))
    add('wrong-binding-version', 'schema', lambda x: x.update(binding_version='other'))
    add('unknown-root', 'fields', lambda x: x.update(unknown=True))
    add('unknown-initial', 'fields', lambda x: x['initial'].update(unknown=True))
    add('unknown-binding', 'fields', lambda x: x['bindings']['keys'][0].update(unknown=True))
    add('unknown-command', 'fields', lambda x: x['commands'][0].update(unknown=True))
    add('unknown-times', 'fields', lambda x: x['commands'][0]['times'].update(unknown=True))
    add('unknown-guard', 'fields', lambda x: x['commands'][0]['guard'].update(unknown=True))
    add('unknown-schedule', 'fields', lambda x: x['commands'][0]['schedule'].update(unknown=True))
    add('unknown-completion', 'fields', lambda x: x['commands'][0]['schedule']['completions'][0].update(unknown=True))
    add('unknown-budget', 'fields', lambda x: x['budgets'].update(unknown=True))
    add('boolean-time', 'fields', lambda x: x['commands'][0]['times'].update(admission_us=True))
    add('negative-time', 'command', lambda x: x['commands'][0]['times'].update(admission_us=-1))
    add('invalid-key-hex', 'binding', lambda x: x['bindings']['keys'][0].update(hex='00'))
    add('duplicate-key-binding', 'binding', lambda x: x['bindings']['keys'].append(copy.deepcopy(x['bindings']['keys'][0])))
    add('unknown-actor', 'command', lambda x: x['commands'][0].update(actor='unbound'))
    add('forward-causal', 'command', lambda x: x['commands'][0].update(causal_id='op-2'))
    add('empty-commands', 'budget', lambda x: x.update(commands=[]))
    add('budget-zero', 'budget', lambda x: x['budgets'].update(events=0))
    add('unknown-cut', 'schedule', lambda x: x['commands'][0]['schedule'].update(cut='process_kill'))
    add('native-exact-only-cleanup', 'schedule', lambda x: x['commands'][0]['schedule'].update(cleanup='exact_key_only'))
    add('missing-completions', 'schedule', lambda x: x['commands'][0]['schedule'].update(completions=[]))
    for field in ('stage1',):
        add('missing-' + field, 'fields', lambda x, field=field: x.pop(field))
    for field in ('causal_id', 'reconcile_of'):
        add('missing-command-' + field, 'fields', lambda x, field=field: x['commands'][0].pop(field))
    for field in ('origin_id', 'proof'):
        add('missing-guard-' + field, 'fields', lambda x, field=field: x['commands'][0]['guard'].pop(field))
    add('missing-completion-reconcile', 'fields', lambda x: x['commands'][0]['schedule']['completions'][0].pop('reconcile_of'))
    add('missing-completion-proof', 'fields', lambda x: x['commands'][0]['schedule']['completions'][0]['guard'].pop('proof'))
    cases += [{'id': 'duplicate-field', 'bytes': '{"schema":"a","schema":"b"}', 'reason': 'invalid_json'},
              {'id': 'malformed-json', 'bytes': '{', 'reason': 'invalid_json'},
              {'id': 'nonfinite-json', 'bytes': '{"x":NaN}', 'reason': 'invalid_json'}]
    return cases


LIMITATIONS = [
    'Controlled in-memory storage and scripted guard outcomes; shared Rust coordinator and locked-row decisions execute',
    'No SQL, locks, cryptographic verification, real clocks, wire, services or process-loss conformance',
    'World commit is injected adapter state; CommitCallEntered is caller knowledge, not proof COMMIT bytes were sent',
    'Exact-key-only cleanup is limited to the unchanged Stage1 bridge; native bounded cleanup uses declared skip-locked keys',
    'Late-finalize active4097 is a conditional model/source candidate with cleanup-survival premise, not a proven live product bug',
    'Reservation and finalization only; outer cancellation ownership, durable-message write, route, ACK and recovery remain Stage3',
]


def expected_output(value):
    """Independent exact expected bytes/shape, never passed to the Rust runner."""
    prediction = predict(value)
    projection, compatibility, events, complete = [], [], 0, True
    for index, event in enumerate(prediction['projection']):
        events += 1 + len(value['commands'][index]['schedule']['completions'])
        if events > value['budgets']['events'] or len(canonical(projection).encode()) + len(canonical(event).encode()) > max(0, value['budgets']['evidence_bytes']-2048):
            complete = False
            break
        projection.append(event)
        if value['stage1']:
            compatibility.append(prediction['compatibility_projection'][index])
    terminal = complete and prediction['terminal']
    output = {'schema': OUTPUT_SCHEMA, 'adapter': ADAPTER, 'model': MODEL, 'scenario_id': value['scenario_id'],
              'input_sha256': digest(value), 'execution': prediction['execution'] if terminal else 'Inconclusive',
              'terminal': terminal, 'evidence_complete': complete, 'projection': projection,
              'coordinators_finished': complete and prediction['coordinators_finished'],
              'observation_failure': None,
              'compatibility_projection': compatibility if value['stage1'] else None, 'limitations': LIMITATIONS.copy()}
    while len(canonical(output).encode()) > value['budgets']['evidence_bytes']:
        require(output['projection'], 'root_evidence_budget')
        output['projection'].pop()
        if output['compatibility_projection'] is not None:
            output['compatibility_projection'].pop()
        output.update(evidence_complete=False, terminal=False, coordinators_finished=False, execution='Inconclusive')
    return output


def verify_late_premise(value):
    maps = parse_scenario(value)
    commands = value['commands']
    begin = next((c for c in commands if c['operation_id'] == 'op-1'), None)
    finalize = next((c for c in commands if c['operation_id'] == 'op-2'), None)
    require(begin is not None and finalize is not None and commands.index(begin) < commands.index(finalize), 'late_causal_commands')
    require(begin['action'] == 'reserve' and finalize['action'] == 'finalize' and finalize['causal_id'] == begin['operation_id'], 'late_causal_link')
    require(begin['actor'] == finalize['actor'] and begin['key'] != finalize['key'] and
            begin['schedule']['cut'] == finalize['schedule']['cut'] == 'none', 'late_identity_cut')
    require(begin['schedule']['cleanup'] == 'bounded_skip_locked' and finalize['key'] in begin['schedule']['locked_keys'] and
            shard(maps, begin['key']) == shard(maps, finalize['key']), 'late_cleanup_survival')
    target = next((r for r in value['initial']['rows'] if r['key'] == finalize['key']), None)
    require(target is not None and target['state'] == 'pending' and target['actor'] == begin['actor'] and
            target['lease'] == finalize['lease'] and target['payload_tag'] == finalize['payload_tag'] and
            target['expires_at_us'] <= begin['times']['admission_us'], 'late_retained_pending')
    require(sum(r['actor'] == begin['actor'] and r['state'] == 'accepted' and
                r['expires_at_us'] > finalize['times']['finalize_us'] for r in value['initial']['rows']) == 4095,
            'late_exact_initial_occupancy')
    return begin, finalize


def prune_bindings(value):
    """Remove unused fixture material only; preserve the concrete used bindings."""
    result = copy.deepcopy(value)
    needed = {'actors': set(), 'keys': set(), 'payloads': set(), 'leases': set()}
    items = result['initial']['rows'] + result['commands'] + [completion for c in result['commands'] for completion in c['schedule']['completions']]
    for item in items:
        for category, key in (('actors', 'actor'), ('keys', 'key'), ('payloads', 'payload_tag'), ('leases', 'lease')):
            needed[category].add(item[key])
        needed['keys'].update(item.get('candidates', []))
        if 'schedule' in item:
            needed['keys'].update(item['schedule']['locked_keys'])
    for category in needed:
        result['bindings'][category] = [b for b in result['bindings'][category] if b['label'] in needed[category]]
    result['initial']['actor_sequences'] = {name: seq for name, seq in result['initial']['actor_sequences'].items() if name in needed['actors']}
    return result


def shrink_counterexample(value, binary, *, expected_provenance, directory, root=ROOT):
    """Reexecute every tested reduction; no modeled candidate is observed evidence."""
    verify_late_premise(value)
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    attempts = []
    def execute_candidate(candidate, name):
        path = directory / (name + '.input.json')
        path.write_text(canonical(candidate) + '\n')
        execution = run_saved_input(path, binary, expected_provenance=expected_provenance, root=root)
        require(execution['returncode'] == 0, 'shrink_runner_rejected')
        result = evaluate(candidate, execution['output'], expected_failure=expected_counterexample(candidate))
        saved = {'input': candidate, 'execution': execution, 'evaluation': result}
        (directory / (name + '.execution.json')).write_text(canonical(saved) + '\n')
        attempts.append(saved)
        return saved
    original = execute_candidate(value, 'original')
    require(original['evaluation']['replay_matched'] and original['evaluation']['verdict'] == 'InvariantViolation', 'shrink_original_mismatch')
    reduced = copy.deepcopy(value)
    for command in list(reduced['commands']):
        if command['operation_id'] in ('op-1', 'op-2'):
            continue
        candidate = copy.deepcopy(reduced)
        candidate['commands'] = [c for c in candidate['commands'] if c['operation_id'] != command['operation_id']]
        candidate = prune_bindings(candidate)
        try:
            verify_late_premise(candidate)
        except InvalidScenario:
            continue
        execution = execute_candidate(candidate, f'candidate-{len(attempts)}')
        invariant = execution['evaluation']['invariant']
        # The invariant's complete event and all semantic fields stay exact.
        original_invariant = original['evaluation']['invariant']
        same = invariant is not None and all(invariant[key] == original_invariant[key] for key in ('id', 'class', 'cut', 'location'))
        if same:
            same = invariant['output'] == original_invariant['output']
        if execution['evaluation']['replay_matched'] and same:
            reduced = candidate
    # Positive control removes one accepted row, preserving cleanup and both commands.
    positive = copy.deepcopy(reduced)
    accepted = next(r for r in positive['initial']['rows'] if r['actor'] == 'actor-a' and r['state'] == 'accepted')
    positive['initial']['rows'].remove(accepted)
    positive = prune_bindings(positive)
    control = execute_candidate(positive, 'positive-control')
    require(control['evaluation']['verdict'] == 'Pass' and control['evaluation']['replay_matched'], 'shrink_positive_control')
    final = execute_candidate(reduced, 'reduced')
    require(final['evaluation']['replay_matched'], 'shrink_final_mismatch')
    result = {'schema': 'northstar-controlled-shrink-v1', 'original': original, 'attempts': attempts,
              'reduced': final, 'positive_control': control,
              'scope': 'Bounded deletion of independent commands; every candidate and positive control reruns shared Rust. No global minimality claim.'}
    (directory / 'shrink.json').write_text(canonical(result) + '\n')
    return result


def _safe_file(directory, name):
    require(type(name) is str and re.fullmatch(r'[a-zA-Z0-9_.-]+', name), 'corpus_file_name')
    return Path(directory) / name


def record_corpus(directory, binary, *, expected_provenance, root=ROOT):
    """Record actual Rust outputs beside their complete concrete saved inputs."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    check_current_provenance(binary, expected_provenance, root)
    manifest = {'schema': CORPUS_SCHEMA, 'provenance': copy.deepcopy(expected_provenance),
                'scope': LIMITATIONS.copy(), 'cases': [], 'rejections': [], 'shrink_file': 'shrink/shrink.json'}
    for value in controlled_cases():
        name = value['scenario_id']
        input_name, output_name = name + '.input.json', name + '.execution.json'
        path = _safe_file(directory, input_name)
        path.write_text(canonical(value) + '\n')
        executed = run_saved_input(path, binary, expected_provenance=expected_provenance, root=root)
        require(executed['returncode'] == 0, 'declared_case_rejected:' + name)
        expected = expected_output(value)
        require(executed['output'] == expected, 'rust_oracle_mismatch:' + name + ':' + canonical(stage1.first_mismatch(expected['projection'], executed['output'].get('projection', []))))
        failure = expected_counterexample(value)
        evaluation = evaluate(value, executed['output'], expected_failure=failure)
        _safe_file(directory, output_name).write_text(canonical(executed) + '\n')
        manifest['cases'].append({'id': name, 'input_file': input_name, 'input_sha256': digest(value),
                                  'execution_file': output_name, 'output_sha256': digest(executed['output']),
                                  'expected_failure': failure, 'evaluation': evaluation})
    for rejection in rejection_cases():
        input_name = 'reject-' + rejection['id'] + '.input.json'
        path = _safe_file(directory, input_name)
        path.write_text(rejection['bytes'])
        executed = run_saved_input(path, binary, expected_provenance=expected_provenance, root=root)
        expected = {'schema': REJECTION_SCHEMA, 'class': 'InvalidScenario', 'reason': rejection['reason']}
        require(executed['returncode'] == 2 and executed['output'] == expected, 'rejection_mismatch:' + rejection['id'])
        output_name = 'reject-' + rejection['id'] + '.execution.json'
        _safe_file(directory, output_name).write_text(canonical(executed) + '\n')
        manifest['rejections'].append({'id': rejection['id'], 'input_file': input_name,
                                       'input_file_sha256': sha256_file(path), 'execution_file': output_name,
                                       'expected_rejection': expected})
    shrink_counterexample(late_candidate(), binary, expected_provenance=expected_provenance, directory=directory / 'shrink', root=root)
    check_current_provenance(binary, expected_provenance, root)
    (directory / 'corpus.json').write_text(canonical(manifest) + '\n')
    return {'cases': len(manifest['cases']), 'rejections': len(manifest['rejections']), 'recorded': True,
            'scope': 'Actual controlled Rust only; no real adapter qualification'}


def replay_corpus(directory, binary, *, expected_provenance, root=ROOT):
    """Reexecute saved concrete input files; saved outputs never replace execution."""
    directory = Path(directory)
    manifest = read_json(directory / 'corpus.json')
    fields(manifest, 'schema provenance scope cases rejections shrink_file', 'controlled_corpus')
    require(manifest['schema'] == CORPUS_SCHEMA and manifest['scope'] == LIMITATIONS and
            manifest['provenance'] == expected_provenance, 'corpus_provenance')
    cases, rejections = controlled_cases(), rejection_cases()
    require(len(manifest['cases']) == len(cases) and len(manifest['rejections']) == len(rejections), 'corpus_case_set')
    check_current_provenance(binary, expected_provenance, root)
    for saved, source in zip(manifest['cases'], cases):
        fields(saved, 'id input_file input_sha256 execution_file output_sha256 expected_failure evaluation', 'saved_case')
        require(saved['id'] == source['scenario_id'] and saved['input_sha256'] == digest(source), 'corpus_case_identity')
        input_path = _safe_file(directory, saved['input_file'])
        value = read_json(input_path)
        require(value == source, 'saved_input_differs_from_fixed_fixture')
        prior = read_json(_safe_file(directory, saved['execution_file']))
        fields(prior, 'command returncode wall_ms input_file_sha256 stdout_sha256 output provenance', 'saved_execution')
        require(prior['provenance'] == expected_provenance and prior['returncode'] == 0 and
                prior['input_file_sha256'] == sha256_file(input_path) and
                saved['output_sha256'] == digest(prior['output']), 'saved_execution_identity')
        require(saved['expected_failure'] == expected_counterexample(value), 'saved_counterexample_changed')
        executed = run_saved_input(input_path, binary, expected_provenance=expected_provenance, root=root)
        require(executed['returncode'] == 0 and executed['output'] == prior['output'] == expected_output(value),
                'saved_rust_reexecution_mismatch')
        evaluation = evaluate(value, executed['output'], expected_failure=saved['expected_failure'])
        require(evaluation == saved['evaluation'], 'saved_evaluation_changed')
    for saved, source in zip(manifest['rejections'], rejections):
        fields(saved, 'id input_file input_file_sha256 execution_file expected_rejection', 'saved_rejection')
        require(saved['id'] == source['id'], 'rejection_case_identity')
        input_path = _safe_file(directory, saved['input_file'])
        require(input_path.read_text() == source['bytes'] and sha256_file(input_path) == saved['input_file_sha256'], 'rejection_input_changed')
        expected = {'schema': REJECTION_SCHEMA, 'class': 'InvalidScenario', 'reason': source['reason']}
        prior = read_json(_safe_file(directory, saved['execution_file']))
        executed = run_saved_input(input_path, binary, expected_provenance=expected_provenance, root=root)
        require(executed['returncode'] == prior['returncode'] == 2 and
                executed['output'] == prior['output'] == saved['expected_rejection'] == expected, 'rejection_reexecution_mismatch')
    require(manifest['shrink_file'] == 'shrink/shrink.json', 'shrink_path')
    shrink = read_json(directory / manifest['shrink_file'])
    fields(shrink, 'schema original attempts reduced positive_control scope', 'shrink')
    require(shrink['schema'] == 'northstar-controlled-shrink-v1' and shrink['original']['input'] == late_candidate(), 'shrink_original')
    verify_late_premise(shrink['reduced']['input'])
    require(len(shrink['reduced']['input']['commands']) < len(shrink['original']['input']['commands']), 'shrink_not_reduced')
    for index, saved in enumerate(shrink['attempts']):
        fields(saved, 'input execution evaluation', 'shrink_execution')
        value = saved['input']
        with tempfile.TemporaryDirectory(prefix='northstar-replay-shrink-') as scratch:
            path = Path(scratch) / 'input.json'
            path.write_text(canonical(value) + '\n')
            executed = run_saved_input(path, binary, expected_provenance=expected_provenance, root=root)
        failure = expected_counterexample(value)
        require(executed['returncode'] == 0 and executed['output'] == saved['execution']['output'] == expected_output(value), 'shrink_reexecution_mismatch')
        require(evaluate(value, executed['output'], expected_failure=failure) == saved['evaluation'], 'shrink_evaluation_changed')
    require(shrink['reduced'] in shrink['attempts'] and shrink['positive_control'] in shrink['attempts'] and
            shrink['positive_control']['evaluation']['verdict'] == 'Pass', 'shrink_control')
    check_current_provenance(binary, expected_provenance, root)
    return {'replay_matched': True, 'cases': len(cases), 'rejections': len(rejections),
            'shrink_executions': len(shrink['attempts']), 'scope': 'Actual controlled Rust reexecution only'}
