"""Pure Stage 1 admission fixture contract, not a production-shared core.

Inputs contain precomputed SYNTHETIC admission keys, payload tags and leases.
This does not model MAC derivation, proof consumption, rate-limit actor state,
shard capacity, locks, durable-message commit, routing or real adapter behavior.
Only the explicit SQL-domain clock is controlled; no OS/Tokio clock is paused.
Prediction is never substituted for supplied observations. No I/O at import.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from dataclasses import asdict, dataclass

SCHEMA = 'northstar-admission-scenario-v1'
MODEL = 'admission-fixture-v1'
EVIDENCE_SCHEMA = 'northstar-admission-evidence-v1'
CAPACITY = 4096
SECOND = 1_000_000
POLICY = {'actor_capacity': CAPACITY, 'accepted_ttl_us': 21600 * SECOND,
          'pending_ttl_us': 1800 * SECOND, 'lease_us': 60 * SECOND}
VERDICTS = ('Pass', 'InvariantViolation', 'InvalidScenario',
            'EnvironmentInterrupted', 'Inconclusive', 'Cancelled')
MAX_BYTES = 8 * 1024 * 1024
MAX_ITEMS = 20000
MAX_TIME = 9_000_000_000_000_000
LIMITATIONS = [
    'Stage 1 synthetic model/fixture contract; not production-shared Rust evidence',
    'Precomputed synthetic keys/payload tags do not prove production MAC compatibility',
    'Proof consumption, rate-limit state, cryptography, shard capacity and SQL concurrency are not modeled',
    'Physical retained counts model exact-key cleanup only; SQL also has bounded shard/background cleanup',
    'Late-finalize 4097 assumes its expired pending row survives cleanup; live reachability remains unproved',
    'Normal fixture preflight covers actor retention for the fresh two-actor offered workload, not every guard/queue/archive/shard limit',
    'Unknown means reservation transaction knowledge only, never durable-message commit',
    'No SQL, wire, process-loss, resource endurance or real elapsed TTL qualification',
]


class InvalidScenario(ValueError):
    """Invalid or unsupported input, never a product invariant failure."""


def require(value, message):
    if not value:
        raise InvalidScenario(message)


def fields(value, names, label):
    require(type(value) is dict and set(value) == set(names.split()),
            f'{label}: exact fields required ({names})')


def integer(value, label, minimum=0, maximum=MAX_TIME):
    require(type(value) is int and minimum <= value <= maximum,
            f'{label}: bounded integer required')
    return value


def label(value, name):
    require(type(value) is str and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}', value),
            f'{name}: synthetic label required')
    return value


def array(value, name, maximum=MAX_ITEMS):
    require(type(value) is list and len(value) <= maximum, f'{name}: bounded array required')
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def bounded(value, maximum=MAX_BYTES):
    try:
        require(len(canonical(value).encode()) <= maximum, 'serialized evidence/input budget exceeded')
    except (TypeError, ValueError, RecursionError) as error:
        raise InvalidScenario('bounded JSON required') from error


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def read_json(path):
    """Strict bounded JSON, including duplicate fields and NaN rejection."""
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON field')
            result[key] = value
        return result
    with open(path, 'rb') as stream:
        data = stream.read(MAX_BYTES + 1)
    require(len(data) <= MAX_BYTES, 'input byte budget exceeded')
    try:
        return json.loads(data, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(InvalidScenario('non-finite JSON')))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise InvalidScenario('invalid JSON') from error


@dataclass(frozen=True)
class Row:
    actor: str
    key: str
    payload_tag: str
    state: str
    expires_at_us: int
    lease: str
    lease_until_us: int


@dataclass(frozen=True)
class Command:
    operation_id: str
    effect_id: str
    causal_id: str | None
    attempt: int
    time_us: int
    action: str
    kind: str
    actor: str
    key: str
    payload_tag: str
    lease: str
    cut: str


@dataclass(frozen=True)
class Scenario:
    source: dict
    actors: tuple[str, ...]
    rows: tuple[Row, ...]
    commands: tuple[Command, ...]


ROW_FIELDS = 'actor key payload_tag state expires_at_us lease lease_until_us'
COMMAND_FIELDS = 'operation_id effect_id causal_id attempt time_us action kind actor key payload_tag lease cut'
BUDGET_FIELDS = 'domain_us wall_ms steps events evidence_bytes memory_bytes files'


def parse_scenario(value):
    bounded(value)
    fields(value, 'schema model scenario_id purpose policy clock actors initial_rows commands budgets termination seed', 'scenario')
    require(value['schema'] == SCHEMA and value['model'] == MODEL, 'unsupported scenario/model version')
    label(value['scenario_id'], 'scenario_id')
    require(value['purpose'] in ('normal', 'capacity', 'replay', 'ttl', 'lease', 'unknown'), 'unsupported purpose')
    fields(value['policy'], 'actor_capacity accepted_ttl_us pending_ttl_us lease_us', 'policy')
    for key, expected in POLICY.items():
        integer(value['policy'][key], key)
        require(value['policy'][key] == expected, 'policy drift')
    fields(value['clock'], 'domain unit start_us', 'clock')
    require(value['clock']['domain'] == 'sql_model' and value['clock']['unit'] == 'microsecond', 'unsupported clock')
    start = integer(value['clock']['start_us'], 'clock.start_us')
    fields(value['budgets'], BUDGET_FIELDS, 'budgets')
    for key, limit in value['budgets'].items():
        integer(limit, 'budget.' + key, 0 if key == 'files' else 1,
                MAX_BYTES if key == 'evidence_bytes' else MAX_TIME)
    require(value['budgets']['steps'] <= MAX_ITEMS and value['budgets']['events'] <= MAX_ITEMS,
            'step/event hard bound exceeded')
    fields(value['termination'], 'after_commands terminal_required', 'termination')
    require(value['termination']['after_commands'] == 'complete' and value['termination']['terminal_required'] is True,
            'unsupported termination contract')
    if value['seed'] is not None:
        integer(value['seed'], 'seed')
    actors = tuple(label(actor, 'actor') for actor in array(value['actors'], 'actors', 64))
    require(actors and len(set(actors)) == len(actors), 'missing/duplicate actor')
    rows, keys = [], set()
    for item in array(value['initial_rows'], 'initial_rows'):
        fields(item, ROW_FIELDS, 'row')
        for key in ('actor', 'key', 'payload_tag', 'lease'):
            label(item[key], 'row.' + key)
        require(item['actor'] in actors and item['key'] not in keys, 'unknown actor/duplicate admission key')
        require(item['state'] in ('pending', 'accepted'), 'invalid row state')
        integer(item['expires_at_us'], 'row expiry', -MAX_TIME)
        integer(item['lease_until_us'], 'row lease expiry', -MAX_TIME)
        keys.add(item['key'])
        rows.append(Row(**item))
    operations, effects, commands, previous = set(), set(), [], start
    for item in array(value['commands'], 'commands'):
        fields(item, COMMAND_FIELDS, 'command')
        for key in ('operation_id', 'effect_id', 'actor', 'key', 'payload_tag', 'lease'):
            label(item[key], 'command.' + key)
        require(item['actor'] in actors, 'unknown command actor')
        require(item['operation_id'] not in operations and item['effect_id'] not in effects,
                'duplicate operation/effect identity')
        if item['causal_id'] is not None:
            label(item['causal_id'], 'causal_id')
        require(item['causal_id'] is None or item['causal_id'] in operations, 'dangling or forward causal identity')
        integer(item['attempt'], 'attempt', 1, MAX_ITEMS)
        now = integer(item['time_us'], 'command time')
        require(now >= previous and now - start <= value['budgets']['domain_us'], 'domain time order/budget violated')
        require(item['action'] in ('reserve', 'finalize'), 'unsupported action')
        require(item['kind'] in ('direct', 'muc', 'mix'), 'unsupported message kind')
        require(item['cut'] in ('none', 'before_effect_cancel', 'reservation_commit_unknown'), 'unsupported semantic cut')
        require(item['cut'] != 'reservation_commit_unknown' or item['action'] == 'reserve', 'Unknown is reservation-only')
        if commands:
            require(commands[-1].cut == 'none', 'continuation after cancellation/Unknown is unsupported; never blind retry')
        operations.add(item['operation_id'])
        effects.add(item['effect_id'])
        commands.append(Command(**item))
        previous = now
    require(commands and len(commands) <= value['budgets']['steps'], 'missing commands/step budget exceeded')
    require(len(commands) <= value['budgets']['events'], 'planned event budget exceeded')
    return Scenario(copy.deepcopy(value), actors, tuple(rows), tuple(commands))


def _counts(rows, actor, now):
    owned = [row for row in rows.values() if row.actor == actor]
    return sum(row.expires_at_us > now for row in owned), len(owned)


def predict(value):
    """Selected SQL predicate model. Expiry is not GC; model reserve cleans its exact key.

    Finalize deliberately has no expiry predicate or fresh capacity check. This
    is source semantics, not evidence that a late-finalize product bug is live.
    Bounded shard/background cleanup is deliberately outside this model, so
    physical retained count is not a full SQL adapter conformance projection.
    """
    scenario = parse_scenario(value)
    rows = {row.key: row for row in scenario.rows}
    events = []
    for command in scenario.commands:
        c, now = command, command.time_us
        before = rows.copy()
        row = rows.get(c.key)
        domain, effect, execution = None, 'Confirmed', 'Completed'
        uncertain = 0
        if c.cut == 'before_effect_cancel':
            domain, effect, execution = 'NotRequested', 'NotRequested', 'Cancelled'
        elif c.action == 'reserve':
            if row is not None and row.expires_at_us <= now:
                del rows[c.key]
                row = None
            if row is not None:
                if row.actor != c.actor or row.payload_tag != c.payload_tag:
                    domain = 'Conflict'
                elif row.state == 'accepted':
                    domain = 'ReplayAccepted'
                elif row.lease_until_us > now:
                    domain = 'InProgress'
                else:
                    domain = 'Proceed'
                    rows[c.key] = Row(row.actor, row.key, row.payload_tag, 'pending',
                                      row.expires_at_us, c.lease, now + POLICY['lease_us'])
            elif _counts(rows, c.actor, now)[0] >= CAPACITY:
                domain = 'CapacityLimited'
            elif c.cut == 'reservation_commit_unknown':
                domain, effect, uncertain = 'Unknown', 'Unknown', 1
            else:
                domain = 'Proceed'
                rows[c.key] = Row(c.actor, c.key, c.payload_tag, 'pending',
                                  now + POLICY['pending_ttl_us'], c.lease, now + POLICY['lease_us'])
            require(c.cut != 'reservation_commit_unknown' or domain == 'Unknown',
                    'Unknown fixture supports only a fresh reservation with available capacity')
            if domain in ('Conflict', 'CapacityLimited'):
                # Expired exact-key cleanup is inside this transaction too.
                rows = before
            elif domain == 'Unknown':
                # No COMMIT receipt: both original rows and the tentative
                # deletion/insertion remain possible. Do not confirm deletion.
                rows = before
        else:
            require(row is None or row.actor == c.actor, 'finalize actor must identify the actual row owner')
            if row is None:
                domain = 'Missing'
            elif row.payload_tag != c.payload_tag:
                domain = 'Conflict'
            elif row.state == 'accepted':
                domain = 'AlreadyAccepted'  # SQL checks this before lease equality.
            elif row.lease != c.lease:
                domain = 'LeaseLost'
            else:
                domain = 'Accepted'
                rows[c.key] = Row(row.actor, row.key, row.payload_tag, 'accepted',
                                  now + POLICY['accepted_ttl_us'], row.lease, row.lease_until_us)
        active, retained = _counts(rows, c.actor, now)
        row = rows.get(c.key)
        events.append({
            'schema_version': 1, 'operation_id': c.operation_id, 'effect_id': c.effect_id,
            'causal_id': c.causal_id, 'attempt': c.attempt, 'time_us': now,
            'transition': c.action, 'actor': c.actor, 'key': c.key, 'kind': c.kind,
            'execution': execution, 'domain': domain, 'effect_status': effect,
            'active_min': active, 'active_max': active + uncertain,
            'retained_min': retained, 'retained_max': retained + (uncertain if row is None or row.actor != c.actor else 0),
            'row_state': 'Unconfirmed' if uncertain else row.state if row else 'Absent',
            'expires_at_us': row.expires_at_us if row and not uncertain else None,
            'lease': row.lease if row and not uncertain else None,
        })
    bounded(events, scenario.source['budgets']['evidence_bytes'])
    return {'origin': 'prediction', 'scenario_sha256': digest(value), 'projection': events,
            'limitations': LIMITATIONS.copy()}


def preflight_normal(value):
    """Conservative real-fixture bound, independent of declared model outcomes.

    Initial accepted rows expire by SQL time. ALL initial pending rows, even
    currently expired ones, occupy a slot through the run: surviving rows may
    finalize late. New identities also stay charged while finalization time is
    unobserved. This deliberately cannot qualify a long steady-state TTL run.
    """
    scenario = parse_scenario(value)
    require(value['purpose'] == 'normal', 'normal preflight requires normal purpose')
    require(all(c.action == 'reserve' and c.cut == 'none' for c in scenario.commands),
            'real-fixture preflight accepts offered reserves only, not declared resolution/faults')
    rows = {row.key: row for row in scenario.rows}
    held = {actor: set() for actor in scenario.actors}
    peaks = {actor: sum(row.actor == actor and (row.state == 'pending' or row.expires_at_us > value['clock']['start_us'])
                        for row in scenario.rows) for actor in scenario.actors}
    require(all(count <= CAPACITY for count in peaks.values()), 'initial conservative actor occupancy exceeds capacity')
    for c in scenario.commands:
        # Accepted rows can expire. Pending rows cannot be credited as free.
        row = rows.get(c.key)
        if row is not None and row.state == 'accepted' and row.expires_at_us <= c.time_us:
            del rows[c.key]
            row = None
        if row is not None:
            require(row.actor == c.actor and row.payload_tag == c.payload_tag,
                    f'{c.operation_id}: exact identity/actor/payload conflict in normal workload')
        elif c.key not in held[c.actor]:
            # Keep synthetic identity/payload mapping for replay/conflict checks.
            rows[c.key] = Row(c.actor, c.key, c.payload_tag, 'pending', MAX_TIME, c.lease, MAX_TIME)
            held[c.actor].add(c.key)
        count = sum(item.actor == c.actor and (item.state == 'pending' or item.expires_at_us > c.time_us)
                    for item in rows.values())
        peaks[c.actor] = max(peaks[c.actor], count)
        require(count <= CAPACITY,
                f'{c.operation_id}: normal workload exceeds actor capacity ({count}>{CAPACITY})')
    return {'verdict': 'Pass', 'scope': 'conservative actor-retention preflight only; guard/queue/archive/shard bounds not qualified',
            'scenario_sha256': digest(value), 'maximum_held_per_actor': peaks,
            'initial_pending_retention': 'held_through_run',
            'new_identity_retention': 'held_until_observed_resolution_not_assumed',
            'predicted_is_observed': False}


EVENT_FIELDS = ('schema_version operation_id effect_id causal_id attempt time_us transition actor key kind '
                'execution domain effect_status active_min active_max retained_min retained_max row_state expires_at_us lease')
DOMAINS = ('Proceed', 'ReplayAccepted', 'InProgress', 'CapacityLimited', 'Conflict', 'Unknown',
           'NotRequested', 'Missing', 'AlreadyAccepted', 'LeaseLost', 'Accepted')


def validate_projection(events, scenario):
    array(events, 'projection')
    for event in events:
        fields(event, EVENT_FIELDS, 'projection event')
        integer(event['schema_version'], 'event schema', 1, 1)
        for key in ('operation_id', 'effect_id', 'actor', 'key'):
            label(event[key], key)
        if event['causal_id'] is not None:
            label(event['causal_id'], 'causal_id')
        integer(event['attempt'], 'event attempt', 1, MAX_ITEMS)
        integer(event['time_us'], 'event time')
        for key in ('active_min', 'active_max', 'retained_min', 'retained_max'):
            integer(event[key], key, 0, MAX_ITEMS * 2)
        require(event['active_min'] <= event['active_max'] <= event['retained_max'] and
                event['retained_min'] <= event['retained_max'], 'invalid projected count interval')
        require(event['transition'] in ('reserve', 'finalize') and event['kind'] in ('direct', 'muc', 'mix'), 'invalid event transition/kind')
        require(event['execution'] in ('Completed', 'Cancelled') and event['domain'] in DOMAINS and
                event['effect_status'] in ('Confirmed', 'Unknown', 'NotRequested'), 'invalid semantic event class')
        require(event['row_state'] in ('pending', 'accepted', 'Absent', 'Unconfirmed'), 'invalid projected row state')
        if event['expires_at_us'] is not None:
            integer(event['expires_at_us'], 'projected expiry', -MAX_TIME)
        if event['lease'] is not None:
            label(event['lease'], 'projected synthetic lease')
    bounded(events)


def validate_invariant(value, scenario):
    if value is None:
        return
    fields(value, 'id class location', 'invariant')
    label(value['id'], 'invariant id')
    label(value['location'], 'invariant location')
    require(value['class'] in ('Safety', 'ReplayDivergence', 'Responsibility'), 'unsupported invariant class')
    require(value['location'] in {c.operation_id for c in scenario.commands}, 'invariant location is not a concrete command')


def first_mismatch(expected, actual):
    for index in range(max(len(expected), len(actual))):
        want = expected[index] if index < len(expected) else None
        got = actual[index] if index < len(actual) else None
        if want != got:
            return {'index': index, 'expected': want, 'actual': got}
    return None


def derive_invariant(predicted, actual, scenario):
    """The supported Stage 1 invariant is exact replay projection equality.

    No caller-provided invariant label is authority. Later production-shared
    domain invariants need their own independently checked rules.
    """
    mismatch = first_mismatch(predicted[:len(actual)], actual)
    if mismatch is None:
        return None
    index = min(mismatch['index'], len(scenario.commands) - 1)
    return {'id': 'projection-mismatch', 'class': 'ReplayDivergence',
            'location': scenario.commands[index].operation_id}


def evaluate(value, actual, expected_failure=None, *, expected_provenance):
    """Check SUPPLIED evidence. Missing/partial evidence never becomes predicted.

    An expected counterexample matches replay only with its exact projection AND
    independently derived invariant id/class/location. Its semantic verdict is
    still InvariantViolation, never qualified Pass. Malformed input is rejected;
    runtime evidence overflow/missing terminal is Inconclusive unless the saved
    prefix already establishes a violation. Provenance is bound by the caller's
    trusted expected identity, not by the evidence's self-declaration.
    """
    scenario = parse_scenario(value)
    predicted = predict(value)
    fields(actual, 'schema origin scenario_sha256 projection invariant execution terminal evidence_complete '
           'wall_ms peak_memory_bytes files cleanup provenance', 'actual evidence')
    require(actual['schema'] == EVIDENCE_SCHEMA and actual['origin'] in ('supplied_synthetic', 'observed_adapter'),
            'actual must be separately supplied evidence, never prediction')
    require(actual['scenario_sha256'] == digest(value), 'actual evidence belongs to another concrete scenario')
    require(type(actual['projection']) is list, 'projection must be an array')
    captured = []
    captured_bytes = len(canonical({**actual, 'projection': []}).encode())
    for event in actual['projection'][:scenario.source['budgets']['events']]:
        validate_projection([event], scenario)
        event_bytes = len(canonical(event).encode())
        if captured_bytes + event_bytes > scenario.source['budgets']['evidence_bytes']:
            break
        captured.append(event)
        captured_bytes += event_bytes
    overflow = len(captured) < len(actual['projection'])
    actual = {**actual, 'projection': captured}
    validate_invariant(actual['invariant'], scenario)
    expected_projection = predicted['projection']
    expected_invariant = None
    if expected_failure is not None:
        fields(expected_failure, 'projection invariant', 'expected failure')
        validate_projection(expected_failure['projection'], scenario)
        validate_invariant(expected_failure['invariant'], scenario)
        require(len(expected_failure['projection']) == len(predicted['projection']), 'expected failure must contain exact full projection')
        derived = derive_invariant(predicted['projection'], expected_failure['projection'], scenario)
        require(derived is not None and expected_failure['invariant'] == derived,
                'expected invariant must be independently derived from its concrete counterexample')
        expected_projection, expected_invariant = expected_failure['projection'], derived
    require(actual['execution'] in ('Completed', 'EnvironmentInterrupted', 'Cancelled'), 'unsupported execution result')
    require(type(actual['terminal']) is bool and type(actual['evidence_complete']) is bool, 'terminal/completeness must be booleans')
    for key in ('wall_ms', 'peak_memory_bytes', 'files'):
        integer(actual[key], key)
    fields(actual['cleanup'], 'status independent owned remaining', 'cleanup')
    cleanup = actual['cleanup']
    require(cleanup['status'] in ('NotRequired', 'Clean', 'Incomplete') and type(cleanup['independent']) is bool,
            'invalid cleanup status')
    for key in ('owned', 'remaining'):
        for resource in array(cleanup[key], 'cleanup.' + key, 128):
            label(resource, 'synthetic resource id')
        require(len(set(cleanup[key])) == len(cleanup[key]), 'duplicate cleanup resource')
    require(set(cleanup['remaining']) <= set(cleanup['owned']), 'cleanup remaining resource not owned')
    require(cleanup['status'] != 'NotRequired' or not cleanup['owned'], 'owned resources require cleanup evidence')
    require(cleanup['status'] != 'Clean' or not cleanup['remaining'], 'clean result retains resources')
    fields(actual['provenance'], 'source_sha256 runner model adapter', 'provenance')
    require(type(actual['provenance']['source_sha256']) is str and
            re.fullmatch('[a-f0-9]{64}', actual['provenance']['source_sha256']), 'invalid source fingerprint')
    label(actual['provenance']['runner'], 'runner')
    require(actual['provenance']['model'] == MODEL and actual['provenance']['adapter'] in ('synthetic_fixture', 'real_adapter'),
            'unsupported provenance model/adapter')
    require((actual['origin'] == 'supplied_synthetic') == (actual['provenance']['adapter'] == 'synthetic_fixture'),
            'evidence origin/adapter mismatch')
    fields(expected_provenance, 'source_sha256 runner model adapter', 'expected provenance')
    require(actual['provenance'] == expected_provenance, 'evidence does not match trusted source/runner/model/adapter provenance')
    overflow = overflow or len(canonical(actual).encode()) > scenario.source['budgets']['evidence_bytes']
    mismatch = first_mismatch(predicted['projection'], actual['projection'])
    # Missing suffix under interruption/gaps is an evidence gap, not a fabricated
    # product failure. Preserve a known mismatch within the observed prefix.
    prefix_mismatch = first_mismatch(predicted['projection'][:len(actual['projection'])], actual['projection'])
    derived_invariant = derive_invariant(predicted['projection'], actual['projection'], scenario)
    reported_matches = actual['invariant'] == derived_invariant
    complete = (actual['terminal'] and actual['evidence_complete'] and
                len(actual['projection']) == len(predicted['projection']) and not overflow)
    budget_ok = (actual['wall_ms'] <= value['budgets']['wall_ms'] and
                 actual['peak_memory_bytes'] <= value['budgets']['memory_bytes'] and
                 actual['files'] <= value['budgets']['files'])
    if prefix_mismatch is not None or not reported_matches:
        verdict = 'InvariantViolation'
    elif actual['execution'] != 'Completed':
        verdict = actual['execution']
    elif not complete or not budget_ok:
        verdict = 'Inconclusive'
    elif mismatch is not None:
        verdict = 'InvariantViolation'
    elif any(event['execution'] == 'Cancelled' for event in actual['projection']):
        verdict = 'Cancelled'
    else:
        verdict = 'Pass'
    cleanup_ok = cleanup['status'] in ('NotRequired', 'Clean') and cleanup['independent'] and not cleanup['remaining']
    replay_matched = (complete and budget_ok and actual['execution'] == 'Completed' and reported_matches and
                      first_mismatch(expected_projection, actual['projection']) is None and
                      derived_invariant == expected_invariant)
    return {'verdict': verdict, 'qualified': verdict == 'Pass' and cleanup_ok,
            'replay_matched': replay_matched, 'evidence_overflow': overflow,
            'first_mismatch': mismatch, 'invariant_expected': expected_invariant,
            'invariant_actual': derived_invariant, 'invariant_reported': actual['invariant'], 'expected_refusals':
            sum(event['domain'] in ('CapacityLimited', 'Conflict', 'InProgress', 'LeaseLost', 'Missing')
                for event in predicted['projection']),
            'cleanup': copy.deepcopy(cleanup), 'prediction': predicted, 'actual': copy.deepcopy(actual)}


def scenario(name, commands, rows=(), actors=('actor-a',), purpose='normal'):
    """Construct concrete synthetic input; generated commands, not just seed, are saved."""
    return {'schema': SCHEMA, 'model': MODEL, 'scenario_id': name, 'purpose': purpose,
            'policy': POLICY.copy(), 'clock': {'domain': 'sql_model', 'unit': 'microsecond', 'start_us': 0},
            'actors': list(actors), 'initial_rows': [asdict(row) if isinstance(row, Row) else row for row in rows],
            'commands': [asdict(command) if isinstance(command, Command) else command for command in commands],
            'budgets': {'domain_us': 100000 * SECOND, 'wall_ms': 10000, 'steps': MAX_ITEMS,
                        'events': MAX_ITEMS, 'evidence_bytes': MAX_BYTES, 'memory_bytes': 256 * 1024 * 1024, 'files': 0},
            'termination': {'after_commands': 'complete', 'terminal_required': True}, 'seed': None}


def command(number, key=None, *, actor='actor-a', payload='payload-a', action='reserve',
            kind='direct', time_us=0, lease=None, cut='none', causal_id=None):
    return Command(f'op-{number}', f'effect-{number}', causal_id, 1, time_us, action, kind,
                   actor, key or f'key-{number}', payload, lease or f'lease-{number}', cut)


def mixed_workload(seconds):
    """Concrete conservative offered upper bound of the existing two-second fixture.

    Each round has A direct, B direct, A MUC; every tenth adds A no-store
    direct (still admission-rated). Real I/O can reduce rounds, never raise this
    bound because the existing harness paces each round from its start time.
    """
    require(type(seconds) in (int, float) and math.isfinite(seconds) and 0 < seconds <= 7200,
            'mixed workload duration must be finite and in (0,7200]')
    commands = []
    for round_index in range(math.ceil(seconds / 2)):
        now = round_index * 2 * SECOND
        kinds = [('actor-a', 'direct', 'ab'), ('actor-b', 'direct', 'ba'), ('actor-a', 'muc', 'group')]
        if (round_index + 1) % 10 == 0:
            kinds.append(('actor-a', 'direct', 'nostore'))
        for actor, kind, suffix in kinds:
            key = f'round-{round_index + 1}-{suffix}'
            commands.append(command(len(commands) + 1, key, actor=actor, kind=kind,
                                    payload='payload-' + key, time_us=now))
    return scenario('mixed-traffic-offered-upper-bound', commands, actors=('actor-a', 'actor-b'))
