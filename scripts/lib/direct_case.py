"""Independent Stage3 oracle source, currently incomplete.

Native/None literal construction and inspection do not enable a partial fixed16
profile. Full transaction/transport fixture evaluation, build-record validation
and complete profile preflight remain incomplete. Runner entry points fail
closed until the whole selected profile is implemented.

The eventual oracle must derive expectations from the literal Case and declared
adapter contracts before opening output. A child verdict or saved transcript is
never an expected-output source. Planned cancellations remain unqualified;
normative Safety precedes fixture comparison for both executable artifacts.
"""
import copy
import hashlib
import json
import re
import xml.etree.ElementTree as ET


CASE_SCHEMA = 'northstar-direct-case-v1'
EVIDENCE_SCHEMA = 'northstar-direct-evidence-v1'
ADAPTER = 'local-direct-controlled-v1'
ENTRY = 'xmpp::protocol::messaging::saved_case::replay_saved_case'
FIXED16 = 'stage3-direct-fixed16-v1'
FIXED4 = 'stage3-direct-no-flush-fixed4-v1'
ALICE = 'alice@example.test/device'
BOB = 'bob@example.test/phone'
DOMAIN = 'example.test'
AT_UTC = '1970-01-01T00:01:40Z'
TARGET_XML = "<message type='chat' id='m' to='bob@example.test/phone'><body>x</body><origin-id xmlns='urn:xmpp:sid:0' id='o'/></message>"
BARE_XML = TARGET_XML.replace("to='bob@example.test/phone'", "to='bob@example.test'")
UNRATED_XML = "<message to='bob@example.test'><store xmlns='urn:xmpp:hints'/></message>"
PLAIN_XML = "<message id='plain'/>"
ORIGINAL_TRIPLES = {
    'C01': ((101, 10101, 20101),), 'C02': ((201, 10201, 20201),),
    'C03': ((301, 10301, 20301), (302, 10302, 20302)),
    'C04': ((401, 10401, 20401),), 'C05': ((501, 10501, 20501),),
    'C06': ((601, 10601, 20601),), 'C07': ((701, 10701, 20701), (702, 10702, 20702)),
}
NATIVE_STATE_FIELDS = ('original preparation managed_by_sm fence_entered returned_fence writer_entered '
                       'writer_result write_decision ack ack_returned terminal')


class DirectCaseInvalid(ValueError):
    """Malformed bounded Case/evidence, distinct from an observed Safety fault."""


def _need(condition, reason):
    if not condition:
        raise DirectCaseInvalid(reason)


def _fields(value, names):
    _need(type(value) is dict, 'object_required')
    expected = set(names.split())
    _need(not set(value) - expected, 'UnknownField:' + names)
    _need(set(value) == expected, 'required_fields:' + names)
    return value


def _text(value, maximum=4096):
    _need(type(value) is str, 'string')
    try:
        _need(len(value.encode('utf-8')) <= maximum, 'string_bytes')
    except UnicodeError as error:
        raise DirectCaseInvalid('string_utf8') from error


def _integer(value, maximum=2 ** 32 - 1):
    _need(type(value) is int and 0 <= value <= maximum, 'bounded_integer')


def _boolean(value):
    _need(type(value) is bool, 'boolean')


def _enum(value, values):
    _need(type(value) is str and value in values.split(), 'enum:' + values)


def _id(value):
    _text(value, 36)
    _need(re.fullmatch(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', value) is not None,
          'canonical_uuid')


def _hex(value, size=None, maximum=8192):
    _text(value, maximum)
    _need(len(value) % 2 == 0 and re.fullmatch('[a-f0-9]*', value) is not None and
          (size is None or len(value) == size * 2), 'lowercase_hex')


def _nullable(value, check):
    if value is not None:
        check(value)


def _array(value, check, maximum=256):
    _need(type(value) is list and len(value) <= maximum, 'bounded_array')
    for item in value:
        check(item)


def _uuid(integer):
    # The reviewed explicit integer table expands to complete saved UUID bytes;
    # no Rust output, random generator or replay-time seed supplies identities.
    value = f'{integer:032x}'
    return '-'.join((value[:8], value[8:12], value[12:16], value[16:20], value[20:]))


def _encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('utf-8')


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def _c2s(message, claim):
    return {'kind': 'C2s', 'recipient_id': _uuid(2), 'message_id': message, 'claim_id': claim}


def _source(value, *, c2s=False):
    _need(type(value) is dict, 'source_object')
    if value.get('kind') == 'C2s':
        _fields(value, 'kind recipient_id message_id claim_id')
        _id(value['recipient_id'])
        _id(value['message_id'])
        _nullable(value['claim_id'], _id)
    else:
        _need(not c2s and value.get('kind') == 'Mix', 'source_variant')
        _fields(value, 'kind delivery_id lease_token')
        _id(value['delivery_id'])
        _id(value['lease_token'])


def _transaction(value):
    _need(type(value) is dict, 'transaction_object')
    if value.get('kind') == 'Stored':
        _fields(value, 'kind recipient_id delivery_id archive_ids live_claim_id')
        _id(value['recipient_id'])
        _id(value['delivery_id'])
        _nullable(value['live_claim_id'], _id)
        _array(value['archive_ids'], _id, 2)
    elif value.get('kind') == 'Replay':
        _fields(value, 'kind archive_ids')
        _array(value['archive_ids'], _id, 2)
    else:
        _fields(value, 'kind')
        _enum(value['kind'], 'AccountUnavailable')


def _fence(value):
    _fields(value, 'admission_key_hex payload_mac_hex lease_token')
    _hex(value['admission_key_hex'], 32)
    _hex(value['payload_mac_hex'], 32)
    _id(value['lease_token'])


def _slot(value):
    _fields(value, 'xml source')
    _text(value['xml'])
    _nullable(value['source'], _source)


def _write_script(value):
    _fields(value, 'chunk_limit fail_after_accepted_bytes flush')
    _integer(value['chunk_limit'], 4096)
    _need(value['chunk_limit'] > 0, 'positive_chunk_limit')
    _nullable(value['fail_after_accepted_bytes'], lambda item: _integer(item, 1))
    _need(value['fail_after_accepted_bytes'] in (None, 1), 'fixed_short_write')
    _enum(value['flush'], 'Ok Error')


def _base_case(case_id, triples):
    value = {'schema': CASE_SCHEMA, 'case_id': case_id, 'adapter_contract': ADAPTER,
             'identities': {'actor_id': _uuid(1), 'recipient_id': _uuid(2), 'originals': [],
                            'connection_id': _uuid(3), 'sm_session_id': None, 'bosh_session_id': None,
                            'native_claim_id': _uuid(6), 'mix_delivery_id': None, 'mix_old_token': None,
                            'mix_new_token': None, 'replacement_connection_id': None, 'replacement_claim_id': None},
             'originals': [], 'policy': [], 'admission': [], 'direct_repository': [], 'route': [],
             'recipient_owner': {'kind': 'None'}, 'drive': {'kind': 'Complete'}}
    for frame, sender, recipient in triples:
        frame_id, sender_id, recipient_id = _uuid(frame), _uuid(sender), _uuid(recipient)
        value['identities']['originals'].append({'frame_id': frame_id, 'sender_stable_id': sender_id,
                                                'recipient_stable_id': recipient_id})
        value['originals'].append({'frame_id': frame_id, 'xml': TARGET_XML, 'sender_full': ALICE,
                                   'target': BOB, 'at_utc': AT_UTC})
        value['policy'].append({'frame_id': frame_id, 'domain': DOMAIN, 'recipient_bare': BOB.split('/')[0],
                                'encrypted': False, 'sender_archive': False, 'recipient_archive': False,
                                'clustered': True, 'degraded_spool_eligible': False, 'spool_privacy_permits': True})
        value['admission'].append({
            'frame_id': frame_id, 'kind': 'Reserved',
            'fence': {'admission_key_hex': '01' * 32, 'payload_mac_hex': '02' * 32,
                      'lease_token': _uuid(30000 + frame), 'dedupe_digest_hex': '04' * 32},
            'requirement': {'action': 'message', 'step': 0, 'work_factor': 1, 'max_work_factor': 1,
                            'hard_wait_seconds': 0, 'retry_after_seconds': 0, 'cooldown_seconds': 0,
                            'approximate_max_device_seconds': 0, 'notice': ''},
            'begin_commit': 'Complete', 'finalize_commit': 'Complete'})
        value['direct_repository'].append({
            'frame_id': frame_id,
            'transaction': {'kind': 'Stored', 'recipient_id': _uuid(2), 'delivery_id': recipient_id,
                            'archive_ids': [], 'live_claim_id': recipient_id},
            'admitted_mode': 'Live', 'commit': 'Complete', 'completion': {'kind': 'Return', 'mode': 'Live'}})
        value['route'].append({'frame_id': frame_id, 'initial_queue': 'Empty', 'prefill': None,
                               'targets': [], 'health_modes': [], 'remote_primary_returns': [], 'rearm': 'Return'})
    return value


def _native_owner(value, index=-1):
    original = value['identities']['originals'][index]
    value['recipient_owner'] = {'kind': 'Native', 'frame_id': original['frame_id'], 'native': {
        'connection_id': _uuid(3), 'fence': {'returned_source': _c2s(original['recipient_stable_id'], _uuid(6))},
        'write': {'chunk_limit': 4096, 'fail_after_accepted_bytes': None, 'flush': 'Ok'},
        'ack': {'commit': 'Complete', 'disposition': 'Deleted'}}}


def _no_native(value):
    value['identities']['native_claim_id'] = None
    value['identities']['connection_id'] = None


def _fixture(identity, kind, value, verdict, *, raw=None, reason=None):
    data = _encoded(value) if raw is None else raw
    return {'id': identity, 'kind': kind, 'value': copy.deepcopy(value), 'bytes': data,
            'expected_verdict': verdict, 'reason': reason}


def native_fixtures():
    """Ten complete literal inputs for inspection; never a runnable subprofile."""
    values = {name: _base_case(name, triples) for name, triples in ORIGINAL_TRIPLES.items()}
    c01 = values['C01']
    c01['policy'][0].update(clustered=False, sender_archive=True, recipient_archive=True)
    c01['direct_repository'][0]['transaction'].update(
        live_claim_id=None, archive_ids=[_uuid(10101), _uuid(20101)])
    _native_owner(c01)
    c02 = values['C02']
    c02['admission'][0]['finalize_commit'] = 'Error'
    _native_owner(c02)
    c02['recipient_owner']['native']['ack']['commit'] = 'Pending'
    c02['drive'] = {'kind': 'DropNativeAckCommit', 'frame_id': _uuid(201)}
    c03 = values['C03']
    _no_native(c03)
    for index, suffix in enumerate(('a', 'b')):
        c03['originals'][index].update(xml=BARE_XML.replace("id='m'", f"id='m-c03-{suffix}'")
                                      .replace("id='o'", f"id='o-c03-{suffix}'").replace('>x<', f'>x-{suffix}<'),
                                      target=BOB.split('/')[0])
        c03['policy'][index]['degraded_spool_eligible'] = True
        c03['direct_repository'][index]['completion']['mode'] = 'SpoolOnly'
    c03['direct_repository'][0]['admitted_mode'] = 'SpoolOnly'
    c03['direct_repository'][0]['transaction']['live_claim_id'] = None
    c04 = values['C04']
    _no_native(c04)
    c04['direct_repository'][0]['completion'] = {'kind': 'ErrorAfterReceipt'}
    c05 = values['C05']
    _no_native(c05)
    c05['direct_repository'][0]['commit'] = 'Pending'
    c05['drive'] = {'kind': 'DropDirectCommit', 'frame_id': _uuid(501)}
    c06 = values['C06']
    _no_native(c06)
    c06['identities']['connection_id'] = _uuid(3)
    c06['originals'][0].update(xml=BARE_XML, target=BOB.split('/')[0])
    c06['policy'][0]['degraded_spool_eligible'] = True
    c06['route'][0].update(initial_queue='PrefilledPlain',
                           prefill={'kind': 'Plain', 'xml': PLAIN_XML, 'transport_receipt': False},
                           remote_primary_returns=[False], rearm='Pending')
    c06['drive'] = {'kind': 'DropRearm', 'frame_id': _uuid(601)}
    c07 = values['C07']
    c07['originals'][0].update(xml=UNRATED_XML, target=BOB.split('/')[0])
    c07['policy'][0]['degraded_spool_eligible'] = True
    c07['admission'][0] = {'frame_id': _uuid(701), 'kind': 'NotRated'}
    c07['direct_repository'][0]['transaction'] = {'kind': 'Replay', 'archive_ids': []}
    _native_owner(c07)
    c07['recipient_owner']['native']['write'].update(chunk_limit=2, flush='Error')
    # The shared router contract is PostFinalize, PrimaryRoute and (only after
    # completed routing/recovery) AfterRouting. These are literal port replies.
    for name, index in (('C01', 0), ('C02', 0), ('C06', 0), ('C07', 1)):
        values[name]['route'][index]['targets'] = [{'jid': BOB, 'connection_id': _uuid(3)}]
        values[name]['route'][index]['health_modes'] = ['Live'] * (2 if name == 'C06' else 3)
    fixtures = [_fixture(name, 'normal', value, 'Cancelled' if name in ('C02', 'C05', 'C06') else 'Pass')
                for name, value in values.items()]
    raw = _encoded(c01)
    duplicate = b'{"schema":"' + CASE_SCHEMA.encode() + b'",' + raw[1:]
    unknown = copy.deepcopy(c01)
    unknown['extra'] = True
    unbound = copy.deepcopy(c01)
    unbound['direct_repository'][0]['transaction']['recipient_id'] = _uuid(99)
    fixtures.extend((_fixture('R01', 'rejection', None, 'InvalidScenario', raw=duplicate, reason='DuplicateKey'),
                     _fixture('R02', 'rejection', None, 'InvalidScenario', raw=_encoded(unknown), reason='UnknownField'),
                     _fixture('R03', 'rejection', None, 'InvalidScenario', raw=_encoded(unbound), reason='IdentityBinding')))
    return fixtures


def mutation_fixtures():
    original = next(item for item in native_fixtures() if item['id'] == 'C07')
    reduced = copy.deepcopy(original['value'])
    reduced['identities']['originals'].pop(0)
    for name in ('originals', 'policy', 'admission', 'direct_repository', 'route'):
        reduced[name].pop(0)
    positive = copy.deepcopy(reduced)
    positive['recipient_owner']['native']['write']['fail_after_accepted_bytes'] = 1
    return [_fixture('M1', 'shrink', original['value'], 'InvariantViolation', raw=original['bytes']),
            _fixture('M2', 'shrink', reduced, 'InvariantViolation'),
            _fixture('M3', 'shrink', positive, 'Pass'),
            _fixture('M4', 'shrink', reduced, 'InvariantViolation')]


def validate_native_input(value):
    """Closed Native/None Case grammar; roles are input authority, not evidence."""
    _fields(value, 'schema case_id adapter_contract identities originals policy admission direct_repository route recipient_owner drive')
    _need(value['schema'] == CASE_SCHEMA and value['adapter_contract'] == ADAPTER, 'InvalidSchema')
    _text(value['case_id'], 64)
    _need(bool(value['case_id']), 'empty_case_id')
    identities = value['identities']
    _fields(identities, 'actor_id recipient_id originals connection_id sm_session_id bosh_session_id native_claim_id '
            'mix_delivery_id mix_old_token mix_new_token replacement_connection_id replacement_claim_id')
    for name in ('actor_id', 'recipient_id'):
        _id(identities[name])
    for name in set(identities) - {'actor_id', 'recipient_id', 'originals'}:
        _nullable(identities[name], _id)
    _need(type(identities['originals']) is list and 1 <= len(identities['originals']) <= 2, 'original_identity_count')
    for item in identities['originals']:
        _fields(item, 'frame_id sender_stable_id recipient_stable_id')
        for identity in item.values():
            _id(identity)
    frames = [item['frame_id'] for item in identities['originals']]
    _need(len(set(frames)) == len(frames), 'IdentityBinding:duplicate_frame')
    xml_bytes = 0
    for name in ('originals', 'policy', 'admission', 'direct_repository', 'route'):
        _need(type(value[name]) is list and len(value[name]) == len(frames), 'aligned_array')
        for index, item in enumerate(value[name]):
            _need(type(item) is dict and item.get('frame_id') == frames[index], 'IdentityBinding:frame_alignment')
    for index, original in enumerate(value['originals']):
        _fields(original, 'frame_id xml sender_full target at_utc')
        for name in ('xml', 'sender_full', 'target', 'at_utc'):
            _text(original[name])
        xml_bytes += len(original['xml'].encode('utf-8'))
        policy = value['policy'][index]
        _fields(policy, 'frame_id domain recipient_bare encrypted sender_archive recipient_archive clustered '
                'degraded_spool_eligible spool_privacy_permits')
        for name in ('domain', 'recipient_bare'):
            _text(policy[name])
        for name in set(policy) - {'frame_id', 'domain', 'recipient_bare'}:
            _boolean(policy[name])
        admission = value['admission'][index]
        if admission.get('kind') == 'NotRated':
            _fields(admission, 'frame_id kind')
        else:
            _fields(admission, 'frame_id kind fence requirement begin_commit finalize_commit')
            _enum(admission['kind'], 'Reserved')
            _fields(admission['fence'], 'admission_key_hex payload_mac_hex lease_token dedupe_digest_hex')
            for name in ('admission_key_hex', 'payload_mac_hex', 'dedupe_digest_hex'):
                _hex(admission['fence'][name], 32)
            _id(admission['fence']['lease_token'])
            requirement = admission['requirement']
            _fields(requirement, 'action step work_factor max_work_factor hard_wait_seconds retry_after_seconds '
                    'cooldown_seconds approximate_max_device_seconds notice')
            for name in ('action', 'notice'):
                _text(requirement[name])
            _integer(requirement['step'])
            for name in set(requirement) - {'action', 'notice', 'step'}:
                _integer(requirement[name], 2 ** 64 - 1)
            for name in ('begin_commit', 'finalize_commit'):
                _enum(admission[name], 'Complete Pending Error')
        direct = value['direct_repository'][index]
        _fields(direct, 'frame_id transaction admitted_mode commit completion')
        _transaction(direct['transaction'])
        transaction = direct['transaction']
        if transaction['kind'] == 'Stored':
            bound = identities['originals'][index]
            _need(transaction['recipient_id'] == identities['recipient_id'] and
                  transaction['delivery_id'] == bound['recipient_stable_id'] and
                  transaction['live_claim_id'] in (None, bound['recipient_stable_id']), 'IdentityBinding:direct_tuple')
            _need(set(transaction['archive_ids']) <= {bound['sender_stable_id'], bound['recipient_stable_id']},
                  'IdentityBinding:archive_tuple')
        _enum(direct['admitted_mode'], 'Live SpoolOnly')
        _enum(direct['commit'], 'Complete Pending Error')
        completion = direct['completion']
        if type(completion) is dict and completion.get('kind') == 'Return':
            _fields(completion, 'kind mode')
            _enum(completion['mode'], 'Live SpoolOnly')
        else:
            _fields(completion, 'kind')
            _enum(completion['kind'], 'ErrorAfterReceipt')
        route = value['route'][index]
        _fields(route, 'frame_id initial_queue prefill targets health_modes remote_primary_returns rearm')
        _enum(route['initial_queue'], 'Empty PrefilledPlain')
        _need((route['initial_queue'] == 'Empty') == (route['prefill'] is None), 'prefill_presence')
        if route['prefill'] is not None:
            _fields(route['prefill'], 'kind xml transport_receipt')
            _enum(route['prefill']['kind'], 'Plain')
            _text(route['prefill']['xml'])
            xml_bytes += len(route['prefill']['xml'].encode('utf-8'))
            _boolean(route['prefill']['transport_receipt'])
        _need(type(route['targets']) is list and len(route['targets']) <= 4, 'route_target_count')
        for target in route['targets']:
            _fields(target, 'jid connection_id')
            _text(target['jid'])
            _id(target['connection_id'])
            _need(target['connection_id'] == identities['connection_id'], 'IdentityBinding:route_connection')
        _array(route['health_modes'], lambda mode: _enum(mode, 'Live SpoolOnly'), 4)
        _array(route['remote_primary_returns'], _boolean, 4)
        _enum(route['rearm'], 'Return Pending')
    _need(xml_bytes <= 16384 and len(_encoded(value)) <= 65536, 'Limit:input_bytes')
    owner = value['recipient_owner']
    _need(type(owner) is dict, 'owner_object')
    if owner.get('kind') == 'None':
        _fields(owner, 'kind')
        _need(identities['native_claim_id'] is None, 'IdentityBinding:unused_native_claim')
    elif owner.get('kind') == 'Native':
        _fields(owner, 'kind frame_id native')
        _need(owner['frame_id'] in frames, 'IdentityBinding:native_frame')
        native = owner['native']
        _fields(native, 'connection_id fence write ack')
        _id(native['connection_id'])
        _need(native['connection_id'] == identities['connection_id'], 'IdentityBinding:native_connection')
        _fields(native['fence'], 'returned_source')
        _source(native['fence']['returned_source'], c2s=True)
        bound = identities['originals'][frames.index(owner['frame_id'])]
        expected = {'kind': 'C2s', 'recipient_id': identities['recipient_id'],
                    'message_id': bound['recipient_stable_id'], 'claim_id': identities['native_claim_id']}
        _need(native['fence']['returned_source'] == expected, 'IdentityBinding:native_fence')
        _write_script(native['write'])
        _fields(native['ack'], 'commit disposition')
        _enum(native['ack']['commit'], 'Complete Pending Error')
        _enum(native['ack']['disposition'], 'Deleted')
    else:
        raise DirectCaseIncomplete('stage3_transport_input_validator_incomplete')
    for name in ('sm_session_id', 'bosh_session_id', 'mix_delivery_id', 'mix_old_token', 'mix_new_token',
                 'replacement_connection_id', 'replacement_claim_id'):
        _need(identities[name] is None, 'IdentityBinding:unused_owner_role')
    drive = value['drive']
    if type(drive) is dict and drive.get('kind') == 'Complete':
        _fields(drive, 'kind')
    else:
        _fields(drive, 'kind frame_id')
        _enum(drive['kind'], 'DropDirectCommit DropRearm DropNativeAckCommit')
        _need(drive['frame_id'] in frames, 'IdentityBinding:drive_frame')
    return copy.deepcopy(value)


def parse_native_input(raw):
    _need(type(raw) is bytes and len(raw) <= 65536, 'Limit:input_bytes')
    def pairs(items):
        result = {}
        for key, value in items:
            _need(key not in result, 'DuplicateKey')
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(DirectCaseInvalid('nonfinite')))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise DirectCaseInvalid('Malformed') from error
    return validate_native_input(value)


def rejection_reason(raw):
    try:
        parse_native_input(raw)
    except DirectCaseInvalid as error:
        reason = str(error).split(':', 1)[0]
        return reason if reason in ('DuplicateKey', 'UnknownField', 'IdentityBinding', 'InvalidSchema', 'Limit') else 'Malformed'
    return None


def _correlation(value):
    _fields(value, 'operation_id effect generation attempt')
    _id(value['operation_id'])
    for name in ('effect', 'generation', 'attempt'):
        _integer(value[name], 2 ** 64 - 1)


def _admission_commit(value):
    _fields(value, 'correlation scope fact')
    _correlation(value['correlation'])
    _enum(value['scope'], 'RatedBeginNewReservation AdmissionFinalize')
    fact = value['fact']
    _need(type(fact) is dict, 'admission_fact')
    if fact.get('kind') == 'Reserved':
        _fields(fact, 'kind fence')
    else:
        _fields(fact, 'kind fence result')
        _enum(fact['kind'], 'Finalized')
        _enum(fact['result'], 'PendingAccepted')
    _fence(fact['fence'])


def _admission_evidence(value):
    _fields(value, 'correlation started knowledge returned')
    _correlation(value['correlation'])
    _boolean(value['started'])
    knowledge = value['knowledge']
    _need(type(knowledge) is dict, 'admission_knowledge')
    if knowledge.get('kind') == 'NoCommitRequested':
        _fields(knowledge, 'kind')
    elif knowledge.get('kind') == 'CommitCallEntered':
        _fields(knowledge, 'kind prepared')
        _admission_commit(knowledge['prepared'])
    else:
        _fields(knowledge, 'kind receipt')
        _enum(knowledge['kind'], 'ReceiptKnown')
        _admission_commit(knowledge['receipt'])
    returned = value['returned']
    if returned is not None:
        _need(type(returned) is dict, 'admission_returned')
        if returned.get('kind') == 'Proceed':
            _fields(returned, 'kind fence')
            _fence(returned['fence'])
        else:
            _fields(returned, 'kind')
            _enum(returned['kind'], 'AcceptPending Error')


def _direct_prepared(value):
    _fields(value, 'correlation transaction admitted_mode')
    _correlation(value['correlation'])
    _transaction(value['transaction'])
    _enum(value['admitted_mode'], 'Live SpoolOnly')


def _direct_evidence(value):
    _fields(value, 'correlation started knowledge returned preserved_transaction application_error')
    _correlation(value['correlation'])
    _boolean(value['started'])
    _boolean(value['application_error'])
    _nullable(value['preserved_transaction'], _transaction)
    knowledge = value['knowledge']
    _need(type(knowledge) is dict, 'direct_knowledge')
    if knowledge.get('kind') == 'NoCommitRequested':
        _fields(knowledge, 'kind')
    elif knowledge.get('kind') == 'CommitCallEntered':
        _fields(knowledge, 'kind prepared')
        _direct_prepared(knowledge['prepared'])
    else:
        _fields(knowledge, 'kind receipt')
        _enum(knowledge['kind'], 'ReceiptKnown')
        _fields(knowledge['receipt'], 'prepared')
        _direct_prepared(knowledge['receipt']['prepared'])
    returned = value['returned']
    if returned is not None:
        _fields(returned, 'commit mode live_claim_id')
        _enum(returned['mode'], 'Live SpoolOnly')
        _nullable(returned['live_claim_id'], _id)
        commit = returned['commit']
        _need(type(commit) is dict, 'direct_return_commit')
        if commit.get('kind') == 'Stored':
            _fields(commit, 'kind archive_written recipient_id delivery_id')
            _boolean(commit['archive_written'])
            _id(commit['recipient_id'])
            _id(commit['delivery_id'])
        else:
            _fields(commit, 'kind')
            _enum(commit['kind'], 'Replay AccountUnavailable')


def _handoff(value):
    _fields(value, 'correlation source local_call local_accepted last_local_refusal remote prior_remote_uncertain '
            'rearm route_end retired')
    _correlation(value['correlation'])
    _source(value['source'], c2s=True)
    _enum(value['local_call'], 'NotRequested CallEntered Refused Accepted')
    _enum(value['remote'], 'NotRequested CallEntered NoPositiveReceipt AcceptanceReported')
    _enum(value['rearm'], 'NotRequested CallEntered CallReturned')
    _enum(value['route_end'], 'NotStarted Running Returned Dropped')
    _nullable(value['last_local_refusal'], lambda item: _enum(item, 'Full Closed'))
    for name in ('local_accepted', 'prior_remote_uncertain', 'retired'):
        _boolean(value[name])


def _projection(value):
    _fields(value, 'message_type origin_id rated normalized_payload live_xml stored_xml archives')
    _text(value['message_type'])
    _nullable(value['origin_id'], _text)
    _boolean(value['rated'])
    _nullable(value['normalized_payload'], _text)
    _text(value['live_xml'])
    _text(value['stored_xml'])
    def archive(item):
        _fields(item, 'archive_id owner_id peer_jid stanza_id encrypted xml')
        _id(item['archive_id'])
        _id(item['owner_id'])
        _text(item['peer_jid'])
        _nullable(item['stanza_id'], _text)
        _boolean(item['encrypted'])
        _text(item['xml'])
    _array(value['archives'], archive, 2)


def _prepared(value):
    _fields(value, 'actor_id recipient_id delivery_id eligibility encrypted mam_backed archive_ids identity')
    for name in ('actor_id', 'recipient_id', 'delivery_id'):
        _id(value[name])
    _enum(value['eligibility'], 'Eligible LiveOnly')
    for name in ('encrypted', 'mam_backed'):
        _boolean(value[name])
    _array(value['archive_ids'], _id, 2)
    if value['identity'] is not None:
        identity = value['identity']
        _fields(identity, 'authority actor_scope_raw actor_scope target_scope value payload')
        _enum(identity['authority'], 'LocalOrigin')
        for name in ('actor_scope_raw', 'actor_scope', 'target_scope', 'value', 'payload'):
            _text(identity[name])


def _continuation(value):
    _fields(value, 'kind error_type error_condition')
    _enum(value['kind'], 'Live Accepted Reject')
    _nullable(value['error_type'], _text)
    _nullable(value['error_condition'], _text)


def _observations(values, fields, check, counter, *, polls=False, maximum=256):
    _need(type(values) is list and len(values) <= maximum, 'observation_count')
    previous = 0
    for value in values:
        _fields(value, 'seq ' + fields)
        seq = value['seq']
        _integer(seq, 256)
        _need(seq > previous, 'observation_order')
        previous = seq
        counter['seq'].append(seq)
        counter['polls'] += int(polls)
        check(value)


def _polls(values, counter):
    _observations(values, 'result', lambda item: _enum(item['result'], 'Ready Pending'), counter, polls=True, maximum=64)


def _route_evidence(value, counter):
    _fields(value, 'health_reads enqueue dequeued queue_remaining backpressure_disconnected remote_calls rearm_calls handoff')
    def health(item):
        _enum(item['phase'], 'PostFinalize Router')
        _enum(item['mode'], 'Live SpoolOnly')
    _observations(value['health_reads'], 'phase mode', health, counter, maximum=4)
    def enqueue(item):
        _source(item['source'])
        _text(item['xml'])
        _enum(item['result'], 'Accepted Full Closed BindingRejected')
    _observations(value['enqueue'], 'source xml result', enqueue, counter, maximum=4)
    def dequeue(item):
        _nullable(item['source'], _source)
        _text(item['xml'])
    _observations(value['dequeued'], 'source xml', dequeue, counter, maximum=4)
    _array(value['queue_remaining'], _slot, 4)
    _boolean(value['backpressure_disconnected'])
    def remote(item):
        _source(item['source'])
        _nullable(item['returned'], _boolean)
    _observations(value['remote_calls'], 'source returned', remote, counter, maximum=4)
    def rearm(item):
        _source(item['source'])
        _boolean(item['returned'])
    _observations(value['rearm_calls'], 'source returned', rearm, counter, maximum=4)
    _nullable(value['handoff'], _handoff)


def _original_state(value):
    _fields(value, 'begin finalize direct handoff terminal')
    for name in ('begin', 'finalize'):
        _nullable(value[name], _admission_evidence)
    _nullable(value['direct'], _direct_evidence)
    _nullable(value['handoff'], _handoff)
    _nullable(value['terminal'], lambda item: _enum(item, 'Completed BackendFailure TimedOut Cancelled Panicked'))


def _original_evidence(value, counter):
    _fields(value, 'frame_id projection prepared begin finalize direct continuation route terminal prefixes polls')
    _id(value['frame_id'])
    _nullable(value['projection'], _projection)
    _nullable(value['prepared'], _prepared)
    for name in ('begin', 'finalize'):
        _nullable(value[name], _admission_evidence)
    _nullable(value['direct'], _direct_evidence)
    _nullable(value['continuation'], _continuation)
    _route_evidence(value['route'], counter)
    _nullable(value['terminal'], lambda item: _enum(item, 'Completed BackendFailure TimedOut Cancelled Panicked'))
    _observations(value['prefixes'], 'state', lambda item: _original_state(item['state']), counter)
    _polls(value['polls'], counter)


def _native_state(value):
    _fields(value, NATIVE_STATE_FIELDS)
    for name in ('original', 'returned_fence'):
        _nullable(value[name], _source)
    _enum(value['preparation'], 'NotStarted Recording FenceCallEntered Prepared Superseded Failed')
    _nullable(value['managed_by_sm'], _boolean)
    for name in ('fence_entered', 'writer_entered'):
        _boolean(value[name])
    _nullable(value['writer_result'], lambda item: _enum(item, 'FullWrite Failed'))
    _nullable(value['write_decision'], lambda item: _enum(item, 'Written Withhold'))
    _nullable(value['ack_returned'], _boolean)
    _nullable(value['terminal'], lambda item: _enum(item, 'Returned Cancelled Panicked'))
    ack = value['ack']
    _need(type(ack) is dict, 'native_ack_knowledge')
    if ack.get('kind') in ('NotRequested', 'NoCommitRequested'):
        _fields(ack, 'kind')
    else:
        _fields(ack, 'kind fact')
        _enum(ack['kind'], 'CommitCallEntered ReceiptKnown')
        _fields(ack['fact'], 'source disposition')
        _source(ack['fact']['source'])
        _enum(ack['fact']['disposition'], 'Deleted AbsentUnclaimed NoMatchingMix')


def _native_evidence(value, counter):
    _fields(value, 'frame_id connection_id ' + NATIVE_STATE_FIELDS +
            ' write_calls flush_calls ack_calls ownership_receipts write_receipts prefixes polls')
    _id(value['frame_id'])
    _id(value['connection_id'])
    _native_state({name: value[name] for name in NATIVE_STATE_FIELDS.split()})
    def write(item):
        _integer(item['offered_len'], 4096)
        _hex(item['offered_sha256'], 32)
        _hex(item['accepted_bytes_hex'])
        _enum(item['result'], 'Accepted Error Pending')
    _observations(value['write_calls'], 'offered_len offered_sha256 accepted_bytes_hex result', write, counter)
    _observations(value['flush_calls'], 'result', lambda item: _enum(item['result'], 'Ok Error Pending'), counter)
    def ack(item):
        _source(item['source'])
        _nullable(item['returned'], _boolean)
    _observations(value['ack_calls'], 'source returned', ack, counter)
    for name in ('ownership_receipts', 'write_receipts'):
        _observations(value[name], 'result', lambda item: _enum(item['result'], 'Received Empty Closed'), counter)
    _observations(value['prefixes'], 'state', lambda item: _native_state(item['state']), counter)
    _polls(value['polls'], counter)


def validate_native_evidence(value):
    """Types/encoding/order only: an unsafe authorization history stays visible."""
    _fields(value, 'schema entry input_sha256 rejection execution originals recipient')
    _need(value['schema'] == EVIDENCE_SCHEMA and value['entry'] == ENTRY, 'evidence_identity')
    _hex(value['input_sha256'], 32)
    _nullable(value['execution'], lambda item: _enum(item, 'Complete Cancelled'))
    counter = {'seq': [], 'polls': 0}
    if value['rejection'] is not None:
        _fields(value['rejection'], 'class reason')
        _enum(value['rejection']['class'], 'InvalidScenario')
        _enum(value['rejection']['reason'], 'DuplicateKey UnknownField IdentityBinding InvalidSchema Malformed Limit UnsupportedOwner')
        _need(value['execution'] is None and value['originals'] == [] and value['recipient'] is None,
              'rejection_without_owners')
    else:
        _need(value['execution'] is not None and type(value['originals']) is list and
              1 <= len(value['originals']) <= 2, 'semantic_owner_count')
        for original in value['originals']:
            _original_evidence(original, counter)
        recipient = value['recipient']
        _need(type(recipient) is dict, 'recipient_object')
        if recipient.get('kind') == 'None':
            _fields(recipient, 'kind')
        elif recipient.get('kind') == 'Native':
            _fields(recipient, 'kind native')
            _native_evidence(recipient['native'], counter)
        else:
            raise DirectCaseIncomplete('stage3_transport_evidence_validator_incomplete')
    _need(counter['polls'] <= 64 and len(counter['seq']) <= 256 and
          sorted(counter['seq']) == list(range(1, len(counter['seq']) + 1)), 'global_observation_sequence')
    _need(len(_encoded(value)) <= 131072, 'evidence_frame_budget')
    return copy.deepcopy(value)


def _xml(value):
    _text(value)
    _need('<!DOCTYPE' not in value and '<!ENTITY' not in value, 'xml_document_type')
    try:
        element = ET.fromstring(value)
    except (ET.ParseError, ValueError) as error:
        raise DirectCaseInvalid('xml_document') from error
    _need(element.tag == 'message', 'message_root')
    return element


def _tree(element):
    """Compare XML meaning independently of Rust quote/attribute serialization."""
    attributes = dict(element.attrib)
    if element.tag == '{urn:xmpp:delay}delay' and attributes.get('stamp', '').endswith('+00:00'):
        attributes['stamp'] = attributes['stamp'][:-6] + 'Z'
    return (element.tag, tuple(sorted(attributes.items())), element.text or '',
            tuple(_tree(child) for child in element), element.tail or '')


def _bare(jid):
    return jid.split('/', 1)[0]


def _local_stanza_id(element, domain):
    by = _bare(element.get('by', ''))
    return element.tag == '{urn:xmpp:sid:0}stanza-id' and by.rsplit('@', 1)[-1] == domain


def _expected_projection(original, policy, identity, roles):
    captured = _xml(original['xml'])
    routed = copy.deepcopy(captured)
    routed.set('from', original['sender_full'])
    routed.set('to', original['target'])
    sender_bare, target_bare = _bare(original['sender_full']), _bare(original['target'])
    # This closed literal slice has chat body-bearing T/B and bodyless U. It
    # does not claim a general protocol rating policy for arbitrary stanzas.
    body = captured.find('body')
    rated = body is not None
    _need(captured.get('type', 'normal') in ('chat', 'normal'), 'native_literal_message_type')
    normalized = copy.deepcopy(routed)
    normalized.set('from', sender_bare)
    origins = captured.findall('{urn:xmpp:sid:0}origin-id')
    _need(len(origins) <= 1, 'native_literal_origin_count')
    origin_id = origins[0].get('id') if origins else None
    sender_archive = copy.deepcopy(routed)
    ET.SubElement(sender_archive, '{urn:xmpp:sid:0}stanza-id',
                  {'id': identity['sender_stable_id'], 'by': sender_bare})
    live = copy.deepcopy(routed)
    for child in list(live):
        if _local_stanza_id(child, policy['domain']):
            live.remove(child)
    ET.SubElement(live, '{urn:xmpp:sid:0}stanza-id',
                  {'id': identity['recipient_stable_id'], 'by': policy['recipient_bare']})
    if roles['actor_id'] == roles['recipient_id']:
        live = copy.deepcopy(sender_archive)
    stored = copy.deepcopy(live)
    for child in list(stored):
        if child.tag == '{urn:xmpp:delay}delay':
            stored.remove(child)
    ET.SubElement(stored, '{urn:xmpp:delay}delay', {'from': policy['domain'], 'stamp': original['at_utc']})
    archives = []
    if policy['sender_archive']:
        archives.append({'archive_id': identity['sender_stable_id'], 'owner_id': roles['actor_id'],
                         'peer_jid': original['target'], 'stanza_id': captured.get('id'),
                         'encrypted': policy['encrypted'], 'xml': _tree(sender_archive)})
    if policy['recipient_archive'] and roles['actor_id'] != roles['recipient_id']:
        archives.append({'archive_id': identity['recipient_stable_id'], 'owner_id': roles['recipient_id'],
                         'peer_jid': original['sender_full'], 'stanza_id': captured.get('id'),
                         'encrypted': policy['encrypted'], 'xml': _tree(live)})
    payload_identity = None if origin_id is None else {
        'authority': 'LocalOrigin', 'actor_scope_raw': sender_bare, 'actor_scope': sender_bare,
        'target_scope': target_bare, 'value': origin_id, 'payload': _tree(routed)}
    return ({'message_type': captured.get('type', 'normal'), 'origin_id': origin_id, 'rated': rated,
             'normalized_payload': _tree(normalized) if rated else None,
             'live_xml': _tree(live), 'stored_xml': _tree(stored), 'archives': archives},
            {'actor_id': roles['actor_id'], 'recipient_id': roles['recipient_id'],
             'delivery_id': identity['recipient_stable_id'],
             'eligibility': 'Eligible' if policy['degraded_spool_eligible'] and
                            policy['spool_privacy_permits'] else 'LiveOnly',
             'encrypted': policy['encrypted'], 'mam_backed': policy['recipient_archive'],
             'archive_ids': [archive['archive_id'] for archive in archives], 'identity': payload_identity})


def derive_native_ledger(value):
    """Input-only authority/transaction/XML obligations, before output is opened.

    This is an independent ledger of required facts, not a generated Rust DTO.
    Numeric purpose tags identify distinct handles; they are not event order.
    Full transcript/retirement comparison remains a separate incomplete step.
    """
    value = validate_native_input(value)
    roles = value['identities']
    originals = []
    for index, original in enumerate(value['originals']):
        identity, policy = roles['originals'][index], value['policy'][index]
        projection, prepared = _expected_projection(original, policy, identity, roles)
        admission, direct, route = (value[name][index] for name in ('admission', 'direct_repository', 'route'))
        _need(projection['rated'] == (admission['kind'] == 'Reserved'), 'literal_rating_contract')
        def correlation(effect):
            return {'operation_id': original['frame_id'], 'effect': effect, 'generation': 0, 'attempt': 1}
        correlations = dict(begin=correlation(1), finalize=correlation(2), direct=correlation(3), handoff=correlation(4))
        begin = None
        if admission['kind'] == 'Reserved':
            begin = {'correlation': correlations['begin'], 'fence': {name: admission['fence'][name] for name in
                     ('admission_key_hex', 'payload_mac_hex', 'lease_token')}, 'commit': admission['begin_commit']}
        transaction = copy.deepcopy(direct['transaction'])
        returned = direct['completion']['mode'] if direct['commit'] == 'Complete' and direct['completion']['kind'] == 'Return' else None
        finalizes = begin is not None and direct['commit'] == 'Complete' and transaction['kind'] in ('Stored', 'Replay')
        finalize = None if not finalizes else {'correlation': correlations['finalize'],
                                             'fence': copy.deepcopy(begin['fence']), 'commit': admission['finalize_commit']}
        source = None if transaction['kind'] != 'Stored' else {
            'kind': 'C2s', 'recipient_id': transaction['recipient_id'],
            'message_id': transaction['delivery_id'], 'claim_id': transaction['live_claim_id']}
        if direct['commit'] != 'Complete':
            continuation = 'NotReturned' if direct['commit'] == 'Pending' else 'Reject'
            route_action = 'None'
        elif transaction['kind'] == 'Replay':
            continuation, route_action = 'Accepted', 'None'
        elif transaction['kind'] == 'AccountUnavailable':
            continuation, route_action = 'Reject', 'None'
        elif returned != 'Live':
            continuation, route_action = 'Accepted', 'Rearm' if source['claim_id'] is not None else 'None'
        else:
            continuation, route_action = 'Live', 'Queue' if route['initial_queue'] == 'Empty' else 'FullThenRearm'
        originals.append({'frame_id': original['frame_id'], 'projection': projection, 'prepared': prepared,
                          'correlations': correlations, 'begin': begin, 'finalize': finalize,
                          'direct': {'correlation': correlations['direct'], 'transaction': transaction,
                                     'admitted_mode': direct['admitted_mode'], 'commit': direct['commit'],
                                     'returned_mode': returned,
                                     'preserved_transaction': transaction if direct['commit'] == 'Complete' and
                                                              direct['completion']['kind'] == 'ErrorAfterReceipt' else None},
                          'source': source, 'continuation': continuation, 'route_action': route_action,
                          'health_modes': list(route['health_modes']),
                          'remote_returns': list(route['remote_primary_returns']), 'rearm': route['rearm'],
                          'terminal': 'Cancelled' if direct['commit'] == 'Pending' or
                                      (route_action in ('Rearm', 'FullThenRearm') and route['rearm'] == 'Pending') else 'Completed'})
    native = None
    owner = value['recipient_owner']
    if owner['kind'] == 'Native':
        item = next(item for item in originals if item['frame_id'] == owner['frame_id'])
        native = {'frame_id': owner['frame_id'], 'connection_id': owner['native']['connection_id'],
                  'original_source': copy.deepcopy(item['source']),
                  'fenced_source': copy.deepcopy(owner['native']['fence']['returned_source']),
                  'write': copy.deepcopy(owner['native']['write']), 'ack': copy.deepcopy(owner['native']['ack'])}
    return {'originals': originals, 'native': native, 'drive': copy.deepcopy(value['drive'])}


def projection_findings(ledger, payload):
    """Compare independent XML/identity expectations without a Rust serializer."""
    findings = []
    for expected, actual in zip(ledger['originals'], payload['originals']):
        if actual['frame_id'] != expected['frame_id']:
            findings.append('original_frame_identity')
        projection = copy.deepcopy(actual['projection'])
        prepared = copy.deepcopy(actual['prepared'])
        if projection is None or prepared is None:
            findings.append('missing_prepared_projection')
            continue
        for name in ('normalized_payload', 'live_xml', 'stored_xml'):
            if projection[name] is not None:
                projection[name] = _tree(_xml(projection[name]))
        for archive in projection['archives']:
            archive['xml'] = _tree(_xml(archive['xml']))
        if prepared['identity'] is not None:
            prepared['identity']['payload'] = _tree(_xml(prepared['identity']['payload']))
        if projection != expected['projection']:
            findings.append('xml_projection')
        if prepared != expected['prepared']:
            findings.append('prepared_identity')
        expected_live = expected['projection']['live_xml']
        for name in ('enqueue', 'dequeued'):
            for observation in actual['route'][name]:
                if _tree(_xml(observation['xml'])) != expected_live:
                    findings.append('route_xml_projection')
        enqueued = [item['xml'] for item in actual['route']['enqueue'] if item['result'] == 'Accepted']
        dequeued = [item['xml'] for item in actual['route']['dequeued']]
        if dequeued and dequeued != enqueued:
            findings.append('enqueue_dequeue_bytes')
    if len(ledger['originals']) != len(payload['originals']):
        findings.append('original_inventory')
    return findings


def native_safety_findings(value, payload):
    """Normative facts only, identical for baseline and no-flush artifacts.

    This never looks at profile, case name, source/binary hash or child verdict.
    It can expose a truthful unsafe transcript before fixture comparison. It is
    not the still-incomplete full transaction/retirement fixture evaluator.
    """
    ledger = derive_native_ledger(value)  # Always derive authority before output validation.
    validate_native_evidence(payload)
    if payload['rejection'] is not None or payload['recipient']['kind'] != 'Native':
        return []
    native = payload['recipient']['native']
    violations = []
    original = next((item for item in payload['originals'] if item['frame_id'] == native['frame_id']), None)
    dequeued = original['route']['dequeued'] if original is not None else []
    raw = dequeued[0]['xml'].encode('utf-8') if len(dequeued) == 1 else None
    expected = ledger['native']
    for ack in native['ack_calls']:
        target = {'frame_id': native['frame_id'], 'connection_id': native['connection_id'],
                  'owner': 'Tcp', 'source': copy.deepcopy(ack['source'])}
        def violation(identity):
            violations.append({'id': identity, 'class': 'Safety', 'target': copy.deepcopy(target)})
        if expected is None or native['frame_id'] != expected['frame_id'] or native['connection_id'] != expected['connection_id']:
            violation('NativeAckOwnerIdentityMismatch')
        if not native['fence_entered'] or native['returned_fence'] is None or ack['source'] != native['returned_fence']:
            violation('NativeAckWithoutMatchingFence')
        if expected is not None and ack['source'] != expected['fenced_source']:
            violation('NativeAckSourceIdentityMismatch')
        if native['managed_by_sm'] is True:
            violation('NativeAckAfterSmOwnership')
        accepted, consistent, last_accepted_seq = b'', raw is not None, 0
        for write in native['write_calls']:
            if write['seq'] >= ack['seq']:
                continue
            tail = raw[len(accepted):] if raw is not None else b''
            chunk = bytes.fromhex(write['accepted_bytes_hex'])
            consistent = consistent and write['offered_len'] == len(tail) and write['offered_sha256'] == _hash(tail)
            if write['result'] == 'Accepted':
                consistent = consistent and bool(chunk) and tail.startswith(chunk)
                accepted += chunk
                last_accepted_seq = write['seq']
            else:
                consistent = consistent and not chunk
        complete = consistent and accepted == raw and bool(raw)
        if not complete:
            violation('NativeAckWithoutCompleteWrite')
        if not any(last_accepted_seq < item['seq'] < ack['seq'] and item['result'] == 'Ok'
                   for item in native['flush_calls']):
            violation('NativeAckWithoutSuccessfulFlush')
        if native['writer_result'] != 'FullWrite':
            violation('NativeAckWithoutFullWrite')
    return violations


class DirectCaseIncomplete(ValueError):
    """No partial Stage3 corpus or oracle may produce a fixture match."""


def require_implemented():
    raise DirectCaseIncomplete('stage3_literal_corpus_wire_oracle_and_build_record_incomplete')


def validate_provenance(provenance):
    require_implemented()


def check_current_provenance(contract):
    """Future reader checks the external build-record file hash before fields.

    That small record binds source-manifest/compiler/lock/command identities,
    target/features, original/runnable binary identities, exact strip tool and
    flags, and the optional single-statement no-flush ancestry. It never issues
    commands from the record or reads the oversized original executable during
    a saved pass. The runnable executable retains the fixed 128 MiB bound.
    """
    require_implemented()


def fixture_plan(profile_id):
    """Will return only the complete fixed16 or fixed4 literal input inventory."""
    require_implemented()


def evaluate_fixture(fixture, record, payload, profile_id):
    """Will return semantic projection, evaluation, fixture match and stop.

    Structural DTO checks must permit a truthful unsafe ACK transcript to reach
    the independent NativeAckWithoutSuccessfulFlush Safety predicate. Variable
    runtime sequence/time and libtest diagnostics must not enter replay equality.
    """
    require_implemented()


def shrink_relations(observations):
    """Will check the one deletion, exact same-target violations and control."""
    require_implemented()
