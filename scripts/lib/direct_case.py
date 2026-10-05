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
CLIENT_NAMESPACE = 'jabber:client'
TARGET_XML = "<message type='chat' id='m' to='bob@example.test/phone'><body>x</body><origin-id xmlns='urn:xmpp:sid:0' id='o'/></message>"
BARE_XML = TARGET_XML.replace("to='bob@example.test/phone'", "to='bob@example.test'")
UNRATED_XML = "<message to='bob@example.test'><store xmlns='urn:xmpp:hints'/></message>"
PLAIN_XML = "<message id='plain'/>"
MIX_XML = "<message id='mix'/>"
ORIGINAL_TRIPLES = {
    'C01': ((101, 10101, 20101),), 'C02': ((201, 10201, 20201),),
    'C03': ((301, 10301, 20301), (302, 10302, 20302)),
    'C04': ((401, 10401, 20401),), 'C05': ((501, 10501, 20501),),
    'C06': ((601, 10601, 20601),), 'C07': ((701, 10701, 20701), (702, 10702, 20702)),
}
NATIVE_STATE_FIELDS = ('original preparation managed_by_sm fence_entered returned_fence writer_entered '
                       'writer_result write_decision ack ack_returned terminal')
SM_STATE_FIELDS = ('scope binding h_decision knowledge appended restored ownership_applied acknowledged_h_applied '
                   'notification_attempted capacity_completed returned_updated returned_error record_managed_by_sm terminal')


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


def _mix(token):
    return {'kind': 'Mix', 'delivery_id': _uuid(7), 'lease_token': _uuid(token)}


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
            'expected_verdict': verdict, 'reason': reason, 'expected_failure': None}


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
    fixtures = [_fixture('M1', 'shrink', original['value'], 'InvariantViolation', raw=original['bytes']),
                _fixture('M2', 'shrink', reduced, 'InvariantViolation'),
                _fixture('M3', 'shrink', positive, 'Pass'),
                _fixture('M4', 'shrink', reduced, 'InvariantViolation')]
    for index in (0, 1, 3):
        fixtures[index]['expected_failure'] = _native_failure_target(derive_native_ledger(fixtures[index]['value']))
    return fixtures


def _sm_config(*, initial_h):
    return {'session_id': _uuid(4), 'enabled': True, 'resume_allowed': True, 'inbound_h': 2,
            'outbound_h': initial_h, 'acked_h': initial_h, 'resume_timeout_seconds': 60,
            'live_lease_seconds': 30, 'claim_lease_seconds': 10, 'require_same_device': True,
            'max_per_account': 4, 'max_global': 100, 'max_unacked_stanzas': 32,
            'max_unacked_bytes': 16384, 'max_snapshot_bytes': 32768, 'ip_binding': 'none', 'peer_ip': '127.0.0.1',
            'governor': {'max_bytes': 65536, 'max_recovery_bytes': 32768,
                         'max_recovery_jobs': 4, 'max_snapshot_bytes': 32768}}


def owner_fixtures():
    """Closed SM/replacement literals; these do not enable a runnable profile."""
    fixtures = []
    for identity, frame, sender, recipient in (('C08', 801, 10801, 20801), ('C09', 901, 10901, 20901)):
        value = _base_case(identity, ((frame, sender, recipient),))
        value['identities'].update(sm_session_id=_uuid(4), native_claim_id=None)
        value['route'][0].update(targets=[{'jid': BOB, 'connection_id': _uuid(3)}], health_modes=['Live'] * 3)
        pending = identity == 'C09'
        owner = {'kind': 'Sm', 'frame_id': _uuid(frame), 'connection_id': _uuid(3),
                 'config': _sm_config(initial_h=0 if pending else 4294967294), 'extra_items': [],
                 'record_replies': [{'commit': 'Pending' if pending else 'Complete', 'updated': True, 'rotations': []}],
                 'write': {'chunk_limit': 4096, 'fail_after_accepted_bytes': None, 'flush': 'Ok'}, 'ack': None}
        if pending:
            value['drive'] = {'kind': 'DropSmCheckpointCommit', 'frame_id': _uuid(frame)}
        else:
            value['identities'].update(mix_delivery_id=_uuid(7), mix_old_token=_uuid(8), mix_new_token=_uuid(9))
            owner['extra_items'] = [{'kind': 'Plain', 'xml': PLAIN_XML, 'transport_receipt': False},
                                    {'kind': 'Mix', 'xml': MIX_XML, 'source': _mix(8)}]
            owner['record_replies'].extend(({'commit': 'Complete', 'updated': True, 'rotations': []},
                                            {'commit': 'Complete', 'updated': True,
                                             'rotations': [{'previous': _mix(8), 'current': _mix(9)}]}))
            owner['ack'] = {'h': 0, 'reply': {'commit': 'Complete', 'updated': True, 'rotations': []}}
        value['recipient_owner'] = owner
        fixtures.append(_fixture(identity, 'normal', value, 'Cancelled' if pending else 'Pass'))
    value = _base_case('C13', ((1301, 11301, 21301),))
    value['identities'].update(replacement_connection_id=_uuid(11), replacement_claim_id=_uuid(10))
    value['route'][0].update(targets=[{'jid': BOB, 'connection_id': _uuid(3)}], health_modes=['Live'] * 3)
    _native_owner(value)
    old = copy.deepcopy(value['recipient_owner']['native'])
    replacement = copy.deepcopy(old)
    replacement['connection_id'] = _uuid(11)
    replacement['fence']['returned_source'] = _c2s(_uuid(21301), _uuid(10))
    value['recipient_owner'] = {'kind': 'NativeReplacement', 'frame_id': _uuid(1301),
                                'initial_row': _c2s(_uuid(21301), _uuid(21301)), 'old': old,
                                'replacement': replacement, 'replacement_claim_id': _uuid(10)}
    value['drive'] = {'kind': 'ReplaceBeforeOldAckRead', 'frame_id': _uuid(1301)}
    fixtures.append(_fixture('C13', 'normal', value, 'Pass'))
    return fixtures


def _governor(value):
    _fields(value, 'max_bytes max_recovery_bytes max_recovery_jobs max_snapshot_bytes')
    for item in value.values():
        _integer(item)


def _sm_configuration(value):
    _fields(value, 'session_id enabled resume_allowed inbound_h outbound_h acked_h resume_timeout_seconds '
            'live_lease_seconds claim_lease_seconds require_same_device max_per_account max_global '
            'max_unacked_stanzas max_unacked_bytes max_snapshot_bytes ip_binding peer_ip governor')
    _nullable(value['session_id'], _id)
    for name in ('enabled', 'resume_allowed', 'require_same_device'):
        _boolean(value[name])
    for name in ('inbound_h', 'outbound_h', 'acked_h', 'max_per_account', 'max_global', 'max_unacked_stanzas',
                 'max_unacked_bytes', 'max_snapshot_bytes'):
        _integer(value[name])
    for name in ('resume_timeout_seconds', 'live_lease_seconds', 'claim_lease_seconds'):
        _integer(value[name], 2 ** 64 - 1)
    for name in ('ip_binding', 'peer_ip'):
        _text(value[name], 64)
    _governor(value['governor'])


def _rotation(value):
    _fields(value, 'previous current')
    for source in value.values():
        _source(source)
        _need(source['kind'] == 'Mix', 'mix_rotation_source')


def _checkpoint_reply(value):
    _fields(value, 'commit updated rotations')
    _enum(value['commit'], 'Complete Pending Error')
    _boolean(value['updated'])
    _array(value['rotations'], _rotation, 4)


def _fixture_item(value):
    _need(type(value) is dict, 'item_object')
    if value.get('kind') == 'Plain':
        _fields(value, 'kind xml transport_receipt')
        _boolean(value['transport_receipt'])
    else:
        _fields(value, 'kind xml source')
        _enum(value['kind'], 'Mix')
        _source(value['source'])
        _need(value['source']['kind'] == 'Mix', 'mix_item_source')
    _text(value['xml'])


def _native_spec(value):
    _fields(value, 'connection_id fence write ack')
    _id(value['connection_id'])
    _fields(value['fence'], 'returned_source')
    _source(value['fence']['returned_source'], c2s=True)
    _write_script(value['write'])
    _fields(value['ack'], 'commit disposition')
    _enum(value['ack']['commit'], 'Complete Pending Error')
    _enum(value['ack']['disposition'], 'Deleted')


def validate_case_input(value):
    """Closed implemented owner grammar; roles are input authority, not evidence."""
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
    owner = value['recipient_owner']
    _need(type(owner) is dict, 'owner_object')
    used_roles = {'connection_id'}
    if owner.get('kind') == 'None':
        _fields(owner, 'kind')
        _need(identities['native_claim_id'] is None, 'IdentityBinding:unused_native_claim')
    elif owner.get('kind') == 'Native':
        _fields(owner, 'kind frame_id native')
        _need(owner['frame_id'] in frames, 'IdentityBinding:native_frame')
        native = owner['native']
        _native_spec(native)
        _need(native['connection_id'] == identities['connection_id'], 'IdentityBinding:native_connection')
        bound = identities['originals'][frames.index(owner['frame_id'])]
        expected = {'kind': 'C2s', 'recipient_id': identities['recipient_id'],
                    'message_id': bound['recipient_stable_id'], 'claim_id': identities['native_claim_id']}
        _need(native['fence']['returned_source'] == expected, 'IdentityBinding:native_fence')
        used_roles.add('native_claim_id')
    elif owner.get('kind') == 'Sm':
        _fields(owner, 'kind frame_id connection_id config extra_items record_replies write ack')
        _need(owner['frame_id'] in frames, 'IdentityBinding:sm_frame')
        _id(owner['connection_id'])
        _need(owner['connection_id'] == identities['connection_id'], 'IdentityBinding:sm_connection')
        _sm_configuration(owner['config'])
        _need(owner['config']['session_id'] == identities['sm_session_id'], 'IdentityBinding:sm_session')
        _array(owner['extra_items'], _fixture_item, 3)
        xml_bytes += sum(len(item['xml'].encode('utf-8')) for item in owner['extra_items'])
        _need(len(value['originals']) + len(owner['extra_items']) +
              sum(route['prefill'] is not None for route in value['route']) <= 4, 'Limit:item_count')
        _array(owner['record_replies'], _checkpoint_reply, 4)
        _need(len(owner['record_replies']) == 1 + len(owner['extra_items']), 'aligned_record_replies')
        replies = list(owner['record_replies'])
        if owner['ack'] is not None:
            _fields(owner['ack'], 'h reply')
            _integer(owner['ack']['h'])
            _checkpoint_reply(owner['ack']['reply'])
            replies.append(owner['ack']['reply'])
        _write_script(owner['write'])
        used_roles.add('sm_session_id')
        mix_items = [item for item in owner['extra_items'] if item['kind'] == 'Mix']
        if mix_items:
            used_roles.update(('mix_delivery_id', 'mix_old_token', 'mix_new_token'))
            for name in ('mix_delivery_id', 'mix_old_token', 'mix_new_token'):
                _id(identities[name])
            previous = {'kind': 'Mix', 'delivery_id': identities['mix_delivery_id'], 'lease_token': identities['mix_old_token']}
            current = dict(previous, lease_token=identities['mix_new_token'])
            _need(all(item['source'] == previous for item in mix_items), 'IdentityBinding:mix_item')
            _need(all(rotation == {'previous': previous, 'current': current} for reply in replies
                      for rotation in reply['rotations']), 'IdentityBinding:mix_rotation')
        else:
            _need(all(not reply['rotations'] for reply in replies), 'IdentityBinding:rotation_without_mix')
    elif owner.get('kind') == 'NativeReplacement':
        _fields(owner, 'kind frame_id initial_row old replacement replacement_claim_id')
        _need(owner['frame_id'] in frames, 'IdentityBinding:replacement_frame')
        index = frames.index(owner['frame_id'])
        transaction = value['direct_repository'][index]['transaction']
        _source(owner['initial_row'], c2s=True)
        _need(transaction['kind'] == 'Stored' and owner['initial_row'] == {
            'kind': 'C2s', 'recipient_id': transaction['recipient_id'], 'message_id': transaction['delivery_id'],
            'claim_id': transaction['live_claim_id']}, 'IdentityBinding:initial_row')
        for name, connection_role, claim_role in (('old', 'connection_id', 'native_claim_id'),
                                                ('replacement', 'replacement_connection_id', 'replacement_claim_id')):
            _native_spec(owner[name])
            _id(identities[connection_role])
            _id(identities[claim_role])
            _need(owner[name]['connection_id'] == identities[connection_role] and
                  owner[name]['fence']['returned_source'] == dict(owner['initial_row'], claim_id=identities[claim_role]),
                  'IdentityBinding:replacement_native')
        _id(owner['replacement_claim_id'])
        _need(owner['replacement_claim_id'] == identities['replacement_claim_id'] and
              identities['replacement_connection_id'] != identities['connection_id'] and
              identities['replacement_claim_id'] != identities['native_claim_id'], 'IdentityBinding:replacement_roles')
        used_roles.update(('native_claim_id', 'replacement_connection_id', 'replacement_claim_id'))
    else:
        raise DirectCaseIncomplete('stage3_transport_input_validator_incomplete')
    for name in set(identities) - {'actor_id', 'recipient_id', 'originals'} - used_roles:
        _need(identities[name] is None, 'IdentityBinding:unused_owner_role')
    _need(xml_bytes <= 16384 and len(_encoded(value)) <= 65536, 'Limit:input_bytes')
    drive = value['drive']
    if type(drive) is dict and drive.get('kind') == 'Complete':
        _fields(drive, 'kind')
    else:
        _fields(drive, 'kind frame_id')
        _enum(drive['kind'], 'DropDirectCommit DropRearm DropNativeAckCommit DropSmCheckpointCommit ReplaceBeforeOldAckRead')
        _need(drive['frame_id'] in frames, 'IdentityBinding:drive_frame')
    if drive['kind'] in ('DropSmCheckpointCommit', 'ReplaceBeforeOldAckRead'):
        required_owner = 'Sm' if drive['kind'] == 'DropSmCheckpointCommit' else 'NativeReplacement'
        _need(owner['kind'] == required_owner and drive['frame_id'] == owner['frame_id'], 'IdentityBinding:owner_drive')
    if owner['kind'] == 'Sm':
        pending = owner['record_replies'][0]['commit'] == 'Pending'
        _need((drive['kind'] == 'DropSmCheckpointCommit') == pending and
              drive['kind'] in ('Complete', 'DropSmCheckpointCommit'), 'fixed_sm_drive')
        _need(not pending or owner['ack'] is None, 'sm_ack_after_pending_cut')
        _need(all(reply['commit'] != 'Pending' for reply in owner['record_replies'][1:]), 'unsupported_later_sm_cut')
    if owner['kind'] == 'NativeReplacement':
        _need(drive == {'kind': 'ReplaceBeforeOldAckRead', 'frame_id': owner['frame_id']}, 'fixed_replacement_drive')
    return copy.deepcopy(value)


def validate_native_input(value):
    value = validate_case_input(value)
    if value['recipient_owner']['kind'] not in ('None', 'Native'):
        raise DirectCaseIncomplete('native_only_input_validator')
    return value


def parse_case_input(raw):
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
    return validate_case_input(value)


def parse_native_input(raw):
    value = parse_case_input(raw)
    if value['recipient_owner']['kind'] not in ('None', 'Native'):
        raise DirectCaseIncomplete('native_only_input_validator')
    return value


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


def _sm_scope(value):
    _fields(value, 'purpose session_id connection_id inbound_h outbound_h acked_h queued')
    purpose = value['purpose']
    _need(type(purpose) is dict, 'sm_purpose')
    if purpose.get('kind') == 'Acknowledge':
        _fields(purpose, 'kind h')
        _integer(purpose['h'])
    else:
        _fields(purpose, 'kind')
        _enum(purpose['kind'], 'Record Checkpoint')
    _nullable(value['session_id'], _id)
    _id(value['connection_id'])
    for name in ('inbound_h', 'outbound_h', 'acked_h', 'queued'):
        _integer(value[name])


def _sm_binding(value):
    _fields(value, 'session_id connection_id inbound_h outbound_h acked_h whole acknowledged remaining')
    _nullable(value['session_id'], _id)
    _id(value['connection_id'])
    for name in ('inbound_h', 'outbound_h', 'acked_h'):
        _integer(value[name])
    for name in ('whole', 'acknowledged', 'remaining'):
        _array(value[name], lambda source: _nullable(source, _source), 4)


def _sm_fact(value):
    _need(type(value) is dict, 'sm_fact')
    if value.get('kind') == 'Checkpoint':
        _fields(value, 'kind rotations settled')
        _array(value['rotations'], _rotation, 4)
        _array(value['settled'], _source, 4)
    else:
        _fields(value, 'kind deleted absent_unclaimed')
        _enum(value['kind'], 'UnpersistedAck')
        _array(value['deleted'], _source, 4)
        _array(value['absent_unclaimed'], lambda source: _source(source, c2s=True), 4)


def _sm_state(value):
    _fields(value, SM_STATE_FIELDS)
    _sm_scope(value['scope'])
    _nullable(value['binding'], _sm_binding)
    decision = value['h_decision']
    _need(type(decision) is dict, 'sm_h_decision')
    if decision.get('kind') == 'Prefix':
        _fields(decision, 'kind count')
        _integer(decision['count'])
    else:
        _fields(decision, 'kind')
        _enum(decision['kind'], 'NotRequested Invalid')
    knowledge = value['knowledge']
    _need(type(knowledge) is dict, 'sm_knowledge')
    if knowledge.get('kind') in ('CommitCallEntered', 'ReceiptKnown'):
        _fields(knowledge, 'kind fact')
        _sm_fact(knowledge['fact'])
    else:
        _fields(knowledge, 'kind')
        _enum(knowledge['kind'], 'NotRequested NoCommitRequested NoPersistence RollbackCallEntered RollbackKnown')
    for name in ('appended', 'restored', 'ownership_applied', 'notification_attempted', 'returned_error'):
        _boolean(value[name])
    _nullable(value['acknowledged_h_applied'], _integer)
    for name in ('capacity_completed', 'returned_updated', 'record_managed_by_sm'):
        _nullable(value[name], _boolean)
    _nullable(value['terminal'], lambda item: _enum(item, 'Returned Cancelled Panicked'))


def _sm_evidence(value, counter):
    _fields(value, SM_STATE_FIELDS + ' prefixes polls')
    _sm_state({name: value[name] for name in SM_STATE_FIELDS.split()})
    _observations(value['prefixes'], 'state', lambda item: _sm_state(item['state']), counter)
    _polls(value['polls'], counter)


def _mix_handoffs(values, counter):
    def handoff(item):
        _id(item['delivery_id'])
        result = item['result']
        _need(type(result) is dict, 'mix_handoff_result')
        if result.get('kind') in ('SmPersisted', 'BoshPersisted'):
            _fields(result, 'kind session_id')
            _id(result['session_id'])
        elif result.get('kind') == 'SocketFenced':
            _fields(result, 'kind connection_id')
            _id(result['connection_id'])
        else:
            _fields(result, 'kind')
            _enum(result['kind'], 'Empty Closed')
    _observations(values, 'delivery_id result', handoff, counter, maximum=4)


def _row_events(values, counter):
    _need(type(values) is list and len(values) <= 16, 'row_event_count')
    previous = 0
    for value in values:
        _need(type(value) is dict, 'row_event')
        if value.get('kind') == 'Replace':
            _fields(value, 'seq kind recipient_id message_id before_claim_id after_claim_id')
            for name in ('recipient_id', 'message_id', 'before_claim_id', 'after_claim_id'):
                _id(value[name])
        elif value.get('kind') == 'AuthorityRead':
            _fields(value, 'seq kind source current_claim_id matches')
            _source(value['source'], c2s=True)
            _nullable(value['current_claim_id'], _id)
            _boolean(value['matches'])
        else:
            _fields(value, 'seq kind source')
            _enum(value['kind'], 'Delete')
            _source(value['source'], c2s=True)
        _integer(value['seq'], 256)
        _need(value['seq'] > previous, 'row_event_order')
        previous = value['seq']
        counter['seq'].append(value['seq'])


def validate_case_evidence(value):
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
        elif recipient.get('kind') == 'Sm':
            _fields(recipient, 'kind native_writes sm_turns fifo_after outbound_h acked_h mix_handoffs')
            _array(recipient['native_writes'], lambda item: _native_evidence(item, counter), 4)
            _array(recipient['sm_turns'], lambda item: _sm_evidence(item, counter), 5)
            _array(recipient['fifo_after'], _slot, 4)
            _integer(recipient['outbound_h'])
            _integer(recipient['acked_h'])
            _mix_handoffs(recipient['mix_handoffs'], counter)
        elif recipient.get('kind') == 'NativeReplacement':
            _fields(recipient, 'kind old replacement replacement_dequeued row_events row_after')
            _native_evidence(recipient['old'], counter)
            _native_evidence(recipient['replacement'], counter)
            def dequeue(item):
                _nullable(item['source'], _source)
                _text(item['xml'])
            _observations([recipient['replacement_dequeued']], 'source xml', dequeue, counter, maximum=1)
            _row_events(recipient['row_events'], counter)
            _nullable(recipient['row_after'], lambda item: _source(item, c2s=True))
        else:
            raise DirectCaseIncomplete('stage3_transport_evidence_validator_incomplete')
    _need(counter['polls'] <= 64 and len(counter['seq']) <= 256 and
          sorted(counter['seq']) == list(range(1, len(counter['seq']) + 1)), 'global_observation_sequence')
    _need(len(_encoded(value)) <= 131072, 'evidence_frame_budget')
    return copy.deepcopy(value)


def validate_native_evidence(value):
    value = validate_case_evidence(value)
    if value['recipient'] is not None and value['recipient']['kind'] not in ('None', 'Native'):
        raise DirectCaseIncomplete('native_only_evidence_validator')
    return value


def _xml(value, *, projected=False):
    _text(value)
    _need('<!DOCTYPE' not in value and '<!ENTITY' not in value, 'xml_document_type')
    try:
        element = ET.fromstring(value)
    except (ET.ParseError, ValueError) as error:
        raise DirectCaseInvalid('xml_document') from error
    expected_root = '{' + CLIENT_NAMESPACE + '}message' if projected else 'message'
    allowed = ('message', '{' + CLIENT_NAMESPACE + '}message') if projected is None else (expected_root,)
    _need(element.tag in allowed, 'projected_message_namespace' if projected else 'original_message_root')
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


def _fixed_client_view(captured):
    """Model default client namespace insertion for the fixed T/B/U literals.

    Their original root/body names are unqualified and they contain no empty
    namespace resets. Explicit SID/hint namespaces stay intact. Actual output
    namespaces are compared exactly; this never normalizes them away.
    """
    view = copy.deepcopy(captured)
    for element in view.iter():
        if not element.tag.startswith('{'):
            element.tag = '{' + CLIENT_NAMESPACE + '}' + element.tag
    return view


def _expected_projection(original, policy, identity, roles):
    if re.search(r"""\bxmlns\s*=\s*(['"])\s*\1""", original['xml']):
        raise DirectCaseIncomplete('namespace_reset_outside_fixed_literal_subset')
    captured = _xml(original['xml'])
    routed = _fixed_client_view(captured)
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
    Transcript comparison is separate from this input-only derivation.
    """
    return _derive_sender_ledger(validate_native_input(value))


def _derive_sender_ledger(value):
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


def _sm_native_state(source, *, pending=False):
    return {'original': copy.deepcopy(source), 'preparation': 'Recording' if pending else 'Prepared',
            'managed_by_sm': None if pending else source is not None, 'fence_entered': False, 'returned_fence': None,
            'writer_entered': not pending, 'writer_result': None if pending else 'FullWrite',
            'write_decision': None if pending else 'Written', 'ack': {'kind': 'NotRequested'}, 'ack_returned': None,
            'terminal': 'Cancelled' if pending else 'Returned'}


def _sm_owner_ledger(value, sender):
    owner, roles = value['recipient_owner'], value['identities']
    config = owner['config']
    _need(config['enabled'] and config['resume_allowed'] and config['session_id'] is not None,
          'fixed_persisted_sm_required')
    original = next(item for item in sender['originals'] if item['frame_id'] == owner['frame_id'])
    _need(original['route_action'] == 'Queue', 'sm_requires_routed_item')
    _need(owner['write'] == {'chunk_limit': 4096, 'fail_after_accepted_bytes': None, 'flush': 'Ok'},
          'fixed_sm_complete_writer')
    items = [{'xml': original['projection']['live_xml'], 'source': copy.deepcopy(original['source'])}]
    for extra in owner['extra_items']:
        # These are separately supplied raw SM extras. They do not pass through
        # application set_from and do not acquire the routed client's namespace.
        items.append({'xml': _tree(_xml(extra['xml'])), 'source': copy.deepcopy(extra.get('source'))})
    outbound, acked, fifo = config['outbound_h'], config['acked_h'], []
    turns, native, handoffs = [], [], []
    cancelled = False
    for index, (item, reply) in enumerate(zip(items, owner['record_replies'])):
        _need(reply['updated'] and reply['commit'] in ('Complete', 'Pending'), 'fixed_sm_record_reply')
        scope = {'purpose': {'kind': 'Record'}, 'session_id': config['session_id'], 'connection_id': owner['connection_id'],
                 'inbound_h': config['inbound_h'], 'outbound_h': outbound, 'acked_h': acked, 'queued': len(fifo)}
        outbound = (outbound + 1) % (2 ** 32)
        fifo.append(copy.deepcopy(item))
        whole = [copy.deepcopy(slot['source']) for slot in fifo]
        binding = {'session_id': config['session_id'], 'connection_id': owner['connection_id'],
                   'inbound_h': config['inbound_h'], 'outbound_h': outbound, 'acked_h': acked,
                   'whole': whole, 'acknowledged': [], 'remaining': copy.deepcopy(whole)}
        rotations = []
        if item['source'] is not None and item['source']['kind'] == 'Mix':
            rotations = [{'previous': copy.deepcopy(item['source']),
                          'current': dict(item['source'], lease_token=roles['mix_new_token'])}]
        _need(reply['rotations'] == rotations, 'fixed_sm_new_source_rotation')
        known = reply['commit'] == 'Complete'
        state = {'scope': scope, 'binding': binding, 'h_decision': {'kind': 'NotRequested'},
                 'knowledge': {'kind': 'ReceiptKnown' if known else 'CommitCallEntered',
                               'fact': {'kind': 'Checkpoint', 'rotations': copy.deepcopy(rotations), 'settled': []}},
                 'appended': True, 'restored': False, 'ownership_applied': known, 'acknowledged_h_applied': None,
                 'notification_attempted': known and item['source'] is not None, 'capacity_completed': None,
                 'returned_updated': True if known else None, 'returned_error': False,
                 'record_managed_by_sm': (item['source'] is not None) if known else None,
                 'terminal': 'Returned' if known else 'Cancelled'}
        turns.append({'item_index': index, 'state': state, 'polls': []})
        native.append({'item_index': index, 'frame_id': owner['frame_id'], 'connection_id': owner['connection_id'],
                       'xml': copy.deepcopy(item['xml']), 'state': _sm_native_state(item['source'], pending=not known),
                       'polls': ['Ready' if known else 'Pending']})
        if not known:
            cancelled = True
            break
        if rotations:
            fifo[-1]['source'] = copy.deepcopy(rotations[0]['current'])
            handoffs.append({'delivery_id': item['source']['delivery_id'],
                             'result': {'kind': 'SmPersisted', 'session_id': config['session_id']}})
    if not cancelled and owner['ack'] is not None:
        request, reply = owner['ack']['h'], owner['ack']['reply']
        _need(reply == {'commit': 'Complete', 'updated': True, 'rotations': []}, 'fixed_sm_ack_reply')
        count = (request - acked) % (2 ** 32)
        _need(count <= len(fifo), 'fixed_sm_ack_prefix')
        scope = {'purpose': {'kind': 'Acknowledge', 'h': request}, 'session_id': config['session_id'],
                 'connection_id': owner['connection_id'], 'inbound_h': config['inbound_h'],
                 'outbound_h': outbound, 'acked_h': acked, 'queued': len(fifo)}
        whole = [copy.deepcopy(slot['source']) for slot in fifo]
        acknowledged, remaining = whole[:count], whole[count:]
        binding = {'session_id': config['session_id'], 'connection_id': owner['connection_id'],
                   'inbound_h': config['inbound_h'], 'outbound_h': outbound, 'acked_h': request,
                   'whole': whole, 'acknowledged': acknowledged, 'remaining': remaining}
        state = {'scope': scope, 'binding': binding, 'h_decision': {'kind': 'Prefix', 'count': count},
                 'knowledge': {'kind': 'ReceiptKnown', 'fact': {'kind': 'Checkpoint', 'rotations': [],
                                'settled': [source for source in acknowledged if source is not None]}},
                 'appended': False, 'restored': False, 'ownership_applied': True, 'acknowledged_h_applied': request,
                 'notification_attempted': False, 'capacity_completed': True, 'returned_updated': True,
                 'returned_error': False, 'record_managed_by_sm': None, 'terminal': 'Returned'}
        turns.append({'item_index': None, 'state': state, 'polls': ['Ready']})
        fifo, acked = fifo[count:], request
    return {'kind': 'Sm', 'frame_id': owner['frame_id'], 'turns': turns, 'native_writes': native,
            'fifo_after': fifo, 'outbound_h': outbound, 'acked_h': acked, 'mix_handoffs': handoffs,
            'execution': 'Cancelled' if cancelled else 'Complete'}


def _replacement_owner_ledger(value, sender):
    owner = value['recipient_owner']
    original = next(item for item in sender['originals'] if item['frame_id'] == owner['frame_id'])
    _need(original['route_action'] == 'Queue' and original['source'] == owner['initial_row'], 'replacement_routed_row')
    old_source = copy.deepcopy(owner['old']['fence']['returned_source'])
    current = copy.deepcopy(owner['replacement']['fence']['returned_source'])
    states = []
    for name, source, succeeds in (('old', original['source'], False), ('replacement', current, True)):
        spec = owner[name]
        _need(spec['write'] == {'chunk_limit': 4096, 'fail_after_accepted_bytes': None, 'flush': 'Ok'} and
              spec['ack'] == {'commit': 'Complete', 'disposition': 'Deleted'}, 'fixed_replacement_native_script')
        fenced = copy.deepcopy(spec['fence']['returned_source'])
        state = {'original': copy.deepcopy(source), 'preparation': 'Prepared', 'managed_by_sm': False,
                 'fence_entered': True, 'returned_fence': fenced, 'writer_entered': True,
                 'writer_result': 'FullWrite', 'write_decision': 'Written',
                 'ack': {'kind': 'ReceiptKnown', 'fact': {'source': fenced, 'disposition': 'Deleted'}} if succeeds else
                        {'kind': 'NoCommitRequested'}, 'ack_returned': succeeds, 'terminal': 'Returned'}
        states.append({'frame_id': owner['frame_id'], 'connection_id': spec['connection_id'], 'state': state,
                       'polls': ['Ready'] if succeeds else ['Pending', 'Ready']})
    events = [{'kind': 'Replace', 'recipient_id': current['recipient_id'], 'message_id': current['message_id'],
               'before_claim_id': old_source['claim_id'], 'after_claim_id': current['claim_id']},
              {'kind': 'AuthorityRead', 'source': old_source, 'current_claim_id': current['claim_id'], 'matches': False},
              {'kind': 'AuthorityRead', 'source': current, 'current_claim_id': current['claim_id'], 'matches': True},
              {'kind': 'Delete', 'source': current}]
    return {'kind': 'NativeReplacement', 'old': states[0], 'replacement': states[1], 'row_events': events,
            'replacement_dequeued': {'source': current, 'xml': copy.deepcopy(original['projection']['live_xml'])},
            'row_after': None, 'execution': 'Complete'}


def derive_owner_ledger(value):
    """Input-derived expected ownership, separate from actual evidence decoding.

    The SM wraparound/FIFO and controlled replacement contracts are bounded to
    the selected literals. This helper supplies no fixture verdict or permission.
    """
    value = validate_case_input(value)
    sender = _derive_sender_ledger(value)
    kind = value['recipient_owner']['kind']
    if kind == 'Sm':
        owner = _sm_owner_ledger(value, sender)
    elif kind == 'NativeReplacement':
        owner = _replacement_owner_ledger(value, sender)
    else:
        raise DirectCaseIncomplete('owner_ledger_transport_incomplete')
    return {'sender': sender, 'owner': owner}


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
                projection[name] = _tree(_xml(projection[name], projected=True))
        for archive in projection['archives']:
            archive['xml'] = _tree(_xml(archive['xml'], projected=True))
        if prepared['identity'] is not None:
            prepared['identity']['payload'] = _tree(_xml(prepared['identity']['payload'], projected=True))
        if projection != expected['projection']:
            findings.append('xml_projection')
        if prepared != expected['prepared']:
            findings.append('prepared_identity')
        expected_live = expected['projection']['live_xml']
        for name in ('enqueue', 'dequeued'):
            for observation in actual['route'][name]:
                if _tree(_xml(observation['xml'], projected=True)) != expected_live:
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
    original = next((item for item in payload['originals'] if item['frame_id'] == native['frame_id']), None)
    dequeued = original['route']['dequeued'] if original is not None else []
    raw = dequeued[0]['xml'].encode('utf-8') if len(dequeued) == 1 else None
    return _native_settlement_findings(ledger['native'], native, raw)


def _native_settlement_findings(expected, native, raw):
    """Same fenced-writer/ACK contract for ordinary and replacement owners."""
    violations = []
    for ack in native['ack_calls']:
        target = {'frame_id': native['frame_id'], 'connection_id': native['connection_id'],
                  'owner': 'Tcp', 'purpose': 'NativeSettlement', 'source': copy.deepcopy(ack['source'])}
        def violation(identity):
            violations.append({'id': identity, 'class': 'Safety', 'target': copy.deepcopy(target)})
        if expected is None or native['frame_id'] != expected['frame_id'] or native['connection_id'] != expected['connection_id']:
            violation('NativeAckOwnerIdentityMismatch')
        first_write = next((item['seq'] for item in native['write_calls'] if item['seq'] < ack['seq']), None)
        prepared_before_write = first_write is not None and any(
            prefix['seq'] < first_write and prefix['state']['preparation'] == 'Prepared' and
            prefix['state']['fence_entered'] and prefix['state']['returned_fence'] == ack['source']
            for prefix in native['prefixes'])
        if not prepared_before_write:
            violation('NativeAckWithoutMatchingFence')
        if expected is not None and ack['source'] != expected['fenced_source']:
            violation('NativeAckSourceIdentityMismatch')
        if expected is not None and native['original'] != expected['original_source']:
            violation('NativeAckOriginalSourceMismatch')
        if native['managed_by_sm'] is True or any(prefix['seq'] < ack['seq'] and
                                                prefix['state']['managed_by_sm'] is True for prefix in native['prefixes']):
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
        positive_at_ack = any(prefix['seq'] == ack['seq'] + 1 and last_accepted_seq < ack['seq'] and
                                  prefix['state']['preparation'] == 'Prepared' and prefix['state']['fence_entered'] and
                                  expected is not None and prefix['state']['original'] == expected['original_source'] and
                                  prefix['state']['writer_entered'] and
                                  prefix['state']['writer_result'] == 'FullWrite' and
                                  prefix['state']['write_decision'] == 'Written' and
                                  prefix['state']['returned_fence'] == ack['source'] and
                                  prefix['state']['ack'] == {'kind': 'NoCommitRequested'} and
                                  prefix['state']['ack_returned'] is None for prefix in native['prefixes'])
        if not positive_at_ack:
            violation('NativeAckWithoutFullWrite')
    return violations


def _admission_expected(entry, *, finalization=False):
    if entry is None:
        return None
    fact = {'kind': 'Finalized' if finalization else 'Reserved', 'fence': copy.deepcopy(entry['fence'])}
    if finalization:
        fact['result'] = 'PendingAccepted'
    commit = {'correlation': copy.deepcopy(entry['correlation']),
              'scope': 'AdmissionFinalize' if finalization else 'RatedBeginNewReservation', 'fact': fact}
    known = entry['commit'] == 'Complete'
    returned = ({'kind': 'AcceptPending'} if finalization else
                {'kind': 'Proceed', 'fence': copy.deepcopy(entry['fence'])}) if known else \
        {'kind': 'Error'} if entry['commit'] == 'Error' else None
    return {'correlation': copy.deepcopy(entry['correlation']), 'started': True,
            'knowledge': {'kind': 'ReceiptKnown', 'receipt': commit} if known else
                         {'kind': 'CommitCallEntered', 'prepared': commit}, 'returned': returned}


def _direct_expected(entry):
    prepared = {'correlation': copy.deepcopy(entry['correlation']),
                'transaction': copy.deepcopy(entry['transaction']), 'admitted_mode': entry['admitted_mode']}
    known = entry['commit'] == 'Complete'
    returned = None
    if entry['returned_mode'] is not None:
        transaction = entry['transaction']
        commit = {'kind': transaction['kind']}
        if transaction['kind'] == 'Stored':
            commit.update(archive_written=bool(transaction['archive_ids']),
                          recipient_id=transaction['recipient_id'], delivery_id=transaction['delivery_id'])
        returned = {'commit': commit, 'mode': entry['returned_mode'], 'live_claim_id': transaction.get('live_claim_id')}
    return {'correlation': copy.deepcopy(entry['correlation']), 'started': True,
            'knowledge': {'kind': 'ReceiptKnown', 'receipt': {'prepared': prepared}} if known else
                         {'kind': 'CommitCallEntered', 'prepared': prepared},
            'returned': returned, 'preserved_transaction': copy.deepcopy(entry['preserved_transaction']),
            'application_error': entry['preserved_transaction'] is not None or entry['commit'] == 'Error'}


def _handoff_expected(item):
    if item['source'] is None or item['direct']['commit'] != 'Complete':
        return None
    queued, refused = item['route_action'] == 'Queue', item['route_action'] == 'FullThenRearm'
    rearmed = item['route_action'] in ('Rearm', 'FullThenRearm')
    return {'correlation': copy.deepcopy(item['correlations']['handoff']), 'source': copy.deepcopy(item['source']),
            'local_call': 'Accepted' if queued else 'Refused' if refused else 'NotRequested',
            'local_accepted': queued, 'last_local_refusal': 'Full' if refused else None,
            'remote': 'NoPositiveReceipt' if refused else 'NotRequested', 'prior_remote_uncertain': refused,
            'rearm': ('CallEntered' if item['rearm'] == 'Pending' else 'CallReturned') if rearmed else 'NotRequested',
            'route_end': 'Dropped' if rearmed and item['rearm'] == 'Pending' else 'Returned', 'retired': True}


def _finding(findings, label, condition):
    if not condition:
        findings.append(label)


def _knowledge_fact(observation, *, direct=False):
    knowledge = observation['knowledge']
    if knowledge['kind'] == 'NoCommitRequested':
        return None
    if knowledge['kind'] == 'CommitCallEntered':
        return knowledge['prepared']
    return knowledge['receipt']['prepared'] if direct else knowledge['receipt']


def _transaction_prefixes(prefixes, name, expected, findings):
    """Keep actual prefix knowledge/returns immutable and purpose-associated."""
    rank, existed, returned, started = -1, False, False, False
    entered_seq = receipt_seq = None
    preserved = application_error = False
    for prefix in prefixes:
        value = prefix['state'][name]
        if expected is None:
            _finding(findings, name + '_unexpected_prefix', value is None)
            continue
        if value is None:
            _finding(findings, name + '_prefix_erased', not existed)
            continue
        existed = True
        current_rank = {'NoCommitRequested': 0, 'CommitCallEntered': 1, 'ReceiptKnown': 2}[value['knowledge']['kind']]
        final_rank = 2 if expected['knowledge']['kind'] == 'ReceiptKnown' else 1
        _finding(findings, name + '_prefix_knowledge', rank <= current_rank <= final_rank)
        rank = current_rank
        _finding(findings, name + '_prefix_correlation', value['correlation'] == expected['correlation'])
        _finding(findings, name + '_prefix_started', (not started or value['started']) and
                 (current_rank == 0 or value['started']))
        started = started or value['started']
        if current_rank:
            _finding(findings, name + '_prefix_fact',
                     _knowledge_fact(value, direct=name == 'direct') == _knowledge_fact(expected, direct=name == 'direct'))
        if current_rank == 1 and entered_seq is None:
            entered_seq = prefix['seq']
        if current_rank == 2 and receipt_seq is None:
            receipt_seq = prefix['seq']
        _finding(findings, name + '_prefix_return_erased', not returned or value['returned'] is not None)
        if value['returned'] is not None:
            returned = True
            _finding(findings, name + '_prefix_return', value['returned'] == expected['returned'])
            successful = name == 'direct' or value['returned']['kind'] != 'Error'
            _finding(findings, name + '_return_knowledge', current_rank == 2 if successful else current_rank >= 1)
        if name == 'direct':
            _finding(findings, 'direct_prefix_error_erased', not application_error or value['application_error'])
            application_error = application_error or value['application_error']
            _finding(findings, 'direct_prefix_error', not application_error or expected['application_error'])
            if value['application_error']:
                _finding(findings, 'direct_error_knowledge', current_rank == 2 if expected['preserved_transaction'] is not None
                         else current_rank >= 1)
            _finding(findings, 'direct_prefix_preserved_erased', not preserved or value['preserved_transaction'] is not None)
            if value['preserved_transaction'] is not None:
                preserved = True
                _finding(findings, 'direct_prefix_preserved', value['preserved_transaction'] == expected['preserved_transaction'])
                _finding(findings, 'direct_preserved_receipt_knowledge', current_rank == 2)
    if expected is not None:
        _finding(findings, name + '_entered_prefix_required', entered_seq is not None)
        if expected['knowledge']['kind'] == 'ReceiptKnown':
            _finding(findings, name + '_receipt_prefix_required', receipt_seq is not None and
                     entered_seq is not None and entered_seq < receipt_seq)
    return entered_seq, receipt_seq


def _retained_handoff_prefixes(prefixes, expected, findings):
    previous = None
    ranks = {'local_call': {'NotRequested': 0, 'CallEntered': 1, 'Refused': 2, 'Accepted': 3},
             'remote': {'NotRequested': 0, 'CallEntered': 1, 'NoPositiveReceipt': 2, 'AcceptanceReported': 3},
             'rearm': {'NotRequested': 0, 'CallEntered': 1, 'CallReturned': 2},
             'route_end': {'NotStarted': 0, 'Running': 1, 'Returned': 2, 'Dropped': 2}}
    for prefix in prefixes:
        value = prefix['state']['handoff']
        if value is None:
            _finding(findings, 'handoff_prefix_erased', previous is None)
            continue
        _finding(findings, 'handoff_prefix_binding', expected is not None and
                 value['correlation'] == expected['correlation'] and value['source'] == expected['source'])
        if previous is not None:
            for name in ('local_accepted', 'prior_remote_uncertain', 'retired'):
                _finding(findings, 'handoff_retained_' + name, not previous[name] or value[name])
            if previous['last_local_refusal'] is not None:
                _finding(findings, 'handoff_retained_refusal', value['last_local_refusal'] == previous['last_local_refusal'])
            for name, order in ranks.items():
                _finding(findings, 'handoff_monotone_' + name, order[value[name]] >= order[previous[name]])
            if previous['route_end'] in ('Returned', 'Dropped'):
                _finding(findings, 'handoff_retained_route_end', value['route_end'] == previous['route_end'])
        previous = value


def _retained_native_prefixes(prefixes, findings):
    previous = None
    preparation = {'NotStarted': 0, 'Recording': 1, 'FenceCallEntered': 2, 'Prepared': 3, 'Superseded': 3, 'Failed': 3}
    for prefix in prefixes:
        state = prefix['state']
        if previous is not None:
            for name in ('fence_entered', 'writer_entered'):
                _finding(findings, 'native_retained_' + name, not previous[name] or state[name])
            for name in ('original', 'managed_by_sm', 'returned_fence', 'writer_result', 'write_decision', 'ack_returned', 'terminal'):
                if previous[name] is not None:
                    _finding(findings, 'native_retained_' + name, state[name] == previous[name])
            _finding(findings, 'native_preparation_monotone', preparation[state['preparation']] >= preparation[previous['preparation']])
            if preparation[previous['preparation']] == 3:
                _finding(findings, 'native_retained_preparation', state['preparation'] == previous['preparation'])
        if state['writer_result'] is not None:
            _finding(findings, 'native_result_requires_writer_entry', state['writer_entered'])
        if state['write_decision'] is not None:
            _finding(findings, 'native_decision_requires_result', state['writer_result'] is not None)
        previous = state


def _original_fixture_findings(value, ledger, payload):
    findings = []
    if len(payload['originals']) != len(ledger['originals']):
        return ['original_inventory']
    previous_final = 0
    for index, (expected, actual) in enumerate(zip(ledger['originals'], payload['originals'])):
        _finding(findings, 'original_frame', actual['frame_id'] == expected['frame_id'])
        begin = _admission_expected(expected['begin'])
        finalize = _admission_expected(expected['finalize'], finalization=True)
        direct = _direct_expected(expected['direct'])
        handoff = _handoff_expected(expected)
        for name, wanted in (('begin', begin), ('finalize', finalize), ('direct', direct)):
            _finding(findings, name + '_final_observation', actual[name] == wanted)
        _finding(findings, 'sender_terminal', actual['terminal'] == expected['terminal'])
        continuation = None if expected['continuation'] == 'NotReturned' else {
            'kind': expected['continuation'], 'error_type': None, 'error_condition': None}
        _finding(findings, 'continuation_result', actual['continuation'] == continuation)
        prefixes, polls = actual['prefixes'], actual['polls']
        _finding(findings, 'sender_poll', len(polls) == 1 and
                 polls[0]['result'] == ('Pending' if expected['terminal'] == 'Cancelled' else 'Ready'))
        final_seq = prefixes[-1]['seq'] if prefixes else 0
        final_state = {'begin': begin, 'finalize': finalize, 'direct': direct, 'handoff': handoff,
                       'terminal': expected['terminal']}
        _finding(findings, 'sender_final_retirement_prefix', bool(prefixes) and prefixes[-1]['state'] == final_state and
                 len(polls) == 1 and polls[0]['seq'] < final_seq)
        # The entry records Poll, then drops the runner and captures its final
        # handle. This is observation cadence, not when internal retirement began.
        if len(polls) == 1:
            _finding(findings, 'sender_post_poll_snapshot', [item['seq'] for item in prefixes if item['seq'] > polls[0]['seq']] ==
                     ([final_seq] if prefixes else []))
        _finding(findings, 'original_prefix_order', all(prefix['seq'] > previous_final for prefix in prefixes))
        entered_begin, receipt_begin = _transaction_prefixes(prefixes, 'begin', begin, findings)
        entered_direct, receipt_direct = _transaction_prefixes(prefixes, 'direct', direct, findings)
        entered_finalize, _receipt_finalize = _transaction_prefixes(prefixes, 'finalize', finalize, findings)
        if entered_begin is not None:
            _finding(findings, 'original_order', previous_final < entered_begin)
        elif entered_direct is not None:
            _finding(findings, 'original_order', previous_final < entered_direct)
        if begin is not None and entered_direct is not None:
            _finding(findings, 'reservation_before_direct', receipt_begin is not None and receipt_begin < entered_direct)
        if finalize is not None and entered_finalize is not None:
            _finding(findings, 'direct_receipt_before_finalize', receipt_direct is not None and receipt_direct < entered_finalize)
        previous_final = final_seq
        route = actual['route']
        _finding(findings, 'handoff_final', route['handoff'] == handoff)
        _retained_handoff_prefixes(prefixes, handoff, findings)
        retained_terminal = None
        for prefix in prefixes:
            terminal = prefix['state']['terminal']
            _finding(findings, 'sender_retained_terminal', retained_terminal is None or terminal == retained_terminal)
            if terminal is not None:
                retained_terminal = terminal
                _finding(findings, 'sender_prefix_terminal', terminal == expected['terminal'])
                _finding(findings, 'sender_terminal_after_poll', len(polls) == 1 and
                         polls[0]['seq'] < prefix['seq'] == final_seq)
            held = prefix['state']['handoff']
            if held is None:
                continue
            if held['retired']:
                _finding(findings, 'handoff_retired_after_poll', len(polls) == 1 and
                         polls[0]['seq'] < prefix['seq'] == final_seq)
            local_before = [item for item in route['enqueue'] if item['seq'] < prefix['seq']]
            remote_before = [item for item in route['remote_calls'] if item['seq'] < prefix['seq']]
            rearm_before = [item for item in route['rearm_calls'] if item['seq'] < prefix['seq']]
            if held['local_accepted'] or held['local_call'] == 'Accepted':
                _finding(findings, 'handoff_acceptance_after_call', any(item['result'] == 'Accepted' for item in local_before))
            if held['local_call'] == 'Refused' or held['last_local_refusal'] is not None:
                _finding(findings, 'handoff_refusal_after_call', any(item['result'] == held['last_local_refusal']
                         and item['result'] in ('Full', 'Closed') for item in local_before))
            if held['prior_remote_uncertain'] or held['remote'] == 'NoPositiveReceipt':
                _finding(findings, 'handoff_uncertainty_after_call', any(item['returned'] is False for item in remote_before))
            if held['remote'] == 'AcceptanceReported':
                _finding(findings, 'handoff_remote_receipt_after_call', any(item['returned'] is True for item in remote_before))
            if held['rearm'] != 'NotRequested':
                _finding(findings, 'handoff_rearm_after_call', bool(rearm_before) and
                         (held['rearm'] != 'CallReturned' or any(item['returned'] for item in rearm_before)))
        phases = ['PostFinalize'] + ['Router'] * (len(expected['health_modes']) - 1) if expected['health_modes'] else []
        _finding(findings, 'health_reads', [(item['phase'], item['mode']) for item in route['health_reads']] ==
                 list(zip(phases, expected['health_modes'])))
        if route['health_reads'] and finalize is not None:
            _finding(findings, 'finalization_return_before_health', any(
                prefix['seq'] < route['health_reads'][0]['seq'] and prefix['state']['finalize'] is not None and
                prefix['state']['finalize']['returned'] == finalize['returned'] and finalize['returned'] is not None
                for prefix in prefixes))
        if route['rearm_calls'] and finalize is not None:
            _finding(findings, 'finalization_return_before_rearm', any(
                prefix['seq'] < route['rearm_calls'][0]['seq'] and prefix['state']['finalize'] is not None and
                prefix['state']['finalize']['returned'] == finalize['returned'] and finalize['returned'] is not None
                for prefix in prefixes))
        _finding(findings, 'remote_calls', [(item['source'], item['returned']) for item in route['remote_calls']] ==
                 [(expected['source'], returned) for returned in expected['remote_returns']])
        rearmed = expected['route_action'] in ('Rearm', 'FullThenRearm')
        _finding(findings, 'rearm_calls', [(item['source'], item['returned']) for item in route['rearm_calls']] ==
                 ([(expected['source'], expected['rearm'] == 'Return')] if rearmed else []))
        enqueue_result = 'Accepted' if expected['route_action'] == 'Queue' else \
            'Full' if expected['route_action'] == 'FullThenRearm' else None
        _finding(findings, 'local_enqueue', [(item['source'], item['result']) for item in route['enqueue']] ==
                 ([(expected['source'], enqueue_result)] if enqueue_result else []))
        _finding(findings, 'backpressure_disconnect', route['backpressure_disconnected'] == (enqueue_result == 'Full'))
        if route['enqueue'] and len(route['health_reads']) >= 2:
            _finding(findings, 'primary_health_before_enqueue', route['health_reads'][1]['seq'] < route['enqueue'][0]['seq'])
        if route['remote_calls'] and route['enqueue']:
            _finding(findings, 'local_refusal_before_remote', route['enqueue'][-1]['seq'] < route['remote_calls'][0]['seq'])
        if route['remote_calls'] and route['rearm_calls']:
            _finding(findings, 'remote_before_rearm', route['remote_calls'][-1]['seq'] < route['rearm_calls'][0]['seq'])
        if len(route['health_reads']) == 3 and route['enqueue']:
            _finding(findings, 'after_routing_health', route['enqueue'][-1]['seq'] < route['health_reads'][-1]['seq'])
        receiving = value['recipient_owner'].get('frame_id') == expected['frame_id']
        _finding(findings, 'dequeue_lineage', [item['source'] for item in route['dequeued']] ==
                 ([expected['source']] if receiving and enqueue_result == 'Accepted' else []))
        prefill = value['route'][index]['prefill']
        remaining = [] if prefill is None else [{'xml': prefill['xml'], 'source': None}]
        _finding(findings, 'queue_remaining', route['queue_remaining'] == remaining)
        for event in route['health_reads'] + route['enqueue'] + route['remote_calls'] + route['rearm_calls']:
            _finding(findings, 'sender_call_before_poll', len(polls) == 1 and event['seq'] < polls[0]['seq'])
        for event in route['enqueue'] + route['remote_calls'] + route['rearm_calls']:
            _finding(findings, 'receipt_before_handoff_effect', receipt_direct is not None and receipt_direct < event['seq'])
            _finding(findings, 'handoff_effect_before_sender_return', len(polls) == 1 and event['seq'] < polls[0]['seq'])
        for event in route['dequeued']:
            _finding(findings, 'sender_retired_before_recipient', final_seq < event['seq'])
        if expected['terminal'] == 'Cancelled' and len(polls) == 1:
            boundary = entered_direct if expected['direct']['commit'] == 'Pending' else \
                route['rearm_calls'][0]['seq'] if len(route['rearm_calls']) == 1 else None
            _finding(findings, 'sender_pending_boundary', boundary is not None and boundary < polls[0]['seq'])
    return findings


def _expected_native_state(ledger, *, no_flush=False):
    native = ledger['native']
    script = native['write']
    written = script['fail_after_accepted_bytes'] is None and (script['flush'] == 'Ok' or no_flush)
    commit = native['ack']['commit']
    fact = {'source': copy.deepcopy(native['fenced_source']), 'disposition': native['ack']['disposition']}
    ack = {'kind': 'NotRequested'} if not written else \
        {'kind': 'ReceiptKnown' if commit == 'Complete' else 'CommitCallEntered', 'fact': fact}
    return {'original': copy.deepcopy(native['original_source']), 'preparation': 'Prepared', 'managed_by_sm': False,
            'fence_entered': True, 'returned_fence': copy.deepcopy(native['fenced_source']), 'writer_entered': True,
            'writer_result': 'FullWrite' if written else 'Failed', 'write_decision': 'Written' if written else 'Withhold',
            'ack': ack, 'ack_returned': None if not written or commit == 'Pending' else commit == 'Complete',
            'terminal': 'Cancelled' if written and commit == 'Pending' else 'Returned'}


def _expected_native_prefixes(final):
    """Fixed non-SM callbacks, including the post-invocation ACK boundary."""
    recording = copy.deepcopy(final)
    recording.update(preparation='Recording', managed_by_sm=None, fence_entered=False, returned_fence=None,
                     writer_entered=False, writer_result=None, write_decision=None,
                     ack={'kind': 'NotRequested'}, ack_returned=None, terminal=None)
    fence = copy.deepcopy(recording)
    fence.update(preparation='FenceCallEntered', managed_by_sm=False, fence_entered=True)
    prepared = copy.deepcopy(fence)
    prepared.update(preparation='Prepared', returned_fence=copy.deepcopy(final['returned_fence']))
    prefixes = [recording, fence, prepared]
    if final['ack']['kind'] != 'NotRequested':
        authority = copy.deepcopy(prepared)
        authority.update(writer_entered=True, writer_result='FullWrite', write_decision='Written',
                         ack={'kind': 'NoCommitRequested'})
        prefixes.append(authority)
        if final['ack']['kind'] in ('CommitCallEntered', 'ReceiptKnown'):
            entered = copy.deepcopy(authority)
            entered['ack'] = {'kind': 'CommitCallEntered', 'fact': copy.deepcopy(final['ack']['fact'])}
            prefixes.append(entered)
        if final['ack']['kind'] == 'ReceiptKnown':
            receipt = copy.deepcopy(entered)
            receipt['ack'] = copy.deepcopy(final['ack'])
            prefixes.append(receipt)
    prefixes.append(copy.deepcopy(final))
    return prefixes


def _native_fixture_findings(ledger, payload, *, no_flush=False):
    wanted = ledger['native']
    if wanted is None:
        return [] if payload['recipient'] == {'kind': 'None'} else ['unexpected_recipient_owner']
    if payload['recipient']['kind'] != 'Native':
        return ['missing_native_owner']
    native, findings = payload['recipient']['native'], []
    _finding(findings, 'native_owner_identity', native['frame_id'] == wanted['frame_id'] and
             native['connection_id'] == wanted['connection_id'])
    expected = _expected_native_state(ledger, no_flush=no_flush)
    _finding(findings, 'native_final_state', {name: native[name] for name in NATIVE_STATE_FIELDS.split()} == expected)
    original = next((item for item in payload['originals'] if item['frame_id'] == wanted['frame_id']), None)
    dequeued = original['route']['dequeued'] if original is not None else []
    raw = dequeued[0]['xml'].encode('utf-8') if len(dequeued) == 1 else b''
    expected_writes, offset = [], 0
    short = wanted['write']['fail_after_accepted_bytes']
    while offset < len(raw):
        tail = raw[offset:]
        count = min(wanted['write']['chunk_limit'], len(tail))
        if short is not None:
            count = min(count, max(0, short - offset))
        expected_writes.append({'offered_len': len(tail), 'offered_sha256': _hash(tail),
                                'accepted_bytes_hex': tail[:count].hex(), 'result': 'Accepted' if count else 'Error'})
        if not count:
            break
        offset += count
    _finding(findings, 'native_write_calls', bool(raw) and
             [{name: item[name] for name in expected_writes[0]} for item in native['write_calls']] == expected_writes)
    expected_flush = [] if short is not None or no_flush else [wanted['write']['flush']]
    _finding(findings, 'native_flush_calls', [item['result'] for item in native['flush_calls']] == expected_flush)
    written = expected['writer_result'] == 'FullWrite'
    calls = [(wanted['fenced_source'], expected['ack_returned'])] if written else []
    _finding(findings, 'native_ack_invocation', [(item['source'], item['returned']) for item in native['ack_calls']] == calls)
    _finding(findings, 'routed_item_has_no_receipt_channels', not native['ownership_receipts'] and not native['write_receipts'])
    polls, prefixes = native['polls'], native['prefixes']
    _finding(findings, 'native_callback_prefixes', [prefix['state'] for prefix in prefixes] == _expected_native_prefixes(expected))
    _retained_native_prefixes(prefixes, findings)
    _finding(findings, 'native_poll', len(polls) == 1 and
             polls[0]['result'] == ('Pending' if expected['terminal'] == 'Cancelled' else 'Ready'))
    _finding(findings, 'native_final_retirement_prefix', bool(prefixes) and prefixes[-1]['state'] == expected and
             len(polls) == 1 and polls[0]['seq'] < prefixes[-1]['seq'])
    if len(polls) == 1:
        _finding(findings, 'native_post_poll_snapshot', [item['seq'] for item in prefixes if item['seq'] > polls[0]['seq']] ==
                 ([prefixes[-1]['seq']] if prefixes else []))
    calls_before_poll = native['write_calls'] + native['flush_calls'] + native['ack_calls'] + \
        native['ownership_receipts'] + native['write_receipts']
    _finding(findings, 'native_calls_before_poll', len(polls) == 1 and
             all(item['seq'] < polls[0]['seq'] for item in calls_before_poll))
    first_write = native['write_calls'][0]['seq'] if native['write_calls'] else None
    _finding(findings, 'native_start_after_dequeue', len(dequeued) == 1 and bool(prefixes) and
             dequeued[0]['seq'] < prefixes[0]['seq'])
    _finding(findings, 'native_preparation_prefix', first_write is not None and len(dequeued) == 1 and
             any(dequeued[0]['seq'] < prefix['seq'] < first_write and
                 prefix['state']['preparation'] == 'Prepared' and
                 prefix['state']['returned_fence'] == wanted['fenced_source'] and
                 prefix['state']['writer_entered'] is False for prefix in prefixes))
    rank = -1
    entered = receipt = None
    for prefix in prefixes:
        state = prefix['state']
        if state['terminal'] is not None:
            _finding(findings, 'native_terminal_after_poll', len(polls) == 1 and
                     polls[0]['seq'] < prefix['seq'] == prefixes[-1]['seq'])
        if state['original'] is not None:
            _finding(findings, 'native_prefix_original', state['original'] == wanted['original_source'])
        if state['returned_fence'] is not None:
            _finding(findings, 'native_prefix_fence', state['returned_fence'] == wanted['fenced_source'])
        if state['writer_result'] is not None:
            _finding(findings, 'native_prefix_writer_result', state['writer_result'] == expected['writer_result'])
            _finding(findings, 'native_writer_result_after_calls', bool(native['write_calls']) and
                     all(item['seq'] < prefix['seq'] for item in native['write_calls'] + native['flush_calls']))
        if state['write_decision'] is not None:
            _finding(findings, 'native_prefix_write_decision', state['write_decision'] == expected['write_decision'])
        knowledge = state['ack']
        current = {'NotRequested': 0, 'NoCommitRequested': 1, 'CommitCallEntered': 2, 'ReceiptKnown': 3}[knowledge['kind']]
        _finding(findings, 'native_prefix_ack_monotone', current >= rank)
        rank = current
        if current >= 2:
            _finding(findings, 'native_prefix_ack_fact', knowledge['fact'] ==
                     {'source': wanted['fenced_source'], 'disposition': wanted['ack']['disposition']})
            _finding(findings, 'native_ack_knowledge_after_call', len(native['ack_calls']) == 1 and
                     native['ack_calls'][0]['seq'] < prefix['seq'])
        if state['ack_returned'] is not None:
            _finding(findings, 'native_ack_return_knowledge', current == 3 if state['ack_returned'] else current >= 1)
            _finding(findings, 'native_prefix_ack_return', state['ack_returned'] == expected['ack_returned'])
        if current == 2 and entered is None:
            entered = prefix['seq']
        if current == 3 and receipt is None:
            receipt = prefix['seq']
    if written:
        ack_seq = native['ack_calls'][0]['seq'] if len(native['ack_calls']) == 1 else None
        _finding(findings, 'native_full_write_at_ack_boundary', ack_seq is not None and
                 any(prefix['seq'] == ack_seq + 1 and prefix['state']['writer_result'] == 'FullWrite' and
                     prefix['state']['write_decision'] == 'Written' and prefix['state']['ack'] == {'kind': 'NoCommitRequested'} and
                     prefix['state']['ack_returned'] is None for prefix in prefixes))
        _finding(findings, 'native_ack_entered_prefix', ack_seq is not None and entered is not None and ack_seq + 1 < entered)
        if wanted['ack']['commit'] == 'Complete':
            _finding(findings, 'native_ack_receipt_prefix', entered is not None and receipt is not None and entered < receipt)
        else:
            _finding(findings, 'native_no_unreceived_ack_receipt', receipt is None)
        if expected['terminal'] == 'Cancelled':
            _finding(findings, 'native_pending_boundary', entered is not None and len(polls) == 1 and entered < polls[0]['seq'])
    else:
        _finding(findings, 'withheld_ack_has_no_transaction', entered is None and receipt is None)
    return findings


def _native_failure_target(ledger):
    native = ledger['native']
    _need(native is not None, 'native_expected_failure_owner')
    return {'id': 'NativeAckWithoutSuccessfulFlush', 'class': 'Safety',
            'target': {'frame_id': native['frame_id'], 'connection_id': native['connection_id'], 'owner': 'Tcp',
                       'purpose': 'NativeSettlement', 'source': copy.deepcopy(native['fenced_source'])}}


def _sm_receipt_matches(state, expected):
    return (state['scope'] == expected['scope'] and state['binding'] == expected['binding'] and
            state['knowledge'] == {'kind': 'ReceiptKnown', 'fact': expected['knowledge']['fact']})


def sm_safety_findings(value, payload):
    """Observed SM authority precedes fixture expectations and native work."""
    ledger = derive_owner_ledger(value)
    validate_case_evidence(payload)
    if ledger['owner']['kind'] != 'Sm' or payload['rejection'] is not None or payload['recipient']['kind'] != 'Sm':
        return []
    expected, actual = ledger['owner'], payload['recipient']
    violations = []
    for index, turn in enumerate(actual['sm_turns']):
        wanted = expected['turns'][index]['state'] if index < len(expected['turns']) else None
        target = {'frame_id': expected['frame_id'], 'connection_id': turn['scope']['connection_id'],
                  'owner': 'Sm', 'purpose': copy.deepcopy(turn['scope']['purpose']),
                  'item_index': expected['turns'][index]['item_index'] if wanted is not None else None}
        states = [prefix['state'] for prefix in turn['prefixes']] + [turn]
        def violation(identity):
            violations.append({'id': identity, 'class': 'Safety', 'target': copy.deepcopy(target)})
        authority = lambda state: wanted is not None and _sm_receipt_matches(state, wanted)
        if any(state['knowledge']['kind'] == 'ReceiptKnown' and not authority(state) for state in states):
            violation('SmCheckpointReceiptIdentityMismatch')
        if any((state['ownership_applied'] or state['record_managed_by_sm'] is True) and
               not authority(state) for state in states):
            violation('SmOwnershipWithoutCheckpointReceipt')
        if any(state['notification_attempted'] and not authority(state) for state in states):
            violation('SmNotificationWithoutCheckpointReceipt')
        if any(state['acknowledged_h_applied'] is not None and not (
                authority(state) and state['scope']['purpose'] == {'kind': 'Acknowledge', 'h': state['acknowledged_h_applied']} and
                state['binding']['acked_h'] == state['acknowledged_h_applied']) for state in states) or any(
                state['capacity_completed'] is True and not (authority(state) and
                state['scope']['purpose']['kind'] == 'Acknowledge') for state in states):
            violation('SmAcknowledgementAppliedWithoutReceipt')
        commit_seen = restored_after_entry = False
        for state in states:
            commit_seen = commit_seen or state['knowledge']['kind'] in ('CommitCallEntered', 'ReceiptKnown')
            restored_after_entry = restored_after_entry or (commit_seen and state['restored'])
        if restored_after_entry:
            violation('SmRestorationAfterCommitEntry')
    for index, native in enumerate(actual['native_writes']):
        wanted = expected['turns'][index]['state'] if index < len(expected['native_writes']) else None
        turn = actual['sm_turns'][index] if index < len(actual['sm_turns']) else None
        prefixes = turn['prefixes'] if turn is not None else []
        target = {'frame_id': native['frame_id'], 'connection_id': native['connection_id'],
                  'owner': 'Tcp', 'purpose': 'Write', 'item_index': index}
        owner_matches = (index < len(expected['native_writes']) and native['frame_id'] == expected['frame_id'] and
                         native['connection_id'] == expected['native_writes'][index]['connection_id'] and
                         wanted is not None and native['connection_id'] == wanted['scope']['connection_id'])
        source_matches = index < len(expected['native_writes']) and native['original'] == expected['native_writes'][index]['state']['original']
        if (native['write_calls'] or native['ack_calls']) and not owner_matches:
            violations.append({'id': 'SmNativeOwnerIdentityMismatch', 'class': 'Safety', 'target': copy.deepcopy(target)})
        if (native['write_calls'] or native['ack_calls']) and not source_matches:
            violations.append({'id': 'SmNativeItemSourceMismatch', 'class': 'Safety', 'target': copy.deepcopy(target)})
        def completed_before(seq):
            return owner_matches and any(prefix['seq'] < seq and _sm_receipt_matches(prefix['state'], wanted) and
                prefix['state']['ownership_applied'] and prefix['state']['returned_updated'] is True and
                prefix['state']['record_managed_by_sm'] is not None and prefix['state']['terminal'] == 'Returned'
                for prefix in prefixes)
        if any(not completed_before(call['seq']) for call in native['write_calls']):
            violations.append({'id': 'NativeWriteBeforeSmCheckpointReturn', 'class': 'Safety', 'target': target})
        durable = wanted is not None and wanted['binding']['remaining'][-1] is not None
        if any(prefix['state']['managed_by_sm'] is True and not completed_before(prefix['seq'])
               for prefix in native['prefixes']):
            violations.append({'id': 'NativeManagedWithoutSmReceipt', 'class': 'Safety', 'target': copy.deepcopy(target)})
        if (native['fence_entered'] and native['managed_by_sm'] is True) or (durable and any(
                prefix['state']['fence_entered'] and completed_before(prefix['seq']) for prefix in native['prefixes'])):
            violations.append({'id': 'NativeFenceAfterSmOwnership', 'class': 'Safety', 'target': copy.deepcopy(target)})
        for ack in native['ack_calls']:
            ack_target = {'frame_id': native['frame_id'], 'connection_id': native['connection_id'],
                          'owner': 'Tcp', 'purpose': 'NativeSettlement', 'source': copy.deepcopy(ack['source'])}
            transferred = completed_before(ack['seq']) and durable
            violations.append({'id': 'NativeAckAfterSmOwnership' if transferred else 'NativeAckWithoutMatchingFence',
                               'class': 'Safety', 'target': ack_target})
    for handoff in actual['mix_handoffs']:
        result = handoff['result']
        if result['kind'] not in ('SmPersisted', 'BoshPersisted', 'SocketFenced'):
            continue
        matching = False
        for index, wanted in enumerate(expected['turns'][:len(expected['native_writes'])]):
            if index >= len(actual['sm_turns']):
                continue
            rotations = wanted['state']['knowledge']['fact']['rotations']
            if not any(item['previous']['delivery_id'] == handoff['delivery_id'] for item in rotations):
                continue
            matching = result == {'kind': 'SmPersisted', 'session_id': wanted['state']['scope']['session_id']} and any(
                prefix['seq'] < handoff['seq'] and _sm_receipt_matches(prefix['state'], wanted['state']) and
                prefix['state']['ownership_applied'] for prefix in actual['sm_turns'][index]['prefixes'])
        if not matching:
            violations.append({'id': 'MixSmHandoffWithoutMatchingReceipt', 'class': 'Safety',
                               'target': {'owner': 'Sm', 'delivery_id': handoff['delivery_id'], 'purpose': 'MixHandoff'}})
    return violations


def _sm_turn_findings(turn, wanted, findings):
    expected = wanted['state']
    _finding(findings, 'sm_final_state', {name: turn[name] for name in SM_STATE_FIELDS.split()} == expected)
    _finding(findings, 'sm_direct_polls', [item['result'] for item in turn['polls']] == wanted['polls'])
    prefixes = turn['prefixes']
    _finding(findings, 'sm_final_retirement_prefix', bool(prefixes) and prefixes[-1]['state'] == expected)
    record = expected['scope']['purpose']['kind'] == 'Record'
    known = expected['knowledge']['kind'] == 'ReceiptKnown'
    phases = (['NotRequested'] if record else []) + ['CommitCallEntered'] + (['ReceiptKnown'] if known else []) + [expected['knowledge']['kind']]
    _finding(findings, 'sm_prefix_cadence', [prefix['state']['knowledge']['kind'] for prefix in prefixes] == phases)
    if record:
        initial = copy.deepcopy(expected)
        initial.update(binding=None, knowledge={'kind': 'NotRequested'}, appended=False, restored=False,
                       ownership_applied=False, acknowledged_h_applied=None, notification_attempted=False,
                       capacity_completed=None, returned_updated=None, returned_error=False,
                       record_managed_by_sm=None, terminal=None)
        _finding(findings, 'sm_recorded_before_append', bool(prefixes) and prefixes[0]['state'] == initial)
    entered = receipt = None
    previous = None
    rank = -1
    for prefix in prefixes:
        state = prefix['state']
        _finding(findings, 'sm_prefix_scope', state['scope'] == expected['scope'])
        if state['binding'] is not None:
            _finding(findings, 'sm_prefix_binding', state['binding'] == expected['binding'])
        knowledge = state['knowledge']
        current = {'NotRequested': 0, 'NoCommitRequested': 1, 'CommitCallEntered': 2, 'ReceiptKnown': 3}.get(knowledge['kind'])
        _finding(findings, 'sm_expected_commit_path', current is not None)
        if current is not None:
            _finding(findings, 'sm_prefix_knowledge', current >= rank and
                     (expected['knowledge']['kind'] == 'ReceiptKnown' or current < 3))
            rank = current
        if knowledge['kind'] in ('CommitCallEntered', 'ReceiptKnown'):
            _finding(findings, 'sm_prefix_fact', knowledge['fact'] == expected['knowledge']['fact'])
            if knowledge['kind'] == 'CommitCallEntered' and entered is None:
                entered = prefix['seq']
            if knowledge['kind'] == 'ReceiptKnown' and receipt is None:
                receipt = prefix['seq']
                _finding(findings, 'sm_receipt_before_local_application', not state['ownership_applied'] and
                         not state['notification_attempted'] and state['acknowledged_h_applied'] is None and
                         state['capacity_completed'] is None and state['returned_updated'] is None and
                         state['record_managed_by_sm'] is None and state['terminal'] is None)
        if state['returned_updated'] is not None:
            _finding(findings, 'sm_return_requires_receipt', knowledge['kind'] == 'ReceiptKnown' and state['returned_updated'] is True)
        if state['record_managed_by_sm'] is not None:
            _finding(findings, 'sm_managed_return_after_record', state['returned_updated'] is True and
                     state['record_managed_by_sm'] == expected['record_managed_by_sm'])
        for name in ('h_decision', 'restored', 'returned_error'):
            _finding(findings, 'sm_prefix_' + name, state[name] == expected[name])
        _finding(findings, 'sm_prefix_appended', state['appended'] == (record and knowledge['kind'] != 'NotRequested'))
        if previous is not None:
            for name in ('binding', 'acknowledged_h_applied', 'capacity_completed', 'returned_updated',
                         'record_managed_by_sm', 'terminal'):
                if previous[name] is not None:
                    _finding(findings, 'sm_retained_' + name, state[name] == previous[name])
            for name in ('appended', 'ownership_applied', 'notification_attempted'):
                _finding(findings, 'sm_retained_' + name, not previous[name] or state[name])
        if state['terminal'] is not None:
            _finding(findings, 'sm_terminal_only_final', prefix is prefixes[-1] and state['terminal'] == expected['terminal'])
        previous = state
    _finding(findings, 'sm_entered_prefix', entered is not None)
    if expected['knowledge']['kind'] == 'ReceiptKnown':
        _finding(findings, 'sm_receipt_prefix', entered is not None and receipt is not None and
                 bool(prefixes) and entered < receipt < prefixes[-1]['seq'])
    if wanted['polls']:
        _finding(findings, 'sm_final_after_poll', len(turn['polls']) == 1 and bool(prefixes) and
                 prefixes[-1]['seq'] > turn['polls'][0]['seq'] and
                 all(prefix['seq'] < turn['polls'][0]['seq'] for prefix in prefixes[:-1]))
    return entered, receipt


def _sm_fixture_findings(value, ledger, payload):
    wanted = ledger['owner']
    if payload['recipient']['kind'] != 'Sm':
        return ['missing_sm_owner']
    actual, findings = payload['recipient'], []
    _finding(findings, 'sm_owner_inventory', len(actual['sm_turns']) == len(wanted['turns']) and
             len(actual['native_writes']) == len(wanted['native_writes']))
    original = next((item for item in payload['originals'] if item['frame_id'] == wanted['frame_id']), None)
    dequeued = original['route']['dequeued'] if original is not None else []
    raw_items = [dequeued[0]['xml'].encode('utf-8') if len(dequeued) == 1 else b''] + [
        item['xml'].encode('utf-8') for item in value['recipient_owner']['extra_items']]
    previous_end = dequeued[0]['seq'] if len(dequeued) == 1 else 0
    for index, (turn, expected_turn) in enumerate(zip(actual['sm_turns'], wanted['turns'])):
        entered, receipt = _sm_turn_findings(turn, expected_turn, findings)
        _finding(findings, 'sm_owner_sequence', entered is not None and bool(turn['prefixes']) and
                 previous_end < turn['prefixes'][0]['seq'] <= entered)
        if expected_turn['item_index'] is None:
            previous_end = turn['prefixes'][-1]['seq'] if turn['prefixes'] else previous_end
            continue
        if index >= len(actual['native_writes']):
            continue
        native, expected_native = actual['native_writes'][index], wanted['native_writes'][index]
        state = expected_native['state']
        _finding(findings, 'sm_native_identity', native['frame_id'] == expected_native['frame_id'] and
                 native['connection_id'] == expected_native['connection_id'])
        _finding(findings, 'sm_native_final_state', {name: native[name] for name in NATIVE_STATE_FIELDS.split()} == state)
        _finding(findings, 'sm_native_poll', [item['result'] for item in native['polls']] == expected_native['polls'])
        _finding(findings, 'sm_native_receipt_channels', not native['ownership_receipts'] and not native['write_receipts'])
        _finding(findings, 'sm_native_no_ack', not native['ack_calls'])
        _retained_native_prefixes(native['prefixes'], findings)
        pending = state['terminal'] == 'Cancelled'
        raw = raw_items[index]
        writes = [] if pending else [{'offered_len': len(raw), 'offered_sha256': _hash(raw),
                                      'accepted_bytes_hex': raw.hex(), 'result': 'Accepted'}]
        _finding(findings, 'sm_native_write_calls', bool(raw) and
                 [{name: call[name] for name in ('offered_len', 'offered_sha256', 'accepted_bytes_hex', 'result')}
                  for call in native['write_calls']] == writes)
        _finding(findings, 'sm_native_flush_calls', [call['result'] for call in native['flush_calls']] == ([] if pending else ['Ok']))
        prefixes, polls = native['prefixes'], native['polls']
        final_seq = prefixes[-1]['seq'] if prefixes else 0
        sm_final = turn['prefixes'][-1]['seq'] if turn['prefixes'] else 0
        recording = copy.deepcopy(state)
        recording.update(preparation='Recording', managed_by_sm=None, writer_entered=False,
                         writer_result=None, write_decision=None, terminal=None)
        _finding(findings, 'sm_native_prefix_cadence', len(prefixes) == (2 if pending else 3))
        _finding(findings, 'sm_native_recording_prefix', bool(prefixes) and prefixes[0]['state'] == recording and
                 bool(turn['prefixes']) and previous_end < prefixes[0]['seq'] < turn['prefixes'][0]['seq'])
        _finding(findings, 'sm_native_final_snapshot', bool(prefixes) and prefixes[-1]['state'] == state and
                 len(polls) == 1 and polls[0]['seq'] < final_seq)
        if len(polls) == 1:
            _finding(findings, 'sm_native_post_poll_snapshot',
                     [prefix['seq'] for prefix in prefixes if prefix['seq'] > polls[0]['seq']] == ([final_seq] if prefixes else []))
        _finding(findings, 'sm_native_call_poll_boundary', len(polls) == 1 and all(call['seq'] < polls[0]['seq']
                 for call in native['write_calls'] + native['flush_calls'] + native['ack_calls']))
        for prefix in prefixes:
            observed = prefix['state']
            _finding(findings, 'sm_native_prefix_source', observed['original'] == state['original'])
            _finding(findings, 'sm_native_no_fence', not observed['fence_entered'] and observed['returned_fence'] is None)
            _finding(findings, 'sm_native_ack_not_requested', observed['ack'] == {'kind': 'NotRequested'} and observed['ack_returned'] is None)
            if observed['terminal'] is not None:
                _finding(findings, 'sm_native_terminal_after_poll', prefix is prefixes[-1] and len(polls) == 1 and
                         polls[0]['seq'] < prefix['seq'])
            if observed['writer_result'] is not None:
                _finding(findings, 'sm_native_result_after_flush', observed['writer_result'] == 'FullWrite' and
                         len(native['flush_calls']) == 1 and native['flush_calls'][0]['seq'] < prefix['seq'])
        if pending:
            _finding(findings, 'sm_nested_cancelled_after_parent_poll', len(polls) == 1 and entered is not None and
                     entered < polls[0]['seq'] < sm_final < final_seq)
        else:
            first_write = native['write_calls'][0]['seq'] if len(native['write_calls']) == 1 else 0
            _finding(findings, 'sm_record_return_before_native_prepare', any(sm_final < prefix['seq'] < first_write and
                     prefix['state']['preparation'] == 'Prepared' and prefix['state']['managed_by_sm'] == state['managed_by_sm'] and
                     not prefix['state']['writer_entered'] for prefix in prefixes))
            _finding(findings, 'sm_write_then_flush', len(native['flush_calls']) == 1 and
                     first_write < native['flush_calls'][0]['seq'])
        previous_end = final_seq
    _finding(findings, 'sm_final_counters', (actual['outbound_h'], actual['acked_h']) == (wanted['outbound_h'], wanted['acked_h']))
    _finding(findings, 'sm_typed_handoff_inventory', [{name: item[name] for name in ('delivery_id', 'result')}
             for item in actual['mix_handoffs']] == wanted['mix_handoffs'])
    for handoff in actual['mix_handoffs']:
        indexes = [index for index, item in enumerate(wanted['native_writes']) if item['state']['original'] is not None and
                   item['state']['original']['kind'] == 'Mix' and item['state']['original']['delivery_id'] == handoff['delivery_id']]
        if len(indexes) == 1 and indexes[0] < len(actual['native_writes']) and indexes[0] < len(actual['sm_turns']):
            index = indexes[0]
            native, turn = actual['native_writes'][index], actual['sm_turns'][index]
            _finding(findings, 'sm_handoff_between_record_and_write', bool(turn['prefixes']) and bool(native['write_calls']) and
                     turn['prefixes'][-1]['seq'] < handoff['seq'] < native['write_calls'][0]['seq'] and
                     any(turn['prefixes'][-1]['seq'] < prefix['seq'] < handoff['seq'] and
                         prefix['state']['preparation'] == 'Prepared' for prefix in native['prefixes']))
    fifo = [{'xml': _tree(_xml(slot['xml'], projected=None)),
             'source': slot['source']} for slot in actual['fifo_after']]
    _finding(findings, 'sm_final_fifo', fifo == wanted['fifo_after'])
    acknowledged = wanted['turns'][-1]['state']['h_decision'].get('count', 0) if wanted['turns'] else 0
    _finding(findings, 'sm_fifo_byte_continuity', [slot['xml'].encode('utf-8') for slot in actual['fifo_after']] ==
             raw_items[acknowledged:len(wanted['native_writes'])])
    return findings


def _inspect_sm_fixture(fixture, record, payload):
    """Pure SM supplied-evidence matcher; no public profile can invoke it yet."""
    if type(record) is not dict or record.get('observation') != 'Complete':
        return None, None, False, record.get('observation', 'IncompleteProcess') if type(record) is dict else 'IncompleteProcess'
    process = record.get('process')
    if type(process) is not dict or type(process.get('returncode')) is not int or process['returncode'] != 0:
        return None, None, False, 'ProcessFailure'
    value = parse_case_input(fixture['bytes'])
    ledger = derive_owner_ledger(value)
    _need(ledger['owner']['kind'] == 'Sm', 'sm_fixture_owner')
    try:
        validate_case_evidence(payload)
    except (DirectCaseInvalid, DirectCaseIncomplete, TypeError, KeyError, ValueError) as error:
        evaluation = {'schema': 'northstar-direct-evaluation-v1', 'verdict': 'Inconclusive', 'qualified': False,
                      'invariant': None, 'violations': [], 'mismatches': ['malformed_evidence:' + str(error)[:160]]}
        return None, evaluation, False, 'MalformedOrUnexpectedOutput'
    if payload['input_sha256'] != _hash(fixture['bytes']):
        evaluation = {'schema': 'northstar-direct-evaluation-v1', 'verdict': 'Inconclusive', 'qualified': False,
                      'invariant': None, 'violations': [], 'mismatches': ['raw_input_binding']}
        return copy.deepcopy(payload), evaluation, False, 'InputBindingMismatch'
    findings, violations = [], []
    if payload['rejection'] is not None:
        findings.append('unexpected_rejection')
    else:
        violations = _authority_safety_findings(ledger['sender'], payload) + sm_safety_findings(value, payload)
        try:
            findings.extend(projection_findings(ledger['sender'], payload))
            findings.extend(_sm_fixture_findings(value, ledger, payload))
        except (DirectCaseInvalid, ET.ParseError, ValueError) as error:
            findings.append('owner_xml:' + str(error)[:160])
        findings.extend(_original_fixture_findings(value, ledger['sender'], payload))
        _finding(findings, 'driver_execution', payload['execution'] == ledger['owner']['execution'])
        _finding(findings, 'unexpected_safety_failure', not violations)
    invariant = violations[0] if violations else None
    if violations:
        verdict = 'InvariantViolation'
    elif payload['rejection'] is not None:
        verdict = 'InvalidScenario'
    elif payload['execution'] == 'Cancelled':
        verdict = 'Cancelled'
    elif findings:
        verdict = 'InvariantViolation'
        invariant = {'id': 'DirectFixtureDivergence', 'class': 'ReplayDivergence', 'location': findings[0]}
    else:
        verdict = 'Pass'
    matched = not findings and verdict == fixture['expected_verdict']
    evaluation = {'schema': 'northstar-direct-evaluation-v1', 'verdict': verdict, 'qualified': verdict == 'Pass',
                  'invariant': invariant, 'violations': violations, 'mismatches': findings}
    return copy.deepcopy(payload), evaluation, matched, None if matched else 'FixtureMismatch'


def replacement_safety_findings(value, payload):
    """The fixed shared-row history permits a stale attempt, never stale commit."""
    ledger = derive_owner_ledger(value)
    validate_case_evidence(payload)
    if ledger['owner']['kind'] != 'NativeReplacement' or payload['rejection'] is not None or payload['recipient']['kind'] != 'NativeReplacement':
        return []
    expected, actual = ledger['owner'], payload['recipient']
    original = next((item for item in payload['originals'] if item['frame_id'] == expected['old']['frame_id']), None)
    old_dequeue = original['route']['dequeued'] if original is not None else []
    old_raw = old_dequeue[0]['xml'].encode('utf-8') if len(old_dequeue) == 1 else None
    new_raw = actual['replacement_dequeued']['xml'].encode('utf-8')
    violations = []
    identities = {}
    for name, raw in (('old', old_raw), ('replacement', new_raw)):
        native, wanted = actual[name], expected[name]
        identity = {'frame_id': wanted['frame_id'], 'connection_id': wanted['connection_id'],
                    'original_source': wanted['state']['original'], 'fenced_source': wanted['state']['returned_fence']}
        identities[name] = identity
        violations.extend(_native_settlement_findings(identity, native, raw))
    def row_violation(identity, source):
        violations.append({'id': identity, 'class': 'Safety', 'target': {
            'frame_id': expected['old']['frame_id'], 'owner': 'ControlledNativeRow',
            'purpose': 'ReplacementSettlement', 'source': copy.deepcopy(source)}})
    if actual['replacement_dequeued']['source'] != identities['replacement']['original_source'] and (
            actual['replacement']['write_calls'] or actual['replacement']['ack_calls']):
        row_violation('NativeReplacementDequeueIdentityMismatch', actual['replacement_dequeued']['source'])
    row = copy.deepcopy(value['recipient_owner']['initial_row'])
    old_fence = next((prefix for prefix in actual['old']['prefixes'] if
                     prefix['state']['preparation'] == 'Prepared' and prefix['state']['fence_entered'] and
                     prefix['state']['returned_fence'] == identities['old']['fenced_source']), None)
    events = [(event['seq'], event['kind'], event) for event in actual['row_events']]
    if old_fence is not None:
        events.append((old_fence['seq'], 'InitialNativeFence', identities['old']['fenced_source']))
    allowed_reads = []
    deletion_sources = []
    for sequence, kind, event in sorted(events, key=lambda item: item[0]):
        if kind == 'InitialNativeFence':
            row = copy.deepcopy(event)
        elif kind == 'Replace':
            expected_before = identities['old']['fenced_source']
            expected_after = identities['replacement']['fenced_source']
            if row != expected_before or event != {
                    'seq': sequence, 'kind': 'Replace', 'recipient_id': expected_after['recipient_id'],
                    'message_id': expected_after['message_id'], 'before_claim_id': expected_before['claim_id'],
                    'after_claim_id': expected_after['claim_id']}:
                row_violation('NativeReplacementAuthorityMismatch', row)
            row = {'kind': 'C2s', 'recipient_id': event['recipient_id'],
                   'message_id': event['message_id'], 'claim_id': event['after_claim_id']}
        elif kind == 'AuthorityRead':
            same_row = row is not None and all(row[name] == event['source'][name] for name in ('recipient_id', 'message_id'))
            current = row['claim_id'] if same_row else None
            matches = same_row and event['source']['claim_id'] is not None and event['source']['claim_id'] == current
            if event['current_claim_id'] != current or event['matches'] != matches:
                row_violation('NativeClaimAuthorityReadMismatch', event['source'])
            if matches and event['matches'] and event['current_claim_id'] == current:
                allowed_reads.append(event)
        else:
            if row != event['source']:
                row_violation('NativeRowDeleteWithoutCurrentClaim', event['source'])
            deletion_sources.append((sequence, copy.deepcopy(event['source'])))
            row = None
    authorized_receipts = []
    for name in ('old', 'replacement'):
        native, identity = actual[name], identities[name]
        bound_call = (native['frame_id'] == identity['frame_id'] and native['connection_id'] == identity['connection_id'] and
                      len(native['ack_calls']) == 1 and native['ack_calls'][0]['source'] == identity['fenced_source'])
        entered_authority = None
        first_receipt = None
        for prefix in native['prefixes']:
            state, knowledge = prefix['state'], prefix['state']['ack']
            if knowledge['kind'] in ('CommitCallEntered', 'ReceiptKnown'):
                fact_bound = knowledge['fact'] == {'source': identity['fenced_source'], 'disposition': 'Deleted'}
                reads = [event for event in allowed_reads if event['source'] == identity['fenced_source'] and
                         bound_call and native['ack_calls'][0]['seq'] + 1 < event['seq'] < prefix['seq']]
                active_reads = [read for read in reads if not any(read['seq'] < event['seq'] < prefix['seq'] and
                                event['kind'] in ('Replace', 'Delete') for event in actual['row_events'])]
                if knowledge['kind'] == 'CommitCallEntered' and entered_authority is None and bound_call and fact_bound and active_reads:
                    entered_authority = prefix['seq']
                authorized = bound_call and fact_bound and entered_authority is not None
                if knowledge['kind'] == 'ReceiptKnown' and first_receipt is None:
                    authorized = authorized and entered_authority < prefix['seq'] and bool(active_reads)
                    if authorized:
                        first_receipt = prefix['seq']
                        authorized_receipts.append((prefix['seq'], identity['fenced_source']))
                if not authorized:
                    row_violation('NativeCommitWithoutCurrentClaimAuthority', knowledge['fact']['source'])
            if state['ack_returned'] is True and knowledge['kind'] != 'ReceiptKnown':
                row_violation('NativePositiveReturnWithoutReceipt', identity['fenced_source'])
    for sequence, source in deletion_sources:
        if not any(receipt_seq < sequence and receipt_source == source for receipt_seq, receipt_source in authorized_receipts):
            row_violation('NativeRowDeleteWithoutReceipt', source)
    if actual['row_after'] is None and row is not None:
        row_violation('NativeRowDisappearedWithoutObservedDelete', row)
    return violations


def _replacement_fixture_findings(value, ledger, payload):
    wanted = ledger['owner']
    if payload['recipient']['kind'] != 'NativeReplacement':
        return ['missing_replacement_owner']
    actual, findings = payload['recipient'], []
    original = next((item for item in payload['originals'] if item['frame_id'] == wanted['old']['frame_id']), None)
    dequeued = original['route']['dequeued'] if original is not None else []
    raw = dequeued[0]['xml'].encode('utf-8') if len(dequeued) == 1 else b''
    replacement_dequeue = actual['replacement_dequeued']
    _finding(findings, 'replacement_dequeue_source', replacement_dequeue['source'] == wanted['replacement_dequeued']['source'])
    _finding(findings, 'replacement_dequeue_projection', _tree(_xml(replacement_dequeue['xml'], projected=True)) ==
             wanted['replacement_dequeued']['xml'])
    _finding(findings, 'replacement_dequeue_bytes', replacement_dequeue['xml'].encode('utf-8') == raw)
    _finding(findings, 'replacement_row_events', [{name: item[name] for name in item if name != 'seq'}
             for item in actual['row_events']] == wanted['row_events'])
    _finding(findings, 'replacement_row_after', actual['row_after'] == wanted['row_after'])
    for name in ('old', 'replacement'):
        native, expected = actual[name], wanted[name]
        state = expected['state']
        _finding(findings, 'replacement_native_identity', native['frame_id'] == expected['frame_id'] and
                 native['connection_id'] == expected['connection_id'])
        _finding(findings, 'replacement_native_final', {field: native[field] for field in NATIVE_STATE_FIELDS.split()} == state)
        _finding(findings, 'replacement_native_prefixes', [prefix['state'] for prefix in native['prefixes']] == _expected_native_prefixes(state))
        _retained_native_prefixes(native['prefixes'], findings)
        _finding(findings, 'replacement_native_polls', [poll['result'] for poll in native['polls']] == expected['polls'])
        _finding(findings, 'replacement_native_receipt_channels', not native['ownership_receipts'] and not native['write_receipts'])
        _finding(findings, 'replacement_native_writes', bool(raw) and [
            {field: call[field] for field in ('offered_len', 'offered_sha256', 'accepted_bytes_hex', 'result')}
            for call in native['write_calls']] == [{'offered_len': len(raw), 'offered_sha256': _hash(raw),
                                                  'accepted_bytes_hex': raw.hex(), 'result': 'Accepted'}])
        _finding(findings, 'replacement_native_flush', [call['result'] for call in native['flush_calls']] == ['Ok'])
        _finding(findings, 'replacement_native_ack', [(call['source'], call['returned']) for call in native['ack_calls']] ==
                 [(state['returned_fence'], state['ack_returned'])])
        prefixes, polls = native['prefixes'], native['polls']
        _finding(findings, 'replacement_final_after_poll', bool(prefixes) and bool(polls) and
                 polls[-1]['seq'] < prefixes[-1]['seq'] and all(prefix['seq'] < polls[-1]['seq'] for prefix in prefixes[:-1]))
        if len(prefixes) >= 4 and len(native['ack_calls']) == 1:
            _finding(findings, 'replacement_adjacent_ack_boundary', prefixes[3]['seq'] == native['ack_calls'][0]['seq'] + 1)
        if len(prefixes) >= 3 and native['write_calls'] and native['flush_calls'] and native['ack_calls']:
            _finding(findings, 'replacement_write_flush_ack_order', prefixes[2]['seq'] < native['write_calls'][0]['seq'] <
                     native['flush_calls'][0]['seq'] < native['ack_calls'][0]['seq'])
    old, replacement, events = actual['old'], actual['replacement'], actual['row_events']
    if len(events) == 4 and len(old['prefixes']) == 5 and len(replacement['prefixes']) == 7 and len(old['polls']) == 2 and len(replacement['polls']) == 1:
        _finding(findings, 'replacement_actual_boundary_order', len(dequeued) == 1 and
                 dequeued[0]['seq'] < old['prefixes'][0]['seq'] and
                 old['prefixes'][3]['seq'] < old['polls'][0]['seq'] < events[0]['seq'] < replacement_dequeue['seq'] <
                 events[1]['seq'] < old['polls'][1]['seq'] < old['prefixes'][-1]['seq'] < replacement['prefixes'][0]['seq'] and
                 replacement['prefixes'][3]['seq'] < events[2]['seq'] < replacement['prefixes'][4]['seq'] <
                 replacement['prefixes'][5]['seq'] < events[3]['seq'] < replacement['polls'][0]['seq'] < replacement['prefixes'][-1]['seq'])
    else:
        findings.append('replacement_boundary_inventory')
    return findings


def _inspect_replacement_fixture(fixture, record, payload):
    """Pure C13 evidence inspection, independent of any expected-output sample."""
    if type(record) is not dict or record.get('observation') != 'Complete':
        return None, None, False, record.get('observation', 'IncompleteProcess') if type(record) is dict else 'IncompleteProcess'
    process = record.get('process')
    if type(process) is not dict or type(process.get('returncode')) is not int or process['returncode'] != 0:
        return None, None, False, 'ProcessFailure'
    value = parse_case_input(fixture['bytes'])
    ledger = derive_owner_ledger(value)
    _need(ledger['owner']['kind'] == 'NativeReplacement', 'replacement_fixture_owner')
    try:
        validate_case_evidence(payload)
    except (DirectCaseInvalid, DirectCaseIncomplete, TypeError, KeyError, ValueError) as error:
        evaluation = {'schema': 'northstar-direct-evaluation-v1', 'verdict': 'Inconclusive', 'qualified': False,
                      'invariant': None, 'violations': [], 'mismatches': ['malformed_evidence:' + str(error)[:160]]}
        return None, evaluation, False, 'MalformedOrUnexpectedOutput'
    if payload['input_sha256'] != _hash(fixture['bytes']):
        evaluation = {'schema': 'northstar-direct-evaluation-v1', 'verdict': 'Inconclusive', 'qualified': False,
                      'invariant': None, 'violations': [], 'mismatches': ['raw_input_binding']}
        return copy.deepcopy(payload), evaluation, False, 'InputBindingMismatch'
    findings, violations = [], []
    if payload['rejection'] is not None:
        findings.append('unexpected_rejection')
    else:
        violations = _authority_safety_findings(ledger['sender'], payload) + replacement_safety_findings(value, payload)
        try:
            findings.extend(projection_findings(ledger['sender'], payload))
            findings.extend(_replacement_fixture_findings(value, ledger, payload))
        except (DirectCaseInvalid, ET.ParseError, ValueError) as error:
            findings.append('owner_xml:' + str(error)[:160])
        findings.extend(_original_fixture_findings(value, ledger['sender'], payload))
        _finding(findings, 'driver_execution', payload['execution'] == 'Complete')
        _finding(findings, 'unexpected_safety_failure', not violations)
    invariant = violations[0] if violations else None
    if violations:
        verdict = 'InvariantViolation'
    elif payload['rejection'] is not None:
        verdict = 'InvalidScenario'
    elif payload['execution'] == 'Cancelled':
        verdict = 'Cancelled'
    elif findings:
        verdict = 'InvariantViolation'
        invariant = {'id': 'DirectFixtureDivergence', 'class': 'ReplayDivergence', 'location': findings[0]}
    else:
        verdict = 'Pass'
    matched = not findings and verdict == fixture['expected_verdict']
    evaluation = {'schema': 'northstar-direct-evaluation-v1', 'verdict': verdict, 'qualified': verdict == 'Pass',
                  'invariant': invariant, 'violations': violations, 'mismatches': findings}
    return copy.deepcopy(payload), evaluation, matched, None if matched else 'FixtureMismatch'


def _authority_safety_findings(ledger, payload):
    findings = []
    expected_by_id = {item['frame_id']: item for item in ledger['originals']}
    for actual in payload['originals']:
        expected = expected_by_id.get(actual['frame_id'])
        for call in actual['route']['enqueue'] + actual['route']['remote_calls'] + actual['route']['rearm_calls']:
            target = {'frame_id': actual['frame_id'], 'source': copy.deepcopy(call['source'])}
            if expected is None or call['source'] != expected['source']:
                findings.append({'id': 'HandoffSourceIdentityMismatch', 'class': 'Safety', 'target': target})
                continue
            authority = _direct_expected(expected['direct'])
            known = authority['knowledge']['kind'] == 'ReceiptKnown' and expected['direct']['transaction']['kind'] == 'Stored'
            receipt_before = known and any(
                prefix['seq'] < call['seq'] and prefix['state']['direct'] is not None and
                prefix['state']['direct']['correlation'] == authority['correlation'] and
                prefix['state']['direct']['knowledge'] == authority['knowledge']
                for prefix in actual['prefixes'])
            if not receipt_before:
                findings.append({'id': 'HandoffWithoutStoredReceipt', 'class': 'Safety', 'target': target})
    return findings


def _inspect_native_fixture(fixture, record, payload):
    """Pure supplied-evidence inspection; the public runner gate stays closed.

    Expected failure permission affects only exact fixture matching. Normative
    Safety and the actual verdict are computed first, independently of the
    fixture's expected outcome, profile name or executable/source identity.
    """
    if type(record) is not dict or record.get('observation') != 'Complete':
        return None, None, False, record.get('observation', 'IncompleteProcess') if type(record) is dict else 'IncompleteProcess'
    process = record.get('process')
    if type(process) is not dict or type(process.get('returncode')) is not int or process['returncode'] != 0:
        return None, None, False, 'ProcessFailure'
    raw = fixture['bytes']
    reason = rejection_reason(raw)
    value = ledger = None
    if reason is None:
        value = parse_native_input(raw)
        ledger = derive_native_ledger(value)
    findings, violations = [], []
    try:
        validate_native_evidence(payload)
    except (DirectCaseInvalid, DirectCaseIncomplete, TypeError, KeyError, ValueError) as error:
        evaluation = {'schema': 'northstar-direct-evaluation-v1', 'verdict': 'Inconclusive', 'qualified': False,
                      'invariant': None, 'violations': [], 'mismatches': ['malformed_evidence:' + str(error)[:160]]}
        return None, evaluation, False, 'MalformedOrUnexpectedOutput'
    if payload['input_sha256'] != _hash(raw):
        evaluation = {'schema': 'northstar-direct-evaluation-v1', 'verdict': 'Inconclusive', 'qualified': False,
                      'invariant': None, 'violations': [], 'mismatches': ['raw_input_binding']}
        return copy.deepcopy(payload), evaluation, False, 'InputBindingMismatch'
    if reason is not None:
        _finding(findings, 'fixed_rejection_input', fixture['kind'] == 'rejection' and
                 reason in ('DuplicateKey', 'UnknownField', 'IdentityBinding') and fixture['reason'] == reason)
        _finding(findings, 'exact_rejection', payload['rejection'] == {'class': 'InvalidScenario', 'reason': reason})
        matched = not findings
        evaluation = {'schema': 'northstar-direct-evaluation-v1', 'verdict': 'InvalidScenario', 'qualified': False,
                      'invariant': None, 'violations': [], 'mismatches': findings}
        return copy.deepcopy(payload), evaluation, matched, None if matched else 'FixtureMismatch'
    if payload['rejection'] is not None:
        findings.append('unexpected_rejection')
    else:
        # The predicates see every well-formed unsafe call before any baseline
        # comparison. Missing/incorrect XML remains a saved failed observation.
        violations = _authority_safety_findings(ledger, payload) + native_safety_findings(value, payload)
        expected_failure = fixture.get('expected_failure')
        no_flush = expected_failure is not None
        if no_flush:
            _finding(findings, 'expected_failure_authority', expected_failure == _native_failure_target(ledger))
        try:
            findings.extend(projection_findings(ledger, payload))
        except (DirectCaseInvalid, ET.ParseError, ValueError) as error:
            findings.append('projected_xml:' + str(error)[:160])
        findings.extend(_original_fixture_findings(value, ledger, payload))
        findings.extend(_native_fixture_findings(ledger, payload, no_flush=no_flush))
        cancelled = any(item['terminal'] == 'Cancelled' for item in ledger['originals']) or \
            (ledger['native'] is not None and _expected_native_state(ledger, no_flush=no_flush)['terminal'] == 'Cancelled')
        _finding(findings, 'driver_execution', payload['execution'] == ('Cancelled' if cancelled else 'Complete'))
        if no_flush:
            native = payload['recipient'].get('native')
            _finding(findings, 'exact_expected_native_failure', violations == [expected_failure] and native is not None and
                     len(native['ack_calls']) == 1 and native['ack_calls'][0]['source'] == expected_failure['target']['source'] and
                     native['ack']['kind'] in ('CommitCallEntered', 'ReceiptKnown') and
                     native['ack']['fact']['source'] == native['ack_calls'][0]['source'])
        else:
            _finding(findings, 'unexpected_safety_failure', not violations)
    invariant = violations[0] if violations else None
    if violations:
        verdict = 'InvariantViolation'
    elif payload['rejection'] is not None:
        verdict = 'InvalidScenario'
    elif payload['execution'] == 'Cancelled':
        verdict = 'Cancelled'
    elif findings:
        verdict = 'InvariantViolation'
        invariant = {'id': 'DirectFixtureDivergence', 'class': 'ReplayDivergence', 'location': findings[0]}
    else:
        verdict = 'Pass'
    matched = not findings and verdict == fixture['expected_verdict']
    evaluation = {'schema': 'northstar-direct-evaluation-v1', 'verdict': verdict, 'qualified': verdict == 'Pass',
                  'invariant': invariant, 'violations': violations, 'mismatches': findings}
    return copy.deepcopy(payload), evaluation, matched, None if matched else 'FixtureMismatch'


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
