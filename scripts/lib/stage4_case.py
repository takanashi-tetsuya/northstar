"""Private, source-only independent Stage4 semantic reader. NOT EXECUTED.

This module neither starts a process nor authenticates an artifact or occurrence.
Its results are semantic inspections, never saved-run qualification. The caller
must discharge CALLER_CONTRACT.md using the existing external supervisor first.
The closed grammar is a frozen table, not an extension to Stage3. No Rust code is
loaded, evaluated, imported or asked to adjudicate its own output.
"""
from dataclasses import dataclass
from pathlib import Path
import copy
import hashlib
import json
import re
import xml.etree.ElementTree as ET

from . import stage4_compact

CASE_SCHEMA = 'northstar-stage4-composition-case-v1'
EVIDENCE_SCHEMA = 'northstar-stage4-composition-evidence-v1'
ADAPTER = 'local-stage4-composition-controlled-v1'
ENTRY = 'stage4_replay::replay_saved_case'
FRAME_TAG = b'\x1eNORTHSTAR_STAGE4_COMPOSITION_V1 '
MAX_INPUT, MAX_FRAME, MAX_FACTS, MAX_POLLS = 65536, 131072, 256, 64
SCHEMA_SOURCE_SHA256 = '3c5f2e26bec9ede91f163b5246d0e3f7aae50d39b084d0a72c655c2948e0d636'
SHAPES_SHA256 = 'fc481c94bbd99e3891235b54f32450ec951c41ab4d56b3b04477ed3c01d30e38'
TARGET = 'BoshCacheBeforeSelectedAuthCompletion'
POLL_MAX = dict(Muc=2, Foreground=2, Claim=1, Worker=1, Credential=1,
                Native=4, Publication=1, Bosh=3)
UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z')
HEX = re.compile(r'[0-9a-f]*\Z')
EMPTY_MEMBERSHIP = {'c2s_message_ids': [], 'mix_delivery_ids': []}
LOCI = {
    **dict.fromkeys(('frame', 'frame_id', 'foreground_frame'), 'Frame'),
    **dict.fromkeys(('connection', 'connection_id', 'connection_uuid', 'caps_connection',
                     'first_validated_connection', 'validated_connection'), 'Connection'),
    'session': 'Session', 'session_id': 'Session', 'attempt': 'CredentialAttempt',
    'constructed_receipt': 'ConstructedReceipt', 'returned_receipt': 'ReturnedReceipt',
    'transferred_receipt': 'TransferredReceipt', 'begun_receipt': 'BegunReceipt',
    'control': 'ControlIdentity', 'auth_control': 'ControlIdentity',
    'receipt': 'ReceiptAssociation', 'personal_archive_id': 'ArchiveCandidate',
    'stage_id': 'StageIdentity', 'delivery_id': 'SourceIdentity',
    'lease_token': 'SourceIdentity', 'message_id': 'SourceIdentity', 'claim_id': 'SourceIdentity',
}


class Stage4Invalid(ValueError):
    """Closed input or wire-encoding rejection; never the causal mutant."""


class Stage4Incomplete(ValueError):
    """Missing factual evidence; never successful acceptance."""


def _need(ok, reason='Relationship'):
    if not ok:
        raise Stage4Invalid(reason)


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _pairs(items):
    out = {}
    for k, v in items:
        _need(k not in out, 'Json:DuplicateKey')
        out[k] = v
    return out


def _json(raw, cap):
    _need(type(raw) is bytes and len(raw) <= cap, 'TooLarge')
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Stage4Invalid('Json:Nonfinite')))
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        if isinstance(error, Stage4Invalid):
            raise
        raise Stage4Invalid('Json') from error


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')


def _key(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def _kind(value):
    return value['kind'] if value is not None else None


def _data(value):
    return value['data']


def _fixed(value):
    return {'kind': 'Fixed', 'data': {'uuid': value}}


def _text(value, cap):
    _need(type(value) is str, 'Json:String')
    try:
        _need(len(value.encode('utf-8')) <= cap and '\0' not in value, 'Bound:Text')
    except UnicodeError as error:
        raise Stage4Invalid('Json:Unicode') from error


def _fields(value, names):
    _need(type(value) is dict and set(value) == set(names), 'Json:ObjectFields')


# Only this fixed sibling is loaded, verified by byte digest and schema binding.
# Neither API callers nor inputs can choose a table, filename, root or type.
def _load_shapes():
    raw = Path(__file__).with_name('stage4_shapes.json').read_bytes()
    _need(_hash(raw) == SHAPES_SHA256, 'ReaderSource:ShapeDigest')
    table = _json(raw, 200000)
    _need(table['schema_source_sha256'] == SCHEMA_SOURCE_SHA256 and
          table['roots'] == ['Case', 'Envelope'], 'ReaderSource:SchemaBinding')
    return table['shapes']


SHAPES = _load_shapes()


def _shape(value, node, visit=None, locus='UnexpectedObservedIdentity', depth=0):
    _need(depth <= 48, 'Bound:Depth')
    tag = node[0]
    if tag == 'ref':
        return _shape(value, SHAPES[node[1]], visit, locus, depth + 1)
    if tag == 'nullable':
        return None if value is None else _shape(value, node[1], visit, locus, depth + 1)
    if tag in ('list', 'array'):
        _need(type(value) is list and (len(value) == node[2] if tag == 'array' else len(value) <= node[2]), 'Bound:List')
        return [_shape(x, node[1], visit, locus, depth + 1) for x in value]
    if tag == 'object':
        _fields(value, [f[0] for f in node[1]])
        return {name: _shape(value[name], child, visit, LOCI.get(name, 'UnexpectedObservedIdentity'), depth + 1)
                for name, child in node[1]}
    if tag == 'sum':
        _fields(value, ('kind', 'data'))
        variants = dict(node[1])
        _need(type(value['kind']) is str and value['kind'] in variants, 'Json:SumTag')
        return {'kind': value['kind'], 'data': _shape(value['data'], variants[value['kind']], visit, locus, depth + 1)}
    if tag == 'enum':
        _need(type(value) is str and value in node[1], 'Json:Enum')
    elif tag == 'bool':
        _need(type(value) is bool, 'Json:Boolean')
    elif tag == 'int':
        _need(type(value) is int and node[1] <= value <= node[2], 'Json:Integer')
    elif tag == 'text':
        _text(value, node[1])
    elif tag in ('hex', 'bytes'):
        _need(type(value) is str and HEX.fullmatch(value) is not None and len(value) % 2 == 0 and
              (len(value) == 2 * node[1] if tag == 'hex' else len(value) <= 2 * node[1]), 'Encoding:Hex')
    elif tag == 'Id':
        _need(type(value) is str and UUID.fullmatch(value) is not None, 'Encoding:Uuid')
        return visit(value, locus) if visit else value
    elif tag in ('EvidenceId', 'IdentityLabel'):
        _fields(value, ('kind', 'data'))
        if value['kind'] == 'Fixed':
            _fields(value['data'], ('uuid',))
            _shape(value['data']['uuid'], ['Id'])
        else:
            _need(value['kind'] == 'Opaque', 'Encoding:IdentityTag')
            _fields(value['data'], ('ordinal',))
            _shape(value['data']['ordinal'], ['int', 0, 255])
        value = {'kind':value['kind'],'data':({'uuid':value['data']['uuid']} if value['kind']=='Fixed' else {'ordinal':value['data']['ordinal']})}
        return visit(value, locus) if visit and tag == 'EvidenceId' else value
    else:
        raise Stage4Invalid('ReaderSource:UnknownShape')
    return value


def _xml(text):
    # No DTD/entity expansion, external entity or network source is accepted.
    _need('<!DOCTYPE' not in text.upper() and '<!ENTITY' not in text.upper(), 'Encoding:XmlDtd')
    try:
        return ET.fromstring(text)
    except (ET.ParseError, ValueError) as error:
        raise Stage4Invalid('Encoding:Xml') from error


def _bare(value, full=False):
    # Saved finite literals are ASCII canonical JIDs. This is deliberately not
    # a Python reimplementation of general production Unicode JID preparation.
    _need(value.isascii() and value.strip() == value and '@' in value, 'Encoding:Jid')
    base, slash, resource = value.partition('/')
    local, domain = base.rsplit('@', 1)
    _need(bool(local and domain) and domain == domain.lower() and not any(c.isspace() for c in base), 'Encoding:Jid')
    _need((bool(slash and resource) if full else not slash), 'Encoding:JidKind')
    return base


def _auth_xml(auth):
    return auth['control']['data']['xml']


def _write(plan, text):
    n = len(text.encode('utf-8'))
    _need(1 <= plan['chunk_limit'] <= 4096 and (n + plan['chunk_limit'] - 1) // plan['chunk_limit'] <= 32)
    _need(plan['fail_after_accepted_bytes'] is None and plan['flush'] == 'Ok')


def _auth(auth, kind, transport):
    _need(not auth['notification_expected'], 'Unsupported')
    p, f, b = auth['preparation'], auth['frame'], auth['binding']
    _need(auth['credential_kind'] == kind and f['transport'] == transport and auth['ordinal'] == 0 and auth['auth_generation'] >= 0)
    _need(p['generation_allowed'] and p['commit'] == 'Complete' and (p['stage_epoch'] is not None) == p['stage_present'])
    if _kind(auth['publication']) in ('Committed', 'CommitPending'):
        _need((auth['publication']['data']['epoch'] is not None) == p['stage_present'])
    _xml(f['input'])
    x = _xml(_auth_xml(auth)); c = auth['control']['data']
    _need(_kind(auth['control']) == kind)
    if kind == 'Binding':
        _need(b is not None and b['full_jid'] == c['full_jid'] and 1 <= b['lease_seconds'] <= 3600)
        _bare(c['full_jid'], True)
        _need(bool(b['resource']) and c['full_jid'].rsplit('/', 1)[1] == b['resource'])
        _need(p['binding_reserved'] and p['stage_present'] == (auth['device_id'] is not None))
        _need(x.tag == '{jabber:client}iq' and x.attrib == {'id': c['iq_id'], 'type': 'result'} and len(x) == 1)
        bind = x[0]
        _need(bind.tag == '{urn:ietf:params:xml:ns:xmpp-bind}bind' and not bind.attrib and len(bind) == 1)
        jid = bind[0]
        _need(jid.tag == '{urn:ietf:params:xml:ns:xmpp-bind}jid' and not jid.attrib and not len(jid) and jid.text == c['full_jid'])
    else:
        _bare(c['authorization_identifier'])
        _need(b is None and auth['device_id'] is None and not p['binding_reserved'] and not p['stage_present'])
        _need(x.tag == '{urn:xmpp:sasl:2}success' and not x.attrib and len(x) == 1)
        _need(x[0].tag == '{urn:xmpp:sasl:2}authorization-identifier' and not x[0].attrib and not len(x[0]) and x[0].text == c['authorization_identifier'])
        _need(_kind(auth['publication']) == 'NoSql')
    _need('<token' not in _auth_xml(auth) and '<additional-data' not in _auth_xml(auth))


def _ascii_u64(text):
    _need(type(text) is str and re.fullmatch(r'[0-9]+', text) is not None, 'Relationship')
    canonical = text.lstrip('0') or '0'
    _need(len(canonical) < 20 or (len(canonical) == 20 and canonical <= '18446744073709551615'), 'Relationship')
    return int(canonical)


def _request(request, session):
    _need(request['rid'] > 0 and 'Open' in request['responders'])
    _need(request['fingerprint'] == _hash(request['request_xml'].encode()))
    x = _xml(request['request_xml'])
    _need(x.tag == '{http://jabber.org/protocol/httpbind}body' and x.get('sid') == session)
    _need(_ascii_u64(x.get('rid', '')) == request['rid'])
    return x


def _session(session):
    g = session['governor']
    _need(session['max_response_bytes'] == 16384 and session['max_output_bytes'] == 65536 and 1 <= session['ttl_seconds'] <= 3600)
    _need(65536 <= g['max_bytes'] <= 1048576 and g['max_snapshot_bytes'] <= g['max_bytes'] and
          g['max_snapshot_bytes'] <= g['max_recovery_bytes'] <= 1048576 and 1 <= g['max_recovery_jobs'] <= 2)
    _need(session['bind']['commit'] == 'Complete'); _request(session['response'], session['session_id'])


def _route(route):
    _need(1 <= route['queue_capacity'] <= 2)
    keys = set()
    for r in route['targets']:
        _bare(r['full_jid'], True)
        _need(r['full_jid'] not in keys and r['user_id'] == route['enabled_account_id'] and r['auth_generation'] >= 0)
        keys.add(r['full_jid'])
        _need(r['caps']['connection_id'] == r['connection_id'])
        _need(len(set(r['caps']['verified_features'])) == len(r['caps']['verified_features']))
        _need(r['routable'] == (_kind(r['provenance']) == 'InitiallyPublished'))


def _attempt(a):
    c = a['claim']
    _need(c['limit'] == 1 and 1 <= c['max_bytes'] <= 4096 and c['attempt_count'] >= 0 and c['route_wake_generation'] >= 0)
    _need(c['commit'] == 'Complete' and a['archive']['commit'] == 'Complete'); _route(a['route'])


def _worker(w):
    _attempt(w['attempt'])
    if _kind(w['origin']) == 'InitialDurableRow':
        row, claim = w['origin']['data'], w['attempt']['claim']
        _bare(row['channel_jid']); _bare(row['recipient_jid']); _xml(row['stanza'])
        _need(row['source']['lease_token'] == claim['lease_token'] and row['attempt_count'] == claim['attempt_count'] and row['route_wake_generation'] == claim['route_wake_generation'])
        _need(row['archive'] and row['authoritative_stanza_id'] is not None)
        for r in w['attempt']['route']['targets']:
            _need(_bare(r['full_jid'], True) == row['recipient_jid'])


def _delivered(route):
    _need(not route['privacy_blocked'] and len(route['targets']) == 1)
    r = route['targets'][0]
    _need(not r['disconnected'] and r['lifecycle'] == 'Active' and bool(r['caps']['verified_features']))


def _delivery(w):
    return w['origin']['data']['declared_delivery_id'] if _kind(w['origin']) == 'FreshProjection' else w['origin']['data']['source']['delivery_id']


def _transport(w, t, ack):
    s = t['session']; _session(s); _delivered(w['attempt']['route'])
    _need(t['transfer']['commit'] == 'Complete' and t['transfer']['returned_source']['delivery_id'] == _delivery(w))
    _need(s['bind']['membership'] == {'c2s_message_ids': [], 'mix_delivery_ids': [_delivery(w)]})
    _need(any(r['connection_id'] == s['connection_id'] for r in w['attempt']['route']['targets']))
    _need((t['ack'] is not None) == ack)
    if ack:
        a = t['ack']; x = _request(a['request'], s['session_id'])
        _need(a['acknowledged_rid'] == s['response']['rid'] and a['request']['rid'] > a['acknowledged_rid'])
        _need(_ascii_u64(x.get('ack', '')) == a['acknowledged_rid'])
        _need(a['deleted'] == t['transfer']['returned_source'] and a['commit'] == a['renewal'] == 'Complete')


def _lanes(m, a, w, b):
    ms = m['session']
    _need(ms['connection_id'] != a['connection_id'] and ms['session_id'] != a['session_id'] and ms['response']['rid'] != a['response']['rid'])
    for r in w['attempt']['route']['targets']:
        _need(r['full_jid'] != b['binding']['full_jid'] and r['connection_id'] != a['connection_id'] and _kind(r['provenance']) == 'InitiallyPublished')


def _drive(a, drive):
    _need((_kind(a['publication']), drive) in (('BackendError', 'Complete'), ('CommitPending', 'DropPublicationCommit')))


def _auths(case):
    k, c = case['composition']['kind'], case['composition']['data']
    if k in ('AuthThenMixNative', 'NativeAuth'): return [c['auth']]
    if k == 'ReplayMixQueuedAuth': return [c['auth']['unbound'], c['auth']['bound']]
    if k == 'BoshAuth': return [c['auth']['bound']]
    return []


def _workers(case):
    k, c = case['composition']['kind'], case['composition']['data']
    if k == 'BoshAuth': return [] if c['mix'] is None else [c['mix']['worker']]
    if k == 'ReplayMixQueuedAuth': return [c['mix']['worker']]
    if k == 'MixRecoveryNative':
        newer = copy.deepcopy(c['worker']); newer['attempt'] = c['replacement']
        row = newer['origin']['data']; cl = c['replacement']['claim']
        row['source']['lease_token'] = cl['lease_token']; row['attempt_count'] = cl['attempt_count']; row['route_wake_generation'] = cl['route_wake_generation']
        return [c['worker'], newer]
    return [c['worker']] if k in ('AuthThenMixNative', 'MixDefer') else []


def _sessions(case):
    k, c = case['composition']['kind'], case['composition']['data']
    if k == 'ReplayMixQueuedAuth': return [(c['mix']['transport']['session'], c['mix']['transport']['ack']), (c['auth']['session'], None)]
    if k == 'BoshAuth': return ([(c['mix']['transport']['session'], None)] if c['mix'] else []) + [(c['auth']['session'], None)]
    return []


def _input_relationships(case):
    _need(case['schema'] == CASE_SCHEMA and case['adapter_contract'] == ADAPTER, 'Schema')
    _need(bool(case['case_id']) and case['case_id'].isascii())
    k, c = case['composition']['kind'], case['composition']['data']
    if k == 'Muc':
        co, a = c['command'], c['command']['authority']
        _need(_kind(a['principal']) == 'Local', 'Unsupported')
        _need(c['frame']['transport'] == 'Tcp' and 0 <= co['retention_days'] <= 3650 and not a['clustered'] and a['cluster_target'] is None)
        _need(a['connection_uuid'] == c['frame']['connection_id'] and co['actor_scope'] == a['actor_scope'] and co['sender_jid'] == a['full_jid'] and co['nick'] == a['nick'])
        _bare(co['actor_scope']); _need(_bare(co['sender_jid'], True) == co['actor_scope'])
        _need(co['actor_scope'].rsplit('@', 1)[1] == c['configured_domain'] == a['principal']['data']['local_domain'])
        _xml(co['stanza']); _need(c['admission']['begin_commit'] == c['admission']['finalize_commit'] == 'Complete')
        for r in c['recipients']: _bare(r['full_jid'], True); _need(not r['blocked'])
        mode = (c['repository']['original_id'] is not None, c['repository']['commit'], c['drive'])
        if mode == (False, 'Complete', 'Complete'):
            _need(co['archive'] and co['origin_id'] is not None and len(c['recipients']) == 1 and c['recipients'][0]['endpoint'] == 'Return')
            _need(c['native'] is not None and c['native']['connection_id'] == c['recipients'][0]['connection_id']); _write(c['native']['write'], co['stanza'])
        elif mode == (True, 'Complete', 'Complete'):
            _need(co['origin_id'] is not None and not c['recipients'] and c['native'] is None)
        elif mode == (False, 'Complete', 'DropSecondEndpoint'):
            _need(not co['archive'] and co['origin_id'] is None and c['native'] is None and [r['endpoint'] for r in c['recipients']] == ['Return', 'Pending'])
        elif mode == (False, 'Pending', 'DropCommit'):
            _need(not c['recipients'] and c['native'] is None)
        else: raise Stage4Invalid('Unsupported')
    elif k == 'AuthThenMixNative':
        a, f, w = c['auth'], c['foreground'], c['worker']; _auth(a, 'Binding', 'Tcp'); _worker(w); _delivered(w['attempt']['route'])
        _need(_kind(a['publication']) == 'Committed' and a['frame']['connection_id'] == c['auth_native']['connection_id'] and a['frame']['frame_id'] != f['frame']['frame_id'])
        _write(c['auth_native']['write'], _auth_xml(a)); _need(_kind(w['origin']) == 'FreshProjection' and _kind(w['attempt']['archive']['reply']) == 'StoreCandidate')
        o, s, cmd, i = w['origin']['data'], f['stored'], f['command'], f['ingress']
        _need(o['foreground_frame'] == f['frame']['frame_id'] and f['commit'] == 'Complete' and f['frame']['transport'] == 'Tcp')
        _need(s['authoritative_id'] == cmd['item_id'] and s['channel_id'] == cmd['channel_id'] == i['channel_id'] and s['channel_jid'] == i['channel_jid'])
        _need(cmd['actor'] == i['actor_bare'] and cmd['identity'] == i['identity'] and cmd['delivery_payload'] == i['children'] and cmd['encrypted'] == i['encrypted'])
        _need(cmd['visible_jid'] is None or cmd['visible_jid'] == i['actor_bare']); _need(_bare(i['actor_full'], True) == i['actor_bare']); _bare(i['channel_jid'])
        _need(i['channel_jid'].rsplit('@', 1)[1] == f['configured_domain'])
        p = s['projection']; _need(p is not None and len(p['recipients']) == 1 and o['recipient_ordinal'] == 0)
        r = p['recipients'][0]; _need(r['delivery_id'] == o['declared_delivery_id'] and r['sequence'] > 0)
        _need(p['event_id'] == p['authoritative_stanza_id'] == s['authoritative_id'] and p['channel_id'] == s['channel_id'] and p['channel_jid'] == s['channel_jid'])
        _need(p['archive'] and p['encrypted'] == cmd['encrypted'] and bool(p['stanza_template']))
        rt = w['attempt']['route']['targets'][0]; _bare(r['participant']['jid'])
        _need(_bare(rt['full_jid'], True) == r['participant']['jid'] and rt['connection_id'] == a['frame']['connection_id'] == c['delivery_native']['connection_id'])
        _need(rt['user_id'] == a['user_id'] and rt['auth_generation'] == a['auth_generation'] and rt['full_jid'] == a['binding']['full_jid'])
        _need(rt['provenance'] == {'kind':'ActivatedByAuth','data':{'frame_id':a['frame']['frame_id']}})
        _need(c['delivery_native']['returned_fence']['delivery_id'] == o['declared_delivery_id'] and c['delivery_native']['ack_commit'] == 'Complete'); _write(c['delivery_native']['write'], p['stanza_template'])
    elif k == 'ReplayMixQueuedAuth':
        m, a = c['mix'], c['auth']; u, b = a['unbound'], a['bound']
        _auth(u, 'UnboundFast', 'Bosh'); _auth(b, 'Binding', 'Bosh'); _session(a['session']); _worker(m['worker']); _transport(m['worker'], m['transport'], True); _lanes(m['transport'], a['session'], m['worker'], b)
        _need(u['frame']['connection_id'] == b['frame']['connection_id'] == a['session']['connection_id'])
        _need(len({u['frame']['frame_id'], b['frame']['frame_id'], m['foreground']['frame']['frame_id']}) == 3 and a['session']['bind']['membership'] == EMPTY_MEMBERSHIP)
        target = 16384 - 256 - len(_auth_xml(u).encode()); pad = a['padding']
        count = target - len('<presence><status></status></presence>')
        _need(count >= 0 and pad['presence_xml'] == '<presence><status>' + 'x' * count + '</status></presence>')
        _need(pad['features_xml'] == '<stream:features xmlns:stream="http://etherx.jabber.org/streams"/>' and len(_auth_xml(b).encode()) + 256 <= 16384)
        _need(_kind(m['worker']['origin']) == 'InitialDurableRow' and _kind(m['worker']['attempt']['archive']['reply']) == 'Replay')
        row, fg = m['worker']['origin']['data'], m['foreground']
        _need(row['event_id'] == row['authoritative_stanza_id'] == fg['original_id'] == fg['existing']['authoritative_id'] and fg['ingress']['identity'] is not None)
        _need(row['channel_id'] == fg['ingress']['channel_id'] and row['channel_jid'] == fg['ingress']['channel_jid'])
        _bare(fg['ingress']['actor_bare']); _need(_bare(fg['ingress']['actor_full'], True) == fg['ingress']['actor_bare'])
        _need(row['channel_jid'].rsplit('@', 1)[1] == fg['configured_domain'])
    elif k == 'MixRecoveryNative':
        _worker(c['worker']); _attempt(c['replacement']); _delivered(c['worker']['attempt']['route']); _delivered(c['replacement']['route'])
        old, new = c['worker']['attempt'], c['replacement']
        _need(_kind(c['worker']['origin']) == 'InitialDurableRow' and old['claim']['lease_token'] != new['claim']['lease_token'])
        _need(_kind(old['archive']['reply']) == _kind(new['archive']['reply']) == 'Replay' and old['archive']['reply'] == new['archive']['reply'])
        r1, r2 = old['route']['targets'][0], new['route']['targets'][0]
        _need(_kind(r1['provenance']) == _kind(r2['provenance']) == 'InitiallyPublished' and r1['connection_id'] != r2['connection_id'])
        row = c['worker']['origin']['data']; _need(c['native']['returned_fence']['delivery_id'] == row['source']['delivery_id'] and c['native']['connection_id'] == r2['connection_id'])
        _need(_bare(r2['full_jid'], True) == row['recipient_jid'] and c['native']['ack_commit'] == 'Complete'); _write(c['native']['write'], row['stanza'])
    elif k == 'MixDefer':
        _worker(c['worker']); _need(_kind(c['worker']['origin']) == 'InitialDurableRow' and not c['worker']['attempt']['route']['targets'] and not c['worker']['attempt']['route']['privacy_blocked'])
        _need(c['settlement_commit'] == 'Complete' and c['updated'])
    elif k == 'NativeAuth':
        _auth(c['auth'], 'Binding', 'Tcp'); _drive(c['auth'], c['drive']); _need(c['native']['connection_id'] == c['auth']['frame']['connection_id']); _write(c['native']['write'], _auth_xml(c['auth']))
    elif k == 'BoshAuth':
        a = c['auth']; _auth(a['bound'], 'Binding', 'Bosh'); _drive(a['bound'], a['drive']); _session(a['session'])
        _need(a['bound']['frame']['connection_id'] == a['session']['connection_id'] and len(_auth_xml(a['bound']).encode()) + 256 <= 16384 and a['session']['bind']['membership'] == EMPTY_MEMBERSHIP)
        if c['mix'] is not None:
            m = c['mix']; _worker(m['worker']); _need(_kind(m['worker']['origin']) == 'InitialDurableRow' and _kind(m['worker']['attempt']['archive']['reply']) == 'StoreCandidate')
            _transport(m['worker'], m['transport'], False); _lanes(m['transport'], a['session'], m['worker'], a['bound'])
        else: _need(a['drive'] == 'Complete')
    _input_budgets(case)


def _input_budgets(case):
    ids, frames, connections, sessions = set(), set(), set(), set()
    def visit(v, locus):
        ids.add(v)
        {'Frame':frames, 'Connection':connections, 'Session':sessions}.get(locus, set()).add(v)
        return v
    _shape(case, ['ref','Case'], visit)
    _need(len(ids) <= 64 and len(frames) <= (3 if _kind(case['composition']) == 'ReplayMixQueuedAuth' else 2) and len(connections) <= 2 and len(sessions) <= 2, 'Bound:Identities')
    # Logical occurrences count even when byte strings happen to coincide.
    k, c = case['composition']['kind'], case['composition']['data']
    size = sum(len(_auth_xml(a).encode()) for a in _auths(case))
    if k == 'Muc': size += len(c['command']['stanza'].encode()) * max(1, len(c['recipients']))
    if k == 'AuthThenMixNative': size += sum(len(c['foreground']['stored']['projection']['stanza_template'].encode()) for _ in c['foreground']['stored']['projection']['recipients'])
    for w in _workers(case):
        if _kind(w['origin']) == 'InitialDurableRow': size += len(w['origin']['data']['stanza'].encode())
    if k == 'ReplayMixQueuedAuth': size += len(c['auth']['padding']['features_xml'].encode())
    _need(size <= 16384, 'Bound:LogicalBytes')
    actors, by_id, by_bare = set(), {}, {}
    def add(bare, uid=None):
        actors.add(bare); _need(len(actors) <= 2, 'Bound:Actors')
        if uid is not None:
            _need(by_id.get(uid, bare) == bare and by_bare.get(bare, uid) == uid)
            by_id[uid] = bare; by_bare[bare] = uid
    for a in _auths(case):
        add(_auth_xml(a) and (a['binding']['full_jid'].split('/',1)[0] if a['binding'] else a['control']['data']['authorization_identifier']), a['user_id'])
    for w in _workers(case):
        if _kind(w['origin']) == 'InitialDurableRow': add(w['origin']['data']['recipient_jid'], w['attempt']['route']['enabled_account_id'])
        for r in w['attempt']['route']['targets']: add(r['full_jid'].split('/',1)[0], r['user_id'])
    if k == 'Muc':
        add(c['command']['actor_scope'], c['command']['authority']['principal']['data']['user_id'])
        for r in c['recipients']: add(r['full_jid'].split('/',1)[0], r['user_id'])
    if k == 'AuthThenMixNative':
        add(c['foreground']['ingress']['actor_bare'])
        for r in c['foreground']['stored']['projection']['recipients']: add(r['participant']['jid'])
    if k == 'ReplayMixQueuedAuth': add(c['mix']['foreground']['ingress']['actor_bare'])


def parse_case_input(raw):
    decoded = _json(raw, MAX_INPUT)
    try: value = _shape(decoded, ['ref', 'Case'])
    except Stage4Invalid as error: raise Stage4Invalid('Json') from error
    _input_relationships(value)
    return value


def parse_compact_frame(raw):
    """Explicit V2 transport selection; never synthesize a legacy frame."""
    try:
        envelope = stage4_compact.decode_compact_frame(raw)
    except stage4_compact.Stage4Invalid as error:
        raise Stage4Invalid(str(error)) from error
    _need(envelope['schema'] == EVIDENCE_SCHEMA and envelope['entry'] == ENTRY, 'Schema:Envelope')
    return envelope


def parse_frame(raw, *, wire_version='V1'):
    if wire_version == 'V2':
        return parse_compact_frame(raw)
    _need(wire_version == 'V1', 'Schema:CompactVersion')
    _need(type(raw) is bytes and len(raw) <= MAX_FRAME, 'TooLarge:Frame')
    header, separator, rest = raw.partition(b'\n')
    _need(separator == b'\n' and header.startswith(FRAME_TAG), 'Encoding:FrameHeader')
    digits = header[len(FRAME_TAG):]
    _need(bool(re.fullmatch(b'0|[1-9][0-9]{0,5}', digits)), 'Encoding:FrameLength')
    length = int(digits); payload = rest[:length]
    _need(rest[length:] == b'\n\x1eEND\n' and len(payload) == length, 'Encoding:FrameTrailer')
    envelope = _shape(_json(payload, MAX_FRAME), ['ref', 'Envelope'])
    _need(envelope['schema'] == EVIDENCE_SCHEMA and envelope['entry'] == ENTRY, 'Schema:Envelope')
    _need(_canonical(envelope) == payload, 'Encoding:NoncanonicalEnvelope')
    return envelope


@dataclass(frozen=True)
class SemanticInspection:
    category: str
    findings: tuple
    input_sha256: str
    evidence_sha256: str
    # Deliberately no qualified/accepted/provenance boolean. This is a local
    # semantic result; the outer authenticated supervisor owns acceptance.


@dataclass(frozen=True)
class Event:
    seq: int
    family: str
    kind: str
    data: dict
    fact: dict


class SafetyViolation(ValueError):
    pass


def _safe(ok, label):
    if not ok:
        raise SafetyViolation(label)


def _complete(ok, label):
    if not ok:
        raise Stage4Incomplete(label)


def _one(values, label):
    _complete(len(values) > 0, label + ':Missing')
    _safe(len(values) == 1, label + ':Ambiguous')
    return values[0]


def _last(values, label):
    _complete(bool(values), label + ':Missing')
    return values[-1]


def _events(envelope):
    out = []
    for r in envelope['facts']:
        fact = r['fact']; family = fact['kind']; data = fact['data']
        if family in ('Frame', 'Credential', 'Driver'):
            kind = family
        else:
            kind, data = data['kind'], data['data']
        out.append(Event(r['seq'], family, kind, data, fact))
    return out


def _snapshot_key(e):
    d = e.data
    if e.family == 'Frame': return ('Frame', _key(d['frame']))
    if e.family in ('Muc','Foreground') and e.kind == 'Snapshot': return (e.family, _key(d['frame']))
    if e.family == 'Claim' and e.kind == 'Snapshot': return ('Claim', d['claim_ordinal'])
    if e.family == 'Worker' and e.kind in ('Snapshot','ChildDrop','Settlement'): return ('Worker', d['attempt_ordinal'])
    if e.family == 'Credential': return ('Credential', _key(d['snapshot']['attempt']))
    if e.family == 'Control' and e.kind == 'LivePublication': return ('Publication', _key(d['snapshot']['control']))
    if e.family == 'Control' and e.kind == 'Holder' and d['holder'] and d['holder']['introduced']:
        return ('Holder', _key(d['holder']['introduced']['control']))
    if e.family == 'Native' and e.kind == 'Snapshot': return ('Native', d['item_ordinal'])
    if e.family == 'Bosh' and e.kind == 'Snapshot': return ('Bosh', d['owner_ordinal'])
    if e.family == 'Bosh' and e.kind == 'Selection': return ('Selection', _key(d['selection']['session']), d['selection']['rid'])
    return None


def _wire_structure(case, envelope):
    fixed = set()
    _shape(case, ['ref','Case'], lambda v, _: (fixed.add(v) or v))
    seen, introductions, opaque = set(), [], 0
    counts, io_counts, polls = {}, {}, 0
    _need([r['seq'] for r in envelope['facts']] == list(range(1,len(envelope['facts'])+1)), 'Encoding:Sequence')
    for e in _events(envelope):
        def visit(label, locus):
            nonlocal opaque
            key = _key(label)
            if key in seen: return label
            if label['kind'] == 'Fixed': _need(label['data']['uuid'] in fixed, 'Encoding:UnanchoredFixed')
            else:
                _need(label['data']['ordinal'] == opaque + 1 and opaque < 16 and len(fixed) + opaque < 64, 'Encoding:OpaqueOrderOrBound')
                opaque += 1
            seen.add(key); introductions.append({'label':label,'first_seq':e.seq,'locus':locus})
            return label
        _shape(e.fact, ['ref','Fact'], visit)
        key = _snapshot_key(e)
        if key is not None:
            counts[key] = counts.get(key, 0) + 1; _need(counts[key] <= 16, 'Bound:OwnerSnapshots')
        if e.family == 'Driver':
            polls += 1; _need(e.data['owner_ordinal'] <= POLL_MAX[e.data['owner']] and polls <= 64, 'Bound:Poll')
        if e.family == 'Native' and e.kind in ('Write','Flush'):
            key = (e.kind,e.data['item_ordinal']); io_counts[key] = io_counts.get(key,0) + 1
            _need(e.data['item_ordinal'] <= 4 and io_counts[key] <= (32 if e.kind == 'Write' else 1), 'Bound:NativeIo')
    _need(introductions == envelope['identity_map'], 'Encoding:IdentityMap')
    stop = envelope['resource_stop']
    if stop is not None:
        _need(envelope['execution'] is None, 'Encoding:StoppedExecution')
        s = stop['data']
        if stop['kind'] == 'DriverPoll': _need(s['owner_ordinal'] <= POLL_MAX[s['owner']] and s['admitted_calls'] == 64, 'Encoding:DriverStop')
        else: _need(s['item_ordinal'] <= 4 and s['admitted_calls'] <= (32 if stop['kind'] == 'NativeWrite' else 1), 'Encoding:NativeStop')
    else: _need(envelope['execution'] is not None, 'Encoding:MissingExecution')
    if _kind(envelope['observation_status']) == 'Lost':
        _need(envelope['observation_status']['data']['after_seq'] == len(envelope['facts']), 'Encoding:LossSequence')


class Ledger:
    def __init__(self, case, envelope):
        self.case = case
        self.wire_case = _shape(case, ['ref','Case'], lambda v, _: _fixed(v))
        self.envelope = envelope
        self.events = _events(envelope)
        self.auth = {}
        self.items = {}
        self.native_success = {}
        self.request_views = {}
        self.cache_candidates = []
        self.bosh_owners = {}
        self.bosh_request_owners = {}

    def get(self, family, kind=None, predicate=lambda e: True, before=None):
        return [e for e in self.events if e.family == family and (kind is None or e.kind == kind)
                and (before is None or e.seq < before) and predicate(e)]

    def auth_for_frame(self, frame):
        return _one([a for a in self.auth.values() if a['input']['frame']['frame_id'] == frame], 'CredentialFrameOwner')

    def item(self, value, seq):
        ordinal = value['item_ordinal']; _safe(0 <= ordinal <= 4, 'QueueItemOrdinalBound')
        old = self.items.get(ordinal)
        if old:
            original = old[1]
            unchanged = all(original[n] == value[n] for n in ('item_ordinal','connection_id','stanza','auth_control'))
            typed = self.get('Bosh','Snapshot', lambda e: any(t['source'] == (original['source']['data'] if _kind(original['source']) == 'Mix' else None) and t['returned_source'] == (value['source']['data'] if _kind(value['source']) == 'Mix' else None) and t['source_applied'] and t['queue_accepted'] is True and _kind(t['knowledge']) == 'ReceiptKnown' and t['knowledge']['data'] == t['returned_source'] for t in e.data['snapshot']['transfers']), before=seq)
            _safe(original == value or (unchanged and bool(typed)), 'QueueItemOrdinalReassignment')
        else:
            self.items[ordinal] = (seq, value)

    def holders(self, control, before=None, cut=None):
        return self.get('Control','Holder',lambda e: e.data['holder'] is not None and e.data['holder']['introduced'] is not None and
                        e.data['holder']['introduced']['control'] == control and (cut is None or e.data['cut'] == cut), before)

    def live(self, control, before=None, cut=None):
        return self.get('Control','LivePublication',lambda e: e.data['snapshot']['control'] == control and (cut is None or e.data['cut'] == cut),before)


def _owner_fields(snapshot):
    return {n:snapshot[n] for n in ('attempt','frame','connection','ordinal','kind')}


def _association_identity(a):
    # Introduced and transferred associations are immutable historical copies.
    # Their begun_receipt stays null; only LivePublication records actual begin.
    _safe(a['publication']['begun_receipt'] is None, 'HistoricalAssociationBegunReceiptChanged')
    return copy.deepcopy(a)


def _auth_ledger(l):
    inputs = {_key(a['frame']['frame_id']): a for a in _auths(l.wire_case)}
    introductions = {}
    # Validate EVERY record before selecting groups by any mutable output field.
    # A changed snapshot frame must not make a fact disappear from its owner.
    for e in l.get('Credential'):
        snap, joins = e.data['snapshot'], e.data['joins']
        _complete(joins is not None, 'CredentialJoinsMissing')
        owner = joins['owner']
        _safe(_owner_fields(snap) == owner, 'CredentialSnapshotOwnerReassignment')
        actual_input = inputs.get(_key(owner['frame']))
        _safe(actual_input is not None, 'CredentialUnassignedFrame')
        _safe(owner['connection'] == actual_input['frame']['connection_id'] and owner['ordinal'] == actual_input['ordinal'] and owner['kind'] == actual_input['credential_kind'], 'CredentialInputOwnerReassignment')
        key = _key(owner['attempt'])
        if e.data['cut'] == 'Introduction':
            _safe(key not in introductions, 'CredentialDuplicateIntroduction')
            introductions[key] = (e.seq, copy.deepcopy(owner))
        else:
            _complete(key in introductions, 'CredentialIntroductionMissing')
            _safe(introductions[key][0] < e.seq and introductions[key][1] == owner, 'CredentialIntroducedOwnerReassignment')
    for actual_input in _auths(l.wire_case):
        frame = actual_input['frame']['frame_id']
        creds = l.get('Credential', predicate=lambda e:e.data['snapshot']['frame'] == frame)
        intro = _one([e for e in creds if e.data['cut'] == 'Introduction'], 'CredentialIntroduction')
        s = intro.data['snapshot']; j = intro.data['joins']
        _complete(j is not None, 'CredentialIntroductionJoins')
        owner = _owner_fields(s)
        _safe(j['owner'] == owner and owner['connection'] == actual_input['frame']['connection_id'] and owner['ordinal'] == actual_input['ordinal'] and owner['kind'] == actual_input['credential_kind'], 'CredentialIntroductionAnchor')
        _safe(not s['service_started'] and not s['repository_started'] and s['begin'] == s['commit'] == 'NotEntered' and not s['receipt_constructed'], 'CredentialWorkBeforeIntroduction')
        _safe(all(j[n] is None for n in ('constructed_receipt','returned_receipt','transferred_receipt')), 'CredentialReceiptBeforeIntroduction')
        attempt = s['attempt']; receipt = None; retained = dict(constructed_receipt=None,returned_receipt=None,transferred_receipt=None)
        for e in creds:
            s, j = e.data['snapshot'], e.data['joins']; _complete(j is not None, 'CredentialJoinsMissing')
            _safe(_owner_fields(s) == owner and j['owner'] == owner, 'CredentialOwnerReassignment')
            _safe(e.seq >= intro.seq, 'CredentialIntroductionOrder')
            for n in retained:
                value = j[n]
                if retained[n] is not None: _safe(value == retained[n], 'CredentialReceiptKnowledgeLostOrReassigned')
                if value is not None:
                    if receipt is None: receipt = value
                    _safe(value == receipt, 'CredentialReceiptReassignment'); retained[n] = value
            if s['receipt_constructed']:
                _complete(j['constructed_receipt'] is not None, 'ConstructedReceiptMissing')
                _safe(s['commit'] == 'Ok' and s['transaction_returned'], 'CredentialReceiptBeforeCommit')
            if j['returned_receipt'] is not None:
                _safe(j['constructed_receipt'] == j['returned_receipt'] and s['return_matches'] and not s['integrity_failure'], 'CredentialRawReturnMismatch')
            if s['transferred']:
                _complete(j['transferred_receipt'] is not None, 'CredentialTransferMissing')
                _safe(j['transferred_receipt'] == j['returned_receipt'], 'CredentialTransferReassignment')
        _complete(receipt is not None and retained['returned_receipt'] is not None, 'CredentialReceiptUnavailable')
        holders = l.get('Control','Holder',lambda e:e.data['holder'] is not None and e.data['holder']['introduced'] is not None and e.data['holder']['introduced']['frame'] == frame)
        hi = _one([e for e in holders if e.data['cut'] == 'Introduction'], 'HolderIntroduction')
        association = hi.data['holder']['introduced']; control = association['control']; pub = association['publication']
        _complete(hi.data['actual_xml'] is not None, 'HolderIntroductionBytes')
        raw = hi.data['actual_xml'].encode()
        _safe(hi.data['actual_xml'] == _auth_xml(actual_input) and association['length'] == len(raw) and association['digest'] == _hash(raw), 'IntroducedControlBytesMismatch')
        _safe(association['receipt'] == receipt and association['connection'] == owner['connection'] and association['frame'] == owner['frame'] and pub['credential'] == owner, 'HolderCredentialAssociationMismatch')
        _safe(pub['control'] == control and pub['frame'] == frame and pub['receipt'] == receipt and pub['begun_receipt'] is None, 'IntroducedPublicationJoinMismatch')
        _safe(pub['bound_effects'] == (actual_input['credential_kind'] == 'Binding') and pub['notification_expected'] == actual_input['notification_expected'], 'ActualSealingEffectsMismatch')
        _safe(hi.seq > intro.seq and any(e.seq < hi.seq and e.data['joins'] is not None and e.data['joins']['returned_receipt'] == receipt for e in creds), 'ControlSealBeforeReturnedCredential')
        _safe(_key(control) not in l.auth and not any(x['owner']['attempt'] == attempt for x in l.auth.values()), 'AuthOwnerIdentityCollision')
        auth = dict(input=actual_input, owner=owner, receipt=receipt, control=control, intro=hi,
                    association=association, creds=creds, holders=holders)
        l.auth[_key(control)] = auth
        transferred = False
        for e in holders:
            h = e.data['holder']; a = h['introduced']
            _safe(_association_identity(a) == _association_identity(association), 'ControlIntroductionReassignment')
            if e.data['actual_xml'] is not None: _safe(e.data['actual_xml'].encode() == raw, 'ControlRawBytesReassignment')
            if h['transferred'] is not None:
                _safe(_association_identity(h['transferred']) == _association_identity(association), 'ControlTransferReassignment'); transferred = True
            elif transferred: raise SafetyViolation('ControlTransferKnowledgeLost')
        live = l.live(control); _complete(bool(live), 'LivePublicationMissing')
        for e in live:
            s, j = e.data['snapshot'], e.data['joins']; _complete(j is not None, 'LivePublicationJoinsMissing')
            _safe(j['control'] == control and j['frame'] == frame and j['receipt'] == receipt and j['credential'] == owner and
                  j['bound_effects'] == pub['bound_effects'] and j['notification_expected'] == pub['notification_expected'], 'LivePublicationOwnerReassignment')
            _safe(s['control'] == control and s['frame'] == frame and s['sealed'], 'LivePublicationSnapshotJoinMismatch')
            if j['begun_receipt'] is not None: _safe(j['begun_receipt'] == receipt, 'PublicationBegunReceiptReassignment')
            if _kind(s['publication']) != 'NotStarted':
                _complete(j['begun_receipt'] is not None, 'PublicationBegunReceiptMissing')
                standalone = any(h.seq <= e.seq and h.data['holder']['transferred'] is not None for h in holders)
                callback_transfer = any(any(x['control'] == control and _association_identity(x) == _association_identity(association) for x in cb.data['invoked_owners']) for cb in l.get('Control','Callback',before=e.seq))
                _complete(standalone or callback_transfer, 'PublicationHolderTransferMissing')
    # No extra unanchored credential/holder/live owner may hide in the envelope.
    for e in l.get('Credential'):
        _safe(any(e.data['joins'] is not None and e.data['joins']['owner'] == a['owner'] for a in l.auth.values()), 'UnintroducedCredentialOwner')
    for e in l.get('Control','LivePublication'):
        _safe(_key(e.data['snapshot']['control']) in l.auth, 'UnintroducedLivePublication')
    for e in l.get('Control','Callback'):
        d = e.data
        _safe(bool(d['invoked_owners']), 'EmptySelectedSetCallbackInvented')
        for association in d['invoked_owners']:
            a = l.auth.get(_key(association['control'])); _complete(a is not None,'CallbackOwnerIntroductionMissing')
            _safe(_association_identity(association) == _association_identity(a['association']) and d['connection'] == a['owner']['connection'], 'CallbackOwnerReassignment')
            _safe(association['publication']['begun_receipt'] is None, 'HistoricalTransferPretendsLiveBegin')


def _ready(l, auth, live, holder, before):
    """Reconstruct actual completion; frame outcome is intentionally unused."""
    s, j = live.data['snapshot'], live.data['joins']; h = holder.data['holder']
    _complete(j is not None and h is not None and h['introduced'] is not None, 'PreFinishOwnerJoinsMissing')
    _safe(_association_identity(h['introduced']) == _association_identity(auth['association']), 'PreFinishHolderReassignment')
    if h['transferred'] is not None: _safe(_association_identity(h['transferred']) == _association_identity(auth['association']), 'PreFinishTransferReassignment')
    receipt = auth['receipt']; p = s['publication']; returned = s['returned']; effects = s['effects']
    latest = _last([e for e in auth['creds'] if e.seq < before], 'PreFinishCredentialRead')
    cj = latest.data['joins']; _complete(cj is not None, 'PreFinishCredentialJoins')
    _safe(cj['constructed_receipt'] == receipt and cj['returned_receipt'] == receipt, 'PreFinishCredentialReceiptMismatch')
    callback = l.get('Control','Callback',lambda e:any(a['control'] == auth['control'] for a in e.data['invoked_owners']), before)
    callbacks_returned = [e for e in callback if e.data['returned'] is True]
    knowledge_ok = (_kind(p) == 'ReceiptKnown' and _kind(returned) == 'Authenticated' and p['data']['epoch'] == returned['data']['epoch']) or (
        _kind(p) == 'NotRequired' and returned == {'kind':'Authenticated','data':{'epoch':None}})
    ready = bool(h['transferred'] is not None and cj['transferred_receipt'] == receipt and j['begun_receipt'] == receipt and
                 latest.data['snapshot']['return_matches'] and s['return_matches'] and knowledge_ok and callbacks_returned)
    bound = j['bound_effects']
    ready &= ((not effects['unbound'] and effects['epoch_applied'] and effects['route_mapping'] is True and effects['route_activation'] is True and
               effects['caps_entered'] and effects['caps_returned']) if bound else
              (effects['unbound'] and not effects['epoch_applied'] and effects['route_mapping'] is None and effects['route_activation'] is None and
               not effects['caps_entered'] and not effects['caps_returned']))
    epoch = returned['data']['epoch'] if _kind(returned) == 'Authenticated' else None
    if j['notification_expected'] and epoch is not None:
        ready &= effects['notification_entered'] and ((s['terminal'] == 'Completed' and effects['notification_returned'] is True) or
                  (s['terminal'] == 'DeferredNotification' and effects['notification_returned'] is False))
    else:
        ready &= s['terminal'] == 'Completed' and not effects['notification_entered'] and effects['notification_returned'] is None
    return bool(ready)


def _queue_ledger(l):
    for e in l.events:
        d = e.data
        if e.family == 'Worker' and e.kind == 'LocalQueue': l.item(d['item'],e.seq)
        elif e.family == 'Muc' and e.kind == 'Endpoint' and d['queued_item'] is not None: l.item(d['queued_item'],e.seq)
        elif e.family == 'Native' and e.kind == 'Dequeue': l.item(d['item'],e.seq)
        elif e.family == 'Bosh' and e.kind == 'Queue':
            _safe(d['output_bytes'] == sum(len(x['stanza'].encode()) for x in d['fifo']), 'BoshFifoByteCount')
            _safe(len({x['item_ordinal'] for x in d['fifo']}) == len(d['fifo']), 'BoshDuplicateFifoOrdinal')
            for item in d['fifo']:
                _safe(item['connection_id'] == d['connection'],'BoshCrossLaneQueue'); l.item(item,e.seq)
        elif e.family == 'Bosh' and e.kind == 'Snapshot' and _kind(d['association']) == 'Outbound': l.item(d['association']['data'],e.seq)
    for seq, item in l.items.values():
        if item['auth_control'] is not None:
            a = l.auth.get(_key(item['auth_control'])); _complete(a is not None, 'QueuedAuthOwnerMissing')
            _safe(a['intro'].seq < seq and item['connection_id'] == a['owner']['connection'] and item['stanza'] == _auth_xml(a['input']) and item['source'] is None, 'QueueAuthAssociationMismatch')


def _native_ledger(l):
    dequeues = l.get('Native','Dequeue')
    assigned = {}
    for event in dequeues:
        ordinal = event.data['item']['item_ordinal']
        _safe(ordinal not in assigned, 'NativeDuplicateDequeue')
        assigned[ordinal] = event
    for event in l.get('Native'):
        if event.kind == 'Dequeue': continue
        origin = assigned.get(event.data['item_ordinal'])
        _safe(origin is not None, 'NativeUnassignedItemOrdinal')
        _safe(origin.seq < event.seq, 'NativeFactBeforeDequeue')
        if event.kind == 'Ack':
            item = origin.data['item']
            _safe(_kind(origin.data['owner'])=='Mix' and _kind(item['source'])=='Mix', 'NativeAckWithoutMixDurableOwner')
            _safe(_kind(event.data['source'])=='Mix' and event.data['source']['data']['delivery_id']==item['source']['data']['delivery_id'], 'NativeAckDurableSourceMismatch')
    for a in l.auth.values():
        if a['input']['frame']['transport'] == 'Tcp':
            _one(l.get('Native','Dequeue',lambda e:e.data['item']['auth_control']==a['control']),'NativeAuthDequeueMissing')
    for e in l.get('Native','Dequeue'):
        item, owner = e.data['item'], e.data['owner']; ordinal = item['item_ordinal']; raw = item['stanza'].encode()
        _safe(len(l.get('Native','Dequeue',lambda x:x.data['item']['item_ordinal'] == ordinal)) == 1, 'NativeDuplicateDequeue')
        if _kind(owner) == 'Auth':
            a = l.auth.get(_key(owner['data']['control'])); _complete(a is not None, 'NativeAuthOwnerMissing')
            _safe(owner['data']['frame'] == a['owner']['frame'] and item['auth_control'] == a['control'] and item['connection_id'] == a['owner']['connection'], 'NativeAuthOwnerMismatch')
        elif _kind(owner) == 'Mix':
            q = _one(l.get('Worker','LocalQueue',lambda x:x.data['attempt_ordinal'] == owner['data']['attempt_ordinal'] and x.data['item']['item_ordinal'] == ordinal), 'NativeMixQueueOrigin')
            _safe(q.seq < e.seq and q.data['item'] == item, 'NativeQueueItemReassignment')
        elif _kind(owner) == 'Muc':
            q = _one(l.get('Muc','Endpoint',lambda x:x.data['frame'] == owner['data']['frame'] and x.data['ordinal'] == owner['data']['recipient_ordinal'] and x.data['queued_item'] is not None),'NativeMucQueueOrigin')
            _safe(q.seq < e.seq and q.data['queued_item'] == item,'NativeMucQueueReassignment')
        accepted, flushed = b'', None
        writes = l.get('Native','Write',lambda x:x.data['item_ordinal'] == ordinal)
        for w in l.get('Native','Write',lambda x:x.data['item_ordinal'] == ordinal):
            _safe(w.seq > e.seq, 'NativeWriteBeforeDequeue'); d = w.data
            _safe(d['offered_len'] == len(raw) - len(accepted) and d['offered_sha256'] == _hash(raw[len(accepted):]), 'NativeOfferedBytesMismatch')
            chunk = bytes.fromhex(d['accepted_bytes_hex'])
            _safe(raw[len(accepted):].startswith(chunk) and len(chunk) <= d['offered_len'], 'NativeAcceptedBytesMismatch')
            if d['result'] != 'Ok': _safe(not chunk, 'NativeFailedCallAcceptedBytes')
            accepted += chunk
        for f in l.get('Native','Flush',lambda x:x.data['item_ordinal'] == ordinal):
            _safe(f.seq > e.seq and accepted == raw and bool(writes) and writes[-1].seq < f.seq, 'NativeFlushBeforeFullWrite')
            if f.data['result'] == 'Ok': flushed = f
        # A dequeued old recovery item may intentionally be cancelled without
        # write; success is derived only for actual write-complete items.
        snaps = l.get('Native','Snapshot',lambda x:x.data['item_ordinal'] == ordinal)
        _complete(bool(snaps),'NativeSnapshotMissing')
        if _kind(owner) != 'Auth':
            final = _last([x for x in snaps if x.data['cut']=='AfterRunnerDrop' and x.data['snapshot'] is not None],'NativeOwnerRetirementMissing')
            fs = final.data['snapshot']
            _safe(fs['writer_result']=='FullWrite' and fs['write_decision']=='Written' and fs['terminal']=='Returned','NativeActualWriteOutcomeMismatch')
        for n in snaps:
            _safe(n.data['owner'] == owner and n.data['connection'] == item['connection_id'],'NativeSnapshotOwnerMismatch')
            s = n.data['snapshot']
            if s is None: continue
            if s['write_decision'] == 'Written' or s['writer_result'] == 'FullWrite':
                _complete(flushed is not None,'NativeFlushObservationMissing')
                _safe(accepted == raw and flushed.seq < n.seq, 'NativePublicationBeforeWriteAndFlush')
            if item['source'] is not None:
                _safe(s['original'] == item['source'], 'NativeSourceMismatch')
                if s['returned_fence'] is not None:
                    _safe(s['returned_fence']==_native_fence_for_item(l, owner), 'NativeReturnedFenceMismatch')
                if s['write_decision'] == 'Written':
                    _safe(s['fence_entered'] and s['returned_fence'] is not None and s['preparation'] == 'Prepared' and s['managed_by_sm'] is False, 'NativeDurableWriteWithoutFence')
            if _kind(s['ack']) in ('CommitCallEntered','ReceiptKnown'):
                _complete(flushed is not None,'NativeAckWriteObservationMissing')
                _safe(flushed.seq < n.seq and s['write_decision'] == 'Written' and s['returned_fence'] == s['ack']['data']['source'], 'NativeAckBeforeWriteOrWrongFence')
        if flushed:
            _safe(accepted == raw, 'NativeShortWrite'); l.native_success[ordinal] = flushed.seq
            if _kind(item['source']) == 'Mix':
                calls = l.get('Native','Ack',lambda x:x.data['item_ordinal']==ordinal)
                entry = _one([x for x in calls if x.data['returned'] is None],'NativeActualAckEntry')
                returned = _one([x for x in calls if x.data['returned'] is not None],'NativeActualAckReturn')
                final = _last([x for x in snaps if x.data['snapshot'] is not None],'NativeAckFinalRead')
                fs = final.data['snapshot']
                _safe(len(calls)==2, 'NativeAckPairMultiplicity')
                _safe(flushed.seq < entry.seq < returned.seq <= final.seq and entry.data['source']==returned.data['source']==fs['returned_fence'] and returned.data['returned'] is True and _kind(fs['ack'])=='ReceiptKnown' and fs['ack']['data']['source']==fs['returned_fence'],'NativeAckSourceOrOrder')
        if item['auth_control'] is not None:
            for h in l.holders(item['auth_control']):
                if h.data['holder']['transferred'] is not None:
                    _complete(flushed is not None, 'NativeAuthFlushMissing')
                    _safe(flushed.seq < h.seq, 'NativeAuthTransferredBeforeFlush')
            for c in l.get('Control','Callback',lambda x:any(a['control']==item['auth_control'] for a in x.data['invoked_owners'])):
                _complete(flushed is not None,'NativeCallbackFlushMissing'); _safe(flushed.seq < c.seq,'NativePublicationBeforeFlush')


def _muc_ledger(l):
    if _kind(l.case['composition']) != 'Muc':
        _safe(not l.get('Muc'), 'UnexpectedMucOwner'); return
    c = l.wire_case['composition']['data']; frame = c['frame']['frame_id']
    snaps = l.get('Muc','Snapshot'); _complete(bool(snaps), 'MucSnapshotsMissing')
    _safe(all(e.data['frame'] == frame for e in l.get('Muc')), 'MucFrameReassignment')
    intro = _one([e for e in snaps if e.data['cut'] == 'Introduction'],'MucIntroduction')
    final = _last([e for e in snaps if e.data['cut'] == 'AfterRunnerDrop'],'MucRetirement')
    _safe(intro.seq < final.seq and not intro.data['snapshot']['repository_started'],'MucWorkBeforeIntroduction')
    drops = [e for e in snaps if e.data['cut'] == 'ChildDrop']
    _complete(bool(drops),'MucChildDropMissing')
    for d in drops: _safe(d.seq < final.seq and d.data['snapshot']['terminal'] is None,'MucRetiredBeforeChildClosure')
    retained = None
    for e in snaps:
        d, s = e.data, e.data['snapshot']
        if d['command'] is not None: _safe(d['command'] == c['command'],'MucCommandAuthorityMismatch')
        if _kind(s['knowledge']) == 'ReceiptKnown':
            if retained is not None: _safe(s['knowledge'] == retained,'MucReceiptKnowledgeReassignment')
            retained = s['knowledge']
        elif retained is not None: raise SafetyViolation('MucReceiptKnowledgeLost')
    endpoints = l.get('Muc','Endpoint')
    for e in endpoints:
        d = e.data; ordinal = d['ordinal']; _safe(ordinal < len(c['recipients']),'MucRecipientOrdinal')
        r = c['recipients'][ordinal]; _safe(d['recipient'] == {n:r[n] for n in ('user_id','full_jid','connection_id')},'MucRecipientReassignment')
        if d['entered']:
            prior = [s for s in snaps if s.seq < e.seq]
            before = _last(prior,'MucReceiptBeforeFanout')
            _safe(_kind(before.data['snapshot']['knowledge']) == 'ReceiptKnown','MucFanoutBeforeStoredReceipt')
            _safe(_kind(before.data['snapshot']['knowledge']['data']['outcome']) == 'Stored','MucReplayFreshFanout')
            privacy = [p for p in endpoints if p.seq < e.seq and p.data['ordinal'] == ordinal and p.data['privacy_returned'] is not None]
            _complete(bool(privacy),'MucPrivacyReadMissing'); _safe(privacy[-1].data['privacy_returned'] is False,'MucFanoutBeforePrivacy')
        if d['queued_item'] is not None:
            _safe(d['entered'] and d['returned'] is True and d['queued_item']['connection_id'] == r['connection_id'] and d['queued_item']['source'] is None and d['queued_item']['auth_control'] is None,'MucQueuedItemMismatch')
    if c['repository']['original_id'] is not None:
        expected = {'kind':'Replay','data':{'id':c['repository']['original_id']}}
        _safe(final.data['snapshot']['returned'] == {'kind':'Outcome','data':expected},'MucReplayOriginalIdMismatch')
        _safe(not endpoints and not l.get('Muc','Recipients') and not l.get('Native') and final.data['snapshot']['fanout']['stage'] == 'Unavailable','MucReplayProducedFreshWork')
    elif c['drive'] == 'DropCommit':
        pending = _last([e for e in snaps if e.data['cut'] == 'AfterPoll'],'MucCommitPendingCut')
        _safe(_kind(pending.data['snapshot']['knowledge']) == 'CommitCallEntered' and pending.data['snapshot']['knowledge'] == final.data['snapshot']['knowledge'] and final.data['snapshot']['returned'] is None and not endpoints,'MucPendingCommitInventedReceipt')
    else:
        expected_class = 'Volatile' if c['drive'] == 'DropSecondEndpoint' else 'ArchiveAndIdentity'
        s = final.data['snapshot']; _complete(_kind(s['knowledge']) == 'ReceiptKnown','MucCommittedReceiptMissing')
        _safe(s['knowledge']['data'] == {'outcome':{'kind':'Stored','data':{'id':c['command']['id']}},'fresh_class':expected_class},'MucStoredReceiptIdentityOrClass')
        recipients = _one(l.get('Muc','Recipients'),'MucRecipientPlan')
        _safe(recipients.data['recipients'] == [{n:r[n] for n in ('user_id','full_jid','connection_id')} for r in c['recipients']],'MucRecipientOrder')
        if c['drive'] == 'DropSecondEndpoint':
            first = _one([e for e in endpoints if e.data['ordinal']==0 and e.data['returned'] is True],'MucVolatileKnownPrefix')
            second = _one([e for e in endpoints if e.data['ordinal']==1 and e.data['entered']],'MucSecondPendingEndpoint')
            _safe(first.seq < second.seq and second.data['returned'] is None and second.data['queued_item'] is None,'MucVolatilePrefixLost')
            _safe(s['fanout']['accepted'] == 1 and s['fanout']['next_recipient'] == 1 and s['fanout']['endpoint_pending'],'MucVolatilePrefixRewritten')
    frames = l.get('Frame',predicate=lambda e:e.data['frame']==frame)
    end = _last(frames,'MucFrameMissing')
    begin = end.data['admission_begin']; _complete(begin is not None,'MucAdmissionBeginMissing')
    _safe(_kind(begin['knowledge']) == 'ReceiptKnown','MucAdmissionWithoutReceipt')
    if c['drive'] == 'Complete':
        finalize = _last([e for e in frames if e.data['admission_finalize'] is not None],'MucAdmissionFinalizeMissing')
        _safe(_kind(finalize.data['admission_finalize']['knowledge']) == 'ReceiptKnown','MucFinalizeWithoutReceipt')
        if c['native'] is not None:
            _complete(bool(l.native_success),'MucNativeCompletionMissing')
            _safe(max(l.native_success.values()) < finalize.seq,'MucFinalizeBeforeNativeFlush')
    else: _safe(all(e.data['admission_finalize'] is None for e in frames),'MucFinalizeAfterCancellation')


def _projected_row(c, projection):
    o = c['worker']['origin']['data']; cl = c['worker']['attempt']['claim']; r = projection['recipients'][o['recipient_ordinal']]
    return dict(source={'delivery_id':r['delivery_id'],'lease_token':cl['lease_token']}, event_id=projection['event_id'],
                channel_id=projection['channel_id'],channel_jid=projection['channel_jid'],participant_id=r['participant']['participant_id'],
                recipient_jid=r['participant']['jid'],recipient_nick=r['participant']['nick'],stanza=projection['stanza_template'],
                authoritative_stanza_id=projection['authoritative_stanza_id'],archive=projection['archive'],encrypted=projection['encrypted'],
                attempt_count=cl['attempt_count'],route_wake_generation=cl['route_wake_generation'])


def _foreground_ledger(l):
    k, c = l.wire_case['composition']['kind'], l.wire_case['composition']['data']
    if k not in ('AuthThenMixNative','ReplayMixQueuedAuth'):
        _safe(not l.get('Foreground','Snapshot') and not l.get('Foreground','ProjectionRow'),'UnexpectedForeground'); return
    fg = c['foreground'] if k == 'AuthThenMixNative' else c['mix']['foreground']
    snaps = l.get('Foreground','Snapshot',lambda e:e.data['frame']==fg['frame']['frame_id'])
    intro = _one([e for e in snaps if e.data['cut']=='Introduction'],'ForegroundIntroduction')
    final = _last([e for e in snaps if e.data['cut']=='AfterRunnerDrop'],'ForegroundRetirement')
    _safe(intro.seq < final.seq,'ForegroundIntroductionOrder')
    for e in snaps: _safe(e.data['ingress']==fg['ingress'],'ForegroundIngressReassignment')
    s = final.data['snapshot']
    if k == 'AuthThenMixNative':
        _complete(_kind(s['knowledge']) == 'ReceiptKnown','ForegroundReceiptMissing')
        actual = s['knowledge']['data']; _safe(actual==fg['stored'],'ForegroundStoredReceiptMismatch')
        _safe(s['returned']=={'kind':'AcceptedStored','data':{'id':actual['authoritative_id']}} and s['wake']=='Invoked','ForegroundStoredReturnOrWake')
        join = _one(l.get('Foreground','ProjectionRow'),'ForegroundProjectionRowJoin')
        _safe(join.seq > final.seq and join.data['foreground_frame']==fg['frame']['frame_id'] and join.data['stored_authoritative_id']==actual['authoritative_id'] and
              join.data['recipient_ordinal']==c['worker']['origin']['data']['recipient_ordinal'] and join.data['row_slot']==0,'ForegroundProjectionAnchor')
        _safe(join.data['actual_row']==_projected_row(c,actual['projection']),'ForegroundProjectionRowReassignment')
    else:
        expected = {'kind':'Replay','data':{'id':fg['original_id']}}
        _safe(s['replay']['existing']['raw']==fg['existing'] and s['replay']['existing']['authenticated']==expected and
              s['replay']['returned']=={'kind':'Outcome','data':expected},'ForegroundReplayAuthenticationOrOriginalId')
        _safe(not s['request_issued'] and not s['repository_started'] and _kind(s['knowledge'])=='NoCommitRequested' and s['wake']=='Unavailable' and not l.get('Foreground','ProjectionRow'),'ForegroundReplayFreshWork')
        _safe(s['returned'] is None,'ForegroundReplayInventedStoreReturn')


def _mix_ledger(l):
    workers = _workers(l.wire_case)
    _safe(len(l.get('Claim','Attempt')) <= len(workers),'ExtraClaimAttempt')
    for ordinal, w in enumerate(workers):
        attempt = _one(l.get('Claim','Attempt',lambda e:e.data['attempt_ordinal']==ordinal),'ClaimWorkerAssociation')
        j = attempt.data; _complete(j['same_retained_row'] is not None,'RetainedClaimIdentityMissing')
        _safe(j['claim_ordinal']==ordinal and j['row_ordinal']==0 and j['same_retained_row'] is True and j['source']==j['row']['source'],'ClaimRowReassignment')
        row = j['row']
        if _kind(w['origin']) == 'InitialDurableRow':
            _safe(row==w['origin']['data'],'InitialDurableRowReassignment')
            if ordinal == 0:
                initial = _one(l.get('Foreground','InitialRow'),'InitialRowLoadMissing')
                _safe(initial.seq < attempt.seq and initial.data['actual_row']==row and initial.data['input_row_ordinal']==0 and initial.data['row_slot']==0,'InitialRowLoadReassignment')
        else:
            p = _one(l.get('Foreground','ProjectionRow'),'ProjectionRowMissing')
            _safe(p.seq < attempt.seq and p.data['actual_row']==row,'ClaimNotActualForegroundProjection')
        claims = l.get('Claim','Snapshot',lambda e:e.data['claim_ordinal']==ordinal)
        claimed = _last([e for e in claims if _kind(e.data['snapshot']['knowledge'])=='StatementReceipt'],'ClaimReceiptMissing')
        _safe(claimed.seq < attempt.seq and claimed.data['snapshot']['knowledge']['data']['rows']==[row] and
              claimed.data['snapshot']['returned']=={'kind':'Accepted','data':{'count':1}},'ClaimReceiptMismatch')
        for e in claims: _safe(e.data['command']=={n:w['attempt']['claim'][n] for n in ('limit','max_bytes')},'ClaimCommandMismatch')
        snaps = l.get('Worker','Snapshot',lambda e:e.data['attempt_ordinal']==ordinal)
        intro = _one([e for e in snaps if e.data['cut']=='Introduction'],'WorkerIntroduction')
        final = _last([e for e in snaps if e.data['cut']=='AfterRunnerDrop'],'WorkerFinalDrop')
        _safe(attempt.seq < intro.seq <= final.seq,'WorkerIntroductionOrder')
        for e in snaps:
            _safe(e.data['row']==row,'WorkerRowReassignment')
            r=e.data['snapshot']['renewal']; _safe(r['issued']==0 and not r['started'] and not r['pending'] and _kind(r['knowledge'])=='NotEntered' and r['last_receipt'] is None,'UnexpectedActiveRenewal')
        archive = l.get('Worker','Archive',lambda e:e.data['attempt_ordinal']==ordinal)
        entry = _one([e for e in archive if e.data['returned'] is None],'ArchiveInvocation')
        returned = _one([e for e in archive if e.data['returned'] is not None],'ArchiveReturn')
        cmd = entry.data['command']; _safe(entry.seq < returned.seq and returned.data['command']==cmd,'ArchiveCommandReassignment')
        _safe(cmd['owner_id']==w['attempt']['route']['enabled_account_id'] and cmd['channel_jid']==row['channel_jid'] and cmd['authoritative_stanza_id']==row['authoritative_stanza_id'] and cmd['encrypted']==row['encrypted'],'ArchiveSourceJoin')
        result = returned.data['returned']; _safe(_kind(result)=='Outcome','ArchiveReturnNotKnown')
        mode = w['attempt']['archive']['reply']
        expected_id = cmd['personal_archive_id'] if _kind(mode)=='StoreCandidate' else mode['data']['original_archive_id']
        expected = {'kind':'Stored' if _kind(mode)=='StoreCandidate' else 'Replay','data':{'id':expected_id}}
        _safe(result['data']==expected,'ArchiveReplayOriginalIdMismatch')
        for e in snaps:
            a=e.data['snapshot']['archive']
            if _kind(a['knowledge'])=='ReceiptKnown': _safe(a['knowledge']['data']==expected,'ArchiveReceiptReassignment')
        queues = l.get('Worker','LocalQueue',lambda e:e.data['attempt_ordinal']==ordinal)
        for q in queues:
            d=q.data; item=d['item']; _safe(returned.seq < q.seq and item['source']=={'kind':'Mix','data':row['source']} and item['auth_control'] is None,'MixQueueSourceOrArchiveOrder')
            candidate = _one(l.get('Worker','Candidate',lambda e:e.data['attempt_ordinal']==ordinal and e.data['full_jid']==d['target']),'MixRouteCandidate')
            r=candidate.data
            _safe(candidate.seq < q.seq and item['connection_id']==r['connection_id'] and r['routable'] and not r['disconnected'] and r['lifecycle']==0 and r['capability']=='Supported','MixQueuedToIneligibleRoute')
            _safe(r['caps_after'] is not None and _kind(r['caps_after']['owner'])=='Local' and r['caps_after']['owner']['data']=={'connection_id':r['connection_id'],'generation':r['caps_observation_generation']},'MixCapsOwnerReassignment')
            route_stanzas=[e.data['route_stanza'] for e in snaps if e.seq<=q.seq and e.data['route_stanza'] is not None]
            _complete(bool(route_stanzas),'ActualRouteStanzaMissing'); _safe(item['stanza']==route_stanzas[-1],'MixQueuedStanzaMismatch')
        hands = l.get('Worker','Handoff',lambda e:e.data['attempt_ordinal']==ordinal)
        transfers = []
        for h in hands:
            d=h.data; q=_one([e for e in queues if e.data['item']['item_ordinal']==d['item_ordinal']],'HandoffQueueOrdinal')
            _safe(q.seq<h.seq and d['source']==row['source'],'TypedHandoffSourceMismatch')
            if _kind(d['received'])=='Received':
                boundary=d['received']['data']; transfers.append(h)
                _safe(boundary['kind'] in ('SocketFenced','BoshPersisted'),'UnexpectedTransportBoundary')
                if boundary['kind']=='SocketFenced':
                    ns=l.get('Native','Snapshot',lambda e:e.data['item_ordinal']==d['item_ordinal'] and e.data['snapshot'] is not None and e.data['snapshot']['returned_fence'] is not None,before=h.seq)
                    n=_last(ns,'ActualNativeHandoffFence')
                    _safe(boundary['data']['id']==n.data['connection']==q.data['item']['connection_id'], 'NativeHandoffConnectionMismatch')
                    _safe(n.data['snapshot']['returned_fence']==_native_fence_for_item(l, n.data['owner']), 'NativeHandoffReturnedFenceMismatch')
                else:
                    bs=l.get('Bosh','Snapshot',lambda e:_kind(e.data['association'])=='Outbound' and e.data['association']['data']['item_ordinal']==d['item_ordinal'] and any(t['source']==row['source'] and t['source_applied'] and t['queue_accepted'] is True and t['returned_source'] is not None for t in e.data['snapshot']['transfers']),before=h.seq)
                    actual=_last(bs,'ActualBoshTransferReceiptMissing')
                    transport=_mix_bosh_transport(l)
                    _safe(boundary['data']['id']==actual.data['snapshot']['scope']['session_id']==transport['session']['session_id'], 'BoshHandoffSessionMismatch')
                    transfer=_one([t for t in actual.data['snapshot']['transfers'] if t['source']==row['source']], 'ActualBoshTransferredSource')
                    _safe(transfer['returned_source']==transport['transfer']['returned_source'] and _kind(transfer['knowledge'])=='ReceiptKnown' and transfer['knowledge']['data']==transfer['returned_source'], 'BoshHandoffTransferTokenMismatch')
                    _safe(actual.data['association']['data']['connection_id']==q.data['item']['connection_id']==transport['session']['connection_id'], 'BoshHandoffConnectionMismatch')
        recipe = _kind(l.case['composition'])
        requires_delivery = recipe != 'MixDefer' and not (recipe == 'MixRecoveryNative' and ordinal == 0)
        if requires_delivery:
            _complete(bool(hands), 'DeliveredWorkerHandoffMissing')
            _safe(len(hands) == 1 and len(transfers) == 1, 'DeliveredWorkerTypedCompletionMismatch')
            _safe(final.data['snapshot']['route_returned'] == 'Transferred', 'DeliveredWorkerRouteReturnMismatch')
            _safe(len(queues) == 1 and transfers[0].data['item_ordinal'] == queues[0].data['item']['item_ordinal'], 'DeliveredWorkerQueueCompletionMismatch')
        child = _one(l.get('Worker','ChildDrop',lambda e:e.data['attempt_ordinal']==ordinal),'WorkerRouteChildDrop')
        _safe(child.seq < final.seq and child.data['snapshot']['terminal'] is None,'WorkerRetiredBeforeChildClosure')
        settlements=l.get('Worker','Settlement',lambda e:e.data['attempt_ordinal']==ordinal)
        if transfers:
            _safe(not settlements and all(e.data['snapshot']['settlement'] is None for e in snaps),'OldWorkerSettlementAfterTypedTransfer')
            _safe(final.data['snapshot']['renewal_scope_closed'],'TransferredWorkerRenewalScopeOpen')
            observed_transfer=final.data['snapshot']['transfer']; _complete(observed_transfer is not None,'WorkerTransferKnowledgeMissing')
            _safe(observed_transfer['boundary']==transfers[-1].data['received']['data'],'WorkerTransferBoundaryReassignment')
        for e in settlements:
            d=e.data; _safe(child.seq < e.seq and d['at_entry']['renewal_scope_closed'] and d['source']==row['source'] and d['attempt_count']==row['attempt_count'] and d['route_wake_generation']==row['route_wake_generation'],'SettlementBeforeChildClosureOrWrongSource')
            _safe(d['kind']==d['command']['kind'],'SettlementCommandKindMismatch')
        if _kind(l.case['composition'])=='MixDefer':
            _complete(bool(settlements),'DeferSettlementMissing')
            _safe(all(e.data['kind']=='Defer' for e in settlements) and not queues and not hands,'DeferInventedTransport')
            entry, returned = _port_pair(settlements, 'returned', 'WorkerDeferCall')
            expected_result = {'kind':'Defer','data':{'value':l.case['composition']['data']['updated']}}
            expected_command = {'kind':'Defer','data':{'delay_seconds':30}}
            _safe(entry.data['command']==returned.data['command']==expected_command and returned.data['returned']=={'kind':'Outcome','data':expected_result}, 'DeferCommandOrResultMismatch')
            actual=final.data['snapshot']['settlement'];_complete(actual is not None, 'DeferFinalKnowledgeMissing')
            _safe(actual['kind']=='Defer' and actual['started'] and actual['knowledge']=={'kind':'ReceiptKnown','data':expected_result} and actual['returned']==returned.data['returned'], 'DeferReceiptOrReturnMismatch')
            _safe(entry.data['at_entry']==returned.data['at_entry'] and entry.seq<returned.seq<final.seq, 'DeferCallObservationMismatch')
        if _kind(l.case['composition'])=='MixRecoveryNative' and ordinal==0:
            _safe(child.data['disconnected'] and final.data['snapshot']['terminal']=='Cancelled' and not transfers and not settlements,'CancelledWorkerInventedSettlement')


def _response_body(raw, rid, items):
    try: text = raw.decode('utf-8')
    except UnicodeError as error: raise SafetyViolation('BoshResponseUtf8') from error
    root = _xml(text)
    _safe(root.tag=='{http://jabber.org/protocol/httpbind}body' and root.attrib=={'ack':str(rid)},'BoshResponseMetadata')
    payload = ''.join(x['stanza'] for x in items)
    match = re.fullmatch(r'<body\b[^>]*>(.*)</body>',text,re.S)
    if match: _safe(match[1]==payload,'BoshResponseSelectedBytes')
    else: _safe(not payload and re.fullmatch(r'<body\b[^>]*/>',text,re.S) is not None,'BoshResponseEmptyBytes')


def _bosh_ledger(l):
    specs = {}
    for session, ack in _sessions(l.wire_case):
        specs[_key(session['session_id'])] = (session,ack)
    if not specs:
        _safe(not l.get('Bosh'),'UnexpectedBoshOwner'); return
    for e in l.get('Bosh','Snapshot'):
        d=e.data; s=d['snapshot']; scope=s['scope']; spec=specs.get(_key(scope['session_id']))
        _complete(spec is not None,'BoshSessionInputAnchor')
        session,ack=spec
        _safe(scope['ttl_seconds']==session['ttl_seconds'],'BoshScopeTtlMismatch')
        a=d['association']
        if _kind(a)=='Request':
            a=a['data']; requests=[session['response']]+([ack['request']] if ack else [])
            r=_one([r for r in requests if r['rid']==a['rid']],'BoshRequestInputAnchor')
            _safe(a['session']==scope['session_id'] and a['connection']==session['connection_id'] and a['fingerprint']==r['fingerprint'] and
                  a['request_xml']==r['request_xml'] and a['sid']==session['session_id']['data']['uuid'],'BoshRequestAssociationMismatch')
            _safe(a['ack']==(ack['acknowledged_rid'] if ack and a['rid']==ack['request']['rid'] else None),'BoshRequestAckMismatch')
            _safe(scope['kind']=='Request','BoshWrongRequestScope')
        else:
            _safe(scope['kind']=='Outbound' and a['data']['connection_id']==session['connection_id'],'BoshOutboundLaneMismatch')
    _bosh_owner_calls(l, specs)
    for e in l.get('Bosh','Cache')+l.get('Bosh','Queue'):
        spec=specs.get(_key(e.data['session'])); _complete(spec is not None,'BoshStateSessionMissing')
        _safe(e.data['connection']==spec[0]['connection_id'],'BoshCrossLaneState')
    for sk,(session,ack) in specs.items():
        sid,connection=session['session_id'],session['connection_id']
        requests=[session['response']]+([ack['request']] if ack else [])
        for req in requests:
            rid=req['rid']; is_ack=bool(ack and rid==ack['request']['rid'])
            sels=l.get('Bosh','Selection',lambda e:e.data['selection']['session']==sid and e.data['selection']['rid']==rid)
            before=_one([e for e in sels if e.data['cut']=='BeforePublish'],'BoshSelectionBeforeExposure')
            s=before.data['selection']; _complete(_kind(s['status'])=='Complete','BoshSelectionIncomplete')
            _safe(s['fingerprint']==req['fingerprint'] and s['first_validated_connection']==connection and s['validated_connection']==connection,'BoshSelectionConnectionOrRequestMismatch')
            n=s['selected_count']; _safe(n<=4 and all(x is not None for x in s['items'][:n]) and all(x is None for x in s['items'][n:]),'BoshSelectionSlotMismatch')
            fifo=_last(l.get('Bosh','Queue',lambda e:e.data['session']==sid,before=before.seq),'BoshActualFifoBeforeSelection')
            selected=fifo.data['fifo'][:n]; _safe(len(selected)==n,'BoshSelectionAbsentFifoItems')
            selected_controls=[]
            for i,(slot,item) in enumerate(zip(s['items'][:n],selected)):
                _safe(slot['ordinal']==i and slot['source']==item['source'] and slot['utf8_length']==len(item['stanza'].encode()) and slot['sha256']==_hash(item['stanza'].encode()),'BoshSelectionItemReassignment')
                _safe(slot['auth_marker']==(item['auth_control'] is not None),'BoshSelectionAuthMarkerMismatch')
                if slot['auth_marker']:
                    _complete(slot['sealed_association'] is not None and slot['holder_joins'] is not None and slot['holder_joins']['introduced'] is not None,'BoshSelectedAuthAssociationMissing')
                    a=l.auth.get(_key(item['auth_control'])); _complete(a is not None,'BoshSelectedOwnerIntroductionMissing')
                    _safe(a['intro'].seq < before.seq and slot['sealed_association']==a['association'] and
                          _association_identity(slot['holder_joins']['introduced'])==_association_identity(a['association']),'BoshSelectedOwnerReassignment')
                    selected_controls.append(a)
                else: _safe(slot['sealed_association'] is None and slot['holder_joins'] is None,'BoshPlainItemInventedHolder')
            # Limit to this operation, before a later request or teardown.
            same_after=[e for e in l.get('Bosh','Queue',lambda e:e.data['session']==sid and e.seq>before.seq) if e.data['cut'] in ('BeforePublish','BeforeFinish')]
            _complete(bool(same_after),'BoshFifoAfterSelectionMissing')
            after_fifo=same_after[0]
            _safe(after_fifo.data['fifo']==fifo.data['fifo'][n:],'BoshSelectedFifoNotRemovedExactly')
            receivers=l.get('Bosh','Receiver',lambda e:e.data['session']==sid and e.data['rid']==rid)
            _complete(bool(receivers),'BoshActualResponseReceiverMissing')
            actual_slots = [r.data['receiver_ordinal'] for r in receivers]
            open_slots = {i for i, behavior in enumerate(req['responders']) if behavior == 'Open'}
            _safe(len(set(actual_slots)) == len(actual_slots) and set(actual_slots) <= open_slots, 'BoshReceiverSlotReassignment')
            _complete(set(actual_slots) == open_slots, 'BoshOpenReceiverMissing')
            received=[]
            for r in receivers:
                _safe(r.data['connection']==connection and r.seq>before.seq and r.data['receiver_ordinal']<len(req['responders']),'BoshReceiverAssociationMismatch')
                if _kind(r.data['result'])=='Received':
                    raw=bytes.fromhex(r.data['result']['data']['body_hex']); _response_body(raw,rid,selected); received.append((r,raw))
            _complete(bool(received),'BoshAcceptedExposureMissing')
            _safe(len({raw for _,raw in received})==1,'BoshResponderBodyDisagreement')
            body=received[0][1]
            for auth in selected_controls:
                exposed=_one(l.live(auth['control'],cut='BeforePublish'),'SelectedLiveAfterExposure')
                _one(l.holders(auth['control'],cut='BeforePublish'),'SelectedHolderAfterExposure')
                _safe(exposed.seq > max(r.seq for r,_ in received) and _kind(exposed.data['snapshot']['transport'])=='BoshAccepted' and exposed.data['snapshot']['transport']['data']['rid']==rid,'SelectedExposureJoinMismatch')
            ops=l.get('Bosh','Snapshot',lambda e:_kind(e.data['association'])=='Request' and e.data['association']['data']['session']==sid and e.data['association']['data']['rid']==rid)
            responses=[(e,r) for e in ops for r in e.data['snapshot']['responses'] if r['rid']==rid]
            _complete(bool(responses),'BoshResponseSnapshotMissing')
            for event,response in responses:
                _safe(response['kind']=='Payload','BoshWrongResponseKind')
                if response['exposure_entered']:
                    _safe(response['responder_calls']==response['accepted_responders']+response['refused_responders'],'BoshResponderCounts')
                    _safe(response['control_calls']==0 and response['control_accepted']==0 and response['control_refused']==0,'BoshPayloadUsedControlPath')
                    _safe(response['lineage']==[x['source'] for x in fifo.data['fifo']],'BoshLineageReassignment')
            _bosh_bind_calls(l, sid, rid, before, selected, responses)
            callbacks=l.get('Control','Callback',lambda e:e.data['session']==sid and e.data['rid']==rid)
            for cb in callbacks:
                _safe(cb.data['connection']==connection and [a['control'] for a in cb.data['invoked_owners']]==[a['control'] for a in selected_controls],'BoshCallbackSelectedSetMismatch')
                _safe(cb.seq>max(r.seq for r,_ in received),'BoshPublicationBeforeAcceptedExposure')
            if not selected_controls: _safe(not callbacks,'EmptySelectedSetCallbackInvented')
            # Cancellation may never reach BeforeFinish. Its complete pre-drop
            # observation is handled separately, and no cache may exist.
            prefin=[e for e in sels if e.data['cut']=='BeforeFinish']
            cache_events=l.get('Bosh','Cache',lambda e:e.data['session']==sid and any(x['rid']==rid for x in e.data['entries']))
            if cache_events:
                pf=_one(prefin,'BoshSelectionBeforeCache')
                _complete(_kind(pf.data['selection']['status'])=='Complete','BoshPreFinishSelectionIncomplete')
                for slot in pf.data['selection']['items']:
                    if slot is not None and slot['auth_marker']:
                        _complete(slot['sealed_association'] is not None and slot['holder_joins'] is not None and slot['holder_joins']['introduced'] is not None,'PreFinishSelectedHolderMissing')
                        auth=l.auth.get(_key(slot['sealed_association']['control']));_complete(auth is not None,'PreFinishSelectedOwnerMissing')
                        _safe(_association_identity(slot['sealed_association'])==_association_identity(auth['association']) and _association_identity(slot['holder_joins']['introduced'])==_association_identity(auth['association']),'PreFinishSelectedOwnerReassignment')
                        if slot['holder_joins']['transferred'] is not None:_safe(_association_identity(slot['holder_joins']['transferred'])==_association_identity(auth['association']),'PreFinishSelectedTransferReassignment')
                ps=copy.deepcopy(pf.data['selection']); bs=copy.deepcopy(s)
                for view in (ps,bs):
                    for slot in view['items']:
                        if slot is not None: slot['holder_joins']=None
                _safe(ps==bs,'BoshSelectionChangedBeforeFinish')
                before_cache=_last(l.get('Bosh','Cache',lambda e:e.data['session']==sid and e.data['cut']=='BeforeFinish' and e.seq>before.seq,before=cache_events[0].seq),'BoshPreFinishCacheRead')
                _safe(all(x['rid']!=rid for x in before_cache.data['entries']),'BoshCacheAlreadyPresentBeforeFinish')
                completed_responses=[(e,r) for e,r in responses if r['cached'] and r['bookkeeping']]
                _complete(bool(completed_responses),'BoshActualFinishFactsMissing')
                after=_one([e for e in cache_events if e.data['cut']=='AfterFinish'],'BoshActualCacheAfterFinish')
                entry=_one([x for x in after.data['entries'] if x['rid']==rid],'BoshExactCacheKey')
                membership={'c2s_message_ids':[x['source']['data']['message_id'] for x in selected if _kind(x['source'])=='C2s'],
                            'mix_delivery_ids':[x['source']['data']['delivery_id'] for x in selected if _kind(x['source'])=='Mix']}
                _safe(entry['fingerprint']==req['fingerprint'] and entry['membership']==membership and bytes.fromhex(entry['body_hex'])==body and entry['response_bytes']==len(body) and entry['transport_receipt_count']==0,'BoshCacheContentOrScopeMismatch')
                _safe(pf.seq < before_cache.seq < after.seq and all(r.seq<pf.seq for r,_ in received),'BoshCacheCausalOrder')
                complete=[]
                for auth in selected_controls:
                    live=_one(l.live(auth['control'],before=after.seq,cut='BeforeFinish'),'SelectedLiveBeforeFinish')
                    holder=_one(l.holders(auth['control'],before=after.seq,cut='BeforeFinish'),'SelectedHolderBeforeFinish')
                    _safe(before.seq<live.seq<after.seq and before.seq<holder.seq<after.seq,'SelectedPreFinishCutOrder')
                    _safe(_kind(live.data['snapshot']['transport'])=='BoshAccepted' and live.data['snapshot']['transport']['data']['rid']==rid,'SelectedOwnerExposureMismatch')
                    complete.append(_ready(l,auth,live,holder,after.seq))
                # Deferred until all domain ledgers and exact cache facts have
                # been checked. A absent join cannot become this counterexample.
                if not all(complete): l.cache_candidates.append((sid,rid,selected_controls,after))
            else:
                _safe(not any(r['cached'] or r['bookkeeping'] for _,r in responses),'BoshFinishWithoutActualCache')
                if prefin:
                    _safe(len(prefin)==1,'BoshDuplicatePreFinishSelection')
                    for a in selected_controls:
                        _complete(bool(l.live(a['control'],cut='BeforeFinish')) and bool(l.holders(a['control'],cut='BeforeFinish')),'SelectedErrorLiveCutMissing')
                else:
                    _complete(all(any(e.data['cut']=='AfterPoll' and _kind(e.data['snapshot']['publication'])=='CommitCallEntered' for e in l.live(a['control'])) for a in selected_controls),'BoshMissingPreFinishOrCancellationCut')
            l.request_views[(sk,rid)] = dict(selection=before, selected=selected, controls=selected_controls,
                                               receivers=received, responses=responses, cache=cache_events, callbacks=callbacks)
        if ack: _ack_ledger(l,session,ack)
    _all_bosh_selections(l)
    _all_bosh_queue_lifecycle(l)
    _queued_unselected(l)
    _independent_lane_order(l)


def _ack_ledger(l,session,ack):
    sid=session['session_id']; rid=ack['request']['rid']; old=session['response']['rid']
    view=l.request_views[(_key(sid),rid)]
    _safe(not view['selected'] and not view['controls'] and not view['callbacks'],'BoshAckInventedLogicalItem')
    before=view['selection'].seq
    ops=l.get('Bosh','Snapshot',lambda e:_kind(e.data['association'])=='Request' and e.data['association']['data']['session']==sid and e.data['association']['data']['rid']==rid)
    final=_last(ops,'BoshAckOwnerMissing'); state=final.data['snapshot']
    renewal=_one(state['renewals'],'BoshAckRenewalMissing'); fact=_one(state['acknowledgements'],'BoshAckReceiptMissing')
    _safe(renewal['knowledge']=='ReceiptKnown' and renewal['returned'] and renewal['return_matches'] and renewal['ack_issued'],'BoshAckRenewalIncomplete')
    _safe(fact['rid']==old and fact['knowledge']=='ReceiptKnown' and fact['returned'] and fact['return_matches'] and
          fact['deleted']==[{'kind':'Mix','data':ack['deleted']}] and fact['cache_evictions']==1 and fact['receipt_calls']==0 and fact['receipts_sent']==0 and fact['receipts_refused']==0,'BoshAckWrongDeletedFence')
    # Fresh ACK renews session fences; only cached replay supplies a batch scope.
    _safe(renewal['expected'] is None,'BoshAckRenewalScopeMismatch')
    calls=l.get('Bosh','Ack',lambda e:e.data['owner_ordinal']==final.data['owner_ordinal'])
    returned=_one([e for e in calls if e.data['returned'] is True],'BoshAckActualReturn')
    _safe(returned.seq<before and returned.data['rid']==old,'BoshAckResponseBeforeActualAck')
    pre=_one(l.get('Bosh','Cache',lambda e:e.data['session']==sid and e.data['cut']=='BeforeFinish' and e.seq>before),'BoshAckPreFinishCache')
    post=_one(l.get('Bosh','Cache',lambda e:e.data['session']==sid and e.data['cut']=='AfterFinish' and e.seq>before),'BoshAckNewEmptyCache')
    _safe(all(x['rid']!=old for x in pre.data['entries']) and all(x['rid']!=old for x in post.data['entries']),'BoshOldPayloadCacheNotEvicted')
    new=_one([x for x in post.data['entries'] if x['rid']==rid],'BoshNewAckCacheMissing')
    _safe(new['membership']==EMPTY_MEMBERSHIP and new['transport_receipt_count']==0 and len(post.data['entries'])==1,'BoshAckCacheMembershipOrCount')



def _queued_unselected(l):
    if _kind(l.case['composition'])!='ReplayMixQueuedAuth': return
    c=l.wire_case['composition']['data']; lane=c['auth']; s=lane['session']; sid=s['session_id']; rid=s['response']['rid']
    view=l.request_views[(_key(sid),rid)]; before=view['selection']
    fifo=_last(l.get('Bosh','Queue',lambda e:e.data['session']==sid,before=before.seq),'S06ActualFifo')
    expected=[lane['padding']['presence_xml'],_auth_xml(lane['unbound']),lane['padding']['features_xml'],_auth_xml(lane['bound'])]
    _safe([x['stanza'] for x in fifo.data['fifo']]==expected,'S06FifoNotPUFB')
    u=l.auth_for_frame(lane['unbound']['frame']['frame_id']); b=l.auth_for_frame(lane['bound']['frame']['frame_id'])
    _safe(fifo.data['fifo'][1]['auth_control']==u['control'] and fifo.data['fifo'][3]['auth_control']==b['control'],'S06QueuedOwnerReassignment')
    _safe(view['selected']==fifo.data['fifo'][:2] and [a['control'] for a in view['controls']]==[u['control']],'S06ActualSelectedSetNotPU')
    before_live=_last(l.live(b['control'],before=before.seq),'S06UnselectedBefore')
    after_live=_one(l.live(b['control'],cut='BeforeFinish'),'S06UnselectedAfter')
    _safe(before_live.data['snapshot']==after_live.data['snapshot'] and before_live.data['joins']==after_live.data['joins'],'S06UnselectedBoundOwnerChanged')
    _safe(_kind(after_live.data['snapshot']['publication'])=='NotStarted' and after_live.data['snapshot']['terminal'] is None,'S06UnselectedOwnerNotPending')
    before_holder=_last(l.holders(b['control'],before=before.seq),'S06UnselectedHolderBefore')
    after_holder=_one(l.holders(b['control'],cut='BeforeFinish'),'S06UnselectedHolderAfter')
    _safe(before_holder.data['holder']==after_holder.data['holder'] and after_holder.data['holder']['transferred'] is None,'S06UnselectedHolderConsumed')
    pending=_one(l.live(b['control'],cut='BeforeTeardown'),'S06UnselectedPendingTeardown')
    dropped=_one(l.live(b['control'],cut='AfterTeardown'),'S06UnselectedDropped')
    _safe(pending.seq<dropped.seq and pending.data['snapshot']['terminal'] is None and dropped.data['snapshot']['terminal']=='Abandoned','S06TeardownRewritesPendingCut')
    remnant=_one(l.get('Bosh','Queue',lambda e:e.data['session']==sid and e.data['cut']=='BeforeTeardown'),'S06RemainingFifo')
    _safe(remnant.data['fifo']==fifo.data['fifo'][2:],'S06RemainingFifoNotFB')
    _safe(len(l.request_views)==3,'S06ThreePayloadResponsesRequired')


def _independent_lane_order(l):
    if _kind(l.case['composition'])!='BoshAuth': return
    c=l.wire_case['composition']['data']
    if c['mix'] is None: return
    m=c['mix']['transport']['session']; a=c['auth']['session']
    mv=l.request_views[(_key(m['session_id']),m['response']['rid'])]; av=l.request_views[(_key(a['session_id']),a['response']['rid'])]
    _safe(not mv['controls'] and len(av['controls'])==1,'IndependentLaneAuthMembership')
    mcache=_one([e for e in mv['cache'] if e.data['cut']=='AfterFinish'],'IndependentMixCacheCompletion')
    _safe(mcache.seq < av['selection'].seq,'IndependentMixMustCompleteBeforeAuthResponse')
    _safe(len(l.request_views)==2,'IndependentLaneExtraResponse')


class FixtureMismatch(ValueError):
    pass


def _fixture(ok,label):
    if not ok: raise FixtureMismatch(label)


def _auth_route_ledger(l):
    for a in l.auth.values():
        if a['input']['binding'] is None: continue
        key=a['input']['binding']['full_jid']; frame=a['owner']['frame']
        lookups=l.get('Worker','Lookup',lambda e:e.data['owner']=={'kind':'Auth','data':{'id':frame}})
        _complete(bool(lookups),'BoundAuthRouteLookupMissing')
        before=lookups[0]
        callbacks=l.get('Control','Callback',lambda e:any(x['control']==a['control'] for x in e.data['invoked_owners']))
        _safe(not callbacks or before.seq < callbacks[0].seq,'AuthInitialLookupAfterPublication')
        _safe(before.data['lookup_key']==key and not before.data['entries'],'AuthRouteVisibleBeforePublication')
        for e in lookups:
            _safe(e.data['lookup_key']==key,'AuthRouteKeyReassigned')
            for row in e.data['entries']:
                _safe(row['full_jid']==key and row['connection_id']==a['owner']['connection'] and row['user_id']==a['input']['user_id'] and row['auth_generation']==a['input']['auth_generation'] and row['routable'] and not row['disconnected'] and row['lifecycle']==0,'AuthActivatedDifferentRoute')
                live=_last(l.live(a['control'],before=e.seq),'AuthRoutePublicationRead')
                _safe(_kind(live.data['snapshot']['returned'])=='Authenticated','AuthRouteWithoutPublicationResult')
                epoch=live.data['snapshot']['returned']['data']['epoch']
                _safe(row['user_agent_epoch']==epoch,'AuthRouteEpochMismatch')
    for ordinal,w in enumerate(_workers(l.wire_case)):
        account=l.get('Worker','Account',lambda e:e.data['attempt_ordinal']==ordinal)
        ae=_one([e for e in account if e.data['returned'] is None],'WorkerAccountEntry')
        ar=_one([e for e in account if e.data['returned'] is not None],'WorkerAccountReturn')
        _safe(ae.seq<ar.seq and ae.data['username']==ar.data['username'] and _kind(ar.data['returned'])=='Found' and ar.data['returned']['data']['id']==w['attempt']['route']['enabled_account_id'],'WorkerAccountAssociation')
        privacy=l.get('Worker','Privacy',lambda e:e.data['attempt_ordinal']==ordinal)
        pe=_one([e for e in privacy if e.data['returned'] is None],'WorkerPrivacyEntry')
        pr=_one([e for e in privacy if e.data['returned'] is not None],'WorkerPrivacyReturn')
        _safe(ar.seq<pe.seq<pr.seq and pe.data['owner_id']==pr.data['owner_id']==ar.data['returned']['data']['id'] and pe.data['candidate']==pr.data['candidate'] and pr.data['returned']=={'kind':'Outcome','data':{'value':False}},'WorkerPrivacyAssociation')
        lookup=_one(l.get('Worker','Lookup',lambda e:e.data['owner']=={'kind':'Worker','data':{'attempt_ordinal':ordinal}}),'WorkerActualLookup')
        if _kind(w['origin'])=='InitialDurableRow': _safe(lookup.data['lookup_key']==w['origin']['data']['recipient_jid'],'WorkerLookupKeyMismatch')
        for r in lookup.data['entries']:
            expected=_one([x for x in w['attempt']['route']['targets'] if x['full_jid']==r['full_jid']],'WorkerLookupTarget')
            _safe(all(r[n]==expected[n] for n in ('connection_id','user_id','auth_generation')) and r['routable'] and not r['disconnected'] and r['lifecycle']==0,'WorkerLookupTargetReassignment')


def _outcomes(l):
    """Literal-driven completion matching is strictly after every safety pass."""
    k,c=l.case['composition']['kind'],l.case['composition']['data']
    cancelled=(k=='Muc' and c['drive']!='Complete') or (k=='NativeAuth' and c['drive']=='DropPublicationCommit') or (k=='BoshAuth' and c['auth']['drive']=='DropPublicationCommit')
    _fixture(l.envelope['execution']==('Cancelled' if cancelled else 'Complete'),'ExecutionClassMismatch')
    for a in l.auth.values():
        control=a['control']; inp=a['input']; live=l.live(control)
        terminal=_last([e for e in live if e.data['snapshot']['terminal'] is not None],'PublicationTerminalMissing')
        s=terminal.data['snapshot']; callbacks=l.get('Control','Callback',lambda e:any(x['control']==control for x in e.data['invoked_owners']))
        unselected=k=='ReplayMixQueuedAuth' and inp['credential_kind']=='Binding'
        if unselected:
            _fixture(not callbacks and s['terminal']=='Abandoned' and _kind(s['publication'])=='NotStarted','QueuedUnselectedPublicationChanged'); continue
        _fixture(bool(callbacks),'ActualPublicationCallbackAbsent')
        mode=inp['publication']['kind']
        if mode in ('NoSql','Committed'):
            holder=_last(l.holders(control,before=terminal.seq+1),'CompletedHolderMissing')
            _fixture(_ready(l,a,terminal,holder,terminal.seq+1),'ActualAuthCompletionMismatch')
        elif mode=='BackendError':
            _fixture(s['terminal']=='Failed' and _kind(s['returned'])=='BackendFailure' and s['service_started'],'ActualPublicationBackendFailureMissing')
            _fixture(any(e.data['returned'] is False for e in callbacks),'ActualCallbackFailureReturnMissing')
            _fixture(s['effects']['route_activation'] is not True and s['effects']['route_mapping'] is not True,'FailedPublicationActivatedRoute')
        elif mode=='CommitPending':
            before=_last([e for e in live if e.data['cut']=='AfterPoll'],'PublicationPendingCut')
            child=_one([e for e in live if e.data['cut']=='ChildDrop'],'PublicationCommitChildDrop')
            after=_last([e for e in live if e.data['cut']=='AfterRunnerDrop'],'PublicationCancelledRetirement')
            _fixture(before.seq<child.seq<after.seq and _kind(before.data['snapshot']['publication'])=='CommitCallEntered' and before.data['snapshot']['returned'] is None,'PublicationPendingCutMismatch')
            _fixture(child.data['snapshot']['terminal'] is None and child.data['snapshot']['publication']==before.data['snapshot']['publication'] and after.data['snapshot']['terminal']=='Cancelled' and after.data['snapshot']['publication']==before.data['snapshot']['publication'],'PublicationChildClosureOrUnknownKnowledgeLost')
            _fixture(all(e.data['returned'] is None for e in callbacks),'CancelledCallbackInventedReturn')
    if k=='Muc':
        final=_last(l.get('Muc','Snapshot',lambda e:e.data['cut']=='AfterRunnerDrop'),'MucFinalOutcome')
        _fixture(final.data['snapshot']['terminal']==('Cancelled' if cancelled else 'Completed'),'MucTerminalMismatch')
    for ordinal,_ in enumerate(_workers(l.case)):
        final=_last(l.get('Worker','Snapshot',lambda e:e.data['attempt_ordinal']==ordinal and e.data['cut']=='AfterRunnerDrop'),'WorkerTerminalMissing')
        expected='Cancelled' if k=='MixRecoveryNative' and ordinal==0 else 'Completed'
        _fixture(final.data['snapshot']['terminal']==expected,'WorkerTerminalMismatch')
    return 'Cancelled' if cancelled else 'Pass'


def inspect_semantics(raw_input, framed_evidence, *, wire_version='V1'):
    """Inspect explicitly selected wire semantics; caller authenticates separately.

    evidence_sha256 always binds actual framed_evidence, including its V2 tag,
    length and trailer. The expanded digest is never substituted for provenance.
    """
    ih=_hash(raw_input) if type(raw_input) is bytes else ''
    eh=_hash(framed_evidence) if type(framed_evidence) is bytes else ''
    try:
        envelope=parse_frame(framed_evidence,wire_version=wire_version)
    except Stage4Invalid as error:
        return SemanticInspection('EvidenceInvalid',(str(error),),ih,eh)
    return _inspect_envelope(raw_input,envelope,ih,eh)


def _inspect_envelope(raw_input,envelope,ih,eh):
    # The original named-Envelope semantic evaluator is transport-independent.
    # The caller passes the digest of the actual selected frame, not a V1 proxy.
    result=lambda category,*findings:SemanticInspection(category,tuple(findings),ih,eh)
    try:
        _need(envelope['input_sha256']==ih,'Encoding:InputHash')
        try: case=parse_case_input(raw_input)
        except Stage4Invalid as error:
            reason=str(error).split(':',1)[0]
            _need(envelope['rejection']==reason and envelope['execution'] is None and envelope['resource_stop'] is None and
                  not envelope['identity_map'] and not envelope['facts'] and _kind(envelope['observation_status'])=='Complete','Encoding:RejectedEnvelopeMismatch')
            return result('InvalidScenario',reason)
        _need(envelope['rejection'] is None,'Encoding:UnexpectedRejection')
        _wire_structure(case,envelope)
        if envelope['resource_stop'] is not None:
            return result('Inconclusive','ResourceStop:'+envelope['resource_stop']['kind'])
        if _kind(envelope['observation_status'])=='Lost':
            return result('Inconclusive','ObservationLost:'+envelope['observation_status']['data']['reason'])
        ledger=Ledger(case,envelope)
        _auth_ledger(ledger); _raw_owner_assignment(ledger); _callback_ledger(ledger); _queue_ledger(ledger); _native_ledger(ledger)
        _muc_ledger(ledger); _foreground_ledger(ledger); _mix_ledger(ledger)
        _auth_route_ledger(ledger); _bosh_ledger(ledger); _closed_fact_scope(ledger); _driver_owner_scope(ledger)
        if ledger.cache_candidates:
            return result('InvariantViolation',TARGET)
        return result(_outcomes(ledger))
    except Stage4Incomplete as error: return result('Inconclusive',str(error))
    except SafetyViolation as error: return result('InvariantViolation',str(error))
    except FixtureMismatch as error: return result('FixtureMismatch',str(error))
    except Stage4Invalid as error: return result('EvidenceInvalid',str(error))


# This is the only public fixture inventory. It contains input bindings and
# planned classes, never Rust output. It is filled from source-only literals.
FIXTURES = {'S01': (2505, '4eb6aa0f9e09812d7dd04e1d96ab0314a47b63d9342c767a4f40ca6633402fdb', 'Pass'), 'S02': (2232, '7150f774c75af25c36da649ac2197e3bf0c038f9f197a1fa332cf482e2343157', 'Pass'), 'S03': (2515, '06efc3d10c422aff7a6dc938cb2c03f223fe3cdae1ddb1a3535546cde0bb181d', 'Cancelled'), 'S04': (2206, '220773f13cb61e8f5ed8f84c05e5a928da8fadaf4a56409274d1897f3e7aeece', 'Cancelled'), 'S05': (4353, '50b8f1c737a2bd0c4fb77ba88148e2ba4b0bcbd775ed7a624f87d331eacb234f', 'Pass'), 'S06': (22911, 'c609da10e108c0d5023f4b102d31b73e4d39de534703b915ad40e53cefb2d150', 'Pass'), 'S07': (2935, '4475bc05d216de84318962eb39a2cd0589dcb8c35cba2c238d7893f36bc18a3f', 'Pass'), 'S08': (1510, '3eaef97d5754331a61dd70995e359d1596069960ccb7fed1f2e0f86af11d00ee', 'Pass'), 'S09': (1234, 'fceae61bcc15dd3a9648bf7e6dd149f46e13799ca27a022f26c07a33b9bde77e', 'Pass'), 'S10': (1261, '79d59093f0eabf929856566f8377c322ab91ec164c9885d3f13012625eea44c6', 'Cancelled'), 'S11': (4264, '9f9b0c57a629b910a03c723bea8480139613bf9572e7e5c17e9f94b202880931', 'Pass'), 'S12': (4291, '8c2a05acd8909c7d00e0def329ca500d4d87c85febda9bace4224523b06688cc', 'Cancelled'), 'S13': (1779, 'e49d45ca5970b7aa84cd9004faffe0aad55d34142758ba9649c6d7bea73ed987', 'Pass'), 'S14': (1827, '56149c2ff03195230fd466528ccb3312a17be660b10b57c51e635ab95cd129a2', 'InvalidScenario'), 'S15': (1732, 'b7bffb4202bf75f207c16e2b7353b0a12b6c6224380d69dd7fe02a72f17d17a5', 'InvalidScenario'), 'S16': (4264, '6de2c80e32b93803f42df74b16ed055ba7d0d13e41198c1411219e0e0791b84e', 'InvalidScenario')}
MUTANT_INPUTS = {'M1':'S11','M2':'S13','M3':'S13'}


def evaluate_fixture_semantics(occurrence,raw_input,framed_evidence,*,artifact_role,wire_version='V1'):
    """The role is a routing argument, NOT proof that a binary has that role.

    Only an external supervisor's authenticated contract may supply it. Passing
    a role cannot qualify a result here, create a process tuple or authenticate
    an artifact. The fixed baseline has 16 and mutant 3 external occurrences.
    """
    if artifact_role=='baseline': identity=occurrence
    elif artifact_role=='auth-cache-bypass-mutant' and occurrence in MUTANT_INPUTS: identity=MUTANT_INPUTS[occurrence]
    else: raise Stage4Invalid('Fixture:UnknownRoleOrOccurrence')
    _need(identity in FIXTURES,'Fixture:UnknownOccurrence')
    size,digest,planned=FIXTURES[identity]
    _need(type(raw_input) is bytes and len(raw_input)==size and _hash(raw_input)==digest,'Fixture:LiteralBinding')
    result=inspect_semantics(raw_input,framed_evidence,wire_version=wire_version)
    # Incompleteness/integrity/safety is never converted into fixture success.
    if artifact_role=='auth-cache-bypass-mutant':
        if result.category=='InvariantViolation' and result.findings==(TARGET,) and whole_branch_mutant_signature(raw_input,framed_evidence,wire_version=wire_version): return result
        return SemanticInspection('Inconclusive' if result.category in ('Inconclusive','EvidenceInvalid') else 'FixtureMismatch',
                                  ('ExactCausalMutantNotEstablished',)+result.findings,result.input_sha256,result.evidence_sha256)
    if result.category in ('Inconclusive','EvidenceInvalid','InvariantViolation'): return result
    if result.category!=planned:
        return SemanticInspection('FixtureMismatch',('PlannedClassMismatch',)+result.findings,result.input_sha256,result.evidence_sha256)
    return result


@dataclass(frozen=True)
class SemanticRelation:
    category: str
    findings: tuple
    input_hashes: tuple
    evidence_hashes: tuple


def compare_replay_semantics(record_input,record_frame,replay_input,replay_frame,*,wire_version='V1'):
    a=inspect_semantics(record_input,record_frame,wire_version=wire_version); b=inspect_semantics(replay_input,replay_frame,wire_version=wire_version)
    hashes=(a.input_sha256,b.input_sha256); evidence=(a.evidence_sha256,b.evidence_sha256)
    if a.category in ('Inconclusive','EvidenceInvalid','FixtureMismatch') or b.category in ('Inconclusive','EvidenceInvalid','FixtureMismatch'):
        return SemanticRelation('Inconclusive',('ReplayRequiresCompleteSemanticInputs',),hashes,evidence)
    if record_input!=replay_input or record_frame!=replay_frame or a.category!=b.category or a.findings!=b.findings:
        return SemanticRelation('Different',('LiteralOrCompleteCanonicalDtoChanged',),hashes,evidence)
    return SemanticRelation('Equivalent',(),hashes,evidence)


def _raw_auth_fragment(raw):
    # Exactly one BoshAuth auth member exists in the closed validated recipe.
    text=raw.decode('utf-8'); matches=list(re.finditer(r'"auth"\s*:\s*',text))
    _need(len(matches)==1,'Shrink:AuthMemberAmbiguous')
    start=matches[0].end(); decoder=json.JSONDecoder(object_pairs_hook=_pairs)
    _,used=decoder.raw_decode(text[start:])
    return text[start:start+used].encode('utf-8')


def _normalize_opaque(value):
    mapping={}
    def walk(v):
        if type(v) is dict:
            if set(v)=={'kind','data'} and v['kind']=='Opaque' and set(v['data'])=={'ordinal'}:
                key=_key(v)
                if key not in mapping: mapping[key]=len(mapping)+1
                return {'kind':'Opaque','data':{'ordinal':mapping[key]}}
            return {k:walk(x) for k,x in v.items()}
        if type(v) is list:return [walk(x) for x in v]
        return v
    return walk(value)


def _retained_auth_graph(raw,frame,*,anchors_only=False,wire_version='V1'):
    c=parse_case_input(raw); e=parse_frame(frame,wire_version=wire_version); lane=c['composition']['data']['auth']
    sid=_fixed(lane['session']['session_id']); fid=_fixed(lane['bound']['frame']['frame_id']); conn=_fixed(lane['bound']['frame']['connection_id'])
    events=_events(e)
    owners={x.data['owner_ordinal'] for x in events if x.family=='Bosh' and x.kind=='Snapshot' and
            _kind(x.data['association'])=='Request' and x.data['association']['data']['session']==sid}
    ordinals={x['item_ordinal'] for y in events if y.family=='Bosh' and y.kind=='Queue' and y.data['session']==sid for x in y.data['fifo']}
    _complete(len(owners)==1 and len(ordinals)==1,'ShrinkActualAuthOwnerOrdinals')
    owner=next(iter(owners)); item=next(iter(ordinals)); kept=[]
    mix=c['composition']['data']['mix']
    mix_sid=_fixed(mix['transport']['session']['session_id']) if mix is not None else None
    mix_owners={x.data['owner_ordinal'] for x in events if x.family=='Bosh' and x.kind=='Snapshot' and x.data['snapshot']['scope']['session_id']==mix_sid}
    _safe(not (mix_owners & owners),'ShrinkOwnerLaneCollision')
    for event in events:
        d=event.data; keep=False
        if event.family=='Frame':keep=d['frame']==fid
        elif event.family=='Credential':keep=d['snapshot']['frame']==fid
        elif event.family=='Control':
            if event.kind=='Holder':keep=d['holder'] is not None and d['holder']['introduced'] is not None and d['holder']['introduced']['frame']==fid
            elif event.kind=='LivePublication':keep=d['snapshot']['frame']==fid
            else:keep=d['connection']==conn and d['session']==sid
        elif event.family=='Bosh':
            if event.kind=='Snapshot':keep=d['snapshot']['scope']['session_id']==sid
            elif event.kind=='Selection':keep=d['selection']['session']==sid
            elif 'session' in d:keep=d['session']==sid
            elif 'owner_ordinal' in d:keep=d['owner_ordinal']==owner
        elif event.family=='Worker' and event.kind=='Lookup':keep=d['owner']=={'kind':'Auth','data':{'id':fid}}
        elif event.family=='Driver':keep=(d['owner'] in ('Credential','Publication')) or (d['owner']=='Bosh' and d['owner_ordinal']==owner)
        if not keep:
            mix=c['composition']['data']['mix']
            _safe(mix is not None,'ShrinkDiscardedNonMixFact')
            msid=_fixed(mix['transport']['session']['session_id'])
            removable=event.family in ('Claim','Worker','Foreground')
            if event.family=='Bosh':
                observed_session=d['snapshot']['scope']['session_id'] if event.kind=='Snapshot' else (d['selection']['session'] if event.kind=='Selection' else d.get('session'))
                removable=observed_session==msid or ('owner_ordinal' in d and d['owner_ordinal'] in mix_owners)
            if event.family=='Driver':removable=d['owner'] in ('Claim','Worker') or (d['owner']=='Bosh' and d['owner_ordinal'] in mix_owners)
            _safe(removable,'ShrinkDiscardedNonMixFact')
            continue
        if anchors_only:
            keep=(event.family=='Credential' and d['cut']=='Introduction') or (event.family=='Control' and event.kind in ('Holder','LivePublication') and d['cut']=='Introduction') or (event.family=='Bosh' and event.kind=='Selection' and d['cut']=='BeforePublish') or (event.family=='Bosh' and event.kind=='Receiver')
            if not keep:continue
        fact=copy.deepcopy(event.fact)
        def normalize(v):
            if type(v) is dict:
                for k,x in list(v.items()):
                    if k=='item_ordinal':
                        _safe(x==item,'ShrinkItemCrossLane');v[k]=0
                    elif k=='owner_ordinal' and event.family=='Bosh':
                        _safe(x==owner,'ShrinkOwnerCrossLane');v[k]=0
                    elif k=='owner_ordinal' and event.family=='Driver' and event.data['owner']=='Bosh':v[k]=0
                    else:normalize(x)
            elif type(v) is list:
                for x in v:normalize(x)
        normalize(fact);kept.append(fact)
    return _normalize_opaque(kept)


def shrink_semantics(full_mutant,reduced_mutant,reduced_baseline,repeated_reduced_mutant,*,wire_version='V1'):
    """Four (literal bytes, framed DTO bytes) pairs; no process/provenance API.

    Caller MUST first authenticate four distinct occurrence/process tuples and
    the three mutant positions, and exact baseline/mutant contract ancestry.
    This function cannot replace that external check or accept duplicate tuples.
    """
    pairs=(full_mutant,reduced_mutant,reduced_baseline,repeated_reduced_mutant)
    inspections=[inspect_semantics(*p,wire_version=wire_version) for p in pairs]
    ih=tuple(x.input_sha256 for x in inspections);eh=tuple(x.evidence_sha256 for x in inspections)
    try:
        _complete(all(x.category=='InvariantViolation' and x.findings==(TARGET,) for x in (inspections[0],inspections[1],inspections[3])),'ShrinkExactCausalMutantsMissing')
        _complete(inspections[2].category=='Pass','ShrinkReducedBaselinePositiveMissing')
        _complete(all(whole_branch_mutant_signature(*p,wire_version=wire_version) for p in (full_mutant,reduced_mutant,repeated_reduced_mutant)),'ShrinkWholeBranchSignatureMissing')
        _safe(reduced_mutant[0]==reduced_baseline[0]==repeated_reduced_mutant[0],'ShrinkReducedLiteralBytesDiffer')
        full=parse_case_input(full_mutant[0]);reduced=parse_case_input(reduced_mutant[0])
        _safe(_kind(full['composition'])==_kind(reduced['composition'])=='BoshAuth','ShrinkWrongRecipe')
        _safe(full['composition']['data']['mix'] is not None and reduced['composition']['data']['mix'] is None,'ShrinkDeletionNotIndependentMix')
        only=copy.deepcopy(full);only['composition']['data']['mix']=None
        _safe(only==reduced and _raw_auth_fragment(full_mutant[0])==_raw_auth_fragment(reduced_mutant[0]),'ShrinkChangedRetainedAuthInput')
        graphs=[_retained_auth_graph(*p,wire_version=wire_version) for p in (full_mutant,reduced_mutant,repeated_reduced_mutant)]
        _safe(graphs[0]==graphs[1]==graphs[2],'ShrinkRetainedAuthGraphOrOrderChanged')
        anchors=[_retained_auth_graph(*p,anchors_only=True,wire_version=wire_version) for p in pairs]
        _safe(anchors[0]==anchors[1]==anchors[2]==anchors[3],'ShrinkAuthIntroductionOrExposureChanged')
        return SemanticRelation('Related',(),ih,eh)
    except Stage4Incomplete as error:return SemanticRelation('Inconclusive',(str(error),),ih,eh)
    except (Stage4Invalid,SafetyViolation) as error:return SemanticRelation('Different',(str(error),),ih,eh)


def whole_branch_mutant_signature(raw_input,framed_evidence,*,wire_version='V1'):
    """Narrow factual signature, not source mutation authentication.

    Call only after inspect_semantics returned the exact causal invariant. The
    external mutation-source guard is still mandatory and stays outside here.
    """
    case=parse_case_input(raw_input); envelope=parse_frame(framed_evidence,wire_version=wire_version)
    if _kind(case['composition'])!='BoshAuth':return False
    frame=_fixed(case['composition']['data']['auth']['bound']['frame']['frame_id'])
    events=_events(envelope)
    intro=[e for e in events if e.family=='Control' and e.kind=='Holder' and e.data['cut']=='Introduction' and e.data['holder'] is not None and e.data['holder']['introduced'] is not None and e.data['holder']['introduced']['frame']==frame]
    if len(intro)!=1:return False
    control=intro[0].data['holder']['introduced']['control']
    live=[e for e in events if e.family=='Control' and e.kind=='LivePublication' and e.data['snapshot']['control']==control and e.data['cut']=='BeforeFinish']
    holders=[e for e in events if e.family=='Control' and e.kind=='Holder' and e.data['cut']=='BeforeFinish' and e.data['holder'] is not None and e.data['holder']['introduced'] is not None and e.data['holder']['introduced']['control']==control]
    if len(live)!=1 or len(holders)!=1:return False
    s,j=live[0].data['snapshot'],live[0].data['joins']
    callbacks=[e for e in events if e.family=='Control' and e.kind=='Callback' and any(a['control']==control for a in e.data['invoked_owners'])]
    return (j is not None and j['begun_receipt'] is None and holders[0].data['holder']['transferred'] is None and
            _kind(s['publication'])=='NotStarted' and not s['service_started'] and not s['repository_started'] and
            s['returned'] is None and s['terminal'] is None and not callbacks)


def _closed_fact_scope(l):
    """No unexamined domain owner may disappear during semantic reduction."""
    k,c=l.wire_case['composition']['kind'],l.wire_case['composition']['data']
    frames={reader_frame for reader_frame in (_key(a['owner']['frame']) for a in l.auth.values())}
    if k=='Muc':frames.add(_key(c['frame']['frame_id']))
    if k=='AuthThenMixNative':frames.add(_key(c['foreground']['frame']['frame_id']))
    if k=='ReplayMixQueuedAuth':frames.add(_key(c['mix']['foreground']['frame']['frame_id']))
    workers=_workers(l.wire_case)
    bound_frames={_key(a['owner']['frame']) for a in l.auth.values() if a['input']['binding'] is not None}
    sessions={(_key(s['session_id']),r['rid']) for s,a in _sessions(l.wire_case) for r in [s['response']]+([a['request']] if a else [])}
    _safe(not l.get('Bosh','TransportReceipt') and not l.get('Native','OwnershipReceipt') and not l.get('Native','WriteReceipt'),'UnexpectedOptionalGenericReceiptChannel')
    for e in l.events:
        d=e.data
        if e.family=='Frame':_safe(_key(d['frame']) in frames,'UnexpectedFrameOwner')
        if e.family=='Claim':_safe(d['claim_ordinal']<len(workers),'UnexpectedClaimOwner')
        if e.family=='Worker':
            if e.kind=='Lookup':
                if _kind(d['owner'])=='Auth':_safe(_key(d['owner']['data']['id']) in bound_frames,'UnexpectedAuthLookupOwner')
                else:_safe(d['owner']['data']['attempt_ordinal']<len(workers),'UnexpectedWorkerLookupOwner')
            else:_safe(d['attempt_ordinal']<len(workers),'UnexpectedWorkerOwner')
        if e.family=='Foreground':
            allowed=(e.kind=='InitialRow' and bool(workers) and _kind(workers[0]['origin'])=='InitialDurableRow') or (e.kind=='Snapshot' and k in ('AuthThenMixNative','ReplayMixQueuedAuth')) or (e.kind=='ProjectionRow' and k=='AuthThenMixNative')
            _safe(allowed,'UnexpectedForegroundFact')
            if e.kind=='Snapshot':
                expected_frame=c['foreground']['frame']['frame_id'] if k=='AuthThenMixNative' else c['mix']['foreground']['frame']['frame_id']
                _safe(d['frame']==expected_frame,'ForegroundSnapshotFrameReassignment')
        if e.family=='Control' and e.kind=='Holder':
            _complete(d['holder'] is not None and d['holder']['introduced'] is not None,'UnassociatedHolderRead')
            a=l.auth.get(_key(d['holder']['introduced']['control']));_complete(a is not None,'UnintroducedHolder')
            _safe(_association_identity(d['holder']['introduced'])==_association_identity(a['association']),'ExtraHolderReassignment')
        if e.family=='Bosh' and e.kind=='Selection':_safe((_key(d['selection']['session']),d['selection']['rid']) in sessions,'UnexpectedBoshSelectionKey')
        if e.family=='Bosh' and e.kind=='Receiver':_safe((_key(d['session']),d['rid']) in sessions,'UnexpectedBoshReceiverKey')
        if e.family=='Bosh' and e.kind=='Cache':
            rids=[entry['rid'] for entry in d['entries']]
            _safe(len(set(rids))==len(rids),'DuplicateBoshCacheKey')
            for entry in d['entries']:
                _safe((_key(d['session']),entry['rid']) in sessions,'UndeclaredBoshCacheKey')
                introductions=l.get('Bosh','Cache',lambda x:x.data['session']==d['session'] and x.data['cut']=='AfterFinish' and any(y['rid']==entry['rid'] for y in x.data['entries']))
                introduced=_one(introductions,'BoshCacheLifecycleIntroduction')
                original=_one([x for x in introduced.data['entries'] if x['rid']==entry['rid']],'BoshCacheLifecycleEntry')
                _safe(introduced.seq<=e.seq and original==entry,'BoshCacheLifecycleReassignment')


def _port_pair(events, returned_field, label):
    entry = _one([e for e in events if e.data[returned_field] is None], label + 'Entry')
    returned = _one([e for e in events if e.data[returned_field] is not None], label + 'Return')
    _safe(len(events) == 2 and entry.seq < returned.seq, label + 'PairOrder')
    return entry, returned


def _bosh_owner_calls(l, specs):
    """Close actual operation owners before interpreting any emitted port call."""
    expected_requests = {(_key(s['session_id']), r['rid']) for s, ack in specs.values()
                         for r in [s['response']] + ([ack['request']] if ack else [])}
    for e in l.get('Bosh', 'Snapshot'):
        d = e.data; ordinal = d['owner_ordinal']
        owner = l.bosh_owners.get(ordinal)
        if owner is None:
            owner = dict(association=copy.deepcopy(d['association']), scope=copy.deepcopy(d['snapshot']['scope']), snapshots=[])
            l.bosh_owners[ordinal] = owner
        _safe(owner['association'] == d['association'] and owner['scope'] == d['snapshot']['scope'], 'BoshOperationOwnerReassignment')
        owner['snapshots'].append(e)
        a = d['association']; state = d['snapshot']
        if _kind(a) == 'Outbound':
            _safe(not state['responses'] and not state['renewals'] and not state['acknowledgements'], 'BoshOutboundNestedRequestFacts')
            for transfer in state['transfers']:
                _safe(_kind(a['data']['source'])=='Mix' and transfer['source']==a['data']['source']['data'], 'BoshNestedTransferSourceMismatch')
        else:
            _safe(not state['transfers'], 'BoshRequestNestedTransferFacts')
            _safe(len(state['responses'])<=1 and all(r['rid']==a['data']['rid'] for r in state['responses']), 'BoshNestedResponseRidMismatch')
            if a['data']['ack'] is None:
                _safe(not state['renewals'] and not state['acknowledgements'], 'BoshNonAckNestedAckFacts')
            else:
                _safe(len(state['renewals'])<=1 and len(state['acknowledgements'])<=1 and all(x['rid']==a['data']['ack'] for x in state['acknowledgements']), 'BoshNestedAckRidMismatch')
                for renewal in state['renewals']:
                    if renewal['expected'] is not None:_safe(renewal['expected']['rid']==a['data']['ack'], 'BoshNestedRenewRidMismatch')
    for ordinal, owner in l.bosh_owners.items():
        snaps = owner['snapshots']
        intro = _one([e for e in snaps if e.data['cut'] == 'Introduction'], 'BoshOperationIntroduction')
        _safe(intro.seq == snaps[0].seq, 'BoshOperationBeforeIntroduction')
        owner['introduction'] = intro
        association = owner['association']; scope = owner['scope']
        if _kind(association) == 'Request':
            key = (_key(association['data']['session']), association['data']['rid'])
            _safe(key in expected_requests and key not in l.bosh_request_owners, 'BoshRequestOperationReassigned')
            l.bosh_request_owners[key] = ordinal
        else:
            item = association['data']
            _safe(_kind(item['source']) == 'Mix' and item['auth_control'] is None, 'BoshOutboundSourceOwner')
    _complete(set(l.bosh_request_owners) == expected_requests, 'BoshRequestOperationMissing')
    # Each field-bearing event belongs to an actual introduced owner, not just
    # any integer that happens to be in the scalar bound.
    for e in l.get('Bosh'):
        if e.kind not in ('Transfer', 'Bind', 'Renew', 'Ack', 'Receiver'): continue
        owner = l.bosh_owners.get(e.data['owner_ordinal'])
        _safe(owner is not None, 'BoshPortUnknownOperationOwner')
        association = owner['association']; a = association['data']
        if e.kind == 'Transfer':
            _safe(_kind(association) == 'Outbound', 'BoshTransferCrossOwner')
        else:
            _safe(_kind(association) == 'Request', 'BoshRequestPortCrossOwner')
            if e.kind == 'Receiver':
                _safe(e.data['session'] == a['session'] and e.data['connection'] == a['connection'] and e.data['rid'] == a['rid'], 'BoshReceiverOperationOwnerMismatch')
            elif e.kind == 'Bind':
                _safe(e.data['rid'] == a['rid'] and a['ack'] is None, 'BoshBindOperationOwnerMismatch')
            else:
                _safe(a['ack'] is not None, 'BoshAckRenewCrossOwner')
                if e.kind == 'Ack': _safe(e.data['rid'] == a['ack'], 'BoshAckOperationOwnerMismatch')
        _safe(owner['introduction'].seq < e.seq, 'BoshPortBeforeOperationIntroduction')
    outbound_sessions = []
    for ordinal, owner in l.bosh_owners.items():
        if _kind(owner['association']) != 'Outbound': continue
        snaps = owner['snapshots']; intro = owner['introduction']; item = owner['association']['data']
        outbound_sessions.append(_key(owner['scope']['session_id']))
        queue = _one(l.get('Worker','LocalQueue',lambda e:e.data['item']['item_ordinal']==item['item_ordinal']), 'BoshOutboundQueueOrigin')
        _safe(queue.seq < intro.seq and queue.data['item'] == item, 'BoshOutboundQueueAssociationMismatch')
        transfer = _one(snaps[-1].data['snapshot']['transfers'], 'BoshActualTransferSnapshot')
        _safe(transfer['source'] == item['source']['data'], 'BoshTransferSourceOwnerMismatch')
        _complete(transfer['returned_source'] is not None and _kind(transfer['knowledge']) == 'ReceiptKnown', 'BoshTransferReceiptMissing')
        _safe(transfer['knowledge']['data'] == transfer['returned_source'] and transfer['return_matches_receipt'] and
              transfer['local_entered'] and transfer['source_applied'] and transfer['queue_accepted'] is True, 'BoshTransferContinuationMismatch')
        calls = l.get('Bosh', 'Transfer', lambda e:e.data['owner_ordinal'] == ordinal)
        entry, returned = _port_pair(calls, 'returned_source', 'BoshTransferCall')
        _safe(intro.seq < entry.seq < returned.seq < snaps[-1].seq and entry.data['source'] == returned.data['source'] == transfer['source'] and
              returned.data['returned_source'] == transfer['returned_source'], 'BoshTransferCallAssociationMismatch')
    expected_outbound = [_key(session['session_id']) for session, ack in specs.values() if session['bind']['membership']['mix_delivery_ids']]
    _complete(len(outbound_sessions) >= len(expected_outbound), 'BoshOutboundOperationMissing')
    _safe(sorted(outbound_sessions) == sorted(expected_outbound), 'BoshExtraOutboundOperation')
    for key, ordinal in l.bosh_request_owners.items():
        owner = l.bosh_owners[ordinal]; a = owner['association']['data']
        if a['ack'] is None: continue
        snaps = owner['snapshots']; final = snaps[-1]
        renewal = _one(final.data['snapshot']['renewals'], 'BoshRenewalOwnerSnapshot')
        acknowledgment = _one(final.data['snapshot']['acknowledgements'], 'BoshAckOwnerSnapshot')
        renew_entry, renew_return = _port_pair(l.get('Bosh', 'Renew', lambda e:e.data['owner_ordinal'] == ordinal), 'returned', 'BoshRenewCall')
        ack_entry, ack_return = _port_pair(l.get('Bosh', 'Ack', lambda e:e.data['owner_ordinal'] == ordinal), 'returned', 'BoshAckCall')
        _safe(renew_entry.data['expected'] == renew_return.data['expected'] == renewal['expected'] and renew_return.data['returned'] is True and
              renewal['knowledge'] == 'ReceiptKnown' and renewal['returned'] and renewal['return_matches'], 'BoshRenewCallAssociationMismatch')
        _safe(ack_entry.data['rid'] == ack_return.data['rid'] == acknowledgment['rid'] == a['ack'] and ack_return.data['returned'] is True and
              acknowledgment['knowledge'] == 'ReceiptKnown' and acknowledgment['returned'] and acknowledgment['return_matches'], 'BoshAckCallAssociationMismatch')
        _safe(owner['introduction'].seq < renew_entry.seq < renew_return.seq < ack_entry.seq < ack_return.seq < final.seq, 'BoshRenewAckCallOrder')


def _bosh_bind_calls(l, sid, rid, selection, selected, responses):
    ordinal = l.bosh_request_owners[(_key(sid), rid)]
    calls = l.get('Bosh', 'Bind', lambda e:e.data['owner_ordinal'] == ordinal)
    sources = [item['source'] for item in selected if item['source'] is not None]
    initial = _last(l.get('Bosh','Queue',lambda e:e.data['session']==sid,before=selection.seq), 'BoshBindInitialFifo')
    lineage = [item['source'] for item in initial.data['fifo']]
    expected_end = len(selected)-1 if selected else None
    attempts = []
    for event, response in responses:
        _safe(response['lineage']==lineage and response['removed']==[False]*len(lineage) and response['construction_restored']==0, 'BoshBindLineageMismatch')
        attempt = _one(response['attempts'], 'BoshActualBindAttempt')
        _complete(attempt['sources'] is not None and attempt['returned'] is not None, 'BoshBindAttemptObservationMissing')
        _safe(attempt['selected_end']==expected_end and attempt['selected_len']==len(selected) and attempt['sources']==sources, 'BoshBindSelectedPrefixMismatch')
        _safe(attempt['superseded_message'] is None and not attempt['restored'] and not attempt['restore_matches'] and not attempt['removed_indices'], 'BoshUnexpectedBindRebuild')
        expected_kind = 'ReceiptKnown' if sources else 'NotRequired'
        _safe(_kind(attempt['knowledge'])==expected_kind, 'BoshBindAttemptKnowledgeMismatch')
        if sources:
            _safe(attempt['knowledge']['data']==attempt['returned'] and attempt['return_matches'], 'BoshBindAttemptReturnMismatch')
        else:
            _safe(attempt['returned']==EMPTY_MEMBERSHIP and attempt['return_matches'], 'BoshBindAttemptReturnMismatch')
        if attempts:_safe(attempts[0]==attempt, 'BoshBindAttemptChangedAcrossCuts')
        attempts.append(attempt)
    _complete(bool(attempts), 'BoshBindAttemptMissing')
    if not sources:
        _safe(not calls, 'BoshBindWithoutSelectedSources')
        return
    entry, returned = _port_pair(calls, 'returned_membership', 'BoshBindCall')
    _safe(entry.data['rid']==returned.data['rid']==rid and entry.data['sources']==returned.data['sources']==sources and returned.data['returned_membership']==attempts[0]['returned'], 'BoshBindCallAssociationMismatch')
    _safe(entry.seq < returned.seq < selection.seq, 'BoshSelectionBeforeActualBindReturn')


def _driver_owner_scope(l):
    """Poll labels must refer to actual introduced owners in this finite case."""
    owners = {}
    def put(role, ordinal, seq):
        key = (role, ordinal)
        if key not in owners or seq < owners[key]: owners[key] = seq
    for e in l.events:
        d = e.data
        if e.family == 'Muc' and e.kind == 'Snapshot' and d['cut'] == 'Introduction': put('Muc', 0, e.seq)
        if e.family == 'Foreground' and e.kind == 'Snapshot' and d['cut'] == 'Introduction': put('Foreground', 0, e.seq)
        if e.family == 'Claim' and e.kind == 'Snapshot' and d['cut'] == 'Introduction': put('Claim', d['claim_ordinal'], e.seq)
        if e.family == 'Worker' and e.kind == 'Snapshot' and d['cut'] == 'Introduction': put('Worker', d['attempt_ordinal'], e.seq)
        if e.family == 'Native' and e.kind == 'Dequeue': put('Native', d['item']['item_ordinal'], e.seq)
    # Credential site ordinals follow actual ordered frame introductions; the
    # within-frame credential ordinal is a different field and remains zero.
    intros = l.get('Credential', predicate=lambda e:e.data['cut'] == 'Introduction')
    for ordinal, e in enumerate(intros): put('Credential', ordinal, e.seq)
    native_auth = [a for a in l.auth.values() if a['input']['frame']['transport'] == 'Tcp']
    for ordinal, auth in enumerate(native_auth):
        introduction = _one(l.live(auth['control'], cut='BeforePublish'), 'NativePublicationBoundaryIntroduction')
        put('Publication', ordinal, introduction.seq)
    for ordinal, owner in l.bosh_owners.items(): put('Bosh', ordinal, owner['introduction'].seq)
    observed = set()
    for e in l.get('Driver'):
        key = (e.data['owner'], e.data['owner_ordinal'])
        _safe(key in owners, 'DriverUnintroducedOwner')
        _safe(owners[key] < e.seq, 'DriverPollBeforeOwnerIntroduction')
        observed.add(key)
    for role, ordinal in sorted(owners):
        _complete((role,ordinal) in observed, 'DriverOwnerPollMissing:'+role+':'+str(ordinal))


def _raw_owner_assignment(l):
    """Reject reassigned/orphan records before domain grouping can hide them."""
    k, c = l.wire_case['composition']['kind'], l.wire_case['composition']['data']
    auth_frames = {_key(a['owner']['frame']) for a in l.auth.values()}
    bound_frames = {_key(a['owner']['frame']) for a in l.auth.values() if a['input']['binding'] is not None}
    workers = _workers(l.wire_case)
    foreground = (c['foreground'] if k == 'AuthThenMixNative' else c['mix']['foreground']) if k in ('AuthThenMixNative', 'ReplayMixQueuedAuth') else None
    request_keys = {(_key(s['session_id']), r['rid']) for s, ack in _sessions(l.wire_case)
                    for r in [s['response']] + ([ack['request']] if ack else [])}
    for e in l.events:
        d = e.data
        if e.family == 'Frame' and _key(d['frame']) in auth_frames:
            _safe(d['admission_begin'] is None and d['admission_finalize'] is None, 'AuthFrameInventedAdmissionFacts')
        if e.family == 'Foreground':
            if e.kind == 'Snapshot':
                _safe(foreground is not None and d['frame'] == foreground['frame']['frame_id'], 'ForegroundSnapshotFrameReassignment')
            elif e.kind == 'ProjectionRow':
                _safe(k == 'AuthThenMixNative' and d['foreground_frame'] == c['foreground']['frame']['frame_id'], 'UnexpectedForegroundProjectionOwner')
            else:
                _safe(bool(workers) and _kind(workers[0]['origin']) == 'InitialDurableRow', 'UnexpectedInitialDurableRow')
        if e.family == 'Muc' and e.kind == 'Recipients' and k == 'Muc' and c['drive'] == 'DropCommit':
            raise SafetyViolation('MucRecipientsBeforeStoredReceipt')
        if e.family == 'Worker' and e.kind == 'Lookup' and _kind(d['owner']) == 'Auth':
            _safe(_key(d['owner']['data']['id']) in bound_frames, 'UnexpectedAuthLookupOwner')
        if e.family == 'Worker' and e.kind == 'Candidate':
            ordinal = d['attempt_ordinal']
            _safe(ordinal < len(workers), 'UnassignedWorkerCandidate')
            lookups = l.get('Worker','Lookup',lambda x:x.data['owner']=={'kind':'Worker','data':{'attempt_ordinal':ordinal}})
            lookup = _one(lookups, 'CandidateActualLookup')
            rows = [row for row in lookup.data['entries'] if row['full_jid'] == d['full_jid']]
            _safe(len(rows)==1 and lookup.seq<e.seq and d['lookup_key']==lookup.data['lookup_key'], 'CandidateAbsentFromActualLookup')
            _safe(all(d[n]==rows[0][n] for n in ('full_jid','connection_id','user_id','auth_generation','caps_observation_generation','routable','disconnected','lifecycle')), 'CandidateLookupRowReassignment')
            expected = [r for r in workers[ordinal]['attempt']['route']['targets'] if r['full_jid']==d['full_jid']]
            _safe(len(expected)==1 and all(d[n]==expected[0][n] for n in ('connection_id','user_id','auth_generation')), 'CandidateOutsideInputRoute')
        if e.family == 'Control' and e.kind == 'Callback':
            for invoked in d['invoked_owners']:
                a = l.auth.get(_key(invoked['control']))
                _complete(a is not None, 'CallbackIntroducedOwnerMissing')
                if a['input']['frame']['transport'] == 'Tcp':
                    _safe(d['session'] is None and d['rid'] is None, 'NativeCallbackBoshKeyReassignment')
                else:
                    sessions = [s for s, _ in _sessions(l.wire_case) if s['connection_id']==a['owner']['connection']]
                    session = _one(sessions, 'CallbackActualSession')
                    _safe(d['session']==session['session_id'] and d['rid']==session['response']['rid'], 'BoshCallbackRequestKeyReassignment')
        if e.family == 'Bosh' and e.kind == 'Cache':
            for entry in d['entries']:
                _safe((_key(d['session']),entry['rid']) in request_keys, 'UndeclaredBoshCacheKey')


def _all_bosh_selections(l):
    signatures = {}
    for e in l.get('Bosh', 'Selection'):
        d, s = e.data, e.data['selection']
        _safe(d['cut'] in ('BeforePublish','BeforeFinish'), 'BoshUnassignedSelectionCut')
        _complete(_kind(s['status'])=='Complete', 'BoshSelectionIncomplete')
        n=s['selected_count']
        _safe(n<=4 and all(x is not None for x in s['items'][:n]) and all(x is None for x in s['items'][n:]), 'BoshSelectionSlotMismatch')
        for ordinal, item in enumerate(s['items'][:n]):
            _safe(item['ordinal']==ordinal, 'BoshSelectionItemOrdinal')
            if item['auth_marker']:
                _complete(item['sealed_association'] is not None and item['holder_joins'] is not None and item['holder_joins']['introduced'] is not None, 'BoshSelectedHolderMissing')
                auth=l.auth.get(_key(item['sealed_association']['control']))
                _complete(auth is not None, 'BoshSelectedIntroductionMissing')
                _safe(_association_identity(item['sealed_association'])==_association_identity(auth['association']), 'BoshSelectedSealedAssociationChanged')
                _safe(_association_identity(item['holder_joins']['introduced'])==_association_identity(auth['association']), 'BoshSelectedHistoricalIntroductionChanged')
                if item['holder_joins']['transferred'] is not None:
                    _safe(_association_identity(item['holder_joins']['transferred'])==_association_identity(auth['association']), 'BoshSelectedHistoricalTransferChanged')
                standalone=_one(l.holders(auth['control'],cut=d['cut']), 'BoshSelectedStandaloneHolder')
                _safe(standalone.data['holder']==item['holder_joins'], 'BoshSelectedHolderReadDisagrees')
            else:
                _safe(item['sealed_association'] is None and item['holder_joins'] is None, 'BoshPlainSelectedHolderInvented')
        signature=copy.deepcopy(s)
        for item in signature['items']:
            if item is not None:item['holder_joins']=None
        key=(_key(s['session']),s['rid'])
        if key in signatures:_safe(signatures[key]==signature, 'BoshSelectionChangedAcrossCuts')
        else:signatures[key]=signature


def _all_bosh_queue_lifecycle(l):
    """Every retained FIFO cut derives from its real initial FIFO and selection."""
    for session, _ in _sessions(l.wire_case):
        sid=session['session_id']; queues=l.get('Bosh','Queue',lambda e:e.data['session']==sid)
        initial=_one([e for e in queues if e.data['cut']=='BeforePoll'], 'BoshInitialQueueCut')
        selections=l.get('Bosh','Selection',lambda e:e.data['selection']['session']==sid and e.data['cut']=='BeforePublish')
        for event in queues:
            _safe(event.seq>=initial.seq and event.data['cut'] in ('BeforePoll','BeforePublish','BeforeFinish','AfterFinish','BeforeTeardown','AfterTeardown'), 'BoshUnassignedQueueCut')
            expected=copy.deepcopy(initial.data['fifo'])
            for selected in selections:
                if selected.seq<event.seq:expected=expected[selected.data['selection']['selected_count']:]
            if event.data['cut']=='AfterTeardown':expected=[]
            _safe(event.data['fifo']==expected, 'BoshQueueLifecycleReassignment')
        for item in initial.data['fifo']:
            if item['auth_control'] is not None:
                auth=l.auth.get(_key(item['auth_control']))
                _complete(auth is not None, 'BoshQueueAuthIntroductionMissing')
                _safe(auth['intro'].seq<initial.seq and item['stanza']==_auth_xml(auth['input']), 'BoshQueueAuthOriginMismatch')
            elif item['source'] is not None:
                _safe(_kind(item['source'])=='Mix', 'BoshQueueUnexpectedSourceKind')
                origin=_one(l.get('Worker','LocalQueue',lambda e:e.data['item']['item_ordinal']==item['item_ordinal']), 'BoshQueueMixIntroduction')
                _safe(origin.seq<initial.seq and all(origin.data['item'][n]==item[n] for n in ('connection_id','stanza','auth_control')), 'BoshQueueMixOriginMismatch')
            else:
                _safe(_kind(l.case['composition'])=='ReplayMixQueuedAuth', 'BoshPlainItemWithoutHelperOrigin')
                lane=l.wire_case['composition']['data']['auth']
                _safe(sid==lane['session']['session_id'] and item['stanza'] in (lane['padding']['presence_xml'],lane['padding']['features_xml']), 'BoshPlainHelperOriginMismatch')


def _native_fence_for_item(l, owner):
    _safe(_kind(owner)=='Mix', 'NativeFenceWithoutMixOwner')
    k, c = l.wire_case['composition']['kind'], l.wire_case['composition']['data']
    if k=='AuthThenMixNative' and owner['data']['attempt_ordinal']==0: fence=c['delivery_native']['returned_fence']
    elif k=='MixRecoveryNative' and owner['data']['attempt_ordinal']==1: fence=c['native']['returned_fence']
    else: raise SafetyViolation('NativeFenceOutsideDeclaredDelivery')
    return {'kind':'Mix','data':fence}


def _mix_bosh_transport(l):
    k, c = l.wire_case['composition']['kind'], l.wire_case['composition']['data']
    _safe(k in ('ReplayMixQueuedAuth','BoshAuth') and c['mix'] is not None, 'BoshHandoffWithoutDeclaredMixLane')
    return c['mix']['transport']


def _callback_cancellation(l, entry, auths):
    """Entry-only callback requires actual Pending, child drop and retirement."""
    if not auths or not all(_kind(a['input']['publication'])=='CommitPending' for a in auths): return False
    for auth in auths:
        live=l.live(auth['control'])
        pending=[e for e in live if e.data['cut']=='AfterPoll' and _kind(e.data['snapshot']['publication'])=='CommitCallEntered' and e.data['snapshot']['returned'] is None and e.data['snapshot']['terminal'] is None]
        children=[e for e in live if e.data['cut']=='ChildDrop' and _kind(e.data['snapshot']['publication'])=='CommitCallEntered' and e.data['snapshot']['returned'] is None and e.data['snapshot']['terminal'] is None]
        retired=[e for e in live if e.data['cut']=='AfterRunnerDrop' and _kind(e.data['snapshot']['publication'])=='CommitCallEntered' and e.data['snapshot']['returned'] is None and e.data['snapshot']['terminal']=='Cancelled']
        if not pending or not children or not retired:return False
        before=pending[-1]; child=children[0]; after=retired[-1]
        if not entry.seq<before.seq<child.seq<after.seq:return False
        if before.data['joins']!=child.data['joins'] or child.data['joins']!=after.data['joins']:return False
        if auth['input']['frame']['transport']=='Tcp': role,ordinal='Publication',0
        else:
            operations=l.get('Bosh','Snapshot',lambda e:_kind(e.data['association'])=='Request' and e.data['association']['data']['session']==entry.data['session'] and e.data['association']['data']['rid']==entry.data['rid'])
            ordinals={e.data['owner_ordinal'] for e in operations}
            if len(ordinals)!=1:return False
            role,ordinal='Bosh',next(iter(ordinals))
        polls=l.get('Driver',predicate=lambda e:e.data['owner']==role and e.data['owner_ordinal']==ordinal and e.data['result']=='Pending' and entry.seq<e.seq<before.seq)
        if not polls:return False
    return True


def _callback_ledger(l):
    groups={}
    for event in l.get('Control','Callback'):
        d=event.data;key=(_key(d['connection']),_key(d['session']),d['rid'])
        groups.setdefault(key,[]).append(event)
    covered=set()
    for events in groups.values():
        entries=[e for e in events if e.data['returned'] is None]
        entry=_one(entries,'PublicationCallbackEntry')
        returns=[e for e in events if e.data['returned'] is not None]
        _safe(len(returns)<=1,'PublicationCallbackReturnMultiplicity')
        controls=[a['control'] for a in entry.data['invoked_owners']]
        _safe(len({_key(c) for c in controls})==len(controls),'PublicationCallbackDuplicateOwner')
        auths=[]
        for control in controls:
            auth=l.auth.get(_key(control));_complete(auth is not None,'PublicationCallbackOwnerMissing')
            _safe(_key(control) not in covered,'PublicationCallbackOwnerReinvoked')
            covered.add(_key(control));auths.append(auth)
        cancelled=_callback_cancellation(l,entry,auths)
        if returns:
            returned=returns[0];a=copy.deepcopy(entry.data);b=copy.deepcopy(returned.data)
            a['returned']=None;b['returned']=None
            _safe(len(events)==2 and entry.seq<returned.seq and a==b,'PublicationCallbackPairMismatch')
            _safe(not cancelled,'PublicationCallbackReturnedAfterCancellation')
        else:
            _complete(cancelled,'PublicationCallbackReturnMissing')
            _safe(len(events)==1,'PublicationCallbackEntryMultiplicity')
    for key,auth in l.auth.items():
        began=any(_kind(e.data['snapshot']['publication'])!='NotStarted' for e in l.live(auth['control']))
        transferred=any(e.data['holder']['transferred'] is not None for e in l.holders(auth['control']))
        if began or transferred:_complete(key in covered,'PublicationCallbackInvocationMissing')
