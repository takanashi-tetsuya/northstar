"""V2 semantic controls with authenticated actual-frame prerequisites.

Every positive requires actual authenticated V2 occurrence bytes. Constructed
codec fixtures and historical V1 transcodes cannot substitute for those bytes.
Missing evidence is a hard prerequisite failure, never a skip or test pass.
"""
import copy
import json
import os
import re
from pathlib import Path
import unittest

from lib import stage4_case as reader
from lib import stage4_compact as codec


# (exact control name, required real occurrence, mutation, expected category,
#  required exact finding or None). Inventory is intentionally closed.
CONTROLS = (
    ('duplicate_root_key_is_structural_rejection','S13','input_duplicate','InvalidScenario',None),
    ('positional_frame_is_structural_rejection','S13','input_positional','InvalidScenario',None),
    ('inconsistent_input_connection_rejected','S11','input_connection','InvalidScenario',None),
    ('unknown_input_field_rejected','S13','input_unknown','InvalidScenario',None),
    ('boolean_integer_rejected','S13','input_bool_integer','InvalidScenario',None),
    ('notification_required_input_unsupported','S13','input_notification','InvalidScenario',None),
    ('binary_semantics_nul_nonutf8_roundtrip','S06','binary_roundtrip','InputShapeRoundtrip',None),
    ('binary_semantics_odd_hex_rejected','S06','binary_odd','InputShapeRejected',None),
    ('binary_semantics_uppercase_hex_rejected','S06','binary_upper','InputShapeRejected',None),
    ('binary_semantics_malformed_hex_rejected','S06','binary_malformed','InputShapeRejected',None),
    ('binary_semantics_overbound_rejected','S06','binary_overbound','InputShapeRejected',None),
    ('framed_payload_truncation_rejected','S13','frame_truncate','EvidenceInvalid',None),
    ('framed_second_envelope_rejected','S13','frame_duplicate','EvidenceInvalid',None),
    ('noncanonical_frame_length_rejected','S13','frame_leading_zero','EvidenceInvalid',None),
    ('noncanonical_json_whitespace_rejected','S13','frame_whitespace','EvidenceInvalid',None),
    ('unknown_wire_field_rejected','S13','wire_unknown','EvidenceInvalid',None),
    ('missing_nullable_resource_stop_rejected','S13','wire_stop_absent','EvidenceInvalid',None),
    ('input_hash_mismatch_rejected','S13','wire_hash','EvidenceInvalid',None),
    ('sequence_gap_rejected','S13','seq_gap','EvidenceInvalid',None),
    ('duplicate_sequence_rejected','S13','seq_duplicate','EvidenceInvalid',None),
    ('fact_cap_overflow_rejected','S13','facts_overflow','EvidenceInvalid',None),
    ('poll_cap_overflow_rejected','S13','polls_overflow','EvidenceInvalid',None),
    ('snapshot_cap_overflow_rejected','S13','snapshots_overflow','EvidenceInvalid',None),
    ('opaque_introduction_order_rejected','S13','opaque_map','EvidenceInvalid',None),
    ('observation_loss_precedes_cache_target','M2','lost','Inconclusive',None),
    ('driver_resource_stop_precedes_cache_target','M2','stop_driver','Inconclusive',None),
    ('native_write_stop_precedes_cache_target','M2','stop_write','Inconclusive',None),
    ('native_flush_stop_precedes_cache_target','M2','stop_flush','Inconclusive',None),
    ('missing_credential_introduction_incomplete','M2','credential_intro_drop','Inconclusive',None),
    ('constructed_receipt_reassignment_rejected','S13','constructed_receipt','InvariantViolation',None),
    ('returned_receipt_reassignment_rejected','S13','returned_receipt','InvariantViolation',None),
    ('transferred_receipt_reassignment_rejected','S13','transferred_receipt','InvariantViolation',None),
    ('credential_frame_reassignment_rejected','S13','credential_frame','InvariantViolation','CredentialSnapshotOwnerReassignment'),
    ('credential_connection_reassignment_rejected','S13','credential_connection','InvariantViolation',None),
    ('credential_ordinal_reassignment_rejected','S13','credential_ordinal','InvariantViolation',None),
    ('credential_kind_reassignment_rejected','S13','credential_kind','InvariantViolation',None),
    ('control_receipt_reassignment_rejected','S13','holder_receipt','InvariantViolation',None),
    ('control_connection_reassignment_rejected','S13','holder_connection','InvariantViolation',None),
    ('control_digest_corruption_rejected','S13','holder_digest','InvariantViolation',None),
    ('control_length_corruption_rejected','S13','holder_length','InvariantViolation',None),
    ('live_begun_receipt_reassignment_rejected','S13','begun_receipt','InvariantViolation',None),
    ('missing_live_joins_incomplete','M2','live_joins_missing','Inconclusive',None),
    ('frame_completed_does_not_complete_owner','M2','frame_completed','InvariantViolation',reader.TARGET),
    ('actual_notstarted_cache_exact_target','M2','identity_copy','InvariantViolation',reader.TARGET),
    ('missing_selection_is_not_cache_target','M2','selection_drop','Inconclusive',None),
    ('incomplete_selection_is_not_cache_target','M2','selection_incomplete','Inconclusive',None),
    ('wrong_selected_connection_rejected','M2','selection_connection','InvariantViolation',None),
    ('selected_digest_corruption_rejected','S06','selection_digest','InvariantViolation',None),
    ('selected_length_corruption_rejected','S06','selection_length','InvariantViolation',None),
    ('selected_slot_reassignment_rejected','S06','selection_ordinal','InvariantViolation',None),
    ('selected_u_cannot_stand_for_b','S06','selection_owner','InvariantViolation',None),
    ('actual_fifo_order_corruption_rejected','S06','fifo_order','InvariantViolation',None),
    ('remaining_fb_corruption_rejected','S06','fifo_remnant','InvariantViolation',None),
    ('unselected_bound_pending_cut_not_teardown','S06','unselected_terminal','InvariantViolation',None),
    ('cache_fingerprint_reassignment_rejected','M2','cache_fingerprint','InvariantViolation',None),
    ('cache_body_corruption_rejected','M2','cache_body','InvariantViolation',None),
    ('mix_cache_cannot_substitute_for_auth_cache','M1','cache_lane','InvariantViolation',None),
    ('ack_wrong_deleted_fence_rejected','S06','ack_fence','InvariantViolation',None),
    ('ack_new_empty_cache_not_old_payload','S06','ack_cache_rid','InvariantViolation',None),
    ('ack_requires_payload_response_kind','S06','ack_emptycontrol','InvariantViolation',None),
    ('empty_ack_callback_cannot_be_invented','S06','ack_callback','InvariantViolation',None),
    ('empty_ack_selection_no_invented_item','S06','ack_selected_count','InvariantViolation',None),
    ('native_actual_accepted_bytes_corruption','S09','native_bytes','InvariantViolation',None),
    ('native_flush_removed_incomplete','S09','native_flush_drop','Inconclusive',None),
    ('native_write_after_flush_rejected','S09','native_flush_order','InvariantViolation',None),
    ('native_dequeue_ordinal_reassignment','S05','native_ordinal','InvariantViolation',None),
    ('muc_fanout_before_receipt_rejected','S01','muc_receipt','InvariantViolation',None),
    ('muc_replay_original_id_reassignment','S02','muc_replay_id','InvariantViolation',None),
    ('muc_volatile_prefix_not_erased','S03','muc_volatile_prefix','InvariantViolation',None),
    ('muc_child_drop_before_settlement_required','S01','muc_child_terminal','InvariantViolation',None),
    ('foreground_projection_row_reassignment','S05','projection_row','InvariantViolation',None),
    ('authenticated_replay_cannot_fresh_wake','S06','foreground_replay_wake','InvariantViolation',None),
    ('claim_source_reassignment_rejected','S05','claim_source','InvariantViolation',None),
    ('archive_replay_original_id_reassignment','S07','archive_replay_id','InvariantViolation',None),
    ('worker_child_closure_before_settlement','S08','settlement_closed','InvariantViolation',None),
    ('old_worker_cannot_settle_after_transfer','S05','transfer_settlement','InvariantViolation',None),
    ('s08_active_renewal_not_claimed','S08','renewal_started','InvariantViolation',None),
    ('complete_delivered_handoff_set_removed_is_incomplete','S05','handoff_all_drop','Inconclusive','DeliveredWorkerHandoffMissing'),
    ('typed_handoff_queue_ordinal_reassignment','S05','handoff_ordinal','Inconclusive',None),
    ('route_activation_cannot_change_connection','S05','route_connection','InvariantViolation',None),
    ('historical_begun_receipt_is_not_erased', 'S13', 'holder_begun_receipt', 'InvariantViolation', 'HistoricalAssociationBegunReceiptChanged'),
    ('bosh_receiver_operation_owner_reassignment', 'S06', 'receiver_owner', 'InvariantViolation', 'BoshReceiverOperationOwnerMismatch'),
    ('bosh_transfer_source_call_reassignment', 'S06', 'transfer_source', 'InvariantViolation', 'BoshTransferCallAssociationMismatch'),
    ('bosh_transfer_return_call_reassignment', 'S06', 'transfer_return', 'InvariantViolation', 'BoshTransferCallAssociationMismatch'),
    ('bosh_transfer_pair_missing_is_incomplete', 'S06', 'transfer_pair_drop', 'Inconclusive', 'BoshTransferCallEntry:Missing'),
    ('bosh_transfer_call_cross_owner_rejected', 'S06', 'transfer_owner', 'InvariantViolation', 'BoshTransferCrossOwner'),
    ('bosh_bind_source_call_reassignment', 'S06', 'bind_source', 'InvariantViolation', 'BoshBindCallAssociationMismatch'),
    ('bosh_bind_membership_call_reassignment', 'S06', 'bind_membership', 'InvariantViolation', 'BoshBindCallAssociationMismatch'),
    ('bosh_bind_pair_missing_is_incomplete', 'S06', 'bind_pair_drop', 'Inconclusive', 'BoshBindCallEntry:Missing'),
    ('bosh_renew_expected_reassignment', 'S06', 'renew_expected', 'InvariantViolation', 'BoshRenewCallAssociationMismatch'),
    ('bosh_ack_renewal_rejects_consistent_cached_batch_scope', 'S06', 'ack_renew_batch_scope', 'InvariantViolation', 'BoshAckRenewalScopeMismatch'),
    ('bosh_renew_pair_missing_is_incomplete', 'S06', 'renew_pair_drop', 'Inconclusive', 'BoshRenewCallEntry:Missing'),
    ('bosh_ack_entry_missing_is_incomplete', 'S06', 'ack_entry_drop', 'Inconclusive', 'BoshAckCallEntry:Missing'),
    ('bosh_ack_false_return_rejected', 'S06', 'ack_false', 'InvariantViolation', 'BoshAckCallAssociationMismatch'),
    ('ascii_request_rid_rejects_superscript_digit', 'S13', 'input_rid_unicode', 'InvalidScenario', 'Relationship'),
    ('ascii_request_rid_rejects_u64_overflow', 'S13', 'input_rid_overflow', 'InvalidScenario', 'Relationship'),
    ('ascii_ack_rejects_superscript_digit', 'S06', 'input_ack_unicode', 'InvalidScenario', 'Relationship'),
    ('native_fact_requires_dequeue_assignment', 'S09', 'native_orphan', 'InvariantViolation', 'NativeUnassignedItemOrdinal'),
    ('driver_poll_requires_introduced_owner', 'S13', 'driver_orphan', 'InvariantViolation', 'DriverUnintroducedOwner'),
    ('foreground_snapshot_cannot_leave_frame_group', 'S05', 'foreground_frame', 'InvariantViolation', 'ForegroundSnapshotFrameReassignment'),
    ('initial_row_cannot_join_fresh_projection_recipe', 'S05', 'initial_row_fresh', 'InvariantViolation', 'UnexpectedInitialDurableRow'),
    ('every_cache_entry_requires_declared_request', 'S06', 'cache_undeclared', 'InvariantViolation', 'UndeclaredBoshCacheKey'),
    ('auth_lookup_requires_bound_auth_frame', 'S06', 'lookup_unbound', 'InvariantViolation', 'UnexpectedAuthLookupOwner'),
    ('candidate_requires_actual_lookup_row', 'S05', 'candidate_orphan', 'InvariantViolation', 'CandidateAbsentFromActualLookup'),
    ('callback_requires_actual_bosh_request_key', 'S06', 'callback_key', 'InvariantViolation', 'BoshCallbackRequestKeyReassignment'),
    ('muc_pending_commit_cannot_supply_recipient_plan', 'S04', 'muc_orphan_recipients', 'InvariantViolation', 'MucRecipientsBeforeStoredReceipt'),
    ('bosh_nested_response_requires_operation_rid', 'S06', 'nested_response_rid', 'InvariantViolation', 'BoshNestedResponseRidMismatch'),
    ('bosh_request_cannot_contain_transfer_snapshot', 'S06', 'nested_transfer', 'InvariantViolation', 'BoshRequestNestedTransferFacts'),
    ('bosh_non_ack_cannot_contain_renewal_snapshot', 'S06', 'nested_renewal', 'InvariantViolation', 'BoshNonAckNestedAckFacts'),
    ('auth_frame_cannot_invent_admission_evidence', 'S13', 'auth_admission', 'InvariantViolation', 'AuthFrameInventedAdmissionFacts'),
    ('settlement_return_requires_actual_success', 'S08', 'settlement_result', 'InvariantViolation', 'DeferCommandOrResultMismatch'),
    ('settlement_command_payload_is_exact', 'S08', 'settlement_command', 'InvariantViolation', 'DeferCommandOrResultMismatch'),
    ('selection_extra_cut_cannot_hide_facts', 'S06', 'selection_extra_cut', 'InvariantViolation', 'BoshUnassignedSelectionCut'),
    ('later_fifo_cannot_resurrect_selected_plain_item', 'S06', 'fifo_resurrect', 'InvariantViolation', 'BoshQueueLifecycleReassignment'),
    ('socket_handoff_cannot_use_lease_token_as_connection', 'S05', 'socket_boundary_lease', 'InvariantViolation', 'NativeHandoffConnectionMismatch'),
    ('bosh_handoff_cannot_use_lease_token_as_session', 'S06', 'bosh_boundary_lease', 'InvariantViolation', 'BoshHandoffSessionMismatch'),
    ('native_returned_fence_token_is_independent', 'S05', 'native_fence_token', 'InvariantViolation', 'NativeReturnedFenceMismatch'),
    ('native_ack_cannot_belong_to_auth_item', 'S09', 'native_ack_nondurable', 'InvariantViolation', 'NativeAckWithoutMixDurableOwner'),
    ('native_ack_cannot_belong_to_plain_muc_item', 'S01', 'native_ack_nondurable', 'InvariantViolation', 'NativeAckWithoutMixDurableOwner'),
    ('auth_bind_notrequired_knowledge_is_validated', 'S13', 'bind_nosource_knowledge', 'InvariantViolation', 'BoshBindAttemptKnowledgeMismatch'),
    ('empty_ack_notrequired_return_is_validated', 'S06', 'bind_empty_ack_return', 'InvariantViolation', 'BoshBindAttemptReturnMismatch'),
    ('full_fifo_lineage_cannot_drop_unselected_fb', 'S06', 'bind_lineage_prefix', 'InvariantViolation', 'BoshLineageReassignment'),
    ('callback_contradictory_returns_are_rejected', 'S05', 'callback_duplicate_return', 'InvariantViolation', 'PublicationCallbackReturnMultiplicity'),
    ('callback_missing_return_is_incomplete', 'S13', 'callback_return_drop', 'Inconclusive', 'PublicationCallbackReturnMissing'),
    ('callback_missing_entry_is_incomplete', 'S13', 'callback_entry_drop', 'Inconclusive', None),
    ('cancelled_callback_cannot_invent_return', 'S10', 'callback_cancel_return', 'InvariantViolation', 'PublicationCallbackReturnedAfterCancellation'),
    ('all_driver_facts_missing_is_incomplete', 'S13', 'driver_all_drop', 'Inconclusive', 'DriverOwnerPollMissing:Bosh:0'),
    ('executed_worker_requires_retained_driver_poll', 'S05', 'driver_worker_drop', 'Inconclusive', 'DriverOwnerPollMissing:Worker:0'),
    ('standalone_publication_requires_retained_driver_poll', 'S09', 'driver_publication_drop', 'Inconclusive', 'DriverOwnerPollMissing:Publication:0'),
)


def frame(envelope):
    # Every semantic mutation recomputes both expanded transport commitments.
    # This does not create actual execution/provenance evidence.
    return codec.encode_compact_frame(envelope)


def wire_payload(framed):
    # Test-only framing mutation helper; starts from canonical re-packed V2.
    return json.loads(framed.split(b'\n', 1)[1][:-len(codec.TRAILER)])


def malformed_payload(value):
    # Malformed transport controls intentionally need not repair commitments.
    payload=reader._canonical(value)
    return codec.FRAME_TAG+str(len(payload)).encode()+b'\n'+payload+codec.TRAILER


def select(envelope,family,kind=None,cut=None):
    matches=[]
    for record in envelope['facts']:
        fact=record['fact']
        if fact['kind']!=family:continue
        data=fact['data']
        if family not in ('Frame','Credential','Driver'):
            if kind is not None and data['kind']!=kind:continue
            data=data['data']
        if cut is None or data.get('cut')==cut:matches.append((record,data))
    if not matches:raise AssertionError('Actual prerequisite fact missing: '+str((family,kind,cut)))
    return matches


def alternate(label,envelope):
    choices=[x['label'] for x in envelope['identity_map'] if x['label']!=label]
    if not choices:raise AssertionError('Actual second identity missing')
    return copy.deepcopy(choices[-1])


def captured_ack_batch_scope(envelope):
    """Use only the actual ACK owner and its captured prior cache membership."""
    returns=[d for _,d in select(envelope,'Bosh','Ack') if d['returned'] is True]
    if len(returns)!=1:raise AssertionError('Actual single ACK return required')
    owner=returns[0]['owner_ordinal'];rid=returns[0]['rid']
    renew=[(r,d) for r,d in select(envelope,'Bosh','Renew') if d['owner_ordinal']==owner]
    if len(renew)!=2 or any(d['expected'] is not None for _,d in renew):
        raise AssertionError('Actual null-scope renewal pair required')
    intro=[d for _,d in select(envelope,'Bosh','Snapshot',cut='Introduction') if d['owner_ordinal']==owner]
    if len(intro)!=1 or intro[0]['association']['kind']!='Request':
        raise AssertionError('Actual ACK request-owner introduction required')
    association=intro[0]['association']['data']
    if association['ack']!=rid:raise AssertionError('Actual ACK owner RID mismatch')
    first=min(r['seq'] for r,_ in renew)
    cached=[entry for r,d in select(envelope,'Bosh','Cache',cut='AfterFinish')
            if d['session']==association['session'] and r['seq']<first
            for entry in d['entries'] if entry['rid']==rid]
    if len(cached)!=1:raise AssertionError('Actual captured prior batch scope required')
    return owner,{'rid':rid,'membership':copy.deepcopy(cached[0]['membership'])}


def repair_copy(raw,envelope):
    """Reframe a negative without hiding joins under stale sequence/map errors.

    This only renumbers the whole remaining opaque equality graph bijectively;
    it never repairs an owner association, missing fact, control or receipt.
    """
    opaque={};seen=set();introductions=[]
    for seq,record in enumerate(envelope['facts'],1):
        record['seq']=seq
        def visit(label,locus):
            if label['kind']=='Opaque':
                old=label['data']['ordinal']
                if old not in opaque:opaque[old]=len(opaque)+1
                label={'kind':'Opaque','data':{'ordinal':opaque[old]}}
            key=reader._key(label)
            if key not in seen:
                seen.add(key);introductions.append({'label':label,'first_seq':seq,'locus':locus})
            return label
        record['fact']=reader._shape(record['fact'],['ref','Fact'],visit)
    envelope['identity_map']=introductions
    envelope['input_sha256']=reader._hash(raw)
    if envelope['observation_status']['kind']=='Lost':envelope['observation_status']['data']['after_seq']=len(envelope['facts'])
    return envelope


def mutate(raw,original,operation):
    e=copy.deepcopy(original)
    if operation=='identity_copy':return raw,frame(e)
    if operation.startswith('input_'):
        c=reader.parse_case_input(raw)
        if operation=='input_duplicate':bad=b'{"schema":"'+reader.CASE_SCHEMA.encode()+b'",'+raw.lstrip()[1:]
        else:
            d=c['composition']['data'];a=d['auth']['bound']
            if operation=='input_positional':a['frame']=list(a['frame'].values())
            elif operation=='input_connection':d['mix']['transport']['session']['connection_id']=a['frame']['connection_id']
            elif operation=='input_unknown':c['extra']=None
            elif operation=='input_bool_integer':a['ordinal']=False
            elif operation=='input_notification':a['notification_expected']=True
            elif operation in ('input_rid_unicode','input_rid_overflow','input_ack_unicode'):
                request=d['mix']['transport']['ack']['request'] if operation=='input_ack_unicode' else d['auth']['session']['response']
                attribute='ack' if operation=='input_ack_unicode' else 'rid'
                replacement='18446744073709551616' if operation=='input_rid_overflow' else '²'
                request['request_xml']=re.sub(attribute+r'=([\"\'])[^\"\']*\1',lambda m:attribute+'='+m[1]+replacement+m[1],request['request_xml'],count=1)
                request['fingerprint']=reader._hash(request['request_xml'].encode())
            else:raise AssertionError(operation)
            bad=reader._canonical(c)
        try:reader.parse_case_input(bad)
        except reader.Stage4Invalid as error:reason=str(error).split(':',1)[0]
        else:raise AssertionError('Negative input unexpectedly parsed')
        # Rejection DTO is synthetic parser control only. No runtime positive
        # or actual producer rejection is claimed by this mutation helper.
        e.update(input_sha256=reader._hash(bad),rejection=reason,execution=None,resource_stop=None,identity_map=[],facts=[],observation_status={'kind':'Complete','data':{}})
        return bad,frame(e)
    if operation.startswith('frame_'):
        f=frame(e)
        if operation=='frame_truncate':return raw,f[:-1]
        if operation=='frame_duplicate':return raw,f+f
        if operation=='frame_leading_zero':return raw,codec.FRAME_TAG+b'0'+f[len(codec.FRAME_TAG):]
        if operation=='frame_whitespace':
            payload=reader._canonical(wire_payload(f))+b' ';return raw,codec.FRAME_TAG+str(len(payload)).encode()+b'\n'+payload+codec.TRAILER
    if operation=='wire_unknown':
        payload=wire_payload(frame(e));payload[3].append(None);return raw,malformed_payload(payload)
    if operation=='wire_stop_absent':
        payload=wire_payload(frame(e));del payload[3][5];return raw,malformed_payload(payload)
    if operation=='wire_hash':e['input_sha256']='0'*64;return raw,frame(e)
    if operation=='seq_gap':e['facts'][0]['seq']=2;return raw,frame(e)
    if operation=='seq_duplicate':e['facts'][1]['seq']=e['facts'][0]['seq'];return raw,frame(e)
    if operation=='opaque_map':e['identity_map'][0]['first_seq']+=1;return raw,frame(e)
    if operation=='facts_overflow':
        payload=wire_payload(frame(e));payload[3][7]=(payload[3][7]*257)[:257];return raw,malformed_payload(payload)
    if operation=='polls_overflow':
        r=select(e,'Driver')[0][0];e['facts']=[copy.deepcopy(r) for _ in range(65)]
    elif operation=='snapshots_overflow':
        r=select(e,'Credential')[0][0];e['facts']=[copy.deepcopy(r) for _ in range(17)]
    elif operation=='lost':e['observation_status']={'kind':'Lost','data':{'reason':'MissingObservation','after_seq':len(e['facts'])}}
    elif operation.startswith('stop_'):
        data={'owner':'Bosh','owner_ordinal':0,'admitted_calls':64} if operation=='stop_driver' else {'item_ordinal':0,'admitted_calls':32 if operation=='stop_write' else 1}
        e['resource_stop']={'kind':{'stop_driver':'DriverPoll','stop_write':'NativeWrite','stop_flush':'NativeFlush'}[operation],'data':data};e['execution']=None
    elif operation=='credential_intro_drop':
        record=select(e,'Credential',cut='Introduction')[0][0];e['facts'].remove(record)
    elif operation in ('constructed_receipt','returned_receipt','transferred_receipt'):
        d=select(e,'Credential')[-1][1];d['joins'][operation]=alternate(d['joins'][operation],e)
    elif operation.startswith('credential_'):
        d=select(e,'Credential')[-1][1];name=operation[len('credential_'):]
        replacement={'ordinal':1,'kind':'UnboundFast'}.get(name)
        if replacement is None:replacement=alternate(d['snapshot'][name],e)
        d['snapshot'][name]=replacement
    elif operation=='holder_begun_receipt':
        d=select(e,'Control','Holder')[-1][1];a=d['holder']['introduced'];a['publication']['begun_receipt']=alternate(a['receipt'],e)
    elif operation.startswith('holder_'):
        d=select(e,'Control','Holder')[-1][1];a=d['holder']['introduced'];name=operation[len('holder_'):]
        if name=='digest':a[name]='0'*64
        elif name=='length':a[name]+=1
        else:a[name]=alternate(a[name],e)
    elif operation=='begun_receipt':
        d=select(e,'Control','LivePublication')[-1][1];d['joins']['begun_receipt']=alternate(d['joins']['begun_receipt'],e)
    elif operation=='live_joins_missing':select(e,'Control','LivePublication',cut='BeforeFinish')[0][1]['joins']=None
    elif operation=='frame_completed':
        for _,d in select(e,'Frame'):d['outcome']='Completed'
    elif operation=='selection_drop':
        e['facts']=[r for r in e['facts'] if not(r['fact']['kind']=='Bosh' and r['fact']['data']['kind']=='Selection')]
    elif operation=='selection_incomplete':select(e,'Bosh','Selection')[0][1]['selection']['status']={'kind':'Incomplete','data':{'omitted_items':1,'missing_auth_associations':0,'connection_changed':False}}
    elif operation in ('selection_connection','selection_digest','selection_length','selection_ordinal','selection_owner'):
        candidates=select(e,'Bosh','Selection');d=next(d for _,d in candidates if any(x and x['auth_marker'] for x in d['selection']['items']));s=d['selection']
        item=next(x for x in s['items'] if x and x['auth_marker'])
        if operation=='selection_connection':s['validated_connection']=alternate(s['validated_connection'],e)
        elif operation=='selection_digest':item['sha256']='0'*64
        elif operation=='selection_length':item['utf8_length']+=1
        elif operation=='selection_ordinal':item['ordinal']=3
        elif operation=='selection_owner':
            holders=select(e,'Control','Holder',cut='Introduction');other=next(x['holder']['introduced'] for _,x in holders if x['holder']['introduced']['control']!=item['sealed_association']['control']);item['sealed_association']=copy.deepcopy(other)
    elif operation in ('fifo_order','fifo_remnant'):
        wanted=4 if operation=='fifo_order' else 2
        d=next(d for _,d in select(e,'Bosh','Queue') if len(d['fifo'])==wanted)
        d['fifo'].reverse()
    elif operation=='unselected_terminal':
        d=next(d for _,d in select(e,'Control','LivePublication',cut='BeforeFinish') if d['snapshot']['transport']['kind']=='NotStarted');d['snapshot']['terminal']='Completed'
    elif operation in ('cache_fingerprint','cache_body','cache_lane'):
        candidates=[d for _,d in select(e,'Bosh','Cache',cut='AfterFinish') if d['entries']];d=candidates[-1];c=d['entries'][-1]
        if operation=='cache_fingerprint':c['fingerprint']='0'*64
        elif operation=='cache_body':c['body_hex']='00'+c['body_hex'][2:]
        elif operation=='cache_lane':d['session']=candidates[0]['session']
    elif operation=='ack_fence':
        d=next(d for _,d in reversed(select(e,'Bosh','Snapshot')) if d['snapshot']['acknowledgements']);a=d['snapshot']['acknowledgements'][0];a['deleted'][0]['data']['lease_token']=alternate(a['deleted'][0]['data']['lease_token'],e)
    elif operation=='ack_cache_rid':
        d=next(d for _,d in reversed(select(e,'Bosh','Cache',cut='AfterFinish')) if d['entries'] and d['entries'][0]['membership']==reader.EMPTY_MEMBERSHIP and d['entries'][0]['transport_receipt_count']==0 and b'<body' in bytes.fromhex(d['entries'][0]['body_hex']))
        d['entries'][0]['rid']+=1
    elif operation=='ack_emptycontrol':
        d=next(d for _,d in reversed(select(e,'Bosh','Snapshot')) if d['snapshot']['acknowledgements']);d['snapshot']['responses'][-1]['kind']='EmptyControl'
    elif operation=='ack_callback':
        source=copy.deepcopy(select(e,'Control','Callback')[0][0]);source['fact']['data']['data']['invoked_owners']=[];e['facts'].append(source)
    elif operation=='ack_selected_count':
        d=next(d for _,d in select(e,'Bosh','Selection') if d['selection']['selected_count']==0);d['selection']['selected_count']=1
    elif operation=='native_bytes':
        d=select(e,'Native','Write')[0][1];d['accepted_bytes_hex']='00'+d['accepted_bytes_hex'][2:]
    elif operation=='native_flush_drop':
        e['facts']=[r for r in e['facts'] if not(r['fact']['kind']=='Native' and r['fact']['data']['kind']=='Flush')]
    elif operation=='native_flush_order':
        f=select(e,'Native','Flush')[0][0];w=select(e,'Native','Write')[0][0];e['facts'].remove(f);e['facts'].insert(e['facts'].index(w),f)
    elif operation=='native_ordinal':select(e,'Native','Dequeue')[-1][1]['item']['item_ordinal']=select(e,'Native','Dequeue')[0][1]['item']['item_ordinal']
    elif operation=='muc_receipt':
        for _,d in select(e,'Muc','Snapshot'):
            if d['snapshot']['knowledge']['kind']=='ReceiptKnown':d['snapshot']['knowledge']['kind']='CommitCallEntered'
    elif operation=='muc_replay_id':
        d=select(e,'Muc','Snapshot')[-1][1];v=d['snapshot']['returned']['data']['data'];v['id']=alternate(v['id'],e)
    elif operation=='muc_volatile_prefix':select(e,'Muc','Snapshot')[-1][1]['snapshot']['fanout']['accepted']=0
    elif operation=='muc_child_terminal':select(e,'Muc','Snapshot',cut='ChildDrop')[0][1]['snapshot']['terminal']='Completed'
    elif operation=='projection_row':
        d=select(e,'Foreground','ProjectionRow')[0][1];d['actual_row']['source']['delivery_id']=alternate(d['actual_row']['source']['delivery_id'],e)
    elif operation=='foreground_replay_wake':select(e,'Foreground','Snapshot')[-1][1]['snapshot']['wake']='Invoked'
    elif operation=='claim_source':
        d=select(e,'Claim','Attempt')[0][1];d['source']['lease_token']=alternate(d['source']['lease_token'],e)
    elif operation=='archive_replay_id':
        d=next(d for _,d in select(e,'Worker','Archive') if d['returned'] is not None);v=d['returned']['data']['data'];v['id']=alternate(v['id'],e)
    elif operation=='settlement_closed':select(e,'Worker','Settlement')[0][1]['at_entry']['renewal_scope_closed']=False
    elif operation=='transfer_settlement':
        d=select(e,'Worker','Snapshot')[-1][1];d['snapshot']['settlement']={'kind':'Ack','started':False,'knowledge':{'kind':'NotEntered','data':{}},'returned':None}
    elif operation=='renewal_started':select(e,'Worker','Snapshot')[-1][1]['snapshot']['renewal']['issued']=1
    elif operation=='handoff_all_drop':
        e['facts']=[r for r in e['facts'] if not(r['fact']['kind']=='Worker' and r['fact']['data']['kind']=='Handoff')]
    elif operation=='handoff_ordinal':select(e,'Worker','Handoff')[0][1]['item_ordinal']=4
    elif operation=='route_connection':
        d=next(d for _,d in reversed(select(e,'Worker','Lookup')) if d['entries']);d['entries'][0]['connection_id']=alternate(d['entries'][0]['connection_id'],e)
    elif operation=='receiver_owner':
        d=select(e,'Bosh','Receiver')[0][1];d['owner_ordinal']=next(x['owner_ordinal'] for _,x in select(e,'Bosh','Snapshot') if x['association']['kind']=='Request' and x['owner_ordinal']!=d['owner_ordinal'])
    elif operation in ('transfer_source','transfer_return','transfer_owner'):
        entries=select(e,'Bosh','Transfer');d=entries[-1 if operation=='transfer_return' else 0][1]
        if operation=='transfer_owner':d['owner_ordinal']=next(x['owner_ordinal'] for _,x in select(e,'Bosh','Snapshot') if x['association']['kind']=='Request')
        else:
            source=d['returned_source'] if operation=='transfer_return' else d['source'];source['lease_token']=alternate(source['lease_token'],e)
    elif operation in ('transfer_pair_drop','bind_pair_drop','renew_pair_drop'):
        kind={'transfer_pair_drop':'Transfer','bind_pair_drop':'Bind','renew_pair_drop':'Renew'}[operation]
        e['facts']=[r for r in e['facts'] if not(r['fact']['kind']=='Bosh' and r['fact']['data']['kind']==kind)]
    elif operation=='bind_source':
        d=select(e,'Bosh','Bind')[0][1];source=d['sources'][0]['data'];source['lease_token']=alternate(source['lease_token'],e)
    elif operation=='bind_membership':
        d=select(e,'Bosh','Bind')[-1][1];membership=d['returned_membership'];membership['mix_delivery_ids'][0]=alternate(membership['mix_delivery_ids'][0],e)
    elif operation=='renew_expected':
        owner,scope=captured_ack_batch_scope(e)
        returned=[d for _,d in select(e,'Bosh','Renew') if d['owner_ordinal']==owner and d['returned'] is True]
        if len(returned)!=1:raise AssertionError('Actual single renewal return required')
        returned[0]['expected']=scope
    elif operation=='ack_renew_batch_scope':
        owner,scope=captured_ack_batch_scope(e)
        for _,d in select(e,'Bosh','Renew'):
            if d['owner_ordinal']==owner:d['expected']=copy.deepcopy(scope)
        changed=0
        for _,d in select(e,'Bosh','Snapshot'):
            if d['owner_ordinal']!=owner:continue
            for renewal in d['snapshot']['renewals']:
                if renewal['expected'] is not None:raise AssertionError('Actual null renewal snapshot required')
                renewal['expected']=copy.deepcopy(scope);changed+=1
        if not changed:raise AssertionError('Actual ACK renewal snapshots required')
    elif operation=='ack_entry_drop':
        record=next(r for r,d in select(e,'Bosh','Ack') if d['returned'] is None);e['facts'].remove(record)
    elif operation=='ack_false':select(e,'Bosh','Ack')[-1][1]['returned']=False
    elif operation=='native_orphan':
        record=copy.deepcopy(select(e,'Native','Write')[0][0]);record['fact']['data']['data']['item_ordinal']=4;e['facts'].append(record)
    elif operation=='driver_orphan':e['facts'].append({'seq':0,'fact':{'kind':'Driver','data':{'owner':'Worker','owner_ordinal':0,'result':'Ready'}}})
    elif operation=='foreground_frame':
        d=select(e,'Foreground','Snapshot')[-1][1];d['frame']=select(e,'Credential')[0][1]['snapshot']['frame']
    elif operation=='initial_row_fresh':
        projection=select(e,'Foreground','ProjectionRow')[0][1];e['facts'].append({'seq':0,'fact':{'kind':'Foreground','data':{'kind':'InitialRow','data':{'input_row_ordinal':0,'row_slot':0,'actual_row':copy.deepcopy(projection['actual_row'])}}}})
    elif operation=='cache_undeclared':
        d=next(d for _,d in select(e,'Bosh','Cache') if d['entries']);new=copy.deepcopy(d['entries'][0]);new['rid']+=10000;d['entries'].append(new)
    elif operation=='lookup_unbound':
        unbound=next(d['snapshot']['frame'] for _,d in select(e,'Credential') if d['snapshot']['kind']=='UnboundFast')
        d=next(d for _,d in select(e,'Worker','Lookup') if d['owner']['kind']=='Auth');d['owner']['data']['id']=unbound
    elif operation=='candidate_orphan':select(e,'Worker','Candidate')[0][1]['full_jid']='absent@example.test/r'
    elif operation=='callback_key':select(e,'Control','Callback')[0][1]['rid']+=10000
    elif operation=='muc_orphan_recipients':
        f=select(e,'Muc','Snapshot')[0][1]['frame'];e['facts'].append({'seq':0,'fact':{'kind':'Muc','data':{'kind':'Recipients','data':{'frame':f,'recipients':[]}}}})
    elif operation=='nested_response_rid':
        d=next(d for _,d in reversed(select(e,'Bosh','Snapshot')) if d['snapshot']['responses']);d['snapshot']['responses'][0]['rid']+=10000
    elif operation=='nested_transfer':
        transfer=next(d['snapshot']['transfers'][0] for _,d in reversed(select(e,'Bosh','Snapshot')) if d['snapshot']['transfers'])
        d=next(d for _,d in select(e,'Bosh','Snapshot') if d['association']['kind']=='Request');d['snapshot']['transfers']=[copy.deepcopy(transfer)]
    elif operation=='nested_renewal':
        renewal=next(d['snapshot']['renewals'][0] for _,d in reversed(select(e,'Bosh','Snapshot')) if d['snapshot']['renewals'])
        d=next(d for _,d in select(e,'Bosh','Snapshot') if d['association']['kind']=='Request' and d['association']['data']['ack'] is None);d['snapshot']['renewals']=[copy.deepcopy(renewal)]
    elif operation=='auth_admission':
        d=select(e,'Frame')[0][1];correlation={'operation_id':d['frame'],'effect':1,'generation':1,'attempt':1}
        d['admission_begin']={'correlation':correlation,'started':False,'knowledge':{'kind':'NoCommitRequested','data':{}},'returned':None}
    elif operation=='settlement_result':select(e,'Worker','Settlement')[-1][1]['returned']['data']['data']['value']=False
    elif operation=='settlement_command':select(e,'Worker','Settlement')[-1][1]['command']['data']['delay_seconds']=31
    elif operation=='selection_extra_cut':
        record=copy.deepcopy(select(e,'Bosh','Selection')[0][0]);record['fact']['data']['data']['cut']='AfterTeardown';e['facts'].append(record)
    elif operation=='fifo_resurrect':
        original=next(d for _,d in select(e,'Bosh','Queue') if len(d['fifo'])==4)
        d=next(d for _,d in select(e,'Bosh','Queue',cut='AfterFinish') if d['session']==original['session'] and len(d['fifo'])==2)
        d['fifo'].append(copy.deepcopy(original['fifo'][0]));d['output_bytes']=sum(len(x['stanza'].encode()) for x in d['fifo'])
    elif operation=='socket_boundary_lease':
        d=next(d for _,d in select(e,'Worker','Handoff') if d['received']['kind']=='Received' and d['received']['data']['kind']=='SocketFenced')
        native=next(x for _,x in reversed(select(e,'Native','Snapshot')) if x['item_ordinal']==d['item_ordinal'] and x['snapshot'] is not None and x['snapshot']['returned_fence'] is not None)
        d['received']['data']['data']['id']=native['snapshot']['returned_fence']['data']['lease_token']
    elif operation=='bosh_boundary_lease':
        d=next(d for _,d in select(e,'Worker','Handoff') if d['received']['kind']=='Received' and d['received']['data']['kind']=='BoshPersisted')
        source=next(x['snapshot']['transfers'][0]['returned_source'] for _,x in reversed(select(e,'Bosh','Snapshot')) if x['snapshot']['transfers'] and x['snapshot']['transfers'][0]['returned_source'] is not None)
        d['received']['data']['data']['id']=source['lease_token']
    elif operation=='native_fence_token':
        d=next(d for _,d in reversed(select(e,'Native','Snapshot')) if d['snapshot'] is not None and d['snapshot']['returned_fence'] is not None)
        d['snapshot']['returned_fence']['data']['lease_token']=d['connection']
    elif operation=='native_ack_nondurable':
        d=next(d for _,d in select(e,'Native','Dequeue') if d['item']['source'] is None)
        source={'kind':'Mix','data':{'delivery_id':d['item']['connection_id'],'lease_token':d['item']['connection_id']}}
        for result in (None,True):e['facts'].append({'seq':0,'fact':{'kind':'Native','data':{'kind':'Ack','data':{'item_ordinal':d['item']['item_ordinal'],'source':copy.deepcopy(source),'returned':result}}}})
    elif operation=='bind_nosource_knowledge':
        d=next(d for _,d in reversed(select(e,'Bosh','Snapshot')) if d['snapshot']['responses'])
        d['snapshot']['responses'][0]['attempts'][0]['knowledge']={'kind':'ReceiptKnown','data':copy.deepcopy(reader.EMPTY_MEMBERSHIP)}
    elif operation=='bind_empty_ack_return':
        d=next(d for _,d in reversed(select(e,'Bosh','Snapshot')) if d['snapshot']['acknowledgements'] and d['snapshot']['responses'])
        d['snapshot']['responses'][0]['attempts'][0]['return_matches']=False
    elif operation=='bind_lineage_prefix':
        d=next(d for _,d in select(e,'Bosh','Snapshot') if any(len(r['lineage'])==4 and r['exposure_entered'] for r in d['snapshot']['responses']))
        response=next(r for r in d['snapshot']['responses'] if len(r['lineage'])==4);response['lineage']=response['lineage'][:2];response['removed']=response['removed'][:2]
    elif operation=='callback_duplicate_return':
        record=copy.deepcopy(next(r for r,d in select(e,'Control','Callback') if d['returned'] is not None));record['fact']['data']['data']['returned']=not record['fact']['data']['data']['returned'];e['facts'].append(record)
    elif operation in ('callback_return_drop','callback_entry_drop'):
        e['facts']=[r for r in e['facts'] if not(r['fact']['kind']=='Control' and r['fact']['data']['kind']=='Callback' and ((r['fact']['data']['data']['returned'] is None)==(operation=='callback_entry_drop')))]
    elif operation=='callback_cancel_return':
        record=copy.deepcopy(select(e,'Control','Callback')[0][0]);record['fact']['data']['data']['returned']=True;e['facts'].append(record)
    elif operation in ('driver_all_drop','driver_worker_drop','driver_publication_drop'):
        role={'driver_all_drop':None,'driver_worker_drop':'Worker','driver_publication_drop':'Publication'}[operation]
        e['facts']=[r for r in e['facts'] if not(r['fact']['kind']=='Driver' and (role is None or r['fact']['data']['owner']==role))]
    else:raise AssertionError('Unknown closed mutation: '+operation)
    return raw,frame(repair_copy(raw,e))


class ActualPositiveCopyControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configured=os.environ.get('STAGE4_AUTHENTICATED_V2_READER_INPUTS')
        if not configured:raise AssertionError('Actual complete source-bound positive envelopes are required; synthetic envelopes cannot substitute')
        cls.root=Path(configured)

    def pair(self,occurrence,side):
        # The caller establishes provenance before exposing these files. File
        # paths, JSON booleans and this method are never authentication.
        directory=self.root/occurrence/side
        return (directory.joinpath('input.json').read_bytes(),directory.joinpath('evidence.frame').read_bytes())

    def check_actual(self,occurrence,pair):
        role='auth-cache-bypass-mutant' if occurrence.startswith('M') else 'baseline'
        got=reader.evaluate_fixture_semantics(occurrence,*pair,artifact_role=role,wire_version='V2')
        expected='InvariantViolation' if occurrence.startswith('M') else reader.FIXTURES[occurrence][2]
        self.assertEqual(got.category,expected)
        if occurrence.startswith('M'):self.assertEqual(got.findings,(reader.TARGET,))


def authored_control(name,occurrence,operation,expected,finding):
    def test(self):
        before=self.pair(occurrence,'before')
        self.check_actual(occurrence,before)
        if operation.startswith('binary_'):
            value=reader.parse_case_input(before[0]);identity=value['composition']['data']['mix']['foreground']['ingress']['identity']
            replacement={'binary_roundtrip':'00ff80','binary_odd':'0','binary_upper':'FF','binary_malformed':'zz','binary_overbound':'00'*4097}[operation]
            identity['canonical_semantics']=replacement
            if expected=='InputShapeRoundtrip':
                actual=reader._shape(value,['ref','Case']);self.assertEqual(bytes.fromhex(actual['composition']['data']['mix']['foreground']['ingress']['identity']['canonical_semantics']),b'\0\xff\x80')
            else:
                with self.assertRaises(reader.Stage4Invalid):reader._shape(value,['ref','Case'])
        else:
            raw,negative=mutate(before[0],reader.parse_frame(before[1],wire_version='V2'),operation)
            got=reader.inspect_semantics(raw,negative,wire_version='V2');self.assertEqual(got.category,expected)
            if finding is not None:self.assertEqual(got.findings,(finding,))
            if expected!='InvariantViolation' or finding!=reader.TARGET:self.assertNotEqual(got.findings,(reader.TARGET,))
        # This is a fresh read AFTER evaluating the exact negative copy.
        after=self.pair(occurrence,'after')
        self.check_actual(occurrence,after)
        # Positive copies have to be the same actual literal and complete DTO,
        # authenticated separately by the supervisor at the two evaluation cuts.
        self.assertEqual(before,after)
    test.__name__='test_'+name
    return test


for _name,_occurrence,_operation,_expected,_finding in CONTROLS:
    setattr(ActualPositiveCopyControls,'test_'+_name,authored_control(_name,_occurrence,_operation,_expected,_finding))


RELATION_PREREQUISITES = {
    'test_actual_s14_duplicate_rejects_without_owner_facts': ('S14',),
    'test_actual_s15_positional_rejects_without_owner_facts': ('S15',),
    'test_actual_s16_relationship_rejects_without_owner_facts': ('S16',),
    'test_replay_requires_identical_complete_canonical_dto': ('S13',),
    'test_four_role_relation_has_exact_reduced_baseline': ('M1','M2','S13','M3'),
    'test_four_role_rejects_missing_reduced_baseline': ('M1','M2','S13','M3'),
    'test_four_role_rejects_reduced_literal_change': ('M1','M2','S13','M3'),
    'test_global_opaque_renaming_preserves_semantic_graph': ('M2',),
}


class ActualRelationControls(unittest.TestCase):
    setUpClass=classmethod(ActualPositiveCopyControls.setUpClass.__func__)
    pair=ActualPositiveCopyControls.pair
    check_actual=ActualPositiveCopyControls.check_actual

    def setUp(self):
        required=RELATION_PREREQUISITES[self._testMethodName]
        self.pristine={name:self.pair(name,'before') for name in required}
        for name,pair in self.pristine.items():self.check_actual(name,pair)

    def tearDown(self):
        for name,pair in self.pristine.items():
            after=self.pair(name,'after');self.check_actual(name,after);self.assertEqual(pair,after)

    def test_actual_s14_duplicate_rejects_without_owner_facts(self):
        self.check_actual('S14',self.pristine['S14'])

    def test_actual_s15_positional_rejects_without_owner_facts(self):
        self.check_actual('S15',self.pristine['S15'])

    def test_actual_s16_relationship_rejects_without_owner_facts(self):
        self.check_actual('S16',self.pristine['S16'])

    def four(self):
        return tuple(self.pristine[name] for name in ('M1','M2','S13','M3'))

    def test_four_role_relation_has_exact_reduced_baseline(self):
        self.assertEqual(reader.shrink_semantics(*self.four(),wire_version='V2').category,'Related')

    def test_four_role_rejects_missing_reduced_baseline(self):
        a,b,_,d=self.four();self.assertEqual(reader.shrink_semantics(a,b,b,d,wire_version='V2').category,'Inconclusive')

    def test_four_role_rejects_reduced_literal_change(self):
        a,b,c,d=self.four();changed=(d[0]+b' ',d[1])
        self.assertNotEqual(reader.shrink_semantics(a,b,c,changed,wire_version='V2').category,'Related')

    def test_replay_requires_identical_complete_canonical_dto(self):
        a=self.pair('S13','before');b=self.pair('S13','after')
        self.assertEqual(reader.compare_replay_semantics(*a,*b,wire_version='V2').category,'Equivalent')

    def test_global_opaque_renaming_preserves_semantic_graph(self):
        raw,framed=self.pair('M2','before');e=reader.parse_frame(framed,wire_version='V2')
        # Raw generated identity values are intentionally unavailable. Reassign
        # all wire labels by a bijection and re-canonicalize first occurrence.
        def swap(v):
            if type(v) is dict:
                if v.get('kind')=='Opaque' and set(v.get('data',{}))=={'ordinal'}:v['data']['ordinal']=17-v['data']['ordinal']
                else:
                    for x in v.values():swap(x)
            elif type(v) is list:
                for x in v:swap(x)
        swap(e['facts']);fixed=frame(repair_copy(raw,e))
        self.assertEqual(reader.inspect_semantics(raw,fixed,wire_version='V2'),reader.inspect_semantics(raw,framed,wire_version='V2'))




class ActualV2TransportSemanticControls(unittest.TestCase):
    """Additional controls requiring authenticated fresh V2, never a transcode."""
    setUpClass=classmethod(ActualPositiveCopyControls.setUpClass.__func__)
    pair=ActualPositiveCopyControls.pair
    check_actual=ActualPositiveCopyControls.check_actual

    def setUp(self):
        names=tuple(reader.FIXTURES) if self._testMethodName=='test_all16_actual_v2_roundtrip_and_raw_provenance' else ('S06',) if self._testMethodName=='test_actual_s06_expansion_does_not_hit_v1_frame_cap' else ('S13',)
        self.pristine={name:self.pair(name,'before') for name in names}
        for name,pair in self.pristine.items():self.check_actual(name,pair)

    def tearDown(self):
        for name,pair in self.pristine.items():
            after=self.pair(name,'after');self.check_actual(name,after);self.assertEqual(pair,after)

    def test_same_typed_unequal_slots_reach_original_owner_predicate(self):
        raw,actual=self.pristine['S13'];e=reader.parse_frame(actual,wire_version='V2')
        s=select(e,'Credential')[-1][1]['snapshot']
        self.assertNotEqual(s['frame'],s['connection'])
        s['frame'],s['connection']=s['connection'],s['frame']
        negative=frame(repair_copy(raw,e))
        reader.parse_frame(negative,wire_version='V2')  # commitments must validate
        got=reader.inspect_semantics(raw,negative,wire_version='V2')
        self.assertEqual((got.category,got.findings),('InvariantViolation',('CredentialSnapshotOwnerReassignment',)))

    def test_valid_identity_reference_reassignment_is_semantic(self):
        raw,actual=self.pristine['S13'];e=reader.parse_frame(actual,wire_version='V2')
        s=select(e,'Credential')[-1][1]['snapshot']
        s['frame']=alternate(s['frame'],e)
        negative=frame(repair_copy(raw,e))
        reader.parse_frame(negative,wire_version='V2')
        got=reader.inspect_semantics(raw,negative,wire_version='V2')
        self.assertEqual((got.category,got.findings),('InvariantViolation',('CredentialSnapshotOwnerReassignment',)))

    def test_equal_slot_swap_does_not_invent_a_violation(self):
        raw,actual=self.pristine['S13'];e=reader.parse_frame(actual,wire_version='V2')
        s=select(e,'Credential',cut='Introduction')[0][1]['snapshot']
        self.assertEqual(s['begin'],s['commit'])
        s['begin'],s['commit']=s['commit'],s['begin']
        self.assertEqual(frame(e),actual)
        self.assertEqual(reader.inspect_semantics(raw,frame(e),wire_version='V2'),reader.inspect_semantics(raw,actual,wire_version='V2'))

    def test_actual_s06_expansion_does_not_hit_v1_frame_cap(self):
        raw,actual=self.pristine['S06'];e=reader.parse_frame(actual,wire_version='V2')
        expanded_size,_=codec._commit(e,codec._Budget())
        self.assertGreater(expanded_size,reader.MAX_FRAME)
        self.assertLessEqual(len(actual),reader.MAX_FRAME)
        self.assertEqual(reader.inspect_semantics(raw,actual,wire_version='V2').category,'Pass')

    def test_all16_actual_v2_roundtrip_and_raw_provenance(self):
        for name,(raw,actual) in self.pristine.items():
            with self.subTest(occurrence=name):
                self.assertTrue(actual.startswith(codec.FRAME_TAG))
                e=reader.parse_frame(actual,wire_version='V2')
                self.assertEqual(frame(e),actual)
                result=reader.inspect_semantics(raw,actual,wire_version='V2')
                self.assertEqual(result.evidence_sha256,reader._hash(actual))


if __name__=='__main__':unittest.main()
