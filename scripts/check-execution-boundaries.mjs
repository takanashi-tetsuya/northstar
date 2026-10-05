import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const files = {
  frame: 'src/xmpp/frame_execution.rs',
  protocol: 'src/xmpp/protocol.rs',
  transport: 'src/xmpp/mod.rs',
  tcp: 'src/xmpp/tcp_action.rs',
  websocket: 'src/xmpp/websocket_action.rs',
  bosh: 'src/bosh.rs',
  boshAction: 'src/bosh/action.rs',
  outbound: 'src/outbound.rs',
  muc: 'src/xmpp/protocol/muc.rs',
  mucFanout: 'src/services/muc/fanout.rs',
  mucCore: 'crates/northstar-room-application/src/discussion.rs',
  mucApplication: 'crates/northstar-room-application/src/lib.rs',
  mucService: 'src/services/muc.rs',
  mucSlot: 'src/services/muc/discussion.rs',
  mucDb: 'src/db/muc.rs',
  mucRepository: 'src/db/room.rs',
  mix: 'src/xmpp/protocol/mix.rs',
  mixService: 'src/services/mix.rs',
  nativeWrite: 'src/xmpp/direct_delivery.rs',
  nativeCore: 'crates/northstar-delivery-core/src/native_write.rs',
  replayDb: 'src/db/replay.rs',
  mixDb: 'src/db/mix.rs',
  smProtocol: 'src/xmpp/protocol/sm.rs',
  smOwner: 'src/xmpp/protocol/sm_owner.rs',
  smCore: 'crates/northstar-delivery-core/src/sm_ownership.rs',
  smPrepared: 'src/services/sm/ownership.rs',
  smDb: 'src/db/sm.rs',
  boshOwner: 'src/bosh/ownership.rs',
  boshCore: 'crates/northstar-delivery-core/src/bosh_ownership.rs',
  mixRepository: 'src/db/mix_repository.rs',
  boshResponse: 'src/bosh/response_owner.rs',
  boshResponseCore: 'crates/northstar-delivery-core/src/bosh_ownership/response.rs',
  replayService: 'src/services/replay.rs',
  replayRepository: 'src/db/replay_repository.rs',
};

function requireBoundary(condition, message) {
  if (!condition) throw new Error(`execution boundary: ${message}`);
}

// Mask comments and Rust literals without moving tokens. This is a bounded
// source-shape gate, not a substitute for executing the continuation tests.
// Nested block comments and raw strings cannot provide fake executable hooks.
function codeOnly(source) {
  const output = source.split('');
  function mask(start, end) {
    for (let index = start; index < end; index++) {
      if (source[index] !== '\n' && source[index] !== '\r') output[index] = ' ';
    }
  }
  for (let index = 0; index < source.length;) {
    const start = index;
    if (source.startsWith('//', index)) {
      const end = source.indexOf('\n', index + 2);
      index = end < 0 ? source.length : end;
    } else if (source.startsWith('/*', index)) {
      let depth = 1;
      index += 2;
      while (index < source.length && depth) {
        if (source.startsWith('/*', index)) { depth++; index += 2; }
        else if (source.startsWith('*/', index)) { depth--; index += 2; }
        else index++;
      }
      requireBoundary(depth === 0, 'unterminated source comment');
    } else {
      const raw = /^(?:br|rb|r)(#+)?"/.exec(source.slice(index));
      if (raw) {
        const terminator = `"${raw[1] ?? ''}`;
        const end = source.indexOf(terminator, index + raw[0].length);
        requireBoundary(end >= 0, 'unterminated raw source literal');
        index = end + terminator.length;
      } else if (source[index] === '"') {
        index++;
        while (index < source.length) {
          if (source[index] === '\\') index += 2;
          else if (source[index++] === '"') break;
        }
      } else if (source[index] === "'") {
        const character = /^'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|.)|[^'\\])'/u.exec(source.slice(index));
        if (!character) { index++; continue; } // Rust lifetime, not a literal.
        index += character[0].length;
      } else { index++; continue; }
    }
    mask(start, index);
  }
  return output.join('');
}

function body(source, declaration) {
  const code = codeOnly(source);
  const pattern = new RegExp(declaration, 'g');
  const matches = [...code.matchAll(pattern)];
  requireBoundary(matches.length === 1, `expected one production body: ${declaration}`);
  const opening = code.indexOf('{', matches[0].index + matches[0][0].length);
  requireBoundary(opening >= 0, `missing body: ${declaration}`);
  let depth = 1;
  for (let index = opening + 1; index < code.length; index++) {
    if (code[index] === '{') depth++;
    else if (code[index] === '}' && --depth === 0) return code.slice(opening + 1, index);
  }
  throw new Error(`execution boundary: unterminated body: ${declaration}`);
}

function productionModule(source) {
  const markers = [...codeOnly(source).matchAll(/\n#\[cfg\(test\)\]\s*\nmod\s+tests\b/g)];
  requireBoundary(markers.length <= 1, 'expected at most one test-module boundary');
  return markers.length ? source.slice(0, markers[0].index) : source;
}

function compact(source) { return source.replace(/\s+/g, ''); }
function count(source, text) { return source.split(text).length - 1; }
function ordered(source, steps, message) {
  let previous = -1;
  for (const step of steps) {
    const index = source.indexOf(step, previous + 1);
    requireBoundary(index >= 0, message);
    previous = index;
  }
}

export function readExecutionSources() {
  return Object.fromEntries(Object.entries(files).map(([name, file]) => [name,
    fs.readFileSync(path.join(root, file), 'utf8')]));
}

// Drift detection for the existing native/compatibility MIX service boundary.
// This checks source wiring, not transaction success or exact-token SQL behavior.
export function verifyNativeAckService(source) {
  const normalize = value => compact(value).replace(/,\)/g, ')');
  const legacy = normalize(body(source, 'pub\\s*\\(crate\\)\\s+async\\s+fn\\s+acknowledge_mix_delivery\\b'));
  requireBoundary(legacy === 'self.acknowledge_mix_delivery_inner(delivery_id,lease_token,None).await',
    'legacy MIX acknowledgement must forward the exact delivery/token without an observation');
  const observed = normalize(body(source, 'pub\\s*\\(crate\\)\\s+async\\s+fn\\s+acknowledge_mix_socket_write\\b'));
  requireBoundary(observed === 'letcrate::outbound::TransportOwnershipSource::Mix(source)=request.source()else{anyhow::bail!();};self.acknowledge_mix_delivery_inner(source.delivery_id,source.lease_token,Some(request)).await',
    'native MIX acknowledgement must extract its exact source and forward the same request');
  const shared = normalize(body(source, 'async\\s+fn\\s+acknowledge_mix_delivery_inner\\b'));
  requireBoundary(shared === 'let_admission=self.outbox_db_admission_guard().await;letresult=self.repository.acknowledge_mix_delivery(delivery_id,lease_token,observation).await?;ifresult{self.publish_delivery_local_commit();}Ok(result)',
    'shared MIX acknowledgement must own one permit, exact repository turn and true-only wake');
}

export function verifyNativeWriteBoundaries({ transport, nativeWrite, nativeCore, replayDb, mixDb }) {
  const normalize = value => compact(value).replace(/,\)/g, ')');
  for (const name of ['tcp_record_and_send_item', 'websocket_record_and_send_item']) {
    const callback = normalize(body(transport, `async\\s+fn\\s+${name}\\b`));
    requireBoundary(callback.startsWith('letobservation=northstar_delivery_core::native_write::Observation::new(item.durable_source);direct_delivery::NativeWriteRunner::new(observation.clone(),asyncmove{') && callback.endsWith('}).await'),
      `${name} must create its receiving owner before polling the borrowed item child`);
    ordered(callback, ['DirectWriteLease::prepare(session,item,&observation).await', 'lease.write(', 'written.settle(session).await'],
      `${name} must prepare, fully write and then settle the same item`);
    requireBoundary(count(callback, 'lease.write(') === 1 && count(callback, 'written.settle(session).await') === 1,
      `${name} must consume its write and settlement continuations once`);
  }
  const tcpItem = normalize(body(transport, 'async\\s+fn\\s+tcp_record_and_send_item\\b'));
  requireBoundary(tcpItem.includes('letwritten=lease.write(|stanza|send(io,stanza)).await?;written.settle(session).await;'),
    'native TCP must supply the bound stanza to the real send future and propagate write failure');
  const wsItem = normalize(body(transport, 'async\\s+fn\\s+websocket_record_and_send_item\\b'));
  requireBoundary(wsItem.includes('lease.write(|stanza|asyncmove{anyhow::ensure!(websocket_send_live(socket,Message::Text(stanza.to_owned().into()),cancellation).await);Ok(())}).await{Ok(written)=>written,Err(_)=>returnfalse,};written.settle(session).await;'),
    'native WebSocket must require its actual bound-stanza write before settlement');
  const wsSend = normalize(body(transport, 'async\\s+fn\\s+websocket_send_live\\b'));
  requireBoundary(wsSend === 'bounded_websocket_live_write(socket.send(message),cancellation).await',
    'WebSocket live writes must use the shared bounded selection');
  const wsBounded = normalize(body(transport, 'async\\s+fn\\s+bounded_websocket_live_write\\b'));
  requireBoundary(wsBounded === 'tokio::select!{biased;_=cancellation.actor_shutdown.cancelled()=>false,_=cancellation.signals.revoked()=>false,_=cancellation.signals.backpressured()=>false,result=tokio::time::timeout(XMPP_WRITE_TIMEOUT,write)=>{matches!(result,Ok(Ok(())))}}',
    'WebSocket live selection must preserve cancellation priority and the existing timeout');
  const write = normalize(body(nativeWrite, 'pub\\s*\\(super\\)\\s+async\\s+fn\\s+write\\b'));
  ordered(write, ['self.observation.begin_write()?;', 'letactual=writer(&self.item.stanza).await;', 'lettruth=ifactual.is_ok(){WriterResult::FullWrite}else{WriterResult::Failed};', 'letwritten=self.observation.writer_completed(truth)?;', 'actual?;', 'Ok(WrittenDirectLease{item:self.item,written,managed_by_sm:self.managed_by_sm,})'],
    'native lease must retain actual writer truth before issuing the consuming written continuation');
  const settle = normalize(body(nativeWrite, 'async\\s+fn\\s+settle_with\\b'));
  ordered(settle, ['self.item.confirm_transport_write();', 'if!self.managed_by_sm{self.item.confirm_transport_ownership();}', 'self.written.begin_ack()', 'request.source()'],
    'native settlement must preserve full-write notification and require the consuming ACK request');
  for (const kind of ['c2s', 'mix']) {
    requireBoundary(settle.includes(`letresult=port.acknowledge_${kind}(&request).await;request.returned(result.is_ok());`),
      `native ${kind} settlement must pass the exact request and retain the actual call result`);
  }
  const runnerDrop = normalize(body(nativeWrite, 'impl<F>\\s+Drop\\s+for\\s+NativeWriteRunner<F>'));
  requireBoundary(runnerDrop === 'fndrop(&mutself){drop(self.child.take());ifself.poll_in_progress{self.observation.finish(Terminal::Panicked);}}',
    'native owner must destroy its child before retirement and retain a caught panic');
  const runner = body(nativeWrite, 'impl<F:\\s*Future>\\s+Future\\s+for\\s+NativeWriteRunner<F>');
  const poll = normalize(body(runner, 'fn\\s+poll\\b'));
  ordered(poll, ['this.poll_in_progress=true;', '.poll(cx)', 'drop(this.child.take());this.poll_in_progress=false;this.observation.finish(Terminal::Returned);'],
    'native poll must mark a panic boundary and destroy its ready child before retirement');
  requireBoundary(poll.includes('Poll::Pending=>{this.poll_in_progress=false;returnPoll::Pending;}') && count(poll, 'this.poll_in_progress=false;') === 2 && count(poll, '.finish(') === 1,
    'native pending and ready polls must preserve their distinct retirement facts');
  const commit = normalize(body(nativeCore, 'pub\\s+async\\s+fn\\s+commit_observed\\b'));
  requireBoundary(commit === 'letpermit=request.enter_commit(disposition).map_err(CommitError::Binding)?;commit.await.map_err(CommitError::Repository)?;permit.received();Ok(())',
    'native ACK must bind preparation before COMMIT and retain its receipt before returning');
  const c2s = normalize(body(replayDb, 'async\\s+fn\\s+acknowledge_durable_deliveries_observed\\b'));
  requireBoundary(c2s.includes('ifpresent[0]{AckDisposition::Deleted}else{AckDisposition::AbsentUnclaimed}') && c2s.includes('anyhow::ensure!(removed==1);'),
    'C2S ACK receipt must distinguish checked deletion from accepted absent-unclaimed');
  requireBoundary(count(c2s, 'commit_observed(') === 1 && c2s.includes('commit_observed(transaction.commit(),observation,disposition).await?;'),
    'actual C2S ACK transaction must use the native COMMIT observer');
  const mix = normalize(body(mixDb, 'async\\s+fn\\s+acknowledge_mix_delivery_observed\\b'));
  requireBoundary(count(mix, 'commit_observed(') === 1 && mix.includes('commit_observed(transaction.commit(),observation,ifremoved{AckDisposition::Deleted}else{AckDisposition::NoMatchingMix}).await?;'),
    'actual MIX ACK transaction must retain the deleted versus no-match COMMIT receipt');
}

// These are source-wiring checks for the production SM helper. The exact
// continuation tests establish behavior; this gate only detects selected
// bypasses and ordering drift and makes no SQL or memory-bound claim.
export function verifySmOwnershipBoundaries({ protocol, smProtocol, smOwner, smCore, smPrepared, smDb }) {
  const normalize = value => compact(value).replace(/,\)/g, ')');
  for (const [source, name, purpose, call] of [
    [protocol, 'record_outbound_item', 'Record', 'turn.record_item(item,&observation).await'],
    [protocol, 'record_outbound_with_source', 'Record', 'turn.record_source(stanza,durable_source,&observation).await'],
    [protocol, 'checkpoint_sm', 'Checkpoint', 'turn.checkpoint_in_turn(&observation).await'],
    [smProtocol, 'acknowledge', 'Acknowledge{h}', 'turn.acknowledge(h,&observation).await'],
  ]) {
    const entry = normalize(body(source, `async\\s+fn\\s+${name}\\b`));
    ordered(entry, ['letmutturn=self.sm_transport_turn();',
      `letobservation=turn.start(northstar_delivery_core::sm_ownership::Purpose::${purpose});`,
      'SmTurnRunner::new(observation.clone(),asyncmove{', `letresult=${call};`,
      'ifresult.is_err(){observation.returned_error();}', 'result}).await'],
    `SM ${name} must retain one observation outside its actual child`);
    requireBoundary(count(entry, 'turn.start(') === 1 && count(entry, 'SmTurnRunner::new(') === 1,
      `SM ${name} must create one turn owner`);
  }
  const item = normalize(body(smOwner, 'async\\s+fn\\s+record_item\\b'));
  ordered(item, ['item.validate_durable_source_shape()', 'durable_delivery_managed_by_sm(',
    'self.record_source(&item.stanza,item.durable_source,observation).await?;',
    'ifmanaged_by_sm{', 'item.complete_mix_handoff(', 'item.confirm_transport_ownership();', 'observation.notification_attempted();'],
  'SM recording must retain the real item through persistence before ownership notification');
  const record = normalize(body(smOwner, 'async\\s+fn\\s+record_source\\b'));
  ordered(record, ['self.port.recorded();', 'ifself.sm.enabled&&super::is_counted_stanza(stanza){',
    'self.sm.outbound_h=self.sm.outbound_h.wrapping_add(1);',
    'self.sm.unacked.push_back(SmUnackedStanza::with_source(stanza.to_owned(),source));',
    'observation.appended();', 'self.checkpoint_in_turn(observation).await',
    'iferror.downcast_ref::<crate::outbound::DurableDeliverySuperseded>().is_some()&&observation.may_restore_superseded(){',
    'self.sm.unacked.pop_back();', 'self.sm.outbound_h=self.sm.outbound_h.wrapping_sub(1);', 'observation.restored();'],
  'SM recording must append before checkpoint and restore only typed supersession');
  requireBoundary(count(record, 'pop_back(') === 1 && count(record, '.await') === 1,
    'SM recording must retain its one checkpoint await and one typed restoration');
  const restoration = normalize(body(smCore, 'pub\\s+fn\\s+may_restore_superseded\\b'));
  requireBoundary(restoration.endsWith('state.terminal.is_none()&&state.knowledge==Knowledge::NoCommitRequested'),
    'SM typed restoration must respect independent active no-COMMIT knowledge');
  const checkpoint = normalize(body(smOwner, 'async\\s+fn\\s+checkpoint_in_turn\\b'));
  ordered(checkpoint, ['self.port.reserve_snapshot(live_bytes)',
    'self.view.snapshot(self.sm,self.sm.unacked.iter().cloned().collect())',
    'PreparedCheckpoint::bind(observation,id,self.connection_id,&self.sm.unacked,&snapshot,&[],self.checkpoint_policy())?',
    'tokio::time::timeout(std::time::Duration::from_secs(5),self.port.checkpoint(&prepared)).await',
    'prepared.request().validate_checkpoint_return(outcome.updated,&rotations)?;',
    'anyhow::ensure!(outcome.updated);',
    'ProtocolSession::apply_sm_ownership_resolution_to_unacked(&mutself.sm.unacked,&outcome.ownership);',
    'observation.ownership_applied();'],
  'SM checkpoint must bind its snapshot and returned receipt before applying rotations');
  const ack = normalize(body(smOwner, 'async\\s+fn\\s+acknowledge\\b'));
  ordered(ack, ['northstar_xep_0198::acknowledgement_delta(self.sm.acked_h,h,self.sm.unacked.len())',
    'observation.h_decision(Some(delta));',
    'self.sm.unacked.iter().take(delta).cloned().collect::<Vec<_>>()',
    'self.sm.unacked.iter().skip(delta).cloned().collect::<VecDeque<_>>()',
    'self.port.reserve_snapshot(clone_bytes)?;',
    'snapshot.acked_h=h;',
    'PreparedCheckpoint::bind(observation,id,self.connection_id,&self.sm.unacked,&snapshot,&acknowledged,self.checkpoint_policy())?',
    'tokio::time::timeout(std::time::Duration::from_secs(5),self.port.checkpoint(&prepared)).await',
    'prepared.request().validate_checkpoint_return(outcome.updated,&rotations)?;',
    'ProtocolSession::apply_sm_ownership_resolution_to_unacked(&mutremaining,&outcome.ownership);'],
  'SM ACK must preserve actual h arithmetic, clone order and exact persisted cut');
  ordered(ack, ['PreparedBatch::bind(',
    'tokio::time::timeout(std::time::Duration::from_secs(5),self.port.acknowledge_batch(&prepared)).await',
    'prepared.request().validate_batch_return()?;',
    'self.sm.unacked=remaining;self.sm.acked_h=h;observation.ack_applied(h);',
    'self.view.resident_bytes(self.sm)', 'self.port.shrink(capacity,live_bytes)',
    'observation.capacity_completed(result.is_ok());result?;'],
  'SM ACK must preserve separate batch authority and retain local apply before fallible shrink');
  requireBoundary(count(checkpoint, '.await') === 1 && count(ack, '.await') === 2,
    'SM persistence must keep its existing bounded awaits');
  const prepared = body(smPrepared, "impl<'a>\\s+PreparedCheckpoint<'a>");
  const projection = normalize(body(prepared, 'fn\\s+validate_projection\\b'));
  ordered(projection, ['session_id==self.session_id()&&connection_id==self.connection_id()',
    'snapshot==SnapshotProjection::from(self.snapshot)&&acknowledged==self.acknowledged&&policy==self.policy',
    'self.request.validate_binding(self.request.binding())?;'],
  'SM prepared persistence must compare the entire immutable projection');
  for (const [name, entered, completed] of [
    ['commit_observed', 'request.enter_commit(fact)', 'permit.received();'],
    ['rollback_observed', 'request.rollback_entered()', 'permit.completed();'],
  ]) {
    const turn = normalize(body(smCore, `pub\\s+async\\s+fn\\s+${name}\\b`));
    requireBoundary(turn === `letpermit=${entered}.map_err(CompletionError::Binding)?;future.await.map_err(CompletionError::Repository)?;${completed}Ok(())`,
      `SM ${name} must bind before the real future and retain only its successful receipt`);
  }
  const sql = normalize(body(smDb, 'async\\s+fn\\s+checkpoint_sm_session_and_acknowledge_observed\\b'));
  ordered(sql, ['request.validate_binding(binding)?;', 'validate_snapshot(snapshot,max_stanzas,max_bytes)?;',
    'pool.begin().await?', 'update_snapshot(', 'if!updated{',
    'rollback_observed(transaction.rollback(),request).await?;', 'updated:false',
    'replace_queue_inner(', 'CommitFact::Checkpoint{',
    'commit_observed(transaction.commit(),request,fact).await?;', 'updated:true'],
  'SM SQL checkpoint must preserve rollback and COMMIT observations around its actual transaction');
  const batch = normalize(body(smDb, 'async\\s+fn\\s+acknowledge_transport_sources_observed\\b'));
  ordered(batch, ['request.validate_binding(request.binding())?;', 'ifsources.is_empty(){', 'request.no_persistence()?;',
    'pool.begin().await?', 'CommitFact::UnpersistedAck{',
    'commit_observed(transaction.commit(),request,fact).await?;'],
  'SM unpersisted SQL ACK must retain no-call and actual commit authority separately');
  const runnerDrop = normalize(body(smOwner, 'impl<F>\\s+Drop\\s+for\\s+SmTurnRunner<F>'));
  requireBoundary(runnerDrop === 'fndrop(&mutself){drop(self.child.take());ifself.poll_in_progress{self.observation.finish(Terminal::Panicked);}}',
    'SM turn must destroy its child before retiring and retain a caught panic');
  const runner = body(smOwner, 'impl<F:\\s*Future>\\s+Future\\s+for\\s+SmTurnRunner<F>');
  const poll = normalize(body(runner, 'fn\\s+poll\\b'));
  ordered(poll, ['this.poll_in_progress=true;', '.poll(cx)',
    'drop(this.child.take());this.poll_in_progress=false;this.observation.finish(Terminal::Returned);'],
  'SM turn must preserve child-first normal completion and its panic marker');
}

// Pending BOSH transfer only. Response binding, exposure, cache and ACK are
// distinct later owners. This gate detects selected source-wiring drift.
export function verifyBoshTransferBoundaries({ bosh, boshOwner, boshCore, mixService, mixRepository, mixDb }) {
  const normalize = value => compact(value).replace(/,\)/g, ')');
  requireBoundary(normalize(codeOnly(bosh)).includes('constBOSH_BACKEND_OPERATION_TIMEOUT:Duration=Duration::from_secs(5);'),
    'BOSH must retain its existing backend timeout');
  const actor = normalize(body(bosh, 'async\\s+fn\\s+run_loop\\b'));
  requireBoundary(count(actor, 'ownership::OperationRunner::new(') === 4 &&
    count(actor, 'tokio::time::timeout(BOSH_BACKEND_OPERATION_TIMEOUT,') === 4 &&
    count(actor, 'self.begin_ownership_operation(') === 4,
  'BOSH must observe the four existing timed actor operations');
  for (const kind of ['Request', 'Outbound']) {
    const call = kind === 'Request' ? 'self.accept_request(*request,response,&operation)' : 'self.queue_outbound(stanza,&operation)';
    ordered(actor, [`letoperation=self.begin_ownership_operation(northstar_delivery_core::bosh_ownership::OperationKind::${kind});`,
      'ownership::OperationRunner::new(operation.clone(),tokio::time::timeout(BOSH_BACKEND_OPERATION_TIMEOUT,', call],
    `BOSH ${kind} must retain the same outer operation before its child`);
  }
  const wrapper = normalize(body(bosh, 'async\\s+fn\\s+record_and_push_item\\b'));
  requireBoundary(count(wrapper, 'ownership::record_and_push(') === 1 &&
    wrapper.includes('ownership::record_and_push(&mutoutput,item,operation,&mutself.protocol,&transfer).await') &&
    wrapper.includes('Err(ownership::RecordPushError::Record(error))ifsuperseded_bosh_message_id(&error).is_some()=>') &&
    !wrapper.includes('Err(ownership::RecordPushError::Transfer{source,error})if'),
  'BOSH actor must delegate the same item and keep record-only supersession separate from transfer errors');
  const record = normalize(body(boshOwner, 'async\\s+fn\\s+record_and_push\\b'));
  requireBoundary(record.startsWith('letmanaged_by_sm=record.record(&item).await.map_err(RecordPushError::Record)?;'),
    'BOSH must record its actual item before a capacity precheck');
  ordered(record, ['ifmanaged_by_sm{item.durable_source=None;item.mix_handoff=None;}',
    'elseifletSome(source)=item.mix_delivery(){',
    'returntransfer_and_push(output,item,operation,transfer).await.map_err(|error|RecordPushError::Transfer{source,error});',
    'Ok(output.push(item))'],
  'BOSH must clear SM-owned source/handoff only after actual record and preserve its exact transfer/FIFO continuation');
  const transfer = normalize(body(boshOwner, 'async\\s+fn\\s+transfer_and_push\\b'));
  requireBoundary(transfer === 'if!output.can_push(&item){returnOk(false);}letprepared=PreparedTransferItem::new(item,operation)?;letreturned=port.transfer(&prepared.request).await?;prepared.returned(returned)?.push(output)',
    'BOSH transfer must own the original item and consume only its exact returned continuation');
  const transferred = body(boshOwner, 'impl\\s+TransferredItem\\b');
  const push = normalize(body(transferred, 'fn\\s+push\\b'));
  ordered(push, ['letlocal=self.transferred.begin_local()?;', 'letmutitem=self.item;',
    'item.durable_source=Some(TransportOwnershipSource::Mix(local.current()));', 'local.source_applied();',
    'item.complete_mix_handoff(MixTransportCompletion::BoshPersisted{session_id:local.session_id(),});',
    'local.notification_attempted();', 'letaccepted=output.push(item);', 'local.queue_returned(accepted);'],
  'BOSH must retain exact source mutation, notification attempt and actual FIFO result independently');
  const service = normalize(body(mixService, 'pub\\s*\\(crate\\)\\s+async\\s+fn\\s+transfer_mix_delivery_to_bosh\\b'));
  requireBoundary(service === 'let_admission=self.outbox_db_admission_guard().await;self.repository.transfer_mix_delivery_to_bosh(request).await',
    'BOSH MIX service must retain existing admission and forward the same closed request');
  const repository = normalize(body(mixRepository, 'async\\s+fn\\s+transfer_mix_delivery_to_bosh\\b'));
  requireBoundary(repository === 'db::mix::transfer_mix_delivery_to_bosh(&self.pool,request).await',
    'BOSH MIX repository must forward the same closed request');
  const sql = normalize(body(mixDb, 'pub\\s+async\\s+fn\\s+transfer_mix_delivery_to_bosh\\b'));
  ordered(sql, ['request.validate_for_io()?;', 'letsource=request.source();', 'letsession_id=request.session_id();',
    'letttl_seconds=request.ttl_seconds();', 'ttl_seconds.clamp(1,300)', 'pool.begin().await?',
    'anyhow::ensure!(inserted==1);',
    'northstar_delivery_core::bosh_ownership::transfer_commit_observed(transaction.commit(),request,transferred).await?;',
    'Ok(transferred)'],
  'BOSH SQL transfer must use the closed inputs and retain its actual COMMIT receipt before returning');
  const commit = normalize(body(boshCore, 'pub\\s+async\\s+fn\\s+transfer_commit_observed\\b'));
  requireBoundary(commit === 'letpermit=request.enter_commit(current).map_err(CompletionError::Binding)?;future.await.map_err(CompletionError::Repository)?;permit.received();Ok(())',
    'BOSH COMMIT wrapper must bind the actual preparation and retain only a successful receipt');
  const request = body(boshCore, 'impl\\s+TransferRequest\\b');
  const returned = normalize(body(request, 'pub\\s+fn\\s+returned\\b'));
  ordered(returned, ['self.validate(&mutstate)?;', 'transfer.returned_source=Some(current);',
    'transfer.return_matches_receipt=transfer.knowledge==TransferKnowledge::ReceiptKnown(current);',
    'if!transfer.return_matches_receipt{returnErr(Rejected::Receipt);}', 'Ok(Transferred{request:self,current,})'],
  'BOSH must retain the actual return separately and reject it without matching receipt authority');
  const runnerDrop = normalize(body(boshOwner, 'impl<F>\\s+Drop\\s+for\\s+OperationRunner<F>'));
  requireBoundary(runnerDrop === 'fndrop(&mutself){drop(self.child.take());ifself.poll_in_progress{self.observation.finish(Terminal::Panicked,None);}}',
    'BOSH operation must destroy its child before retirement and retain caught panic');
  const runner = body(boshOwner, 'impl<F:\\s*Future<Output\\s*=\\s*Result<bool,\\s*tokio::time::error::Elapsed>>>\\s+Future\\s+for\\s+OperationRunner<F>');
  const poll = normalize(body(runner, 'fn\\s+poll\\b'));
  ordered(poll, ['this.poll_in_progress=true;', '.poll(cx)', 'drop(this.child.take());',
    'this.poll_in_progress=false;', 'this.observation.finish(ifresult.is_err(){Terminal::TimedOut}else{Terminal::Returned},result.as_ref().ok().copied());'],
  'BOSH operation must retain actual timeout/return and keep_running after child destruction');
}

// Wiring checks for the response seam. The pure owner/helper tests establish
// behavior; these lexical checks keep production on those exact shared paths.
export function verifyBoshResponseBoundaries({ bosh, boshResponse, boshResponseCore, replayService, replayRepository, replayDb }) {
  boshResponse = productionModule(boshResponse);
  boshResponseCore = productionModule(boshResponseCore);
  const normalize = value => compact(value).replace(/,\)/g, ')');
  const finish = normalize(body(bosh, 'async\\s+fn\\s+finish_pending\\b'));
  requireBoundary(finish.includes('cache:cache&&condition.is_none()&&pending.request.pause.is_none(),') &&
    finish.includes('response_owner::prepare(&mutresponse_owner::Fields{output:&mutself.output,output_bytes:&mutself.output_bytes,replay:&mutself.replay,governor:&self.sm_memory_governor,max_response_bytes:self.max_response_bytes,max_output_stanzas:self.max_output_stanzas,content_type:&self.content_type,received_rid,},metadata,condition,operation,&response_owner::ServiceReplay{service:&self.replay_service,}).await'),
  'BOSH response preparation must borrow the actual actor fields and retain its existing cache predicate');
  const ingress = normalize(body(bosh, 'async\\s+fn\\s+accept_request\\b'));
  ordered(ingress, ['if!valid_client_response_ack(', 'response_owner::replay_cached(&mutself.replay,&request,response,&mutself.last_response,operation,', 'matchclassify_rid(self.next_rid,request.rid)'],
    'BOSH must validate client ACK before cached replay and fresh RID classification');
  const pending = normalize(body(bosh, 'async\\s+fn\\s+process_pending\\b'));
  ordered(pending, ['advance_bosh_key_sequence(', 'bosh_request_shape_error(', 'self.renew_and_apply_response_ack(request.ack,operation).await'],
    'BOSH fresh requests must preserve key, shape and renewal/ACK order');
  requireBoundary(normalize(body(bosh, 'async\\s+fn\\s+renew_and_apply_response_ack\\b')) ===
    'response_owner::renew_and_acknowledge(&mutself.replay,ack,operation,&response_owner::ServiceReplay{service:&self.replay_service,}).await',
  'BOSH actor ACK wrapper must delegate the actual cache and same operation to the shared helper');
  requireBoundary(normalize(body(bosh, 'fn\\s+finish_pending_empty\\b')) ===
    'response_owner::finish_empty_control(pending.request.rid,pending.responders,&self.content_type,&mutself.last_response,&mutself.highest_responded,operation);',
  'BOSH actor pause wrapper must use the shared empty-control primitive without extra behavior');
  const replayPort = body(boshResponse, 'impl<R:\\s*ReplayRepository>\\s+ReplayPort\\s+for\\s+ServiceReplay');
  for (const [method, service] of [['bind', 'bind_bosh_response_sources'], ['renew', 'renew_bosh_fences'], ['acknowledge', 'acknowledge_bosh_responses']]) {
    requireBoundary(normalize(body(replayPort, `async\\s+fn\\s+${method}\\b`)) === `self.service.${service}(request).await`,
      'BOSH ReplayPort must pass each exact request into the real service');
  }
  const prepare = normalize(body(boshResponse, 'async\\s+fn\\s+prepare\\b'));
  ordered(prepare, ['.begin_response(', 'loop{', 'fields.body(', 'build.attempt(sources,selected.iter().map(|item|item.durable_source))',
    'letresult=ifrequest.sources().is_empty(){Ok(BoshResponseOwnership::default())}else{port.bind(&request).await};',
    'letbound=request.returned(ownership)', 'letownership=bound.ownership().clone();',
    'letauth_control_selected=selected.iter().any(OutboundItem::is_bosh_auth_control);',
    'Ok(BoundResponse{metadata,response,receipts,ownership,bound,auth_control_selected,})'],
  'BOSH must bind selected sources and consume the actual returned membership before releasing response bytes');
  ordered(prepare, ['ifletSome(message_id)=superseded_bosh_message_id(&error){', 'ifletOk(restoration)=request.supersession(message_id){',
    'restore_response_items_observed(', 'restoration.restored(removed_indices)', 'ifremoved&&superseded_rebuilds<fields.max_output_stanzas{'],
  'BOSH restoration must require independent pre-COMMIT authority and retain actual removal ordinals');
  const bindImpl = body(boshResponseCore, 'impl\\s+BindRequest\\b');
  const supersession = normalize(body(bindImpl, 'fn\\s+supersession\\b'));
  requireBoundary(supersession.includes('self.validate(&mutstate)?;') &&
    supersession.includes('ifattempt.knowledge!=BindKnowledge::NoCommitRequested||attempt.returned.is_some()||attempt.restored{returnErr(Rejected::State);}'),
  'BOSH supersession cannot restore an entered or confirmed bind');
  const returned = normalize(body(bindImpl, 'fn\\s+returned\\b'));
  ordered(returned, ['self.validate(&mutstate)?;', 'BindKnowledge::ReceiptKnown(receipt)=>receipt==&ownership',
    'attempt.returned=Some(ownership.clone());', 'if!attempt.return_matches{returnErr(Rejected::Receipt);}', 'Ok(BoundResponse{request:self,ownership,})'],
  'BOSH actual bind return must remain separate from matching receipt authority');
  const bound = normalize(body(body(boshResponseCore, 'impl\\s+BoundResponse\\b'), 'fn\\s+begin_exposure\\b'));
  ordered(bound, ['self.request.validate(&mutstate)?;', 'if!attempt.return_matches||attempt.restored{returnErr(Rejected::Receipt);}', 'response.exposure_entered=true;'],
    'BOSH payload exposure must consume the checked bound continuation');
  const localFinish = normalize(body(body(boshResponse, 'impl\\s+PublicationReadyResponse\\b'), 'fn\\s+finish\\b'));
  ordered(localFinish, ['letExposedResponse{metadata,response,receipts,ownership,exposure,..}=self.exposed;',
    'exposure.begin_bookkeeping()?;', 'update_response_position(last_response,highest_responded,metadata.rid);',
    'bookkeeping.updated();', 'ifmetadata.cache{', 'replay.push_back(CachedResponse{', 'bookkeeping.cached();'],
  'BOSH cache bookkeeping must consume exposure and record insertion after the actual push');
  for (const field of ['response,', 'durable_ownership:ownership,', 'transport_receipts:receipts,']) {
    requireBoundary(localFinish.includes(field), 'BOSH cache must retain the same bytes, membership and receipt channels');
  }
  const pause = normalize(body(boshResponse, 'fn\\s+finish_empty_control\\b'));
  requireBoundary(pause.includes('operation.observe_empty_control(rid)') && pause.includes('bosh_body_element(None,false,None).finish()') &&
    pause.includes('update_response_position(last_response,highest_responded,rid);control.updated();') &&
    !/await|\.bind\(|\.renew\(|\.acknowledge\(|auth_publication|replay\.push_back/.test(pause),
  'BOSH pause must remain an empty synchronous control without durable binding, auth or cache');
  const replay = normalize(body(boshResponse, 'async\\s+fn\\s+replay_cached\\b'));
  ordered(replay, ['super::replay_response(replay,request)', 'operation.begin_renew(Some((request.rid,ownership)))',
    'port.renew(&renewal).await', 'renewal.returned().and_then(|renewed|renewed.begin_replay())',
    'send_one(reply,responder,||exposure.sending(),|accepted|exposure.sent(accepted));', '*last_response=Instant::now();', 'exposure.updated();'],
  'BOSH cached replay must select/count first and require its exact renewal before payload exposure');
  requireBoundary(replay.includes('operation.observe_terminal_control(request.rid)') && !replay.includes('port.acknowledge('),
    'BOSH replay termination is a terminal control and cached replay cannot apply a fresh ACK');
  const acknowledge = normalize(body(boshResponse, 'async\\s+fn\\s+renew_and_acknowledge\\b'));
  ordered(acknowledge, ['operation.begin_renew(None)?;', 'port.renew(&request).await?;', 'request.returned()?;', 'ifletSome(rid)=ack{',
    'renewed.begin_ack(rid)?;', 'port.acknowledge(&request).await?;', 'letacknowledged=request.returned()?;',
    'cached.rid<=acknowledged.rid()', 'replay.pop_front()', 'acknowledged.evicted();', 'acknowledged.sending_receipt();',
    'letaccepted=receipt.send(()).is_ok();', 'acknowledged.receipt_sent(accepted);'],
  'BOSH fresh ACK must renew first and preserve exact committed return, cache eviction and actual receipt sends');
  for (const [name, sql] of [['bind_bosh_response_sources', 'bind_bosh_transport_response_observed'],
    ['renew_bosh_fences', 'renew_bosh_transport_fences'], ['acknowledge_bosh_responses', 'acknowledge_bosh_transport_responses']]) {
    const service = normalize(body(replayService, `pub\\(crate\\)\\s+async\\s+fn\\s+${name}\\b`));
    requireBoundary(service === `self.repository.${name}(request).await`, 'BOSH service must forward the same closed response request');
    const repository = normalize(body(replayRepository, `async\\s+fn\\s+${name}\\b`));
    requireBoundary(repository.includes(`db::replay::${sql}(&self.pool,request).await`),
      'BOSH repository must forward the same closed response request');
  }
  const bindSql = normalize(body(replayDb, 'async\\s+fn\\s+bind_bosh_transport_response_observed\\b'));
  requireBoundary(bindSql === 'request.validate_for_io()?;bind_bosh_transport_response_inner(pool,request.session_id(),request.rid(),request.sources(),request.ttl_seconds(),Some(request)).await',
    'BOSH bind SQL must use validated closed inputs and retain its request');
  const bindInner = normalize(body(replayDb, 'async\\s+fn\\s+bind_bosh_transport_response_inner\\b'));
  ordered(bindInner, ['letownership=crate::outbound::BoshResponseOwnership{', 'letreceipt=ownership.clone();',
    'response::bind_commit_observed(transaction.commit(),request,receipt).await?;', 'Ok(ownership)'],
  'BOSH bind must prepare its independent membership receipt before actual COMMIT and return');
  const renewSql = normalize(body(replayDb, 'async\\s+fn\\s+renew_bosh_transport_fences\\b'));
  ordered(renewSql, ['request.validate_for_io()?;', 'letsession_id=request.session_id();', 'letexpected_response=request.expected();',
    'letttl_seconds=request.ttl_seconds();', 'pool.begin().await?', 'response::renew_commit_observed(transaction.commit(),request).await?;', 'Ok(())'],
  'BOSH renewal SQL must preserve closed request inputs and actual COMMIT receipt');
  const ackSql = normalize(body(replayDb, 'async\\s+fn\\s+acknowledge_bosh_transport_responses\\b'));
  ordered(ackSql, ['request.validate_for_io()?;', 'letsession_id=request.session_id();', 'letacknowledged_rid=request.rid();',
    'pool.begin().await?', 'deleted_sources.push(', 'letacknowledged=deleted_sources.len();',
    'response::ack_commit_observed(transaction.commit(),request,deleted_sources).await?;', 'Ok(acknowledged)'],
  'BOSH ACK SQL must retain actual deletion facts before COMMIT and return');
  for (const [name, argument] of [['bind', 'receipt'], ['renew', ''], ['ack', 'deleted']]) {
    const commit = normalize(body(boshResponseCore, `async\\s+fn\\s+${name}_commit_observed\\b`));
    requireBoundary(commit === `letpermit=request.enter_commit(${argument}).map_err(CompletionError::Binding)?;future.await.map_err(CompletionError::Repository)?;permit.received();Ok(())`,
      'BOSH response COMMIT wrappers must bind first, await once and record the exact receipt synchronously');
  }
}

export function verifyExecutionBoundaries({ frame, protocol, transport, tcp, websocket, bosh, boshAction, boshResponse, outbound }) {
  boshResponse = productionModule(boshResponse);
  for (const name of ['drive_io', 'websocket_connection']) {
    const ingress = compact(body(transport, `async\\s+fn\\s+${name}\\b`));
    requireBoundary(ingress.includes('session.process_frame(&frame).await') && !ingress.includes('session.handle('),
      `${name} must enter the observed frame runner`);
  }
  const ingress = compact(body(protocol, 'async\\s+fn\\s+process_frame\\b'));
  requireBoundary(ingress === 'letexecution=self.frame_executions.begin(self.transport,frame);letresult=execution.run(self.handle(frame)).await;ifmatches!(&result,Ok(Action::SendManyThenActivate(_)))||matches!(&result,Ok(Action::Resume(payload))ifpayload.activate_route){self.frame_executions.defer_publication(execution);}result',
    'activation actions must retain their originating frame observation under the reviewed live condition');

  const publication = compact(body(protocol, 'async\\s+fn\\s+publish_committed_authentication_and_route\\b'));
  requireBoundary(publication === 'ifletSome(execution)=self.frame_executions.take_publication(){execution.observe_publication(self.publish_committed_authentication_and_route_inner()).await}else{self.publish_committed_authentication_and_route_inner().await.transport_succeeded()}',
    'publication must use the observed typed owner and preserve the direct-test fallback');
  const observer = compact(body(frame, 'async\\s+fn\\s+observe_publication\\b'));
  requireBoundary(observer.includes('Observation::new(self.clone(),') &&
    observer.includes(',None)') && observer.includes('letresult=future.await;') &&
    observer.includes('observation.finish(result.outcome());') && observer.endsWith('result.transport_succeeded()') &&
    count(observer, '.await') === 1 && !/timeout|spawn|select!/.test(observer),
  'publication observation must preserve the typed result without adding a deadline or task');
  const frameCode = compact(codeOnly(frame));
  for (const [name, seconds] of [['FRAME_BUDGET', 5], ['INLINE_AUTH_BUDGET', 8]]) {
    requireBoundary(frameCode.includes(`const${name}:Duration=Duration::from_secs(${seconds});`),
      `${name} reviewed budget changed`);
  }
  // The synchronous constructor owns observation before the child is polled;
  // the inner async wrapper still starts the existing timer on its first poll.
  // Result and destruction checks follow the actual runner, not an unused
  // legacy async body. These remain lexical drift checks, not execution proof.
  const run = compact(body(frame, 'pub\\(super\\)\\s+fn\\s+run\\b'));
  ordered(run, ['letobservation=Observation::new(',
    'letbudget=self.0.policy.budget;', 'FrameRunner{',
    'child:Some(Box::pin(asyncmove{tokio::time::timeout(budget,future).await}))'],
  'frame execution must preserve its transport-specific policy budget and first-poll timer');
  requireBoundary(count(run, '.await') === 1 && count(run, 'tokio::time::timeout(') === 1
    && run.includes('poll_in_progress:false') && !/spawn|select!/.test(run),
  'frame execution must retain one first-poll timer without a new task');
  const runner = body(frame, 'impl<F,\\s*T>\\s+Future\\s+for\\s+FrameRunner<F>');
  const poll = compact(body(runner, 'fn\\s+poll\\b'));
  ordered(poll, ['this.poll_in_progress=true;', '.poll(cx)',
    'Poll::Pending=>{this.poll_in_progress=false;returnPoll::Pending;}',
    'drop(this.child.take());this.poll_in_progress=false;', 'Poll::Ready(matchresult{'],
  'frame runner must retain panic knowledge and destroy the ready child before terminal observation');
  for (const branch of [
    'Ok(Ok(value))=>{this.observation.finish(Outcome::Completed);Ok(value)}',
    'Ok(Err(error))=>{this.observation.finish(Outcome::BackendFailure);Err(FrameFailure::Backend(error))}',
    'Err(_)=>{this.observation.finish(Outcome::TimedOut);Err(FrameFailure::TimedOut)}',
  ]) {
    requireBoundary(poll.includes(branch), 'frame runner must preserve each typed terminal result');
  }
  const runnerDrop = compact(body(frame, 'impl<F>\\s+Drop\\s+for\\s+FrameRunner<F>'));
  requireBoundary(runnerDrop === 'fndrop(&mutself){drop(self.child.take());ifself.poll_in_progress{self.observation.finish(Outcome::Panicked);}}',
    'frame runner drop must destroy the child first and preserve a caught panic');
  const policy = compact(body(frame, 'fn\\s+for_frame\\b'));
  requireBoundary(policy.startsWith('letinline=transport==ClientTransport::WebSocket&&is_inline_auth(frame);') &&
    policy.includes('budget:ifinline{INLINE_AUTH_BUDGET}else{FRAME_BUDGET}'),
  'inline budget must remain restricted to guarded WebSocket inline authentication');
  const resultOutcome = compact(body(frame, 'const\\s+fn\\s+outcome\\b'));
  const outcomes = ['Completed', 'BackendFailure', 'IntegrityRejected', 'CredentialRejected',
    'RouteRejected', 'CompletedWithDeferredNotification'];
  requireBoundary(resultOutcome === `matchself{${outcomes.map(name => `Self::${name}=>Outcome::${name},`).join('')}}`,
    'publication result-to-outcome classification must preserve every reviewed variant');
  const boolResult = compact(body(frame, 'const\\s+fn\\s+transport_succeeded\\b'));
  requireBoundary(boolResult === 'matches!(self,Self::Completed|Self::CompletedWithDeferredNotification)',
    'only authoritative publication success may continue the transport');

  const inner = body(protocol, 'async\\s+fn\\s+publish_committed_authentication_and_route_inner\\b');
  for (const [source, result] of [['BackendFailure\\(error\\)', 'BackendFailure'], ['IntegrityFailure', 'IntegrityRejected']]) {
    const arm = compact(body(inner, `AuthenticationResult::${source}\\s*=>`));
    requireBoundary(arm.includes(`self.sm.resume_allowed=false;returnPublicationResult::${result};`),
      `authentication ${result} must retain its failure classification and resume fence`);
  }
  const credential = compact(body(inner, '_\\s*=>'));
  requireBoundary(credential.includes('self.sm.resume_allowed=false;returnPublicationResult::CredentialRejected;'),
    'credential fence rejection must retain its typed failure and resume fence');
  const innerCode = compact(inner);
  requireBoundary(!/timeout|spawn|select!/.test(innerCode) &&
    innerCode.includes('matchself.state.authentication_service().publish_credential_commit(&receipt).await{'),
  'inner credential publication must not add a deadline, task or cancellation race');
  requireBoundary(innerCode.includes('if!route_is_current||!self.activate_committed_route(){self.sm.resume_allowed=false;returnPublicationResult::RouteRejected;}') &&
    innerCode.includes('letSome(user)=self.authenticated.clone()else{returnPublicationResult::RouteRejected;};'),
  'route fence and missing principal must reject without changing existing resume decisions');
  const notification = compact(body(inner, 'if\\s+let\\s+Err\\(error\\)\\s*=\\s*self\\s*\\.state\\s*\\.notify_remote_user_agent_replacement\\('));
  requireBoundary(notification.includes('returnPublicationResult::CompletedWithDeferredNotification;'),
    'best-effort replacement notification must remain successful but visibly deferred');

  for (const [label, source] of [['tcp', tcp], ['websocket', websocket]]) {
    const apply = body(source, 'async\\s+fn\\s+apply\\b');
    const code = compact(apply);
    requireBoundary(count(code, '.publish_committed_authentication_and_route().await') === 2 &&
      !code.includes('publish_committed_authentication_and_route_inner'),
    `${label} must use exactly its two observed publication continuations`);
    for (const [variant, value, activation] of [
      ['SendManyThenActivate', 'reply', 'index==0'], ['Resume', 'control', 'activate_route'],
    ]) {
      const arm = compact(body(apply, `(?:Ok\\()?Action::${variant}\\([^)]*\\)\\)?\\s*=>`));
      const successGuard = label === 'tcp'
        ? `if!tcp_record_and_send(io,session,&${value},opening).await?{returnOk(TcpActionDisposition::Close);}`
        : `if!websocket_send_live(socket,Message::Text(${value}.into()),send_cancellation).await{returnfalse;}`;
      const publish = `if${activation}&&!session.publish_committed_authentication_and_route().await`;
      const rejection = label === 'tcp' ? '{returnOk(TcpActionDisposition::Close);}' : '{returnfalse;}';
      requireBoundary(arm.includes(successGuard + publish + rejection),
        `${label} ${variant} must publish only after the successful first/control write`);
    }
  }

  const boshIngress = compact(body(bosh, 'async\\s+fn\\s+process_pending\\b'));
  requireBoundary(boshIngress.includes('matchself.protocol.process_frame(payload).await{') &&
    !boshIngress.includes('self.protocol.handle('), 'BOSH must enter the observed frame runner');
  const boshPublication = compact(body(bosh, 'async\\s+fn\\s+finish_pending\\b'));
  const exposure = 'letexposed=matchbound.expose(pending.responders){Ok(exposed)=>exposed,Err(error)=>{tracing::error!(?error,rid,);returnfalse;}};';
  const continuation = 'letready=matchexposed.publish_authentication(||self.protocol.publish_committed_authentication_and_route()).await{Ok(ready)=>ready,Err(_)=>returnfalse,};';
  requireBoundary(boshPublication.includes(exposure + continuation +
    'ready.finish(&mutself.last_response,&mutself.highest_responded,&mutself.replay,).is_ok()'),
  'BOSH must observe publication only after response exposure and before cache bookkeeping');
  requireBoundary(count(boshPublication, 'bound.expose(') === 1 &&
    count(boshPublication, '.publish_committed_authentication_and_route()') === 1 &&
    !boshPublication.includes('publish_committed_authentication_and_route_inner') &&
    !compact(codeOnly(productionModule(bosh))).includes('auth_publication_pending'),
  'BOSH must observe publication only after response exposure and reject publication failure');
  const send = compact(body(boshResponse, 'fn\\s+send_one\\b'));
  const expose = compact(body(body(boshResponse, 'impl\\s+BoundResponse\\b'), 'fn\\s+expose\\b'));
  requireBoundary(send === 'entering();letaccepted=responder.send(response).is_ok();returned(accepted);accepted' &&
    expose.includes('letexposure=self.bound.begin_exposure()?;letmutaccepted=false;') &&
    expose.includes('accepted|=send_one(self.response.clone(),responder,||exposure.sending(),|accepted|exposure.sent(accepted),);') &&
    expose.includes('exposure,accepted,auth_control_selected:self.auth_control_selected,})') &&
    compact(body(body(boshResponse, 'impl\\s+ExposedResponse\\b'), 'fn\\s+any_accepted\\b')) === 'self.accepted',
  'BOSH response exposure must preserve the actual responder acceptance');
  const gate = compact(body(body(boshResponse, 'impl\\s+ExposedResponse\\b'), 'async\\s+fn\\s+publish_authentication\\b'));
  requireBoundary(gate === 'ifself.auth_control_selected{anyhow::ensure!(self.accepted,);anyhow::ensure!(publish().await,);}Ok(PublicationReadyResponse{exposed:self})',
    'BOSH publication gate must consume selected exposure, require actual acceptance and successful lazy publication');
  // Closed lexical inventory for these three concrete owners, not a Rust
  // parser or a proof over alternate syntax, macro expansion or other files.
  const responseCode = codeOnly(boshResponse);
  const commonFields = 'metadata:Metadata,response:BoshHttpResponse,receipts:Vec<mpsc::UnboundedSender<()>>,ownership:Arc<BoshResponseOwnership>,';
  const finishHead = 'pub(super)fnfinish(self,last_response:&mutInstant,highest_responded:&mutu64,replay:&mutVecDeque<CachedResponse>,)->Result<()>{';
  const ownerShapes = [
    ['BoundResponse', commonFields + 'bound:response::BoundResponse,auth_control_selected:bool,',
      ['expose'], ['pub(super)fnexpose(self,responders:Vec<Responder>)->Result<ExposedResponse>{']],
    ['ExposedResponse', commonFields + 'exposure:response::Exposure,accepted:bool,auth_control_selected:bool,',
      ['any_accepted', 'publish_authentication', 'finish'], [
        '#[cfg(test)]pub(super)fnany_accepted(&self)->bool{',
        'pub(super)asyncfnpublish_authentication<F:Future<Output=bool>>(self,publish:implFnOnce()->F,)->Result<PublicationReadyResponse>{',
        '#[cfg(test)]' + finishHead,
      ]],
    ['PublicationReadyResponse', 'exposed:ExposedResponse,', ['finish'], [finishHead]],
  ];
  for (const [name, fields, methods, heads] of ownerShapes) {
    requireBoundary(compact(body(boshResponse, `pub\\(super\\)\\s+struct\\s+${name}\\b`)) === fields,
      `BOSH ${name} must retain its exact private field shape`);
    const declaration = responseCode.match(new RegExp(`((?:#\\[[^\\]]*\\]\\s*)*)pub\\(super\\)\\s+struct\\s+${name}\\b`));
    const manualCopy = new RegExp(`\\bimpl\\b[^{};]*\\b(?:Clone|Copy)\\s+for\\s+(?:\\w+\\s*::\\s*)*${name}\\b`);
    requireBoundary(declaration && !/\bderive\s*\([^)]*\b(?:Clone|Copy)\b/.test(declaration[1]) && !manualCopy.test(responseCode),
      `BOSH ${name} cannot derive or manually implement Clone or Copy`);
    const implementation = body(boshResponse, `impl\\s+${name}\\b`);
    const actualMethods = [...implementation.matchAll(/\bfn\s+(\w+)\b/g)].map(match => match[1]);
    requireBoundary(actualMethods.join(',') === methods.join(','),
      `BOSH ${name} must retain its closed inherent-method inventory`);
    for (const head of heads) {
      requireBoundary(compact(implementation).includes(head),
        `BOSH ${name} must retain its named consuming declaration heads and test-only compatibility methods`);
    }
    requireBoundary(!/\bSelf\s*\{/.test(implementation),
      `BOSH ${name} cannot add Self-brace construction inside its owner implementation`);
    // Four name-plus-brace sites each: the declaration and inherent impl,
    // plus Bound's Debug impl/construction, Exposed's construction/destructure,
    // or Ready's two reviewed construction sites. Extra constructors fail.
    requireBoundary([...responseCode.matchAll(new RegExp(`\\b${name}\\s*\\{`, 'g'))].length === 4,
      `BOSH ${name} cannot add named construction sites outside the reviewed continuations`);
  }
  const plainFinish = compact(body(body(boshResponse, 'impl\\s+ExposedResponse\\b'), 'fn\\s+finish\\b'));
  requireBoundary(plainFinish === 'anyhow::ensure!(!self.auth_control_selected,);PublicationReadyResponse{exposed:self}.finish(last_response,highest_responded,replay)',
    'BOSH plain compatibility finish must reject selected auth before bookkeeping');
  const prepare = compact(body(boshResponse, 'async\\s+fn\\s+prepare\\b'));
  ordered(prepare, ['loop{', 'let(response,sources,receipts,selected)=built',
    'letbound=request.returned(ownership)', 'letauth_control_selected=selected.iter().any(OutboundItem::is_bosh_auth_control);',
    'Ok(BoundResponse{metadata,response,receipts,ownership,bound,auth_control_selected,})'],
    'BOSH auth membership must come from the final bound selection on every rebuild');
  const cached = compact(body(bosh, 'struct\\s+CachedResponse\\b'));
  const replay = compact(body(boshResponse, 'async\\s+fn\\s+replay_cached\\b'));
  requireBoundary(!/auth_control|auth_publication|publish_authentication/.test(cached + replay),
    'BOSH cache and replay cannot recreate auth publication membership or authority');
  const item = compact(body(outbound, 'pub\\s+struct\\s+OutboundItem\\b'));
  requireBoundary(item.includes('bosh_auth_control:bool,') && !/pub(?:\([^)]*\))?bosh_auth_control/.test(item) &&
    compact(body(outbound, 'fn\\s+with_bosh_auth_control\\b')) === 'self.bosh_auth_control=true;self' &&
    compact(body(outbound, 'fn\\s+is_bosh_auth_control\\b')) === 'self.bosh_auth_control',
    'BOSH auth control must remain private item selection metadata with an exact marker accessor');
  const boshApply = body(boshAction, 'async\\s+fn\\s+apply_action\\b');
  requireBoundary(!compact(boshApply).includes('publish_committed_authentication'),
    'BOSH FIFO admission must defer authentication publication until response exposure');
  const boshActivate = compact(body(boshApply, 'Action::SendManyThenActivate\\([^)]*\\)\\s*=>'));
  requireBoundary(boshActivate.includes('ifself.protocol.record_outbound(&reply).await.is_err(){returnfalse;}letitem=crate::outbound::OutboundItem::plain(reply);letitem=ifindex==0{item.with_bosh_auth_control()}else{item};if!self.push_output_item(item){returnfalse;}'),
    'BOSH activation must record then enqueue the exact first control with selection membership');
  const boshResume = compact(body(boshApply, 'Action::Resume\\([^)]*\\)\\s*=>'));
  requireBoundary(boshResume.includes('ifself.protocol.record_outbound(&control).await.is_err(){returnfalse;}') &&
    boshResume.includes('ResumeTransportParts{control,post_control,replay,activate_route,transient_capacity,}') &&
    !boshResume.includes('with_bosh_auth_control'),
    'BOSH resume must retain activation intent for atomic queue admission');
  const resumeQueue = compact(body(bosh, 'fn\\s+queue_bosh_resume_payload\\b'));
  ordered(resumeQueue, ['activate_route,', '.is_none_or(|count|count>max_output_stanzas)',
    '.is_none_or(|bytes|bytes>max_output_bytes){returnfalse;}',
    'letcontrol=ifactivate_route{control.with_bosh_auth_control()}else{control};',
    'output.push_back(control);', 'forstanzainpost_control.into_iter().chain(replay){', '*output_bytes+=batch_bytes;'],
    'BOSH resume must mark only the exact control after complete batch capacity admission');
}

export function verifyMucDiscussionBoundaries({ muc, mucCore, mucApplication, mucService, mucSlot, mucDb, mucRepository, frame, protocol }) {
  const compact = source => source.replace(/\s+/g, '').replace(/,([)}])/g, '$1');
  requireBoundary(!/(?:tokio|sqlx|reqwest)::|std::(?:fs|net|time|env)::|Uuid::new_v4|AppState/.test(codeOnly(productionModule(mucCore))),
    'MUC discussion core must remain free of ambient I/O, clocks and application state');
  const application = body(mucApplication, 'impl<R>\\s+RoomApplication<R>');
  const prepare = compact(body(application, 'fn\\s+prepare_discussion\\b'));
  requireBoundary(prepare === 'discussion::PreparedDiscussion::new(command,self.configured_domain.clone())',
    'MUC preparation must use the receiving application configuration');
  const admit = compact(body(application, 'async\\s+fn\\s+admit_discussion_observed\\b'));
  ordered(admit, ['if!request.valid_for_domain(&self.configured_domain).map_err(AdmissionError::Observation)?{',
    'returnrequest.refuse_invalid_authority().map_err(AdmissionError::Observation);',
    'request.start().map_err(AdmissionError::Observation)?;',
    'self.repository.admit_discussion_observed(request).await',
    'request.returned(outcome).map_err(AdmissionError::Observation)'],
  'MUC observed application must validate receiving domain before repository start and validate return');
  const request = body(mucCore, 'impl\\s+Request\\b');
  const domain = compact(body(request, 'fn\\s+valid_for_domain\\b'));
  requireBoundary(domain.includes('self.observation.0.prepared.0.configured_domain==configured_domain&&self.command().authority_is_consistent(configured_domain)'),
    'MUC prepared input cannot authorize its own configured domain');
  const coreCommit = compact(body(mucCore, 'async\\s+fn\\s+commit_observed\\b'));
  requireBoundary(coreCommit === 'letprepared=request.enter_commit(outcome).map_err(CommitError::Observation)?;commit.await.map_err(CommitError::Commit)?;request.received(prepared).map_err(CommitError::Observation)',
    'MUC COMMIT must record actual entry and successful receipt before return without another await');
  const received = compact(body(request, 'fn\\s+received\\b'));
  ordered(received, ['if!self.observation.same_invocation(&prepared.observation){returnErr(Rejected::Invocation);}',
    'awaiting_return(&state)?;', 'ifstate.knowledge!=Knowledge::CommitCallEntered(prepared.fact){returnErr(Rejected::Knowledge);}',
    'state.knowledge=Knowledge::ReceiptKnown(prepared.fact);'],
  'MUC receipt must match its exact active invocation and prepared COMMIT');
  const returned = compact(body(request, 'fn\\s+returned\\b'));
  requireBoundary(returned.includes('Knowledge::ReceiptKnown(receipt)ifreceipt==proposed=>{}') &&
    returned.includes('state.returned=Some(Returned::Outcome(outcome));returnErr(Rejected::MissingReceipt);') &&
    returned.includes('state.fanout.stage=FanoutStage::Ready;Some(FanoutPermit{observation:self.observation.clone()})'),
  'MUC returned-only success must not mint the observed fanout permit');
  const proposed = compact(body(request, 'fn\\s+proposed\\b'));
  requireBoundary(proposed.includes('MucDiscussionAdmission::Stored(id)ifid==self.command().id=>') &&
    proposed.includes('MucDiscussionAdmission::Replay(_)ifself.command().origin_id.is_some()=>None,'),
  'MUC Stored must match fresh identity and Replay must keep original identity without a fresh class');
  const classes = compact(body(mucCore, 'impl\\s+AcceptanceClass\\b'));
  requireBoundary(classes.includes('(true,true)=>Self::ArchiveAndIdentity,') &&
    classes.includes('(true,false)=>Self::ArchiveOnly,') &&
    classes.includes('(false,true)=>Self::IdentityOnly,') &&
    classes.includes('(false,false)=>Self::Volatile'), 'MUC fresh classes must preserve archive and identity independence');

  const observedDb = compact(body(mucDb, 'async\\s+fn\\s+admit_muc_discussion_observed\\b'));
  requireBoundary(observedDb === 'admit_muc_discussion_inner(pool,super::room::discussion_to_db(request.command()),Some(request)).await',
    'MUC SQL input must be projected from its bound request');
  const transaction = compact(body(mucDb, 'async\\s+fn\\s+admit_muc_discussion_inner\\b'));
  requireBoundary(count(transaction, 'commit_muc_discussion(transaction,request,MucDiscussionAdmission::Stored(message.id)).await') === 2 &&
    count(transaction, 'commit_muc_discussion(transaction,request,MucDiscussionAdmission::Replay(existing_id)).await') === 1 &&
    !transaction.includes('transaction.commit('), 'MUC must observe all three existing COMMIT exits with exact Stored/Replay facts');
  const commit = compact(body(mucDb, 'async\\s+fn\\s+commit_muc_discussion\\b'));
  requireBoundary(commit.includes('commit_observed(transaction.commit(),request,observed).await') &&
    commit.includes('MucDiscussionAdmission::Stored(id)=>{northstar_room_core::MucDiscussionAdmission::Stored(id)}') &&
    commit.includes('MucDiscussionAdmission::Replay(id)=>{northstar_room_core::MucDiscussionAdmission::Replay(id)}'),
  'MUC SQL wrapper must observe the actual transaction and its unchanged result identity');
  const repository = compact(body(mucRepository, 'fn\\s+admit_discussion_observed\\b'));
  requireBoundary(repository.includes('db::admit_muc_discussion_observed(&self.pool,request).await?'),
    'MUC production repository must use the observed SQL entry');
  const serviceOwner = body(mucService, 'impl<R:\\s*MucRepository>\\s+MucService<R>');
  const serviceNew = compact(body(serviceOwner, 'fn\\s+new\\b'));
  ordered(serviceNew, ['letconfigured_domain:Arc<str>=Arc::from(configured_domain.as_ref());',
    'discussion_application:RoomApplication::new(repository.clone(),configured_domain.to_string())',
    'repository,configured_domain,local_join_gates'],
  'MUC service constructor must bind its actual receiving configuration to RoomApplication');
  const servicePrepare = compact(body(serviceOwner, 'fn\\s+prepare_muc_discussion\\b'));
  requireBoundary(servicePrepare === 'self.discussion_application.prepare_discussion(command)',
    'MUC service preparation must forward to its configured discussion application');
  const service = compact(body(mucService, 'async\\s+fn\\s+execute_muc_discussion_observed\\b'));
  requireBoundary(service.includes('self.discussion_application.admit_discussion_observed(request).await'),
    'MUC production service must use the request-bound application');

  const slot = body(mucSlot, 'impl\\s+MucDiscussionSlot\\b');
  const register = compact(body(slot, 'fn\\s+register\\b'));
  ordered(register, ['letmutslot=self.0.lock()', 'ifslot.terminal.is_some(){returnErr(Rejected::Retired);}',
    'if!observation.is_for(prepared){returnErr(Rejected::Input);}',
    'letobservation=Observation::new(prepared.clone());', 'slot.observation=Some(observation.clone());'],
  'MUC lazy slot must serialize retired/conflicting rejection before registration');
  const session = body(frame, 'impl\\s+SessionExecutions\\b');
  const selection = compact(body(session, 'fn\\s+muc_discussion\\b'));
  requireBoundary(selection === 'letSome(execution)=&self.currentelse{returnOk(None);};ifexecution.0.outcome.load(Ordering::Relaxed)!=Outcome::Pendingasu8{returnErr(discussion::Rejected::Retired);}execution.0.muc_discussion.register(prepared).map(Some)',
    'MUC legacy absence must remain distinct from retired or conflicting frame registration');
  const accessor = compact(body(protocol, 'fn\\s+muc_discussion_operation\\b'));
  requireBoundary(accessor === 'self.frame_executions.muc_discussion(prepared)',
    'MUC protocol accessor must propagate registration errors without legacy fallback');
  const finish = compact(body(frame, 'fn\\s+finish\\(&mut\\s+self,\\s*outcome:\\s*Outcome\\)'));
  ordered(finish, ['ifself.phase==', 'letmuc_reason=matchreason{', 'progress.muc_discussion.retire(muc_reason)', 'progress.outcome.store('],
    'MUC frame retirement must remain in the existing frame terminal hook');

  const envelope = body(muc, 'impl\\s+PreparedMucDiscussion\\b');
  const envelopeNew = compact(body(envelope, 'fn\\s+new\\b'));
  requireBoundary(envelopeNew.includes('command.stanza==archive') &&
    envelopeNew.includes('command.room_id==room.id&&command.authority.expected_room_epoch==room.room_epoch') &&
    envelopeNew.includes('letarchive=ifcommand.archive&&command.encrypted{encrypted_archive_stanza(&stanza)}else{stanza.clone()};'),
  'MUC live envelope must bind exact archive projection and room authority');
  const bind = compact(body(envelope, 'fn\\s+bind\\b'));
  ordered(bind, ['observation.is_for(&self.prepared)', 'letrequest=observation.request()?;', 'live:self.live'],
    'MUC live envelope must bind its private input before issuing the request');
  const bound = body(muc, 'impl\\s+BoundMucDiscussion\\b');
  const boundFinish = compact(body(bound, 'fn\\s+finish\\b'));
  requireBoundary(boundFinish.includes('completion.into_fanout(&self.observation)?') &&
    boundFinish.includes('AcceptedMucDiscussion{live:self.live,permit}'),
    'MUC accepted envelope must consume matching completion and retain original live bytes');
  const accepted = body(muc, 'impl\\s+AcceptedMucDiscussion\\b');
  const fanout = compact(body(accepted, 'async\\s+fn\\s+fanout\\b'));
  requireBoundary(fanout.includes('letSelf{live,permit}=self;') &&
    fanout.includes('run_muc_discussion_fanout(&MucMessageFanout{session,room_jid:&live.room_jid,room_from:&live.room_from,sender:&live.sender,stanza:&live.stanza},permit).await?'),
    'MUC accepted fanout must consume its envelope and cannot substitute live payload');
}

export function verifyRoomExecutionBoundaries(sources) {
  const { muc, mucFanout, mix } = sources;
  const message = compact(body(muc, 'async\\s+fn\\s+muc_message\\b'));
  requireBoundary(message.startsWith('self.enter_frame_stage(Stage::MucPolicy);'),
    'MUC message policy stage must precede principal and protocol policy checks');
  requireBoundary(message.includes('letlocal_authority_guard=ifself.state.muc_pg_authority_enabled(){None}else{self.enter_frame_stage(Stage::MucGateWait);Some(self.state.muc_service().lock_local_room_mutation(initial_room.id).await,)};self.enter_frame_stage(Stage::MucAuthority);'),
    'MUC standalone gate wait and authority stages must surround the actual guard acquisition');
  for (const call of [
    'matchself.state.muc_service().execute_muc_retraction(',
    'matchservice.set_local_cluster_subject(',
    'matchservice.execute_muc_subject(',
    'letcompletion=self.state.muc_service().execute_muc_discussion_observed(',
    'self.state.muc_service().execute_muc_discussion(',
  ]) {
    requireBoundary(message.includes('self.enter_frame_stage(Stage::MucAdmission);' + call),
      `MUC admission stage must immediately precede ${call}`);
  }
  const discussionDispatch = 'letoperation=self.muc_discussion_operation(&prepared.prepared)?;' +
    'letadmission=ifletSome(operation)=operation{' +
    'letbound=prepared.bind(operation)?;' +
    'self.enter_frame_stage(Stage::MucAdmission);' +
    'letcompletion=self.state.muc_service().execute_muc_discussion_observed(&bound.request).await?;' +
    'letadmission=completion.outcome();discussion_fanout=bound.finish(completion)?;admission' +
    '}else{self.enter_frame_stage(Stage::MucAdmission);' +
    'self.state.muc_service().execute_muc_discussion(prepared.prepared.command()).await?};';
  requireBoundary(message.replace(/,\)/g, ')').includes(discussionDispatch),
    'MUC discussion dispatch must retain the unfiltered active-frame branch and bound request/completion chain');
  requireBoundary(message.includes('MucDiscussionAdmission::Replay(_)=>{fanout_disposition=MucFanoutDisposition::Replay;}') &&
    message.includes('letoperation=self.muc_discussion_operation(&prepared.prepared)?;') &&
    message.includes('discussion_fanout=bound.finish(completion)?;') &&
    message.includes('letattempted=ifletSome(accepted)=discussion_fanout{accepted.fanout(self).await?}else{run_muc_fanout(&MucMessageFanout{session:self,room_jid:&room_jid,room_from:&room_from,sender:from,stanza:&rewritten,},fanout_disposition,).await};if!attempted{returnOk(Action::None);}drop(local_authority_guard);'),
  'MUC replay and accepted fanout must use the typed owner before releasing the room guard');
  const adapter = body(muc, 'impl\\s+MucFanoutPort\\s+for\\s+MucMessageFanout\\b');
  const stageAdapter = compact(body(adapter, 'fn\\s+enter\\b'));
  requireBoundary(stageAdapter === 'self.session.enter_frame_stage(matchstage{MucFanoutStage::Cluster=>Stage::MucClusterFanout,MucFanoutStage::Local=>Stage::MucLocalFanout,});',
    'MUC fanout adapter must attribute both stages to the originating session');
  const fanout = compact(body(mucFanout, 'async\\s+fn\\s+run_muc_fanout\\b'));
  requireBoundary(fanout === 'ifdisposition==MucFanoutDisposition::Replay{returnfalse;}run_muc_fanout_effects(port,None).await.expect();true',
    'MUC fanout must skip replay and preserve cluster, owned snapshot, privacy and sequential local delivery');
  const observedFanout = compact(body(mucFanout, 'async\\s+fn\\s+run_muc_discussion_fanout\\b'));
  requireBoundary(observedFanout === 'letprogress=permit.start()?;run_muc_fanout_effects(port,Some(&progress)).await?;progress.complete()?;Ok(true)',
    'MUC observed fanout must consume its permit and complete only after actual effects');
  const effects = compact(body(mucFanout, 'async\\s+fn\\s+run_muc_fanout_effects\\b'));
  requireBoundary(effects === 'ifletSome(progress)=progress{progress.enter_cluster()?;}port.enter(MucFanoutStage::Cluster);port.publish_cluster().await;ifletSome(progress)=progress{progress.cluster_returned()?;}port.enter(MucFanoutStage::Local);letrecipients=port.recipients();ifletSome(progress)=progress{progress.enter_privacy(recipients.len())?;}letblocked=port.blocked(&recipients).await;ifletSome(progress)=progress{progress.privacy_returned()?;}for(index,recipient)inrecipients.into_iter().enumerate(){ifport.is_blocked(&recipient,&blocked){ifletSome(progress)=progress{progress.blocked(index)?;}continue;}ifletSome(progress)=progress{progress.enter_delivery(index)?;}letaccepted=port.deliver(&recipient).await;ifletSome(progress)=progress{progress.delivery_returned(index,accepted)?;}if!accepted{port.record_failure(&recipient);}}Ok(())',
    'MUC effects must preserve cluster, acquired order, privacy, sequential delivery and observed prefix');
  verifyMucDiscussionBoundaries(sources);

  const mixIngress = compact(body(mix, 'async\\s+fn\\s+try_mix_message\\b'));
  requireBoundary(mixIngress.includes('if!CanonicalJid::parse(to).is_ok_and(|target|target.domainpart()==self.mix_domain()){returnOk(None);}self.enter_frame_stage(Stage::MixPolicy);letSome(user)=self.authenticated.as_ref()') &&
    mixIngress.includes('process_channel_message(&self.state,&actor_bare,full_jid,raw,Some(&self.frame_executions),).await?'),
  'C2S MIX must attribute policy after target selection and pass its originating observation');
  const channelMessage = compact(body(mix, 'async\\s+fn\\s+process_channel_message\\b'));
  requireBoundary(channelMessage.startsWith('ifletSome(observation)=observation{observation.enter(Stage::MixPolicy);}'),
    'MIX shared owner must retain optional policy observation');
  for (const call of ['retract_mix_message', 'store_mix_message']) {
    requireBoundary(channelMessage.includes(`ifletSome(observation)=observation{observation.enter(Stage::MixAdmission);}letadmission=state.mix_service().${call}(`),
      `MIX admission stage must immediately precede ${call}`);
  }
  const federated = compact(body(mix, 'async\\s+fn\\s+federated_mix_message\\b'));
  requireBoundary(federated.includes('process_channel_message(&state,&actor_bare,&actor_full,&raw,None).await?'),
    'federated MIX must not fabricate a C2S frame observation');
  const finish = compact(body(mix, 'async\\s+fn\\s+finish_mix_delivery_owner\\b'));
  requireBoundary(finish === 'matchoutcome{ChannelStanzaDeliveryOutcome::CompletedByClaimingWorker=>acknowledge().await,ChannelStanzaDeliveryOutcome::TransferredToRecoverableTransport=>Ok(true),}',
    'MIX settlement must acknowledge exactly the worker-owned result and never the transferred transport owner');
  const claimed = body(mix, 'async\\s+fn\\s+process_claimed_mix_delivery\\b');
  const completion = compact(body(claimed, 'Ok\\(outcome\\)\\s*=>'));
  requireBoundary(completion === 'finish_mix_delivery_owner(outcome,||{bounded_mix_outbox_turn(&cancel,attempt_deadline,context.service().acknowledge_mix_delivery(delivery.delivery_id,delivery.lease_token),)}).await',
    'MIX claimed delivery must delegate exact-token acknowledgement lazily under its existing deadline and cancellation');
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const sources = readExecutionSources();
  verifyExecutionBoundaries(sources);
  verifyRoomExecutionBoundaries(sources);
  verifyNativeAckService(sources.mixService);
  verifyNativeWriteBoundaries(sources);
  verifySmOwnershipBoundaries(sources);
  verifyBoshTransferBoundaries(sources);
  verifyBoshResponseBoundaries(sources);
  console.log('Execution publication boundaries passed');
}
