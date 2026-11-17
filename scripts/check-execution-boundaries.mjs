import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readModuleParts, readProductionModule, readRoleSplitFile } from './lib/source-module.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const files = {
  frame: 'crates/edges/northstar-stream/src/frame_execution.rs',
  authFacts: 'crates/contexts/session/northstar-session-core/src/publication.rs',
  authOwner: 'crates/edges/northstar-stream/src/auth_publication.rs',
  authCredential: 'crates/contexts/auth/northstar-auth-core/src/credential.rs',
  authDb: 'crates/contexts/auth/northstar-auth-postgres/src/authentication.rs',
  authUsers: 'crates/contexts/auth/northstar-auth-postgres/src/users.rs',
  credentialSmDb: 'crates/contexts/workflows/northstar-workflows/src/sm_repository.rs',
  sasl2: 'crates/edges/northstar-stream/src/protocol/sasl2.rs',
  protocol: 'crates/edges/northstar-stream/src/protocol.rs',
  transport: 'crates/edges/northstar-c2s/src/lib.rs',
  bosh: 'crates/edges/northstar-bosh/src/lib.rs',
  boshAction: 'crates/edges/northstar-bosh/src/action.rs',
  outbound: 'crates/edges/northstar-stream/src/outbound.rs',
  mucCore: 'crates/contexts/room/northstar-room-application/src/discussion.rs',
  mucService: 'crates/contexts/room/northstar-room-application/src/muc_service.rs',
  mix: 'crates/contexts/room/northstar-mix-xmpp/src/lib.rs',
  mixService: 'crates/contexts/room/northstar-room-application/src/mix_service.rs',
  mixCore: 'crates/contexts/room/northstar-room-application/src/mix.rs',
  mixData: 'crates/contexts/room/northstar-room-core/src/mix.rs',
  mixWorkerCore: 'crates/contexts/message/northstar-delivery-core/src/mix_outbox.rs',
  mixWorkerOwner: 'crates/contexts/room/northstar-room-application/src/mix_service/outbox.rs',
  state: 'src/node.rs',
  sessionTable: 'crates/edges/northstar-stream/src/local_routes/session_table.rs',
  mixOutboxState: 'src/node/adapters/mix_outbox.rs',
  nativeWrite: 'crates/edges/northstar-c2s/src/direct_delivery.rs',
  nativeCore: 'crates/contexts/message/northstar-delivery-core/src/native_write.rs',
  replayDb: 'crates/contexts/session/northstar-session-postgres/src/replay.rs',
  mixDb: 'crates/contexts/room/northstar-room-postgres/src/mix.rs',
  smProtocol: 'crates/edges/northstar-stream/src/protocol/sm.rs',
  smOwner: 'crates/edges/northstar-stream/src/protocol/sm_owner.rs',
  smCore: 'crates/contexts/message/northstar-delivery-core/src/sm_ownership.rs',
  smPrepared: 'crates/contexts/session/northstar-session-application/src/sm/ownership.rs',
  smDb: 'crates/contexts/workflows/northstar-workflows/src/sm.rs',
  boshOwner: 'crates/edges/northstar-bosh/src/ownership.rs',
  boshCore: 'crates/contexts/message/northstar-delivery-core/src/bosh_ownership.rs',
  mixRepository: 'crates/contexts/room/northstar-room-postgres/src/mix_repository.rs',
  boshResponse: 'crates/edges/northstar-bosh/src/response_owner.rs',
  boshResponseCore: 'crates/contexts/message/northstar-delivery-core/src/bosh_ownership/response.rs',
  replayService: 'crates/contexts/session/northstar-session-application/src/replay.rs',
  replayRepository: 'crates/contexts/session/northstar-session-postgres/src/replay_repository.rs',
};

// Sources read as whole production modules (the file plus its non-test
// child module files), so items keep being found after a module split.
const productionModules = new Set([
  'mix', 'mixDb', 'state', 'authUsers', 'sasl2',
  'mucService', 'mixService', 'replayDb', 'smDb', 'mixRepository',
]);

// These directories hold independently owned modules, so read the file plus
// its role-split children listed in catalog/source-role-splits.json.
const roleSplitSources = new Set(['protocol', 'bosh']);

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

function body(source, declaration, original = false) {
  const code = codeOnly(source);
  const pattern = new RegExp(declaration, 'g');
  const matches = [...code.matchAll(pattern)];
  requireBoundary(matches.length === 1, `expected one production body: ${declaration}`);
  const opening = code.indexOf('{', matches[0].index + matches[0][0].length);
  requireBoundary(opening >= 0, `missing body: ${declaration}`);
  let depth = 1;
  for (let index = opening + 1; index < code.length; index++) {
    if (code[index] === '{') depth++;
    else if (code[index] === '}' && --depth === 0) return (original ? source : code).slice(opening + 1, index);
  }
  throw new Error(`execution boundary: unterminated body: ${declaration}`);
}

// A test-only item that a sibling crate's tests read is compiled for the owning
// crate's tests and for its test-support feature, which only dev-dependencies enable.
const CROSS_CRATE_TEST_ONLY = '#[cfg(any(test, feature = "test-support"))]';

function productionModule(source) {
  const markers = [...codeOnly(source).matchAll(/\n#\[cfg\(test\)\]\s*\nmod\s+tests\b/g)];
  requireBoundary(markers.length <= 1, 'expected at most one test-module boundary');
  return markers.length ? source.slice(0, markers[0].index) : source;
}

// Remove every `#[cfg(test)]` module, inline block or `mod name;` declaration,
// wherever it occurs. A production module read appends the child files after
// the parent, so cutting at the first test module would also drop the children.
function withoutTestModules(source) {
  const code = codeOnly(source);
  let output = '';
  let cursor = 0;
  for (const match of code.matchAll(/\n#\[cfg\(test\)\]\s*(?:#\[[^\]]*\]\s*)?mod\s+\w+\s*([;{])/g)) {
    if (match.index < cursor) continue;
    let end = match.index + match[0].length;
    if (match[1] === '{') {
      let depth = 1;
      for (; end < code.length && depth > 0; end++) {
        if (code[end] === '{') depth++;
        else if (code[end] === '}') depth--;
      }
      requireBoundary(depth === 0, 'unterminated test module');
    }
    output += source.slice(cursor, match.index);
    cursor = end;
  }
  return output + source.slice(cursor);
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

// The composition root's SessionHost impls (src/node/*session_host.rs) forward to ServerNode methods of the same
// names; the boundaries below are the inherent ServerNode bodies, so the state source leaves the forwards out.
const sessionHostForwards = /^src\/node\/hosts\/(?:[a-z_]+_)?session\.rs$/;

export function readExecutionSources() {
  return Object.fromEntries(Object.entries(files).map(([name, file]) => [name,
    name === 'state' ? readModuleParts(file, { root, includeTests: false })
      .filter(part => !sessionHostForwards.test(part.path.replaceAll('\\', '/')))
      .map(part => part.source).join('\n')
      : productionModules.has(name) ? readProductionModule(file, { root })
      : roleSplitSources.has(name) ? readRoleSplitFile(file, { root }) : fs.readFileSync(path.join(root, file), 'utf8')]));
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
  const write = normalize(body(nativeWrite, 'pub\\s+async\\s+fn\\s+write\\b'));
  ordered(write, ['self.observation.begin_write()?;', 'letactual=writer(&self.item.stanza).await;', 'lettruth=ifactual.is_ok(){WriterResult::FullWrite}else{WriterResult::Failed};', 'letwritten=self.observation.writer_completed(truth)?;', 'actual?;', 'Ok(WrittenDirectLease{item:self.item,written,managed_by_sm:self.managed_by_sm,})'],
    'native lease must retain actual writer truth before issuing the consuming written continuation');
  const settle = normalize(body(nativeWrite, 'pub\\s+async\\s+fn\\s+settle\\b'));
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
    'super::session_sm::apply_sm_ownership_resolution_to_unacked(&mutself.sm.unacked,&outcome.ownership);',
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
    'super::session_sm::apply_sm_ownership_resolution_to_unacked(&mutremaining,&outcome.ownership);'],
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
  const service = normalize(body(mixService, 'pub\\s+async\\s+fn\\s+transfer_mix_delivery_to_bosh\\b'));
  requireBoundary(service === 'let_admission=self.outbox_db_admission_guard().await;self.repository.transfer_mix_delivery_to_bosh(request).await',
    'BOSH MIX service must retain existing admission and forward the same closed request');
  const repository = normalize(body(mixRepository, 'async\\s+fn\\s+transfer_mix_delivery_to_bosh\\b'));
  requireBoundary(repository === 'crate::mix::transfer_mix_delivery_to_bosh(&self.pool,request).await',
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
  boshResponse = productionModule(boshResponse).replaceAll(CROSS_CRATE_TEST_ONLY, '#[cfg(test)]');
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
    'letauth_controls=SelectedControls::new(selected.iter().map(|item|(item.stanza.as_str(),item.auth_publication())))',
    'letauth_control_selected=!auth_controls.is_empty();',
    '#[cfg(test)]letselection=SelectionObservation::capture(&selected,operation,metadata);',
    'Ok(BoundResponse{metadata,response,receipts,ownership,bound,auth_control_selected,auth_controls,auth_connection:None,#[cfg(test)]selection,})'],
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
    const service = normalize(body(replayService, `pub\\s+async\\s+fn\\s+${name}\\b`));
    requireBoundary(service === `self.repository.${name}(request).await`, 'BOSH service must forward the same closed response request');
    const repository = normalize(body(replayRepository, `async\\s+fn\\s+${name}\\b`));
    requireBoundary(repository.includes(`crate::replay::${sql}(&self.pool,request).await`),
      'BOSH repository must forward the same closed response request');
  }
  const bindSql = normalize(body(replayDb, 'async\\s+fn\\s+bind_bosh_transport_response_observed\\b'));
  requireBoundary(bindSql === 'request.validate_for_io()?;bind_bosh_transport_response_inner(pool,request.session_id(),request.rid(),request.sources(),request.ttl_seconds(),Some(request)).await',
    'BOSH bind SQL must use validated closed inputs and retain its request');
  const bindInner = normalize(body(replayDb, 'async\\s+fn\\s+bind_bosh_transport_response_inner\\b'));
  ordered(bindInner, ['letownership=northstar_stream::outbound::BoshResponseOwnership{', 'letreceipt=ownership.clone();',
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
  verifyBoshSelectionObservations({ boshResponse });
}

// Auth-specific lexical drift checks for independent credential transaction
// observations and the existing receipt/transport-bound publication owner.
export function verifyAuthPublicationBoundaries(sources) {
  const { authFacts, authOwner, authCredential, authDb, credentialSmDb, protocol, frame,
    bosh, state } = sources;
  const normalize = value => compact(value).replace(/,([)}])/g, '$1').replace(/,$/, '');
  const method = (source, name) => normalize(body(productionModule(source), `(?:async\\s+)?fn\\s+${name}\\b`));
  const facts = productionModule(authFacts).replaceAll(CROSS_CRATE_TEST_ONLY, '#[cfg(test)]');
  const owner = productionModule(authOwner).replaceAll(CROSS_CRATE_TEST_ONLY, '#[cfg(test)]');
  const observation = body(facts, 'impl\\s+Observation\\b');
  const receipt = normalize(body(authCredential, 'pub\\s+struct\\s+CredentialCommitReceipt\\b'));
  requireBoundary(receipt.includes('publication_identity:Uuid') && !/pub(?:\([^)]*\))?publication_identity:/.test(receipt),
    'auth receipt instance identity must remain private');
  requireBoundary(normalize(body(owner, 'pub\\s+struct\\s+OwnedPublication\\b')) ===
    'pending:PendingPublication,holder:AuthControlHolder,managed:bool' &&
    normalize(body(owner, 'struct\\s+PendingPublication\\b')) ===
    'receipt:CredentialCommitReceipt,origin:Option<FrameExecution>,effects:CapturedEffects',
    'auth consuming owner must keep its exact receipt, origin and effects private');
  // Closed inventory for the actual owners, including their reviewed named
  // and Self construction sites. Alternate Rust syntax/macros remain review.
  for (const [source, name, declaration, methods, construction, sites, selfSites] of [
    [owner, 'AuthControlHolder', 'impl\\s+AuthControlHolder\\b',
      ['validate_connection', 'validates', 'validate_control', 'recording', 'write', 'join_observation'], /\bAuthControlHolder\s*\(/g, 2, 0],
    [owner, 'OwnedPublication', 'impl\\s+OwnedPublication\\b',
      ['join_observation', 'captured_effects', 'receipt', 'observation', 'effects', 'origin', 'connection', 'publish', 'run'], /\bOwnedPublication\s*\{/g, 4, 0],
    // Three Self-plus-brace tokens: empty's bare-Self return head and the
    // two constructors, whose exact method locations are pinned below.
    [owner, 'SelectedControls', 'impl\\s+SelectedControls\\b',
      ['empty', 'new', 'is_empty', 'observations', 'validate_connection', 'begin_exposure', 'exposure', 'take_all'], /\bSelectedControls\s*\{/g, 4, 3],
    [facts, 'Invocation', "impl\\s+Invocation<'_>",
      ['receipt', 'validate', 'enter_service', 'enter_repository', 'not_required', 'commit', 'rollback', 'returned'], /\bInvocation\s*\{/g, 1, 0],
  ]) {
    const code = codeOnly(source);
    const implementation = body(source, declaration);
    requireBoundary([...implementation.matchAll(/\bfn\s+(\w+)\b/g)].map(match => match[1]).join(',') === methods.join(','),
      `auth ${name} must retain its closed inherent-method inventory`);
    requireBoundary([...code.matchAll(construction)].length === sites &&
      [...implementation.matchAll(/\bSelf\s*[{(]/g)].length === selfSites,
    `auth ${name} cannot add named or Self construction sites`);
  }
  const begin = method(observation, 'begin');
  requireBoundary(!normalize(codeOnly(productionModule(frame))).includes('take_publication') &&
    !normalize(codeOnly(productionModule(protocol))).includes('defer_publication'),
    'auth publication cannot restore a session-wide latest-frame slot');
  const known = body(owner, 'impl\\s+KnownCredentialOwner\\b');
  const sealed = method(known, 'seal');
  const holder = body(owner, 'impl\\s+AuthControlHolder\\b');
  requireBoundary(/#\[cfg\(test\)\]\s*pub\s+fn\s+join_observation\s*\(\s*&self\s*\)\s*->\s*ControlJoinObservation\s*\{/.test(holder) &&
    method(holder, 'join_observation') === 'self.0.joins.clone()',
    'auth holder join observation must remain a test-only read-only clone of its actual captured joins');
  const selected = body(owner, 'impl\\s+SelectedControls\\b');
  const take = method(selected, 'take_all');
  const finish = method(bosh, 'finish_pending');
  ordered(finish, ['bound.for_connection(self.protocol.connection_id())', 'bound.expose(pending.responders)',
    '.publish_authentication(|owners|async{forownerinowners{if!self.protocol.publish_committed_authentication_and_route(owner).await{returnfalse;}}true})',
    'ready.finish('], 'auth BOSH continuation must preserve selected FIFO, early failure and exact connection');
  // These finite source shapes pin real SQL cuts. They do not execute SQL or
  // infer rollback from a transaction destructor.
  const prepared = body(facts, 'impl\\s+PreparedCredential\\b');
  const credential = body(facts, "impl\\s+CredentialInvocation<'_>");
  const attempt = body(owner, 'impl\\s+CredentialAttempt\\b');
  requireBoundary(normalize(body(facts, 'pub\\s+struct\\s+PreparedCredential\\b')) === 'observation:CredentialObservation' &&
    normalize(body(facts, "pub\\s+struct\\s+CredentialInvocation<'a>")) === "prepared:&'aPreparedCredential" &&
    normalize(body(facts, 'struct\\s+CredentialWitness\\b')) === 'attempt:Uuid,request:CredentialRequest,receipt:ReceiptProjection',
    'credential invocation and witness must keep private original attempt/request/projection authority');
  for (const [implementation, names, label] of [
    [prepared, ['new', 'observation', 'bind', 'fast', 'binding', 'resume', 'transfer'], 'prepared credential'],
    [credential, ['update', 'preparation_update', 'start', 'enter_repository', 'enter_fast', 'enter_binding', 'enter_resume', 'begin', 'eligibility', 'transaction_returned', 'preparation_entered', 'preparation_returned', 'stage_id', 'stage_returned', 'rollback', 'prepared_projection', 'commit', 'constructed', 'returned', 'fast_returned', 'binding_returned', 'resume_returned'], 'credential invocation'],
    [attempt, ['new', 'prepared', 'into_owner'], 'credential attempt'],
  ]) requireBoundary([...implementation.matchAll(/\bfn\s+(\w+)\b/g)].map(match => match[1]).join(',') === names.join(','),
    `${label} must retain its closed inherent-method inventory`);
  requireBoundary(count(normalize(codeOnly(facts)), 'CredentialWitness{') === 2 &&
    count(normalize(codeOnly(facts)), 'CredentialInvocation{') === 1 &&
    count(normalize(codeOnly(productionModule(frame))), 'publication::PreparedCredential::new(') === 1,
    'credential witness and invocation constructors must remain at their exact one-use sites');
  const transfer = method(prepared, 'transfer');
  requireBoundary(!/\.await|spawn|rollback\(|commit\(/.test(method(body(facts, "impl\\s+Drop\\s+for\\s+CredentialInvocation<'_>"), 'drop')),
    'credential invocation Drop cannot perform SQL or I/O');
  for (const [source, name, start, receiptResult, sites] of [
    [authDb, 'commit_fast_with_login_epoch_inner', 'observation.enter_fast(', 'AuthenticationResult::Authenticated(receipt)', ['FastExpired']],
    [credentialSmDb, 'finalize_binding_inner', 'observation.enter_binding(', 'Ok(BindingFinalizationOutcome::Committed{receipt})', ['BindingReservationLost', 'BindingStageMissing', 'BindingFastExpired']],
    [credentialSmDb, 'finalize_resume_inner', 'observation.enter_resume(', 'SmResumeFinalizationCommit{activated:activated.into(),receipt}', ['ResumeStageMissing', 'ResumeClaimLost', 'ResumeFastExpired', 'ResumePrivacyMissing']],
  ]) {
    const transaction = method(source, name);
    ordered(transaction, [start, source === authDb ? 'crate::users::lock_auth_generation_observed(' : 'northstar_auth_postgres::users::lock_auth_generation_observed(', 'stage_login_epoch_in_transaction_observed(',
      'CredentialInvocation::commit(observation,tx.commit()).await', 'CredentialCommitReceipt::new(', 'observation.constructed(&receipt)', receiptResult],
      `credential ${name} must observe its actual transaction and construct only after acknowledged COMMIT`);
    requireBoundary(count(transaction, 'CredentialInvocation::commit(observation,tx.commit()).await') === 1 &&
      count(transaction, 'CredentialInvocation::rollback(') === sites.length,
      `credential ${name} must retain its exact COMMIT and rollback inventory`);
    for (const site of sites) requireBoundary(transaction.includes(`CredentialInvocation::rollback(observation,CredentialRollbackSite::${site},tx.rollback()).await` + (name === 'commit_fast_with_login_epoch_inner' ? ';' : '.map_err(credential_error)?;')),
      `credential ${site} must preserve ignored versus propagated rollback errors`);
  }
  // state is a whole module: drop each test module instead of cutting at the first
  const stateProduction = withoutTestModules(state);
  requireBoundary(method(stateProduction, 'finalize_resource_binding') === 'self.session.sm_service.finalize_binding_observed(connection_id,user_id,expected_auth_generation,full_jid,self.config.capacity_session_lease_seconds,device_id,fast_plan,observation).await' &&
    method(stateProduction, 'finalize_sm_resume') === 'self.session.sm_service.finalize_resume_observed(request,observation).await',
    'credential state forwarding must preserve the actual lease and exact resume request');
  // Read-only test observations must retain actual private association facts.
  const testOnlyItem = (source, declaration) => new RegExp(
    '#\\[cfg\\(test\\)\\]\\s*(?:#\\[[^\\]]*\\]\\s*)*' + declaration,
  ).test(codeOnly(source));
  for (const [source, name, fields] of [
    [facts, 'CredentialAttemptJoin', 'pubattempt:Uuid,pubframe:Uuid,pubconnection:Uuid,pubordinal:u8,pubkind:CredentialKind'],
    [facts, 'CredentialJoins', 'pubowner:CredentialAttemptJoin,pubconstructed_receipt:Option<Uuid>,pubreturned_receipt:Option<Uuid>,pubtransferred_receipt:Option<Uuid>'],
    [facts, 'PublicationJoins', 'pubcontrol:Uuid,pubframe:Option<Uuid>,pubreceipt:Uuid,pubcredential:Option<CredentialAttemptJoin>,pubbegun_receipt:Option<Uuid>,pubbound_effects:bool,pubnotification_expected:bool'],
    [owner, 'ControlAssociation', 'pubcontrol:Uuid,pubconnection:Uuid,pubframe:Option<Uuid>,pubreceipt:Uuid,publength:usize,pubdigest:[u8;32],pubpublication:northstar_auth_application::authentication::publication::PublicationJoins'],
    [owner, 'ControlJoins', 'pubintroduced:Option<ControlAssociation>,pubtransferred:Option<ControlAssociation>'],
  ]) {
    const declaration = 'pub\\s+struct\\s+' + name + '\\b';
    requireBoundary(testOnlyItem(source, declaration) && normalize(body(source, declaration)) === fields,
      `auth ${name} must remain test-only association facts without retained authority`);
  }
  requireBoundary(testOnlyItem(facts, 'impl\\s+CredentialAttemptJoin\\b') &&
    method(body(facts, 'impl\\s+CredentialAttemptJoin\\b'), 'of') ===
      'Self{attempt:snapshot.attempt,frame:snapshot.frame,connection:snapshot.connection,ordinal:snapshot.ordinal,kind:snapshot.kind}',
    'auth credential join anchor must read the original actual attempt snapshot');
  const credentialObservation = body(facts, 'impl\\s+CredentialObservation\\b');
  requireBoundary(testOnlyItem(credentialObservation, 'pub\\s+fn\\s+joins\\s*\\(&self\\)\\s*->\\s*CredentialJoins') &&
    method(credentialObservation, 'joins') ===
      'letstate=self.0.lock().unwrap();CredentialJoins{owner:CredentialAttemptJoin::of(&state.snapshot),constructed_receipt:state.constructed.as_ref().map(|(id,_)|*id),returned_receipt:state.returned.as_ref().map(|(id,_)|*id),transferred_receipt:state.transferred_receipt}',
    'auth credential join reader must independently read actual constructed and raw-returned receipt identities');
  requireBoundary(normalize(body(facts, 'struct\\s+CredentialState\\b')).includes('#[cfg(test)]transferred_receipt:Option<Uuid>') &&
    method(prepared, 'new').includes('#[cfg(test)]transferred_receipt:None') &&
    transfer.includes('state.snapshot.transferred=true;#[cfg(test)]{state.transferred_receipt=Some(receipt.publication_identity());}Ok(self.observation.clone())'),
    'auth transferred receipt observation must remain test-only and follow actual checked transfer');
  requireBoundary(testOnlyItem(observation, 'pub\\s+fn\\s+joins\\s*\\(&self\\)\\s*->\\s*PublicationJoins') &&
    method(observation, 'joins') ===
      'letstate=self.0.lock().unwrap();PublicationJoins{control:state.snapshot.control,frame:state.snapshot.frame,receipt:state.receipt_id,credential:state.credential.as_ref().map(|credential|credential.joins().owner),begun_receipt:state.begun_receipt,bound_effects:state.bound_effects,notification_expected:state.notification_expected}' &&
    method(observation, 'returned_receipt').includes('credential:None'),
    'auth publication join reader must preserve actual receipt identity and only an observed credential anchor with actual State effect intent');
  const publicationJoinDeclarations = [...codeOnly(facts).matchAll(/((?:#\[[^\]]*\]\s*)*)pub\s+struct\s+PublicationJoins\b/g)];
  requireBoundary(publicationJoinDeclarations.length === 1 &&
    compact(publicationJoinDeclarations[0][0]) === '#[cfg(test)]#[derive(Clone,Copy,Debug,Eq,PartialEq)]pubstructPublicationJoins',
    'auth PublicationJoins must preserve its exact test-only derives');
  requireBoundary(normalize(body(facts, 'struct\\s+State\\b')).includes('#[cfg(test)]begun_receipt:Option<Uuid>') &&
    method(observation, 'returned_receipt').includes('#[cfg(test)]begun_receipt:None') &&
    begin.includes('state.snapshot.publication=Knowledge::BeforeCommit;#[cfg(test)]{state.begun_receipt=Some(receipt.publication_identity());}Ok(Invocation{observation:self,receipt})'),
    'auth begun receipt observation must remain test-only and follow actual publication acceptance');
  requireBoundary(testOnlyItem(owner, 'pub\\s+struct\\s+ControlJoinObservation\\(Arc<Mutex<ControlJoins>>\\);') &&
    testOnlyItem(owner, 'impl\\s+ControlJoinObservation\\b') &&
    normalize(body(owner, 'impl\\s+ControlJoinObservation\\b')) ===
      'pubfnsnapshot(&self)->ControlJoins{*self.0.lock().unwrap()}' +
      'pubfnedit(&self,edit:implFnOnce(&mutControlJoins)){edit(&mutself.0.lock().unwrap());}',
    'auth control join reader must retain only test facts, a snapshot and the saved-case damage hook');
  requireBoundary(testOnlyItem(owner, 'fn\\s+control_association\\b') &&
    method(owner, 'control_association') ===
      'ControlAssociation{control:holder.id,connection:holder.connection,frame:pending.origin.as_ref().map(FrameExecution::operation_id),receipt:pending.receipt.publication_identity(),length:holder.length,digest:holder.digest,publication:holder.observation.joins()}',
    'auth control association must read the actual holder and moved pending receipt independently');
  requireBoundary(normalize(body(owner, 'struct\\s+Holder\\b')).includes('#[cfg(test)]joins:ControlJoinObservation') &&
    sealed.includes('#[cfg(test)]joins:ControlJoinObservation(Arc::new(Mutex::new(ControlJoins::default())))') &&
    sealed.endsWith('#[cfg(test)]{letpending=holder.0.pending.lock().unwrap();holder.0.joins.0.lock().unwrap().introduced=Some(control_association(&holder.0,pending.pending.as_ref().expect()));}Ok(holder)') &&
    take.includes('managed:false}));#[cfg(test)]{letowner=&owned.last().expect().1;holder.0.joins.0.lock().unwrap().transferred=Some(control_association(&holder.0,&owner.pending));}'),
    'auth control introduction and transfer must capture their actual owner at each test-only handoff cut');

}

// Closed lexical pins for the bounded, fact-only cfg(test) selection observer.
// These inspect source wiring; they are not the Stage 4 oracle or runtime proof.
export function verifyBoshSelectionObservations({ boshResponse }) {
  const source = productionModule(boshResponse).replaceAll(CROSS_CRATE_TEST_ONLY, '#[cfg(test)]');
  const code = codeOnly(source);
  const normalize = value => compact(value).replace(/,([)}])/g, '$1').replace(/,$/, '');
  const exactDeclaration = (declaration, expected, label) => {
    const matches = [...code.matchAll(new RegExp('((?:#\\[[^\\]]*\\]\\s*)*)' + declaration, 'g'))];
    requireBoundary(matches.length === 1 && compact(matches[0][0]) === expected,
      `BOSH selection ${label} must retain its exact test-only declaration and derives`);
  };
  exactDeclaration('const\\s+MAX_SELECTED_FACTS\\s*:\\s*usize\\s*=\\s*\\d+\\s*;',
    '#[cfg(test)]constMAX_SELECTED_FACTS:usize=4;', 'capacity');
  requireBoundary([...code.matchAll(/\bMAX_SELECTED_FACTS\b/g)].length === 5,
    'BOSH selection capacity must remain the fixed four-slot observation bound');
  for (const [name, kind, visibility, derives, fields] of [
    ['SelectionReadStatus', 'enum', 'pub', 'Clone,Copy,Debug,Eq,PartialEq',
      'Complete,Incomplete{omitted_items:usize,missing_auth_associations:usize,connection_changed:bool}'],
    ['SelectedItemSnapshot', 'struct', 'pub', 'Clone,Copy,Debug,Eq,PartialEq',
      'pubordinal:usize,pubsource:Option<northstar_stream::outbound::TransportOwnershipSource>,pubutf8_length:usize,pubsha256:[u8;32],pubauth_marker:bool,pubsealed_association:Option<northstar_stream::auth_publication::ControlAssociation>,pubholder_joins:Option<northstar_stream::auth_publication::ControlJoins>'],
    ['SelectionSnapshot', 'struct', 'pub', 'Clone,Copy,Debug,Eq,PartialEq',
      'pubsession:uuid::Uuid,pubrid:u64,pubfingerprint:[u8;32],pubfirst_validated_connection:Option<uuid::Uuid>,pubvalidated_connection:Option<uuid::Uuid>,pubselected_count:usize,pubstatus:SelectionReadStatus,pubitems:[Option<SelectedItemSnapshot>;MAX_SELECTED_FACTS]'],
    ['SelectedItemRead', 'struct', '', '',
      'at_selection:SelectedItemSnapshot,joins:Option<northstar_stream::auth_publication::ControlJoinObservation>'],
    ['SelectionState', 'struct', '', '',
      'session:uuid::Uuid,rid:u64,fingerprint:[u8;32],first_validated_connection:Option<uuid::Uuid>,validated_connection:Option<uuid::Uuid>,selected_count:usize,status:SelectionReadStatus,items:[Option<SelectedItemRead>;MAX_SELECTED_FACTS]'],
  ]) {
    const declaration = (visibility ? 'pub\\s+' : '') + kind + '\\s+' + name + '\\b';
    exactDeclaration(declaration,
      '#[cfg(test)]' + (derives ? `#[derive(${derives})]` : '') + visibility + kind + name, name);
    requireBoundary(normalize(body(source, declaration)) === fields,
      `BOSH selection ${name} must retain its exact fact-only field shape`);
  }
  exactDeclaration('pub\\s+struct\\s+SelectionObservation\\s*\\(\\s*Arc\\s*<\\s*std\\s*::\\s*sync\\s*::\\s*Mutex\\s*<\\s*SelectionState\\s*>\\s*>\\s*\\)\\s*;',
    '#[cfg(test)]#[derive(Clone)]pubstructSelectionObservation(Arc<std::sync::Mutex<SelectionState>>);', 'handle');
  exactDeclaration('impl\\s+SelectionObservation\\b', '#[cfg(test)]implSelectionObservation', 'implementation');
  const implementation = body(source, 'impl\\s+SelectionObservation\\b');
  requireBoundary([...implementation.matchAll(/\bfn\s+(\w+)\b/g)].map(match => match[1]).join(',') === 'capture,snapshot' &&
    [...code.matchAll(/\bimpl\b[^{};]*\b(?:SelectionReadStatus|SelectedItemSnapshot|SelectionSnapshot|SelectedItemRead|SelectionState|SelectionObservation)\b[^{};]*\{/g)].length === 1,
    'BOSH selection must retain its closed capture and read-only snapshot inventory');
  requireBoundary(normalize(implementation).startsWith('fncapture(selected:&VecDeque<OutboundItem>,operation:&Operation,metadata:Metadata)->Self{') &&
    normalize(implementation).includes('pubfnsnapshot(&self)->SelectionSnapshot{'),
    'BOSH selection methods must retain private capture and immutable fact-only snapshot declarations');
  const bound = body(source, 'impl\\s+BoundResponse\\b');
  requireBoundary(normalize(bound).includes('#[cfg(test)]pubfnselection_observation(&self)->SelectionObservation{self.selection.clone()}') &&
    normalize(body(bound, 'fn\\s+selection_observation\\b')) === 'self.selection.clone()',
    'BOSH selection getter must remain test-only and clone only its fact handle');
  requireBoundary(normalize(body(source, 'pub\\s+struct\\s+BoundResponse\\b')).endsWith('auth_connection:Option<uuid::Uuid>,#[cfg(test)]selection:SelectionObservation'),
    'BOSH selection owner field must remain a private test-only fact handle');
  // Count all reviewed named construction sites, including declaration/return
  // heads. No new factory or callback may mint an observation or replace facts.
  for (const [name, expected] of [['SelectedItemRead', 2], ['SelectedItemSnapshot', 2], ['SelectionState', 2], ['SelectionSnapshot', 3]]) {
    requireBoundary([...code.matchAll(new RegExp('\\b' + name + '\\s*\\{', 'g'))].length === expected,
      `BOSH selection ${name} must retain only its reviewed construction sites`);
  }
  requireBoundary([...code.matchAll(/\bSelectionObservation\s*\(/g)].length === 1,
    'BOSH selection handle cannot add an unreviewed named constructor');
}

// Narrow lexical correspondence for the three shared production route helpers.
// Inspect complete files: state.rs has earlier test modules followed by production.
// Mask each source once, reject duplicate names and cfg/test-only or wrong-owner
// declarations, then compare full bodies so map guards cannot end before effects.
export function verifyRouteHelperBoundaries({ sessionTable, mixOutboxState }) {
  const normalize = value => compact(value).replace(/,([)}])/g, '$1');
  const sessionTableCode = codeOnly(sessionTable);
  const capsCode = codeOnly(mixOutboxState);
  function closing(code, opening) {
    let depth = 1;
    for (let index = opening + 1; index < code.length; index++) {
      if (code[index] === '{') depth++;
      else if (code[index] === '}' && --depth === 0) return index;
    }
    throw new Error('execution boundary: route helper source has an unterminated scope');
  }
  function item(code, name, declaration, owner = '') {
    const matches = [...code.matchAll(new RegExp('\\bfn\\s+' + name + '\\b', 'g'))];
    requireBoundary(matches.length === 1, `route helper ${name} must have one unique production declaration`);
    const start = matches[0].index;
    const scopes = [];
    let boundary = 0;
    for (let index = 0; index < start; index++) {
      if (code[index] === '{') {
        scopes.push(normalize(code.slice(boundary, index)));
        boundary = index + 1;
      } else if (code[index] === '}') {
        scopes.pop();
        boundary = index + 1;
      } else if (code[index] === ';') boundary = index + 1;
    }
    requireBoundary(owner ? scopes.length === 1 && scopes[0] === `impl${owner}` : scopes.length === 0,
      `route helper ${name} must stay in its exact production scope`);
    const opening = code.indexOf('{', start);
    requireBoundary(opening >= 0 && normalize(code.slice(boundary, opening)) === normalize(declaration),
      `route helper ${name} must retain its unconditioned production signature`);
    return normalize(code.slice(opening + 1, closing(code, opening)));
  }
  item(sessionTableCode, "publish_user_agent_epoch_if_current_in", "pubfnpublish_user_agent_epoch_if_current_in(sessions:&DashMap<String,OnlineSession>,key:&str,connection_id:uuid::Uuid,user_id:uuid::Uuid,auth_generation:i64,lifecycle:&Arc<AtomicU8>,user_agent_epoch:Option<i64>)->bool", "");
  requireBoundary(item(sessionTableCode, "activate_session_if_current_in", "pubfnactivate_session_if_current_in(sessions:&DashMap<String,OnlineSession>,full_jid:&str,connection_id:uuid::Uuid,user_id:uuid::Uuid,auth_generation:i64,lifecycle:&Arc<AtomicU8>,disconnect:&CancellationToken)->bool", "") ===
    "letSome(session)=sessions.get_mut(full_jid)else{returnfalse;};if!staged_route_activation_allowed(StagedRouteActivationCheck{session:StagedRouteIdentity{connection_id:session.connection_id,user_id:session.user_id,auth_generation:session.auth_generation},expected:StagedRouteIdentity{connection_id,user_id,auth_generation},same_lifecycle:Arc::ptr_eq(&session.lifecycle,lifecycle),lifecycle_state:session.lifecycle.load(Ordering::Acquire),session_cancelled:session.disconnect.is_cancelled(),owner_cancelled:disconnect.is_cancelled()}){returnfalse;}session.routable.store(true,Ordering::Release);ifsession.lifecycle.load(Ordering::Acquire)!=0||session.disconnect.is_cancelled()||disconnect.is_cancelled(){session.routable.store(false,Ordering::Release);returnfalse;}true",
    "route helper activate_session_if_current_in must preserve write guard, real predicate inputs, release true-store and post-store recheck/rollback");
  item(sessionTableCode, "session_mix_capability_in", "pubfnsession_mix_capability_in(sessions:&DashMap<String,OnlineSession>,caps_by_jid:&CapsResourceIndex,pending_caps:&PendingCapsIndex,full_jid:&str)->MixSessionCapability", "");
  item(sessionTableCode, "publish_user_agent_epoch_if_current", "pubfnpublish_user_agent_epoch_if_current(&self,key:&str,connection_id:uuid::Uuid,user_id:uuid::Uuid,auth_generation:i64,lifecycle:&Arc<AtomicU8>,user_agent_epoch:Option<i64>)->bool", "LocalSessionTable");
  item(sessionTableCode, "activate_session_if_current", "pubfnactivate_session_if_current(&self,full_jid:&str,connection_id:uuid::Uuid,user_id:uuid::Uuid,auth_generation:i64,lifecycle:&Arc<AtomicU8>,disconnect:&CancellationToken)->bool", "LocalSessionTable");
  requireBoundary(item(capsCode, "session_mix_capability", "fnsession_mix_capability(&self,full_jid:&str)->MixSessionCapability", "MixOutboxPortforMixOutboxContext") ===
    "session_mix_capability_in(&self.sessions,&self.caps_by_jid,&self.pending_caps,full_jid)",
    "route helper session_mix_capability must preserve all exact capability map/index/key arguments");
}

export function verifyExecutionBoundaries(sources) {
  let { frame, bosh, boshAction, boshResponse, outbound } = sources;
  const normalize = value => compact(value).replace(/,([)}])/g, '$1');
  boshResponse = productionModule(boshResponse).replaceAll(CROSS_CRATE_TEST_ONLY, '#[cfg(test)]');
  verifyAuthPublicationBoundaries(sources);
  const observer = compact(body(frame, 'async\\s+fn\\s+observe_publication\\b'));
  requireBoundary(count(observer, '.await') === 1 && !/spawn|select!/.test(observer),
  'publication observation must preserve the typed result without adding a deadline or task');
  // The synchronous constructor owns observation before the child is polled;
  // the inner async wrapper still starts the existing timer on its first poll.
  // Result and destruction checks follow the actual runner, not an unused
  // legacy async body. These remain lexical drift checks, not execution proof.
  const run = compact(body(frame, 'pub\\s+fn\\s+run\\b'));
  requireBoundary(count(run, '.await') === 1 && count(run, 'tokio::time::timeout(') === 1
    && run.includes('poll_in_progress:false') && !/spawn|select!/.test(run),
  'frame execution must retain one first-poll timer without a new task');
  const runner = body(frame, 'impl<F,\\s*T>\\s+Future\\s+for\\s+FrameRunner<F>');
  const poll = compact(body(runner, 'fn\\s+poll\\b'));
  ordered(poll, ['this.poll_in_progress=true;', '.poll(cx)',
    'Poll::Pending=>{this.poll_in_progress=false;returnPoll::Pending;}',
    'drop(this.child.take());this.poll_in_progress=false;', 'Poll::Ready(matchresult{'],
  'frame runner must retain panic knowledge and destroy the ready child before terminal observation');
  const runnerDrop = compact(body(frame, 'impl<F>\\s+Drop\\s+for\\s+FrameRunner<F>'));
  requireBoundary(runnerDrop === 'fndrop(&mutself){drop(self.child.take());ifself.poll_in_progress{self.observation.finish(Outcome::Panicked);}}',
    'frame runner drop must destroy the child first and preserve a caught panic');
  const policy = compact(body(frame, 'fn\\s+for_frame\\b'));
  requireBoundary(policy.startsWith('letinline=transport==ClientTransport::WebSocket&&is_inline_auth(frame);') &&
    policy.includes('budget:ifinline{INLINE_AUTH_BUDGET}else{FRAME_BUDGET}'),
  'inline budget must remain restricted to guarded WebSocket inline authentication');

  const boshIngress = compact(body(bosh, 'async\\s+fn\\s+process_pending\\b'));
  requireBoundary(boshIngress.includes('matchself.protocol.process_frame(payload).await{') &&
    !boshIngress.includes('self.protocol.handle('), 'BOSH must enter the observed frame runner');
  const boshPublication = normalize(body(bosh, 'async\\s+fn\\s+finish_pending\\b'));
  const exposure = 'letexposed=matchbound.expose(pending.responders){Ok(exposed)=>exposed,Err(error)=>{tracing::error!(?error,rid);returnfalse;}};';
  const continuation = 'letready=matchexposed.publish_authentication(|owners|async{forownerinowners{if!self.protocol.publish_committed_authentication_and_route(owner).await{returnfalse;}}true}).await{Ok(ready)=>ready,Err(_)=>returnfalse};';
  requireBoundary(boshPublication.includes(exposure + continuation +
    'ready.finish(&mutself.last_response,&mutself.highest_responded,&mutself.replay).is_ok()'),
  'BOSH must observe publication only after response exposure and before cache bookkeeping');
  requireBoundary(count(boshPublication, 'bound.expose(') === 1 &&
    count(boshPublication, '.publish_committed_authentication_and_route(owner)') === 1 &&
    !boshPublication.includes('publish_committed_authentication_and_route_inner') &&
    !compact(codeOnly(productionModule(bosh))).includes('auth_publication_pending'),
  'BOSH must observe publication only after response exposure and reject publication failure');
  const gate = normalize(body(body(boshResponse, 'impl\\s+ExposedResponse\\b'), 'async\\s+fn\\s+publish_authentication\\b'));
  requireBoundary(gate === 'ifself.auth_control_selected{anyhow::ensure!(self.accepted);letselected=std::mem::replace(&mutself.auth_controls,SelectedControls::empty());letobservations=selected.observations();letowners=selected.take_all()?;anyhow::ensure!(publish(owners).await);anyhow::ensure!(observations.iter().all(|observation|observation.completed()));}Ok(PublicationReadyResponse{exposed:self})',
    'BOSH publication gate must consume selected exposure, require actual acceptance and successful lazy publication');
  // Closed lexical inventory for these three concrete owners, not a Rust
  // parser or a proof over alternate syntax, macro expansion or other files.
  const responseCode = codeOnly(boshResponse);
  const commonFields = 'metadata:Metadata,response:BoshHttpResponse,receipts:Vec<mpsc::UnboundedSender<()>>,ownership:Arc<BoshResponseOwnership>,';
  const finishHead = 'pubfnfinish(self,last_response:&mutInstant,highest_responded:&mutu64,replay:&mutVecDeque<CachedResponse>,)->Result<()>{';
  const ownerShapes = [
    ['BoundResponse', commonFields + 'bound:response::BoundResponse,auth_control_selected:bool,auth_controls:SelectedControls,auth_connection:Option<uuid::Uuid>,#[cfg(test)]selection:SelectionObservation,',
      ['selection_observation', 'for_connection', 'expose'], ['#[cfg(test)]pubfnselection_observation(&self)->SelectionObservation{', 'pubfnfor_connection(mutself,connection:uuid::Uuid)->Result<Self>{', 'pubfnexpose(mutself,responders:Vec<Responder>)->Result<ExposedResponse>{']],
    ['ExposedResponse', commonFields + 'exposure:response::Exposure,accepted:bool,auth_control_selected:bool,auth_controls:SelectedControls,',
      ['any_accepted', 'publish_authentication', 'finish'], [
        '#[cfg(test)]pubfnany_accepted(&self)->bool{',
        'pubasyncfnpublish_authentication<F:Future<Output=bool>>(mutself,publish:implFnOnce(Vec<OwnedPublication>)->F,)->Result<PublicationReadyResponse>{',
        '#[cfg(test)]' + finishHead,
      ]],
    ['PublicationReadyResponse', 'exposed:ExposedResponse,', ['finish'], [finishHead]],
  ];
  for (const [name, fields, methods, heads] of ownerShapes) {
    requireBoundary(compact(body(boshResponse, `pub\\s+struct\\s+${name}\\b`)) === fields,
      `BOSH ${name} must retain its exact private field shape`);
    const declaration = responseCode.match(new RegExp(`((?:#\\[[^\\]]*\\]\\s*)*)pub\\s+struct\\s+${name}\\b`));
    const manualCopy = new RegExp(`\\bimpl\\b[^{};]*\\b(?:Clone|Copy)\\s+for\\s+(?:\\w+\\s*::\\s*)*${name}\\b`);
    requireBoundary(declaration && !/\bderive\s*\([^)]*\b(?:Clone|Copy)\b/.test(declaration[1]) && !manualCopy.test(responseCode),
      `BOSH ${name} cannot derive or manually implement Clone or Copy`);
    const implementation = body(boshResponse, `impl\\s+${name}\\b`);
    const actualMethods = [...implementation.matchAll(/\bfn\s+(\w+)\b/g)].map(match => match[1]);
    requireBoundary(actualMethods.join(',') === methods.join(','),
      `BOSH ${name} must retain its closed inherent-method inventory`);
    for (const head of heads) {
      requireBoundary(normalize(implementation).includes(normalize(head)),
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
  const cached = compact(body(bosh, 'struct\\s+CachedResponse\\b'));
  const replay = compact(body(boshResponse, 'async\\s+fn\\s+replay_cached\\b'));
  requireBoundary(!/auth_control|auth_publication|publish_authentication/.test(cached + replay),
    'BOSH cache and replay cannot recreate auth publication membership or authority');
  const item = compact(body(outbound, 'pub\\s+struct\\s+OutboundItem\\b'));
  requireBoundary(item.includes('bosh_auth_control:bool,') && !/pub(?:\([^)]*\))?bosh_auth_control/.test(item) &&
    item.includes('auth_publication:Option<std::sync::Arc<dynAuthControl>>,') &&
    !/pub(?:\([^)]*\))?auth_publication:/.test(item) &&
    compact(body(outbound, 'fn\\s+with_auth_publication\\b')) === 'holder.validate_control(&self.stanza)?;self.bosh_auth_control=true;self.auth_publication=Some(std::sync::Arc::new(holder));Ok(self)' &&
    compact(body(outbound, 'fn\\s+is_bosh_auth_control\\b')) === 'self.bosh_auth_control',
    'BOSH auth control must remain private item selection metadata with an exact marker accessor');
  const boshApply = body(boshAction, 'async\\s+fn\\s+apply_action\\b');
  requireBoundary(!compact(boshApply).includes('publish_committed_authentication'),
    'BOSH FIFO admission must defer authentication publication until response exposure');
  const boshActivate = normalize(body(boshApply, 'Action::SendManyThenActivate\\([^)]*\\)\\s*=>'));
  ordered(boshActivate, ['ifindex==0{', 'holder.validate_connection(self.protocol.connection_id())',
    '.and_then(|_|holder.validate_control(&reply))', '.and_then(|_|holder.recording()).is_err(){returnfalse;}',
    'ifself.protocol.record_outbound(&reply).await.is_err(){returnfalse;}',
    'letitem=northstar_stream::outbound::OutboundItem::plain(reply);letitem=ifindex==0{',
    'item.with_auth_publication(holder.take().expect())', 'if!self.push_output_item(item){returnfalse;}'],
    'BOSH activation must validate before recording then enqueue the exact first control holder');
  const boshResume = normalize(body(boshApply, 'Action::Resume\\([^)]*\\)\\s*=>'));
  ordered(boshResume, ['ifactivate_route!=auth_publication.is_some(){returnfalse;}',
    'ifletSome(holder)=&auth_publication{', 'holder.validate_connection(self.protocol.connection_id())',
    '.and_then(|_|holder.validate_control(&control))', '.and_then(|_|holder.recording()).is_err(){returnfalse;}',
    'ifself.protocol.record_outbound(&control).await.is_err(){returnfalse;}',
    'ResumeTransportParts{control,post_control,replay,activate_route,auth_publication,transient_capacity}'],
    'BOSH resume must validate exact control before recording and retain its holder for atomic queue admission');
  verifyBoshSelectionObservations(sources);
  verifyRouteHelperBoundaries(sources);
}

export function verifyMucDiscussionBoundaries({ mucCore }) {
  requireBoundary(!/(?:tokio|sqlx|reqwest)::|std::(?:fs|net|time|env)::|Uuid::new_v4|ServerNode/.test(codeOnly(productionModule(mucCore))),
    'MUC discussion core must remain free of ambient I/O, clocks and application state');

}

export function verifyMixForegroundBoundaries({ mixCore, mixData, mixDb, state }) {
  const dense = source => compact(source).replace(/,([)}])/g, '$1');
  for (const source of [mixCore, mixData]) {
    requireBoundary(!/(?:tokio|sqlx|reqwest)::|std::(?:fs|net|time|env)::|Uuid::new_v4|ServerNode/.test(codeOnly(productionModule(source))),
      'MIX foreground core must remain free of ambient effects');
  }
  requireBoundary(dense(codeOnly(state)).includes('MixService::new_with_outbox_database_admission(northstar_workflows::room_effects::PostgresMixRepository::new(pool.clone()),config.domain.clone(),'),
    'MIX ServerNode construction must supply actual runtime configuration');
  const sql = dense(body(mixDb, 'async\\s+fn\\s+store_mix_message_inner\\b'));
  requireBoundary(count(sql, 'request.observed_existing(foreground_existing(&existing))?;}transaction.rollback().await?;') === 2,
    'MIX raw Existing must be retained before both rollback awaits');
}

// Finite production bindings for the Delivery worker; PAM and transport
// ownership retain their separate gates. This proves source correspondence,
// not database execution or successful effects.
export function verifyMixWorkerBoundaries({ mixWorkerCore, mixWorkerOwner, mix }) {
  const dense = source => compact(source).replace(/,([)}])/g, '$1');
  const method = (source, name) => dense(body(source, `fn\\s+${name}\\b`));
  const implementation = (source, name) => body(source, `impl\\s+${name}\\b`);
  const core = productionModule(mixWorkerCore);
  const mixProduction = withoutTestModules(mix);
  const coreCode = dense(codeOnly(core));
  requireBoundary(!/(?:tokio|sqlx|reqwest)::|std::(?:fs|net|time|env)::|Uuid::new_v4|ServerNode/.test(codeOnly(core)),
    'MIX worker core must remain free of ambient effects');
  requireBoundary(coreCode.includes('pubstructAttempt{observation:Observation}') &&
    coreCode.includes('pubstructRenewalScopeClosed{observation:Observation}') &&
    method(implementation(core, 'Observation'), 'same') === 'Arc::ptr_eq(&self.0,&other.0)',
    'MIX worker authority must use private invocation identity');
  for (const name of ['Claim', 'Attempt']) {
    const fields = dense(body(mixWorkerOwner, `struct\\s+${name}Run\\b`));
    requireBoundary(fields.startsWith('child:Option<BoxFuture<') && new RegExp(`retirement:${name}Retirement,?$`).test(fields),
      'MIX worker holder fields must destroy the child before its retirement guard');
  }
  requireBoundary(dense(body(mixProduction, 'trait\\s+ClaimedMixDeliveryPort\\b')) ===
    'fnroute(&self,request:&mix_worker::RouteRequest)->implstd::future::Future<Output=Result<ChannelStanzaDeliveryOutcome>>+Send;' +
    'fnrenew(&self,request:&mix_worker::RenewalRequest)->implstd::future::Future<Output=Result<bool>>+Send;' +
    'fnsettle(&self,request:&mix_worker::SettlementRequest)->implstd::future::Future<Output=Result<mix_worker::SettlementResult>>+Send;',
    'MIX shared policy port must contain only route and observed renewal/settlement turns');
  requireBoundary(dense(body(mixProduction, 'struct\\s+MixOutboxDeliveryPort\\b')) === 'pubcontext:Arc<C>,',
    'MIX production port must retain only its existing context');
}

export function verifyRoomExecutionBoundaries(sources) {
  verifyMucDiscussionBoundaries(sources);

  verifyMixForegroundBoundaries(sources);
  verifyMixWorkerBoundaries(sources);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const sources = readExecutionSources();
  verifyExecutionBoundaries(sources);
  verifyRoomExecutionBoundaries(sources);
  verifyNativeWriteBoundaries(sources);
  verifySmOwnershipBoundaries(sources);
  verifyBoshTransferBoundaries(sources);
  verifyBoshResponseBoundaries(sources);
  console.log('Execution publication boundaries passed');
}
