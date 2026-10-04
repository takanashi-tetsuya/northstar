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
  muc: 'src/xmpp/protocol/muc.rs',
  mucFanout: 'src/services/muc/fanout.rs',
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
    'iferror.downcast_ref::<crate::outbound::DurableDeliverySuperseded>().is_some(){',
    'self.sm.unacked.pop_back();', 'self.sm.outbound_h=self.sm.outbound_h.wrapping_sub(1);', 'observation.restored();'],
  'SM recording must append before checkpoint and restore only typed supersession');
  requireBoundary(count(record, 'pop_back(') === 1 && count(record, '.await') === 1,
    'SM recording must retain its one checkpoint await and one typed restoration');
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

export function verifyExecutionBoundaries({ frame, protocol, transport, tcp, websocket, bosh, boshAction }) {
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
  const exposure = 'letmutexposed_to_transport=false;forresponderinpending.responders{exposed_to_transport|=responder.send(response.clone()).is_ok();}';
  const continuation = 'ifself.auth_publication_pending{if!exposed_to_transport{returnfalse;}self.auth_publication_pending=false;if!self.protocol.publish_committed_authentication_and_route().await{returnfalse;}}';
  requireBoundary(boshPublication.includes(exposure + continuation) &&
    count(boshPublication, '.publish_committed_authentication_and_route().await') === 1 &&
    !boshPublication.includes('publish_committed_authentication_and_route_inner'),
  'BOSH must observe publication only after response exposure and reject publication failure');
  const boshApply = body(boshAction, 'async\\s+fn\\s+apply_action\\b');
  requireBoundary(!compact(boshApply).includes('publish_committed_authentication'),
    'BOSH FIFO admission must defer authentication publication until response exposure');
  const boshActivate = compact(body(boshApply, 'Action::SendManyThenActivate\\([^)]*\\)\\s*=>'));
  requireBoundary(boshActivate.includes('if!self.record_and_push(reply).await{returnfalse;}ifindex==0{self.auth_publication_pending=true;}'),
    'BOSH activation must retain its pending-publication marker after first FIFO admission');
  const boshResume = compact(body(boshApply, 'Action::Resume\\([^)]*\\)\\s*=>'));
  requireBoundary(boshResume.includes('ifself.protocol.record_outbound(&control).await.is_err(){returnfalse;}ifactivate_route{self.auth_publication_pending=true;}'),
    'BOSH resume must retain its conditional pending-publication marker');
}

export function verifyRoomExecutionBoundaries({ muc, mucFanout, mix }) {
  const message = compact(body(muc, 'async\\s+fn\\s+muc_message\\b'));
  requireBoundary(message.startsWith('self.enter_frame_stage(Stage::MucPolicy);'),
    'MUC message policy stage must precede principal and protocol policy checks');
  requireBoundary(message.includes('letlocal_authority_guard=ifself.state.muc_pg_authority_enabled(){None}else{self.enter_frame_stage(Stage::MucGateWait);Some(self.state.muc_service().lock_local_room_mutation(initial_room.id).await,)};self.enter_frame_stage(Stage::MucAuthority);'),
    'MUC standalone gate wait and authority stages must surround the actual guard acquisition');
  for (const call of [
    'matchself.state.muc_service().execute_muc_retraction(',
    'matchservice.set_local_cluster_subject(',
    'matchservice.execute_muc_subject(',
    'letadmission=self.state.muc_service().execute_muc_discussion(',
  ]) {
    requireBoundary(message.includes('self.enter_frame_stage(Stage::MucAdmission);' + call),
      `MUC admission stage must immediately precede ${call}`);
  }
  requireBoundary(message.includes('MucDiscussionAdmission::Replay(_)=>{fanout_disposition=MucFanoutDisposition::Replay;}') &&
    message.includes('if!run_muc_fanout(&MucMessageFanout{session:self,room_jid:&room_jid,room_from:&room_from,sender:from,stanza:&rewritten,},fanout_disposition,).await{returnOk(Action::None);}drop(local_authority_guard);'),
  'MUC replay and accepted fanout must use the typed owner before releasing the room guard');
  const adapter = body(muc, 'impl\\s+MucFanoutPort\\s+for\\s+MucMessageFanout\\b');
  const stageAdapter = compact(body(adapter, 'fn\\s+enter\\b'));
  requireBoundary(stageAdapter === 'self.session.enter_frame_stage(matchstage{MucFanoutStage::Cluster=>Stage::MucClusterFanout,MucFanoutStage::Local=>Stage::MucLocalFanout,});',
    'MUC fanout adapter must attribute both stages to the originating session');
  const fanout = compact(body(mucFanout, 'async\\s+fn\\s+run_muc_fanout\\b'));
  requireBoundary(fanout === 'ifdisposition==MucFanoutDisposition::Replay{returnfalse;}port.enter(MucFanoutStage::Cluster);port.publish_cluster().await;port.enter(MucFanoutStage::Local);letrecipients=port.recipients();letblocked=port.blocked(&recipients).await;forrecipientinrecipients{ifport.is_blocked(&recipient,&blocked){continue;}if!port.deliver(&recipient).await{port.record_failure(&recipient);}}true',
    'MUC fanout must skip replay and preserve cluster, owned snapshot, privacy and sequential local delivery');

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
  console.log('Execution publication boundaries passed');
}
