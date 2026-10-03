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

export function readExecutionSources() {
  return Object.fromEntries(Object.entries(files).map(([name, file]) => [name,
    fs.readFileSync(path.join(root, file), 'utf8')]));
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
  const run = compact(body(frame, 'async\\s+fn\\s+run\\b'));
  requireBoundary(run.includes('matchtokio::time::timeout(self.0.policy.budget,future).await{'),
    'frame execution must consume its transport-specific policy budget');
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
  console.log('Execution publication boundaries passed');
}
