import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const paths = {
  execution: 'crates/northstar-abuse-policy/src/admission_execution.rs',
  transaction: 'crates/northstar-abuse-policy/src/admission_transaction.rs',
  lifecycle: 'crates/northstar-message-application/src/direct_lifecycle.rs',
  service: 'src/services/message_admission.rs',
  witness: 'src/services/message_admission/witness.rs',
  frame: 'src/xmpp/frame_execution.rs',
  messaging: 'src/xmpp/protocol/messaging.rs',
  repository: 'src/db/message_admission_repository.rs',
  verification: 'src/db/abuse_verification_repository.rs',
  actor: 'src/db/abuse_actor_state_repository.rs',
  directWorkflow: 'src/services/messaging/direct_workflow.rs',
  messageService: 'src/services/messaging.rs',
};
function requireAdmission(value, message) {
  if (!value) throw new Error(`admission boundary: ${message}`);
}

// Reuse the reviewed lexical masking approach of the execution-boundary gate.
// This is deliberately a narrow source-shape drift detector, not a Rust or SQL
// semantic proof. Controlled execution, SQL conformance and review remain separate.
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
      requireAdmission(depth === 0, 'unterminated source comment');
    } else {
      const raw = /^(?:br|rb|r)(#+)?"/.exec(source.slice(index));
      if (raw) {
        const terminator = `"${raw[1] ?? ''}`;
        const end = source.indexOf(terminator, index + raw[0].length);
        requireAdmission(end >= 0, 'unterminated raw source literal');
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

function body(source, declaration, keepLiterals = false) {
  const code = codeOnly(source);
  const pattern = new RegExp(declaration, 'g');
  const matches = [...code.matchAll(pattern)];
  requireAdmission(matches.length === 1, `expected one production body: ${declaration}`);
  const opening = code.indexOf('{', matches[0].index + matches[0][0].length);
  requireAdmission(opening >= 0, `missing body: ${declaration}`);
  let depth = 1;
  for (let index = opening + 1; index < code.length; index++) {
    if (code[index] === '{') depth++;
    else if (code[index] === '}' && --depth === 0) return (keepLiterals ? source : code).slice(opening + 1, index);
  }
  throw new Error(`admission boundary: unterminated body: ${declaration}`);
}


function compact(source) { return source.replace(/\s+/g, '').replace(/,\)/g, ')'); }
function count(source, value) { return source.split(value).length - 1; }

function ordered(source, steps, label) {
  let previous = -1;
  for (const step of steps) {
    const index = source.indexOf(step, previous + 1);
    requireAdmission(index >= 0, `${label} lost ordered step ${step}`);
    previous = index;
  }
}

export function readAdmissionSources() {
  return Object.fromEntries(Object.entries(paths).map(([name, file]) => [name,
    fs.readFileSync(path.join(root, file), 'utf8')]));
}

// The result/continuation adapter is deliberately small enough to bind its
// entire forwarding body. These are source-drift checks, not a reachability
// proof or a substitute for the actual application/service tests.
function verifyDirectContinuation(sources) {
  const normalize = source => compact(source).replace(/,([)}])/g, '$1').replace(/,$/, '');
  const workflowCode = codeOnly(sources.directWorkflow);
  const testModule = /\n#\[cfg\(test\)\]\s*\nmod\s+\w+\b/.exec(workflowCode);
  const production = testModule ? workflowCode.slice(0, testModule.index) : workflowCode;
  const pairDeclaration = /((?:#\[[^\]]*\]\s*)*)pub\(crate\)\s+struct\s+AppliedLocalDirect\b/.exec(production);
  requireAdmission(pairDeclaration && !/\b(?:Clone|Copy)\b/.test(pairDeclaration[1]) &&
    !/\bimpl\b[^{};]*\bAppliedLocalDirect\b/.test(production) &&
    [...production.matchAll(/\bAppliedLocalDirect\s*\{/g)].length === 2 &&
    !/\.\s*(?:actual|continuation)\b/.test(production),
  'the applied pair must retain one construction, one shared destructuring and no Clone or decomposition API');
  const bridge = normalize(body(sources.directWorkflow, 'async\\s+fn\\s+commit_prepared_application\\b'));
  requireAdmission(bridge === 'letactual=app.commit_direct(prepared.command(),prepared.eligibility(),Some(&prepared)).await.map_err(super::direct_commit_error);AppliedLocalDirect{actual,continuation:prepared.into_continuation()}',
    'the owned application bridge must seal its actual mapped result with the same preparation continuation');
  const pair = normalize(body(sources.directWorkflow, 'struct\\s+AppliedLocalDirect\\b'));
  requireAdmission(pair === "actual:anyhow::Result<DirectPersonalMessageAdmission>,continuation:LocalDirectContinuation<'live>",
    'the applied direct result and continuation fields must remain private');
  const serviceBridge = normalize(body(sources.messageService, 'async\\s+fn\\s+admit_prepared_personal_message_with_mode\\b'));
  requireAdmission(serviceBridge === 'direct_workflow::commit_prepared_application(&self.personal,prepared).await',
    'the real message service must use the same owned application bridge');

  const finalize = normalize(body(sources.service, 'async\\s+fn\\s+finalize_message_admission_with\\b'));
  requireAdmission(finalize.startsWith('letSome(retained_lease)=lease.as_ref()else{return;};letretained=operation().map(|operation|operation.finalize(retained_lease));letlease=lease.take().expect();enter_followup();'),
    'shared finalization must lazily prepare the exact lease handle before take, stage and await');
  requireAdmission(finalize.includes('Some(Ok(retained))=>{service.accept_message_admission_retained(&lease,&retained).await}') &&
    finalize.includes('Some(Err(error))=>Err(error)') &&
    finalize.includes('None=>service.accept_message_admission(&lease).await') &&
    finalize.includes('ifletErr(error)=result{post_accept_failed();') &&
    finalize.split('.await').length === 3,
  'shared finalization must preserve retained, failed-construction and no-owner behavior without retry');
  const finalizeWrapper = normalize(body(sources.messaging, 'async\\s+fn\\s+finalize_message_admission\\b'));
  requireAdmission(finalizeWrapper === 'crate::services::message_admission::finalize_message_admission_with(self.state.message_admission_service(),lease,route,||self.message_operation(),||self.enter_frame_stage(Stage::MessageFollowup),||self.state.personal_message_telemetry().post_accept_failed()).await;',
    'protocol finalization must forward its exact lease and lazy originating owner to the shared body');

  const message = normalize(body(sources.messaging, 'async\\s+fn\\s+message\\b'));
  ordered(message, ['delayed_projection.bind(operation,admission,eligibility)',
    'letapplied=service.admit_prepared_personal_message_with_mode(prepared).await;',
    'matchcontinue_prepared_local_direct(applied,&mutmessage_admission_lease,self.state.message_admission_service(),&*self.state,||self.enter_frame_stage(Stage::MessageFollowup)).await{'],
  'actual protocol application-to-continuation wiring');
  requireAdmission(message.includes('ContinuedLocalDirect::Accepted=>returnOk(Action::None)') &&
    message.includes('ContinuedLocalDirect::Reject(error)=>{let(kind,condition)=error.stanza_error();returnOk(message_error(root,kind,condition));}') &&
    message.includes('history_committed=live.archive_written();letsource=live.source();durable_c2s_delivery=Some(source.message_id);live_claim_id=source.claim_id;prepared_live=Some(live);'),
  'protocol must consume the shared disposition without reconstructing result or delivery authority');
  requireAdmission(message.includes('self.enter_frame_stage(Stage::MessageRouting);letoutcome=ifletSome(live)=prepared_live{live.route_with(&*self.state,&targets).await?}else{') &&
    message.includes('service.admit_personal_message_with_mode(&admission,eligibility).await') &&
    message.includes('DirectMessageRouter::route(&*self.state,route_request).await?'),
  'retained routing must stay at MessageRouting and preserve the no-owner route path');

  const continuation = normalize(body(sources.directWorkflow, 'async\\s+fn\\s+continue_prepared_local_direct\\b'));
  requireAdmission(continuation.startsWith('letAppliedLocalDirect{actual,continuation}=applied;matchactual{') &&
    continuation.split('finalize_message_admission_with(').length === 5 &&
    continuation.split('||Some(continuation.owner.clone())').length === 5 &&
    continuation.split('continuation.after_finalize(||route.direct_route_mode())').length === 3 &&
    continuation.split('route.direct_route_mode()').length === 3 &&
    !/route_prepared\(|route_with\(|try_local\(/.test(continuation),
  'shared continuation must use its sealed owner, lazy post-finalization health and no early route');
  ordered(continuation, ['MessagePostCommit::RouteLocalDelivery{delivery_id,..}=post_commit',
    'finalize_message_admission_with(', 'continuation.after_finalize(||route.direct_route_mode())'],
  'stored continuation finalization boundary');
  requireAdmission(continuation.indexOf('finalize_message_admission_with(') < continuation.indexOf('continuation.after_finalize('),
    'stored continuation cannot read health before its finalization attempt returns');
  const liveImpl = body(sources.directWorkflow, 'impl\\s+PreparedLiveDirect\\b');
  requireAdmission(normalize(body(liveImpl, 'fn\\s+source\\b')) === 'self.handoff.grant.source()',
    'live continuation source must come from its retained handoff grant');
  const route = normalize(body(liveImpl, 'async\\s+fn\\s+route_with\\b'));
  for (const field of ['letlive=&self.handoff.live;', 'message_type:live.message_type,',
    'target:iflive.target==live.target_bare{super::DirectRouteTarget::Bare(live.target)}else{super::DirectRouteTarget::Full{jid:live.target,bare:live.target_bare}},',
    'sender:live.sender,', 'recipient_id:live.recipient_id,', 'stanza:live.stanza,',
    'delivery:super::DirectRouteDelivery::Committed(self.source()),', 'approved_targets,enforce_direct_health:true']) {
    requireAdmission(route.includes(field), 'late route must use the original private live projection and exact committed source');
  }
  requireAdmission(route.endsWith('super::DirectMessageRouter::route_prepared(port,request,*self.handoff).await') && route.split('.await').length === 2,
    'late live routing must consume the real handoff once through the prepared router');
}

export function verifyAdmissionBoundaries(sources) {
  for (const name of ['execution', 'transaction', 'lifecycle']) {
    const code = codeOnly(sources[name]);
    requireAdmission(!/\b(?:AppState|sqlx|tokio|getrandom|rand|rand_core)\b|std\s*::\s*(?:fs|net|process|thread|env)\b|(?:Utc|SystemTime|Instant)\s*::\s*now\s*\(|Uuid\s*::\s*new_/u.test(code),
      `${name} core regained ambient authority, time, entropy or executor access`);
    requireAdmission(!/\bunsafe\b/u.test(code), `${name} core contains unsafe code`);
  }
  const complete = compact(body(sources.execution, 'pub\\s+fn\\s+complete\\b'));
  const advance = complete.indexOf('self.state=ExecutionState::Finished(outcome)');
  for (const guard of ['validate_effect(expected,&completion.effect)?',
    'self.observed.as_ref()!=Some(&completion.knowledge)', 'validate_knowledge(expected,&completion.knowledge)?',
    'validate_result(expected,&completion.result,&completion.knowledge)?']) {
    const index = complete.indexOf(guard);
    requireAdmission(index >= 0 && advance > index,
      `completion must validate ${guard} before consuming the outstanding effect`);
  }
  const effect = compact(body(sources.execution, 'fn\\s+validate_effect\\b'));
  for (const guard of ['expected.correlation!=actual.correlation',
    'expected.command.kind()!=actual.command.kind()', 'expected.command!=actual.command']) {
    requireAdmission(effect.includes(guard), `effect validation must retain ${guard}`);
  }
  const observe = compact(body(sources.execution, 'pub\\s+fn\\s+observe_witness\\b'));
  ordered(observe, ['validate_effect(expected,witness.effect())?',
    'validate_knowledge(expected,witness.knowledge())?',
    '!knowledge_advances(prior,witness.knowledge())',
    'self.observed=Some(witness.knowledge().clone())'], 'independent witness observation');
  const knowledge = compact(body(sources.execution, 'fn\\s+knowledge_advances\\b'));
  requireAdmission(knowledge.includes('prior==next') && knowledge.includes('prepared.matches_receipt(receipt)'),
    'observed knowledge must be idempotent and retain the same prepared attempt');
  const receipt = compact(body(sources.execution, 'pub\\s+fn\\s+record_receipt\\b'));
  requireAdmission(receipt.includes('prepared.matches_receipt(&receipt)'),
    'positive receipt must match the retained prospective fact');
  requireAdmission(complete.includes('Knowledge::CommitCallEntered(prepared)=>{ExecutionOutcome::Unknown{prepared,cause}}'),
    'Unknown must retain the unconfirmed prospective transaction fact');
  for (const name of ['begin_message_admission', 'accept_message_admission', 'reconcile_message_admission']) {
    const driver = compact(body(sources.service, `pub\\(crate\\)\\s+async\\s+fn\\s+${name}\\b`));
    requireAdmission(driver.includes('coordinator.complete(Completion{') && driver.includes('matchoutcome{'),
      `${name} must consume the shared coordinator result`);
    ordered(driver, ['letobserved=witness.snapshot();', 'coordinator.observe_witness(&observed)?;',
      'coordinator.complete(Completion{'], `${name} retained witness`);
    requireAdmission(count(driver, 'witness.snapshot()') === 1 && driver.includes('observed.knowledge().clone()'),
      `${name} completion must use the single independently observed snapshot`);
  }
  // Protect the actual frame-backed path as well as the convenience drivers.
  // These anchors detect source drift; the Rust drop/fake-port tests establish
  // the behavior independently, and neither gate proves SQL conformance.
  const retainedBegin = compact(body(sources.service, 'pub\\(crate\\)\\s+async\\s+fn\\s+begin_message_admission_retained\\b'));
  ordered(retainedBegin, ['retained.start(&begin_command(request)?)?',
    'self.repository.begin(request,&witness).await', 'retained.complete(completion)?',
    'matchoutcome{'], 'retained begin');
  requireAdmission(retainedBegin.includes('retained.admission_grant()')
    && retainedBegin.includes('Some(AdmissionGrant::Reserved(')
    && retainedBegin.includes('Some(AdmissionGrant::GuardOnly('),
    'retained begin must consume the actual closed admission grant');
  const retainedFinalize = compact(body(sources.service, 'pub\\(crate\\)\\s+async\\s+fn\\s+accept_message_admission_retained\\b'));
  ordered(retainedFinalize, ['letacceptance=lease.acceptance();',
    'retained.start(&Command::Finalize(acceptance_fence(&acceptance)))?',
    'self.repository.accept(&acceptance,&witness).await', 'retained.complete(completion)?'],
  'retained finalization');
  const lifecycleComplete = compact(body(sources.lifecycle, 'pub\\s+fn\\s+complete\\b'));
  ordered(lifecycleComplete, ['execution.coordinator.observe_witness(&execution.witness)?',
    'execution.coordinator.complete(Completion{'], 'outer owner completion');
  const startEffect = compact(body(sources.lifecycle, 'pub\\s+fn\\s+start_effect\\b'));
  ordered(startEffect, ['self.validate_request(handle,command)?', 'ifexecution.started{',
    'execution.started=true'], 'single repository invocation');
  const retainedRequest = compact(body(sources.lifecycle, 'pub\\s+fn\\s+validate_request\\b'));
  requireAdmission(retainedRequest.includes('execution.handle.effect.command!=*command'),
    'retained input must match the complete immutable command');
  for (const method of ['enter_commit', 'record_receipt']) {
    const owned = compact(body(sources.lifecycle, `pub\\s+fn\\s+${method}\\b`));
    ordered(owned, ['execution.coordinator.pending().is_none()',
      `execution.witness.${method}(`], `finished effect ${method}`);
  }
  const grant = compact(body(sources.lifecycle, 'pub\\s+fn\\s+admission_grant\\b'));
  requireAdmission(grant.includes('ExecutionState::Finished(ExecutionOutcome::Completed{')
    && grant.includes('execution.coordinator.state()')
    && grant.includes('BeginResult::Reserved(')
    && grant.includes('BeginResult::GuardOnly(GuardDecision::Allowed)'),
    'admission grant must follow the real successful coordinator completion');
  const newFrame = compact(body(sources.frame, 'pub\\(super\\)\\s+fn\\s+new\\b'));
  requireAdmission(newFrame === 'Self::initialize(transport,frame,Uuid::new_v4())',
    'production frames must preserve fresh identity through the shared initializer');
  const initializeFrame = compact(body(sources.frame, 'fn\\s+initialize\\b'));
  requireAdmission(initializeFrame === 'Self(Arc::new(Progress{' +
    'operation_id,direct_operation:DirectOperationHandle::new(operation_id),' +
    'muc_discussion:MucDiscussionSlot::default(),' +
    'mix_foreground:MixForegroundSlot::default(),' +
    'auth_receipt:std::sync::Mutex::new(None),' +
    'credential_attempts:std::sync::Mutex::new(CredentialAttempts::default()),' +
    'sequence:NEXT_SEQUENCE.fetch_add(1,Ordering::Relaxed),' +
    'policy:Policy::for_frame(transport,frame),stage:AtomicU8::new(Stage::Validationasu8),' +
    'started:tokio::time::Instant::now(),outcome:AtomicU8::new(Outcome::Pendingasu8),}))',
  'the shared initializer must retain the exact owner, sequence, policy and initial observation');
  const savedFrame = compact(body(sources.frame, 'pub\\(super\\)\\s+fn\\s+for_saved_case\\b'));
  requireAdmission(savedFrame === 'Self::initialize(transport,frame,operation_id)' &&
    /#\[cfg\(test\)\]\s*pub\(super\)\s+fn\s+for_saved_case\b/.test(codeOnly(sources.frame)),
  'the test-only frame constructor must use the same initializer and supplied identity');
  const runFrame = compact(body(sources.frame, 'pub\\(super\\)\\s+fn\\s+run\\b'));
  ordered(runFrame, ['letobservation=Observation::new(', 'FrameRunner{',
    'child:Some(Box::pin(asyncmove{tokio::time::timeout(budget,future).await}))'],
  'frame observation and unchanged first-poll deadline');
  const runnerDrop = compact(body(sources.frame, 'impl<F>\\s+Drop\\s+for\\s+FrameRunner<F>'));
  requireAdmission(runnerDrop.includes('drop(self.child.take());'),
    'frame runner must destroy its child before ordinary observation field drop');
  const messaging = compact(codeOnly(sources.messaging));
  requireAdmission(messaging.includes('operation.begin(&request)')
    && messaging.includes('begin_message_admission_retained(&request,&retained).await'),
    'actual protocol begin must use the retained frame operation');
  verifyDirectContinuation(sources);
  const begin = compact(body(sources.repository, 'pub\\(crate\\)\\s+async\\s+fn\\s+begin_message_admission\\b'));
  const beginDecision = begin.indexOf('decision::decide_begin(');
  const fetchedRows = begin.indexOf('.fetch_all(&mut*tx).await?');
  requireAdmission(fetchedRows >= 0 && beginDecision > fetchedRows,
    'begin row decision must consume fetched locked rows');
  requireAdmission(begin.includes('matchrow_decision{') && begin.includes('decision::decide_actor_capacity(active_for_user)')
    && begin.includes('decision::decide_shard_reservation(capacity_reserved)'),
    'actual begin branches must use shared row and authoritative capacity decisions');
  requireAdmission(count(begin, 'tx.rollback().await?') === 3,
    'identity conflict and both capacity refusals retain explicit rollback');
  const finalize = compact(body(sources.repository, 'async\\s+fn\\s+accept_observed\\b'));
  requireAdmission(finalize.includes('letresult=decision::decide_finalize(row.as_ref(),&fence);')
    && finalize.includes('matchresult{') && finalize.includes('decision::accepted_expiry(now)'),
    'actual finalize branch and accepted expiry must use shared decisions');
  const finalizeSql = body(sources.repository, 'async\\s+fn\\s+accept_observed\\b', true);
  ordered(finalizeSql, ['pool.begin().await?', 'pg_advisory_xact_lock', 'FOR UPDATE',
    'decision::decide_finalize', "SET state='accepted'", 'commit_observed('], 'finalize SQL authority');
  const finalizeDecision = compact(body(sources.transaction, 'pub\\s+fn\\s+decide_finalize\\b'));
  ordered(finalizeDecision, ['letSome(row)=rowelse', 'ct_eq(&fence.admission_key)',
    'ct_eq(&fence.payload_mac)', 'row.state==RowState::Accepted',
    'row.lease_token!=fence.lease_token', 'FinalizeDecision::AcceptPending'], 'shared finalize fence');
  requireAdmission(!/expires_at|lease_expires_at|decide_actor_capacity/.test(finalizeDecision),
    'finalization must not silently acquire a new expiry or capacity policy');
  const acceptService = compact(body(sources.service, 'pub\\(crate\\)\\s+async\\s+fn\\s+accept_message_admission\\b'));
  requireAdmission(acceptService.includes('letacceptance=lease.acceptance();')
    && acceptService.includes('self.repository.accept(&acceptance,&witness).await'),
    'service finalization must consume the issued lease fence through the repository');
  const reconcile = compact(body(sources.repository, 'async\\s+fn\\s+reconcile\\b'));
  requireAdmission(reconcile.includes('decision::reconcile(row.as_ref(),fence,now)') && reconcile.includes('tx.rollback().await?'),
    'read-only reconciliation must use shared row interpretation and close its transaction');
  requireAdmission(!codeOnly(sources.repository).includes('.commit('),
    'rated admission commits must all pass through the scoped witness');
  for (const purpose of ['ReplayRead', 'PendingRequirement', 'Reclaim', 'GuardDenial', 'NewReservation']) {
    requireAdmission(begin.includes(`TransactionScope::RatedBegin(BeginCommitPurpose::${purpose})`),
      `rated commit purpose ${purpose} lost its distinct witness scope`);
  }
  requireAdmission(finalize.includes('TransactionScope::AdmissionFinalize'), 'finalization lost its transaction scope');
  const commit = compact(body(sources.witness, 'pub\\(crate\\)\\s+async\\s+fn\\s+commit_observed\\b'));
  requireAdmission(commit === 'letprepared=witness.prepare(scope,fact)?;tx.commit().await?;witness.received(prepared);Ok(())',
    'COMMIT must record caller entry before its sole await and positive receipt synchronously afterward');
  const verify = compact(body(sources.verification, 'pub\\(crate\\)\\s+async\\s+fn\\s+verify\\b'));
  requireAdmission(verify.includes('ifletSome(witness)=witness{')
    && verify.includes('TransactionScope::GuardOnlyVerification')
    && verify.includes('CommitFact::GuardOnly(decision)'),
    'guard-only persistence must retain its own optional scoped witness');
  for (const anchor of ['pg_try_advisory_xact_lock', 'FOR UPDATE NOWAIT', 'AbuseStateBusy', 'keys.sort();', 'keys.dedup();']) {
    requireAdmission(sources.actor.includes(anchor), `actor transaction authority lost ${anchor}`);
  }
  for (const anchor of ['pg_advisory_xact_lock', 'FOR UPDATE', 'clock_timestamp()',
    'LIMIT 128 FOR UPDATE SKIP LOCKED', 'active_records < $2', 'expires_at > $2', 'expires_at <= $2']) {
    requireAdmission(sources.repository.includes(anchor), `admission SQL authority lost ${anchor}`);
  }
  return { scope: 'source-shape drift detector only', shared_cores: 3, service_commands: 5,
    retained_frame_owner: true,
    transaction_scopes: ['rated_begin', 'finalize', 'guard_only'], real_adapter_qualification: false };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log(JSON.stringify(verifyAdmissionBoundaries(readAdmissionSources())));
}
