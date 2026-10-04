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
  requireAdmission(newFrame.includes('direct_operation:DirectOperationHandle::new(operation_id)'),
    'each frame must own its own operation before the handler runs');
  const runFrame = compact(body(sources.frame, 'pub\\(super\\)\\s+fn\\s+run\\b'));
  ordered(runFrame, ['letobservation=Observation::new(', 'FrameRunner{',
    'child:Some(Box::pin(asyncmove{tokio::time::timeout(budget,future).await}))'],
  'frame observation and unchanged first-poll deadline');
  const runnerDrop = compact(body(sources.frame, 'impl<F>\\s+Drop\\s+for\\s+FrameRunner<F>'));
  requireAdmission(runnerDrop.includes('drop(self.child.take());'),
    'frame runner must destroy its child before ordinary observation field drop');
  const messaging = compact(codeOnly(sources.messaging));
  requireAdmission(messaging.includes('operation.begin(&request)')
    && messaging.includes('begin_message_admission_retained(&request,&retained).await')
    && messaging.includes('operation.finalize(retained_lease)')
    && messaging.includes('accept_message_admission_retained(&lease,&retained).await'),
    'actual protocol begin/finalize must use the retained frame operation');
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
