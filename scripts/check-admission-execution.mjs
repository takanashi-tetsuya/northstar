import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const paths = {
  execution: 'crates/contexts/abuse/northstar-abuse-policy/src/admission_execution.rs',
  transaction: 'crates/contexts/abuse/northstar-abuse-policy/src/admission_transaction.rs',
  lifecycle: 'crates/contexts/message/northstar-message-application/src/direct_lifecycle.rs',
  service: 'crates/contexts/message/northstar-message-application/src/message_admission.rs',
  witness: 'crates/contexts/message/northstar-message-application/src/message_admission/witness.rs',
  frame: 'crates/edges/northstar-stream/src/frame_execution.rs',
  repository: 'crates/contexts/abuse/northstar-abuse-postgres/src/message_admission.rs',
  directWorkflow: 'crates/contexts/message/northstar-message-application/src/messaging/direct_workflow.rs',
};
// The frame owner lives in northstar-stream; root saved cases reach its test-only items through test-support.
const CROSS_CRATE_TEST_ONLY = '#[cfg(any(test, feature = "test-support"))]';

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
  const pairDeclaration = /((?:#\[[^\]]*\]\s*)*)pub\s+struct\s+AppliedLocalDirect\b/.exec(production);
  requireAdmission(pairDeclaration && !/\b(?:Clone|Copy)\b/.test(pairDeclaration[1]) &&
    !/\bimpl\b[^{};]*\bAppliedLocalDirect\b/.test(production) &&
    [...production.matchAll(/\bAppliedLocalDirect\s*\{/g)].length === 2 &&
    !/\.\s*(?:actual|continuation)\b/.test(production),
  'the applied pair must retain one construction, one shared destructuring and no Clone or decomposition API');
  const pair = normalize(body(sources.directWorkflow, 'struct\\s+AppliedLocalDirect\\b'));
  requireAdmission(pair === "actual:anyhow::Result<DirectPersonalMessageAdmission>,continuation:LocalDirectContinuation<'live>",
    'the applied direct result and continuation fields must remain private');

  const continuation = normalize(body(sources.directWorkflow, 'async\\s+fn\\s+continue_prepared_local_direct\\b'));
  requireAdmission(continuation.startsWith('letAppliedLocalDirect{actual,continuation}=applied;matchactual{') &&
    continuation.split('finalize_message_admission_with(').length === 5 &&
    continuation.split('||Some(continuation.owner.clone())').length === 5 &&
    continuation.split('continuation.after_finalize(||route.direct_route_mode())').length === 3 &&
    continuation.split('route.direct_route_mode()').length === 3 &&
    !/route_prepared\(|route_with\(|try_local\(/.test(continuation),
  'shared continuation must use its sealed owner, lazy post-finalization health and no early route');
}

export function verifyAdmissionBoundaries(sources) {
  for (const name of ['execution', 'transaction', 'lifecycle']) {
    const code = codeOnly(sources[name]);
    requireAdmission(!/\b(?:ServerNode|sqlx|tokio|getrandom|rand|rand_core)\b|std\s*::\s*(?:fs|net|process|thread|env)\b|(?:Utc|SystemTime|Instant)\s*::\s*now\s*\(|Uuid\s*::\s*new_/u.test(code),
      `${name} core regained ambient authority, time, entropy or executor access`);
    requireAdmission(!/\bunsafe\b/u.test(code), `${name} core contains unsafe code`);
  }
  for (const name of ['begin_message_admission', 'accept_message_admission', 'reconcile_message_admission']) {
    const driver = compact(body(sources.service, `pub\\s+async\\s+fn\\s+${name}\\b`));
    requireAdmission(count(driver, 'witness.snapshot()') === 1 && driver.includes('observed.knowledge().clone()'),
      `${name} completion must use the single independently observed snapshot`);
  }
  // Protect the actual frame-backed path as well as the convenience drivers.
  // These anchors detect source drift; the Rust drop/fake-port tests establish
  // the behavior independently, and neither gate proves SQL conformance.
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
  const savedFrame = compact(body(sources.frame, 'pub\\s+fn\\s+for_saved_case\\b'));
  requireAdmission(savedFrame === 'Self::initialize(transport,frame,operation_id)' &&
    /#\[cfg\(test\)\]\s*pub\s+fn\s+for_saved_case\b/.test(codeOnly(sources.frame.replaceAll(CROSS_CRATE_TEST_ONLY, '#[cfg(test)]'))),
  'the test-only frame constructor must use the same initializer and supplied identity');
  verifyDirectContinuation(sources);
  const begin = compact(body(sources.repository, 'pub\\(crate\\)\\s+async\\s+fn\\s+begin_message_admission\\b'));
  requireAdmission(count(begin, 'tx.rollback().await?') === 3,
    'identity conflict and both capacity refusals retain explicit rollback');
  const finalizeDecision = compact(body(sources.transaction, 'pub\\s+fn\\s+decide_finalize\\b'));
  requireAdmission(!/expires_at|lease_expires_at|decide_actor_capacity/.test(finalizeDecision),
    'finalization must not silently acquire a new expiry or capacity policy');
  requireAdmission(!codeOnly(sources.repository).includes('.commit('),
    'rated admission commits must all pass through the scoped witness');
  return { scope: 'source-shape drift detector only', shared_cores: 3, service_commands: 5,
    retained_frame_owner: true,
    transaction_scopes: ['rated_begin', 'finalize', 'guard_only'], real_adapter_qualification: false };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log(JSON.stringify(verifyAdmissionBoundaries(readAdmissionSources())));
}
