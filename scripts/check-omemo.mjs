import fs from 'node:fs';

const omemo = fs.readFileSync(new URL('../web/omemo.js', import.meta.url), 'utf8');
const xmpp = fs.readFileSync(new URL('../web/xmpp.js', import.meta.url), 'utf8');
const client = fs.readFileSync(new URL('../web/client.js', import.meta.url), 'utf8');
const recovery = fs.readFileSync(new URL('../web/omemo-recovery.mjs', import.meta.url), 'utf8');
const recoveryWorker = fs.readFileSync(new URL('../web/omemo-recovery-worker.mjs', import.meta.url), 'utf8');
const recoveryWorkerClient = fs.readFileSync(new URL('../web/omemo-recovery-worker-client.mjs', import.meta.url), 'utf8');
const recoveryApi = fs.readFileSync(new URL('../src/api/omemo_recovery.rs', import.meta.url), 'utf8');
const recoveryDb = fs.readFileSync(new URL('../src/db/omemo_recovery.rs', import.meta.url), 'utf8');
const serverState = fs.readFileSync(new URL('../src/state.rs', import.meta.url), 'utf8');
const metrics = fs.readFileSync(new URL('../src/metrics.rs', import.meta.url), 'utf8');

function requirePattern(source, pattern, message) {
  if (!pattern.test(source)) throw new Error(message);
}

function functionSection(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  if (start < 0 || end < 0) throw new Error(`could not isolate ${startMarker}`);
  return source.slice(start, end);
}

const exportTransferFlow = functionSection(
  client,
  'async function exportOmemoDevice(event)',
  'function clearOmemoTransferWatch()',
);
const transferWatchFlow = functionSection(
  client,
  'function watchPendingOmemoTransfer()',
  'async function cancelPendingOmemoTransfer(event)',
);
const importTransferFlow = functionSection(
  client,
  'async function importOmemoDevice(event)',
  'function logout(',
);
const initializeFlow = functionSection(
  omemo,
  'async initializeLocked()',
  'destroy()',
);

requirePattern(omemo, /const STORE_VERSION = 5;/, 'OMEMO persisted-state migration version is missing');
requirePattern(omemo, /const SEALED_STATE_VERSION = 1;/, 'OMEMO private state is not versioned as a sealed envelope');
requirePattern(initializeFlow, /upgradeState\(\)[\s\S]+validatePersistedOmemoState\(this\.state\)[\s\S]+replaceLegacyPlaintextState\([\s\S]+validateRecoveryAuthorityLocked\(\)/, 'legacy plaintext OMEMO state is not validated and atomically sealed before recovery authority I/O');
if (initializeFlow.indexOf('replaceLegacyPlaintextState(')
  > initializeFlow.indexOf('validateRecoveryAuthorityLocked()')) {
  throw new Error('recovery authority is consulted before legacy plaintext OMEMO state is sealed');
}
requirePattern(omemo, /async function replaceLegacyPlaintextState[\s\S]+validatePersistedOmemoState\(state\)[\s\S]+await write\('crypto', bareJid\(account\), sealed\)/, 'legacy OMEMO migration does not validate before its atomic same-key replacement');
requirePattern(recovery, /memory_kib: 65536[\s\S]+iterations: 3[\s\S]+parallelism: 1/, 'OMEMO transfer packages do not use the fixed Argon2id profile');
requirePattern(recovery, /AES-256-GCM[\s\S]+additionalData/, 'OMEMO transfer packages are not authenticated with AES-256-GCM and bound metadata');
requirePattern(omemo, /lookupRecoveryAuthority[\s\S]+latest_consumed_generation/, 'a moved OMEMO source device can reconnect without a server generation fence');
requirePattern(client, /installDeviceTransfer[\s\S]+\/consume/, 'the browser does not commit one-time OMEMO transfer consumption after local installation');
requirePattern(omemo, /state: 'distrusted'[\s\S]+recoveryReverification: true/, 'OMEMO transfer import does not force explicit contact re-verification');
requirePattern(exportTransferFlow, /authorityBaseline[\s\S]+freezeDeviceTransfer\(transferId, pollSecret, baselineGeneration\);[\s\S]+sourceFrozen = true;[\s\S]+state\.xmpp\?\.disconnect\(\);[\s\S]+request\('\/api\/v1\/me\/omemo-recovery-transfers'[\s\S]+watchPendingOmemoTransfer\(\);/, 'the source browser does not persist an authority baseline before it freezes, disconnects, allocates, and monitors the transfer');
requirePattern(transferWatchFlow, /validateRecoveryAuthority\([\s\S]+recoveryWatchCurrent[\s\S]+state\.omemoTransferId = null;[\s\S]+maybeReconnect\(\)[\s\S]+watchPendingOmemoTransfer\(\);/, 'the frozen source does not poll fenced authority before reactivation and keep retrying fail closed');
requirePattern(importTransferFlow, /catch \(consumeError\)[\s\S]+transferAfter = await request[\s\S]+authorityAfter = await request\('\/api\/v1\/me\/omemo-recovery-authority'\)[\s\S]+catch \{[\s\S]+logout\([\s\S]+return;[\s\S]+const committed =[\s\S]+if \(!committed\) throw consumeError;/, 'an ambiguous transfer commit can erase the only winning destination state');
requirePattern(omemo, /REPLACEMENT_JOURNAL_PREFIX[\s\S]+await setValue\([\s\S]+replacementJournalName/, 'device replacement is not journaled before retiring the destination state');
requirePattern(omemo, /journalMatchesInstalledState[\s\S]+OMEMO_DEVICE_RETIRED/, 'an interrupted destination replacement can resurrect an unmarked local device');
requirePattern(omemo, /replacementJournalName\(account\)[\s\S]+keyErasureComplete/, 'remote retirement does not erase the independent replacement journal');
requirePattern(client, /replacementStarted = true[\s\S]+eraseInstalledDeviceTransfer/, 'partial replacement failures do not enter fail-closed local erasure');
requirePattern(omemo, /freezeDeviceTransfer[\s\S]+generation: null[\s\S]+pollSecret[\s\S]+store\.persist/, 'the source is not durably frozen before transfer allocation');
requirePattern(omemo, /delete snapshot\.recoveryTransfer/, 'the source poll capability leaks into the destination package');
requirePattern(omemo, /consumerCommitment[\s\S]+await this\.retireOwnDevice/, 'the destination replacement journal does not precede remote retirement');
requirePattern(omemo, /async quiesceStateOperations\(\)[\s\S]+await this\.store\?\.flush/, 'destination replacement cannot quiesce ratchets while retaining its Web Lock');
const installTransfer = functionSection(omemo, 'async installDeviceTransfer(', 'async markDeviceTransferPhase(');
requirePattern(installTransfer, /await this\.retireOwnDevice\(\);[\s\S]+await this\.quiesceStateOperations\(\);/, 'destination replacement releases or fails to quiesce the account Web Lock');
if (/await this\.destroy\(\)/.test(installTransfer)) throw new Error('destination replacement releases its account Web Lock before commit resolution');
requirePattern(client, /omitAuthorization: true[\s\S]+poll_secret: pollSecret/, 'source completion still depends on the bearer revoked by consume');
requirePattern(client, /consumer_secret: consumerSecret/, 'consume is not proven by a private 256-bit destination secret');
requirePattern(client, /retryPendingRecoveryConsume:[\s\S]+consumer_secret: consumerSecret/, 'an installed destination cannot replay an ambiguously committed consume after login');
requirePattern(omemo, /retryPendingRecoveryConsume[\s\S]+resolvePendingRecoveryTransfer/, 'consume replay is not followed by an authenticated authority decision');
requirePattern(omemo, /validateTransferredOmemoState\([\s\S]+await this\.retireOwnDevice/, 'transferred ratchet state is not strictly validated before destructive replacement');
requirePattern(omemo, /SessionRecord\.deserialize[\s\S]+record\.serialize/, 'serialized Double Ratchet records are not decoded and canonicalized before replacement');
requirePattern(recoveryWorkerClient, /new Worker\([\s\S]+type: 'module'[\s\S]+worker\.terminate/, 'OMEMO transfer cryptography is not isolated in a terminating module worker');
requirePattern(recoveryWorkerClient, /signal\?\.addEventListener\('abort', abort/, 'OMEMO transfer worker cannot be cancelled');
requirePattern(recoveryWorkerClient, /signal\?\.removeEventListener\('abort', abort/, 'OMEMO transfer worker leaks its abort listener');
requirePattern(recoveryWorkerClient, /deadline = setTimeout[\s\S]+deadlineMs/, 'OMEMO transfer worker has no hard deadline');
requirePattern(recoveryWorkerClient, /clearTimeout\(deadline\)[\s\S]+worker\.terminate\(\)/, 'OMEMO transfer worker is not terminated on every settled path');
requirePattern(recoveryWorkerClient, /requiredBytes <= budgetBytes[\s\S]+navigator\.deviceMemory/, 'OMEMO transfer worker lacks a device-memory budget');
requirePattern(serverState, /OMEMO_POLL_CONCURRENCY: usize = 4[\s\S]+OMEMO_POLL_IP_REQUESTS_PER_MINUTE: usize = 30[\s\S]+omemo_recovery_poll_pool: PgPool/, 'public OMEMO recovery polling lacks independent bounded admission and database isolation');
requirePattern(recoveryApi, /client_ip\(peer\.ip\(\), &headers, &state\)[\s\S]+acquire_omemo_recovery_poll[\s\S]+db::poll_omemo_recovery_transfer/, 'poll admission must use the trusted-proxy client IP and precede every database lookup');
requirePattern(recoveryDb, /pool\.begin\(\)[\s\S]+SET LOCAL statement_timeout = '1500ms'[\s\S]+fetch_optional\(&mut \*tx\)/, 'public recovery polling has no transaction-local bounded database execution time');
if (/admit_omemo_poll_ip_window\(&mut window, now\)[\s\S]{0,300}window\.push_back\(now\)/.test(serverState)) {
  throw new Error('public recovery poll admission counts one request twice');
}
requirePattern(omemo, /state: 'locally-unallocated'[\s\S]+state: polled\.state/, 'source crash recovery does not distinguish unallocated and server-prepared frozen states');
requirePattern(client, /if \(ownDevice\.recoveryFrozen\)[\s\S]+state\.omemoTransferId = ownDevice\.transferId[\s\S]+watchPendingOmemoTransfer\(\)/, 'login does not rebuild the recoverable frozen source UI');
requirePattern(omemo, /latest_consumed_transfer_id === marker\.transferId[\s\S]+OMEMO_DEVICE_RETIRED[\s\S]+state: 'authority-advanced'/, 'advanced authority neither retires the consumed source nor preserves an unrelated-transfer lock');
requirePattern(exportTransferFlow, /recovered\.generation !== null[\s\S]+await pauseOmemoRecoveryWatch\(\)[\s\S]+method: 'DELETE'[\s\S]+replaceSourceRecoveryMarker[\s\S]+markerReplaced = true[\s\S]+omemoRecoveryTransition = false[\s\S]+watchPendingOmemoTransfer\(\)/, 'prepared replacement does not fence and await observation until its new frozen marker is durable');
requirePattern(omemo, /async replaceSourceRecoveryMarker[\s\S]+quiesceStateOperations\(\)[\s\S]+latest_consumed_generation[\s\S]+this\.state\.recoveryTransfer = \{[\s\S]+await this\.store\.persist\(\)/, 'prepared recovery crosses an unfrozen or markerless ratchet window');
requirePattern(exportTransferFlow, /if \(markerReplaced\)[\s\S]+watchPendingOmemoTransfer\(\)[\s\S]+else if \(sourceFrozen\)/, 'a failed replacement prepare can discard its new frozen marker');
requirePattern(client, /async function pauseOmemoRecoveryWatch\(\)[\s\S]+omemoRecoveryTransition = true[\s\S]+clearOmemoTransferWatch\(\)[\s\S]+await state\.omemoTransferWatchInFlight/, 'repackage does not wait for an already-running authority watcher');
requirePattern(client, /function recoveryWatchCurrent[\s\S]+omemoTransferWatchEpoch === epoch[\s\S]+omemoTransferId === transferId/, 'authority watcher lacks an epoch and transfer-id fence');
requirePattern(client, /validateRecoveryAuthority\([\s\S]+recoveryWatchCurrent\(epoch, transferId\)[\s\S]+if \(!recoveryWatchCurrent\(epoch, transferId\)\) return;/, 'authority watcher does not revalidate its fence after asynchronous authority work');
requirePattern(omemo, /validateRecoveryAuthorityLocked\(isCurrent[\s\S]+if \(!isCurrent\(\)\) return \{ stale: true \};[\s\S]+if \(\['revoked', 'expired'\]/, 'authority validation can mutate a marker after its watcher became stale');
requirePattern(client, /if \(!confirm\([\s\S]+\)\) return;[\s\S]+omemoTransferAbortController\?\.abort\(\)/, 'declining transfer cancellation still aborts the worker');
requirePattern(metrics, /xmpp_omemo_recovery_poll_requests_total \{\}[\s\S]+xmpp_omemo_recovery_poll_rate_limited_total \{\}[\s\S]+xmpp_omemo_recovery_poll_concurrency_rejected_total \{\}/, 'poll metrics must remain aggregate and fixed-cardinality');
requirePattern(recoveryWorker, /payload\.passphrase = ''[\s\S]+payload\.state = null/, 'OMEMO worker does not discard sensitive request references');
requirePattern(omemo, /generateKey\(\{ name: 'AES-GCM', length: 256 \}, false, \['encrypt', 'decrypt'\]\)/, 'OMEMO wrapping key is not non-exportable AES-256-GCM');
requirePattern(omemo, /additionalData = stateAdditionalData\(account\)[\s\S]+additionalData,/, 'sealed OMEMO state is not bound to its account');
requirePattern(omemo, /setValue\('crypto', this\.account, sealed\)/, 'OMEMO persistence does not store the sealed envelope');
requirePattern(omemo, /nextPreKeyId/, 'OMEMO prekeys do not use rotating IDs');
requirePattern(omemo, /retiredPrekeys[\s\S]+RETIRED_PREKEY_RETENTION_MS/, 'consumed OMEMO prekeys are not retained safely for delayed concurrent sessions');
requirePattern(omemo, /this\.state\.prekeys\[String\(keyId\)\][\s\S]+this\.state\.retiredPrekeys/, 'MAM catch-up cannot load a recently consumed prekey');
requirePattern(omemo, /randomOmemoId/, 'OMEMO device ids are not drawn from a 31-bit collision-resistant space');
requirePattern(omemo, /rotateSignedPreKeyIfNeeded/, 'OMEMO signed prekeys are never rotated');
requirePattern(omemo, /oldSignedPreKeys/, 'old signed prekeys are not retained for delayed messages');
requirePattern(omemo, /trustDecisions/, 'OMEMO trust decisions are not persisted');
requirePattern(omemo, /setDeviceTrust\(peer, deviceId, expectedIdentity, state\)/, 'explicit OMEMO trust management is missing');
requirePattern(omemo, /currentIdentity !== expectedIdentity/, 'OMEMO trust confirmation is vulnerable to an identity-change race');
requirePattern(omemo, /identity\.trustState === 'changed'/, 'identity changes do not block outbound OMEMO sessions');
requirePattern(omemo, /identity\.trustState === 'distrusted'/, 'distrusted OMEMO devices are not excluded from encryption');
requirePattern(omemo, /decision\?\.identity === encodedIdentity && decision\.state === 'tofu' && decision\.accepted === true/, 'TOFU acceptance is not distinguished from an undecided first-seen key');
requirePattern(omemo, /explicitlyTofu[\s\S]+decision\.accepted === true[\s\S]+trustState:/, 'incoming opt-out can treat an undecided first-seen key as explicit TOFU');
requirePattern(omemo, /!\['verified', 'tofu'\]\.includes\(identity\.trustState\)[\s\S]+发送已暂停/, 'devices without an explicit trust decision can still receive outbound content keys');
requirePattern(omemo, /assertEncryptable\(peer\)[\s\S]+establishSessions: false/, 'direct-message trust preflight can advance an OMEMO ratchet');
requirePattern(omemo, /assertGroupEncryptable\(peers, roomJid\)[\s\S]+establishSessions: false/, 'group-message trust preflight can advance an OMEMO ratchet');
requirePattern(omemo, /encryptGroup\(peers, plaintext, roomJid,/, 'group OMEMO does not require an explicit room context');
requirePattern(omemo, /const toAffix = to \? `<to jid=/, 'group OMEMO SCE does not emit a to affix');
requirePattern(omemo, /toElements\.length !== 1[\s\S]+OMEMO 群聊上下文校验失败/, 'group OMEMO SCE does not verify its room context');
requirePattern(omemo, /strictBareJid\(fromElements\[0\]\.getAttribute\('jid'\)/, 'SCE from affixes accept resource-bearing JIDs');
requirePattern(omemo, /strictBareJid\(toElements\[0\]\.getAttribute\('jid'\)/, 'SCE to affixes accept resource-bearing JIDs');
requirePattern(omemo, /SCE_MINIMUM_ENVELOPE_CHARACTERS[\s\S]+randomUintBelow\(201\)/, 'SCE padding does not use a fixed minimum plus randomized extra length');
requirePattern(omemo, /longer-than-expected random padding MUST[\s\S]+padding\.length !== 1/, 'incoming SCE incorrectly rejects long authenticated padding');
requirePattern(omemo, /MAX_SCE_TIME_SKEW_MS[\s\S]+referenceTime/, 'SCE time affixes are not checked against delivery or archive time');
requirePattern(omemo, /messages? (?:is|are)?from .*distrusted|消息来自已标记为不信任/, 'messages from distrusted devices are not rejected');
requirePattern(omemo, /function parseDeviceList\(devices\)/, 'strict OMEMO device-list parsing is missing');
requirePattern(omemo, /function parseBundleElement\(bundle, jid, deviceId\)/, 'strict OMEMO bundle parsing is missing');
requirePattern(omemo, /function parseEncryptedElement\(encrypted\)/, 'strict incoming OMEMO message parsing is missing');
requirePattern(omemo, /prekeyElements\.length < 25/, 'incoming OMEMO bundles do not enforce the 25-prekey minimum');
requirePattern(omemo, /direct\[0\]\?\.localName !== 'header'/, 'incoming OMEMO envelopes do not enforce header-before-payload order');
requirePattern(omemo, /MAX_OMEMO_PAYLOAD_BYTES/, 'incoming OMEMO payloads are not size bounded');
requirePattern(omemo, /emptyKey\.byteLength !== 32[\s\S]+byte !== 0/, 'empty OMEMO messages do not require the standard zero key');
requirePattern(omemo, /encryptEmpty\(peer, recipientDevice\)/, 'OMEMO key-exchange acknowledgements and heartbeats are missing');
requirePattern(omemo, /resetSession\(peer, deviceId\)/, 'manual OMEMO session replacement is missing');
requirePattern(client, /omemo-session-reset/, 'manual OMEMO session replacement is not exposed in the web client');
requirePattern(omemo, /MessageCounterError[\s\S]+duplicate: true/, 'duplicate ratchet messages are not silently ignored');
requirePattern(omemo, /withSessionOperation\(address, operation\)/, 'ratchet operations are not serialized per remote device');
requirePattern(omemo, /requireOmemoKeyExchangePreKey\(keyBytes\)/, 'incoming key exchanges do not enforce the mandatory one-time PreKey');
requirePattern(omemo, /silently degrades X3DH to a weaker three-DH exchange/, 'the mandatory OMEMO X3DH PreKey boundary is undocumented');
requirePattern(omemo, /device-list refresh failed during decryption; continuing with authenticated ratchet state/, 'a transient PEP failure still blocks decryption of an established session');
requirePattern(omemo, /ed25519PubKeyToCurvePubKey/, 'displayed OMEMO fingerprints are not converted to Curve25519');
requirePattern(omemo, /urn:xmpp:sfs:0/, 'XEP-0447 stateless file sharing is missing');
requirePattern(omemo, /urn:xmpp:esfs:0/, 'XEP-0448 encrypted sources are missing');
requirePattern(omemo, /aesgcm:\/\//, 'XEP-0454 media-sharing fallback is missing');
requirePattern(omemo, /encryptedHash/, 'encrypted file hashes are not authenticated inside OMEMO SCE');
requirePattern(omemo, /urn:xmpp:tm:1/, 'XEP-0434 Trust Messages are missing');
requirePattern(omemo, /urn:xmpp:atm:1/, 'XEP-0450 Automatic Trust Management is missing');
requirePattern(omemo, /function parseOptOut\(element\)/, 'XEP-0384 encrypted plaintext opt-out parsing is missing');
requirePattern(omemo, /async encryptOptOut\(peer, reason = ''\)/, 'the web client can receive but cannot send XEP-0384 opt-out');
requirePattern(client, /blocked-optout[\s\S]+Northstar 不允许降级为明文/, 'incoming plaintext opt-out is not fail closed');
requirePattern(client, /Northstar 已阻止此降级请求/, 'incoming plaintext downgrade attempts are not visibly rejected');
if (/requestPlaintextConversation|plaintextAllowed|securityModes\.set\([^)]*,\s*['"]plaintext['"]\)/.test(client)) {
  throw new Error('the web client still exposes a plaintext fallback path');
}
if (/\.sendChatState\(/.test(client)) {
  throw new Error('the OMEMO-only web client still leaks typing state outside SCE');
}
requirePattern(omemo, /pendingTrustMessages/, 'trust messages from unauthenticated or unknown endpoints are not persisted');
requirePattern(omemo, /lastTrustTimestamps/, 'trust-message replay and ordering state is missing');
requirePattern(omemo, /scheduleTrustPropagation/, 'manual trust decisions are not propagated through authenticated endpoints');
requirePattern(omemo, /prepareOutbound[\s\S]+kind: 'trust'[\s\S]+encryptWithBundles/, 'trust messages advance the ratchet before anti-abuse preparation');
requirePattern(omemo, /sendEncrypted\(record\)/, 'trust messages bypass the durable encrypted transport');
requirePattern(client, /sendEncrypted: sendDurableEncrypted/, 'OMEMO trust messages are not connected to the encrypted outbox');
requirePattern(omemo, /senderOwner !== this\.account && owner\.jid !== senderOwner/, 'authenticated contact endpoints can act as trust oracles for third-party accounts');
requirePattern(omemo, /existing && !existing\.automatic[\s\S]+entry\.state !== 'distrusted'/, 'automatic trust assertions can overwrite explicit local distrust decisions');
requirePattern(omemo, /contactTargets[\s\S]+sendTrustMessage\(target, singleDecision\)/, 'ATM leaks unrelated contact trust decisions to other contacts');
requirePattern(omemo, /MAX_TRUST_CLOCK_SKEW_MS/, 'future-dated trust messages can freeze later trust changes');
requirePattern(omemo, /MAX_TRUST_ENTRIES/, 'trust-message and deferred ATM state are not resource bounded');
requirePattern(omemo, /MAX_PENDING_TRUST_MESSAGES/, 'deferred ATM messages are not resource bounded');
requirePattern(omemo, /Local OMEMO state exceeds the safety limit/, 'oversized local ratchet state is encrypted without a pre-allocation limit');
requirePattern(omemo, /Promise\.allSettled\(operations\)[\s\S]+store\?\.flush\(\)/, 'logout can invalidate OMEMO state while ratchet persistence is still in flight');
requirePattern(omemo, /await this\.destroy\(\);[\s\S]+deleteValue\('crypto'/, 'secure erasure can be undone by a late IndexedDB write');
requirePattern(xmpp, /getMucAffiliations\(room, affiliation\)/, 'MUC affiliation lists are unavailable to OMEMO recipient selection');
requirePattern(client, /room\.affiliates\.keys\(\)/, 'offline MUC owners, admins and members are omitted from OMEMO recipients');
requirePattern(client, /Promise\.all\(\[[\s\S]+getDiscoFeatures[\s\S]+getMucAffiliations/, 'MUC encryption does not require a complete room discovery and affiliation snapshot');
requirePattern(client, /features\.has\('muc_nonanonymous'\)/, 'MUC encryption does not reject anonymous rooms');
requirePattern(client, /!room\.omemoRoomVerified \|\| !room\.affiliatesReady/, 'MUC encryption can proceed with an incomplete recipient list');
requirePattern(xmpp, /mamQueries\.has\(queryId\)/, 'unsolicited MAM results are not rejected');
requirePattern(xmpp, /来源不匹配的 Message Carbon/, 'Message Carbon outer senders are not authenticated');
requirePattern(xmpp, /origin-id xmlns=/, 'outgoing messages do not carry XEP-0359 origin ids');
requirePattern(client, /sid:\$\{stanzaIds\[0\]\.by\}/, 'message deduplication is not scoped by XEP-0359 assigning entity');
requirePattern(client, /readResponseLimited/, 'encrypted attachment downloads are not size bounded');
requirePattern(client, /referrerPolicy: 'no-referrer'/, 'encrypted attachment downloads disclose the conversation origin as a referrer');
requirePattern(client, /validateEncryptedAttachmentUrl\(response\.url\)/, 'encrypted attachment redirect endpoints do not reuse the exact-origin validator');
requirePattern(xmpp, /secureTransferUrl\(put\.getAttribute\('url'\)\)/, 'HTTP upload PUT URLs are not restricted to secure transports');
requirePattern(xmpp, /url\.origin !== pageOrigin[\s\S]+Cross-origin file transfer URLs are not permitted/, 'HTTP upload slots can redirect browser ciphertext to another origin');
requirePattern(omemo, /url\.origin !== pageOrigin[\s\S]+不允许从跨域地址下载加密文件/, 'encrypted attachment metadata can authorize a cross-origin download');
requirePattern(client, /opaqueUploadName = `\$\{crypto\.randomUUID\(\)\}\.bin`/, 'encrypted upload slot filenames disclose user metadata');
requirePattern(client, /method: 'PUT',[\s\S]+redirect: 'error'/, 'encrypted attachment upload can redirect ciphertext and metadata to another origin');
requirePattern(client, /密文完整性校验失败[\s\S]+解密文件完整性校验失败/, 'encrypted attachments are not verified before and after decryption');
requirePattern(omemo, /canonicalBase64\(identity\.textContent, 32/, 'OMEMO identity-key length is not validated');
requirePattern(omemo, /canonicalBase64\(signature\.textContent, 64/, 'OMEMO signed-prekey signature length is not validated');
requirePattern(omemo, /ensureDeviceAnnouncementLocked[\s\S]+fetchDeviceIds\(this\.account, false\)[\s\S]+publishDeviceList\(merged\)[\s\S]+fetchDeviceIds\(this\.account, false\)/, 'OMEMO device-list convergence does not perform a fresh read/merge/publish/confirm cycle');
requirePattern(omemo, /DEVICE_ANNOUNCEMENT_ATTEMPTS[\s\S]+DEVICE_ANNOUNCEMENT_STABLE_READS/, 'OMEMO device-list convergence is not bounded and stability-checked');
requirePattern(omemo, /owner !== this\.account[\s\S]+deviceRepair/, 'own PEP events do not repair overwritten device IDs');
requirePattern(omemo, /let announcedOwnIds = await this\.fetchDeviceIds\(this\.account, false\);[\s\S]+ensureOwnDeviceForSend\(announcedOwnIds\)/, 'outbound OMEMO does not repair a missing current device from a fresh own-list read');
requirePattern(omemo, /OMEMO_DEVICE_RETIRED[\s\S]+completeRemoteRetirement/, 'an offline device can resurrect after remote OMEMO revocation');
requirePattern(omemo, /ensureOwnDeviceForSend[\s\S]+deviceRetirementGrace\(\)[\s\S]+fetchDeviceIds\(this\.account, false\)[\s\S]+fetchBundle\(this\.account, ownId\)[\s\S]+completeRemoteRetirement\(ownId\)[\s\S]+ensureDeviceAnnouncement\(latest\)/, 'own-list race repair cannot distinguish an intentional remote device revocation after a bounded PEP grace period');
requirePattern(client, /onRemoteRetired:[\s\S]+erasePersistentEncryptedOutbox\(account\)[\s\S]+logout/, 'remote OMEMO revocation does not fence, erase, and terminate the browser outbox session');
requirePattern(client, /async function erasePersistentEncryptedOutbox[\s\S]+outboxErasing = true[\s\S]+outboxGeneration \+= 1[\s\S]+await drainEncryptedOutboxWrites\(\)[\s\S]+deleteValue\('preferences', `encrypted-outbox:/, 'secure outbox erasure can be undone by a late IndexedDB write');
requirePattern(client, /state\.omemo\.initialize\(\)[\s\S]+await state\.xmpp\.subscribePep\(state\.account, NS\.OMEMO2_DEVICES\)[\s\S]+auth-view[\s\S]+chat-view/, 'the browser enters chat without a fail-closed explicit subscription to its own OMEMO device list');
requirePattern(client, /const failedOmemo = state\.omemo[\s\S]+failedOmemo\?\.destroy\(\)[\s\S]+chat-view[\s\S]+auth-view/, 'failed OMEMO login initialization does not tear down keys and restore the authentication view');
requirePattern(xmpp, /configureInstantRoom\(room\)[\s\S]+MUC_OWNER[\s\S]+X_DATA[\s\S]+type: 'set'/, 'the web client cannot submit the XEP-0045 instant-room owner form');
requirePattern(client, /statusCodes\.includes\('201'\)[\s\S]+joinState = 'configuring'[\s\S]+await state\.xmpp\.configureInstantRoom[\s\S]+joinState = 'joined'/, 'a newly-created MUC is marked joined before its instant-room form unlocks it');
requirePattern(client, /failRoomJoin\(room[\s\S]+joinState = 'error'[\s\S]+dataset\.roomJoinRetry/, 'MUC join errors are not surfaced with a semantic retry state');
requirePattern(omemo, /accessModel: 'open', maxItems: 'max'/, 'OMEMO bundle publish-options are incomplete');
requirePattern(omemo, /accessModel: 'open' \}\);/, 'OMEMO device-list access model is not open');
requirePattern(xmpp, /retractPep\(node, itemId/, 'PEP item retraction is unavailable to OMEMO');
requirePattern(omemo, /retireAndEraseLocalState\(\)/, 'current-device retirement does not provide a local key-erasure boundary');
requirePattern(client, /forget-omemo-device/, 'secure current-device removal is not exposed in the web client');
requirePattern(client, /已加密，但发送设备尚未验证/, 'incoming encryption from an unverified device is not visibly distinguished');
requirePattern(xmpp, /<enable xmlns='\$\{NS\.SM\}' resume='true'\/>/, 'XEP-0198 stream management is not enabled');
requirePattern(xmpp, /attribute\.namespaceURI !== 'http:\/\/www\.w3\.org\/2000\/xmlns\/'/, 'SM response validation rejects legal XML namespace declarations');
requirePattern(xmpp, /protocolAttributes\(root\)\.some/, 'SM response attributes bypass strict protocol validation');
requirePattern(xmpp, /<resume xmlns='\$\{NS\.SM\}' previd='\$\{xmlEscape\(this\.smResumeId\)\}' h='\$\{this\.smInbound\}'\/>/, 'SASL2 inline XEP-0198 stream resumption is not attempted during reauthentication');
requirePattern(xmpp, /child\(root, 'resumed', NS\.SM\)[\s\S]+applyInlineResumed/, 'SASL2 inline XEP-0198 resumed responses are not processed');
requirePattern(xmpp, /for \(const stanza of this\.smUnacked\) this\.socket\.send\(stanza\.xml\)/, 'unhandled client stanzas are not replayed after XEP-0198 resumption');
requirePattern(xmpp, /MAX_SM_UNACKED_STANZAS[\s\S]+MAX_SM_UNACKED_BYTES/, 'the browser XEP-0198 retransmission queue is not bounded');
requirePattern(xmpp, /this\.emit\('stanza-acked',/, 'XEP-0198 acknowledgements are not exposed to the encrypted outbox');
requirePattern(client, /function persistEncryptedOutbox\(\)/, 'persistent encrypted outbox is missing');
requirePattern(client, /async function sendDurableEncrypted[\s\S]+await stageEncryptedOutbound\(pending\)[\s\S]+sendGroupMessage/, 'encrypted payload is not durably staged before transport');
requirePattern(client, /state\.omemo\.encrypt[\s\S]+queuedMessageProof\([\s\S]+encrypted\.xml[\s\S]+sendDurableEncrypted/,
  'PoW v2 must commit to completed OMEMO ciphertext before durable staging and transport');
requirePattern(client, /assertEncryptable\(state\.selected\)[\s\S]+state\.omemo\.encrypt[\s\S]+queuedMessageProof/,
  'direct-message trust preflight must run before encryption and its bound proof');
requirePattern(client, /assertGroupEncryptable\(recipients, room\.jid\)[\s\S]+state\.omemo\.encryptGroup[\s\S]+queuedMessageProof/,
  'group-message trust preflight must run before encryption and its bound proof');
requirePattern(client, /contentXml: `<body xmlns='\$\{NS\.CLIENT\}'[\s\S]+<request xmlns='\$\{NS\.RECEIPTS\}'\/>`/, 'XEP-0184 receipt requests leak outside SCE');
requirePattern(client, /async function sendEncryptedReceipt[\s\S]+state\.omemo\.encrypt[\s\S]+sendDurableEncrypted/, 'XEP-0184 receipt responses bypass OMEMO or the durable encrypted outbox');
if (/`\$\{encrypted\.xml\}<request xmlns='\$\{NS\.RECEIPTS\}'/.test(client)) {
  throw new Error('the web client still emits receipt correlation identifiers outside SCE');
}
requirePattern(client, /stanza-acked[\s\S]+settleEncryptedOutbound/, 'server acknowledgements do not enter the encrypted outbox verdict window');
requirePattern(client, /state\.xmpp\.canReconnect\(\)/, 'the web client discards its in-memory FAST credential during reconnect');
requirePattern(xmpp, /canResume\(\)[\s\S]+this\.smResumeId/, 'the XEP-0198 resumption state is not retained for SASL2 inline resume');

console.log('OMEMO multi-device static checks passed');
