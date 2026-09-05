#!/usr/bin/env node
// Keep CI sharding an explicit coverage refactor, not a way to accidentally
// remove a required persistence suite from the workflow.
import fs from 'node:fs';

// Keep every identifier, report title, deadline, and fixture together.  A
// set-only check would allow two scripts to be swapped while preserving both
// the total count and uniqueness, silently giving a suite ID the wrong
// coverage.  This exact contract is the source for all derived checks below.
const expectedManifestEntries = [
  ['auth-admin', 'Auth/admin database', 600, 'auth-admin-db-wsl.sh'],
  ['admin-session-cleanup', 'Admin session cleanup database', 480, 'admin-session-cleanup-db-wsl.sh'],
  ['authentication-service', 'Authentication service database', 600, 'authentication-service-db-wsl.sh'],
  ['api-operations', 'API operations database', 600, 'api-operations-db-wsl.sh'],
  ['api-pages', 'API pages database', 480, 'api-pages-db-wsl.sh'],
  ['migration-upgrade', 'Migration upgrade database', 600, 'migration-upgrade-wsl.sh'],
  ['migration-0056-compatibility', 'Migration 0056 compatibility database', 480, 'migration-0056-db-wsl.sh'],
  ['rfc7622-identity', 'RFC 7622 identity database', 480, 'rfc7622-identity-db-wsl.sh'],
  ['identity-audit', 'Identity audit database', 480, 'identity-audit-db-wsl.sh'],
  ['jid-identity', 'JID identity database', 480, 'jid-identity-db-wsl.sh'],
  ['authorization-jid-identity', 'Authorization JID identity database', 480, 'authorization-jid-identity-db-wsl.sh'],
  ['push-jid-identity', 'Push JID identity database', 480, 'push-jid-identity-db-wsl.sh'],
  ['mix-jid-identity', 'MIX JID identity database', 480, 'mix-jid-identity-db-wsl.sh'],
  ['session-jid-identity', 'Session JID identity database', 480, 'session-jid-identity-db-wsl.sh'],
  ['profile-jid-identity', 'Profile JID identity database', 480, 'profile-jid-identity-db-wsl.sh'],
  ['abuse-reporting', 'Abuse reporting database', 600, 'abuse-reporting-db-wsl.sh'],
  ['abuse-key-deployment', 'Abuse key deployment database', 480, 'abuse-key-deployment-db-wsl.sh'],
  ['message-pow', 'Message PoW database', 600, 'message-pow-db-wsl.sh'],
  ['push-delivery', 'Push delivery database', 480, 'push-delivery-db-wsl.sh'],
  ['offline-replay', 'Offline replay database', 600, 'offline-replay-db-wsl.sh'],
  ['retention', 'Retention database', 480, 'retention-db-wsl.sh'],
  ['stream-management', 'Stream Management database', 600, 'sm-db-wsl.sh'],
  ['s2s', 'S2S database', 600, 's2s-db-wsl.sh'],
  ['roster-service', 'Roster service database', 480, 'roster-service-db-wsl.sh'],
  ['muc', 'MUC database', 600, 'muc-db-wsl.sh'],
  ['pie', 'PIE database', 480, 'pie-db-wsl.sh'],
  ['privacy', 'Privacy database', 600, 'privacy-db-wsl.sh'],
  ['http-upload', 'HTTP Upload database', 600, 'upload-db-wsl.sh'],
  ['muc-cluster', 'MUC cluster database', 600, 'muc-cluster-wsl.sh'],
  ['pubsub', 'PubSub database', 600, 'pubsub-db-wsl.sh'],
  ['pubsub-outbox', 'PubSub outbox database', 600, 'pubsub-outbox-db-wsl.sh'],
  ['pubsub-wire', 'PubSub wire integration', 600, 'pubsub-wire-wsl.sh'],
].map(([suiteId, title, timeoutSeconds, script]) => ({
  suiteId,
  title,
  timeoutSeconds,
  script,
}));
const requiredSuites = expectedManifestEntries.map(({ script }) => script);
const expectedTimeoutBySuiteId = Object.fromEntries(
  expectedManifestEntries.map(({ suiteId, timeoutSeconds }) => [suiteId, timeoutSeconds]),
);

const workflow = fs.readFileSync('.github/workflows/ci.yml', 'utf8');
// The test-only override lets the regression fixture mutate an isolated copy
// without ever touching the checked manifest.  Normal CI always reads the
// repository path below.
const manifestPath = process.env.NORTHSTAR_STATEFUL_DATABASE_MANIFEST
  || 'scripts/stateful-database-ci.sh';
const manifest = fs.readFileSync(manifestPath, 'utf8');
const shards = [
  'auth-identity', 'abuse-delivery', 'collaboration-storage', 'pubsub-federation',
];

const manifestEntries = [...manifest.matchAll(
  /^\s*'([^|'\s]+)\|([^|']+)\|([1-9][0-9]*)\|([^|'\s]+\.sh)'\s*$/gm,
)].map(([, suiteId, title, timeoutSeconds, script]) => ({
  suiteId,
  title,
  timeoutSeconds: Number(timeoutSeconds),
  script,
}));
const manifestScripts = manifestEntries.map(({ script }) => script);
const manifestSuiteIds = manifestEntries.map(({ suiteId }) => suiteId);
const expectedSuiteIds = Object.keys(expectedTimeoutBySuiteId);
const missing = requiredSuites.filter((suite) => !manifestScripts.includes(suite));
const staleWorkflowCalls = requiredSuites.filter((suite) => workflow.includes(suite));
const missingShards = shards.filter((shard) => !workflow.includes(`- ${shard}`));
const duplicateSuites = requiredSuites.filter(
  (suite) => manifestScripts.filter((script) => script === suite).length !== 1,
);
const duplicateSuiteIds = manifestSuiteIds.filter(
  (suiteId, index) => manifestSuiteIds.indexOf(suiteId) !== index,
);
const missingBudgetedSuiteIds = expectedSuiteIds.filter(
  (suiteId) => !manifestSuiteIds.includes(suiteId),
);
const unexpectedSuiteIds = manifestSuiteIds.filter(
  (suiteId) => !Object.hasOwn(expectedTimeoutBySuiteId, suiteId),
);
const changedTimeouts = manifestEntries
  .filter(({ suiteId, timeoutSeconds }) => (
    Object.hasOwn(expectedTimeoutBySuiteId, suiteId)
    && timeoutSeconds !== expectedTimeoutBySuiteId[suiteId]
  ))
  .map(({ suiteId, timeoutSeconds }) => ({
    suiteId,
    expected: expectedTimeoutBySuiteId[suiteId],
    actual: timeoutSeconds,
  }));
const mismatchedManifestEntries = expectedManifestEntries.flatMap((expected) => {
  const actual = manifestEntries.filter(({ suiteId }) => suiteId === expected.suiteId);
  if (actual.length !== 1) {
    return [];
  }
  const observed = actual[0];
  if (
    observed.title === expected.title
    && observed.timeoutSeconds === expected.timeoutSeconds
    && observed.script === expected.script
  ) {
    return [];
  }
  return [{
    suiteId: expected.suiteId,
    expected: {
      title: expected.title,
      timeoutSeconds: expected.timeoutSeconds,
      script: expected.script,
    },
    actual: {
      title: observed.title,
      timeoutSeconds: observed.timeoutSeconds,
      script: observed.script,
    },
  }];
});
const missingTerminalResults = [
  'phase=database_suite_result',
  'passed command-completed',
  'failed command-exit',
  'timeout command-deadline',
  'cancelled process-group-cancellation',
  'not-run process-group-cancellation',
  'blocked_by=',
].filter((marker) => !manifest.includes(marker));
if (
  missing.length
  || staleWorkflowCalls.length
  || missingShards.length
  || duplicateSuites.length
  || duplicateSuiteIds.length
  || manifestEntries.length !== requiredSuites.length
  || expectedSuiteIds.length !== requiredSuites.length
  || missingBudgetedSuiteIds.length
  || unexpectedSuiteIds.length
  || changedTimeouts.length
  || mismatchedManifestEntries.length
  || missingTerminalResults.length
) {
  console.error(JSON.stringify({
    missing,
    staleWorkflowCalls,
    missingShards,
    duplicateSuites,
    duplicateSuiteIds,
    manifestEntryCount: manifestEntries.length,
    expectedEntryCount: requiredSuites.length,
    missingBudgetedSuiteIds,
    unexpectedSuiteIds,
    changedTimeouts,
    mismatchedManifestEntries,
    missingTerminalResults,
  }));
  process.exit(1);
}

console.log(`stateful database CI manifest coverage PASS (${requiredSuites.length} suites, ${shards.length} shards, unique terminal suite results)`);
