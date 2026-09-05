#!/usr/bin/env node
// Keep CI sharding an explicit coverage refactor, not a way to accidentally
// remove a required persistence suite from the workflow.
import fs from 'node:fs';

const requiredSuites = [
  'auth-admin-db-wsl.sh', 'admin-session-cleanup-db-wsl.sh',
  'authentication-service-db-wsl.sh', 'abuse-reporting-db-wsl.sh',
  'abuse-key-deployment-db-wsl.sh', 'message-pow-db-wsl.sh',
  'api-operations-db-wsl.sh', 'api-pages-db-wsl.sh',
  'migration-upgrade-wsl.sh', 'migration-0056-db-wsl.sh',
  'rfc7622-identity-db-wsl.sh', 'identity-audit-db-wsl.sh',
  'jid-identity-db-wsl.sh', 'authorization-jid-identity-db-wsl.sh',
  'push-jid-identity-db-wsl.sh', 'push-delivery-db-wsl.sh',
  'mix-jid-identity-db-wsl.sh', 'session-jid-identity-db-wsl.sh',
  'profile-jid-identity-db-wsl.sh', 'roster-service-db-wsl.sh',
  'muc-db-wsl.sh', 'pie-db-wsl.sh', 'privacy-db-wsl.sh',
  'offline-replay-db-wsl.sh', 'pubsub-db-wsl.sh',
  'pubsub-outbox-db-wsl.sh', 'pubsub-wire-wsl.sh',
  'retention-db-wsl.sh', 'sm-db-wsl.sh', 's2s-db-wsl.sh',
  'upload-db-wsl.sh', 'muc-cluster-wsl.sh',
];

// These are the evidence-backed per-suite budgets.  Keep the values explicit:
// a CI refactor must not silently turn a bounded fixture into a longer job.
const expectedTimeoutBySuiteId = {
  'auth-admin': 600,
  'admin-session-cleanup': 480,
  'authentication-service': 600,
  'api-operations': 600,
  'api-pages': 480,
  'migration-upgrade': 600,
  'migration-0056-compatibility': 480,
  'rfc7622-identity': 480,
  'identity-audit': 480,
  'jid-identity': 480,
  'authorization-jid-identity': 480,
  'push-jid-identity': 480,
  'mix-jid-identity': 480,
  'session-jid-identity': 480,
  'profile-jid-identity': 480,
  'abuse-reporting': 600,
  'abuse-key-deployment': 480,
  'message-pow': 600,
  'push-delivery': 480,
  'offline-replay': 600,
  'retention': 480,
  'stream-management': 600,
  's2s': 600,
  'roster-service': 480,
  'muc': 600,
  'pie': 480,
  'privacy': 600,
  'http-upload': 600,
  'muc-cluster': 600,
  'pubsub': 600,
  'pubsub-outbox': 600,
  'pubsub-wire': 600,
};

const workflow = fs.readFileSync('.github/workflows/ci.yml', 'utf8');
const manifest = fs.readFileSync('scripts/stateful-database-ci.sh', 'utf8');
const shards = [
  'auth-identity', 'abuse-delivery', 'collaboration-storage', 'pubsub-federation',
];

const manifestEntries = [...manifest.matchAll(
  /^\s*'([^|'\s]+)\|[^|']+\|([1-9][0-9]*)\|([^|'\s]+\.sh)'\s*$/gm,
)].map(([, suiteId, timeoutSeconds, script]) => ({
  suiteId,
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
    missingTerminalResults,
  }));
  process.exit(1);
}

console.log(`stateful database CI manifest coverage PASS (${requiredSuites.length} suites, ${shards.length} shards, unique terminal suite results)`);
