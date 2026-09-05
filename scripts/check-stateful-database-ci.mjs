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

const workflow = fs.readFileSync('.github/workflows/ci.yml', 'utf8');
const manifest = fs.readFileSync('scripts/stateful-database-ci.sh', 'utf8');
const shards = [
  'auth-identity', 'abuse-delivery', 'collaboration-storage', 'pubsub-federation',
];

const missing = requiredSuites.filter((suite) => !manifest.includes(suite));
const staleWorkflowCalls = requiredSuites.filter((suite) => workflow.includes(suite));
const missingShards = shards.filter((shard) => !workflow.includes(`- ${shard}`));
const duplicateSuites = requiredSuites.filter(
  (suite) => manifest.split(` ${suite}\n`).length - 1 !== 1,
);
if (missing.length || staleWorkflowCalls.length || missingShards.length || duplicateSuites.length) {
  console.error(JSON.stringify({ missing, staleWorkflowCalls, missingShards, duplicateSuites }));
  process.exit(1);
}

console.log(`stateful database CI manifest coverage PASS (${requiredSuites.length} suites, ${shards.length} shards)`);
