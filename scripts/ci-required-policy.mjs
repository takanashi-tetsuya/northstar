// This list is deliberately explicit: adding a CI job requires a decision about
// its event scope. check-ci-required.mjs also checks that no workflow job is omitted.
export const REQUIRED_CHECK_NAME = 'CI required';
export const ALWAYS_REQUIRED = [
  'rust-fmt', 'rust-check', 'rust-test', 'rust-clippy', 'rust-build',
  'rust-quality', 'contracts-quality', 'contracts-compatibility',
  'dependency-audit', 'dependency-policy', 'web-static', 'container-build',
  'database-role-boundary', 'protocol-integration', 'stateful-database-integration',
  'mix-integration', 'federation-integration', 'listener-readiness-stress-smoke',
  'listener-diagnostics',
  'xep0487-integration', 'disaster-recovery',
];
export const REGULAR_REQUIRED = ['listener-readiness-stress-regular'];
export const SCHEDULED_REQUIRED = [
  'protocol-fuzz', 'production-envelope', 'heavy-runtime-envelope',
  'listener-readiness-stress-scheduled',
];
export const ALL_JOBS = [...ALWAYS_REQUIRED, ...REGULAR_REQUIRED, ...SCHEDULED_REQUIRED];

export function expectedJobResults(event) {
  if (!['push', 'pull_request', 'schedule', 'workflow_dispatch'].includes(event)) {
    throw new Error(`unsupported CI event: ${event}`);
  }
  const scheduled = ['schedule', 'workflow_dispatch'].includes(event);
  return Object.fromEntries([
    ...ALWAYS_REQUIRED.map((job) => [job, 'success']),
    ...REGULAR_REQUIRED.map((job) => [job, scheduled ? 'skipped' : 'success']),
    ...SCHEDULED_REQUIRED.map((job) => [job, scheduled ? 'success' : 'skipped']),
  ]);
}

export function verifyJobResults(event, needs) {
  const expected = expectedJobResults(event);
  const errors = [];
  if (!needs || typeof needs !== 'object' || Array.isArray(needs)) {
    throw new Error('CI dependency results must be an object');
  }
  for (const job of Object.keys(needs)) {
    if (!Object.hasOwn(expected, job)) errors.push(`unclassified job: ${job}`);
  }
  for (const [job, result] of Object.entries(expected)) {
    if (needs[job]?.result !== result) {
      errors.push(`${job}: expected ${result}, received ${needs[job]?.result ?? 'missing'}`);
    }
  }
  if (errors.length) throw new Error(`required CI jobs did not satisfy policy:\n${errors.join('\n')}`);
  return Object.keys(expected).length;
}

export function verifyWorkflowCoverage(workflow) {
  const declared = [...workflow.matchAll(/^  ([a-z][a-z0-9-]*):\s*$/gm)]
    .map((match) => match[1])
    .filter((job) => !['push', 'pull_request', 'workflow_dispatch', 'schedule', 'contents'].includes(job));
  const expected = [...ALL_JOBS, 'ci-required'].sort();
  if (JSON.stringify(declared.sort()) !== JSON.stringify(expected)) {
    throw new Error('CI jobs and the required-check policy differ; classify every workflow job');
  }
  const aggregate = workflow.split(/^  ci-required:\s*$/m)[1];
  const dependencies = [...(aggregate?.split('    steps:')[0] ?? '').matchAll(/^      - ([a-z][a-z0-9-]*)\s*$/gm)]
    .map((match) => match[1]).sort();
  if (JSON.stringify(dependencies) !== JSON.stringify([...ALL_JOBS].sort())) {
    throw new Error('CI required must directly depend on every classified job');
  }
  if (!aggregate?.includes(`    name: ${REQUIRED_CHECK_NAME}\n`) ||
      !aggregate.includes('    if: ${{ always() }}') ||
      !aggregate.includes('CI_REQUIRED_NEEDS: ${{ toJSON(needs) }}')) {
    throw new Error('CI required must retain its stable name, unconditional evaluation and dependency evidence');
  }
}
