import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { githubApi, listPages } from './verify-release-ci.mjs';

export const BUILD_CHECKS = [
  'Validate release inputs', 'Qualify exact release commit',
  'Build Linux AMD64 package', 'Build Windows AMD64 package',
  'Verify downloaded linux-amd64 package', 'Verify downloaded windows-amd64 package',
  'Build and verify northstar image', 'Build and verify northstar-backup image',
  'Build and verify northstar-database-grants image', 'Checksum and attest packages',
];

function requireFact(condition, message) {
  if (!condition) throw new Error(message);
}

export async function verifyArtifactRun({ api, repository, tag, commit, version, runId, evidence }) {
  requireFact(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository ?? '') &&
    /^[a-f0-9]{40}$/.test(commit ?? '') && /^\d+\.\d+\.\d+$/.test(version ?? '') && tag === `v${version}` &&
    Number.isSafeInteger(runId) && runId > 0, 'invalid release artifact identity');
  requireFact(evidence.commit === commit && evidence.version === version && evidence.published_images === true &&
    evidence.workflow_run_id === runId && Number.isSafeInteger(evidence.workflow_run_attempt) &&
    evidence.workflow_run_attempt > 0, 'artifact evidence does not match the requested tag run');
  const root = `/repos/${repository}/actions`;
  const workflow = await api(`${root}/workflows/release.yml`);
  const run = await api(`${root}/runs/${runId}`);
  requireFact(workflow.path === '.github/workflows/release.yml' && workflow.state === 'active' &&
    run.id === runId && run.workflow_id === workflow.id && run.path === workflow.path &&
    run.event === 'push' && run.head_branch === tag && run.head_sha === commit &&
    run.repository?.full_name?.toLowerCase() === repository.toLowerCase() &&
    run.head_repository?.full_name?.toLowerCase() === repository.toLowerCase() &&
    Number.isSafeInteger(run.run_attempt) && run.run_attempt >= evidence.workflow_run_attempt,
  'artifact source is not the exact trusted tag workflow');

  for (const attempt of new Set([evidence.workflow_run_attempt, run.run_attempt])) {
    const jobs = await listPages(api, `${root}/runs/${runId}/attempts/${attempt}/jobs`, 'jobs');
    for (const name of BUILD_CHECKS) {
      const matches = jobs.filter((job) => job.name === name);
      requireFact(matches.length === 1 && matches[0].run_id === runId && matches[0].run_attempt === attempt &&
        matches[0].head_sha === commit && matches[0].status === 'completed' && matches[0].conclusion === 'success',
      `tag build attempt ${attempt} has no unique successful ${name}`);
    }
  }
  const artifacts = await listPages(api, `${root}/runs/${runId}/artifacts`, 'artifacts');
  const matches = artifacts.filter((artifact) => artifact.name === `verified-release-assets-${version}`);
  requireFact(matches.length === 1 && matches[0].expired === false &&
    matches[0].workflow_run?.id === runId && matches[0].workflow_run?.head_sha === commit &&
    /^sha256:[a-f0-9]{64}$/.test(matches[0].digest ?? ''), 'verified release artifact is missing, expired or ambiguous');
  const current = await api(`${root}/runs/${runId}`);
  requireFact(current.run_attempt === run.run_attempt && current.head_sha === commit,
    'artifact source run changed during validation');
  return { runId, buildAttempt: evidence.workflow_run_attempt, artifactId: matches[0].id, digest: matches[0].digest };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const result = await verifyArtifactRun({ api: githubApi, repository: process.env.GITHUB_REPOSITORY,
      tag: process.env.RELEASE_TAG, commit: process.env.RELEASE_COMMIT, version: process.env.RELEASE_VERSION,
      runId: Number(process.env.ARTIFACT_RUN_ID), evidence: JSON.parse(fs.readFileSync('dist/RELEASE-EVIDENCE.json', 'utf8')) });
    process.stdout.write(`Verified original tag build and release artifact: ${JSON.stringify(result)}\n`);
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
