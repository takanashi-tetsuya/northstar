import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { REQUIRED_CHECK_NAME } from './ci-required-policy.mjs';

const SHA = /^[a-f0-9]{40}$/;
export const ACTIONS_APP_ID = 15368;

function requireFact(condition, message) {
  if (!condition) throw new Error(message);
}

export function verifyBranchRules(rules) {
  requireFact(Array.isArray(rules), 'main effective branch rules are unavailable');
  const has = (type) => rules.some((rule) => rule.type === type);
  requireFact(has('pull_request') && has('deletion') && has('non_fast_forward'),
    'main must enforce pull requests, deletion protection and force-push protection before publication');
  requireFact(has('required_signatures'), 'main must enforce verified commit signatures before publication');
  requireFact(rules.some((rule) => rule.type === 'required_status_checks' &&
    rule.parameters?.strict_required_status_checks_policy === true &&
    rule.parameters?.required_status_checks?.some((check) =>
      check.context === REQUIRED_CHECK_NAME && check.integration_id === ACTIONS_APP_ID)),
  'main must require the current CI required check from GitHub Actions on the up-to-date branch');
}

export function selectCiRun(runs, { repository, commit, workflowId }) {
  requireFact(Array.isArray(runs), 'CI workflow run response is invalid');
  const repositoryMatches = (value) => value?.toLowerCase() === repository.toLowerCase();
  const trusted = runs.filter((run) =>
    run.workflow_id === workflowId &&
    run.path?.split('@')[0] === '.github/workflows/ci.yml' &&
    repositoryMatches(run.repository?.full_name) &&
    repositoryMatches(run.head_repository?.full_name) &&
    run.head_sha === commit && run.head_branch === 'main' &&
    ['push', 'schedule'].includes(run.event));
  trusted.sort((left, right) => right.id - left.id);
  requireFact(trusted.length > 0, 'no trusted main push/schedule CI run exists for the exact release commit');
  const run = trusted[0];
  requireFact(Number.isSafeInteger(run.id) && Number.isSafeInteger(run.run_attempt) && run.run_attempt > 0,
    'CI run identity or attempt is invalid');
  requireFact(run.status === 'completed' && run.conclusion === 'success',
    `latest trusted CI run ${run.id} is ${run.status}/${run.conclusion ?? 'pending'}; older success is not release evidence`);
  return run;
}

async function listPages(api, endpoint, property) {
  const items = [];
  for (let page = 1; page <= 10; page++) {
    const data = await api(`${endpoint}${endpoint.includes('?') ? '&' : '?'}per_page=100&page=${page}`);
    requireFact(Array.isArray(data[property]) && Number.isSafeInteger(data.total_count), `${property} response is invalid`);
    items.push(...data[property]);
    if (items.length >= data.total_count) return items;
    requireFact(data[property].length > 0, `${property} pagination ended before all evidence was returned`);
  }
  throw new Error(`${property} evidence exceeds the bounded 1,000-record review limit`);
}

export async function qualifyRelease({ api, repository, commit, tag }) {
  requireFact(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository ?? ''), 'release repository is invalid');
  requireFact(SHA.test(commit ?? ''), 'release commit must be a full immutable SHA');
  requireFact(/^v\d+\.\d+\.\d+$/.test(tag ?? ''), 'release tag must be vMAJOR.MINOR.PATCH');
  const root = `/repos/${repository}`;
  const refPath = `${root}/git/ref/tags/${tag}`;
  const ref = await api(refPath);
  requireFact(ref.ref === `refs/tags/${tag}` && ref.object?.type === 'tag' && SHA.test(ref.object.sha),
    'release requires a signed annotated tag; lightweight or indirect refs are not accepted');
  const tagObject = await api(`${root}/git/tags/${ref.object.sha}`);
  requireFact(tagObject.sha === ref.object.sha && tagObject.tag === tag &&
    tagObject.object?.type === 'commit' && tagObject.object.sha === commit,
  'release tag does not directly identify the exact release commit');
  requireFact(tagObject.verification?.verified === true && tagObject.verification.reason === 'valid' &&
    typeof tagObject.verification.signature === 'string' && tagObject.verification.signature.length > 0,
  'GitHub has not verified the release tag signature');

  await verifyBranchRules(await api(`${root}/rules/branches/main`));
  const comparison = await api(`${root}/compare/${commit}...main`);
  requireFact(['ahead', 'identical'].includes(comparison.status) && comparison.merge_base_commit?.sha === commit,
    'release commit is not in main history');
  const workflow = await api(`${root}/actions/workflows/ci.yml`);
  requireFact(workflow.path === '.github/workflows/ci.yml' && workflow.state === 'active' && Number.isSafeInteger(workflow.id),
    'the authoritative CI workflow is missing or inactive');
  const runs = await listPages(api, `${root}/actions/workflows/${workflow.id}/runs?head_sha=${commit}`, 'workflow_runs');
  const run = selectCiRun(runs, { repository, commit, workflowId: workflow.id });
  const jobs = await listPages(api, `${root}/actions/runs/${run.id}/attempts/${run.run_attempt}/jobs`, 'jobs');
  const required = jobs.filter((job) => job.name === REQUIRED_CHECK_NAME);
  requireFact(required.length === 1 && required[0].run_id === run.id && required[0].run_attempt === run.run_attempt &&
    required[0].head_sha === commit && required[0].status === 'completed' && required[0].conclusion === 'success',
  'the exact CI run attempt has no unique successful CI required aggregate');
  // A re-run or tag move during evidence collection must not inherit old success.
  const currentRun = await api(`${root}/actions/runs/${run.id}`);
  requireFact(currentRun.head_sha === commit && currentRun.run_attempt === run.run_attempt &&
    currentRun.status === 'completed' && currentRun.conclusion === 'success',
  'CI changed while release evidence was being collected');
  const currentRef = await api(refPath);
  requireFact(currentRef.object?.type === 'tag' && currentRef.object.sha === ref.object.sha,
    'release tag changed while release evidence was being collected');
  return { commit, tag, tagObject: ref.object.sha, ciRunId: run.id, ciAttempt: run.run_attempt,
    ciUrl: `https://github.com/${repository}/actions/runs/${run.id}` };
}

async function githubApi(endpoint) {
  requireFact(process.env.GITHUB_API_URL === 'https://api.github.com', 'release qualification supports GitHub.com only');
  requireFact(typeof process.env.GH_TOKEN === 'string' && process.env.GH_TOKEN.length > 0, 'GH_TOKEN is required');
  const response = await fetch(`https://api.github.com${endpoint}`, {
    headers: { Accept: 'application/vnd.github+json', Authorization: `Bearer ${process.env.GH_TOKEN}`,
      'X-GitHub-Api-Version': '2022-11-28' },
    signal: AbortSignal.timeout(15000),
    redirect: 'error',
  });
  requireFact(response.ok, `release evidence request failed with HTTP ${response.status}`);
  return response.json();
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const result = await qualifyRelease({ api: githubApi, repository: process.env.GITHUB_REPOSITORY,
      commit: process.env.RELEASE_COMMIT, tag: process.env.RELEASE_TAG });
    const summary = `Release ${result.tag} qualified at ${result.commit}; CI ${result.ciUrl}, attempt ${result.ciAttempt}.\n`;
    process.stdout.write(summary);
    if (process.env.RELEASE_QUALIFICATION_FILE) {
      fs.writeFileSync(process.env.RELEASE_QUALIFICATION_FILE, `${JSON.stringify(result, null, 2)}\n`);
    }
    if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary);
  } catch (error) {
    process.stderr.write(`Release blocked: ${error.message}\n`);
    process.exitCode = 1;
  }
}
