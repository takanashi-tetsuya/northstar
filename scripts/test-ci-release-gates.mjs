import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { ALL_JOBS, expectedJobResults, verifyJobResults, verifyWorkflowCoverage } from './ci-required-policy.mjs';
import { ACTIONS_APP_ID, qualifyRelease, selectCiRun, verifyBranchRules } from './verify-release-ci.mjs';

const read = (relative) => fs.readFileSync(new URL(relative, import.meta.url), 'utf8').replaceAll('\r\n', '\n');
const repository = 'owner/northstar';
const commit = 'a'.repeat(40);
const tagSha = 'b'.repeat(40);
const tag = 'v0.2.0';
const baseRun = {
  id: 30, run_attempt: 2, workflow_id: 7, path: '.github/workflows/ci.yml',
  repository: { full_name: repository }, head_repository: { full_name: repository },
  head_sha: commit, head_branch: 'main', event: 'push', status: 'completed', conclusion: 'success',
};
const branchRules = [
  { type: 'pull_request' }, { type: 'deletion' }, { type: 'non_fast_forward' }, { type: 'required_signatures' },
  { type: 'required_status_checks', parameters: { strict_required_status_checks_policy: true,
    required_status_checks: [{ context: 'CI required', integration_id: ACTIONS_APP_ID }] } },
];

test('every supported event requires all applicable jobs and precisely classifies legitimate skips', () => {
  for (const event of ['push', 'pull_request', 'schedule', 'workflow_dispatch']) {
    const expected = expectedJobResults(event);
    const needs = Object.fromEntries(Object.entries(expected).map(([job, result]) => [job, { result }]));
    assert.equal(verifyJobResults(event, needs), ALL_JOBS.length);
    for (const job of ALL_JOBS) {
      for (const result of ['failure', 'cancelled', 'skipped', 'success', 'pending', undefined]) {
        if (result !== expected[job]) {
          assert.throws(() => verifyJobResults(event, { ...needs, [job]: { result } }), /expected/);
        }
      }
      const missing = { ...needs };
      delete missing[job];
      assert.throws(() => verifyJobResults(event, missing), /missing/);
    }
    assert.throws(() => verifyJobResults(event, { ...needs, unknown: { result: 'success' } }), /unclassified/);
  }
  assert.throws(() => expectedJobResults('pull_request_target'), /unsupported/);
});

test('the stable aggregate covers every actual workflow job and executes even after failures', () => {
  const workflow = read('../.github/workflows/ci.yml');
  verifyWorkflowCoverage(workflow);
  assert.throws(() => verifyWorkflowCoverage(`${workflow}\n  forgotten-job:\n    runs-on: ubuntu-latest\n`), /classify/);
  assert.throws(() => verifyWorkflowCoverage(workflow.replace('      - disaster-recovery\n', '')), /directly depend/);
  assert.throws(() => verifyWorkflowCoverage(workflow.replace('    if: ${{ always() }}', '    if: ${{ success() }}')), /unconditional/);
});

test('no failed latest run or unrelated successful run can qualify an exact release commit', () => {
  const selection = { repository, commit, workflowId: 7 };
  assert.equal(selectCiRun([baseRun], selection).id, 30);
  assert.equal(selectCiRun([{ ...baseRun, event: 'schedule' }], selection).id, 30);
  for (const patch of [
    { event: 'pull_request' }, { event: 'workflow_dispatch' }, { head_branch: tag }, { head_branch: 'dev' },
    { head_sha: 'c'.repeat(40) }, { workflow_id: 8 }, { path: '.github/workflows/release.yml' },
    { repository: { full_name: 'other/repository' } }, { head_repository: { full_name: 'fork/northstar' } },
  ]) {
    assert.throws(() => selectCiRun([{ ...baseRun, ...patch }], selection), /no trusted/);
  }
  for (const patch of [
    { conclusion: 'failure' }, { conclusion: 'cancelled' }, { status: 'in_progress', conclusion: null },
    { conclusion: 'skipped' }, { conclusion: 'neutral' },
  ]) {
    assert.throws(() => selectCiRun([baseRun, { ...baseRun, id: 31, ...patch }], selection), /latest trusted/);
  }
});

test('publication requires enabled branch rules and the actual GitHub Actions aggregate', () => {
  verifyBranchRules(branchRules);
  for (let index = 0; index < branchRules.length; index++) {
    assert.throws(() => verifyBranchRules(branchRules.filter((_, candidate) => candidate !== index)));
  }
  for (const check of [{ context: 'fmt', integration_id: ACTIONS_APP_ID }, { context: 'CI required', integration_id: null }]) {
    const changed = structuredClone(branchRules);
    changed.at(-1).parameters.required_status_checks = [check];
    assert.throws(() => verifyBranchRules(changed), /CI required/);
  }
});

function fixtureApi(change = () => {}) {
  const seen = [];
  return {
    seen,
    api: async (endpoint) => {
      seen.push(endpoint);
      let data;
      if (endpoint.endsWith(`/git/ref/tags/${tag}`)) {
        data = { ref: `refs/tags/${tag}`, object: { type: 'tag', sha: tagSha } };
      } else if (endpoint.endsWith(`/git/tags/${tagSha}`)) {
        data = { sha: tagSha, tag, object: { type: 'commit', sha: commit },
          verification: { verified: true, reason: 'valid', signature: 'fixture signature' } };
      } else if (endpoint.endsWith('/rules/branches/main')) {
        data = structuredClone(branchRules);
      } else if (endpoint.includes('/compare/')) {
        data = { status: 'identical', merge_base_commit: { sha: commit } };
      } else if (endpoint.endsWith('/actions/workflows/ci.yml')) {
        data = { id: 7, path: '.github/workflows/ci.yml', state: 'active' };
      } else if (endpoint.includes('/actions/workflows/7/runs?')) {
        data = { total_count: 1, workflow_runs: [structuredClone(baseRun)] };
      } else if (endpoint.includes('/actions/runs/30/attempts/2/jobs?')) {
        data = { total_count: 1, jobs: [{ name: 'CI required', head_sha: commit, run_id: 30,
          run_attempt: 2, status: 'completed', conclusion: 'success' }] };
      } else if (endpoint.endsWith('/actions/runs/30')) {
        data = structuredClone(baseRun);
      } else {
        throw new Error(`unexpected endpoint: ${endpoint}`);
      }
      change(endpoint, data, seen);
      return data;
    },
  };
}

test('the release gate binds signature, main ancestry, workflow, SHA and exact successful attempt', async () => {
  const fixture = fixtureApi();
  const evidence = await qualifyRelease({ api: fixture.api, repository, commit, tag });
  assert.deepEqual(evidence, { commit, tag, tagObject: tagSha, ciRunId: 30, ciAttempt: 2,
    ciUrl: `https://github.com/${repository}/actions/runs/30` });
  assert.ok(fixture.seen.some((endpoint) => endpoint.includes('/attempts/2/jobs?')));
  assert.equal(fixture.seen.filter((endpoint) => endpoint.endsWith(`/git/ref/tags/${tag}`)).length, 2);
});

test('release gate rejects unsigned/moved tags, non-main commits and stale/missing aggregate evidence', async () => {
  const mutations = [
    [(endpoint) => endpoint.includes('/git/ref/'), (data) => { data.object.type = 'commit'; }],
    [(endpoint) => endpoint.includes('/git/tags/'), (data) => { data.object.sha = 'c'.repeat(40); }],
    [(endpoint) => endpoint.includes('/git/tags/'), (data) => { data.verification.verified = false; }],
    [(endpoint) => endpoint.includes('/compare/'), (data) => { data.status = 'diverged'; }],
    [(endpoint) => endpoint.includes('/compare/'), (data) => { data.merge_base_commit.sha = 'c'.repeat(40); }],
    [(endpoint) => endpoint.includes('/jobs?'), (data) => { data.jobs[0].run_attempt = 1; }],
    [(endpoint) => endpoint.includes('/jobs?'), (data) => { data.jobs[0].conclusion = 'skipped'; }],
    [(endpoint) => endpoint.includes('/jobs?'), (data) => { data.jobs[0].head_sha = 'c'.repeat(40); }],
    [(endpoint) => endpoint.includes('/jobs?'), (data) => { data.jobs.push({ ...data.jobs[0] }); data.total_count++; }],
    [(endpoint) => endpoint.includes('/jobs?'), (data) => { data.jobs = []; data.total_count = 0; }],
    [(endpoint) => endpoint.endsWith('/actions/runs/30'), (data) => { data.run_attempt = 3; }],
  ];
  for (const [when, mutate] of mutations) {
    const fixture = fixtureApi((endpoint, data) => { if (when(endpoint)) mutate(data); });
    await assert.rejects(qualifyRelease({ api: fixture.api, repository, commit, tag }));
  }
  const moved = fixtureApi((endpoint, data, seen) => {
    if (endpoint.includes('/git/ref/') && seen.filter((value) => value === endpoint).length === 2) {
      data.object.sha = 'd'.repeat(40);
    }
  });
  await assert.rejects(qualifyRelease({ api: moved.api, repository, commit, tag }), /tag changed/);
});

test('release evidence pagination cannot hide a newer failing run', async () => {
  const fixture = fixtureApi((endpoint, data) => {
    if (endpoint.includes('/actions/workflows/7/runs?')) {
      data.total_count = 2;
      data.workflow_runs = endpoint.endsWith('page=1') ? [baseRun] : [{ ...baseRun, id: 31, conclusion: 'failure' }];
    }
  });
  await assert.rejects(qualifyRelease({ api: fixture.api, repository, commit, tag }), /latest trusted/);
  assert.ok(fixture.seen.some((endpoint) => endpoint.endsWith('page=2')));
});

test('reviewable rulesets support one maintainer and require the stable aggregate', () => {
  const branches = JSON.parse(read('../docs/governance/branch-ruleset.json'));
  assert.equal(branches.enforcement, 'active');
  assert.deepEqual(branches.bypass_actors, []);
  assert.deepEqual(branches.conditions.ref_name.include, ['refs/heads/main', 'refs/heads/dev']);
  verifyBranchRules(branches.rules);
  const review = branches.rules.find((rule) => rule.type === 'pull_request').parameters;
  assert.equal(review.required_approving_review_count, 0);
  assert.equal(review.require_code_owner_review, false);
  const tags = JSON.parse(read('../docs/governance/release-tag-ruleset.json'));
  assert.equal(tags.target, 'tag');
  assert.deepEqual(tags.rules.map((rule) => rule.type).sort(), ['deletion', 'update']);
});

test('publication jobs depend on qualification and binary success, with a fresh gate before GHCR login', () => {
  const workflow = read('../.github/workflows/release.yml');
  const images = workflow.split(/^  publish-images:\s*$/m)[1].split(/^  assemble-release-assets:/m)[0];
  assert.ok(images.includes('needs: [prepare, release-qualification, build-binaries, verify-native-packages]'));
  assert.ok(images.indexOf('node scripts/verify-release-ci.mjs') < images.indexOf('uses: docker/login-action@'));
  assert.ok(images.includes('actions: read'));
  assert.ok(images.includes("push: ${{ needs.prepare.outputs.publish == 'true' }}"));
  assert.ok(images.includes("load: ${{ needs.prepare.outputs.publish != 'true' }}"));
  assert.ok(images.includes('scripts/release-image-check.py'));
  assert.ok(images.includes('--evidence image-evidence/container-runtime.json'));
  assert.ok(images.includes('DOCKER_CONFIG="$anonymous_config" docker pull'));
  assert.ok(images.includes('gh attestation verify "oci://$image"'));
  assert.ok(workflow.includes('needs: [prepare, release-qualification]'));
  const native = workflow.split(/^  verify-native-packages:\s*$/m)[1].split(/^  publish-images:/m)[0];
  assert.ok(native.includes('needs: [prepare, build-binaries]'));
  assert.ok(native.includes('scripts/release-package.py verify'));
  assert.ok(native.includes('scripts/release-native-smoke.py'));
  assert.ok(native.includes('digest-mismatch: error'));
  assert.ok(workflow.includes("needs.verify-native-packages.result == 'success'"));
  assert.ok(workflow.includes('--directory native-evidence --output dist/RELEASE-EVIDENCE.json'));
  assert.ok(workflow.includes('--image-directory image-evidence --published "$PUBLISH_RELEASE"'));
  const download = workflow.split(/^  verify-draft-downloads:\s*$/m)[1].split(/^  finalize-draft:/m)[0];
  assert.ok(download.includes('needs: [prepare, prepare-draft-release]'));
  assert.ok(download.includes('gh release download'));
  assert.ok(download.includes('gh attestation verify'));
  assert.ok(download.includes('scripts/release-download.py'));
  assert.ok(download.includes('scripts/release-package.py verify'));
  const finalize = workflow.split(/^  finalize-draft:\s*$/m)[1];
  assert.ok(finalize.includes('needs: [prepare, verify-draft-downloads]'));
  assert.ok(finalize.includes('node scripts/verify-release-ci.mjs'));
  assert.ok(finalize.includes('--draft --notes-file release-notes.md'));
  assert.ok(!workflow.includes('--draft=false'));
});
