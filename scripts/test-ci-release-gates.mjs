import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { ALL_JOBS, expectedJobResults, verifyJobResults, verifyWorkflowCoverage } from './ci-required-policy.mjs';
import { ACTIONS_APP_ID, qualifyRelease, selectCiRun, verifyBranchRules } from './verify-release-ci.mjs';
import { BUILD_CHECKS, verifyArtifactRun } from './verify-release-artifact-run.mjs';

const read = (relative) => fs.readFileSync(new URL(relative, import.meta.url), 'utf8').replaceAll('\r\n', '\n');
const repository = 'owner/northstar';
const commit = 'a'.repeat(40);
const tagSha = 'b'.repeat(40);
const tag = 'v0.2.0';

for (const scenario of ['missing', 'draft', 'published', 'duplicate', 'not-found', 'forbidden', 'server-error', 'network-error', 'malformed']) {
  test(`draft preparation handles ${scenario} without publishing`, () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'northstar-release-draft-'));
    try {
      const workflow = read('../.github/workflows/release.yml');
      const step = workflow.split('      - name: Create or update draft and upload assets\n')[1]
        .split(/^  verify-draft-downloads:/m)[0];
      const script = step.split('        run: |\n')[1].replace(/^          /gm, '');
      fs.mkdirSync(path.join(root, 'bin'));
      fs.mkdirSync(path.join(root, 'dist'));
      fs.writeFileSync(path.join(root, 'bin/git'), '#!/bin/sh\nprintf "%s\\n" "$RELEASE_COMMIT"\n', { mode: 0o700 });
      fs.writeFileSync(path.join(root, 'bin/gh'), `#!/usr/bin/env node
const fs = require('node:fs');
const args = process.argv.slice(2);
fs.appendFileSync(process.env.CALLS, JSON.stringify(args) + '\\n');
const stateFile = process.env.CALLS + '.tag';
if (args[0] === 'api' && args[2] === 'GET') {
  const scenario = process.env.SCENARIO;
  if (['missing', 'draft', 'published', 'duplicate'].includes(scenario)) {
    console.log(JSON.stringify([{id: 1, draft: false, tag_name: 'v0.1.0'}]));
    const release = {id: 42, draft: scenario !== 'published', tag_name: process.env.RELEASE_TAG};
    if (scenario === 'draft') fs.writeFileSync(stateFile, release.tag_name);
    console.log(JSON.stringify(scenario === 'missing' ? [] : scenario === 'duplicate' ? [release, release] : [release]));
  } else {
    const status = {'not-found': '404', forbidden: '403', 'server-error': '500'}[scenario];
    if (status) console.log(JSON.stringify({message: 'API error', status}));
    if (scenario === 'malformed') console.log('upstream error');
    process.exitCode = 1;
  }
} else if (args[0] === 'api' && args[2] === 'PATCH') {
  const tag = args.find(arg => arg.startsWith('tag_name='));
  fs.writeFileSync(stateFile, tag ? tag.slice('tag_name='.length) : 'untagged-draft');
} else if (args[0] === 'release' && args[1] === 'create') {
  fs.writeFileSync(stateFile, args[2]);
} else if (args[0] === 'release' && args[1] === 'upload') {
  if (fs.readFileSync(stateFile, 'utf8') !== args[2]) {
    console.error('release not found');
    process.exitCode = 1;
  }
}
`, { mode: 0o700 });
      fs.writeFileSync(path.join(root, 'dist/asset'), 'verified package');
      const digest = createHash('sha256').update('verified package').digest('hex');
      fs.writeFileSync(path.join(root, 'dist/SHA256SUMS'), `${digest}  asset\n`);
      fs.writeFileSync(path.join(root, 'release-notes.md'), 'Draft verification is still running.\n');
      const callsFile = path.join(root, 'calls.jsonl');
      const result = spawnSync('bash', ['-e', '-o', 'pipefail', '-c', script], {
        cwd: root, encoding: 'utf8', env: {
          PATH: `${path.join(root, 'bin')}:${process.env.PATH}`, SCENARIO: scenario, CALLS: callsFile,
          GITHUB_REPOSITORY: repository, RELEASE_TAG: tag, RELEASE_VERSION: '0.2.0', RELEASE_COMMIT: commit, GITHUB_SHA: commit,
          GITHUB_STEP_SUMMARY: path.join(root, 'summary'),
        },
      });
      const calls = fs.readFileSync(callsFile, 'utf8').trim().split('\n').map(JSON.parse);
      assert.deepEqual(calls[0], ['api', '--method', 'GET', '--paginate', `repos/${repository}/releases?per_page=100`]);
      if (!['missing', 'draft'].includes(scenario)) {
        assert.notEqual(result.status, 0, result.stdout + result.stderr);
        assert.equal(calls.length, 1, 'lookup failure or published release must prevent writes');
        return;
      }
      assert.equal(result.status, 0, result.stdout + result.stderr);
      assert.equal(calls.length, 3);
      if (scenario === 'missing') {
        assert.deepEqual(calls[1], ['release', 'create', tag, '--repo', repository, '--verify-tag', '--draft',
          '--title', 'Northstar 0.2.0', '--notes-file', 'release-notes.md']);
      } else {
        assert.deepEqual(calls[1], ['api', '--method', 'PATCH', `repos/${repository}/releases/42`,
          '-f', `tag_name=${tag}`, '-f', 'name=Northstar 0.2.0', '-F', 'body=@release-notes.md',
          '-F', 'draft=true', '-F', 'prerelease=false']);
      }
      assert.deepEqual(calls[2], ['release', 'upload', tag, 'dist/SHA256SUMS', 'dist/asset', '--repo', repository, '--clobber']);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
}

const baseRun = {
  id: 30, run_attempt: 2, workflow_id: 7, path: '.github/workflows/ci.yml',
  repository: { full_name: repository }, head_repository: { full_name: repository },
  head_sha: commit, head_branch: 'main', event: 'push', status: 'completed', conclusion: 'success',
};

function artifactFixture(mutate = () => {}) {
  const evidence = { commit, version: '0.2.0', published_images: true, workflow_run_id: 50, workflow_run_attempt: 1 };
  const run = { ...baseRun, id: 50, workflow_id: 8, path: '.github/workflows/release.yml', head_branch: tag,
    conclusion: 'failure' };
  const artifacts = [{ id: 70, name: 'verified-release-assets-0.2.0', expired: false, digest: `sha256:${'c'.repeat(64)}`,
    workflow_run: { id: 50, head_sha: commit } }];
  return { evidence, api: async (endpoint) => {
    let data;
    if (endpoint.endsWith('/workflows/release.yml')) data = { id: 8, path: run.path, state: 'active' };
    else if (endpoint.endsWith('/runs/50')) data = structuredClone(run);
    else if (endpoint.includes('/jobs?')) {
      const attempt = Number(endpoint.match(/attempts\/(\d+)/)[1]);
      data = { total_count: BUILD_CHECKS.length, jobs: BUILD_CHECKS.map((name) => ({ name,
        run_id: 50, run_attempt: attempt, head_sha: commit, status: 'completed', conclusion: 'success' })) };
    } else if (endpoint.includes('/artifacts?')) data = { total_count: artifacts.length, artifacts: structuredClone(artifacts) };
    else throw new Error(`unexpected endpoint: ${endpoint}`);
    mutate(endpoint, data);
    return data;
  } };
}

test('draft recovery accepts verified builds even when a later draft job failed', async () => {
  const fixture = artifactFixture();
  const result = await verifyArtifactRun({ ...fixture, repository, tag, commit, version: '0.2.0', runId: 50 });
  assert.equal(result.artifactId, 70);
  assert.equal(result.buildAttempt, 1);
});

test('draft recovery rejects unrelated runs, failed build checks and ambiguous or expired assets', async () => {
  const mutations = [
    (url, d) => { if (url.endsWith('/runs/50')) d.event = 'pull_request'; },
    (url, d) => { if (url.endsWith('/runs/50')) d.head_sha = 'd'.repeat(40); },
    (url, d) => { if (url.endsWith('/runs/50')) d.head_branch = 'main'; },
    (url, d) => { if (url.endsWith('/runs/50')) d.head_repository = { full_name: 'other/northstar' }; },
    (url, d) => { if (url.endsWith('/runs/50')) d.workflow_id = 9; },
    (url, d) => { if (url.endsWith('/workflows/release.yml')) d.state = 'disabled'; },
    (url, d) => { if (url.includes('/jobs?')) d.jobs.pop(); },
    (url, d) => { if (url.includes('/jobs?')) d.jobs.push(d.jobs[0]); },
    (url, d) => { if (url.includes('/attempts/1/jobs?')) d.jobs[0].conclusion = 'failure'; },
    (url, d) => { if (url.includes('/attempts/2/jobs?')) d.jobs[0].conclusion = 'failure'; },
    (url, d) => { if (url.includes('/jobs?')) d.jobs[0].run_attempt = 99; },
    (url, d) => { if (url.includes('/artifacts?')) d.artifacts[0].expired = true; },
    (url, d) => { if (url.includes('/artifacts?')) d.artifacts[0].workflow_run.head_sha = 'd'.repeat(40); },
    (url, d) => { if (url.includes('/artifacts?')) d.artifacts[0].digest = null; },
    (url, d) => { if (url.includes('/artifacts?')) { d.artifacts.push(d.artifacts[0]); d.total_count++; } },
  ];
  for (const mutate of mutations) {
    await assert.rejects(verifyArtifactRun({ ...artifactFixture(mutate), repository, tag, commit, version: '0.2.0', runId: 50 }));
  }
  for (const key of ['commit', 'version', 'published_images', 'workflow_run_id', 'workflow_run_attempt']) {
    const fixture = artifactFixture();
    fixture.evidence[key] = null;
    await assert.rejects(verifyArtifactRun({ ...fixture, repository, tag, commit, version: '0.2.0', runId: 50 }));
  }
  let reads = 0;
  const fixture = artifactFixture((url, d) => {
    if (url.endsWith('/runs/50') && ++reads > 1) d.run_attempt++;
  });
  await assert.rejects(verifyArtifactRun({ ...fixture, repository, tag, commit, version: '0.2.0', runId: 50 }), /changed/);
});
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
  const draft = workflow.split(/^  prepare-draft-release:\s*$/m)[1].split(/^  verify-draft-downloads:/m)[0];
  assert.ok(draft.includes("needs.release-qualification.result == 'success'"));
  assert.ok(draft.includes('node scripts/verify-release-artifact-run.mjs'));
  assert.ok(draft.includes('--source-digest "$RELEASE_COMMIT"'));
  assert.ok(draft.indexOf('node scripts/verify-release-artifact-run.mjs') < draft.indexOf('release create'));
  assert.ok(workflow.includes('"$GITHUB_REF" != refs/heads/main'));
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
  assert.ok(finalize.includes('--tag "$RELEASE_TAG" --verify-tag --draft'));
  assert.ok(!workflow.includes('--draft=false'));
});
