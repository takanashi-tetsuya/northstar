import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';
import { ALWAYS_REQUIRED, expectedJobResults, verifyWorkflowCoverage } from './ci-required-policy.mjs';

const workflow = fs.readFileSync(new URL('../.github/workflows/ci.yml', import.meta.url), 'utf8');
const cache = fs.readFileSync(new URL('../.github/actions/rust-build-cache/action.yml', import.meta.url), 'utf8');
const release = fs.readFileSync(new URL('../.github/workflows/release.yml', import.meta.url), 'utf8');
const job = (source, name) => source.split(`  ${name}:\n`)[1]?.split(/^  [a-z][a-z0-9-]*:\s*$/m)[0];

// These scheduling expressions use the shared JS/Actions boolean subset.
// Evaluate the actual workflow fields so a changed event/ref boundary is tested.
function scheduling(source, github, inputs = {}) {
  const block = source.split('\nconcurrency:\n')[1].split('\njobs:')[0];
  const expression = text => vm.runInNewContext(text, {
    github, inputs, startsWith: (value, prefix) => value.startsWith(prefix),
    format: (template, value) => template.replace('{0}', value),
  }, { timeout: 100 });
  const group = block.match(/^  group: (.+)$/m)[1].replace(/\$\{\{(.*?)\}\}/g, (_, text) => expression(text));
  const cancel = expression(block.match(/^  cancel-in-progress: \$\{\{(.*?)\}\}$/m)[1]);
  return { group, cancel };
}

test('only superseded PR revisions share cancellable CI groups', () => {
  const event = (event_name, ref, run_id = 101, number = 3) => ({
    workflow: 'CI', event_name, ref, run_id, event: { pull_request: { number } },
  });
  for (const [name, ref, cancel] of [
    ['pull_request', 'refs/pull/3/merge', true],
    ['push', 'refs/heads/codex/release-contract-baseline', false],
    ['push', 'refs/heads/codex/fix', false],
    ['push', 'refs/heads/main', false], ['push', 'refs/heads/dev', false],
    ['push', 'refs/heads/feature', false], ['push', 'refs/tags/codex/fix', false],
    ['push', 'refs/tags/v0.2.0', false],
    ['schedule', 'refs/heads/main', false],
    ['workflow_dispatch', 'refs/heads/codex/fix', false],
  ]) {
    const first = scheduling(workflow, event(name, ref));
    const next = scheduling(workflow, event(name, ref, 102));
    assert.equal(first.cancel, cancel, `${name} ${ref}`);
    assert.equal(first.group === next.group, cancel, `${name} ${ref}`);
  }
  assert.notEqual(scheduling(workflow, event('pull_request', '', 101, 3)).group,
    scheduling(workflow, event('pull_request', '', 102, 4)).group);
});

test('every branch push and PR runs source CI; tags retain exact-source release qualification', () => {
  const triggers = workflow.split('\non:\n')[1].split('\npermissions:')[0];
  const push = triggers.split('  push:\n')[1].split(/^  [a-z_]+:/m)[0];
  assert.match(push, /^    branches: \['\*\*'\]$/m);
  assert.doesNotMatch(push, /tags:|branches-ignore:/);
  assert.match(triggers, /^  pull_request:$/m);
  assert.match(release, /tags:\n\s+- "v\*"/);
  assert.ok(job(release, 'release-qualification').includes('node scripts/verify-release-ci.mjs'));
});

test('load, cluster faults and parser fuzzing are mandatory on every source CI event', () => {
  for (const [name, command] of [
    ['protocol-fuzz', 'bash scripts/parser-robustness-wsl.sh'],
    ['production-envelope', 'bash scripts/load-1000-production-wsl.sh'],
    ['heavy-runtime-envelope', 'bash scripts/cluster-wsl.sh'],
  ]) {
    assert.ok(ALWAYS_REQUIRED.includes(name));
    const block = job(workflow, name);
    assert.doesNotMatch(block.split('    steps:')[0], /^    if:/m);
    assert.ok(block.includes(command));
    assert.doesNotMatch(block, /continue-on-error/);
  }
  assert.ok(job(workflow, 'heavy-runtime-envelope').includes('bash scripts/load-1000-wsl.sh'));
});

test('release previews supersede only matching development pushes; tag runs serialize', () => {
  const event = (event_name, ref, run_id = 101) => ({ event_name, ref, run_id });
  for (const [name, ref, cancel, shared] of [
    ['push', 'refs/heads/codex/release-test', true, true],
    ['push', 'refs/heads/main', false, true],
    ['push', 'refs/tags/v0.2.0', false, true],
    ['workflow_dispatch', 'refs/heads/codex/release-test', false, false],
    ['workflow_dispatch', 'refs/tags/v0.2.0', false, false],
  ]) {
    const first = scheduling(release, event(name, ref));
    const next = scheduling(release, event(name, ref, 102));
    assert.equal(first.cancel, cancel, `${name} ${ref}`);
    assert.equal(first.group === next.group, shared, `${name} ${ref}`);
  }
  assert.notEqual(scheduling(release, event('push', 'refs/tags/v0.2.0')).group,
    scheduling(release, event('push', 'refs/tags/v0.2.1')).group);
  const recovery = scheduling(release, event('workflow_dispatch', 'refs/heads/main'), { resume_tag: 'v0.2.0' });
  assert.equal(recovery.group, scheduling(release, event('push', 'refs/tags/v0.2.0')).group);
  assert.equal(recovery.cancel, false);
  assert.notEqual(recovery.group,
    scheduling(release, event('workflow_dispatch', 'refs/heads/main'), { resume_tag: 'v0.2.1' }).group);
});

function verifyPressureGate(source, name, rounds) {
  const block = job(source, name);
  assert.ok(block?.includes('needs: [listener-readiness-stress-smoke, listener-diagnostics]'));
  for (const dependency of ['listener-readiness-stress-smoke', 'listener-diagnostics']) {
    assert.ok(block.includes(`needs.${dependency}.result == 'success'`));
  }
  assert.ok(block.includes(`--rounds ${rounds} --pairs 50`));
  assert.ok(block.includes('NORTHSTAR_LISTENER_STRESS_WORKER_TIMEOUT_SECONDS: "900"'));
  assert.ok(block.includes('if-no-files-found: error'));
}

test('diagnostic preflight is required for every event and both pressure matrices', () => {
  verifyWorkflowCoverage(workflow);
  assert.ok(ALWAYS_REQUIRED.includes('listener-diagnostics'));
  for (const [name, rounds] of [['listener-readiness-stress-regular', 5], ['listener-readiness-stress-scheduled', '"$LISTENER_STRESS_ROUNDS"']]) {
    verifyPressureGate(workflow, name, rounds);
    for (const old of ['needs: [listener-readiness-stress-smoke, listener-diagnostics]',
                       "needs.listener-diagnostics.result == 'success'", `--rounds ${rounds} --pairs 50`]) {
      const block = job(workflow, name);
      const changed = workflow.replace(block, block.replace(old, 'REMOVED'));
      assert.throws(() => verifyPressureGate(changed, name, rounds));
    }
  }
  const diagnostic = job(workflow, 'listener-diagnostics');
  for (const path of ['test-listener-control-observer.py', 'test-listener-readiness-observed.py',
                      'test-listener-control-observer-pg17.py', 'test-listener-database-cleanup.py',
                      'test-fixture-certificate-cache.py', 'test-ci-runtime-artifact.py']) {
    assert.ok(diagnostic.includes(`python3 scripts/${path}`));
  }
  // The independent diagnostic job overlaps smoke; no new serial compile gate.
  assert.doesNotMatch(job(workflow, 'listener-readiness-stress-smoke'), /^    needs:/m);
});

test('manual CI defaults to regular checks and endurance requires explicit selection', () => {
  const triggers = workflow.split('\non:\n')[1].split('\npermissions:')[0];
  assert.match(triggers, /extended_stress:\n\s+description: [^\n]+\n\s+type: boolean\n\s+default: false/);
  assert.match(triggers, /scheduled_stress:\n\s+description: [^\n]+\n\s+type: boolean\n\s+default: false/);
  const regular = job(workflow, 'listener-readiness-stress-regular');
  const scheduled = job(workflow, 'listener-readiness-stress-scheduled');
  // Actions permits hyphens in dotted property names; JS needs bracket access.
  const expression = (value, event, extended, ready = true, endurance = false) => vm.runInNewContext(
    value.replace(/needs\.([a-z-]+)\.result/g, 'needs["$1"].result'), {
    github: { event_name: event }, inputs: { extended_stress: extended, scheduled_stress: endurance },
    needs: Object.fromEntries(['listener-readiness-stress-smoke', 'listener-diagnostics']
      .map(name => [name, { result: ready ? 'success' : 'failure' }])),
  }, { timeout: 100 });
  const condition = block => block.match(/    if: >-\n\s*\$\{\{([\s\S]*?)\}\}/)[1];
  const rounds = scheduled.match(/LISTENER_STRESS_ROUNDS: \$\{\{(.*?)\}\}/)[1];
  const deadline = scheduled.match(/timeout-minutes: \$\{\{(.*?)\}\}/)[1];
  for (const event of ['push', 'pull_request', 'schedule', 'workflow_dispatch']) {
    for (const endurance of [false, true]) {
      for (const extended of [false, true]) {
        const policy = expectedJobResults(event, endurance || extended);
        assert.equal(expression(condition(regular), event, extended, true, endurance),
          policy['listener-readiness-stress-regular'] === 'success');
        assert.equal(expression(condition(scheduled), event, extended, true, endurance),
          policy['listener-readiness-stress-scheduled'] === 'success');
        assert.equal(expression(condition(regular), event, extended, false, endurance), false);
        assert.equal(expression(condition(scheduled), event, extended, false, endurance), false);
      }
    }
    assert.equal(expression(rounds, event, false), 20);
    assert.equal(expression(deadline, event, false), 120);
    assert.equal(expression(rounds, event, true), event === 'workflow_dispatch' ? 100 : 20);
  }
  assert.equal(expression(rounds, 'workflow_dispatch', true), 100);
  assert.equal(expression(deadline, 'workflow_dispatch', true), 360);
});

test('cache restores retain mandatory Cargo commands and checked runtime builds', () => {
  for (const [name, command] of [
    ['rust-check', 'cargo check --workspace --all-targets --all-features --locked'],
    ['rust-test', 'cargo test --workspace --all-targets --all-features --locked'],
    ['rust-clippy', 'cargo clippy --workspace --all-targets --all-features --locked -- -D warnings'],
    ['rust-build', 'cargo build --workspace --bins --locked'],
  ]) {
    const block = job(workflow, name);
    assert.ok(block.includes(command));
    assert.ok(block.indexOf('uses: ./.github/actions/rust-build-cache') < block.indexOf(command));
    assert.doesNotMatch(block, /cache-hit|continue-on-error/);
  }
  for (const name of ['smoke']) {
    const block = job(workflow, `listener-readiness-stress-${name}`);
    assert.ok(block.includes('profile: runtime-test'));
    assert.doesNotMatch(block, /cache-hit|continue-on-error/);
  }
  const driver = fs.readFileSync(new URL('./listener-readiness-stress-wsl.sh', import.meta.url), 'utf8');
  assert.ok(driver.includes('cargo build "${cargo_args[@]}" --bin rust-xmpp-server'));
  assert.ok(driver.includes('--build-log "$runtime_dir/parent-preflight-build.raw.log"'));
});

test('pressure jobs restore only the verified smoke artifact from this run', () => {
  const smoke = job(workflow, 'listener-readiness-stress-smoke');
  const artifactName = 'name: listener-runtime-${{ github.sha }}-${{ github.run_id }}';
  assert.ok(smoke.indexOf('Package verified runtime') > smoke.indexOf('Prove one round with two pairs'));
  assert.ok(smoke.includes('python3 scripts/ci-runtime-artifact.py pack'));
  assert.ok(smoke.includes('--build-log "$RUNNER_TEMP/runtime-build.jsonl"'));
  assert.ok(smoke.includes(artifactName));
  assert.ok(smoke.includes('overwrite: true'));
  for (const lane of ['regular', 'scheduled']) {
    const block = job(workflow, `listener-readiness-stress-${lane}`);
    assert.match(block, /uses: actions\/download-artifact@[0-9a-f]{40}/);
    assert.ok(block.includes(artifactName));
    assert.ok(block.includes('digest-mismatch: error'));
    assert.ok(block.includes('NORTHSTAR_RUNTIME_ARTIFACT_DIR: ${{ runner.temp }}/northstar-runtime-fixture'));
    assert.doesNotMatch(block, /rust-build-cache|cargo fetch|continue-on-error|github-token:|run-id:/);
  }
  const driver = fs.readFileSync(new URL('./listener-readiness-stress-wsl.sh', import.meta.url), 'utf8');
  assert.ok(driver.includes('scripts/ci-runtime-artifact.py" restore'));
  assert.ok(driver.includes('--bundle "$NORTHSTAR_RUNTIME_ARTIFACT_DIR" --binary "$candidate" || return 1'));
});

test('cache boundaries include platform, toolchain, profile and dependency configuration', () => {
  const keys = cache.split('\n').filter(line => /^\s*key: /.test(line));
  assert.equal(keys.length, 2);
  assert.equal(keys[0], keys[1], 'producer and consumers must address the same compiler-work bucket');
  const releaseKeys = release.split('\n').filter(line => /^\s*key: native-release-/.test(line));
  assert.equal(releaseKeys.length, 1);
  for (const key of [...keys, ...releaseKeys]) {
    assert.doesNotMatch(key, /github\.(?:sha|run_id|run_attempt)/,
      'source revisions must not create another multi-GB compiler cache');
  }
  for (const part of ['runner.os', 'matrix.runner', 'matrix.target', '1.97.1-crt-static',
                      '**/Cargo.lock', '**/Cargo.toml', '.cargo/config*', 'rust-toolchain*']) {
    assert.ok(releaseKeys[0].includes(part));
  }
  const native = job(release, 'build-binaries');
  assert.ok(native.includes('cargo build --release --locked --target ${{ matrix.target }}'));
  assert.doesNotMatch(native, /cache-hit/);
  for (const line of cache.split('\n').filter(line => line.includes('rust-v1-'))) {
    for (const part of ['runner.os', 'steps.platform.outputs.version', 'runner.arch', '1.97.1',
                        'inputs.profile', '**/Cargo.lock', '**/Cargo.toml', '.cargo/config*']) {
      assert.ok(line.includes(part));
    }
  }
  assert.ok(cache.includes('!target/${{ inputs.profile }}/incremental'));
  assert.doesNotMatch(cache, /credentials|\.pgpass|\.cargo\/config\s*$/m);
  for (const match of cache.matchAll(/uses: actions\/cache(?:\/restore)?@([^\s]+)/g)) {
    assert.match(match[1], /^[0-9a-f]{40}$/);
  }
  assert.equal((workflow.match(/save: "true"/g) ?? []).length, 1);
  assert.ok(job(workflow, 'rust-test').includes('save: "true"'));
  assert.ok(job(workflow, 'listener-readiness-stress-smoke').includes('save: "${{ matrix.fixture == \'federation\' }}"'));
});
