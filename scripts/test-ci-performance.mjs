import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { ALWAYS_REQUIRED, verifyWorkflowCoverage } from './ci-required-policy.mjs';

const workflow = fs.readFileSync(new URL('../.github/workflows/ci.yml', import.meta.url), 'utf8');
const cache = fs.readFileSync(new URL('../.github/actions/rust-build-cache/action.yml', import.meta.url), 'utf8');
const release = fs.readFileSync(new URL('../.github/workflows/release.yml', import.meta.url), 'utf8');
const job = (source, name) => source.split(`  ${name}:\n`)[1]?.split(/^  [a-z][a-z0-9-]*:\s*$/m)[0];

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
  for (const [name, rounds] of [['listener-readiness-stress-regular', 20], ['listener-readiness-stress-scheduled', 100]]) {
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
  assert.ok(smoke.indexOf('Package verified runtime') > smoke.indexOf('Prove one round with two pairs'));
  assert.ok(smoke.includes('python3 scripts/ci-runtime-artifact.py pack'));
  assert.ok(smoke.includes('--build-log "$RUNNER_TEMP/runtime-build.jsonl"'));
  for (const lane of ['regular', 'scheduled']) {
    const block = job(workflow, `listener-readiness-stress-${lane}`);
    assert.match(block, /uses: actions\/download-artifact@[0-9a-f]{40}/);
    assert.ok(block.includes('name: listener-runtime-${{ github.sha }}-${{ github.run_attempt }}'));
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
