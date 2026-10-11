import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs';
import { parseWorkflowJobs, selectSteps, localize } from './run-ci-offline.mjs';
import { repositoryRoot } from './lib/source-module.mjs';

test('parseWorkflowJobs on a small inline workflow', () => {
  const yaml = [
    'jobs:',
    '  job1:',
    '    env:',
    '      GLOBAL: "yes"',
    '    steps:',
    '      - name: step1',
    '        working-directory: dir1',
    '        env:',
    '          LOCAL: "no"',
    '        run: |',
    '          line1',
    '          ',
    '          line2',
    '      - run: echo single',
    '      - uses: some/action@v1',
    '        with:',
    '          key: val'
  ].join('\n');
  const jobs = parseWorkflowJobs(yaml);
  assert.equal(jobs.size, 1);
  const job = jobs.get('job1');
  assert.deepEqual(job.env, { GLOBAL: 'yes' });
  assert.equal(job.steps.length, 3);
  
  const step1 = job.steps[0];
  assert.equal(step1.name, 'step1');
  assert.equal(step1.workingDirectory, 'dir1');
  assert.deepEqual(step1.env, { LOCAL: 'no' });
  assert.equal(step1.run, 'line1\n\nline2\n');
  assert.equal(step1.runStyle, 'block');
  
  const step2 = job.steps[1];
  assert.equal(step2.run, 'echo single');
  assert.equal(step2.runStyle, 'inline');
  
  const step3 = job.steps[2];
  assert.equal(step3.run, undefined);
  assert.ok(step3.other.includes('uses'));
});

test('selectSteps fail-closed cases', () => {
  const baseYaml = [
    'jobs:',
    '  web-static:',
    '    steps:',
    '      - name: A',
    '        run: |',
    '          echo 1',
    '  rust-quality:',
    '    steps:',
    '      - name: Install pinned Rust 1.97.1 tools',
    '        run: echo install',
    '      - name: B',
    '        run: echo 2',
    '  protocol-fuzz:',
    '    steps:',
    '      - name: Verify fuzz targets exercise production parsers',
    '        run: echo 3'
  ].join('\n');
  
  // missing protocol-fuzz job
  const m1 = baseYaml.replace('  protocol-fuzz:', '  other-job:');
  assert.throws(() => selectSteps(parseWorkflowJobs(m1)), /Selected job missing: protocol-fuzz/);

  // missing steps list
  const m1b = baseYaml.replace(/    steps:[\s\S]*?(?=  rust-quality:)/, '');
  assert.throws(() => selectSteps(parseWorkflowJobs(m1b)), /has no steps list/);
  
  // missing step name to keep
  const m2 = baseYaml.replace('Verify fuzz targets exercise production parsers', 'Other step');
  assert.throws(() => selectSteps(parseWorkflowJobs(m2)), /missing in job protocol-fuzz/);

  // missing step name to skip
  const m3 = baseYaml.replace('Install pinned Rust 1.97.1 tools', 'Other install');
  assert.throws(() => selectSteps(parseWorkflowJobs(m3)), /missing in job rust-quality/);
  
  // if key
  const j1 = baseYaml.replace('run: |', 'if: always()\n        run: |');
  assert.throws(() => selectSteps(parseWorkflowJobs(j1)), /has 'if' or 'shell' key/);

  // shell key
  const j2 = baseYaml.replace('run: |', 'shell: sh\n        run: |');
  assert.throws(() => selectSteps(parseWorkflowJobs(j2)), /has 'if' or 'shell' key/);

  // folded scalar
  const j3 = baseYaml.replace('run: |', 'run: >');
  assert.throws(() => selectSteps(parseWorkflowJobs(j3)), /uses unsupported folded\/chomping run scalar/);

  // chomping scalar
  const j4 = baseYaml.replace('run: |', 'run: |-');
  assert.throws(() => selectSteps(parseWorkflowJobs(j4)), /uses unsupported folded\/chomping run scalar/);

  // chomping scalar 2
  const j4b = baseYaml.replace('run: |', 'run: |2');
  assert.throws(() => selectSteps(parseWorkflowJobs(j4b)), /uses unsupported folded\/chomping run scalar/);

  // ${{ in run
  const j5 = baseYaml.replace('echo 1', "echo ${{ github.sha }}");
  assert.throws(() => selectSteps(parseWorkflowJobs(j5)), /run script contains \$\{\{/);
  
  // ${{ in env
  const j6 = baseYaml.replace('run: |', 'env:\n          V: "${{ secrets.X }}"\n        run: |');
  assert.throws(() => selectSteps(parseWorkflowJobs(j6)), /env value contains \$\{\{/);
});

test('localize drops and keeps correctly', () => {
  const script = [
    'sudo bash scripts/x.sh',
    'bash scripts/ci-install-ubuntu-packages.sh age',
    'bash scripts/sudo-free.sh',
    'echo sudo',
    ''
  ].join('\n');
  const { script: kept, skipped } = localize(script);
  assert.equal(kept, 'bash scripts/sudo-free.sh\necho sudo\n');
  assert.deepEqual(skipped, [
    'sudo bash scripts/x.sh',
    'bash scripts/ci-install-ubuntu-packages.sh age'
  ]);
});

test('Real repository checks', () => {
  const workflowText = fs.readFileSync(path.join(repositoryRoot, '.github/workflows/ci.yml'), 'utf8');
  const jobs = parseWorkflowJobs(workflowText);
  const steps = selectSteps(jobs);
  
  let foundWebStatic = false;
  let rustInstallSelected = false;
  const keys = new Set();
  
  for (const step of steps) {
    assert.ok(!keys.has(step.key), `Duplicate key: ${step.key}`);
    keys.add(step.key);
    
    if (step.key.startsWith('web-static.')) {
      foundWebStatic = true;
      if (step.name === 'Check JavaScript syntax and invariants') {
        assert.ok(step.script.includes('node --test scripts/test-source-module.mjs'));
      }
    }
    
    if (step.key.startsWith('rust-quality.') && step.name === 'Install pinned Rust 1.97.1 tools') {
      rustInstallSelected = true;
    }
  }
  
  assert.ok(foundWebStatic, 'web-static job contributed no steps');
  assert.ok(!rustInstallSelected, 'rust-quality install step was selected');
});

test('CLI tests', () => {
  const scriptPath = path.join(repositoryRoot, 'scripts/run-ci-offline.mjs');
  
  let res = spawnSync(process.execPath, [scriptPath, '--list'], { encoding: 'utf8' });
  assert.equal(res.status, 0);
  assert.ok(res.stdout.includes('muc-cluster-wsl-static'));
  
  res = spawnSync(process.execPath, [scriptPath, '--unknown-arg'], { encoding: 'utf8' });
  assert.equal(res.status, 2);
  assert.ok(res.stderr.includes('Usage:'));

  res = spawnSync(process.execPath, [scriptPath, '--only', 'no-such-step'], { encoding: 'utf8' });
  assert.equal(res.status, 2);
  assert.ok(res.stderr.includes('Error: No steps selected'));
});
