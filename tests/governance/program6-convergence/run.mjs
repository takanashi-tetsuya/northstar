#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const checker = path.join(root, 'scripts', 'check-program6-convergence.mjs');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'northstar-program6-convergence-'));

function invoke(arguments_, expectedStatus = 0) {
  const result = spawnSync(process.execPath, [checker, ...arguments_], { cwd: root, encoding: 'utf8' });
  if (result.status !== expectedStatus) {
    throw new Error(`expected status ${expectedStatus}, got ${result.status}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
  }
  return result;
}

function expectFailure(arguments_, reason) {
  const result = invoke(arguments_, 1);
  if (!result.stderr.includes(reason)) {
    throw new Error(`negative fixture failed for the wrong reason; expected ${reason}\nstderr:\n${result.stderr}`);
  }
}

function write(name, contents) {
  const filename = path.join(temp, name);
  fs.writeFileSync(filename, contents);
  return filename;
}

try {
  const first = invoke([]).stdout;
  const second = invoke([]).stdout;
  if (first !== second) throw new Error('convergence report is not deterministic');
  if (first.includes(root)) throw new Error('convergence report leaked an absolute workspace path');
  const report = JSON.parse(first);
  if (report.inventory_count !== 212 || report.assets.length !== 212) {
    throw new Error('convergence report did not enumerate every fixed checkpoint change record');
  }

  expectFailure(['--inventory-json', '["unclassified/program6-asset.rs"]'], 'exactly one rule is required');

  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'catalog/program6-asset-status.yaml'), 'utf8'));
  const remote = manifest.rules.find((entry) => entry.asset_kind === 'remote-service');
  remote.production_reachable = true;
  expectFailure(
    ['--manifest', write('reachable.json', JSON.stringify(manifest)), '--inventory-json', '["services/identity/src/lib.rs"]'],
    'unaccepted production-reachable assets exist',
  );

  const reverted = JSON.parse(fs.readFileSync(path.join(root, 'catalog/program6-asset-status.yaml'), 'utf8'));
  reverted.rules.find((entry) => entry.id === 'm07-identity-service').current_state = 'revert-required';
  expectFailure(
    ['--manifest', write('revert-required.json', JSON.stringify(reverted)), '--inventory-json', '["services/identity/src/lib.rs"]'],
    'revert-required assets remain',
  );

  expectFailure(['--default-members-json', '[".", "services/identity"]'], 'default-members must contain only the modular-monolith root');

  const catalog = fs.readFileSync(path.join(root, 'catalog/services.yaml'), 'utf8')
    .replace('implementation_status: executable-prototype', 'implementation_status: integrated');
  expectFailure(['--catalog', write('promoted-catalog.yaml', catalog)], 'catalog contains premature maturity');

  const audit = JSON.parse(fs.readFileSync(path.join(root, 'docs/evidence/merge-audits/e02503b.yaml'), 'utf8'));
  audit.conflicts.pop();
  expectFailure(['--merge-audit', write('missing-conflict.json', JSON.stringify(audit))], 'must record all nine conflict resolutions');

  process.stdout.write('program-6 convergence negative fixtures passed\n');
} finally {
  fs.rmSync(temp, { recursive: true, force: true });
}
