#!/usr/bin/env node

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function fail(message) {
  throw new Error(message);
}

function parseArgs(argv) {
  const values = new Map();
  const flags = new Set();
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith('--')) fail(`unexpected argument: ${token}`);
    const key = token.slice(2);
    if (key === 'quiet') {
      flags.add(key);
      continue;
    }
    const value = argv[index + 1];
    if (value == null || value.startsWith('--')) fail(`missing value for --${key}`);
    values.set(key, value);
    index += 1;
  }
  return { values, flags };
}

function option(args, name, fallback) {
  return args.values.get(name) ?? fallback;
}

function readJson(relativeOrAbsolute) {
  const filename = path.resolve(root, relativeOrAbsolute);
  try {
    return JSON.parse(fs.readFileSync(filename, 'utf8'));
  } catch (error) {
    fail(`cannot parse ${relativeOrAbsolute} as JSON-compatible YAML: ${error.message}`);
  }
}

function git(args) {
  try {
    return execFileSync('git', ['-C', root, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  } catch (error) {
    const stderr = String(error.stderr ?? '').trim();
    fail(`git ${args.join(' ')} failed${stderr ? `: ${stderr}` : ''}`);
  }
}

function verifyCommit(name, value) {
  if (!/^[0-9a-f]{40}$/i.test(value)) fail(`${name} must be a full immutable 40-character commit SHA`);
  const resolved = git(['rev-parse', `${value}^{commit}`]);
  if (resolved !== value) fail(`${name} does not resolve to its exact immutable commit`);
}

function parseInventory(text) {
  if (!text) return [];
  return text.split(/\r?\n/).filter(Boolean).map((line) => {
    const parts = line.split('\t');
    const kind = parts.shift();
    if (!kind) fail(`malformed git name-status line: ${line}`);
    if (kind.startsWith('R') || kind.startsWith('C')) {
      if (parts.length !== 2) fail(`malformed rename/copy inventory line: ${line}`);
      return { change: kind, path: parts[1], historical_paths: [parts[0]] };
    }
    if (parts.length !== 1) fail(`malformed inventory line: ${line}`);
    return { change: kind, path: parts[0], historical_paths: [] };
  });
}

function fixtureInventory(value) {
  let paths;
  try {
    paths = JSON.parse(value);
  } catch (error) {
    fail(`--inventory-json must be a JSON array: ${error.message}`);
  }
  if (!Array.isArray(paths) || paths.some((entry) => typeof entry !== 'string')) {
    fail('--inventory-json must contain only path strings');
  }
  return paths.map((entry) => ({ change: 'A', path: entry, historical_paths: [] }));
}

function matchingRules(rules, asset) {
  const candidates = [asset.path, ...asset.historical_paths];
  return rules.filter((rule) => candidates.some((candidate) =>
    (rule.exact_paths ?? []).includes(candidate)
      || (rule.prefixes ?? []).some((prefix) => candidate.startsWith(prefix)),
  ));
}

function parseDefaultMembers(cargoToml) {
  const match = /^default-members\s*=\s*\[([^\]]*)\]/m.exec(cargoToml);
  if (!match) fail('Cargo.toml must declare workspace default-members');
  return [...match[1].matchAll(/"([^"]+)"/g)].map((entry) => entry[1]);
}

function servicePrefixes(rules) {
  return rules
    .filter((rule) => rule.asset_kind === 'remote-service')
    .flatMap((rule) => rule.prefixes ?? [])
    .map((prefix) => prefix.replace(/\/$/, ''));
}

function validateManifest(manifest) {
  const allowed = new Set(manifest.allowed_states ?? []);
  const required = ['id', 'owner_task', 'asset_kind', 'production_reachable', 'current_state', 'activation_guard', 'review_result', 'future_action'];
  if (!Array.isArray(manifest.rules) || manifest.rules.length === 0) fail('asset manifest requires non-empty rules');
  for (const rule of manifest.rules) {
    for (const field of required) {
      if (!(field in rule)) fail(`asset rule ${rule.id ?? '<unknown>'} lacks ${field}`);
    }
    if (typeof rule.production_reachable !== 'boolean') fail(`asset rule ${rule.id} production_reachable must be boolean`);
    if (!allowed.has(rule.current_state)) fail(`asset rule ${rule.id} uses disallowed state ${rule.current_state}`);
    if ((rule.exact_paths?.length ?? 0) + (rule.prefixes?.length ?? 0) === 0) {
      fail(`asset rule ${rule.id} has no exact_paths or prefixes`);
    }
  }
}

function validateMergeAudit(audit, merge, checkpoint) {
  if (audit.merge_commit !== merge) fail('merge audit does not name the requested merge commit');
  if (!Array.isArray(audit.parents) || audit.parents.length !== 2) fail('merge audit must record exactly two parents');
  const actualParents = git(['rev-list', '--parents', '-n', '1', merge]).split(' ').slice(1);
  if (JSON.stringify(audit.parents) !== JSON.stringify(actualParents)) fail('merge audit parents differ from immutable git parent order');
  if (audit.parents[0] !== checkpoint) fail('merge audit first parent must be the unaccepted checkpoint');
  const expectedConflicts = [
    '.github/workflows/ci.yml',
    'README.md',
    'crates/foundation-contracts/src/common.rs',
    'crates/northstar-test-harness/src/lib.rs',
    'crates/northstar-test-harness/src/listener.rs',
    'crates/northstar-test-harness/src/process.rs',
    'docs/evidence/README.md',
    'docs/evidence/baselines/aa2b0df.yaml',
    'docs/microservices_architecture_and_cutover.md',
  ];
  const audited = audit.conflicts ?? [];
  if (audited.length !== expectedConflicts.length) fail('merge audit must record all nine conflict resolutions');
  const paths = audited.map((entry) => entry.path);
  if (new Set(paths).size !== paths.length) fail('merge audit contains duplicate conflict paths');
  for (const conflict of expectedConflicts) {
    if (!paths.includes(conflict)) fail(`merge audit lacks conflict decision for ${conflict}`);
  }
  const message = git(['show', '-s', '--format=%B', merge]);
  for (const conflict of expectedConflicts) {
    if (!message.includes(conflict)) fail(`immutable merge message no longer documents conflict ${conflict}`);
  }
}

function validateActivation(manifest, catalogPath, defaultMembersOverride) {
  const catalog = fs.readFileSync(path.resolve(root, catalogPath), 'utf8');
  const promoted = [...catalog.matchAll(/^\s+implementation_status:\s*(integrated|production-candidate|production)\s*$/gm)]
    .map((match) => match[1]);
  if (promoted.length > 0) fail(`catalog contains premature maturity: ${promoted.join(', ')}`);

  const defaultMembers = defaultMembersOverride
    ? JSON.parse(defaultMembersOverride)
    : parseDefaultMembers(fs.readFileSync(path.join(root, 'Cargo.toml'), 'utf8'));
  if (!Array.isArray(defaultMembers) || defaultMembers.some((entry) => typeof entry !== 'string')) {
    fail('default member override must be an array of paths');
  }
  if (defaultMembers.length !== 1 || defaultMembers[0] !== '.') {
    fail(`default-members must contain only the modular-monolith root, found: ${defaultMembers.join(', ')}`);
  }
  const main = fs.readFileSync(path.join(root, 'src', 'main.rs'), 'utf8');
  for (const servicePath of servicePrefixes(manifest.rules)) {
    if (main.includes(servicePath)) fail(`root production startup references dormant service path ${servicePath}`);
  }
  const exposed = manifest.rules.filter((rule) => rule.current_state !== 'accepted-by-M00-task' && rule.production_reachable);
  if (exposed.length > 0) fail(`unaccepted production-reachable assets exist: ${exposed.map((rule) => rule.id).join(', ')}`);
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const manifestPath = option(args, 'manifest', 'catalog/program6-asset-status.yaml');
  const auditPath = option(args, 'merge-audit', 'docs/evidence/merge-audits/e02503b.yaml');
  const catalogPath = option(args, 'catalog', 'catalog/services.yaml');
  const manifest = readJson(manifestPath);
  const base = option(args, 'base', manifest.inventory?.base_commit);
  const checkpoint = option(args, 'checkpoint', manifest.inventory?.checkpoint_commit);
  const merge = option(args, 'merge', manifest.inventory?.merge_commit);
  verifyCommit('base', base);
  verifyCommit('checkpoint', checkpoint);
  verifyCommit('merge', merge);
  validateManifest(manifest);
  validateMergeAudit(readJson(auditPath), merge, checkpoint);

  const inventory = args.values.has('inventory-json')
    ? fixtureInventory(option(args, 'inventory-json'))
    : parseInventory(git(['diff', '--name-status', `${base}..${checkpoint}`]));
  const expectedCount = manifest.inventory?.expected_change_records;
  if (!args.values.has('inventory-json') && inventory.length !== expectedCount) {
    fail(`checkpoint inventory count ${inventory.length} differs from manifest expectation ${expectedCount}`);
  }
  const resolved = inventory.map((asset) => {
    const matches = matchingRules(manifest.rules, asset);
    if (matches.length !== 1) {
      const identifiers = matches.map((rule) => rule.id).join(', ') || 'none';
      fail(`checkpoint asset ${asset.path} maps to ${identifiers}; exactly one rule is required`);
    }
    const rule = matches[0];
    return {
      path: asset.path,
      historical_paths: asset.historical_paths,
      change: asset.change,
      owner_task: rule.owner_task,
      asset_kind: rule.asset_kind,
      production_reachable: rule.production_reachable,
      current_state: rule.current_state,
      activation_guard: rule.activation_guard,
      review_result: rule.review_result,
      future_action: rule.future_action,
      rule_id: rule.id,
    };
  });
  const reverts = resolved.filter((asset) => asset.current_state === 'revert-required');
  if (reverts.length > 0) fail(`revert-required assets remain: ${reverts.map((asset) => asset.path).join(', ')}`);
  validateActivation(manifest, catalogPath, option(args, 'default-members-json', null));

  const report = {
    schema_version: '1.0',
    base_commit: base,
    checkpoint_commit: checkpoint,
    merge_commit: merge,
    inventory_count: resolved.length,
    summary: {
      integrated_services: 0,
      production_services: 0,
      revert_required: 0,
      unaccepted_production_reachable: 0,
    },
    assets: resolved,
  };
  const serialized = `${JSON.stringify(report, null, 2)}\n`;
  const output = option(args, 'output', null);
  if (output) fs.writeFileSync(path.resolve(root, output), serialized);
  if (!args.flags.has('quiet')) process.stdout.write(serialized);
}

try {
  main();
} catch (error) {
  console.error(`program-6 convergence check failed: ${error.message}`);
  process.exitCode = 1;
}
