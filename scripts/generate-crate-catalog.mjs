import fs from 'node:fs';
import { spawnSync } from 'node:child_process';

const result = spawnSync('cargo', ['metadata', '--format-version', '1', '--no-deps'], { encoding: 'utf8' });
if (result.status !== 0) throw new Error(result.stderr);
const metadata = JSON.parse(result.stdout);
const workspaceRoot = process.cwd().replaceAll('\\', '/');
const packages = metadata.packages
  .filter((pkg) => pkg.manifest_path.replaceAll('\\', '/').startsWith(`${workspaceRoot}/`))
  .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

function tierOf(relativePath) {
  if (relativePath === '.') {
    return { tier: 'composition' };
  }
  const parts = relativePath.split('/');
  if (parts.length === 3 && parts[0] === 'crates' && parts[2]) {
    if (parts[1] === 'kernel') return { tier: 'kernel' };
    if (parts[1] === 'platform') return { tier: 'platform' };
    if (parts[1] === 'edges') return { tier: 'edge' };
  }
  if (parts.length === 2 && parts[0] === 'tools' && parts[1]) {
    return { tier: 'tooling' };
  }
  if (parts.length === 4 && parts[0] === 'crates' && parts[1] === 'contexts' && parts[2] && parts[3]) {
    const context = parts[2];
    const name = parts[3];
    let role = 'core';
    if (name.endsWith('-application') || name === 'northstar-protocol-runtime') {
      role = 'application';
    } else if (name.endsWith('-postgres') || name.endsWith('-xmpp') || name.endsWith('-http')) {
      role = 'adapter';
    }
    return { tier: 'context', context, role };
  }
  throw new Error(`${relativePath}: crate is outside the tier directories`);
}
function owner(name) {
  if (name.startsWith('foundation-')) return 'platform';
  if (name.includes('message') || name.includes('archive') || name.includes('delivery')) return 'messaging';
  if (name.includes('room') || name.includes('pubsub') || name.includes('xep-0045') || name.includes('xep-0060')) return 'realtime';
  if (name.includes('auth') || name.includes('identity') || name.includes('session')) return 'identity-session';
  if (name.includes('upload')) return 'storage';
  if (name.startsWith('service-')) return 'service-operations';
  return 'platform';
}
function stability(tier, role) {
  if (tier === 'kernel') return 'internal-stable';
  if (tier === 'context' && (role === 'core' || role === 'application')) return 'internal-stable';
  return 'internal';
}
function pathFor(pkg) {
  const normalized = pkg.manifest_path.replaceAll('\\', '/');
  if (normalized === `${workspaceRoot}/Cargo.toml`) return '.';
  return normalized.replace(`${workspaceRoot}/`, '').replace(/\/Cargo\.toml$/, '');
}

const lines = [
  'version: "3.0.0"',
  '',
  '# Generated from cargo metadata. Tiers come from the crate directory; architecture-validator enforces them.',
  'crates:',
];
for (const pkg of packages) {
  const relPath = pathFor(pkg);
  const tierInfo = tierOf(relPath);
  lines.push(`  - crate_id: ${pkg.name}`);
  lines.push(`    package: ${pkg.name}`);
  lines.push(`    path: ${relPath}`);
  lines.push(`    tier: ${tierInfo.tier}`);
  if (tierInfo.tier === 'context') {
    lines.push(`    context: ${tierInfo.context}`);
    lines.push(`    role: ${tierInfo.role}`);
  }
  lines.push(`    owner_team: ${owner(pkg.name)}`);
  lines.push(`    api_stability: ${stability(tierInfo.tier, tierInfo.role)}`);
  lines.push(`    publish_policy: never`);
  lines.push('');
}
fs.mkdirSync('catalog', { recursive: true });
fs.writeFileSync('catalog/crates.yaml', lines.join('\n').replace(/\s+$/, '\n'));
console.log(`Wrote crate catalog for ${packages.length} workspace packages.`);
