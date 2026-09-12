import fs from 'node:fs';
import { spawnSync } from 'node:child_process';

const result = spawnSync('cargo', ['metadata', '--format-version', '1', '--no-deps'], { encoding: 'utf8' });
if (result.status !== 0) throw new Error(result.stderr);
const metadata = JSON.parse(result.stdout);
const workspaceRoot = process.cwd().replaceAll('\\', '/');
const packages = metadata.packages
  .filter((pkg) => pkg.manifest_path.replaceAll('\\', '/').startsWith(`${workspaceRoot}/`))
  .filter((pkg) => pkg.name !== 'rust-xmpp-server')
  .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

function layer(name) {
  // PostgreSQL is an infrastructure boundary rather than a pure foundation
  // value crate. Keeping it distinct makes the sqlx dependency explicit in
  // the catalog while preserving the no-database rule for all other crates.
  if (name === 'foundation-postgres' || name === 'foundation-eventing-postgres') return 'infrastructure';
  if (name.startsWith('foundation-')) return 'foundation';
  if (name.includes('-core')) return 'domain';
  if (name.includes('-application')) return 'application';
  if (name.startsWith('northstar-xep-')) return 'xep';
  if (name.includes('web') || name.includes('runtime')) return 'adapter';
  if (name.startsWith('service-')) return 'service';
  if (name.startsWith('catalog-') || name.startsWith('architecture-') || name.startsWith('data-')) return 'tooling';
  return 'support';
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
function stability(layerName) { return ['foundation', 'infrastructure', 'domain', 'application', 'xep'].includes(layerName) ? 'internal-stable' : 'internal'; }
function allowed(layerName) {
  if (layerName === 'infrastructure') return ['foundation-*', 'serde', 'sqlx', 'thiserror', 'tokio'];
  if (layerName === 'domain') return ['foundation-*', 'northstar-xmpp-types', 'northstar-xep-*'];
  if (layerName === 'application') return ['northstar-*-core', 'foundation-*', 'northstar-*-contracts'];
  if (layerName === 'foundation') return ['foundation-*', 'serde', 'thiserror', 'uuid'];
  return ['*'];
}
function pathFor(pkg) { return pkg.manifest_path.replaceAll('\\', '/').replace(`${workspaceRoot}/`, '').replace(/\/Cargo\.toml$/, ''); }

const lines = [
  'version: "2.0.0"',
  '',
  '# Generated from cargo metadata. Layer and dependency policy are validated in CI.',
  'crates:',
];
for (const pkg of packages) {
  const layerName = layer(pkg.name);
  lines.push(`  - crate_id: ${pkg.name}`);
  lines.push(`    package: ${pkg.name}`);
  lines.push(`    path: ${pathFor(pkg)}`);
  lines.push(`    layer: ${layerName}`);
  lines.push(`    owner_team: ${owner(pkg.name)}`);
  lines.push(`    api_stability: ${stability(layerName)}`);
  lines.push(`    publish_policy: never`);
  lines.push('    allowed_dependencies:');
  for (const dependency of allowed(layerName)) lines.push(`      - ${dependency === '*' ? '"*"' : dependency}`);
  lines.push('');
}
fs.mkdirSync('catalog', { recursive: true });
fs.writeFileSync('catalog/crates.yaml', lines.join('\n').replace(/\s+$/, '\n'));
console.log(`Wrote crate catalog for ${packages.length} workspace packages.`);
