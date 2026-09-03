import assert from 'node:assert/strict';
import path from 'node:path';

import { validatePluginArchitecture } from './check-plugin-architecture.mjs';

const root = path.resolve('synthetic-northstar');

function cargoPackage(name, dependencyNames = [], pluginMetadata = undefined) {
  const packageDirectory = path.join(root, 'crates', name);
  return {
    name,
    manifest_path: path.join(packageDirectory, 'Cargo.toml'),
    dependencies: dependencyNames.map((dependency) => ({ name: dependency })),
    metadata: pluginMetadata ? { 'northstar-xep': pluginMetadata } : {},
    targets: [{ kind: ['lib'] }],
  };
}

function rustCrate(name, source) {
  const file = path.join(root, 'crates', name, 'src', 'lib.rs');
  return {
    name,
    rustFiles: [file],
    sources: new Map([[file, source]]),
  };
}

const cleanSource = `
use northstar_xep_core::{ExtensionDescriptor, StanzaKind, StanzaRoute, XepId};
pub const XEP_ID: XepId = XepId::new(184);
pub const NAMESPACE: &str = "urn:xmpp:receipts";
pub static DESCRIPTOR: ExtensionDescriptor = ExtensionDescriptor {
    id: XEP_ID,
    name: "Receipts",
    default_enabled: true,
    dependencies: &[],
    conflicts: &[],
    disco_features: &[NAMESPACE],
    routes: &[StanzaRoute {
        stanza: StanzaKind::Message,
        namespace: NAMESPACE,
        local_name: "request",
    }],
};
`;

function cleanModel() {
  const coreName = 'northstar-xep-core';
  const pluginName = 'northstar-xep-0184';
  const coreDirectory = path.join(root, 'crates', coreName);
  const pluginDirectory = path.join(root, 'crates', pluginName);
  return {
    root,
    rootPackageName: 'rust-xmpp-server',
    rootDependencyNames: new Set([pluginName]),
    rootSource: 'fn parse() { northstar_xep_0184::parse_message(todo!()); }',
    xepDirectories: [coreDirectory, pluginDirectory],
    packages: [
      cargoPackage(coreName),
      cargoPackage(pluginName, [coreName], {
        id: 184,
        'route-ids': ['message|urn:xmpp:receipts|request'],
        'worker-ids': [],
      }),
    ],
    crates: new Map([
      [coreName, rustCrate(coreName, 'pub struct ExtensionDescriptor;')],
      [pluginName, rustCrate(pluginName, cleanSource)],
    ]),
  };
}

assert.deepEqual(validatePluginArchitecture(cleanModel()).violations, []);

{
  const model = cleanModel();
  model.rootSource = '// northstar_xep_0184::parse_message is intentionally only prose';
  const result = validatePluginArchitecture(model).violations.join('\n');
  assert.match(result, /has no root-server call site/);
}

{
  const model = cleanModel();
  model.packages[1].dependencies.push({ name: 'sqlx' }, { name: 'rust-xmpp-server' });
  const file = model.crates.get('northstar-xep-0184').rustFiles[0];
  model.crates.get('northstar-xep-0184').sources.set(
    file,
    `${cleanSource}\nfn escape() { let _: Option<AppState> = None; let _ = TcpStream::connect("ignored"); }`,
  );
  const result = validatePluginArchitecture(model).violations.join('\n');
  assert.match(result, /forbidden runtime capability sqlx/);
  assert.match(result, /forbidden runtime capability rust-xmpp-server/);
  assert.match(result, /global application state/);
  assert.match(result, /raw network stream\/listener/);
}

{
  const model = cleanModel();
  model.packages[1].dependencies.push({
    name: 'server-capability-wrapper',
    path: path.join(root, 'crates', 'server-capability-wrapper'),
  });
  const result = validatePluginArchitecture(model).violations.join('\n');
  assert.match(result, /outside the isolated XEP crate graph/);
}

{
  const model = cleanModel();
  const duplicateName = 'northstar-xep-0184-copy';
  const duplicateDirectory = path.join(root, 'crates', duplicateName);
  model.xepDirectories.push(duplicateDirectory);
  model.packages.push({
    ...cargoPackage(duplicateName, ['northstar-xep-core'], {
      id: 184,
      'route-ids': ['message|urn:xmpp:receipts|request'],
      'worker-ids': ['receipt-delivery'],
    }),
    manifest_path: path.join(duplicateDirectory, 'Cargo.toml'),
  });
  model.packages[1].metadata['northstar-xep']['worker-ids'] = ['receipt-delivery'];
  model.crates.set(duplicateName, rustCrate(duplicateName, cleanSource));
  const result = validatePluginArchitecture(model).violations.join('\n');
  assert.match(result, /is owned by both/);
  assert.match(result, /route .* is owned by both/);
  assert.match(result, /worker .* is owned by both/);
}

{
  const model = cleanModel();
  model.packages[1].metadata['northstar-xep']['route-ids'] = [
    'message|urn:xmpp:receipts|received',
  ];
  const result = validatePluginArchitecture(model).violations.join('\n');
  assert.match(result, /manifest routes .* differ from DESCRIPTOR routes/);
}

console.log('XEP plugin architecture gate self-test passed');
