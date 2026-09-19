import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptPath = fileURLToPath(import.meta.url);
const repositoryRoot = path.resolve(path.dirname(scriptPath), '..');
const XEP_CRATE_PREFIX = 'northstar-xep-';
const XEP_CORE_PACKAGE = 'northstar-xep-core';
const ALLOWED_CAPABILITY_FREE_SHARED_CRATES = new Set([
  XEP_CORE_PACKAGE,
  'northstar-xmpp-types',
  'northstar-xml-builder',
]);

const forbiddenDependencies = new Set([
  'axum',
  'bb8',
  'deadpool',
  'deadpool-postgres',
  'hyper',
  'libc',
  'mio',
  'nix',
  'object_store',
  'postgres',
  'redis',
  'reqwest',
  'socket2',
  'sqlx',
  'tokio-postgres',
  'tonic',
  'tower',
  'tower-http',
  'windows-sys',
]);

const forbiddenSourceCapabilities = [
  ['Northstar global application state', /\bAppState\b/],
  ['PostgreSQL pool', /\bPgPool\b/],
  ['PostgreSQL connection', /\bPgConnection\b/],
  ['SQLx API', /\bsqlx\s*::/],
  ['Axum API', /\baxum\s*::/],
  ['Tokio network API', /\btokio\s*::\s*net\s*::/],
  ['standard-library TCP/UDP API', /\bstd\s*::\s*net\s*::\s*(?:TcpListener|TcpStream|UdpSocket)\b/],
  ['raw network stream/listener', /\b(?:TcpListener|TcpStream|UdpSocket|UnixListener|UnixStream)\b/],
  ['socket2 API', /\bsocket2\s*::/],
  ['libc socket API', /\blibc\s*::\s*(?:socket|connect|bind|listen|accept)\b/],
  ['nix socket API', /\bnix\s*::\s*sys\s*::\s*socket\b/],
  ['mio network API', /\bmio\s*::\s*net\b/],
  ['Windows network API', /\bwindows_sys\s*::[^;\n]*\bNetworking\b/],
  ['raw file descriptor/socket', /\b(?:RawFd|RawSocket)\b/],
  ['root server state module', /\bcrate\s*::\s*state\b/],
  ['root server crate', /\brust_xmpp_server\b/],
  ['connection actor registry', /\bConnectionActorRegistry\b/],
  ['out-of-crate Rust source inclusion', /\binclude\s*!\s*\(/],
  ['out-of-crate module path override', /#\s*\[\s*path\s*=/],
];

function normalized(value) {
  return path.resolve(value).toLowerCase();
}

function lineAt(source, index) {
  return source.slice(0, index).split(/\r?\n/).length;
}

function filesBelow(directory, extension) {
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const target = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...filesBelow(target, extension));
    else if (path.extname(entry.name) === extension) files.push(target);
  }
  return files;
}

// The capability scan ignores prose and literals. This prevents a crate-level
// comment such as "does not use AppState" from becoming a false positive while
// still preserving byte offsets and line numbers for executable identifiers.
export function maskRustCommentsAndStrings(source) {
  const output = [...source];
  const mask = (index) => {
    if (output[index] !== '\n' && output[index] !== '\r') output[index] = ' ';
  };
  let index = 0;
  while (index < source.length) {
    if (source.startsWith('//', index)) {
      while (index < source.length && source[index] !== '\n') mask(index++);
      continue;
    }
    if (source.startsWith('/*', index)) {
      let depth = 0;
      while (index < source.length) {
        if (source.startsWith('/*', index)) {
          mask(index++);
          mask(index++);
          depth += 1;
        } else if (source.startsWith('*/', index)) {
          mask(index++);
          mask(index++);
          depth -= 1;
          if (depth === 0) break;
        } else mask(index++);
      }
      continue;
    }
    const raw = /^(?:br|r)(#+)?"/.exec(source.slice(index));
    if (raw) {
      const hashes = raw[1] ?? '';
      const closing = `"${hashes}`;
      for (let count = 0; count < raw[0].length; count += 1) mask(index++);
      while (index < source.length && !source.startsWith(closing, index)) mask(index++);
      for (let count = 0; count < closing.length && index < source.length; count += 1) {
        mask(index++);
      }
      continue;
    }
    if (source[index] === '"') {
      mask(index++);
      while (index < source.length) {
        if (source[index] === '\\') {
          mask(index++);
          if (index < source.length) mask(index++);
        } else if (source[index] === '"') {
          mask(index++);
          break;
        } else mask(index++);
      }
      continue;
    }
    index += 1;
  }
  return output.join('');
}

function maskRustComments(source) {
  const output = [...source];
  const mask = (index) => {
    if (output[index] !== '\n' && output[index] !== '\r') output[index] = ' ';
  };
  let index = 0;
  let quoted = false;
  let escaped = false;
  while (index < source.length) {
    if (quoted) {
      if (escaped) escaped = false;
      else if (source[index] === '\\') escaped = true;
      else if (source[index] === '"') quoted = false;
      index += 1;
      continue;
    }
    const raw = /^(?:br|r)(#+)?"/.exec(source.slice(index));
    if (raw) {
      const closing = `"${raw[1] ?? ''}`;
      index += raw[0].length;
      const end = source.indexOf(closing, index);
      index = end < 0 ? source.length : end + closing.length;
      continue;
    }
    if (source[index] === '"') {
      quoted = true;
      index += 1;
      continue;
    }
    if (source.startsWith('//', index)) {
      while (index < source.length && source[index] !== '\n') mask(index++);
      continue;
    }
    if (source.startsWith('/*', index)) {
      let depth = 0;
      while (index < source.length) {
        if (source.startsWith('/*', index)) {
          mask(index++);
          mask(index++);
          depth += 1;
        } else if (source.startsWith('*/', index)) {
          mask(index++);
          mask(index++);
          depth -= 1;
          if (depth === 0) break;
        } else mask(index++);
      }
      continue;
    }
    index += 1;
  }
  return output.join('');
}

function balancedEnd(source, opening, openCharacter, closeCharacter) {
  let depth = 1;
  let index = opening + 1;
  let quote = false;
  let escaped = false;
  for (; index < source.length; index += 1) {
    const character = source[index];
    if (quote) {
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === '"') quote = false;
      continue;
    }
    if (character === '"') {
      quote = true;
      continue;
    }
    if (character === openCharacter) depth += 1;
    else if (character === closeCharacter) {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

function descriptorDeclaration(crate) {
  const declarations = [];
  for (const file of crate.rustFiles) {
    const source = maskRustComments(crate.sources.get(file));
    const declaration = /pub\s+static\s+DESCRIPTOR\s*:\s*ExtensionDescriptor\s*=\s*ExtensionDescriptor\s*\{/g;
    for (let match; (match = declaration.exec(source)) !== null; ) {
      const opening = source.indexOf('{', match.index);
      const closing = balancedEnd(source, opening, '{', '}');
      if (closing < 0) {
        return { error: `${file}: unterminated public ExtensionDescriptor` };
      }
      declarations.push({ file, source, body: source.slice(opening + 1, closing) });
      declaration.lastIndex = closing + 1;
    }
  }
  if (declarations.length !== 1) {
    return {
      error: `${crate.name}: expected exactly one public static DESCRIPTOR, found ${declarations.length}`,
    };
  }
  return declarations[0];
}

function descriptorIdentity(crate, declaration) {
  const allSource = crate.rustFiles
    .map((file) => maskRustComments(crate.sources.get(file)))
    .join('\n');
  const id = /pub\s+const\s+XEP_ID\s*:\s*XepId\s*=\s*XepId::new\((\d+)\)\s*;/.exec(allSource);
  if (!id) return { error: `${crate.name}: missing canonical pub const XEP_ID` };
  if (!/\bid\s*:\s*XEP_ID\s*,/.test(declaration.body)) {
    return { error: `${crate.name}: DESCRIPTOR.id must use the canonical XEP_ID constant` };
  }
  return { id: Number(id[1]) };
}

function descriptorRoutes(crate, declaration) {
  const routesField = /\broutes\s*:\s*&\s*\[/.exec(declaration.body);
  if (!routesField) return { error: `${crate.name}: DESCRIPTOR is missing its routes array` };
  const opening = declaration.body.indexOf('[', routesField.index);
  const closing = balancedEnd(declaration.body, opening, '[', ']');
  if (closing < 0) return { error: `${crate.name}: DESCRIPTOR routes array is unterminated` };
  const routesBody = declaration.body.slice(opening + 1, closing);
  const allSource = crate.rustFiles
    .map((file) => maskRustComments(crate.sources.get(file)))
    .join('\n');
  const stringConstants = new Map();
  const constantPattern = /pub\s+const\s+([A-Z][A-Z0-9_]*)\s*:\s*&str\s*=\s*"([^"]+)"\s*;/g;
  for (let match; (match = constantPattern.exec(allSource)) !== null; ) {
    stringConstants.set(match[1], match[2]);
  }
  const kindNames = new Map([
    ['Message', 'message'],
    ['Presence', 'presence'],
    ['IqGet', 'iq-get'],
    ['IqSet', 'iq-set'],
    ['Stream', 'stream'],
  ]);
  const routes = [];
  const routePattern = /StanzaRoute\s*\{/g;
  for (let match; (match = routePattern.exec(routesBody)) !== null; ) {
    const openingBrace = routesBody.indexOf('{', match.index);
    const closingBrace = balancedEnd(routesBody, openingBrace, '{', '}');
    if (closingBrace < 0) return { error: `${crate.name}: unterminated StanzaRoute` };
    const body = routesBody.slice(openingBrace + 1, closingBrace);
    const kind = /\bstanza\s*:\s*StanzaKind::([A-Za-z0-9_]+)/.exec(body)?.[1];
    const namespaceExpression = /\bnamespace\s*:\s*(?:"([^"]+)"|([A-Z][A-Z0-9_]*))/.exec(body);
    const localName = /\blocal_name\s*:\s*"([^"]+)"/.exec(body)?.[1];
    const canonicalKind = kindNames.get(kind);
    const canonicalNamespace =
      namespaceExpression?.[1] ?? stringConstants.get(namespaceExpression?.[2]);
    if (!canonicalKind || !canonicalNamespace || !localName) {
      return { error: `${crate.name}: every StanzaRoute must use a known stanza kind and static namespace/local name` };
    }
    routes.push(`${canonicalKind}|${canonicalNamespace}|${localName}`);
    routePattern.lastIndex = closingBrace + 1;
  }
  return { routes };
}

function northstarMetadata(packageRecord) {
  return packageRecord.metadata?.['northstar-xep'];
}

function recordViolation(violations, message) {
  violations.push(message);
}

export function validatePluginArchitecture(model) {
  const violations = [];
  const xepPackages = model.packages.filter((packageRecord) =>
    packageRecord.name.startsWith(XEP_CRATE_PREFIX),
  );
  const byManifest = new Map(
    xepPackages.map((packageRecord) => [normalized(packageRecord.manifest_path), packageRecord]),
  );

  for (const directory of model.xepDirectories) {
    const manifest = normalized(path.join(directory, 'Cargo.toml'));
    if (!byManifest.has(manifest)) {
      recordViolation(
        violations,
        `${path.relative(model.root, directory)} is not an active Cargo workspace package`,
      );
    }
  }
  for (const packageRecord of xepPackages) {
    const directory = path.dirname(packageRecord.manifest_path);
    if (!model.xepDirectories.some((entry) => normalized(entry) === normalized(directory))) {
      recordViolation(
        violations,
        `${packageRecord.name} is outside crates/${XEP_CRATE_PREFIX}* and bypasses the XEP crate boundary`,
      );
    }
    const expectedName = path.basename(directory);
    if (packageRecord.name !== expectedName) {
      recordViolation(
        violations,
        `${path.relative(model.root, packageRecord.manifest_path)} package name ${packageRecord.name} does not match ${expectedName}`,
      );
    }
    if (!packageRecord.targets.some((target) => target.kind.includes('lib'))) {
      recordViolation(violations, `${packageRecord.name} is not a Rust library`);
    }
    if (packageRecord.targets.some((target) => target.kind.includes('bin'))) {
      recordViolation(violations, `${packageRecord.name} must not own an executable target`);
    }
    if (packageRecord.targets.some((target) => target.kind.includes('custom-build'))) {
      recordViolation(violations, `${packageRecord.name} must not execute a Cargo build script`);
    }
    for (const dependency of packageRecord.dependencies) {
      if (dependency.name === model.rootPackageName || forbiddenDependencies.has(dependency.name)) {
        recordViolation(
          violations,
          `${packageRecord.name} depends on forbidden runtime capability ${dependency.name}`,
        );
      }
      if (
        dependency.path &&
        !ALLOWED_CAPABILITY_FREE_SHARED_CRATES.has(dependency.name) &&
        !model.xepDirectories.some((directory) =>
          normalized(dependency.path).startsWith(`${normalized(directory)}${path.sep}`),
        ) &&
        !model.xepDirectories.some((directory) => normalized(dependency.path) === normalized(directory))
      ) {
        recordViolation(
          violations,
          `${packageRecord.name} depends on local crate ${dependency.name} outside the isolated XEP crate graph`,
        );
      }
    }

    const crate = model.crates.get(packageRecord.name);
    if (!crate) {
      recordViolation(violations, `${packageRecord.name} source tree could not be inspected`);
      continue;
    }
    for (const file of crate.rustFiles) {
      const source = crate.sources.get(file);
      const executableSource = maskRustCommentsAndStrings(source);
      for (const [capability, pattern] of forbiddenSourceCapabilities) {
        const match = pattern.exec(executableSource);
        if (match) {
          recordViolation(
            violations,
            `${path.relative(model.root, file)}:${lineAt(source, match.index)} uses forbidden ${capability}`,
          );
        }
      }
    }
  }

  const core = xepPackages.find((packageRecord) => packageRecord.name === XEP_CORE_PACKAGE);
  if (!core) recordViolation(violations, `workspace is missing ${XEP_CORE_PACKAGE}`);
  const concrete = xepPackages.filter((packageRecord) => packageRecord.name !== XEP_CORE_PACKAGE);
  if (concrete.length === 0) {
    recordViolation(violations, 'workspace has no independently compiled concrete XEP plugin');
  }

  const pluginOwners = new Map();
  const routeOwners = new Map();
  const workerOwners = new Map();
  for (const packageRecord of concrete) {
    if (!model.rootDependencyNames.has(packageRecord.name)) {
      recordViolation(
        violations,
        `${packageRecord.name} is not consumed by the root server package`,
      );
    }
    const rustModuleName = packageRecord.name.replaceAll('-', '_');
    if (!new RegExp(`\\b${rustModuleName}\\b`).test(maskRustCommentsAndStrings(model.rootSource))) {
      recordViolation(
        violations,
        `${packageRecord.name} is declared as a dependency but has no root-server call site`,
      );
    }
    if (!packageRecord.dependencies.some((dependency) => dependency.name === XEP_CORE_PACKAGE)) {
      recordViolation(violations, `${packageRecord.name} does not depend on ${XEP_CORE_PACKAGE}`);
    }
    const metadata = northstarMetadata(packageRecord);
    if (!metadata || typeof metadata !== 'object') {
      recordViolation(
        violations,
        `${packageRecord.name} is missing [package.metadata.northstar-xep] ownership metadata`,
      );
      continue;
    }
    const pluginId = metadata.id;
    if (!Number.isInteger(pluginId) || pluginId < 1 || pluginId > 65_535) {
      recordViolation(violations, `${packageRecord.name} has invalid northstar-xep.id ${pluginId}`);
      continue;
    }
    const expectedPackage = `${XEP_CRATE_PREFIX}${String(pluginId).padStart(4, '0')}`;
    if (packageRecord.name !== expectedPackage) {
      recordViolation(
        violations,
        `${packageRecord.name} declares XEP-${String(pluginId).padStart(4, '0')} but must be named ${expectedPackage}`,
      );
    }
    if (pluginOwners.has(pluginId)) {
      recordViolation(
        violations,
        `XEP-${String(pluginId).padStart(4, '0')} is owned by both ${pluginOwners.get(pluginId)} and ${packageRecord.name}`,
      );
    } else pluginOwners.set(pluginId, packageRecord.name);

    const routeIds = metadata['route-ids'];
    const workerIds = metadata['worker-ids'];
    if (!Array.isArray(routeIds) || !routeIds.every((route) => typeof route === 'string')) {
      recordViolation(violations, `${packageRecord.name} northstar-xep.route-ids must be a string array`);
    }
    if (!Array.isArray(workerIds) || !workerIds.every((worker) => typeof worker === 'string')) {
      recordViolation(violations, `${packageRecord.name} northstar-xep.worker-ids must be a string array`);
    }

    const crate = model.crates.get(packageRecord.name);
    const declaration = crate && descriptorDeclaration(crate);
    if (declaration?.error) recordViolation(violations, declaration.error);
    else if (declaration) {
      const identity = descriptorIdentity(crate, declaration);
      if (identity.error) recordViolation(violations, identity.error);
      else if (identity.id !== pluginId) {
        recordViolation(
          violations,
          `${packageRecord.name} manifest XEP id ${pluginId} differs from DESCRIPTOR id ${identity.id}`,
        );
      }
      const routes = descriptorRoutes(crate, declaration);
      if (routes.error) recordViolation(violations, routes.error);
      else if (Array.isArray(routeIds)) {
        const declared = [...new Set(routeIds)].sort();
        const implemented = [...new Set(routes.routes)].sort();
        if (declared.length !== routeIds.length) {
          recordViolation(violations, `${packageRecord.name} repeats a route id in its manifest`);
        }
        if (JSON.stringify(declared) !== JSON.stringify(implemented)) {
          recordViolation(
            violations,
            `${packageRecord.name} manifest routes ${JSON.stringify(declared)} differ from DESCRIPTOR routes ${JSON.stringify(implemented)}`,
          );
        }
      }
    }

    if (Array.isArray(routeIds)) {
      for (const routeId of routeIds) {
        if (!/^(?:message|presence|iq-get|iq-set|stream)\|[^|]+\|[^|]+$/.test(routeId)) {
          recordViolation(violations, `${packageRecord.name} has malformed route id ${routeId}`);
        }
        if (routeOwners.has(routeId) && routeOwners.get(routeId) !== packageRecord.name) {
          recordViolation(
            violations,
            `route ${routeId} is owned by both ${routeOwners.get(routeId)} and ${packageRecord.name}`,
          );
        } else routeOwners.set(routeId, packageRecord.name);
      }
    }
    if (Array.isArray(workerIds)) {
      const localWorkers = new Set();
      for (const workerId of workerIds) {
        if (!/^[a-z0-9][a-z0-9._:-]*$/.test(workerId)) {
          recordViolation(violations, `${packageRecord.name} has malformed worker id ${workerId}`);
        }
        if (localWorkers.has(workerId)) {
          recordViolation(violations, `${packageRecord.name} repeats worker id ${workerId}`);
        }
        localWorkers.add(workerId);
        if (workerOwners.has(workerId) && workerOwners.get(workerId) !== packageRecord.name) {
          recordViolation(
            violations,
            `worker ${workerId} is owned by both ${workerOwners.get(workerId)} and ${packageRecord.name}`,
          );
        } else workerOwners.set(workerId, packageRecord.name);
      }
    }
  }

  return {
    violations,
    xepPackageCount: xepPackages.length,
    concretePluginCount: concrete.length,
    routeCount: routeOwners.size,
    workerCount: workerOwners.size,
  };
}

function loadRepositoryModel(root) {
  const metadata = JSON.parse(
    execFileSync(
      'cargo',
      ['metadata', '--no-deps', '--format-version', '1', '--locked'],
      { cwd: root, encoding: 'utf8', windowsHide: true },
    ),
  );
  const rootManifest = normalized(path.join(root, 'Cargo.toml'));
  const rootPackage = metadata.packages.find(
    (packageRecord) => normalized(packageRecord.manifest_path) === rootManifest,
  );
  if (!rootPackage) throw new Error('Cargo metadata does not contain the root server package');
  const rootRustFiles = filesBelow(path.join(root, 'src'), '.rs');
  const cratesDirectory = path.join(root, 'crates');
  const xepDirectories = fs
    .readdirSync(cratesDirectory, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && entry.name.startsWith(XEP_CRATE_PREFIX))
    .map((entry) => path.join(cratesDirectory, entry.name));
  const crates = new Map();
  for (const directory of xepDirectories) {
    const name = path.basename(directory);
    const rustFiles = filesBelow(path.join(directory, 'src'), '.rs');
    crates.set(name, {
      name,
      rustFiles,
      sources: new Map(rustFiles.map((file) => [file, fs.readFileSync(file, 'utf8')])),
    });
  }
  return {
    root,
    rootPackageName: rootPackage.name,
    rootDependencyNames: new Set(rootPackage.dependencies.map((dependency) => dependency.name)),
    rootSource: rootRustFiles.map((file) => fs.readFileSync(file, 'utf8')).join('\n'),
    packages: metadata.packages,
    xepDirectories,
    crates,
  };
}

function main() {
  const result = validatePluginArchitecture(loadRepositoryModel(repositoryRoot));
  if (result.violations.length > 0) {
    throw new Error(`XEP plugin architecture boundary violations:\n${result.violations.join('\n')}`);
  }
  console.log(
    `XEP plugin architecture passed: ${result.concretePluginCount} concrete plugin(s), ` +
      `${result.routeCount} exclusive route(s), ${result.workerCount} declared worker(s); ` +
      'no server, database, HTTP, or raw-socket capability crosses the crate boundary',
  );
}

if (process.argv[1] && normalized(process.argv[1]) === normalized(scriptPath)) main();
