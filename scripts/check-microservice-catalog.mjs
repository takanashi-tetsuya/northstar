import fs from 'node:fs';
import path from 'node:path';

// ---------------------------------------------------------------------------
// Robust recursive-descent YAML parser for Northstar catalogs
// Handles mappings, sequences, scalars, comments outside quotes, and nesting
// ---------------------------------------------------------------------------

function stripComment(line) {
  let inDouble = false;
  let inSingle = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"' && !inSingle && (i === 0 || line[i - 1] !== '\\')) {
      inDouble = !inDouble;
    } else if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
    } else if (ch === '#' && !inDouble && !inSingle) {
      return line.slice(0, i);
    }
  }
  return line;
}

function parseScalar(val) {
  val = val.trim();
  if (val === '' || val === '~' || val === 'null') return null;
  if (val === 'true') return true;
  if (val === 'false') return false;
  if (/^-?\d+$/.test(val)) return parseInt(val, 10);
  if (/^-?\d+\.\d+$/.test(val)) return parseFloat(val);
  if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
    return val.slice(1, -1);
  }
  return val;
}

function parseYamlDocument(text) {
  const rawLines = text.split(/\r?\n/);
  const lines = [];
  for (let i = 0; i < rawLines.length; i++) {
    const stripped = stripComment(rawLines[i]);
    if (!stripped.trim()) continue;
    const indent = stripped.search(/\S/);
    lines.push({ indent, text: stripped.trim() });
  }

  let cursor = 0;

  function parseBlock(currentIndent) {
    if (cursor >= lines.length) return null;
    const firstLine = lines[cursor];

    if (firstLine.text.startsWith('- ')) {
      const arr = [];
      while (cursor < lines.length && lines[cursor].indent === currentIndent && lines[cursor].text.startsWith('- ')) {
        const line = lines[cursor];
        const content = line.text.slice(2).trim();
        cursor++;

        if (content === '') {
          if (cursor < lines.length && lines[cursor].indent > currentIndent) {
            arr.push(parseBlock(lines[cursor].indent));
          } else {
            arr.push(null);
          }
        } else if (content.includes(':')) {
          const colonIdx = content.indexOf(':');
          const key = content.slice(0, colonIdx).trim().replace(/^["']|["']$/g, '');
          const valStr = content.slice(colonIdx + 1).trim();
          const obj = {};

          if (valStr === '') {
            if (cursor < lines.length && lines[cursor].indent > currentIndent) {
              obj[key] = parseBlock(lines[cursor].indent);
            } else {
              obj[key] = null;
            }
          } else {
            obj[key] = parseScalar(valStr);
          }

          const itemChildIndent = (cursor < lines.length && lines[cursor].indent > currentIndent) ? lines[cursor].indent : null;
          if (itemChildIndent !== null) {
            while (cursor < lines.length && lines[cursor].indent === itemChildIndent && !lines[cursor].text.startsWith('- ')) {
              const subLine = lines[cursor];
              const subColon = subLine.text.indexOf(':');
              if (subColon >= 0) {
                const subKey = subLine.text.slice(0, subColon).trim().replace(/^["']|["']$/g, '');
                const subVal = subLine.text.slice(subColon + 1).trim();
                cursor++;
                if (subVal === '') {
                  if (cursor < lines.length && lines[cursor].indent > subLine.indent) {
                    obj[subKey] = parseBlock(lines[cursor].indent);
                  } else {
                    obj[subKey] = null;
                  }
                } else {
                  obj[subKey] = parseScalar(subVal);
                }
              } else {
                cursor++;
              }
            }
          }
          arr.push(obj);
        } else {
          arr.push(parseScalar(content));
        }
      }
      return arr;
    } else {
      const obj = {};
      while (cursor < lines.length && lines[cursor].indent === currentIndent && !lines[cursor].text.startsWith('- ')) {
        const line = lines[cursor];
        const colonIdx = line.text.indexOf(':');
        if (colonIdx === -1) {
          cursor++;
          continue;
        }
        const key = line.text.slice(0, colonIdx).trim().replace(/^["']|["']$/g, '');
        const valStr = line.text.slice(colonIdx + 1).trim();
        cursor++;

        if (valStr === '') {
          if (cursor < lines.length && lines[cursor].indent > currentIndent) {
            obj[key] = parseBlock(lines[cursor].indent);
          } else {
            obj[key] = null;
          }
        } else {
          obj[key] = parseScalar(valStr);
        }
      }
      return obj;
    }
  }

  return parseBlock(0);
}

// ---------------------------------------------------------------------------
// Exact Cargo.toml Workspace Member Parser
// ---------------------------------------------------------------------------
function parseWorkspaceMembers(cargoTomlContent) {
  const members = new Set();
  const lines = cargoTomlContent.split(/\r?\n/);
  let inWorkspace = false;
  let inMembers = false;

  for (const rawLine of lines) {
    const line = stripComment(rawLine).trim();
    if (!line) continue;

    if (line.startsWith('[') && line.endsWith(']')) {
      inWorkspace = (line === '[workspace]');
      inMembers = false;
      continue;
    }

    if (inWorkspace && line.startsWith('members') && line.includes('=')) {
      inMembers = true;
      if (line.includes(']')) {
        const arrayContent = line.slice(line.indexOf('[') + 1, line.indexOf(']'));
        for (const item of arrayContent.split(',')) {
          const clean = item.trim().replace(/^["']|["']$/g, '');
          if (clean) members.add(clean);
        }
        inMembers = false;
      }
      continue;
    }

    if (inWorkspace && inMembers) {
      if (line.includes(']')) {
        const part = line.slice(0, line.indexOf(']')).trim();
        for (const item of part.split(',')) {
          const clean = item.trim().replace(/^["']|["']$/g, '');
          if (clean) members.add(clean);
        }
        inMembers = false;
      } else {
        for (const item of line.split(',')) {
          const clean = item.trim().replace(/^["']|["']$/g, '');
          if (clean) members.add(clean);
        }
      }
    }
  }

  return members;
}

// 1. Read catalog files
const servicesRaw = fs.readFileSync('catalog/services.yaml', 'utf8');
const routesRaw = fs.readFileSync('catalog/routes.yaml', 'utf8');
const ownershipRaw = fs.readFileSync('catalog/data-ownership.yaml', 'utf8');
const rootCargoRaw = fs.readFileSync('Cargo.toml', 'utf8');

const servicesDoc = parseYamlDocument(servicesRaw);
const routesDoc = parseYamlDocument(routesRaw);
const ownershipDoc = parseYamlDocument(ownershipRaw);
const workspaceMembers = parseWorkspaceMembers(rootCargoRaw);

console.log(`Loaded ${workspaceMembers.size} exact workspace members from Cargo.toml`);
const declaredServices = new Map();
const VALID_STATUSES = new Set([
  'planned',
  'scaffolded',
  'prototype',
  'executable-prototype',
  'integrated',
  'production'
]);

for (const svc of (servicesDoc.services || [])) {
  const serviceId = svc.service_id;
  if (!serviceId) continue;

  const status = svc.implementation_status || 'planned';
  if (!VALID_STATUSES.has(status)) {
    console.error(`ERROR: Service '${serviceId}' has invalid status '${status}'! Allowed: ${[...VALID_STATUSES].join(', ')}`);
    process.exit(1);
  }

  declaredServices.set(serviceId, {
    status,
    codePath: svc.code_path || null,
    cargoPackage: svc.cargo_package || null,
    database: svc.database || 'none'
  });
}

console.log(`Found ${declaredServices.size} declared services in catalog/services.yaml`);

// Count by status
const statusCounts = {
  planned: 0,
  scaffolded: 0,
  prototype: 0,
  'executable-prototype': 0,
  integrated: 0,
  production: 0
};

// Verify each service against its declared status tier
for (const [id, info] of declaredServices.entries()) {
  statusCounts[info.status]++;

  const expectedDir = info.codePath || `services/${id}`;

  if (info.status === 'planned') {
    continue;
  }

  // Tier 1+: scaffolded and above must have valid directory and workspace inclusion
  if (!fs.existsSync(expectedDir)) {
    console.error(`ERROR: Service '${id}' has status '${info.status}', but code path '${expectedDir}' does not exist!`);
    process.exit(1);
  }

  if (!workspaceMembers.has(expectedDir)) {
    console.error(`ERROR: Service '${id}' is not registered in root Cargo.toml workspace members!`);
    process.exit(1);
  }

  // Tier 2+: prototype must have src/lib.rs
  if (['prototype', 'executable-prototype', 'integrated', 'production'].includes(info.status)) {
    const libPath = path.join(expectedDir, 'src', 'lib.rs');
    if (!fs.existsSync(libPath)) {
      console.error(`ERROR: Service '${id}' has status '${info.status}', but '${libPath}' is missing!`);
      process.exit(1);
    }
  }

  // Tier 3+: executable-prototype must have src/main.rs and a binary target
  if (['executable-prototype', 'integrated', 'production'].includes(info.status)) {
    const mainPath = path.join(expectedDir, 'src', 'main.rs');
    if (!fs.existsSync(mainPath)) {
      console.error(`ERROR: Service '${id}' has status '${info.status}', but '${mainPath}' is missing!`);
      process.exit(1);
    }
    const manifestPath = path.join(expectedDir, 'Cargo.toml');
    const manifestContent = fs.readFileSync(manifestPath, 'utf8');
    if (!manifestContent.includes('[[bin]]')) {
      console.error(`ERROR: Service '${id}' has status '${info.status}', but Cargo.toml lacks [[bin]] definition!`);
      process.exit(1);
    }
  }

  // Tier 4+: integrated requires migration directory and verified RPC contract assets
  if (['integrated', 'production'].includes(info.status)) {
    if (info.database !== 'none') {
      const migrationDir = path.join(expectedDir, 'migrations');
      if (!fs.existsSync(migrationDir) || fs.readdirSync(migrationDir).filter(f => f.endsWith('.sql')).length === 0) {
        console.error(`ERROR: Service '${id}' claims status '${info.status}', but lacks dedicated SQL migrations in '${migrationDir}'!`);
        process.exit(1);
      }
    }
    // Verify Proto contract exists for this service
    const protoCandidates = [
      path.join('contracts/proto/northstar', id.replace(/-/g, '_'), 'v1'),
      path.join('contracts/proto/northstar', id, 'v1'),
      path.join('contracts/proto/northstar', id.replace(/^xep-\d+-/, ''), 'v1'),
    ];
    const protoFound = protoCandidates.some(p => fs.existsSync(p));
    if (!protoFound) {
      console.error(`ERROR: Service '${id}' declared status '${info.status}', but lacks defined protobuf wire contract in contracts/proto/northstar/!`);
      process.exit(1);
    }
  }

  // Tier 5: production requires deployment configuration (compose/k8s)
  if (info.status === 'production') {
    const k8sManifest = 'deploy/kubernetes';
    const composeManifest = 'deploy/compose/docker-compose.microservices.yml';
    if (!fs.existsSync(k8sManifest) && !fs.existsSync(composeManifest)) {
      console.error(`ERROR: Service '${id}' declared status 'production', but lacks deployment manifests in deploy/!`);
      process.exit(1);
    }
  }
}

console.log('Service Implementation Status Breakdown:');
console.log(`  - planned:              ${statusCounts.planned}`);
console.log(`  - scaffolded:          ${statusCounts.scaffolded}`);
console.log(`  - prototype:           ${statusCounts.prototype}`);
console.log(`  - executable-prototype: ${statusCounts['executable-prototype']}`);
console.log(`  - integrated:          ${statusCounts.integrated}`);
console.log(`  - production:          ${statusCounts.production}`);

// Verify that all directories in services/ are accounted for in catalog (0 orphan services)
const physicalServices = fs.readdirSync('services', { withFileTypes: true })
  .filter(d => d.isDirectory())
  .map(d => d.name);

for (const dir of physicalServices) {
  if (!declaredServices.has(dir)) {
    console.error(`ERROR: Orphan service directory found in services/: '${dir}' is not declared in catalog/services.yaml!`);
    process.exit(1);
  }
}
console.log(`Verified ${physicalServices.length} physical service directories (0 orphan services).`);

// 3. Verify routes
const routeKeys = new Set();
const routesList = Array.isArray(routesDoc.routes) ? routesDoc.routes : [];
if (routesList.length === 0) {
  console.error('ERROR: No routes found in catalog/routes.yaml!');
  process.exit(1);
}

for (const r of routesList) {
  const ns = r.namespace;
  const elem = r.element;
  const stanza = r.stanza;
  const phase = r.phase;
  const owner = r.owner;
  if (!ns || !elem || !stanza || !phase || !owner) {
    console.error(`ERROR: Malformed route entry: ${JSON.stringify(r)}`);
    process.exit(1);
  }
  const key = `${ns}::${elem}::${stanza}::${phase}`;
  if (routeKeys.has(key)) {
    console.error(`ERROR: Duplicate route detected: ${key}`);
    process.exit(1);
  }
  routeKeys.add(key);

  if (!declaredServices.has(owner)) {
    console.error(`ERROR: Route owner '${owner}' not found in catalog/services.yaml`);
    process.exit(1);
  }
}

console.log(`Verified ${routeKeys.size} unambiguous routes in catalog/routes.yaml`);

// 4. Verify data ownership
const tableSet = new Set();
const ownershipMap = ownershipDoc.ownership || {};
const ownershipEntries = Object.entries(ownershipMap);
if (ownershipEntries.length === 0) {
  console.error('ERROR: No ownership entries found in catalog/data-ownership.yaml!');
  process.exit(1);
}

for (const [ownerService, ownerData] of ownershipEntries) {
  if (!declaredServices.has(ownerService)) {
    console.error(`ERROR: Data owner '${ownerService}' not found in catalog/services.yaml`);
    process.exit(1);
  }
  const tables = Array.isArray(ownerData.tables) ? ownerData.tables : [];
  for (const table of tables) {
    if (tableSet.has(table)) {
      console.error(`ERROR: Duplicate table ownership detected: table '${table}' owned by multiple services!`);
      process.exit(1);
    }
    tableSet.add(table);
  }
}

console.log(`Verified ${tableSet.size} exclusive tables in catalog/data-ownership.yaml`);
console.log('Catalog validation successful: 0 orphan services, 0 duplicate routes, 0 shared tables.');
