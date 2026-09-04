import fs from 'node:fs';
import path from 'node:path';

// Parse a simple subset of YAML into JavaScript objects (documents, mappings, sequences)
function parseYaml(text) {
  const lines = text.split(/\r?\n/);
  const root = {};
  let currentServiceList = null;
  let currentItem = null;
  let currentKey = null;

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    const commentIdx = rawLine.indexOf('#');
    const line = (commentIdx >= 0 ? rawLine.slice(0, commentIdx) : rawLine);
    if (!line.trim()) continue;

    const indent = line.search(/\S/);
    const trimmed = line.trim();

    if (indent === 0 && trimmed.endsWith(':')) {
      const key = trimmed.slice(0, -1).trim();
      root[key] = [];
      currentServiceList = root[key];
      continue;
    }

    if (indent === 0 && trimmed.includes(':')) {
      const [k, ...v] = trimmed.split(':');
      root[k.trim()] = v.join(':').trim().replace(/^["']|["']$/g, '');
      currentServiceList = null;
      continue;
    }

    if (trimmed.startsWith('- ')) {
      const content = trimmed.slice(2).trim();
      if (content.includes(':')) {
        const [k, ...v] = content.split(':');
        currentItem = {
          [k.trim()]: v.join(':').trim().replace(/^["']|["']$/g, '')
        };
        if (currentServiceList) {
          currentServiceList.push(currentItem);
        }
      } else {
        if (currentServiceList) {
          currentServiceList.push(content.replace(/^["']|["']$/g, ''));
        }
      }
      currentKey = null;
      continue;
    }

    if (currentItem && trimmed.includes(':')) {
      const [k, ...v] = trimmed.split(':');
      const val = v.join(':').trim();
      if (val === '') {
        currentKey = k.trim();
        currentItem[currentKey] = [];
      } else {
        currentItem[k.trim()] = val.replace(/^["']|["']$/g, '');
        currentKey = null;
      }
      continue;
    }

    if (currentItem && currentKey && trimmed.startsWith('- ')) {
      const subVal = trimmed.slice(2).trim().replace(/^["']|["']$/g, '');
      if (Array.isArray(currentItem[currentKey])) {
        currentItem[currentKey].push(subVal);
      }
    }
  }

  return root;
}

// 1. Read catalog files
const servicesRaw = fs.readFileSync('catalog/services.yaml', 'utf8');
const routesRaw = fs.readFileSync('catalog/routes.yaml', 'utf8');
const ownershipRaw = fs.readFileSync('catalog/data-ownership.yaml', 'utf8');
const rootCargoRaw = fs.readFileSync('Cargo.toml', 'utf8');

const servicesDoc = parseYaml(servicesRaw);
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

  if (!rootCargoRaw.includes(expectedDir)) {
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

  // Tier 4+: integrated requires migration directory and verified RPC/persistence integration
  if (['integrated', 'production'].includes(info.status)) {
    if (info.database !== 'none') {
      const migrationDir = path.join(expectedDir, 'migrations');
      if (!fs.existsSync(migrationDir) || fs.readdirSync(migrationDir).filter(f => f.endsWith('.sql')).length === 0) {
        console.error(`ERROR: Service '${id}' claims status '${info.status}', but lacks dedicated SQL migrations in '${migrationDir}'!`);
        process.exit(1);
      }
    }
    // Strict guard: integrated and production require end-to-end integration proof
    console.error(`ERROR: Service '${id}' declared status '${info.status}', which requires verified cross-process RPC, DB, and Kafka integration gates!`);
    process.exit(1);
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
const routeKeyMatches = [...routesRaw.matchAll(/^\s*-\s*namespace:\s*"([^"]+)"[\s\S]*?element:\s*"([^"]+)"[\s\S]*?stanza:\s*"([^"]+)"[\s\S]*?phase:\s*"([^"]+)"[\s\S]*?owner:\s*([a-zA-Z0-9_-]+)/gm)];
const routeKeys = new Set();

for (const match of routeKeyMatches) {
  const [_, ns, elem, stanza, phase, owner] = match;
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
const tableMatches = [...ownershipRaw.matchAll(/^\s*-\s*([a-zA-Z0-9_]+)/gm)];
const tableSet = new Set();
for (const match of tableMatches) {
  const table = match[1];
  if (tableSet.has(table)) {
    console.error(`ERROR: Duplicate table ownership detected: table '${table}' owned by multiple services!`);
    process.exit(1);
  }
  tableSet.add(table);
}

console.log(`Verified ${tableSet.size} exclusive tables in catalog/data-ownership.yaml`);
console.log('Catalog validation successful: 0 orphan services, 0 duplicate routes, 0 shared tables.');
