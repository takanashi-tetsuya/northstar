import fs from 'node:fs';
import path from 'node:path';

// 1. Read catalog files
const servicesRaw = fs.readFileSync('catalog/services.yaml', 'utf8');
const routesRaw = fs.readFileSync('catalog/routes.yaml', 'utf8');
const ownershipRaw = fs.readFileSync('catalog/data-ownership.yaml', 'utf8');
const rootCargoRaw = fs.readFileSync('Cargo.toml', 'utf8');

// 2. Parse services and status
const serviceBlocks = servicesRaw.split(/\n\s*-\s*service_id:\s*/).slice(1);
const declaredServices = new Map();

for (const block of serviceBlocks) {
  const lines = block.split('\n');
  const serviceId = lines[0].trim();
  let status = 'planned';
  let codePath = null;
  let cargoPkg = null;

  for (const line of lines.slice(1)) {
    const trimmed = line.trim();
    if (trimmed.startsWith('implementation_status:')) {
      status = trimmed.replace('implementation_status:', '').trim();
    } else if (trimmed.startsWith('code_path:')) {
      codePath = trimmed.replace('code_path:', '').trim().replace(/"/g, '');
    } else if (trimmed.startsWith('cargo_package:')) {
      cargoPkg = trimmed.replace('cargo_package:', '').trim().replace(/"/g, '');
    }
  }

  declaredServices.set(serviceId, { status, codePath, cargoPkg });
}

console.log(`Found ${declaredServices.size} declared services in catalog/services.yaml`);

// Count by status
let prototypeCount = 0;
let plannedCount = 0;

for (const [id, info] of declaredServices.entries()) {
  if (info.status === 'prototype' || info.status === 'integrated' || info.status === 'production') {
    prototypeCount++;
    // Verify directory exists
    const expectedDir = info.codePath || `services/${id}`;
    if (!fs.existsSync(expectedDir)) {
      console.error(`ERROR: Service '${id}' has status '${info.status}', but code path '${expectedDir}' does not exist!`);
      process.exit(1);
    }

    // Verify Cargo.toml has this member
    if (!rootCargoRaw.includes(expectedDir)) {
      console.error(`ERROR: Service '${id}' is not included in root Cargo.toml workspace members!`);
      process.exit(1);
    }
  } else {
    plannedCount++;
  }
}

console.log(`  - Prototypes implemented & verified in workspace: ${prototypeCount}`);
console.log(`  - Planned future services in catalog: ${plannedCount}`);

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
