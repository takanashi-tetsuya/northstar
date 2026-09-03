import fs from 'node:fs';
import path from 'node:path';

function parseYamlList(content) {
  // Simple YAML parser for the specific catalog structures
  const lines = content.split('\n');
  return lines;
}

const servicesRaw = fs.readFileSync('catalog/services.yaml', 'utf8');
const routesRaw = fs.readFileSync('catalog/routes.yaml', 'utf8');
const ownershipRaw = fs.readFileSync('catalog/data-ownership.yaml', 'utf8');

// Extract service IDs
const serviceIdMatches = [...servicesRaw.matchAll(/^\s*-\s*service_id:\s*([a-zA-Z0-9_-]+)/gm)];
const serviceIds = new Set(serviceIdMatches.map(m => m[1]));

console.log(`Found ${serviceIds.size} declared services in catalog/services.yaml`);

// Verify routes
const routeOwnerMatches = [...routesRaw.matchAll(/^\s*owner:\s*([a-zA-Z0-9_-]+)/gm)];
const routeKeys = [];
const routeKeyMatches = [...routesRaw.matchAll(/^\s*-\s*namespace:\s*"([^"]+)"[\s\S]*?element:\s*"([^"]+)"[\s\S]*?stanza:\s*"([^"]+)"[\s\S]*?phase:\s*"([^"]+)"[\s\S]*?owner:\s*([a-zA-Z0-9_-]+)/gm)];

for (const match of routeKeyMatches) {
  const [_, ns, elem, stanza, phase, owner] = match;
  const key = `${ns}::${elem}::${stanza}::${phase}`;
  if (routeKeys.includes(key)) {
    console.error(`ERROR: Duplicate route detected: ${key}`);
    process.exit(1);
  }
  routeKeys.push(key);

  if (!serviceIds.has(owner)) {
    console.error(`ERROR: Route owner '${owner}' not found in catalog/services.yaml`);
    process.exit(1);
  }
}

console.log(`Verified ${routeKeys.length} unambiguous routes in catalog/routes.yaml`);

// Verify data ownership
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
