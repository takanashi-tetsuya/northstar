import fs from 'node:fs';

const omemo = fs.readFileSync(new URL('../web/omemo.js', import.meta.url), 'utf8');
const xmpp = fs.readFileSync(new URL('../web/xmpp.js', import.meta.url), 'utf8');

function requirePattern(source, pattern, message) {
  if (!pattern.test(source)) throw new Error(message);
}

requirePattern(omemo, /const STORE_VERSION = 2;/, 'OMEMO persisted-state migration version is missing');
requirePattern(omemo, /nextPreKeyId/, 'OMEMO prekeys do not use rotating IDs');
requirePattern(omemo, /ensureDeviceAnnouncement/, 'OMEMO device-list convergence is missing');
requirePattern(omemo, /owner !== this\.account[\s\S]+deviceRepair/, 'own PEP events do not repair overwritten device IDs');
requirePattern(omemo, /accessModel: 'open', maxItems: 'max'/, 'OMEMO bundle publish-options are incomplete');
requirePattern(omemo, /accessModel: 'open' \}\);/, 'OMEMO device-list access model is not open');
requirePattern(xmpp, /retractPep\(node, itemId/, 'PEP item retraction is unavailable to OMEMO');

console.log('OMEMO multi-device static checks passed');
