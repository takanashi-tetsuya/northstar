import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const scriptsDirectory = path.join(root, 'scripts');
const violations = [];

for (const entry of fs.readdirSync(scriptsDirectory, { withFileTypes: true })) {
  if (!entry.isFile() || !entry.name.endsWith('.sh') || entry.name.startsWith('stop-')) continue;
  const file = path.join(scriptsDirectory, entry.name);
  const source = fs.readFileSync(file, 'utf8');

  // A runtime fixture binds at least one Northstar listener and references the
  // server executable. Database-only migration tests deliberately fall outside
  // this boundary.
  const startsNorthstar = /rust-xmpp-server/.test(source)
    && /\b(?:XMPP_BIND|XMPPS_BIND|HTTP_BIND|WEBSOCKET_BIND)=/.test(source);
  if (!startsNorthstar) continue;

  if (!/\bMIGRATOR_DATABASE_URL=/.test(source)) {
    violations.push(`${entry.name}: missing an explicit MIGRATOR_DATABASE_URL`);
  }
  if (!/(?:^|\s)migrate(?:\s|$)/m.test(source)) {
    violations.push(`${entry.name}: starts a runtime without an explicit migrate command`);
  }

  const migration = source.search(/(?:^|\s)migrate(?:\s|$)/m);
  const firstListener = source.search(/\b(?:XMPP_BIND|XMPPS_BIND|HTTP_BIND|WEBSOCKET_BIND)=/);
  if (migration >= 0 && firstListener >= 0 && migration > firstListener) {
    violations.push(`${entry.name}: configures a runtime listener before applying migrations`);
  }

  // The listener-stress parent may hand a runtime fixture a disposable,
  // already-migrated database copy.  This is deliberately narrower than a
  // general migration bypass: both domain databases must be named, the
  // fixture must retain its ordinary explicit migrate path, and it must use
  // the cloned public schema rather than silently sharing the default test
  // database.  Keep this contract visible to static review.
  const usesStressPreprovisioning = /\bNORTHSTAR_LISTENER_STRESS_DATABASE_[AB]\b/.test(source);
  if (usesStressPreprovisioning) {
    for (const required of [
      'NORTHSTAR_LISTENER_STRESS_DATABASE_A',
      'NORTHSTAR_LISTENER_STRESS_DATABASE_B',
      'fixture_preprovisioned=true',
      'schema_a=public',
      'schema_b=public',
    ]) {
      if (!source.includes(required)) {
        violations.push(`${entry.name}: listener-stress preprovisioning lacks ${required}`);
      }
    }
  }
}

if (violations.length > 0) {
  throw new Error(
    `runtime fixtures must establish an isolated migrated database state before startup:\n${violations.join('\n')}`,
  );
}

console.log('Runtime migration-boundary check passed: every server fixture migrates before startup or uses a bounded listener-stress database copy');
