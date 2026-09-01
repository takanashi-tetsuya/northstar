import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const self = path.resolve(fileURLToPath(import.meta.url));
const extensions = new Set(['.sh', '.ps1', '.py', '.mjs', '.cjs', '.js']);
const scanRoots = [path.join(root, 'scripts'), path.join(root, 'deploy')];

function filesBelow(directory) {
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const target = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...filesBelow(target));
    else if (extensions.has(path.extname(entry.name))) files.push(target);
  }
  return files;
}

const forbidden = [
  ['pkill', /(^|[^A-Za-z0-9_])pkill(?:\s|$)/m],
  ['killall', /(^|[^A-Za-z0-9_])killall(?:\s|$)/m],
  ['Windows taskkill', /(^|[^A-Za-z0-9_])taskkill(?:\.exe)?(?:\s|$)/im],
  ['PowerShell name-based Stop-Process', /Stop-Process\b[^\r\n|;]*-(?:Name|InputObject)\b/im],
  ['Get-Process piped to Stop-Process', /Get-Process\b[^\r\n]*\|[^\r\n]*Stop-Process\b/im],
  ['shell kill fed by command substitution', /(^|[;&|]\s*)kill\b[^\r\n]*\$\s*\([^\r\n]*(?:pgrep|ps\b)/m],
  ['shell kill fed by xargs', /(?:pgrep|ps\b)[^\r\n|]*\|[^\r\n]*xargs\b[^\r\n]*\bkill\b/m],
];

const violations = [];
const candidates = fs
  .readdirSync(root, { withFileTypes: true })
  .filter((entry) => entry.isFile() && extensions.has(path.extname(entry.name)))
  .map((entry) => path.join(root, entry.name));
for (const scanRoot of scanRoots) {
  if (fs.existsSync(scanRoot)) candidates.push(...filesBelow(scanRoot));
}
for (const file of candidates) {
    if (path.resolve(file) === self) continue;
    const source = fs.readFileSync(file, 'utf8');
    for (const [description, pattern] of forbidden) {
      const match = pattern.exec(source);
      if (!match) continue;
      const line = source.slice(0, match.index).split(/\r?\n/).length;
      violations.push(`${path.relative(root, file)}:${line}: ${description}`);
    }
}

if (violations.length > 0) {
  throw new Error(
    `test/operations scripts may terminate only explicitly recorded child PIDs:\n${violations.join('\n')}`,
  );
}

console.log('Process-isolation check passed: no broad name/pattern-based termination is present');
