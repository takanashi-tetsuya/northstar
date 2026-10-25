import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const gate = 'scripts/check-outbound-xml-construction.mjs';
const gateSource = fs.readFileSync(path.join(root, gate), 'utf8');
const baseline = /const BASELINE = new Map\(\[([\s\S]*?)\]\);/.exec(gateSource);
assert.ok(baseline, 'gate baseline must be present');
const entries = [...baseline[1].matchAll(/\['((?:src|crates)\/[^']+\.rs)',\s*\d+\]/g)]
  .map((match) => match[1]);
assert.ok(entries.length > 0, 'gate baseline must contain source files');

const rawXml = 'const XML: &str = "<message/>";\n';

function fixture(run) {
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'northstar-outbound-xml-'));
  const write = (relativePath, source) => {
    const absolutePath = path.join(fixtureRoot, relativePath);
    fs.mkdirSync(path.dirname(absolutePath), { recursive: true });
    fs.writeFileSync(absolutePath, source);
  };
  const roleSplits = (children) => write('catalog/source-role-splits.json', JSON.stringify({
    schema: 'northstar-source-role-splits-v1',
    files: { 'src/xmpp/protocol.rs': children },
  }));
  try {
    for (const script of [gate, 'scripts/lib/source-module.mjs']) {
      write(script, fs.readFileSync(path.join(root, script), 'utf8'));
    }
    for (const entry of entries) write(entry, '');
    roleSplits([]);
    write('src/xmpp/protocol/mix/worker.rs', '');
    write('src/services/mix.rs', 'pub(crate) mod foreground;\npub(crate) mod outbox;\n');
    for (const child of ['foreground', 'outbox']) {
      write(`src/services/mix/${child}.rs`, `mod nested;\n${rawXml}`);
      write(`src/services/mix/${child}/nested.rs`, rawXml);
    }
    run({
      write,
      roleSplits,
      append: (relativePath, source) => fs.appendFileSync(path.join(fixtureRoot, relativePath), source),
      check: () => {
        const stdoutPath = path.join(fixtureRoot, 'stdout');
        const stderrPath = path.join(fixtureRoot, 'stderr');
        const stdout = fs.openSync(stdoutPath, 'w');
        const stderr = fs.openSync(stderrPath, 'w');
        try {
          const result = spawnSync(process.execPath, [gate], {
            cwd: fixtureRoot,
            stdio: ['ignore', stdout, stderr],
            env: { ...process.env, NORTHSTAR_XML_GATE_VERBOSE: '0' },
          });
          assert.ifError(result.error);
          return {
            status: result.status,
            stdout: fs.readFileSync(stdoutPath, 'utf8'),
            stderr: fs.readFileSync(stderrPath, 'utf8'),
          };
        } finally {
          fs.closeSync(stdout);
          fs.closeSync(stderr);
        }
      },
    });
  } finally {
    fs.rmSync(fixtureRoot, { recursive: true, force: true });
  }
}

function passes(result) {
  assert.equal(result.status, 0, result.stderr || result.error?.message);
  assert.match(result.stdout, /Outbound XML construction gate passed\./);
}

function rejects(result, relativePath, line = 1) {
  assert.equal(result.status, 1, result.stderr || result.error?.message);
  assert.ok(result.stderr.includes(`${relativePath}:${line}:`), result.stderr);
  assert.match(result.stderr, /raw outbound XML construction regressed/);
}

test('MIX keeps existing child modules and their descendants outside its zero budget', () => {
  fixture(({ check }) => {
    const result = check();
    passes(result);
    assert.match(result.stdout, /src\/services\/mix\.rs: current=0, baseline=0, files=1/);
  });
});

test('file-scoped entries check listed role children at their real file and line', () => {
  fixture(({ write, append, roleSplits, check }) => {
    append('src/xmpp/protocol.rs', 'mod zz_probe;\n');
    write('src/xmpp/protocol/zz_probe.rs', `\n\n${rawXml}`);
    roleSplits(['zz_probe']);
    rejects(check(), 'src/xmpp/protocol/zz_probe.rs', 3);
  });
});

test('file-scoped entries leave independently owned siblings outside their budget', () => {
  fixture(({ write, append, check }) => {
    append('src/xmpp/protocol.rs', 'mod zz_probe;\n');
    write('src/xmpp/protocol/zz_probe.rs', rawXml);
    passes(check());
  });
});

for (const entry of [
  'src/services/xml_util.rs',
  'src/xmpp/protocol/commands.rs',
  'src/xmpp/protocol/presence.rs',
  'src/xmpp/protocol/sasl2.rs',
  'src/xmpp/protocol/messaging.rs',
  'src/xmpp/protocol/pubsub.rs',
  'src/xmpp/protocol/pep.rs',
  'src/services/mix.rs',
  'src/s2s/components.rs',
  'src/s2s/inbound.rs',
  'src/s2s/outbound.rs',
]) {
  test(`${entry} rejects raw XML in a new production child`, () => {
    fixture(({ write, append, check }) => {
      const child = `${entry.slice(0, -3)}/zz_probe.rs`;
      append(entry, 'mod zz_probe;\n');
      write(child, rawXml);
      rejects(check(), child);
    });
  });
}

test('MIX excludes a cfg(test) bodyless child module', () => {
  fixture(({ write, append, check }) => {
    append('src/services/mix.rs', '#[cfg(test)]\nmod zz_probe;\n');
    write('src/services/mix/zz_probe.rs', rawXml);
    passes(check());
  });
});

test('the SASL2 parser literal exemption remains specific to its original file', () => {
  fixture(({ write, append, check }) => {
    const parserLiteral = '\n'.repeat(135) + 'fn parser_input() { let closing = "</stream:stream>"; }\n';
    write('src/xmpp/protocol/sasl2.rs', parserLiteral);
    passes(check());
    append('src/xmpp/protocol/sasl2.rs', 'mod zz_probe;\n');
    write('src/xmpp/protocol/sasl2/zz_probe.rs', parserLiteral);
    rejects(check(), 'src/xmpp/protocol/sasl2/zz_probe.rs', 136);
  });
});
