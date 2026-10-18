import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  moduleFiles,
  productionModuleFiles,
  readModuleParts,
  readModule,
  roleSplitFiles,
  readRoleSplitFile,
  validateRoleSplits,
  matchingRustBrace,
  findRustItem,
  rustItemBody,
  moduleItem,
  repositoryRoot,
} from './lib/source-module.mjs';

const libraryPath = path.join(repositoryRoot, 'scripts/lib/source-module.mjs');

function writeRoleCatalog(root, files) {
  fs.mkdirSync(path.join(root, 'catalog'), { recursive: true });
  fs.writeFileSync(path.join(root, 'catalog/source-role-splits.json'), JSON.stringify({
    schema: 'northstar-source-role-splits-v1',
    files
  }) + '\n');
}

test('module without child directory returns only itself', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'source-module-'));
  try {
    fs.mkdirSync(path.join(root, 'src'));
    fs.writeFileSync(path.join(root, 'src/alone.rs'), 'fn a() {}');
    assert.deepEqual(moduleFiles('src/alone.rs', { root }), ['src/alone.rs']);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('module with nested children: order is module file first, then sorted children; non-.rs files ignored', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'source-module-'));
  try {
    fs.mkdirSync(path.join(root, 'src/mix/b'), { recursive: true });
    fs.writeFileSync(path.join(root, 'src/mix.rs'), '');
    fs.writeFileSync(path.join(root, 'src/mix/worker.rs'), '');
    fs.writeFileSync(path.join(root, 'src/mix/b/child.rs'), '');
    fs.writeFileSync(path.join(root, 'src/mix/README.md'), '');
    assert.deepEqual(moduleFiles('src/mix.rs', { root }), [
      'src/mix.rs',
      'src/mix/b/child.rs',
      'src/mix/worker.rs'
    ]);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('mod.rs style module excludes mod.rs from its children', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'source-module-'));
  try {
    fs.mkdirSync(path.join(root, 'src/foo'), { recursive: true });
    fs.writeFileSync(path.join(root, 'src/foo/mod.rs'), '');
    fs.writeFileSync(path.join(root, 'src/foo/a.rs'), '');
    assert.deepEqual(moduleFiles('src/foo/mod.rs', { root }), [
      'src/foo/mod.rs',
      'src/foo/a.rs'
    ]);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('missing module, absolute path, .. path, and non-.rs path each throw', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'source-module-'));
  try {
    assert.throws(() => moduleFiles('missing.rs', { root }), /does not exist/);
    assert.throws(() => moduleFiles('/absolute/path.rs', { root }), /absolute path rejected/);
    assert.throws(() => moduleFiles('src/../foo.rs', { root }), /\.\. segments rejected/);
    assert.throws(() => moduleFiles('src/foo.txt', { root }), /must end with \.rs/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('readModule joins parts with \\n; readModuleParts preserves order', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'source-module-'));
  try {
    fs.mkdirSync(path.join(root, 'src/mix'), { recursive: true });
    fs.writeFileSync(path.join(root, 'src/mix.rs'), 'a');
    fs.writeFileSync(path.join(root, 'src/mix/1.rs'), 'b');
    fs.writeFileSync(path.join(root, 'src/mix/2.rs'), 'c');
    
    const parts = readModuleParts('src/mix.rs', { root });
    assert.deepEqual(parts, [
      { path: 'src/mix.rs', source: 'a' },
      { path: 'src/mix/1.rs', source: 'b' },
      { path: 'src/mix/2.rs', source: 'c' }
    ]);
    
    const joined = readModule('src/mix.rs', { root });
    assert.equal(joined, 'a\nb\nc');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('role-split reads preserve declaration order and exclude independent siblings for both parent styles', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'source-module-'));
  try {
    fs.mkdirSync(path.join(root, 'src/a/b'), { recursive: true });
    const parent = 'pub(crate) mod z_first;\nmod a_second;';
    fs.writeFileSync(path.join(root, 'src/a/b.rs'), parent);
    fs.writeFileSync(path.join(root, 'src/a/b/z_first.rs'), 'first');
    fs.writeFileSync(path.join(root, 'src/a/b/a_second.rs'), 'second');
    fs.writeFileSync(path.join(root, 'src/a/b/independent.rs'), 'excluded');
    fs.writeFileSync(path.join(root, 'src/a/mod.rs'), 'pub mod leaf;');
    fs.writeFileSync(path.join(root, 'src/a/leaf.rs'), 'leaf');
    writeRoleCatalog(root, {
      'src/a/b.rs': ['z_first', 'a_second'],
      'src/a/mod.rs': ['leaf']
    });
    assert.deepEqual(roleSplitFiles('src/a/b.rs', { root }), [
      'src/a/b.rs', 'src/a/b/z_first.rs', 'src/a/b/a_second.rs'
    ]);
    assert.equal(readRoleSplitFile('src/a/b.rs', { root }), parent + '\nfirst\nsecond');
    assert.deepEqual(roleSplitFiles('src/a/mod.rs', { root }), ['src/a/mod.rs', 'src/a/leaf.rs']);
    assert.equal(readRoleSplitFile('src/a/mod.rs', { root }), 'pub mod leaf;\nleaf');
    assert.deepEqual(validateRoleSplits({ root }), []);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('role-split reads reject unlisted files, missing children and unsafe paths with catalog context', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'source-module-'));
  try {
    fs.mkdirSync(path.join(root, 'src/a'), { recursive: true });
    fs.writeFileSync(path.join(root, 'src/a/b.rs'), 'mod missing;');
    fs.writeFileSync(path.join(root, 'src/unlisted.rs'), '');
    writeRoleCatalog(root, { 'src/a/b.rs': ['missing'] });
    for (const file of ['src/unlisted.rs', 'src/a/b.rs', '/absolute.rs', 'src/../a.rs', 'src/a.txt']) {
      assert.throws(() => roleSplitFiles(file, { root }), error => {
        assert.ok(error.message.includes('catalog/source-role-splits.json:'));
        assert.ok(error.message.includes(file));
        return true;
      });
    }
    assert.throws(() => readRoleSplitFile('src/a/b.rs', { root }), /missing/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('role-split catalog rules 1-3 reject the whole catalog before any read', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'source-module-'));
  try {
    fs.mkdirSync(path.join(root, 'src/a'), { recursive: true });
    fs.writeFileSync(path.join(root, 'src/a/b.rs'), '');
    fs.writeFileSync(path.join(root, 'src/a/c.rs'), '');
    writeRoleCatalog(root, { 'src/a/b.rs': [] });
    const catalogPath = path.join(root, 'catalog/source-role-splits.json');
    const schema = 'northstar-source-role-splits-v1';
    const invalidCatalogs = [
      '{',
      null,
      [],
      { schema, files: {}, extra: true },
      { files: {} },
      { schema },
      { schema: 'wrong', files: {} },
      { schema, files: [] },
      { schema, files: null },
      { schema, files: { 'src/a/c.rs': [], 'src/a/b.rs': [] } },
      ...['/src/a/b.rs', 'src/../a.rs', 'outside.rs', 'src/a/b.txt', 'src/missing.rs', 'src/a.rs']
        .map(file => ({ schema, files: { 'src/a/b.rs': [], [file]: [] } })),
      ...[null, 'leaf', ['leaf', 'leaf'], [1], ['Bad'], ['a/b'], ['mod'], ['tests']]
        .map(children => ({ schema, files: { 'src/a/b.rs': [], 'src/a/c.rs': children } }))
    ];
    fs.mkdirSync(path.join(root, 'src/a.rs'));
    for (const catalog of invalidCatalogs) {
      fs.writeFileSync(catalogPath, typeof catalog === 'string' ? catalog : JSON.stringify(catalog));
      const violations = validateRoleSplits({ root });
      assert.ok(violations.length > 0, JSON.stringify(catalog));
      assert.ok(violations.every(violation => violation.startsWith('catalog/source-role-splits.json:')));
      assert.throws(() => roleSplitFiles('src/a/b.rs', { root }), /catalog\/source-role-splits\.json:.*src\/a\/b.rs/);
    }
    fs.rmSync(catalogPath);
    assert.ok(validateRoleSplits({ root }).length > 0);
    assert.throws(() => roleSplitFiles('src/a/b.rs', { root }), /catalog\/source-role-splits\.json:.*src\/a\/b.rs/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('role-split rule 4 requires existing leaf files and production declarations in parent order', () => {
  const cases = [
    { source: 'mod leaf;', missing: true },
    { source: 'mod leaf;', directory: true },
    { source: '// mod leaf;' },
    { source: 'mod leaf {}' },
    { source: 'const S: &str = "mod leaf;";' },
    { source: '#[cfg(test)]\n/// helper\n#[allow(dead_code)]\npub(crate) mod leaf;' },
    { source: 'mod other;\nmod leaf;', children: ['leaf', 'other'] }
  ];
  for (const fixture of cases) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'source-module-'));
    try {
      fs.mkdirSync(path.join(root, 'src/a/b'), { recursive: true });
      fs.writeFileSync(path.join(root, 'src/a/b.rs'), fixture.source);
      if (!fixture.missing) fs.writeFileSync(path.join(root, 'src/a/b/leaf.rs'), '');
      fs.writeFileSync(path.join(root, 'src/a/b/other.rs'), '');
      if (fixture.directory) fs.mkdirSync(path.join(root, 'src/a/b/leaf'));
      writeRoleCatalog(root, { 'src/a/b.rs': fixture.children ?? ['leaf'] });
      const violations = validateRoleSplits({ root });
      assert.ok(violations.length > 0, JSON.stringify(fixture));
      assert.ok(violations.every(violation => violation.startsWith('catalog/source-role-splits.json:')));
      if (!fixture.missing && !fixture.directory) {
        assert.doesNotThrow(() => roleSplitFiles('src/a/b.rs', { root }));
      }
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  }
});

test('role-split CLI reads a fixture catalog and rejects conflicting flags', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'source-module-'));
  try {
    fs.mkdirSync(path.join(root, 'scripts/lib'), { recursive: true });
    fs.copyFileSync(libraryPath, path.join(root, 'scripts/lib/source-module.mjs'));
    fs.mkdirSync(path.join(root, 'src/a/b'), { recursive: true });
    fs.writeFileSync(path.join(root, 'src/a/b.rs'), 'mod leaf;');
    fs.writeFileSync(path.join(root, 'src/a/b/leaf.rs'), 'child');
    fs.writeFileSync(path.join(root, 'src/a/b/independent.rs'), 'excluded');
    writeRoleCatalog(root, { 'src/a/b.rs': ['leaf'] });
    const script = path.join(root, 'scripts/lib/source-module.mjs');
    let res = spawnSync(process.execPath, [script, 'files', '--role-split', 'src/a/b.rs'], { encoding: 'utf8' });
    assert.equal(res.status, 0, res.stderr);
    assert.equal(res.stdout, 'src/a/b.rs\nsrc/a/b/leaf.rs\n');
    res = spawnSync(process.execPath, [script, 'cat', '--role-split', 'src/a/b.rs'], { encoding: 'utf8' });
    assert.equal(res.status, 0, res.stderr);
    assert.equal(res.stdout, 'mod leaf;\nchild');
    for (const subcommand of ['files', 'cat']) {
      for (const flags of [['--production', '--role-split'], ['--role-split', '--production']]) {
        res = spawnSync(process.execPath, [script, subcommand, ...flags, 'src/a/b.rs'], { encoding: 'utf8' });
        assert.equal(res.status, 1);
        assert.match(res.stderr, /--production.*--role-split|--role-split.*--production/);
      }
    }
    res = spawnSync(process.execPath, [script, 'files', '--role-split', 'src/unlisted.rs'], { encoding: 'utf8' });
    assert.equal(res.status, 1);
    assert.match(res.stderr, /catalog\/source-role-splits\.json:.*src\/unlisted.rs/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('findRustItem ignores braces inside tricky syntax', () => {
  const src = String.raw`fn f<'a>(x: &'a str) -> &'a str {
  // }
  /* } /* } */ } */
  let s = "escaped \" }";
  let raw = r#"}"#;
  let braw = br#"}"#;
  let b = b"}";
  let c = '}';
  let cb = b'}';
  let c_escaped = '\'';
  let uni = '\u{7d}';
  let lifetime: &'a str = x;
  struct Inner {
    x: i32
  }
  return "done";
}`;
  const result = findRustItem(src, "fn f<'a>(x: &'a str) -> &'a str");
  const lastBraceIndex = src.lastIndexOf('}');
  assert.equal(result.close, lastBraceIndex);
  assert.ok(result.text.endsWith('}'));
  
  // separate negative control test
  const naiveCount = (source, openIdx) => {
    let depth = 1;
    let idx = openIdx + 1;
    while(idx < source.length) {
      if (source[idx] === '{') depth++;
      else if (source[idx] === '}') {
        depth--;
        if (depth === 0) return idx;
      }
      idx++;
    }
    return -1;
  };
  const start = src.indexOf('fn f');
  const open = src.indexOf('{', start);
  const naiveClose = naiveCount(src, open);
  assert.notEqual(naiveClose, lastBraceIndex);
});

test('missing declaration, ambiguous declaration, missing body, unterminated body each throw', () => {
  assert.throws(() => findRustItem('fn a() {} fn a() {}', 'fn a()'), /ambiguous/);
  assert.throws(() => findRustItem('fn b() {}', 'fn a()'), /missing/);
  assert.throws(() => findRustItem('fn a() ;', 'fn a()'), /missing body/);
  assert.throws(() => findRustItem('fn a() {', 'fn a()'), /unterminated/);
});

test('rustItemBody returns exactly the text between the braces', () => {
  assert.equal(rustItemBody('fn a() { body }', 'fn a()'), ' body ');
});

test('Real repository checks', () => {
  const files = moduleFiles('src/xmpp/protocol/mix.rs');
  assert.equal(files[0], 'src/xmpp/protocol/mix.rs');
  assert.ok(files.includes('src/xmpp/protocol/mix/worker.rs'));
  
  const body = rustItemBody(readModule('src/runtime/operation_runtime.rs'), 'async fn run_one(');
  assert.ok(body.includes('lease_heartbeat('));
  
  const prodFiles = productionModuleFiles('src/xmpp/protocol/mix.rs');
  assert.ok(prodFiles.includes('src/xmpp/protocol/mix/worker.rs'));
  // exclude every path under src/xmpp/protocol/mix/stage4_saved
  for (const f of prodFiles) {
    assert.ok(!f.includes('stage4_saved'));
  }
});

test('CLI tests', () => {
  // item output
  let res = spawnSync(process.execPath, [libraryPath, 'item', 'src/runtime/operation_runtime.rs', 'async fn run_one('], { encoding: 'utf8' });
  assert.equal(res.status, 0);
  assert.ok(res.stdout.includes('lease_heartbeat('));
  assert.ok(res.stdout.endsWith('}\n'));
  
  // files output
  res = spawnSync(process.execPath, [libraryPath, 'files', 'src/xmpp/protocol/mix.rs'], { encoding: 'utf8' });
  assert.equal(res.status, 0);
  assert.ok(res.stdout.includes('src/xmpp/protocol/mix.rs\n'));
  assert.ok(res.stdout.includes('src/xmpp/protocol/mix/worker.rs\n'));

  // production files output
  res = spawnSync(process.execPath, [libraryPath, 'files', '--production', 'src/xmpp/protocol/mix.rs'], { encoding: 'utf8' });
  assert.equal(res.status, 0);
  assert.ok(res.stdout.includes('src/xmpp/protocol/mix/worker.rs'));
  assert.ok(!res.stdout.includes('stage4_saved'));

  // usage error
  res = spawnSync(process.execPath, [libraryPath, 'unknown'], { encoding: 'utf8' });
  assert.equal(res.status, 2);
  assert.ok(res.stderr.includes('Usage'));
  assert.ok(res.stderr.includes('Unknown subcommand: unknown'));
  
  // missing declaration error
  res = spawnSync(process.execPath, [libraryPath, 'item', 'src/runtime/operation_runtime.rs', 'fn missing_fn('], { encoding: 'utf8' });
  assert.equal(res.status, 1);
  assert.ok(res.stderr.includes('missing'));
});

test('Production modules filtering', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'source-module-'));
  try {
    fs.mkdirSync(path.join(root, 'src/mix/saved'), { recursive: true });
    
    fs.writeFileSync(path.join(root, 'src/mix.rs'), [
      '#[cfg(test)] mod tests;',
      '#[cfg(test)]',
      '/// doc',
      'pub(crate) mod saved;',
      'mod worker;',
      '// #[cfg(test)]',
      'mod worker2;',
      'const S: &str = "#[cfg(test)] mod worker3;";',
      'mod worker3;',
      '#[cfg(test)]',
      'mod inline_tests { }'
    ].join('\n'));
    fs.writeFileSync(path.join(root, 'src/mix/tests.rs'), '');
    fs.writeFileSync(path.join(root, 'src/mix/saved.rs'), '');
    fs.writeFileSync(path.join(root, 'src/mix/saved/inner.rs'), '');
    fs.writeFileSync(path.join(root, 'src/mix/worker.rs'), '');
    fs.writeFileSync(path.join(root, 'src/mix/worker2.rs'), '');
    fs.writeFileSync(path.join(root, 'src/mix/worker3.rs'), '');
    fs.writeFileSync(path.join(root, 'src/mix/inline_tests.rs'), '');
    
    const allFiles = moduleFiles('src/mix.rs', { root });
    assert.deepEqual(allFiles, [
      'src/mix.rs',
      'src/mix/inline_tests.rs',
      'src/mix/saved.rs',
      'src/mix/saved/inner.rs',
      'src/mix/tests.rs',
      'src/mix/worker.rs',
      'src/mix/worker2.rs',
      'src/mix/worker3.rs'
    ]);
    
    const prodFiles = productionModuleFiles('src/mix.rs', { root });
    assert.deepEqual(prodFiles, [
      'src/mix.rs',
      'src/mix/inline_tests.rs',
      'src/mix/worker.rs',
      'src/mix/worker2.rs',
      'src/mix/worker3.rs'
    ]);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
