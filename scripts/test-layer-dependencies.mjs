import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { lexRust } from './check-move-only.mjs';
import {
  moduleTree,
  stripTestCode,
  crateReferences,
  layerOf,
  validateCatalog,
  findViolations,
  evaluateLayers
} from './check-layer-dependencies.mjs';

function references(text, modulePath = []) {
  return crateReferences(stripTestCode(lexRust(text)), modulePath);
}

function layerCatalog() {
  return {
    schema: 'northstar-source-layers-v1',
    layers: {
      composition: { rank: 4, modules: ['main'], may_use: ['composition', 'adapter', 'application', 'platform', 'facade'] },
      adapter: { rank: 3, modules: ['db', 'xmpp'], may_use: ['adapter', 'application', 'platform', 'facade'] },
      application: { rank: 2, modules: ['services'], may_use: ['application', 'platform', 'facade'] },
      platform: { rank: 1, modules: ['platform'], may_use: ['platform', 'facade'] },
      facade: { rank: 0, modules: ['auth'], may_use: ['facade'] }
    },
    aliases: { outbound: 'xmpp' },
    baseline: {}
  };
}

function runCli(root, args) {
  const scriptPath = fileURLToPath(new URL('./check-layer-dependencies.mjs', import.meta.url));
  const stdoutPath = path.join(root, 'stdout');
  const stderrPath = path.join(root, 'stderr');
  // Capture in files because subprocess pipes are unavailable in the sandbox.
  const stdout = fs.openSync(stdoutPath, 'w');
  const stderr = fs.openSync(stderrPath, 'w');
  let result;
  try {
    result = spawnSync(process.execPath, [scriptPath, '--root', root, ...args], { stdio: ['ignore', stdout, stderr] });
    assert.ifError(result.error);
  } finally {
    fs.closeSync(stdout);
    fs.closeSync(stderr);
  }
  return {
    status: result.status,
    stdout: fs.readFileSync(stdoutPath, 'utf8'),
    stderr: fs.readFileSync(stderrPath, 'utf8')
  };
}

test('crateReferences - direct paths are sorted and de-duplicated', () => {
  assert.deepEqual(references('use crate::state::X; use crate::db::Y; crate::state::f();'), ['db', 'state']);
});

test('crateReferences - nested use groups name their first segments', () => {
  assert.deepEqual(references('use crate::{a, b::c, d::{e, f}, self};'), ['a', 'b', 'd']);
});

test('crateReferences - macro paths, comments and literals are ignored', () => {
  assert.deepEqual(references(`
    $crate::z::f();
    // crate::comment::X
    /* crate::block_comment::Y */
    let s = "crate::string::Z";
    let raw = r#"crate::raw::Z"#;
    use crate::db::Q;
  `), ['db']);
});

test('crateReferences - super chains must reach the crate root', () => {
  assert.deepEqual(references('super::super::state::X; super::y; self::xmpp::Z;', ['db', 'x']), ['state']);
});

test('crateReferences - inline modules increase super depth', () => {
  assert.deepEqual(references(`
    mod m {
      super::super::too_short::X;
      super::super::super::x::Y;
      mod nested { super::super::super::super::z::Z; }
    }
    super::super::state::S;
  `, ['db', 'x']), ['state', 'x', 'z']);
});

test('crateReferences - visibility paths name their first segment', () => {
  assert.deepEqual(references('pub(in crate::xmpp::protocol) fn f() {}'), ['xmpp']);
});

test('stripTestCode - removes test modules and use items', () => {
  assert.deepEqual(references(`
    #[cfg(test)] mod tests { use crate::state::X; }
    #[cfg(test)] use crate::state::Y;
    use crate::db::Q;
  `), ['db']);
});

test('stripTestCode - removes attributed functions and impls', () => {
  assert.deepEqual(references(`
    #[cfg(test)] #[allow(dead_code)] fn f() -> [u8; 2] { crate::state::z() }
    #[allow(x)] #[cfg(test)] impl A { fn f() { crate::state::x(); } }
    fn kept() { crate::db::q(); }
  `), ['db']);
});

test('stripTestCode - removes fields without removing kept fields', () => {
  assert.deepEqual(references(`
    struct A {
      #[cfg(test)] probe: crate::state::P,
      kept: crate::db::Q,
    }
  `), ['db']);
});

test('stripTestCode - generic field commas do not end the field', () => {
  assert.deepEqual(references(`
    struct A {
      #[cfg(test)] cache: Arc<Map<String, crate::state::V>>,
      kept: crate::db::Q,
    }
  `), ['db']);
});

test('stripTestCode - return arrows and generic return types do not end a function', () => {
  assert.deepEqual(references(`
    #[cfg(test)] fn g() -> Vec<crate::state::W> { crate::state::w() }
    fn h() { crate::db::r() }
  `), ['db']);
});

test('stripTestCode - strips all(test, ..) cfg and keeps not(test) and any(test, ..)', () => {
  assert.deepEqual(references(`
    #[cfg(all(test, feature = "x"))] use crate::test_only::X;
    #[cfg(not(test))] use crate::state::K;
    #[cfg(any(test, feature = "y"))] use crate::xmpp::Y;
    #[cfg(feature = "other")] use crate::db::Q;
  `), ['db', 'state', 'xmpp']);
});

test('stripTestCode - an inner test cfg makes the whole file test code', () => {
  const tokens = stripTestCode(lexRust('// test helper\n#![allow(dead_code)]\n#![cfg(test)]\nuse crate::state::X;'));
  assert.deepEqual(tokens, []);
});

test('stripTestCode - removes statements, match arms and expressions', () => {
  assert.deepEqual(references(`
    fn f() {
      #[cfg(test)] let probe = crate::state::probe([0; 4]);
      match value {
        #[cfg(test)] A => crate::state::a(),
        B => crate::db::b(),
      }
      call(#[cfg(test)] crate::state::probe(), crate::db::q());
    }
  `), ['db']);
});

test('stripTestCode - expression comparisons stop counting angle brackets after equals', () => {
  assert.deepEqual(references(`
    fn f() {
      #[cfg(test)] let probe = if 1 < 2 { crate::state::probe() };
      crate::db::q();
    }
  `), ['db']);
});

test('stripTestCode - returns significant tokens and keeps production attributes', () => {
  const tokens = stripTestCode(lexRust(' // comment\n#[cfg(not(test))] use crate::db::Q;'));
  assert.equal(tokens.some(token => token.kind === 'ws' || token.kind === 'comment'), false);
  assert.equal(tokens[0].text, '#');
  assert.deepEqual(crateReferences(tokens, []), ['db']);
});

test('moduleTree - follows production declarations with Rust file resolution', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'layer-dependencies-'));
  try {
    fs.mkdirSync(path.join(tmp, 'src', 'a'), { recursive: true });
    fs.mkdirSync(path.join(tmp, 'src', 'b'));
    fs.writeFileSync(path.join(tmp, 'src', 'main.rs'), 'mod a; pub(crate) mod b; #[cfg(test)] mod t;\n');
    fs.writeFileSync(path.join(tmp, 'src', 'a.rs'), 'pub mod c;\n');
    fs.writeFileSync(path.join(tmp, 'src', 'a', 'c.rs'), '\n');
    fs.writeFileSync(path.join(tmp, 'src', 'b', 'mod.rs'), 'mod d; #[cfg(test)] #[path = "b_tests.rs"] mod tests;\n');
    fs.writeFileSync(path.join(tmp, 'src', 'b', 'd.rs'), '\n');
    fs.writeFileSync(path.join(tmp, 'src', 't.rs'), 'mod missing_test_child;\n');
    fs.writeFileSync(path.join(tmp, 'src', 'b', 'b_tests.rs'), '\n');

    const tree = moduleTree(tmp);
    assert.deepEqual([...tree.keys()].sort(), ['src/a.rs', 'src/a/c.rs', 'src/b/d.rs', 'src/b/mod.rs', 'src/main.rs']);
    assert.deepEqual(tree.get('src/main.rs'), { modulePath: [], top: 'main' });
    assert.deepEqual(tree.get('src/a.rs'), { modulePath: ['a'], top: 'a' });
    assert.deepEqual(tree.get('src/a/c.rs'), { modulePath: ['a', 'c'], top: 'a' });
    assert.deepEqual(tree.get('src/b/mod.rs'), { modulePath: ['b'], top: 'b' });
    assert.deepEqual(tree.get('src/b/d.rs'), { modulePath: ['b', 'd'], top: 'b' });
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('moduleTree - follows path attributes and inline module directories', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'layer-dependencies-'));
  try {
    fs.mkdirSync(path.join(tmp, 'src', 'inline'), { recursive: true });
    fs.mkdirSync(path.join(tmp, 'src', 'files', 'nested'), { recursive: true });
    fs.writeFileSync(path.join(tmp, 'src', 'main.rs'), `
      #[path = "files/renamed.rs"] pub mod a;
      mod inline { mod child; }
      #[cfg(test)] fn test_parent() { mod missing; }
    `);
    fs.writeFileSync(path.join(tmp, 'src', 'files', 'renamed.rs'), 'mod leaf; mod nested { mod child; }\n');
    fs.writeFileSync(path.join(tmp, 'src', 'files', 'leaf.rs'), '\n');
    fs.writeFileSync(path.join(tmp, 'src', 'files', 'nested', 'child.rs'), '\n');
    fs.writeFileSync(path.join(tmp, 'src', 'inline', 'child.rs'), '\n');

    const tree = moduleTree(tmp);
    assert.deepEqual([...tree.keys()].sort(), [
      'src/files/leaf.rs', 'src/files/nested/child.rs', 'src/files/renamed.rs', 'src/inline/child.rs', 'src/main.rs'
    ]);
    assert.deepEqual(tree.get('src/files/renamed.rs'), { modulePath: ['a'], top: 'a' });
    assert.deepEqual(tree.get('src/files/leaf.rs'), { modulePath: ['a', 'leaf'], top: 'a' });
    assert.deepEqual(tree.get('src/files/nested/child.rs'), { modulePath: ['a', 'nested', 'child'], top: 'a' });
    assert.deepEqual(tree.get('src/inline/child.rs'), { modulePath: ['inline', 'child'], top: 'inline' });
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('moduleTree - inline modules in non-mod-rs files use the stem directory', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'layer-dependencies-'));
  try {
    fs.mkdirSync(path.join(tmp, 'src', 'a', 'inline'), { recursive: true });
    fs.writeFileSync(path.join(tmp, 'src', 'main.rs'), 'mod a;\n');
    fs.writeFileSync(path.join(tmp, 'src', 'a.rs'), 'mod inline { mod child; }\n');
    fs.writeFileSync(path.join(tmp, 'src', 'a', 'inline', 'child.rs'), '\n');
    const tree = moduleTree(tmp);
    assert.deepEqual(tree.get('src/a/inline/child.rs'), { modulePath: ['a', 'inline', 'child'], top: 'a' });
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('moduleTree - nested main.rs files use the stem directory', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'layer-dependencies-'));
  try {
    fs.mkdirSync(path.join(tmp, 'src', 'a', 'main'), { recursive: true });
    fs.writeFileSync(path.join(tmp, 'src', 'main.rs'), 'mod a;\n');
    fs.writeFileSync(path.join(tmp, 'src', 'a', 'mod.rs'), 'mod main;\n');
    fs.writeFileSync(path.join(tmp, 'src', 'a', 'main.rs'), 'mod child;\n');
    fs.writeFileSync(path.join(tmp, 'src', 'a', 'main', 'child.rs'), '\n');
    const tree = moduleTree(tmp);
    assert.deepEqual(tree.get('src/a/main/child.rs'), { modulePath: ['a', 'main', 'child'], top: 'a' });
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('moduleTree - missing declared files name the declaring file and module', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'layer-dependencies-'));
  try {
    fs.mkdirSync(path.join(tmp, 'src'));
    fs.writeFileSync(path.join(tmp, 'src', 'main.rs'), 'mod missing;\n');
    assert.throws(() => moduleTree(tmp), /src\/main\.rs.*missing/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('layerOf - resolves modules, aliases and unknown names', () => {
  const catalog = layerCatalog();
  assert.equal(layerOf('services', catalog), 'application');
  assert.equal(layerOf('outbound', catalog), 'adapter');
  assert.equal(layerOf('missing', catalog), undefined);
});

test('validateCatalog - accepts the downward catalog and the repository catalog', () => {
  assert.deepEqual(validateCatalog(layerCatalog()), []);
  const repository = JSON.parse(fs.readFileSync(fileURLToPath(new URL('../catalog/source-layers.json', import.meta.url)), 'utf8'));
  assert.deepEqual(validateCatalog(repository), []);
});

test('validateCatalog - rejects upward use, duplicate modules and dangling aliases', () => {
  const catalog = layerCatalog();
  catalog.layers.application.may_use.push('adapter', 'missing');
  catalog.layers.platform.modules.push('db');
  catalog.aliases.xmpp = 'db';
  catalog.aliases.lost = 'nowhere';
  catalog.layers.facade.rank = '0';
  assert.deepEqual(validateCatalog(catalog), [
    'layer application: may_use adapter has a higher rank',
    'layer application: may_use names unknown layer missing',
    'module db is in layers adapter and platform',
    'layer facade: rank must be an integer',
    'alias xmpp is also a module of layer adapter',
    'alias lost names nowhere, which is in no layer'
  ]);
});

test('findViolations - adapter references to application ports are allowed', () => {
  const tree = new Map([['src/db.rs', { modulePath: ['db'], top: 'db' }]]);
  const violations = findViolations(tree, () => 'use crate::services::Port; use crate::db::Q;', layerCatalog());
  assert.deepEqual(violations, []);
});

test('findViolations and evaluateLayers - new forbidden references must be baselined', () => {
  const tree = new Map([['src/services.rs', { modulePath: ['services'], top: 'services' }]]);
  const violations = findViolations(tree, () => 'use crate::db::Q; crate::db::f();', layerCatalog());
  assert.deepEqual(violations, [{ file: 'src/services.rs', target: 'db', from: 'application', to: 'adapter' }]);
  assert.deepEqual(evaluateLayers({ violations, baseline: {} }), {
    errors: ['src/services.rs: layer application must not use crate::db (layer adapter); move the code to a lower layer or use an application port'],
    baselined: 0
  });
  assert.deepEqual(evaluateLayers({ violations, baseline: { 'src/services.rs': ['db'] } }), { errors: [], baselined: 1 });
});

test('evaluateLayers - stale baseline entries must be removed', () => {
  assert.deepEqual(evaluateLayers({ violations: [], baseline: { 'src/services.rs': ['db'] } }), {
    errors: ['src/services.rs: baseline entry db is no longer needed; remove it from catalog/source-layers.json (run with --write)'],
    baselined: 0
  });
});

test('findViolations - aliases use the target module and its layer', () => {
  const tree = new Map([['src/platform.rs', { modulePath: ['platform'], top: 'platform' }]]);
  const violations = findViolations(tree, () => 'use crate::outbound::Item; use crate::xmpp::Q;', layerCatalog());
  assert.deepEqual(violations, [{ file: 'src/platform.rs', target: 'xmpp', from: 'platform', to: 'adapter' }]);
  const result = evaluateLayers({ violations, baseline: {} });
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /layer platform must not use crate::xmpp \(layer adapter\)/);
});

test('findViolations and evaluateLayers - unknown references cannot be baselined', () => {
  const tree = new Map([['src/platform.rs', { modulePath: ['platform'], top: 'platform' }]]);
  const violations = findViolations(tree, () => 'use crate::missing::Q;', layerCatalog());
  assert.equal(violations.length, 1);
  assert.equal(violations[0].unknown, true);
  const result = evaluateLayers({ violations, baseline: { 'src/platform.rs': ['missing'] } });
  assert.equal(result.baselined, 0);
  assert.ok(result.errors.includes('src/platform.rs: crate::missing is not in any layer of catalog/source-layers.json'));
});

test('findViolations - unknown source modules name their files', () => {
  const tree = new Map([['src/missing.rs', { modulePath: ['missing'], top: 'missing' }]]);
  assert.throws(() => findViolations(tree, () => '', layerCatalog()), /src\/missing\.rs/);
});

test('findViolations - results are sorted and test code is ignored', () => {
  const tree = new Map([
    ['src/services/z.rs', { modulePath: ['services', 'z'], top: 'services' }],
    ['src/services/a.rs', { modulePath: ['services', 'a'], top: 'services' }]
  ]);
  const source = {
    'src/services/z.rs': 'use crate::xmpp::Q; use crate::db::Q;',
    'src/services/a.rs': '#[cfg(test)] use crate::xmpp::Q; use crate::db::Q;'
  };
  const violations = findViolations(tree, file => source[file], layerCatalog());
  assert.deepEqual(violations.map(({ file, target }) => ({ file, target })), [
    { file: 'src/services/a.rs', target: 'db' },
    { file: 'src/services/z.rs', target: 'db' },
    { file: 'src/services/z.rs', target: 'xmpp' }
  ]);
});

test('CLI - records forbidden references and rejects stale entries', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'layer-dependencies-'));
  try {
    fs.mkdirSync(path.join(tmp, 'src'));
    fs.mkdirSync(path.join(tmp, 'catalog'));
    fs.writeFileSync(path.join(tmp, 'src', 'main.rs'), 'mod services; mod db;\n');
    fs.writeFileSync(path.join(tmp, 'src', 'services.rs'), 'use crate::db::Q;\n');
    fs.writeFileSync(path.join(tmp, 'src', 'db.rs'), '\n');
    const catalogPath = path.join(tmp, 'catalog', 'source-layers.json');
    fs.writeFileSync(catalogPath, JSON.stringify(layerCatalog(), null, 2) + '\n');
    let res = runCli(tmp, []);
    assert.equal(res.status, 1, res.stderr);
    assert.match(res.stderr, /src\/services\.rs: layer application must not use crate::db \(layer adapter\)/);

    res = runCli(tmp, ['--write']);
    assert.equal(res.status, 0, res.stderr);
    assert.equal(res.stdout, 'Wrote 1 baseline references for 3 files.\n');
    const written = fs.readFileSync(catalogPath, 'utf8');
    const catalog = JSON.parse(written);
    assert.deepEqual(catalog.baseline, { 'src/services.rs': ['db'] });
    assert.equal(written, JSON.stringify(catalog, null, 2) + '\n');

    res = runCli(tmp, []);
    assert.equal(res.status, 0, res.stderr);
    assert.equal(res.stdout, 'Layer dependencies: 3 production files checked, 1 baselined references, 0 new.\n');

    fs.writeFileSync(path.join(tmp, 'src', 'services.rs'), '\n');
    res = runCli(tmp, []);
    assert.equal(res.status, 1, res.stderr);
    assert.match(res.stderr, /src\/services\.rs: baseline entry db is no longer needed; remove it from catalog\/source-layers\.json \(run with --write\)/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('CLI - write excludes unknown names and still fails', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'layer-dependencies-'));
  try {
    fs.mkdirSync(path.join(tmp, 'src'));
    fs.mkdirSync(path.join(tmp, 'catalog'));
    fs.writeFileSync(path.join(tmp, 'src', 'main.rs'), 'mod services; mod db;\n');
    fs.writeFileSync(path.join(tmp, 'src', 'services.rs'), 'use crate::{missing, db};\n');
    fs.writeFileSync(path.join(tmp, 'src', 'db.rs'), '\n');
    const catalogPath = path.join(tmp, 'catalog', 'source-layers.json');
    fs.writeFileSync(catalogPath, JSON.stringify(layerCatalog(), null, 2) + '\n');
    const res = runCli(tmp, ['--write']);
    assert.equal(res.status, 1, res.stderr);
    assert.match(res.stderr, /src\/services\.rs: crate::missing is not in any layer of catalog\/source-layers\.json/);
    assert.deepEqual(JSON.parse(fs.readFileSync(catalogPath, 'utf8')).baseline, { 'src/services.rs': ['db'] });
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
