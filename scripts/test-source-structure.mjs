import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import {
  classify,
  countInlineTestModules,
  evaluateStructure,
  buildBaseline,
  lowerBaseline,
  scanSource
} from './check-source-structure.mjs';

test('classify', () => {
  assert.equal(classify('src/abuse_tests.rs'), 'test');
  assert.equal(classify('src/cluster_muc_routing_tests.rs'), 'test');
  assert.equal(classify('src/tests.rs'), 'test');
  assert.equal(classify('src/test_activation.rs'), 'test');
  assert.equal(classify('src/pubsub_integration_tests.rs'), 'test');
  assert.equal(classify('src/db/tests/x.rs'), 'test');
  
  assert.equal(classify('src/stage4_replay.rs'), 'production');
  assert.equal(classify('src/latest.rs'), 'production');
  assert.equal(classify('src/contest.rs'), 'production');
});

test('evaluateStructure - growth violation', () => {
  const baseline = {
    schema: "northstar-source-structure-baseline-v1",
    budgets: { production: 1500, test: 3000 },
    oversize: { "src/db/huge.rs": 2000 },
    root_rust_files: []
  };
  const files = [{ path: "src/db/huge.rs", lines: 2500 }];
  const result = evaluateStructure({ files, baseline });
  assert.equal(result.violations.length, 1);
  assert.match(result.violations[0], /src\/db\/huge\.rs: grew from 2000 to 2500 lines/);
});

test('evaluateStructure - new oversize violation', () => {
  const baseline = {
    schema: "northstar-source-structure-baseline-v1",
    budgets: { production: 1500, test: 3000 },
    oversize: {},
    root_rust_files: []
  };
  const files = [{ path: "src/db/big.rs", lines: 1600 }];
  const result = evaluateStructure({ files, baseline });
  assert.equal(result.violations.length, 1);
  assert.match(result.violations[0], /src\/db\/big\.rs: new oversize file/);
});

test('evaluateStructure - test budget applies to test files', () => {
  const baseline = {
    schema: "northstar-source-structure-baseline-v1",
    budgets: { production: 1500, test: 3000 },
    oversize: {},
    root_rust_files: []
  };
  const files1 = [{ path: "src/db/big_tests.rs", lines: 2500 }];
  const result1 = evaluateStructure({ files: files1, baseline });
  assert.equal(result1.violations.length, 0); // test budget is 3000

  const files2 = [{ path: "src/db/big_tests.rs", lines: 3001 }];
  const result2 = evaluateStructure({ files: files2, baseline });
  assert.equal(result2.violations.length, 1);
  assert.match(result2.violations[0], /src\/db\/big_tests\.rs: new oversize file/);
});

test('evaluateStructure - shrink notice', () => {
  const baseline = {
    schema: "northstar-source-structure-baseline-v1",
    budgets: { production: 1500, test: 3000 },
    oversize: { "src/db/huge.rs": 2000 },
    root_rust_files: []
  };
  const files = [{ path: "src/db/huge.rs", lines: 1900 }];
  const result = evaluateStructure({ files, baseline });
  assert.equal(result.violations.length, 0);
  assert.equal(result.notices.length, 1);
  assert.match(result.notices[0], /src\/db\/huge\.rs:/);
});

test('evaluateStructure - new root file violation', () => {
  const baseline = {
    schema: "northstar-source-structure-baseline-v1",
    budgets: { production: 1500, test: 3000 },
    oversize: {},
    root_rust_files: []
  };
  const files = [{ path: "src/main.rs", lines: 10 }];
  const result = evaluateStructure({ files, baseline });
  assert.equal(result.violations.length, 1);
  assert.match(result.violations[0], /src\/main\.rs: new root source file/);
});

test('evaluateStructure - deleted root file notice', () => {
  const baseline = {
    schema: "northstar-source-structure-baseline-v1",
    budgets: { production: 1500, test: 3000 },
    oversize: {},
    root_rust_files: ["src/main.rs"]
  };
  const files = [];
  const result = evaluateStructure({ files, baseline });
  assert.equal(result.violations.length, 0);
  assert.equal(result.notices.length, 1);
  assert.match(result.notices[0], /src\/main\.rs:/);
});

test('evaluateStructure - invalid schemas', () => {
  const badSchema = {
    schema: "wrong-schema",
    budgets: { production: 1500, test: 3000 },
    oversize: {},
    root_rust_files: []
  };
  const result1 = evaluateStructure({ files: [], baseline: badSchema });
  assert.equal(result1.violations.length, 1);
  assert.equal(result1.violations[0], "catalog/source-structure-baseline.json: invalid schema or budgets");

  const nonIntegerOversize = {
    schema: "northstar-source-structure-baseline-v1",
    budgets: { production: 1500, test: 3000 },
    oversize: { "src/db/huge.rs": "2000" },
    root_rust_files: []
  };
  const result2 = evaluateStructure({ files: [], baseline: nonIntegerOversize });
  assert.equal(result2.violations.length, 1);
  assert.equal(result2.violations[0], "catalog/source-structure-baseline.json: invalid schema or budgets");
});

test('evaluateStructure - a baseline that names pinned files is invalid', () => {
  const baseline = {
    schema: "northstar-source-structure-baseline-v1",
    budgets: { production: 1500, test: 3000 },
    oversize: {},
    root_rust_files: [],
    pinned: {}
  };
  const result = evaluateStructure({ files: [], baseline });
  assert.deepEqual(result.violations, ["catalog/source-structure-baseline.json: invalid schema or budgets"]);
});

test('countInlineTestModules', () => {
  assert.equal(countInlineTestModules('#[cfg(test)]\nmod tests {\n    use super::*;\n}\n'), 1);
  assert.equal(countInlineTestModules('#[cfg(test)]\n#[allow(clippy::x)]\nmod a_tests {\n}\n\n#[cfg(all(test, unix))]\npub(crate) mod b {\n}\n'), 2);
  assert.equal(countInlineTestModules('#[cfg(test)]\nmod tests;\n'), 0);
  assert.equal(countInlineTestModules('mod helpers {\n}\n#[cfg(feature = "x")]\nmod gated {\n}\n'), 0);
  assert.equal(countInlineTestModules('fn f() {\n    #[cfg(test)]\n    mod nested {\n    }\n}\n'), 0);
  assert.equal(countInlineTestModules('#[cfg(test)]\nfn helper() {}\nmod tests {\n}\n'), 0);
});

test('evaluateStructure - oversize production files keep no inline test modules', () => {
  const baseline = {
    schema: "northstar-source-structure-baseline-v1",
    budgets: { production: 1500, test: 3000 },
    oversize: { "src/db/big.rs": 2000, "src/db/big_tests.rs": 3500 },
    root_rust_files: []
  };
  const files = [
    { path: "src/db/big.rs", lines: 2000, inlineTestModules: 0 },
    { path: "src/db/small.rs", lines: 1000, inlineTestModules: 1 },
    { path: "src/db/big_tests.rs", lines: 3500, inlineTestModules: 1 }
  ];
  assert.deepEqual(evaluateStructure({ files, baseline }).violations, []);

  files[0].inlineTestModules = 2;
  const result = evaluateStructure({ files, baseline });
  assert.deepEqual(result.violations, [
    'src/db/big.rs: oversize file keeps 2 inline test module(s); move them into child files (R1)'
  ]);
});

test('lowerBaseline - lowers and removes but never raises or adds', () => {
  const baseline = {
    schema: "northstar-source-structure-baseline-v1",
    budgets: { production: 1500, test: 3000 },
    oversize: { "src/db/a.rs": 2000, "src/db/b.rs": 2000, "src/db/c.rs": 2000 },
    root_rust_files: ["src/main.rs", "src/deleted.rs"]
  };
  const files = [
    { path: "src/db/a.rs", lines: 2500 }, // grew, should not be raised by lowerBaseline
    { path: "src/db/b.rs", lines: 1800 }, // shrank
    { path: "src/db/c.rs", lines: 1000 }, // within budget, should be removed
    { path: "src/main.rs", lines: 10 }
    // src/deleted.rs is gone
  ];
  const { baseline: lowered, changed } = lowerBaseline({ files, baseline });
  assert.equal(changed, true);
  assert.equal(lowered.oversize["src/db/a.rs"], 2000);
  assert.equal(lowered.oversize["src/db/b.rs"], 1800);
  assert.equal(lowered.oversize["src/db/c.rs"], undefined);
  assert.deepEqual(lowered.root_rust_files, ["src/main.rs"]);
});

test('scanSource - relative path', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'source-structure-'));
  try {
    fs.mkdirSync(path.join(tmp, 'src'));
    fs.writeFileSync(path.join(tmp, 'src', 'test_relative.rs'), '\n');
    const relRoot = path.relative(process.cwd(), tmp);
    const files = scanSource(relRoot);
    assert.equal(files.length, 1);
    assert.equal(files[0].path, 'src/test_relative.rs');
    assert.equal(files[0].inlineTestModules, 0);
    fs.writeFileSync(path.join(tmp, 'src', 'test_relative.rs'), '#[cfg(test)]\nmod tests {\n}\n');
    assert.equal(scanSource(relRoot)[0].inlineTestModules, 1);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('CLI tests', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'source-structure-'));
  
  try {
    fs.mkdirSync(path.join(tmp, 'src'));
    fs.mkdirSync(path.join(tmp, 'src', 'db'));
    fs.mkdirSync(path.join(tmp, 'catalog'));
    fs.writeFileSync(path.join(tmp, 'catalog', 'source-role-splits.json'), JSON.stringify({
      schema: 'northstar-source-role-splits-v1',
      files: {}
    }) + '\n');
    
    // Create a production file that is oversize
    const oversizeContent = '\n'.repeat(1600);
    fs.writeFileSync(path.join(tmp, 'src', 'db', 'heavy.rs'), oversizeContent);
    
    // Create a root file
    fs.writeFileSync(path.join(tmp, 'src', 'main.rs'), '\n');

    const scriptPath = fileURLToPath(new URL('./check-source-structure.mjs', import.meta.url));

    // 0. unknown argument
    let res = spawnSync(process.execPath, [scriptPath, '--unknown', '--root', tmp], { encoding: 'utf8' });
    assert.equal(res.status, 2);
    assert.match(res.stderr, /Usage/);

    // 1. --init then a clean check exits 0
    res = spawnSync(process.execPath, [scriptPath, '--init', '--root', tmp], { encoding: 'utf8' });
    assert.equal(res.status, 0);
    
    const baselineRaw = fs.readFileSync(path.join(tmp, 'catalog', 'source-structure-baseline.json'), 'utf8');
    const baseline = JSON.parse(baselineRaw);
    assert.equal(baseline.oversize["src/db/heavy.rs"], 1600);
    assert.deepEqual(baseline.root_rust_files, ["src/main.rs"]);

    // second init without --force
    res = spawnSync(process.execPath, [scriptPath, '--init', '--root', tmp], { encoding: 'utf8' });
    assert.equal(res.status, 1);
    assert.match(res.stderr, /error: baseline already exists/);

    res = spawnSync(process.execPath, [scriptPath, '--root', tmp], { encoding: 'utf8' });
    assert.equal(res.status, 0); // clean check exits 0
    
    // 2. adding a line to an oversize file makes the CLI exit 1
    fs.appendFileSync(path.join(tmp, 'src', 'db', 'heavy.rs'), '\n');
    res = spawnSync(process.execPath, [scriptPath, '--root', tmp], { encoding: 'utf8' });
    assert.equal(res.status, 1);
    assert.match(res.stderr, /src\/db\/heavy\.rs: grew from 1600 to 1601 lines/);

    // 3. adding a new root file makes the CLI exit 1
    fs.writeFileSync(path.join(tmp, 'src', 'extra.rs'), '\n');
    res = spawnSync(process.execPath, [scriptPath, '--root', tmp], { encoding: 'utf8' });
    assert.equal(res.status, 1);
    assert.match(res.stderr, /src\/extra\.rs: new root source file/);
    fs.rmSync(path.join(tmp, 'src', 'extra.rs'));

    // 4. shrink then --update rewrites the baseline with the lower count
    const shrankContent = '\n'.repeat(1550);
    fs.writeFileSync(path.join(tmp, 'src', 'db', 'heavy.rs'), shrankContent);
    
    res = spawnSync(process.execPath, [scriptPath, '--update', '--root', tmp], { encoding: 'utf8' });
    assert.equal(res.status, 0);
    
    const newBaselineRaw = fs.readFileSync(path.join(tmp, 'catalog', 'source-structure-baseline.json'), 'utf8');
    const newBaseline = JSON.parse(newBaselineRaw);
    assert.equal(newBaseline.oversize["src/db/heavy.rs"], 1550);

    // 5. relative path doesn't corrupt paths
    res = spawnSync(process.execPath, [scriptPath, '--root', path.basename(tmp)], { cwd: path.dirname(tmp), encoding: 'utf8' });
    assert.equal(res.status, 0);
    assert.equal(res.stderr.includes('rc/'), false);

  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('CLI - role-split catalog is checked under --root', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'source-structure-'));
  try {
    fs.mkdirSync(path.join(tmp, 'src', 'db'), { recursive: true });
    fs.mkdirSync(path.join(tmp, 'catalog'));
    fs.writeFileSync(path.join(tmp, 'src', 'db', 'role.rs'), 'mod leaf;\n');
    const scriptPath = fileURLToPath(new URL('./check-source-structure.mjs', import.meta.url));
    const catalogPath = path.join(tmp, 'catalog', 'source-role-splits.json');
    const catalog = {
      schema: 'northstar-source-role-splits-v1',
      files: { 'src/db/role.rs': ['leaf'] }
    };
    fs.writeFileSync(catalogPath, JSON.stringify(catalog) + '\n');
    let res = spawnSync(process.execPath, [scriptPath, '--init', '--root', tmp], { encoding: 'utf8' });
    assert.equal(res.status, 0);

    res = spawnSync(process.execPath, [scriptPath, '--root', tmp], { encoding: 'utf8' });
    assert.equal(res.status, 1);
    assert.match(res.stderr, /error: catalog\/source-role-splits\.json:.*src\/db\/role.rs.*leaf/);

    catalog.files['src/db/role.rs'] = [];
    fs.writeFileSync(catalogPath, JSON.stringify(catalog) + '\n');
    res = spawnSync(process.execPath, [scriptPath, '--root', tmp], { encoding: 'utf8' });
    assert.equal(res.status, 0, res.stderr);
    assert.equal(res.stderr, '');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
