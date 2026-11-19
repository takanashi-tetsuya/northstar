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

const productionDirs = [
  'src/db',
  'crates/contexts/session/northstar-protocol-runtime/src',
  'tools/northstar-test-harness/src'
];

test('classify', () => {
  assert.equal(classify('src/abuse_tests.rs'), 'test');
  assert.equal(classify('src/cluster_muc_routing_tests.rs'), 'test');
  assert.equal(classify('src/tests.rs'), 'test');
  assert.equal(classify('src/test_activation.rs'), 'test');
  assert.equal(classify('src/pubsub_integration_tests.rs'), 'test');
  assert.equal(classify('src/db/tests/x.rs'), 'test');
  
  assert.equal(classify('src/node.rs'), 'production');
  assert.equal(classify('src/latest.rs'), 'production');
  assert.equal(classify('src/contest.rs'), 'production');
  assert.equal(classify('crates/kernel/northstar-xml-framing/src/lib.rs'), 'production');
  assert.equal(classify('crates/edges/northstar-cluster/src/tests.rs'), 'test');
  assert.equal(classify('tools/northstar-db-it/src/lib.rs'), 'test');
  assert.equal(classify('tools/northstar-db-it/src/room/muc.rs'), 'test');
  assert.equal(classify('crates/edges/example/src/protocol_regression_tests/muc.rs'), 'test');
  assert.equal(classify('tools/example/protocol_regression_tests/nested/facade.rs'), 'test');
  assert.equal(classify('tools/northstar-test-harness/src/controlled_admission/execution.rs'), 'production');
  assert.equal(classify('tools/northstar-test-harness/tests/saved_replay/stage4_replay.rs'), 'test');
  assert.equal(classify('tools/northstar-db-it/src_extra/lib.rs'), 'production');
  assert.equal(classify('tools/northstar-db-it-extra/src/lib.rs'), 'production');
  assert.equal(classify('crates/edges/example/src/protocol_regression_tests_extra/muc.rs'), 'production');
});

test('evaluateStructure - growth violation', () => {
  for (const dir of productionDirs) {
    const sourcePath = `${dir}/huge.rs`;
    const baseline = {
      schema: "northstar-source-structure-baseline-v1",
      budgets: { production: 1500, test: 3000 },
      oversize: { [sourcePath]: 2000 },
      root_rust_files: []
    };
    const files = [{ path: sourcePath, lines: 2500 }];
    const result = evaluateStructure({ files, baseline });
    assert.equal(result.violations.length, 1);
    assert.equal(result.violations[0], `${sourcePath}: grew from 2000 to 2500 lines`);
  }
});

test('evaluateStructure - new oversize violation', () => {
  for (const dir of productionDirs) {
    const sourcePath = `${dir}/big.rs`;
    const baseline = {
      schema: "northstar-source-structure-baseline-v1",
      budgets: { production: 1500, test: 3000 },
      oversize: {},
      root_rust_files: []
    };
    const files = [{ path: sourcePath, lines: 1500 }];
    assert.deepEqual(evaluateStructure({ files, baseline }).violations, []);
    files[0].lines = 1501;
    const result = evaluateStructure({ files, baseline });
    assert.equal(result.violations.length, 1);
    assert.equal(result.violations[0], `${sourcePath}: new oversize file`);
  }
});

test('evaluateStructure - shrink notice', () => {
  for (const dir of productionDirs) {
    const sourcePath = `${dir}/huge.rs`;
    const baseline = {
      schema: "northstar-source-structure-baseline-v1",
      budgets: { production: 1500, test: 3000 },
      oversize: { [sourcePath]: 2000 },
      root_rust_files: []
    };
    const files = [{ path: sourcePath, lines: 1900 }];
    const result = evaluateStructure({ files, baseline });
    assert.equal(result.violations.length, 0);
    assert.equal(result.notices.length, 1);
    assert.equal(result.notices[0], `${sourcePath}: shrank or is within budget. Run with --update to lower baseline.`);
  }
});

test('evaluateStructure - test budget applies to test files', () => {
  const baseline = {
    schema: "northstar-source-structure-baseline-v1",
    budgets: { production: 1500, test: 3000 },
    oversize: {},
    root_rust_files: []
  };
  for (const sourcePath of [
    'src/db/big_tests.rs',
    'crates/edges/northstar-cluster/src/tests.rs',
    'crates/contexts/room/northstar-muc-xmpp/src/protocol_regression_tests/muc.rs',
    'tools/northstar-db-it/src/room/muc.rs',
    'tools/northstar-test-harness/tests/saved_replay/stage4_replay.rs',
    'tools/northstar-test-harness/tests/saved_replay/stage4_replay/compact.rs'
  ]) {
    for (const lines of [2500, 3000]) {
      const files = [{ path: sourcePath, lines }];
      assert.deepEqual(evaluateStructure({ files, baseline }).violations, []);
    }
    const files = [{ path: sourcePath, lines: 3001 }];
    assert.deepEqual(evaluateStructure({ files, baseline }).violations, [
      `${sourcePath}: new oversize file`
    ]);
  }
});

test('evaluateStructure - new root file violation', () => {
  const baseline = {
    schema: "northstar-source-structure-baseline-v1",
    budgets: { production: 1500, test: 3000 },
    oversize: {},
    root_rust_files: []
  };
  const files = [
    { path: "src/main.rs", lines: 10 },
    { path: "src/nested/lib.rs", lines: 10 },
    { path: "crates/kernel/example/src/lib.rs", lines: 10 },
    { path: "tools/example/src/lib.rs", lines: 10 }
  ];
  const result = evaluateStructure({ files, baseline });
  assert.equal(result.violations.length, 1);
  assert.match(result.violations[0], /src\/main\.rs: new root source file/);
  assert.deepEqual(buildBaseline(files).root_rust_files, ['src/main.rs']);
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
  for (const dir of productionDirs) {
    const sourcePath = `${dir}/big.rs`;
    const baseline = {
      schema: "northstar-source-structure-baseline-v1",
      budgets: { production: 1500, test: 3000 },
      oversize: { [sourcePath]: 2000, "src/db/big_tests.rs": 3500 },
      root_rust_files: []
    };
    const files = [
      { path: sourcePath, lines: 2000, inlineTestModules: 0 },
      { path: "src/db/small.rs", lines: 1000, inlineTestModules: 1 },
      { path: "src/db/big_tests.rs", lines: 3500, inlineTestModules: 1 }
    ];
    assert.deepEqual(evaluateStructure({ files, baseline }).violations, []);

    files[0].inlineTestModules = 2;
    const result = evaluateStructure({ files, baseline });
    assert.deepEqual(result.violations, [
      `${sourcePath}: oversize file keeps 2 inline test module(s); move them into child files (R1)`
    ]);
  }
});

test('lowerBaseline - lowers and removes but never raises or adds', () => {
  for (const dir of productionDirs) {
    const baseline = {
      schema: "northstar-source-structure-baseline-v1",
      budgets: { production: 1500, test: 3000 },
      oversize: {
        [`${dir}/a.rs`]: 2000,
        [`${dir}/b.rs`]: 2000,
        [`${dir}/c.rs`]: 2000,
        [`${dir}/deleted.rs`]: 2000
      },
      root_rust_files: ["src/main.rs", "src/deleted.rs"]
    };
    const files = [
      { path: `${dir}/a.rs`, lines: 2500 }, // grew, should not be raised by lowerBaseline
      { path: `${dir}/b.rs`, lines: 1800 }, // shrank
      { path: `${dir}/c.rs`, lines: 1000 }, // within budget, should be removed
      { path: `${dir}/new.rs`, lines: 2000 }, // unreviewed, should not be added
      { path: "src/main.rs", lines: 10 },
      { path: "src/extra.rs", lines: 10 } // unreviewed root, should not be added
      // src/deleted.rs is gone
    ];
    const { baseline: lowered, changed } = lowerBaseline({ files, baseline });
    assert.equal(changed, true);
    assert.equal(lowered.oversize[`${dir}/a.rs`], 2000);
    assert.equal(lowered.oversize[`${dir}/b.rs`], 1800);
    assert.equal(lowered.oversize[`${dir}/c.rs`], undefined);
    assert.equal(lowered.oversize[`${dir}/deleted.rs`], undefined);
    assert.equal(lowered.oversize[`${dir}/new.rs`], undefined);
    assert.deepEqual(lowered.root_rust_files, ["src/main.rs"]);
  }
});

test('evaluateStructure - extracted prerequisite test modules need no exception', () => {
  const productionPaths = [
    'crates/contexts/message/northstar-delivery-core/src/bosh_ownership/response.rs',
    'crates/contexts/pubsub/northstar-pubsub-application/src/lib.rs'
  ];
  const childPaths = [
    'crates/contexts/message/northstar-delivery-core/src/bosh_ownership/response/tests.rs',
    'crates/contexts/pubsub/northstar-pubsub-application/src/tests.rs'
  ];
  const baseline = {
    schema: "northstar-source-structure-baseline-v1",
    budgets: { production: 1500, test: 3000 },
    oversize: {},
    root_rust_files: []
  };
  // Synthetic boundary counts, not measurements of the pending WP-628 extractions.
  const files = [
    ...productionPaths.map(sourcePath => ({
      path: sourcePath,
      lines: 1500,
      inlineTestModules: countInlineTestModules('#[cfg(test)]\nmod tests;\n')
    })),
    ...childPaths.map(sourcePath => ({ path: sourcePath, lines: 3000 }))
  ];
  assert.deepEqual(evaluateStructure({ files, baseline }).violations, []);

  for (const file of files) file.lines++;
  assert.deepEqual(evaluateStructure({ files, baseline }).violations,
    files.map(file => `${file.path}: new oversize file`));
});

test('scanSource - relative path', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'source-structure-'));
  try {
    for (const sourceRoot of ['src', 'crates', 'tools']) {
      fs.mkdirSync(path.join(tmp, sourceRoot));
    }
    const expected = [
      { path: 'src/test_relative.rs', lines: 1, inlineTestModules: 0 },
      { path: 'crates/kernel/northstar-xml-framing/src/lib.rs', lines: 2, inlineTestModules: 0 },
      { path: 'crates/platform/northstar-config/src/loading.rs', lines: 3, inlineTestModules: 0 },
      { path: 'crates/contexts/session/northstar-protocol-runtime/src/caps.rs', lines: 4, inlineTestModules: 0 },
      { path: 'crates/edges/northstar-cluster/src/tests.rs', lines: 5, inlineTestModules: 0 },
      { path: 'tools/architecture-validator/src/main.rs', lines: 6, inlineTestModules: 0 },
      { path: 'tools/northstar-test-harness/src/lib.rs', lines: 7, inlineTestModules: 0 },
      { path: 'tools/northstar-test-harness/tests/saved_replay/stage4_replay.rs', lines: 8, inlineTestModules: 0 }
    ].sort((a, b) => a.path.localeCompare(b.path));
    for (const file of expected) {
      fs.mkdirSync(path.dirname(path.join(tmp, file.path)), { recursive: true });
      fs.writeFileSync(path.join(tmp, file.path), '\n'.repeat(file.lines) + '// no final newline');
    }
    for (const ignored of [
      'src/not_rust.txt',
      'crates/kernel/northstar-xml-framing/config.toml',
      'src/target/nested/generated.rs',
      'src/.git/nested/hidden.rs',
      'crates/kernel/northstar-xml-framing/target/generated.rs',
      'crates/.git/hidden.rs',
      'tools/northstar-test-harness/target/nested/generated.rs',
      'tools/.git/hidden.rs',
      'fuzz/src/lib.rs'
    ]) {
      fs.mkdirSync(path.dirname(path.join(tmp, ignored)), { recursive: true });
      fs.writeFileSync(path.join(tmp, ignored), '\n');
    }
    const relRoot = path.relative(process.cwd(), tmp);
    const files = scanSource(relRoot);
    assert.deepEqual(files, expected);
    fs.writeFileSync(path.join(tmp, 'src', 'test_relative.rs'), '#[cfg(test)]\nmod tests {\n}\n');
    const inlineFile = scanSource(relRoot).find(file => file.path === 'src/test_relative.rs');
    assert.equal(inlineFile.lines, 3);
    assert.equal(inlineFile.inlineTestModules, 1);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('scanSource - missing and non-directory required roots fail closed', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'source-structure-'));
  try {
    for (const sourceRoot of ['src', 'crates', 'tools']) {
      fs.mkdirSync(path.join(tmp, sourceRoot));
    }
    for (const sourceRoot of ['src', 'crates', 'tools']) {
      const rootPath = path.join(tmp, sourceRoot);
      fs.rmdirSync(rootPath);
      assert.throws(() => scanSource(tmp), { code: 'ENOENT' });
      fs.writeFileSync(rootPath, 'not a directory');
      assert.throws(() => scanSource(tmp), { code: 'ENOTDIR' });
      fs.rmSync(rootPath);
      fs.mkdirSync(rootPath);
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('scanSource - unreadable required roots fail closed', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'source-structure-'));
  const readdirSync = fs.readdirSync;
  try {
    for (const sourceRoot of ['src', 'crates', 'tools']) {
      fs.mkdirSync(path.join(tmp, sourceRoot));
    }
    for (const sourceRoot of ['src', 'crates', 'tools']) {
      const rootPath = path.join(tmp, sourceRoot);
      fs.readdirSync = (dir, options) => {
        if (dir === rootPath) {
          const error = new Error(`permission denied: ${rootPath}`);
          error.code = 'EACCES';
          throw error;
        }
        return readdirSync(dir, options);
      };
      assert.throws(() => scanSource(tmp), { code: 'EACCES' });
    }
  } finally {
    fs.readdirSync = readdirSync;
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('CLI tests', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'source-structure-'));
  
  try {
    fs.mkdirSync(path.join(tmp, 'src'));
    fs.mkdirSync(path.join(tmp, 'src', 'db'));
    fs.mkdirSync(path.join(tmp, 'crates'));
    fs.mkdirSync(path.join(tmp, 'tools'));
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

    const cratePath = 'crates/contexts/session/northstar-protocol-runtime/src/caps.rs';
    const toolTestPath = 'tools/northstar-test-harness/tests/saved_replay/stage4_replay.rs';
    const toolProductionPath = 'tools/northstar-test-harness/src/lib.rs';
    const reviewedEntries = {
      [cratePath]: 1700,
      'src/db/heavy.rs': 1600,
      [toolProductionPath]: 1800,
      [toolTestPath]: 3200
    };
    for (const [sourcePath, lines] of Object.entries(reviewedEntries)) {
      fs.mkdirSync(path.dirname(path.join(tmp, sourcePath)), { recursive: true });
      fs.writeFileSync(path.join(tmp, sourcePath), '\n'.repeat(lines));
    }
    const crateLibPath = 'crates/kernel/northstar-xml-framing/src/lib.rs';
    fs.mkdirSync(path.dirname(path.join(tmp, crateLibPath)), { recursive: true });
    fs.writeFileSync(path.join(tmp, crateLibPath), '\n');

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
    assert.deepEqual(baseline.oversize, reviewedEntries);
    assert.deepEqual(baseline.root_rust_files, ["src/main.rs"]);

    // second init without --force
    res = spawnSync(process.execPath, [scriptPath, '--init', '--root', tmp], { encoding: 'utf8' });
    assert.equal(res.status, 1);
    assert.match(res.stderr, /error: baseline already exists/);

    res = spawnSync(process.execPath, [scriptPath, '--root', tmp], { encoding: 'utf8' });
    assert.equal(res.status, 0); // clean check exits 0
    
    // 2. growth fails both a normal check and --update without raising the baseline
    for (const [sourcePath, lines] of Object.entries(reviewedEntries)) {
      fs.appendFileSync(path.join(tmp, sourcePath), '\n');
      for (const mode of [[], ['--update']]) {
        res = spawnSync(process.execPath, [scriptPath, ...mode, '--root', tmp], { encoding: 'utf8' });
        assert.equal(res.status, 1, res.stderr);
        assert.ok(res.stderr.includes(`${sourcePath}: grew from ${lines} to ${lines + 1} lines`));
        assert.equal(fs.readFileSync(path.join(tmp, 'catalog', 'source-structure-baseline.json'), 'utf8'), baselineRaw);
      }
      fs.writeFileSync(path.join(tmp, sourcePath), '\n'.repeat(lines));
    }

    // 3. adding a new root file makes the CLI exit 1
    fs.writeFileSync(path.join(tmp, 'src', 'extra.rs'), '\n');
    res = spawnSync(process.execPath, [scriptPath, '--root', tmp], { encoding: 'utf8' });
    assert.equal(res.status, 1);
    assert.match(res.stderr, /src\/extra\.rs: new root source file/);
    fs.rmSync(path.join(tmp, 'src', 'extra.rs'));

    // 4. shrink then --update rewrites the baseline with the lower count
    const shrankContent = '\n'.repeat(1550);
    fs.writeFileSync(path.join(tmp, 'src', 'db', 'heavy.rs'), shrankContent);
    fs.writeFileSync(path.join(tmp, cratePath), '\n'.repeat(1600));
    fs.writeFileSync(path.join(tmp, toolProductionPath), '\n'.repeat(1700));
    fs.writeFileSync(path.join(tmp, toolTestPath), '\n'.repeat(3000));
    
    res = spawnSync(process.execPath, [scriptPath, '--update', '--root', tmp], { encoding: 'utf8' });
    assert.equal(res.status, 0);
    
    let newBaselineRaw = fs.readFileSync(path.join(tmp, 'catalog', 'source-structure-baseline.json'), 'utf8');
    const newBaseline = JSON.parse(newBaselineRaw);
    assert.deepEqual(newBaseline.oversize, {
      [cratePath]: 1600,
      'src/db/heavy.rs': 1550,
      [toolProductionPath]: 1700
    });
    assert.deepEqual(newBaseline.root_rust_files, ['src/main.rs']);

    // 5. relative path doesn't corrupt paths
    res = spawnSync(process.execPath, [scriptPath, '--root', path.basename(tmp)], { cwd: path.dirname(tmp), encoding: 'utf8' });
    assert.equal(res.status, 0);
    assert.equal(res.stderr.includes('rc/'), false);

    // 6. --update removes a crate entry at its budget and a deleted tool entry
    fs.writeFileSync(path.join(tmp, cratePath), '\n'.repeat(1500));
    fs.rmSync(path.join(tmp, toolProductionPath));
    res = spawnSync(process.execPath, [scriptPath, '--update', '--root', tmp], { encoding: 'utf8' });
    assert.equal(res.status, 0, res.stderr);
    newBaselineRaw = fs.readFileSync(path.join(tmp, 'catalog', 'source-structure-baseline.json'), 'utf8');
    assert.deepEqual(JSON.parse(newBaselineRaw).oversize, { 'src/db/heavy.rs': 1550 });

    // 7. --update cannot add unreviewed crate or tool oversize entries
    for (const [sourcePath, lines] of [
      ['crates/contexts/session/northstar-protocol-runtime/src/new.rs', 1501],
      ['tools/northstar-test-harness/src/new.rs', 1501],
      ['tools/northstar-test-harness/tests/saved_replay/unreviewed.rs', 3001]
    ]) {
      fs.writeFileSync(path.join(tmp, sourcePath), '\n'.repeat(lines));
      res = spawnSync(process.execPath, [scriptPath, '--update', '--root', tmp], { encoding: 'utf8' });
      assert.equal(res.status, 1, res.stderr);
      assert.ok(res.stderr.includes(`${sourcePath}: new oversize file`));
      assert.equal(fs.readFileSync(path.join(tmp, 'catalog', 'source-structure-baseline.json'), 'utf8'), newBaselineRaw);
      fs.rmSync(path.join(tmp, sourcePath));
    }

    // 8. no CLI mode may use a partial inventory when a required root is missing
    for (const sourceRoot of ['src', 'crates', 'tools']) {
      const rootPath = path.join(tmp, sourceRoot);
      const savedPath = path.join(tmp, `${sourceRoot}-saved`);
      fs.renameSync(rootPath, savedPath);
      try {
        for (const mode of [[], ['--update'], ['--init', '--force']]) {
          res = spawnSync(process.execPath, [scriptPath, ...mode, '--root', tmp], { encoding: 'utf8' });
          assert.equal(res.status, 1, res.stderr);
          assert.match(res.stderr, /error: could not scan source under/);
          assert.ok(res.stderr.includes(rootPath));
          assert.equal(fs.readFileSync(path.join(tmp, 'catalog', 'source-structure-baseline.json'), 'utf8'), newBaselineRaw);
        }
      } finally {
        fs.renameSync(savedPath, rootPath);
      }
    }

  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('CLI - role-split catalog is checked under --root', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'source-structure-'));
  try {
    fs.mkdirSync(path.join(tmp, 'src', 'db'), { recursive: true });
    fs.mkdirSync(path.join(tmp, 'crates'));
    fs.mkdirSync(path.join(tmp, 'tools'));
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
