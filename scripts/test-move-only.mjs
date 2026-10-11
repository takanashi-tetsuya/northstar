import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { lexRust, normalizeItems, compareItemSets } from './check-move-only.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const checkScript = path.join(__dirname, 'check-move-only.mjs');

test('a. A parent with two functions split into a parent and a child', () => {
  const before = `
    fn f1() {}
    fn f2() {}
  `;
  const afterParent = `
    mod child;
    pub use self::child::*;
    fn f1() {}
  `;
  const afterChildWithUse = `
    //! header
    use super::*;
    fn f2() {}
  `;
  const afterChildNoUse = `
    //! header
    fn f2() {}
  `;
  const beforeFiles = [{ path: 'src/foo.rs', source: before, isChild: false }];
  
  const afterFiles1 = [
    { path: 'src/foo.rs', source: afterParent, isChild: false },
    { path: 'src/foo/child.rs', source: afterChildWithUse, isChild: true }
  ];
  
  const res1Doc = compareItemSets(beforeFiles, afterFiles1, { allowDoc: true });
  assert.equal(res1Doc.removed.length, 0);
  assert.equal(res1Doc.added.length, 0);
  
  const res1NoDoc = compareItemSets(beforeFiles, afterFiles1, { allowDoc: false });
  assert.equal(res1NoDoc.removed.length, 0);
  assert.equal(res1NoDoc.added.length, 0);
  
  const afterFiles2 = [
    { path: 'src/foo.rs', source: afterParent, isChild: false },
    { path: 'src/foo/child.rs', source: afterChildNoUse, isChild: true }
  ];
  
  const res2Doc = compareItemSets(beforeFiles, afterFiles2, { allowDoc: true });
  assert.equal(res2Doc.removed.length, 0);
  assert.equal(res2Doc.added.length, 0);
  
  const res2NoDoc = compareItemSets(beforeFiles, afterFiles2, { allowDoc: false });
  assert.notEqual(res2NoDoc.added.length, 0);
});

test('b. Code moved into a child that wrote super::x::y() must read super::super::x::y()', () => {
  const beforeFiles = [{ path: 'src/foo.rs', source: 'fn f() { super::x::y(); }', isChild: false }];
  
  const afterFilesEqual = [{ path: 'src/foo/child.rs', source: 'fn f() { super::super::x::y(); }', isChild: true }];
  const resEq = compareItemSets(beforeFiles, afterFilesEqual);
  assert.equal(resEq.removed.length, 0);
  assert.equal(resEq.added.length, 0);
  
  const afterFilesDiff = [{ path: 'src/foo/child.rs', source: 'fn f() { super::x::y(); }', isChild: true }];
  const resDiff = compareItemSets(beforeFiles, afterFilesDiff);
  assert.notEqual(resDiff.removed.length, 0);
  assert.notEqual(resDiff.added.length, 0);
  
  const beforeFilesSelf = [{ path: 'src/foo.rs', source: 'fn f() { self::helper(); }', isChild: false }];
  const afterFilesSuper = [{ path: 'src/foo/child.rs', source: 'fn f() { super::helper(); }', isChild: true }];
  const resSelf = compareItemSets(beforeFilesSelf, afterFilesSuper);
  assert.equal(resSelf.removed.length, 0);
  assert.equal(resSelf.added.length, 0);
});

test('c. Re-indenting and rustfmt trailing comma vs adding space in string literal', () => {
  const before = [{ path: 'src/foo.rs', source: 'fn f() {\n  foo(1, 2)\n}', isChild: false }];
  const afterEq = [{ path: 'src/foo/child.rs', source: 'fn f() { foo(1, 2,) }', isChild: true }];
  const resEq = compareItemSets(before, afterEq);
  assert.equal(resEq.removed.length, 0);
  assert.equal(resEq.added.length, 0);

  const beforeStr = [{ path: 'src/foo.rs', source: 'fn f() { "SQL string" }', isChild: false }];
  const afterStrDiff = [{ path: 'src/foo/child.rs', source: 'fn f() { "SQL  string" }', isChild: true }];
  const resStrDiff = compareItemSets(beforeStr, afterStrDiff);
  assert.notEqual(resStrDiff.removed.length, 0);
  
  const beforeRaw = [{ path: 'src/foo.rs', source: 'fn f() { r#"raw"# }', isChild: false }];
  const afterRawDiff = [{ path: 'src/foo/child.rs', source: 'fn f() { r#"raw "# }', isChild: true }];
  const resRawDiff = compareItemSets(beforeRaw, afterRawDiff);
  assert.notEqual(resRawDiff.removed.length, 0);
});

test('d. A lifetime \\\'a and a char literal \\\'"\\\' do not derail lexing', () => {
  const source = `fn f<'a>(x: &'a str) -> char { '"' } fn g() {}`;
  const items = normalizeItems(source);
  assert.equal(items.length, 2);
  assert.ok(items[0].key.includes('fn\x01f\x01<\x01\'\x01a\x01>'));
  assert.ok(items[1].key.includes('fn\x01g'));
});

test('e. Inline test module vs child tests file', () => {
  const before = [{ path: 'src/foo.rs', source: '#[cfg(test)] mod tests { use super::*; #[test] fn t() {} }', isChild: false }];
  const after = [
    { path: 'src/foo.rs', source: '#[cfg(test)] mod tests;', isChild: false },
    { path: 'src/foo/tests.rs', source: 'use super::*; #[test] fn t() {}', isChild: true }
  ];
  const res = compareItemSets(before, after);
  assert.equal(res.removed.length, 0);
  assert.equal(res.added.length, 0);
});

test('f. Visibility signature change', () => {
  const before = [{ path: 'src/foo.rs', source: 'pub(super) fn grant() {}', isChild: false }];
  const after = [{ path: 'src/foo/child.rs', source: 'pub(in crate::db) fn grant() {}', isChild: true }];
  const res = compareItemSets(before, after);
  assert.equal(res.removed.length, 0);
  assert.equal(res.added.length, 0);
  assert.equal(res.visibilityChanges.length, 1);
  assert.deepEqual(res.visibilityChanges[0].before, ['pub(super)']);
  assert.deepEqual(res.visibilityChanges[0].after, ['pub(in crate::db)']);
});

test('g. Changing a doc comment (/// text) on a moved item: different', () => {
  const before = [{ path: 'src/foo.rs', source: '/// doc1\nfn f() {}', isChild: false }];
  const after = [{ path: 'src/foo/child.rs', source: '/// doc2\nfn f() {}', isChild: true }];
  const res = compareItemSets(before, after, { allowDoc: true });
  assert.notEqual(res.removed.length, 0);
  assert.notEqual(res.added.length, 0);
});

test('h. CLI end to end in a temporary git repository', () => {
  const tmpdir = fs.mkdtempSync(path.join(os.tmpdir(), 'test-move-only-'));
  try {
    execFileSync('git', ['init'], { cwd: tmpdir });
    fs.mkdirSync(path.join(tmpdir, 'src'));
    fs.writeFileSync(path.join(tmpdir, 'src/foo.rs'), 'fn f() { "A" }');
    execFileSync('git', ['add', '.'], { cwd: tmpdir });
    execFileSync('git', ['-c', 'user.name=test', '-c', 'user.email=test@example.invalid', 'commit', '-m', 'init'], { cwd: tmpdir });
    
    fs.writeFileSync(path.join(tmpdir, 'src/foo.rs'), 'mod child;');
    fs.mkdirSync(path.join(tmpdir, 'src/foo'));
    fs.writeFileSync(path.join(tmpdir, 'src/foo/child.rs'), 'fn f() { "A" }');
    
    const resOk = spawnSync(process.execPath, [checkScript, '--repo', tmpdir, 'HEAD', 'src/foo.rs'], { encoding: 'utf8' });
    assert.equal(resOk.status, 0);
    assert.ok(resOk.stdout.includes('MOVE-ONLY (items): OK'));
    
    fs.writeFileSync(path.join(tmpdir, 'src/foo/child.rs'), 'fn f() { "B" }');
    const resDiff = spawnSync(process.execPath, [checkScript, '--repo', tmpdir, 'HEAD', 'src/foo.rs'], { encoding: 'utf8' });
    assert.equal(resDiff.status, 1);
    assert.ok(resDiff.stdout.includes('MOVE-ONLY (items): DIFFERENT'));
    
    const resAbs = spawnSync(process.execPath, [checkScript, '--repo', tmpdir, 'HEAD', '/src/foo.rs'], { encoding: 'utf8' });
    assert.equal(resAbs.status, 2);
    
    fs.writeFileSync(path.join(tmpdir, 'src/foo/child.rs'), 'fn f() { "A" }');
    execFileSync('git', ['add', '.'], { cwd: tmpdir });
    execFileSync('git', ['-c', 'user.name=test', '-c', 'user.email=test@example.invalid', 'commit', '-m', 'split'], { cwd: tmpdir });
    
    fs.writeFileSync(path.join(tmpdir, 'src/foo/child.rs'), 'fn f() { "C" }');
    
    const resAfterRev = spawnSync(process.execPath, [checkScript, '--repo', tmpdir, '--after-rev', 'HEAD', 'HEAD~1', 'src/foo.rs'], { encoding: 'utf8' });
    assert.equal(resAfterRev.status, 0);
    assert.ok(resAfterRev.stdout.includes('MOVE-ONLY (items): OK'));
    
    const resNoAfterRev = spawnSync(process.execPath, [checkScript, '--repo', tmpdir, 'HEAD~1', 'src/foo.rs'], { encoding: 'utf8' });
    assert.equal(resNoAfterRev.status, 1);
    
    const resNonExistent = spawnSync(process.execPath, [checkScript, '--repo', tmpdir, 'HEAD', 'src/nonexistent.rs'], { encoding: 'utf8' });
    assert.equal(resNonExistent.status, 2);
    
    const resMissingAfterRev = spawnSync(process.execPath, [checkScript, '--repo', tmpdir, '--after-rev'], { encoding: 'utf8' });
    assert.equal(resMissingAfterRev.status, 2);
  } finally {
    fs.rmSync(tmpdir, { recursive: true, force: true });
  }
});
