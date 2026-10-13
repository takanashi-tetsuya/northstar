import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { lexRust, normalizeItems, compareItemSets, normalizeStringContinuations, unwrapArmBlocks } from './check-move-only.mjs';

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

test('i. Parent impl S { fn a() {} fn b() {} } split into parent mod child; impl S { fn a() {} } and child use super::*; impl S { fn b() {} }: no removed, no added.', () => {
  const before = [{ path: 'src/foo.rs', source: 'impl S { fn a() {} fn b() {} }', isChild: false }];
  const after = [
    { path: 'src/foo.rs', source: 'mod child; impl S { fn a() {} }', isChild: false },
    { path: 'src/foo/child.rs', source: 'use super::*; impl S { fn b() {} }', isChild: true }
  ];
  const res = compareItemSets(before, after);
  assert.equal(res.removed.length, 0);
  assert.equal(res.added.length, 0);
});

test('j. Same split but the body of b changed in the child: DIFFERENT, and the removed and added excerpts both contain impl and b.', () => {
  const before = [{ path: 'src/foo.rs', source: 'impl S { fn a() {} fn b() {} }', isChild: false }];
  const after = [
    { path: 'src/foo.rs', source: 'mod child; impl S { fn a() {} }', isChild: false },
    { path: 'src/foo/child.rs', source: 'use super::*; impl S { fn b() { "changed" } }', isChild: true }
  ];
  const res = compareItemSets(before, after);
  assert.equal(res.removed.length, 1);
  assert.equal(res.added.length, 1);
  assert.ok(res.removed[0].includes('impl') && res.removed[0].includes('b'));
  assert.ok(res.added[0].includes('impl') && res.added[0].includes('b'));
});

test('k. Moving fn b from impl S to impl T (a different self type) in the child: DIFFERENT.', () => {
  const before = [{ path: 'src/foo.rs', source: 'impl S { fn a() {} fn b() {} }', isChild: false }];
  const after = [
    { path: 'src/foo.rs', source: 'mod child; impl S { fn a() {} }', isChild: false },
    { path: 'src/foo/child.rs', source: 'use super::*; impl T { fn b() {} }', isChild: true }
  ];
  const res = compareItemSets(before, after);
  assert.equal(res.removed.length, 1);
  assert.equal(res.added.length, 1);
});

test('l. impl<T: Clone> W<T> where T: Send { fn a() {} fn b() {} } split into two blocks with the same header: OK; with the where clause changed to T: Sync in the child block: DIFFERENT.', () => {
  const before = [{ path: 'src/foo.rs', source: 'impl<T: Clone> W<T> where T: Send { fn a() {} fn b() {} }', isChild: false }];
  const afterOk = [
    { path: 'src/foo.rs', source: 'impl<T: Clone> W<T> where T: Send { fn a() {} }', isChild: false },
    { path: 'src/foo/child.rs', source: 'impl<T: Clone> W<T> where T: Send { fn b() {} }', isChild: true }
  ];
  const resOk = compareItemSets(before, afterOk);
  assert.equal(resOk.removed.length, 0);
  assert.equal(resOk.added.length, 0);

  const afterDiff = [
    { path: 'src/foo.rs', source: 'impl<T: Clone> W<T> where T: Send { fn a() {} }', isChild: false },
    { path: 'src/foo/child.rs', source: 'impl<T: Clone> W<T> where T: Sync { fn b() {} }', isChild: true }
  ];
  const resDiff = compareItemSets(before, afterDiff);
  assert.equal(resDiff.removed.length, 1);
  assert.equal(resDiff.added.length, 1);
});

test('m. Trait impls stay whole: normalizeItems of impl fmt::Display for S { fn fmt(&self) {} } returns exactly one item; normalizeItems of impl<F> S<F> where F: for<\'a> Fn(&\'a str) { fn a() {} fn b() {} } returns two items; normalizeItems of impl S<fn() -> u8> { fn a() {} fn b() {} } returns two items.', () => {
  assert.equal(normalizeItems('impl fmt::Display for S { fn fmt(&self) {} }').length, 1);
  assert.equal(normalizeItems('impl<F> S<F> where F: for<\'a> Fn(&\'a str) { fn a() {} fn b() {} }').length, 2);
  assert.equal(normalizeItems('impl S<fn() -> u8> { fn a() {} fn b() {} }').length, 2);
});

test('n. A member whose visibility changes from none to pub(super) when moved into the child: no removed, no added, one visibilityChanges entry with before [] and after [\'pub(super)\'].', () => {
  const before = [{ path: 'src/foo.rs', source: 'impl S { fn a() {} }', isChild: false }];
  const after = [
    { path: 'src/foo/child.rs', source: 'impl S { pub(super) fn a() {} }', isChild: true }
  ];
  const res = compareItemSets(before, after);
  assert.equal(res.removed.length, 0);
  assert.equal(res.added.length, 0);
  assert.equal(res.visibilityChanges.length, 1);
  assert.deepEqual(res.visibilityChanges[0].before, []);
  assert.deepEqual(res.visibilityChanges[0].after, ['pub(super)']);
});

test('o. #[cfg(test)] impl S { fn a() {} } before and impl S { fn a() {} } after: DIFFERENT.', () => {
  const before = [{ path: 'src/foo.rs', source: '#[cfg(test)] impl S { fn a() {} }', isChild: false }];
  const after = [{ path: 'src/foo/child.rs', source: 'impl S { fn a() {} }', isChild: true }];
  const res = compareItemSets(before, after);
  assert.notEqual(res.removed.length, 0);
  assert.notEqual(res.added.length, 0);
});

test('p. A trailing comment inside an impl body (impl S { fn a() {} // note\\n }) deleted after the split: DIFFERENT; a trailing comment at the end of a file deleted: DIFFERENT; the same trailing comment kept: OK.', () => {
  const beforeBody = [{ path: 'src/foo.rs', source: 'impl S { fn a() {} // note\n }', isChild: false }];
  const afterBodyDiff = [{ path: 'src/foo/child.rs', source: 'impl S { fn a() {} }', isChild: true }];
  assert.notEqual(compareItemSets(beforeBody, afterBodyDiff).removed.length, 0);

  const beforeFile = [{ path: 'src/foo.rs', source: 'fn a() {}\n// note\n', isChild: false }];
  const afterFileDiff = [{ path: 'src/foo/child.rs', source: 'fn a() {}', isChild: true }];
  assert.notEqual(compareItemSets(beforeFile, afterFileDiff).removed.length, 0);

  const afterFileOk = [{ path: 'src/foo/child.rs', source: 'fn a() {}\n// note\n', isChild: true }];
  assert.equal(compareItemSets(beforeFile, afterFileOk).removed.length, 0);
});

test('q. In a child file, impl S { fn a() { super::super::x(); } } matches the parent\'s impl S { fn a() { super::x(); } }: OK.', () => {
  const before = [{ path: 'src/foo.rs', source: 'impl S { fn a() { super::x(); } }', isChild: false }];
  const after = [{ path: 'src/foo/child.rs', source: 'impl S { fn a() { super::super::x(); } }', isChild: true }];
  const res = compareItemSets(before, after);
  assert.equal(res.removed.length, 0);
  assert.equal(res.added.length, 0);
});

test('r. A member duplicated into two child files: DIFFERENT with exactly one added.', () => {
  const before = [{ path: 'src/foo.rs', source: 'impl S { fn a() {} }', isChild: false }];
  const after = [
    { path: 'src/foo/child1.rs', source: 'impl S { fn a() {} }', isChild: true },
    { path: 'src/foo/child2.rs', source: 'impl S { fn a() {} }', isChild: true }
  ];
  const res = compareItemSets(before, after);
  assert.equal(res.removed.length, 0);
  assert.equal(res.added.length, 1);
});

test('s. A /// doc comment on the impl header removed after the split: DIFFERENT.', () => {
  const before = [{ path: 'src/foo.rs', source: '/// doc\nimpl S { fn a() {} }', isChild: false }];
  const after = [{ path: 'src/foo/child.rs', source: 'impl S { fn a() {} }', isChild: true }];
  const res = compareItemSets(before, after, { allowDoc: true });
  assert.equal(res.removed.length, 1);
  assert.equal(res.added.length, 0);
});

test('t. Extend nothing in test h; instead add a CLI end-to-end test like h in a temporary git repository...', () => {
  const tmpdir = fs.mkdtempSync(path.join(os.tmpdir(), 'test-move-only-t-'));
  try {
    execFileSync('git', ['init'], { cwd: tmpdir });
    fs.mkdirSync(path.join(tmpdir, 'src'));
    fs.writeFileSync(path.join(tmpdir, 'src/foo.rs'), 'impl S { fn a() {} fn b() { "B" } }');
    execFileSync('git', ['add', '.'], { cwd: tmpdir });
    execFileSync('git', ['-c', 'user.name=test', '-c', 'user.email=test@example.invalid', 'commit', '-m', 'init'], { cwd: tmpdir });
    
    fs.writeFileSync(path.join(tmpdir, 'src/foo.rs'), 'mod child; impl S { fn a() {} }');
    fs.mkdirSync(path.join(tmpdir, 'src/foo'));
    fs.writeFileSync(path.join(tmpdir, 'src/foo/child.rs'), 'use super::*;\nimpl S { fn b() { "B" } }');
    
    const resOk = spawnSync(process.execPath, [checkScript, '--repo', tmpdir, 'HEAD', 'src/foo.rs'], { encoding: 'utf8' });
    assert.equal(resOk.status, 0);
    assert.ok(resOk.stdout.includes('MOVE-ONLY (items): OK'));
    
    fs.writeFileSync(path.join(tmpdir, 'src/foo/child.rs'), 'use super::*;\nimpl S { fn b() { "C" } }');
    const resDiff = spawnSync(process.execPath, [checkScript, '--repo', tmpdir, 'HEAD', 'src/foo.rs'], { encoding: 'utf8' });
    assert.equal(resDiff.status, 1);
    assert.ok(resDiff.stdout.includes('MOVE-ONLY (items): DIFFERENT'));
  } finally {
    fs.rmSync(tmpdir, { recursive: true, force: true });
  }
});

test('u. Before: parent #[cfg(test)] mod tests { use super::*; #[test] fn t() { super::super::X::new(); super::helper(); } }. After: parent #[cfg(test)] mod tests; and child file src/foo/tests.rs use super::*;\\n#[test] fn t() { super::super::X::new(); super::helper(); }: no removed, no added.', () => {
  const before = [
    { path: 'src/foo.rs', source: '#[cfg(test)] mod tests { use super::*; #[test] fn t() { super::super::X::new(); super::helper(); } }', isChild: false }
  ];
  const after = [
    { path: 'src/foo.rs', source: '#[cfg(test)] mod tests;', isChild: false },
    { path: 'src/foo/tests.rs', source: 'use super::*;\n#[test] fn t() { super::super::X::new(); super::helper(); }', isChild: true }
  ];
  const res = compareItemSets(before, after);
  assert.equal(res.removed.length, 0);
  assert.equal(res.added.length, 0);
});

test('v. Same before, but in the child file super::super::X::new() written as super::X::new(): DIFFERENT (one removed, one added).', () => {
  const before = [
    { path: 'src/foo.rs', source: '#[cfg(test)] mod tests { use super::*; #[test] fn t() { super::super::X::new(); super::helper(); } }', isChild: false }
  ];
  const after = [
    { path: 'src/foo.rs', source: '#[cfg(test)] mod tests;', isChild: false },
    { path: 'src/foo/tests.rs', source: 'use super::*;\n#[test] fn t() { super::X::new(); super::helper(); }', isChild: true }
  ];
  const res = compareItemSets(before, after);
  assert.equal(res.removed.length, 1);
  assert.equal(res.added.length, 1);
});

test('w. An inline module moved one level deeper: before parent mod inner { fn f() { super::g(); } }, after child file src/foo/child.rs mod inner { fn f() { super::super::g(); } }: no removed, no added; with super::g() kept unchanged in the child file: DIFFERENT.', () => {
  const before = [
    { path: 'src/foo.rs', source: 'mod inner { fn f() { super::g(); } }', isChild: false }
  ];
  const afterOk = [
    { path: 'src/foo/child.rs', source: 'mod inner { fn f() { super::super::g(); } }', isChild: true }
  ];
  const resOk = compareItemSets(before, afterOk);
  assert.equal(resOk.removed.length, 0);
  assert.equal(resOk.added.length, 0);

  const afterDiff = [
    { path: 'src/foo/child.rs', source: 'mod inner { fn f() { super::g(); } }', isChild: true }
  ];
  const resDiff = compareItemSets(before, afterDiff);
  assert.notEqual(resDiff.removed.length, 0);
  assert.notEqual(resDiff.added.length, 0);
});

test('x. At depth 2 with k = 1 (a path to the child module itself): child file src/foo/child.rs mod inner { fn f() { super::h(); } } compared with itself: no removed, no added; and normalizeItems of that source with isChild true returns one item whose key contains the word __depth_1 and not the word super.', () => {
  const child = [
    { path: 'src/foo/child.rs', source: 'mod inner { fn f() { super::h(); } }', isChild: true }
  ];
  const res = compareItemSets(child, child);
  assert.equal(res.removed.length, 0);
  assert.equal(res.added.length, 0);

  const items = normalizeItems('mod inner { fn f() { super::h(); } }', { isChild: true });
  assert.equal(items.length, 1);
  assert.ok(items[0].key.includes('__depth_1'));
  assert.ok(!items[0].key.includes('super'));
});

test('y. Paths inside comments and string literals are never rewritten: parent mod m { fn f() { "super::x"; } } versus child file mod m { fn f() { "super::x"; } } under the child directory: no removed, no added (the literal is compared byte for byte, so both sides keep super::x inside the string), and parent mod m { fn f() { "super::x"; } } versus parent mod m { fn f() { "self::x"; } }: DIFFERENT.', () => {
  const parent = [
    { path: 'src/foo.rs', source: 'mod m { fn f() { "super::x"; } }', isChild: false }
  ];
  const child = [
    { path: 'src/foo/child.rs', source: 'mod m { fn f() { "super::x"; } }', isChild: true }
  ];
  const resNoDiff = compareItemSets(parent, child);
  assert.equal(resNoDiff.removed.length, 0);
  assert.equal(resNoDiff.added.length, 0);

  const parentSelf = [
    { path: 'src/foo.rs', source: 'mod m { fn f() { "self::x"; } }', isChild: false }
  ];
  const resDiff = compareItemSets(parent, parentSelf);
  assert.notEqual(resDiff.removed.length, 0);
  assert.notEqual(resDiff.added.length, 0);
});

test('z. Extend nothing in test h or t; instead add a CLI end-to-end test like t in a temporary git repository: commit src/foo.rs with fn a() {}\\n#[cfg(test)]\\nmod tests {\\n    use super::*;\\n    #[test]\\n    fn t() { super::super::X::new(); a(); }\\n}\\n, then write src/foo.rs as fn a() {}\\n#[cfg(test)]\\nmod tests;\\n and src/foo/tests.rs as use super::*;\\n#[test]\\nfn t() { super::super::X::new(); a(); }\\n; the CLI exits 0 and prints MOVE-ONLY (items): OK; change super::super::X to super::X in the child and it exits 1 and prints MOVE-ONLY (items): DIFFERENT.', () => {
  const tmpdir = fs.mkdtempSync(path.join(os.tmpdir(), 'test-move-only-z-'));
  try {
    execFileSync('git', ['init'], { cwd: tmpdir });
    fs.mkdirSync(path.join(tmpdir, 'src'));
    fs.writeFileSync(path.join(tmpdir, 'src/foo.rs'), 'fn a() {}\n#[cfg(test)]\nmod tests {\n    use super::*;\n    #[test]\n    fn t() { super::super::X::new(); a(); }\n}\n');
    execFileSync('git', ['add', '.'], { cwd: tmpdir });
    execFileSync('git', ['-c', 'user.name=test', '-c', 'user.email=test@example.invalid', 'commit', '-m', 'init'], { cwd: tmpdir });

    fs.writeFileSync(path.join(tmpdir, 'src/foo.rs'), 'fn a() {}\n#[cfg(test)]\nmod tests;\n');
    fs.mkdirSync(path.join(tmpdir, 'src/foo'));
    fs.writeFileSync(path.join(tmpdir, 'src/foo/tests.rs'), 'use super::*;\n#[test]\nfn t() { super::super::X::new(); a(); }\n');

    const resOk = spawnSync(process.execPath, [checkScript, '--repo', tmpdir, 'HEAD', 'src/foo.rs'], { encoding: 'utf8' });
    assert.equal(resOk.status, 0);
    assert.ok(resOk.stdout.includes('MOVE-ONLY (items): OK'));

    fs.writeFileSync(path.join(tmpdir, 'src/foo/tests.rs'), 'use super::*;\n#[test]\nfn t() { super::X::new(); a(); }\n');
    const resDiff = spawnSync(process.execPath, [checkScript, '--repo', tmpdir, 'HEAD', 'src/foo.rs'], { encoding: 'utf8' });
    assert.equal(resDiff.status, 1);
    assert.ok(resDiff.stdout.includes('MOVE-ONLY (items): DIFFERENT'));
  } finally {
    fs.rmSync(tmpdir, { recursive: true, force: true });
  }
});

test('aa. A backslash-newline continuation line in a string, re-indented by a move: no removed, no added (also for a byte string); a changed character after the continuation, a changed number of spaces before the backslash, an escaped backslash before the newline (the newline is then content) and a re-indented line in a raw string: DIFFERENT.', () => {
  const cmp = (before, after) => compareItemSets(
    [{ path: 'src/foo.rs', source: before, isChild: false }],
    [{ path: 'src/foo/tests.rs', source: after, isChild: true }],
  );
  const same = cmp('fn f() { "a\\n\\\n        b"; }', 'fn f() { "a\\n\\\n    b"; }');
  assert.equal(same.removed.length, 0);
  assert.equal(same.added.length, 0);
  const sameBytes = cmp('fn f() { b"a\\\n        b"; }', 'fn f() { b"a\\\n    b"; }');
  assert.equal(sameBytes.removed.length, 0);
  assert.equal(sameBytes.added.length, 0);
  assert.equal(cmp('fn f() { "a\\n\\\n        b"; }', 'fn f() { "a\\n\\\n    c"; }').removed.length, 1);
  assert.equal(cmp('fn f() { "a \\\n        b"; }', 'fn f() { "a  \\\n    b"; }').removed.length, 1);
  assert.equal(cmp('fn f() { "a\\\\\n        b"; }', 'fn f() { "a\\\\\n    b"; }').removed.length, 1);
  assert.equal(cmp('fn f() { r"a\n        b"; }', 'fn f() { r"a\n    b"; }').removed.length, 1);
  assert.equal(normalizeStringContinuations('"a\\\n  \t b"'), '"a\\\nb"');
  assert.equal(normalizeStringContinuations('r"a\\\n  b"'), 'r"a\\\n  b"');
});

test('ab. A match-arm body block holding one expression, which rustfmt adds or removes when re-indenting: => { x } compares equal to => x, (also as the last arm, before a comma and nested); a block with a statement, a comment or an attribute, and an empty block, stay DIFFERENT from the unwrapped form.', () => {
  const cmp = (before, after) => compareItemSets(
    [{ path: 'src/foo.rs', source: before, isChild: false }],
    [{ path: 'src/foo/tests.rs', source: after, isChild: true }],
  );
  const same = (before, after) => {
    const result = cmp(before, after);
    assert.equal(result.removed.length, 0);
    assert.equal(result.added.length, 0);
  };
  same('fn f(x: u8) -> u8 { match x { 0 => { g(1) } _ => 2, } }', 'fn f(x: u8) -> u8 { match x { 0 => g(1), _ => 2 } }');
  same('fn f(x: u8) -> u8 { match x { 0 => 1, _ => { 2 } } }', 'fn f(x: u8) -> u8 { match x { 0 => 1, _ => 2, } }');
  same('fn f(x: u8) { match x { 0 => { g(1) }, _ => {} } }', 'fn f(x: u8) { match x { 0 => g(1), _ => {} } }');
  same(
    'fn f(x: u8) -> u8 { match x { 0 => { match y { 1 => { 3 } _ => 4 } } _ => 2 } }',
    'fn f(x: u8) -> u8 { match x { 0 => match y { 1 => 3, _ => 4 }, _ => 2 } }',
  );
  const unwrapped = 'fn f(x: u8) -> u8 { match x { 0 => 1, _ => 2 } }';
  assert.equal(cmp('fn f(x: u8) -> u8 { match x { 0 => { g(); 1 } _ => 2 } }', unwrapped).removed.length, 1);
  assert.equal(cmp('fn f(x: u8) -> u8 { match x { 0 => { // one\n 1 } _ => 2 } }', unwrapped).removed.length, 1);
  assert.equal(cmp('fn f(x: u8) -> u8 { match x { 0 => { #[allow(unused)] 1 } _ => 2 } }', unwrapped).removed.length, 1);
  assert.equal(cmp('fn f(x: u8) { match x { 0 => {} _ => {} } }', 'fn f(x: u8) { match x { 0 => (), _ => {} } }').removed.length, 1);
  assert.deepEqual(unwrapArmBlocks(['=', '>', '{', 'x', '}', '_']), ['=', '>', 'x', ',', '_']);
  for (const kept of [['g', '(', ')', ';', 'x'], ['// c\n', 'x'], ['#', '[', 'a', ']', 'x'], []]) {
    assert.deepEqual(unwrapArmBlocks(['=', '>', '{', ...kept, '}']), ['=', '>', '{', ...kept, '}']);
  }
});
