#!/usr/bin/env node
// Item-level move-only verification for splitting a Rust module into children.
//
// Usage: node scripts/check-move-only.mjs [--repo <dir>] [--allow-doc] [--after-rev <rev>] <base-rev> <module.rs>
//
// Compares the multiset of normalized top-level items of <module.rs> plus every
// .rs file under its child directory at <base-rev> with the working tree.
//   * `use` items and bodyless `mod x;` items are dropped;
//   * inline `mod x { ... }` items are expanded into their inner items;
//   * inherent impl blocks (like `impl S { ... }`) are expanded into their members,
//     keyed by the normalized impl header; trait impls stay whole; impl header
//     comments are compared as their own item;
//   * visibility qualifiers are removed;
//   * module depth is 0 outside the child directory, 1 under the child directory,
//     plus 1 for each enclosing inline `mod x { ... }` block; a maximal run of
//     k leading `super::` pairs is mapped to level L = depth - k: L < 0 maps to
//     `super::` repeated -L times, L = 0 maps to `self::`, and L > 0 maps to
//     `self::__depth_L::`;
//   * whitespace outside literals is removed and a trailing comma before a
//     closing delimiter is dropped (rustfmt reflow); string and char literal
//     contents are compared byte for byte, except that in a non-raw string the
//     whitespace after a backslash-newline continuation is dropped, as rustc
//     drops it from the value (a re-indented continuation line is the same string);
//   * the path literal of `include_str!`/`include_bytes!` is compared as the
//     repository path it resolves to from the containing file, so an item moved
//     to another directory may adjust its relative include path but must read
//     the same file;
//   * a match-arm body block holding a single expression is unwrapped
//     (`=> { x }` compares equal to `=> x,`): rustfmt adds or removes that block
//     when re-indenting changes the line width; a block with a top-level `;`,
//     a comment or a leading attribute is kept;
//   * --allow-doc drops `//!` inner doc comments (new child-module headers).
//   * comment-only remainders (e.g. trailing comments after the last item in a
//     file or impl body) are compared as their own item.

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { repositoryRoot } from './lib/source-module.mjs';

// ---- lexer ---------------------------------------------------------------
// Returns tokens {kind, text}: kind in ws | comment | lit | punct | word.
export function lexRust(src) {
  const out = [];
  let i = 0;
  const push = (kind, end) => { out.push({ kind, text: src.slice(i, end) }); i = end; };
  while (i < src.length) {
    const c = src[i];
    if (/\s/.test(c)) { let j = i; while (j < src.length && /\s/.test(src[j])) j++; push('ws', j); continue; }
    if (src.startsWith('//', i)) { let j = src.indexOf('\n', i); if (j < 0) j = src.length; push('comment', j); continue; }
    if (src.startsWith('/*', i)) {
      let j = i + 2, depth = 1;
      while (j < src.length && depth > 0) {
        if (src.startsWith('/*', j)) { depth++; j += 2; } else if (src.startsWith('*/', j)) { depth--; j += 2; } else j++;
      }
      push('comment', j); continue;
    }
    const raw = /^(?:br|rb|r)(#*)"/.exec(src.slice(i, i + 300));
    if (raw && !/[A-Za-z0-9_]/.test(src[i - 1] ?? '')) {
      const term = '"' + raw[1];
      const j = src.indexOf(term, i + raw[0].length);
      if (j < 0) throw new Error('unterminated raw string');
      push('lit', j + term.length); continue;
    }
    if (c === '"' || (src.startsWith('b"', i) && !/[A-Za-z0-9_]/.test(src[i - 1] ?? ''))) {
      let j = i + (c === '"' ? 1 : 2), esc = false;
      while (j < src.length) { const d = src[j++]; if (esc) esc = false; else if (d === '\\') esc = true; else if (d === '"') break; }
      push('lit', j); continue;
    }
    if (c === "'" || (src.startsWith("b'", i) && !/[A-Za-z0-9_]/.test(src[i - 1] ?? ''))) {
      let j = i + (c === "'" ? 1 : 2);
      if (src[j] === '\\') {
        j += 2;
        if (src[j - 1] === 'u' && src[j] === '{') j = src.indexOf('}', j) + 1;
        else if (src[j - 1] === 'x') j += 2;
      } else {
        const cp = src.codePointAt(j); j += cp > 0xffff ? 2 : 1;
      }
      if (src[j] === "'") { push('lit', j + 1); continue; }
      // lifetime or label: fall through as punct + word
    }
    if (/[A-Za-z0-9_]/.test(c)) { let j = i; while (j < src.length && /[A-Za-z0-9_]/.test(src[j])) j++; push('word', j); continue; }
    push('punct', i + 1);
  }
  return out;
}

// A backslash at the end of a line inside a non-raw string or byte string skips the
// newline and the whitespace (space, tab, CR, LF) at the start of the next line, so
// re-indenting such a continuation line does not change the value. Other literals
// are returned unchanged.
export function normalizeStringContinuations(lit) {
  if (!(lit.startsWith('"') || lit.startsWith('b"'))) return lit;
  let out = '';
  for (let i = 0; i < lit.length; i++) {
    const c = lit[i];
    if (c !== '\\') { out += c; continue; }
    const next = lit[i + 1];
    if (next === '\n' || next === '\r') {
      let j = i + 1;
      while (j < lit.length && ' \t\r\n'.includes(lit[j])) j++;
      out += '\\\n';
      i = j - 1;
    } else {
      out += c + (next ?? '');
      i++;
    }
  }
  return out;
}

// rustfmt wraps a match-arm body in a block when it no longer fits on the arm's
// line and unwraps a block holding a single expression when it fits, so moving
// code to another indentation can switch between `=> { x }` and `=> x,`. Both
// evaluate x as the arm body. Unwrap such blocks in a normalized token list
// (comments are entries ending in a newline); keep blocks with a top-level `;`,
// a comment or a leading attribute, and empty blocks.
export function unwrapArmBlocks(parts) {
  const out = [...parts];
  for (let i = 0; i + 2 < out.length; i++) {
    if (out[i] !== '=' || out[i + 1] !== '>' || out[i + 2] !== '{') continue;
    let depth = 0, close = -1, single = true;
    for (let j = i + 2; j < out.length; j++) {
      const p = out[j];
      if (p === '(' || p === '[' || p === '{') depth++;
      else if ((p === ')' || p === ']' || p === '}') && --depth === 0) { close = j; break; }
      else if (p === ';' && depth === 1) single = false;
      if (p.endsWith('\n')) single = false;
    }
    if (close < 0 || close === i + 3 || !single || out[i + 3] === '#') continue;
    const body = out.slice(i + 3, close);
    out.splice(i + 2, close - i - 1, ...body, ...(out[close + 1] === ',' ? [] : [',']));
  }
  return out;
}

// ---- top-level item splitting --------------------------------------------
function splitItems(tokens) {
  const items = [];
  let cur = [], depth = 0;
  const significant = (t) => t.kind !== 'ws' && t.kind !== 'comment';
  for (let k = 0; k < tokens.length; k++) {
    const t = tokens[k];
    cur.push(t);
    if (t.kind !== 'punct') continue;
    if ('([{'.includes(t.text)) depth++;
    else if (')]}'.includes(t.text)) {
      depth--;
      if (depth === 0 && t.text === '}') {
        let n = k + 1; while (n < tokens.length && !significant(tokens[n])) n++;
        if (n < tokens.length && tokens[n].text === ';') continue;
        items.push(cur); cur = [];
      }
    } else if (t.text === ';' && depth === 0) { items.push(cur); cur = []; }
  }
  if (cur.some(significant)) items.push(cur);
  else if (cur.some(t => t.kind === 'comment')) items.push(cur);
  return items;
}

function sig(toks) { return toks.filter((t) => t.kind !== 'ws' && t.kind !== 'comment'); }
function stripAttrs(toks) {
  const s = sig(toks); let k = 0;
  while (s[k]?.text === '#' ) {
    let j = k + 1; if (s[j]?.text === '!') j++;
    if (s[j]?.text !== '[') break;
    let d = 0;
    for (; j < s.length; j++) { if (s[j].text === '[') d++; else if (s[j].text === ']' && --d === 0) break; }
    k = j + 1;
  }
  return s.slice(k);
}
function stripVis(s) {
  if (s[0]?.text !== 'pub') return s;
  if (s[1]?.text === '(') { let j = 1, d = 0; for (; j < s.length; j++) { if (s[j].text === '(') d++; else if (s[j].text === ')' && --d === 0) break; } return s.slice(j + 1); }
  return s.slice(1);
}

export function normalizeItems(source, { isChild = false, allowDoc = false, filePath } = {}) {
  const result = [];

  const normalizeTokenList = (item, depth) => {
    let visibility = [];
    let parts = [];
    for (let k = 0; k < item.length; k++) {
      const t = item[k];
      if (t.kind === 'ws') continue;
      if (t.kind === 'comment') {
        if (allowDoc && t.text.startsWith('//!')) continue;
        parts.push(t.text.replace(/\s+/g, ' ').trim() + '\n');
        continue;
      }
      if (t.kind === 'word' && t.text === 'pub') {
        let j = k + 1; while (item[j]?.kind === 'ws') j++;
        let visTokens = [t.text];
        if (item[j]?.text === '(') {
          let d = 0; 
          for (; j < item.length; j++) { 
            if (item[j].kind !== 'ws' && item[j].kind !== 'comment') {
              visTokens.push(item[j].text);
            }
            if (item[j].text === '(') d++; 
            else if (item[j].text === ')' && --d === 0) break; 
          }
          k = j;
        }
        let visStr = '';
        for (let v of visTokens) {
          if (v === 'in') visStr += v + ' ';
          else visStr += v;
        }
        visibility.push(visStr.trim());
        continue;
      }
      parts.push(t.kind === 'lit' ? normalizeStringContinuations(t.text) : t.text);
    }
    let s = unwrapArmBlocks(parts).join('\u0001');
    s = s.replace(/(^|\u0001)(super\u0001:\u0001:(?:\u0001super\u0001:\u0001:)*)/g, (match, prefix, run) => {
      const k = (run.match(/super\u0001:\u0001:/g) || []).length;
      const L = depth - k;
      let rep;
      if (L < 0) {
        rep = Array(-L).fill('super\u0001:\u0001:').join('\u0001');
      } else if (L === 0) {
        rep = 'self\u0001:\u0001:';
      } else {
        rep = `self\u0001:\u0001:\u0001__depth_${L}\u0001:\u0001:`;
      }
      return prefix + rep;
    });
    s = s.replace(/\u0001,\u0001(?=[)\]}])/g, '\u0001');
    
    const show = (str) => str.replace(/\u0001/g, ' ').replace(/\n /g, '\n').slice(0, 220);
    return { key: s, visibility, excerpt: show(s) };
  };

  const visit = (tokens, depth = (isChild ? 1 : 0)) => {
    for (const item of splitItems(tokens)) {
      const head = stripVis(stripAttrs(item));
      if (head[0]?.text === 'use') continue;
      if (head[0]?.text === 'mod' && head[2]?.text === ';') continue;
      if (head[0]?.text === 'mod' && head[2]?.text === '{') {
        const open = item.indexOf(head[2]);
        let d = 0, close = -1;
        for (let j = open; j < item.length; j++) {
          if (item[j].kind !== 'punct') continue;
          if ('([{'.includes(item[j].text)) d++;
          else if (')]}'.includes(item[j].text) && --d === 0) { close = j; break; }
        }
        visit(item.slice(open + 1, close), depth + 1);
        continue;
      }
      
      if (head[0]?.text === 'impl') {
        let bodyOpen = -1;
        let braceDepth = 0;
        for (let j = item.length - 1; j >= 0; j--) {
          if (item[j].kind === 'punct') {
            if (item[j].text === '}') braceDepth++;
            else if (item[j].text === '{') {
              braceDepth--;
              if (braceDepth === 0) { bodyOpen = j; break; }
            }
          }
        }
        
        if (bodyOpen !== -1) {
          const headerTokens = item.slice(0, bodyOpen);
          const bodyTokens = item.slice(bodyOpen + 1, item.length - 1);
          
          const sigTokens = headerTokens.filter(t => t.kind !== 'ws' && t.kind !== 'comment');
          let implIdx = sigTokens.findIndex(t => t.text === 'impl');
          let angleDepth = 0;
          let parenDepth = 0;
          let isTraitImpl = false;
          let prevSigToken = null;
          for (let j = implIdx + 1; j < sigTokens.length; j++) {
            const t = sigTokens[j];
            if (t.kind === 'punct') {
              if (t.text === '<') angleDepth++;
              else if (t.text === '>') {
                if (prevSigToken?.text !== '-') angleDepth--;
              } else if (t.text === '(' || t.text === '[') parenDepth++;
              else if (t.text === ')' || t.text === ']') parenDepth--;
            } else if (t.kind === 'word') {
              if (angleDepth === 0 && parenDepth === 0) {
                if (t.text === 'for') { isTraitImpl = true; break; }
                if (t.text === 'where') { break; }
              }
            }
            prevSigToken = t;
          }
          
          if (!isTraitImpl) {
            const headerWithoutComments = headerTokens.filter(t => t.kind !== 'comment');
            const headerNorm = normalizeTokenList(headerWithoutComments, depth);
            const headerComments = headerTokens.filter(t => t.kind === 'comment');
            
            if (headerComments.length > 0) {
              const commentNorm = normalizeTokenList(headerComments, depth);
              if (commentNorm.key) {
                result.push({
                  key: headerNorm.key + '\u0003' + commentNorm.key,
                  visibility: [],
                  excerpt: commentNorm.excerpt
                });
              }
            }
            
            for (const memberItem of splitItems(bodyTokens)) {
              const memberNorm = normalizeTokenList(memberItem, depth);
              if (memberNorm.key) {
                result.push({
                  key: headerNorm.key + '\u0003' + memberNorm.key,
                  visibility: memberNorm.visibility,
                  excerpt: (headerNorm.excerpt + ' :: ' + memberNorm.excerpt).slice(0, 220)
                });
              }
            }
            continue;
          }
        }
      }
      
      const norm = normalizeTokenList(item, depth);
      if (norm.key) result.push(norm);
    }
  };
  const tokens = lexRust(source);
  if (filePath !== undefined) {
    const s = sig(tokens);
    for (let k = 3; k < s.length; k++) {
      const t = s[k];
      if (t.kind !== 'lit' || !/^"[^"\\]*"$/.test(t.text)) continue;
      if (!['include_str', 'include_bytes'].includes(s[k - 3].text) ||
          s[k - 2].text !== '!' || s[k - 1].text !== '(') continue;
      t.text = 'include-path:' + path.posix.normalize(path.posix.join(path.posix.dirname(filePath), t.text.slice(1, -1)));
    }
  }
  visit(tokens, isChild ? 1 : 0);
  return result;
}

export function compareItemSets(beforeFiles, afterFiles, { allowDoc = false } = {}) {
  const before = new Map();
  const after = new Map();
  
  let beforeCount = 0;
  let afterCount = 0;

  for (const f of beforeFiles) {
    const items = normalizeItems(f.source, { isChild: f.isChild, allowDoc, filePath: f.path });
    for (const item of items) {
      if (!before.has(item.key)) before.set(item.key, []);
      before.get(item.key).push(item);
      beforeCount++;
    }
  }

  for (const f of afterFiles) {
    const items = normalizeItems(f.source, { isChild: f.isChild, allowDoc, filePath: f.path });
    for (const item of items) {
      if (!after.has(item.key)) after.set(item.key, []);
      after.get(item.key).push(item);
      afterCount++;
    }
  }

  const removed = [];
  const added = [];
  const visibilityChanges = [];

  for (const [s, items] of before) {
    const afterItems = after.get(s) || [];
    const d = items.length - afterItems.length;
    if (d > 0) {
      for (let i = 0; i < d; i++) removed.push(items[0].excerpt);
    }
  }

  for (const [s, items] of after) {
    const beforeItems = before.get(s) || [];
    const d = items.length - beforeItems.length;
    if (d > 0) {
      for (let i = 0; i < d; i++) added.push(items[0].excerpt);
    }
  }

  const keys = new Set([...before.keys(), ...after.keys()]);
  const sortedKeys = Array.from(keys);
  for (const key of sortedKeys) {
    const bItems = before.get(key) || [];
    const aItems = after.get(key) || [];
    if (bItems.length > 0 && bItems.length === aItems.length) {
      const bVis = bItems.map(i => i.visibility).sort((a, b) => a.join(',').localeCompare(b.join(',')));
      const aVis = aItems.map(i => i.visibility).sort((a, b) => a.join(',').localeCompare(b.join(',')));
      for (let i = 0; i < bVis.length; i++) {
        const bSig = bVis[i];
        const aSig = aVis[i];
        if (bSig.join(',') !== aSig.join(',')) {
          visibilityChanges.push({
            excerpt: bItems[0].excerpt,
            before: bSig,
            after: aSig
          });
        }
      }
    }
  }

  return { beforeCount, afterCount, removed, added, visibilityChanges };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const args = process.argv.slice(2);
    let repo = repositoryRoot;
    let allowDoc = false;
    let afterRev = null;
    
    let positional = [];
    for (let i = 0; i < args.length; i++) {
      if (args[i] === '--repo') {
        if (i + 1 >= args.length) {
          process.stderr.write('Usage: node scripts/check-move-only.mjs [--repo <dir>] [--allow-doc] [--after-rev <rev>] <base-rev> <module.rs>\n');
          process.exit(2);
        }
        repo = args[++i];
      } else if (args[i] === '--allow-doc') {
        allowDoc = true;
      } else if (args[i] === '--after-rev') {
        if (i + 1 >= args.length) {
          process.stderr.write('Usage: node scripts/check-move-only.mjs [--repo <dir>] [--allow-doc] [--after-rev <rev>] <base-rev> <module.rs>\n');
          process.exit(2);
        }
        afterRev = args[++i];
      } else {
        positional.push(args[i]);
      }
    }

    if (positional.length !== 2) {
      process.stderr.write('Usage: node scripts/check-move-only.mjs [--repo <dir>] [--allow-doc] [--after-rev <rev>] <base-rev> <module.rs>\n');
      process.exit(2);
    }

    const [rev, modulePath] = positional;
    if (path.isAbsolute(modulePath)) {
      process.stderr.write('Error: absolute paths rejected\n');
      process.exit(2);
    }
    if (modulePath.split(/[/\\]/).includes('..')) {
      process.stderr.write('Error: .. segments rejected\n');
      process.exit(2);
    }
    if (!modulePath.endsWith('.rs')) {
      process.stderr.write('Error: must end with .rs\n');
      process.exit(2);
    }

    // `a/b.rs` keeps its children in `a/b/`, `a/mod.rs` in `a/` next to itself.
    const childDir = modulePath.endsWith('/mod.rs') ? modulePath.slice(0, -'/mod.rs'.length) : modulePath.replace(/\.rs$/, '');

    let beforePaths = [];
    try {
      const out = execFileSync('git', ['-C', repo, 'ls-tree', '-r', '--name-only', rev, '--', modulePath, childDir], { encoding: 'utf8' });
      beforePaths = out.split('\n').filter(p => p.endsWith('.rs'));
    } catch (err) {
      process.stderr.write(err.message + '\n');
      process.exit(2);
    }
    if (!beforePaths.includes(modulePath)) {
      process.stderr.write(`Error: ${modulePath} does not exist at ${rev}\n`);
      process.exit(2);
    }

    const beforeFiles = beforePaths.map(p => {
      const source = execFileSync('git', ['-C', repo, 'show', `${rev}:${p}`], { encoding: 'utf8', maxBuffer: 1 << 28 });
      return { path: p, source, isChild: p !== modulePath };
    });

    let afterPaths = [];
    let afterFiles = [];
    
    if (afterRev) {
      try {
        const out = execFileSync('git', ['-C', repo, 'ls-tree', '-r', '--name-only', afterRev, '--', modulePath, childDir], { encoding: 'utf8' });
        afterPaths = out.split('\n').filter(p => p.endsWith('.rs'));
      } catch (err) {
        process.stderr.write(err.message + '\n');
        process.exit(2);
      }
      if (!afterPaths.includes(modulePath)) {
        process.stderr.write(`Error: ${modulePath} does not exist at ${afterRev}\n`);
        process.exit(2);
      }
      afterFiles = afterPaths.map(p => {
        const source = execFileSync('git', ['-C', repo, 'show', `${afterRev}:${p}`], { encoding: 'utf8', maxBuffer: 1 << 28 });
        return { path: p, source, isChild: p !== modulePath };
      });
    } else {
      if (fs.existsSync(path.join(repo, modulePath))) {
        afterPaths.push(modulePath);
      } else {
        process.stderr.write(`Error: ${modulePath} does not exist at working tree\n`);
        process.exit(2);
      }
      const walk = (d) => {
        if (!fs.existsSync(path.join(repo, d))) return;
        for (const e of fs.readdirSync(path.join(repo, d), { withFileTypes: true })) {
          const p = `${d}/${e.name}`;
          if (e.isDirectory()) walk(p);
          else if (e.name.endsWith('.rs') && p !== modulePath) afterPaths.push(p);
        }
      };
      walk(childDir);
      afterPaths.sort();

      afterFiles = afterPaths.map(p => {
        const source = fs.readFileSync(path.join(repo, p), 'utf8');
        return { path: p, source, isChild: p !== modulePath };
      });
    }

    const result = compareItemSets(beforeFiles, afterFiles, { allowDoc });
    
    console.log(`before: ${beforeFiles.length} files, ${result.beforeCount} items`);
    console.log(`after:  ${afterFiles.length} files, ${result.afterCount} items`);

    if (result.removed.length === 0 && result.added.length === 0) {
      console.log('MOVE-ONLY (items): OK');
      for (const vc of result.visibilityChanges) {
        console.log(`VISIBILITY: ${vc.excerpt.slice(0, 100)}: [${vc.before.join(', ')}] -> [${vc.after.join(', ')}]`);
      }
      process.exit(0);
    } else {
      console.log(`MOVE-ONLY (items): DIFFERENT (removed ${result.removed.length}, added ${result.added.length})`);
      const diffs = [];
      for (const r of result.removed) diffs.push(['-', r]);
      for (const a of result.added) diffs.push(['+', a]);
      for (const [sign, s] of diffs.slice(0, 40)) {
        console.log(`${sign} ${s}\n`);
      }
      for (const vc of result.visibilityChanges) {
        console.log(`VISIBILITY: ${vc.excerpt.slice(0, 100)}: [${vc.before.join(', ')}] -> [${vc.after.join(', ')}]`);
      }
      process.exit(1);
    }
  } catch (err) {
    process.stderr.write(err.message + '\n');
    process.exit(2);
  }
}
