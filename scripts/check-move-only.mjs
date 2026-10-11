#!/usr/bin/env node
// Item-level move-only verification for splitting a Rust module into children.
//
// Usage: node scripts/check-move-only.mjs [--repo <dir>] [--allow-doc] [--after-rev <rev>] <base-rev> <module.rs>
//
// Compares the multiset of normalized top-level items of <module.rs> plus every
// .rs file under its child directory at <base-rev> with the working tree.
//   * `use` items and bodyless `mod x;` items are dropped;
//   * inline `mod x { ... }` items are expanded into their inner items;
//   * visibility qualifiers are removed;
//   * in files under the child directory `super::super::` maps to `super::`
//     and `super::` maps to `self::` (code moved one level down must reach
//     one level further up, and `self::x` in the parent becomes `super::x`);
//   * whitespace outside literals is removed and a trailing comma before a
//     closing delimiter is dropped (rustfmt reflow); string and char literal
//     contents are compared byte for byte;
//   * --allow-doc drops `//!` inner doc comments (new child-module headers).

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

export function normalizeItems(source, { isChild = false, allowDoc = false } = {}) {
  const result = [];
  const visit = (tokens) => {
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
        visit(item.slice(open + 1, close));
        continue;
      }
      
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
        parts.push(t.text);
      }
      let s = parts.join('\u0001');
      if (isChild) {
        s = s.replace(/(^|\u0001)super\u0001:\u0001:\u0001super\u0001:\u0001:/g, '$1\u0002');
        s = s.replace(/(^|\u0001)super\u0001:\u0001:/g, '$1self\u0001:\u0001:');
        s = s.replace(/\u0002/g, 'super\u0001:\u0001:');
      }
      s = s.replace(/\u0001,\u0001(?=[)\]}])/g, '\u0001');
      
      const show = (str) => str.replace(/\u0001/g, ' ').replace(/\n /g, '\n').slice(0, 220);
      result.push({ key: s, visibility, excerpt: show(s) });
    }
  };
  visit(lexRust(source));
  return result;
}

export function compareItemSets(beforeFiles, afterFiles, { allowDoc = false } = {}) {
  const before = new Map();
  const after = new Map();
  
  let beforeCount = 0;
  let afterCount = 0;

  for (const f of beforeFiles) {
    const items = normalizeItems(f.source, { isChild: f.isChild, allowDoc });
    for (const item of items) {
      if (!before.has(item.key)) before.set(item.key, []);
      before.get(item.key).push(item);
      beforeCount++;
    }
  }

  for (const f of afterFiles) {
    const items = normalizeItems(f.source, { isChild: f.isChild, allowDoc });
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

    const childDir = modulePath.replace(/\.rs$/, '');

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
          else if (e.name.endsWith('.rs')) afterPaths.push(p);
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
