// Checks production root-crate references against the source layer dependency rules.
// Existing forbidden references are baselined: new references and stale baseline entries fail.
// Run node scripts/check-layer-dependencies.mjs --write to record the current baseline for review.

import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';
import { lexRust } from './check-move-only.mjs';

/**
 * Returns the significant Rust tokens, preserving literals as single tokens.
 * @param {Array<{kind: string, text: string}>} tokens
 * @returns {Array<{kind: string, text: string}>}
 */
function significant(tokens) {
  return tokens.filter(token => token.kind !== 'ws' && token.kind !== 'comment');
}

/**
 * Finds the closing delimiter paired with the token at start.
 * @param {Array<{kind: string, text: string}>} tokens
 * @param {number} start
 * @returns {number}
 */
function closingDelimiter(tokens, start) {
  const pairs = { '(': ')', '[': ']', '{': '}' };
  const stack = [];
  for (let i = start; i < tokens.length; i++) {
    const token = tokens[i];
    if (token.kind !== 'punct') continue;
    if (pairs[token.text]) stack.push(pairs[token.text]);
    else if (token.text === stack[stack.length - 1]) {
      stack.pop();
      if (stack.length === 0) return i;
    }
  }
  throw new Error(`unclosed Rust delimiter ${tokens[start]?.text}`);
}

/**
 * Reads one outer or inner attribute, including whether its cfg is test-only.
 * @param {Array<{kind: string, text: string}>} tokens
 * @param {number} start
 * @returns {{end: number, inner: boolean, body: Array, testOnly: boolean}|undefined}
 */
function attributeAt(tokens, start) {
  if (tokens[start]?.text !== '#') return undefined;
  const inner = tokens[start + 1]?.text === '!';
  const open = start + (inner ? 2 : 1);
  if (tokens[open]?.text !== '[') return undefined;
  const end = closingDelimiter(tokens, open) + 1;
  const body = tokens.slice(open + 1, end - 1);
  const words = body.filter(token => token.kind === 'word').map(token => token.text);
  const testOnly = body[0]?.text === 'cfg' && body[1]?.text === '(' &&
    words.includes('test') && !words.includes('not') && !words.includes('any');
  return { end, inner, body, testOnly };
}

/**
 * Checks the initial inner attributes for a test-only file.
 * @param {Array<{kind: string, text: string}>} tokens Significant tokens
 * @returns {boolean}
 */
function testOnlyFile(tokens) {
  let i = 0;
  let attribute;
  while ((attribute = attributeAt(tokens, i)) && attribute.inner) {
    if (attribute.testOnly) return true;
    i = attribute.end;
  }
  return false;
}

/**
 * Skips an annotated item, field, arm or expression, including its terminator.
 * @param {Array<{kind: string, text: string}>} tokens Significant tokens
 * @param {number} start First token after the attributes
 * @returns {number}
 */
function testCodeEnd(tokens, start) {
  let depth = 0;
  let angles = 0;
  let assigned = false;
  for (let i = start; i < tokens.length; i++) {
    if (tokens[i].kind !== 'punct') continue;
    const text = tokens[i].text;
    if (depth === 0 && angles === 0) {
      if (text === ';' || text === ',') return i + 1;
      if (text === '{') return closingDelimiter(tokens, i) + 1;
      if (text === '}') return i;
      if (text === '=') assigned = true;
    }
    if ('([{'.includes(text)) depth++;
    else if (')]}'.includes(text)) depth = Math.max(0, depth - 1);
    else if (!assigned && text === '<') angles++;
    else if (!assigned && text === '>' && !['-', '='].includes(tokens[i - 1]?.text)) {
      angles = Math.max(0, angles - 1);
    }
  }
  return tokens.length;
}

/**
 * Removes test-only code and its attributes, returning significant tokens only.
 * @param {Array<{kind: string, text: string}>} tokens Rust lexer tokens
 * @returns {Array<{kind: string, text: string}>}
 */
export function stripTestCode(tokens) {
  tokens = significant(tokens);
  if (testOnlyFile(tokens)) return [];
  const result = [];
  for (let i = 0; i < tokens.length;) {
    const start = i;
    let testOnly = false;
    let attribute;
    while ((attribute = attributeAt(tokens, i))) {
      testOnly ||= !attribute.inner && attribute.testOnly;
      i = attribute.end;
    }
    if (testOnly) {
      i = testCodeEnd(tokens, i);
    } else {
      result.push(...tokens.slice(start, i));
      if (i < tokens.length) result.push(tokens[i++]);
    }
  }
  return result;
}

/**
 * Reads a module declaration after any visibility qualifier.
 * @param {Array<{kind: string, text: string}>} tokens Significant tokens
 * @param {number} start
 * @returns {{name: string, body: number}|undefined}
 */
function moduleAt(tokens, start) {
  let i = start;
  if (tokens[i]?.text === 'pub') {
    i++;
    if (tokens[i]?.text === '(') i = closingDelimiter(tokens, i) + 1;
  }
  if (tokens[i]?.text === 'mod' && tokens[i + 1]?.kind === 'word' &&
      [';', '{'].includes(tokens[i + 2]?.text)) {
    return { name: tokens[i + 1].text, body: i + 2 };
  }
  return undefined;
}

/**
 * Builds the production module tree by following declarations from src/main.rs.
 * @param {string} root Repository root
 * @returns {Map<string, {modulePath: string[], top: string}>}
 */
export function moduleTree(root) {
  root = path.resolve(root);
  const tree = new Map();

  function visit(file, modulePath, pathLoaded = false) {
    const relative = path.relative(root, file).replace(/\\/g, '/');
    if (tree.has(relative)) return;
    const tokens = significant(lexRust(fs.readFileSync(file, 'utf8')));
    if (testOnlyFile(tokens)) return;
    tree.set(relative, { modulePath, top: modulePath[0] || 'main' });
    const directory = pathLoaded || modulePath.length === 0 || path.basename(file) === 'mod.rs' ?
      path.dirname(file) : file.slice(0, -3);

    function declarations(tokens, directory, modulePath) {
      for (let i = 0; i < tokens.length;) {
        let explicitPath;
        let attribute;
        while ((attribute = attributeAt(tokens, i))) {
          const body = attribute.body;
          if (!attribute.inner && body[0]?.text === 'path' && body[1]?.text === '=' &&
              body[2]?.kind === 'lit') {
            const literal = body[2].text;
            const raw = /^r(#*)"([\s\S]*)"\1$/.exec(literal);
            explicitPath = raw ? raw[2] : JSON.parse(literal);
          }
          i = attribute.end;
        }
        const declaration = moduleAt(tokens, i);
        if (!declaration) {
          i++;
          continue;
        }
        const { name, body } = declaration;
        const childPath = [...modulePath, name];
        if (tokens[body].text === '{') {
          const close = closingDelimiter(tokens, body);
          declarations(tokens.slice(body + 1, close), path.join(directory, name), childPath);
          i = close + 1;
        } else {
          const candidates = explicitPath === undefined ?
            [path.join(directory, `${name}.rs`), path.join(directory, name, 'mod.rs')] :
            [path.resolve(path.dirname(file), explicitPath)];
          const child = candidates.find(candidate => fs.existsSync(candidate) && fs.statSync(candidate).isFile());
          if (!child) throw new Error(`${relative}: declared module ${name} has no file`);
          visit(child, childPath, explicitPath !== undefined);
          i = body + 1;
        }
      }
    }

    declarations(stripTestCode(tokens), directory, modulePath);
  }

  visit(path.join(root, 'src', 'main.rs'), []);
  return new Map([...tree].sort(([a], [b]) => a.localeCompare(b)));
}

/**
 * Finds top-level module names in absolute and root-reaching Rust paths.
 * @param {Array<{kind: string, text: string}>} tokens Stripped Rust tokens
 * @param {string[]} modulePath Module names from the crate root
 * @returns {string[]} Sorted, unique top-level module names
 */
export function crateReferences(tokens, modulePath) {
  tokens = significant(tokens);
  const targets = new Set();

  function targetAt(tokens, start) {
    if (tokens[start]?.text === '{') {
      const close = closingDelimiter(tokens, start);
      let entry = true;
      for (let i = start + 1; i < close; i++) {
        if (entry && tokens[i].kind === 'word' && tokens[i].text !== 'self') {
          targets.add(tokens[i].text);
        }
        entry = tokens[i].text === ',';
        if (['{', '(', '['].includes(tokens[i].text)) i = closingDelimiter(tokens, i);
      }
      return close;
    }
    if (tokens[start]?.kind === 'word' && tokens[start].text !== 'self') {
      targets.add(tokens[start].text);
    }
    return start - 1;
  }

  function scan(tokens, depth) {
    for (let i = 0; i < tokens.length; i++) {
      if (tokens[i].text === 'mod' && tokens[i + 1]?.kind === 'word' && tokens[i + 2]?.text === '{') {
        const close = closingDelimiter(tokens, i + 2);
        scan(tokens.slice(i + 3, close), depth + 1);
        i = close;
        continue;
      }
      if (tokens[i].kind !== 'word' || tokens[i + 1]?.text !== ':' || tokens[i + 2]?.text !== ':') continue;
      if (tokens[i].text === 'crate' && tokens[i - 1]?.text !== '$') {
        i = targetAt(tokens, i + 3);
      } else if (tokens[i].text === 'super') {
        let end = i;
        let count = 0;
        while (tokens[end]?.text === 'super' && tokens[end + 1]?.text === ':' && tokens[end + 2]?.text === ':') {
          count++;
          end += 3;
        }
        i = count === depth ? targetAt(tokens, end) : end - 1;
      }
    }
  }

  scan(tokens, modulePath.length);
  return [...targets].sort();
}

/**
 * Resolves a top-level module alias to its catalog name.
 * @param {string} top
 * @param {object} catalog
 * @returns {string}
 */
function resolveAlias(top, catalog) {
  const seen = new Set();
  while (Object.hasOwn(catalog.aliases || {}, top) && !seen.has(top)) {
    seen.add(top);
    top = catalog.aliases[top];
  }
  return top;
}

/**
 * Returns the layer of a top-level module after resolving aliases.
 * @param {string} top
 * @param {object} catalog
 * @returns {string|undefined}
 */
export function layerOf(top, catalog) {
  top = resolveAlias(top, catalog);
  return Object.entries(catalog.layers).find(([, layer]) => layer.modules.includes(top))?.[0];
}

/**
 * Checks that every module and alias resolves to one layer and that layers only use layers of equal or lower rank.
 * @param {object} catalog
 * @returns {string[]} Errors
 */
export function validateCatalog(catalog) {
  const errors = [];
  const owners = new Map();
  for (const [name, layer] of Object.entries(catalog.layers)) {
    if (!Number.isInteger(layer.rank)) errors.push(`layer ${name}: rank must be an integer`);
    for (const module of layer.modules) {
      if (owners.has(module)) errors.push(`module ${module} is in layers ${owners.get(module)} and ${name}`);
      else owners.set(module, name);
    }
    for (const used of layer.may_use) {
      const target = catalog.layers[used];
      if (!target) errors.push(`layer ${name}: may_use names unknown layer ${used}`);
      else if (target.rank > layer.rank) errors.push(`layer ${name}: may_use ${used} has a higher rank`);
    }
  }
  for (const [alias, module] of Object.entries(catalog.aliases || {})) {
    if (owners.has(alias)) errors.push(`alias ${alias} is also a module of layer ${owners.get(alias)}`);
    if (!owners.has(module)) errors.push(`alias ${alias} names ${module}, which is in no layer`);
  }
  return errors;
}

/**
 * Finds forbidden and unknown production references, one per file and target.
 * @param {Map<string, {modulePath: string[], top: string}>} tree
 * @param {function(string): string} readFile Repository-relative source reader
 * @param {object} catalog
 * @returns {Array<{file: string, target: string, from: string, to?: string, unknown?: boolean}>}
 */
export function findViolations(tree, readFile, catalog) {
  const violations = [];
  for (const [file, { modulePath, top }] of tree) {
    const from = layerOf(top, catalog);
    if (from === undefined) throw new Error(`${file}: module ${top} is not in any layer of catalog/source-layers.json`);
    const tokens = stripTestCode(lexRust(readFile(file)));
    const targets = new Set(crateReferences(tokens, modulePath).map(target => resolveAlias(target, catalog)));
    for (const target of targets) {
      const to = layerOf(target, catalog);
      if (to === undefined) violations.push({ file, target, from, unknown: true });
      else if (from !== to && !catalog.layers[from].may_use.includes(to)) {
        violations.push({ file, target, from, to });
      }
    }
  }
  return violations.sort((a, b) => a.file.localeCompare(b.file) || a.target.localeCompare(b.target));
}

/**
 * Applies the baseline ratchet, rejecting new references and stale allowances.
 * @param {object} params
 * @param {Array<{file: string, target: string, from: string, to?: string, unknown?: boolean}>} params.violations
 * @param {object} params.baseline Repository-relative paths mapped to allowed targets
 * @returns {{errors: string[], baselined: number}}
 */
export function evaluateLayers({ violations, baseline }) {
  const errors = [];
  let baselined = 0;
  const current = new Set();
  for (const { file, target, from, to, unknown } of violations) {
    current.add(`${file}\0${target}`);
    if (unknown) {
      errors.push(`${file}: crate::${target} is not in any layer of catalog/source-layers.json`);
    } else if (baseline[file]?.includes(target)) {
      baselined++;
    } else {
      errors.push(`${file}: layer ${from} must not use crate::${target} (layer ${to}); move the code to a lower layer or use an application port`);
    }
  }
  for (const file of Object.keys(baseline).sort()) {
    for (const target of [...baseline[file]].sort()) {
      if (!current.has(`${file}\0${target}`)) {
        errors.push(`${file}: baseline entry ${target} is no longer needed; remove it from catalog/source-layers.json (run with --write)`);
      }
    }
  }
  return { errors, baselined };
}

// CLI entry point
if (process.argv[1] && import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  let write = false;
  let root = path.resolve(url.fileURLToPath(import.meta.url), '../..');
  let badArgs = false;
  const args = process.argv.slice(2);
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--write') write = true;
    else if (args[i] === '--root' && i + 1 < args.length) root = path.resolve(args[++i]);
    else badArgs = true;
  }
  if (badArgs) {
    console.error('Usage: node scripts/check-layer-dependencies.mjs [--root <dir>] [--write]');
    process.exit(2);
  }

  try {
    const catalogPath = path.join(root, 'catalog', 'source-layers.json');
    const catalog = JSON.parse(fs.readFileSync(catalogPath, 'utf8'));
    const catalogErrors = validateCatalog(catalog);
    if (catalogErrors.length > 0) throw new Error(catalogErrors.map(error => `catalog/source-layers.json: ${error}`).join('\n'));
    const tree = moduleTree(root);
    const violations = findViolations(tree, file => fs.readFileSync(path.join(root, file), 'utf8'), catalog);
    if (write) {
      const baseline = {};
      let count = 0;
      for (const { file, target, unknown } of violations) {
        if (unknown) continue;
        (baseline[file] ||= []).push(target);
        count++;
      }
      catalog.baseline = Object.fromEntries(Object.keys(baseline).sort().map(file => [file, baseline[file].sort()]));
      fs.writeFileSync(catalogPath, JSON.stringify(catalog, null, 2) + '\n');
      console.log(`Wrote ${count} baseline references for ${tree.size} files.`);
      const { errors } = evaluateLayers({ violations: violations.filter(violation => violation.unknown), baseline: {} });
      for (const error of errors) console.error(error);
      process.exit(errors.length > 0 ? 1 : 0);
    }
    const { errors, baselined } = evaluateLayers({ violations, baseline: catalog.baseline });
    for (const error of errors) console.error(error);
    if (errors.length > 0) process.exit(1);
    console.log(`Layer dependencies: ${tree.size} production files checked, ${baselined} baselined references, 0 new.`);
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}
