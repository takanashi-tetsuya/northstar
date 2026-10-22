import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';
import { validateRoleSplits } from './lib/source-module.mjs';

/**
 * Classify a source file as 'test' or 'production'.
 * @param {string} p Repository-relative path to classify
 * @returns {'test'|'production'}
 */
export function classify(p) {
  const parts = p.split('/');
  const basename = parts[parts.length - 1];
  
  if (parts.includes('tests')) {
    return 'test';
  }
  if (basename.startsWith('test_')) {
    return 'test';
  }
  if (/(^|_)tests?(_[a-z0-9_]+)?\.rs$/.test(basename)) {
    return 'test';
  }
  
  return 'production';
}

/**
 * Counts the top-level inline test modules of a Rust file: a `mod name {` line without indentation
 * whose attributes include #[cfg(test)]. An oversize production file moves such modules into child
 * files (R1, WP-71), so only its production code counts against the budget.
 * @param {string} text Rust source
 * @returns {number}
 */
export function countInlineTestModules(text) {
  const lines = text.split('\n');
  let count = 0;
  for (let i = 0; i < lines.length; i++) {
    if (!/^(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{/.test(lines[i])) {
      continue;
    }
    for (let j = i - 1; j >= 0 && lines[j].startsWith('#['); j--) {
      if (/^#\[cfg\((?:all\()?test\b/.test(lines[j])) {
        count++;
        break;
      }
    }
  }
  return count;
}

/**
 * Scans the source directory and returns files with line counts and inline test modules.
 * @param {string} root
 * @returns {Array<{path: string, lines: number, inlineTestModules: number}>}
 */
export function scanSource(root) {
  root = path.resolve(root);
  const srcDir = path.join(root, 'src');
  const results = [];

  function walk(dir) {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      return;
    }
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile() && entry.name.endsWith('.rs')) {
        const buf = fs.readFileSync(fullPath);
        let lines = 0;
        for (let i = 0; i < buf.length; i++) {
          if (buf[i] === 10) lines++;
        }
        const relPath = path.relative(root, fullPath).replace(/\\/g, '/');
        const text = buf.toString('utf8');
        results.push({
          path: relPath,
          lines,
          inlineTestModules: countInlineTestModules(text),
        });
      }
    }
  }

  walk(srcDir);
  results.sort((a, b) => a.path.localeCompare(b.path));
  return results;
}

/**
 * Evaluates the current source files against the baseline.
 * @param {object} params
 * @param {Array<{path: string, lines: number}>} params.files
 * @param {object} params.baseline
 * @returns {{violations: string[], notices: string[]}}
 */
export function evaluateStructure({ files, baseline }) {
  const violations = [];
  const notices = [];

  const isPlainObject = (obj) => obj && typeof obj === 'object' && !Array.isArray(obj);
  let invalidBaseline = false;
  
  if (
    baseline.schema !== "northstar-source-structure-baseline-v1" ||
    !isPlainObject(baseline.budgets) ||
    !Number.isInteger(baseline.budgets.production) || baseline.budgets.production <= 0 ||
    !Number.isInteger(baseline.budgets.test) || baseline.budgets.test <= 0 ||
    (baseline.oversize !== undefined && !isPlainObject(baseline.oversize)) ||
    (baseline.root_rust_files !== undefined && !Array.isArray(baseline.root_rust_files)) ||
    baseline.pinned !== undefined
  ) {
    invalidBaseline = true;
  } else {
    for (const val of Object.values(baseline.oversize || {})) {
      if (!Number.isInteger(val) || val <= 0) {
        invalidBaseline = true;
        break;
      }
    }
    for (const val of (baseline.root_rust_files || [])) {
      if (typeof val !== 'string') {
        invalidBaseline = true;
        break;
      }
    }
  }

  if (invalidBaseline) {
    violations.push("catalog/source-structure-baseline.json: invalid schema or budgets");
    return { violations, notices };
  }

  const oversize = baseline.oversize || {};
  const root_rust_files = baseline.root_rust_files || [];
  
  const currentFiles = new Map(files.map(f => [f.path, f.lines]));
  
  for (const { path, lines, inlineTestModules = 0 } of files) {
    const cls = classify(path);
    const budget = baseline.budgets[cls];
    
    if (lines > budget) {
      if (!(path in oversize)) {
        violations.push(`${path}: new oversize file`);
      } else if (lines > oversize[path]) {
        violations.push(`${path}: grew from ${oversize[path]} to ${lines} lines`);
      }
      if (cls === 'production' && inlineTestModules > 0) {
        violations.push(`${path}: oversize file keeps ${inlineTestModules} inline test module(s); move them into child files (R1)`);
      }
    }
    
    if (path.startsWith('src/') && path.indexOf('/', 4) === -1) {
      if (!root_rust_files.includes(path)) {
        violations.push(`${path}: new root source file`);
      }
    }
  }

  for (const [path, recordedLines] of Object.entries(oversize)) {
    if (!currentFiles.has(path)) {
      notices.push(`${path}: no longer exists. Run with --update to lower baseline.`);
    } else {
      const currentLines = currentFiles.get(path);
      const budget = baseline.budgets[classify(path)];
      if (currentLines < recordedLines || currentLines <= budget) {
        notices.push(`${path}: shrank or is within budget. Run with --update to lower baseline.`);
      }
    }
  }

  for (const path of root_rust_files) {
    if (!currentFiles.has(path)) {
      notices.push(`${path}: listed root file no longer exists. Run with --update to lower baseline.`);
    }
  }

  return { violations, notices };
}

/**
 * Builds a new baseline object from the given files.
 * @param {Array<{path: string, lines: number}>} files 
 * @param {{production: number, test: number}} budgets 
 * @returns {object}
 */
export function buildBaseline(files, budgets = { production: 1500, test: 3000 }) {
  const oversize = {};
  const root_rust_files = [];

  for (const { path, lines } of files) {
    const cls = classify(path);
    const budget = budgets[cls];
    if (lines > budget) {
      oversize[path] = lines;
    }
    if (path.startsWith('src/') && path.indexOf('/', 4) === -1) {
      root_rust_files.push(path);
    }
  }

  return {
    schema: "northstar-source-structure-baseline-v1",
    budgets,
    oversize: Object.fromEntries(Object.entries(oversize).sort()),
    root_rust_files: root_rust_files.sort()
  };
}

/**
 * Lowers an existing baseline based on the current files.
 * @param {object} params
 * @param {Array<{path: string, lines: number}>} params.files
 * @param {object} params.baseline
 * @returns {{baseline: object, changed: boolean}}
 */
export function lowerBaseline({ files, baseline }) {
  const newBaseline = JSON.parse(JSON.stringify(baseline));
  let changed = false;

  const currentFiles = new Map(files.map(f => [f.path, f.lines]));

  for (const path of Object.keys(newBaseline.oversize || {})) {
    if (!currentFiles.has(path)) {
      delete newBaseline.oversize[path];
      changed = true;
    } else {
      const currentLines = currentFiles.get(path);
      const cls = classify(path);
      const budget = newBaseline.budgets[cls];
      if (currentLines <= budget) {
        delete newBaseline.oversize[path];
        changed = true;
      } else if (currentLines < newBaseline.oversize[path]) {
        newBaseline.oversize[path] = currentLines;
        changed = true;
      }
    }
  }

  if (newBaseline.root_rust_files) {
    const newRootFiles = newBaseline.root_rust_files.filter(path => {
      const exists = currentFiles.has(path);
      if (!exists) changed = true;
      return exists;
    });
    if (newBaseline.root_rust_files.length !== newRootFiles.length) {
      changed = true;
      newBaseline.root_rust_files = newRootFiles;
    }
  }

  if (changed) {
    newBaseline.oversize = Object.fromEntries(Object.entries(newBaseline.oversize || {}).sort());
    newBaseline.root_rust_files = (newBaseline.root_rust_files || []).sort();
  }

  return { baseline: newBaseline, changed };
}

// CLI entry point
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  let update = false;
  let init = false;
  let force = false;
  let root = path.resolve(process.argv[1], '../..');
  let badArgs = false;

  const args = process.argv.slice(2);
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--update') update = true;
    else if (args[i] === '--init') init = true;
    else if (args[i] === '--force') force = true;
    else if (args[i] === '--root' && i + 1 < args.length) {
      root = path.resolve(args[++i]);
    }
    else {
      badArgs = true;
    }
  }

  if (badArgs || (init && update)) {
    console.error(`Usage: node scripts/check-source-structure.mjs [--update] [--init] [--force] [--root <dir>]`);
    process.exit(2);
  }

  const baselinePath = path.join(root, 'catalog', 'source-structure-baseline.json');
  const files = scanSource(root);

  if (init) {
    if (fs.existsSync(baselinePath) && !force) {
      console.error(`error: baseline already exists at ${baselinePath}`);
      process.exit(1);
    }
    const baseline = buildBaseline(files);
    fs.mkdirSync(path.dirname(baselinePath), { recursive: true });
    
    const sortedBaseline = {
      schema: baseline.schema,
      budgets: baseline.budgets,
      oversize: baseline.oversize,
      root_rust_files: baseline.root_rust_files
    };
    fs.writeFileSync(baselinePath, JSON.stringify(sortedBaseline, null, 2) + '\n');
    process.exit(0);
  }

  let baselineRaw;
  try {
    baselineRaw = fs.readFileSync(baselinePath, 'utf8');
  } catch (e) {
    console.error(`error: could not read baseline at ${baselinePath}`);
    process.exit(1);
  }

  let baseline;
  try {
    baseline = JSON.parse(baselineRaw);
  } catch (e) {
    console.error(`error: catalog/source-structure-baseline.json: invalid JSON (${e.message})`);
    process.exit(1);
  }

  const { violations, notices } = evaluateStructure({ files, baseline });
  violations.push(...validateRoleSplits({ root }));

  if (violations.length > 0) {
    for (const v of violations) console.error(`error: ${v}`);
    for (const n of notices) console.error(`notice: ${n}`);
    console.log(`Scanned ${files.length} files, ${Object.keys(baseline.oversize || {}).length} oversize, ${baseline.root_rust_files?.length || 0} root files.`);
    process.exit(1);
  }

  if (update) {
    const { baseline: newBaseline, changed } = lowerBaseline({ files, baseline });
    if (changed) {
      const sortedBaseline = {
        schema: newBaseline.schema,
        budgets: newBaseline.budgets,
        oversize: newBaseline.oversize,
        root_rust_files: newBaseline.root_rust_files
      };
      fs.writeFileSync(baselinePath, JSON.stringify(sortedBaseline, null, 2) + '\n');
    }
    process.exit(0);
  }

  for (const n of notices) console.error(`notice: ${n}`);
  console.log(`Scanned ${files.length} files, ${Object.keys(baseline.oversize || {}).length} oversize, ${baseline.root_rust_files?.length || 0} root files.`);
  process.exit(0);
}
