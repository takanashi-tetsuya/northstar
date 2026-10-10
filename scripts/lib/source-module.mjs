import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const currentDir = path.dirname(fileURLToPath(import.meta.url));

/** Absolute path to the repository root, two directories above this file. */
export const repositoryRoot = path.resolve(currentDir, '../..').replaceAll('\\', '/');

/**
 * Returns test-only submodules found in the source.
 * Recognizes only line-leading outer #[cfg(test)] on bodyless mod declarations; #[path] redirects are not followed.
 */
function getTestModules(source) {
  const testModules = new Set();
  const regex = /^[ \t]*#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]/gm;
  let match;
  while ((match = regex.exec(source)) !== null) {
    const tail = source.slice(match.index + match[0].length);
    const itemRegex = /^(?:\s*|(?:\/\/.*)|(?:#\s*\[[^\]]+\]))*/;
    const itemMatch = itemRegex.exec(tail);
    const itemStart = itemMatch ? itemMatch[0].length : 0;
    
    const declTail = tail.slice(itemStart);
    const modMatch = /^(?:pub(?:\([^)]+\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*(;|\{)/.exec(declTail);
    if (modMatch && modMatch[2] === ';') {
      testModules.add(modMatch[1]);
    }
  }
  return testModules;
}

/**
 * Returns the module file and all recursively nested .rs files in its child directory.
 */
export function moduleFiles(modulePath, { root = repositoryRoot, includeTests = true } = {}) {
  if (path.isAbsolute(modulePath)) throw new Error(`absolute path rejected: ${modulePath}`);
  if (modulePath.split(/[/\\]/).includes('..')) throw new Error(`.. segments rejected: ${modulePath}`);
  if (!modulePath.endsWith('.rs')) throw new Error(`must end with .rs: ${modulePath}`);

  const absoluteModulePath = path.join(root, modulePath);
  if (!fs.existsSync(absoluteModulePath) || !fs.statSync(absoluteModulePath).isFile()) {
    throw new Error(`module file does not exist: ${modulePath}`);
  }

  const normalizedModulePath = modulePath.replaceAll('\\', '/');
  let childDir;
  if (normalizedModulePath.endsWith('/mod.rs')) {
    childDir = normalizedModulePath.slice(0, -7);
  } else if (normalizedModulePath === 'mod.rs') {
    childDir = '.';
  } else {
    childDir = normalizedModulePath.slice(0, -3);
  }

  const results = [normalizedModulePath];
  const absoluteChildDir = path.join(root, childDir);
  
  if (fs.existsSync(absoluteChildDir) && fs.statSync(absoluteChildDir).isDirectory()) {
    const walk = (dir, relPrefix, parentModulePath) => {
      let excludedNames = new Set();
      if (!includeTests) {
        if (fs.existsSync(parentModulePath)) {
          const source = fs.readFileSync(parentModulePath, 'utf8');
          excludedNames = getTestModules(source);
        }
      }

      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        if (entry.isSymbolicLink()) continue;
        
        const isRsFile = entry.isFile() && entry.name.endsWith('.rs');
        const isDir = entry.isDirectory();
        
        let moduleName = entry.name;
        if (isRsFile) {
          moduleName = entry.name.slice(0, -3);
          if (moduleName === 'mod') moduleName = null;
        } else if (!isDir) {
          continue;
        }

        if (moduleName && excludedNames.has(moduleName)) {
          continue;
        }

        const entryRelPath = relPrefix === '.' || relPrefix === '' ? entry.name : `${relPrefix}/${entry.name}`;
        const entryAbsPath = path.join(dir, entry.name);
        
        if (isDir) {
          let nextParentModulePath = path.join(dir, `${entry.name}.rs`);
          if (!fs.existsSync(nextParentModulePath)) {
            nextParentModulePath = path.join(entryAbsPath, 'mod.rs');
          }
          walk(entryAbsPath, entryRelPath, nextParentModulePath);
        }
        
        if (isRsFile) {
          const entryRelPathUnix = entryRelPath.replaceAll('\\', '/');
          if (entryRelPathUnix !== normalizedModulePath) {
            results.push(entryRelPathUnix);
          }
        }
      }
    };
    walk(absoluteChildDir, childDir, absoluteModulePath);
  }
  
  return [results[0], ...results.slice(1).sort()];
}

/**
 * Returns module files excluding test modules.
 */
export function productionModuleFiles(modulePath, options) {
  return moduleFiles(modulePath, { ...options, includeTests: false });
}

/**
 * Returns an array of objects containing path and source for each file in the module.
 */
export function readModuleParts(modulePath, options) {
  const files = moduleFiles(modulePath, options);
  const rootDir = options?.root ?? repositoryRoot;
  return files.map(file => ({
    path: file,
    source: fs.readFileSync(path.join(rootDir, file), 'utf8')
  }));
}

/**
 * Returns the sources of all files in the module joined with newlines.
 */
export function readModule(modulePath, options) {
  return readModuleParts(modulePath, options).map(part => part.source).join('\n');
}

/**
 * Returns the sources of all files in the module excluding test modules, joined with newlines.
 */
export function readProductionModule(modulePath, options) {
  return readModule(modulePath, { ...options, includeTests: false });
}

/**
 * Finds the index of the matching closing brace.
 */
export function matchingRustBrace(source, opening) {
  if (source[opening] !== '{') throw new Error("opening must be '{'");
  let depth = 1;
  let index = opening + 1;
  while (index < source.length) {
    if (source.startsWith('//', index)) {
      const newline = source.indexOf('\n', index + 2);
      index = newline < 0 ? source.length : newline + 1;
      continue;
    }
    if (source.startsWith('/*', index)) {
      let commentDepth = 1;
      index += 2;
      while (index < source.length && commentDepth > 0) {
        if (source.startsWith('/*', index)) {
          commentDepth += 1;
          index += 2;
        } else if (source.startsWith('*/', index)) {
          commentDepth -= 1;
          index += 2;
        } else index += 1;
      }
      continue;
    }
    const raw = /^(?:br|rb|r)(#+)?"/.exec(source.slice(index));
    if (raw) {
      const terminator = `"${raw[1] ?? ''}`;
      const closing = source.indexOf(terminator, index + raw[0].length);
      if (closing < 0) return -1;
      index = closing + terminator.length;
      continue;
    }
    const quoteOffset = source[index] === '"' ? 0 : source.startsWith('b"', index) ? 1 : -1;
    if (quoteOffset >= 0) {
      index += quoteOffset + 1;
      let escaped = false;
      while (index < source.length) {
        const character = source[index++];
        if (escaped) escaped = false;
        else if (character === '\\') escaped = true;
        else if (character === '"') break;
      }
      continue;
    }
    const charStart =
      source[index] === "'" ? index + 1 : source.startsWith("b'", index) ? index + 2 : -1;
    if (charStart >= 0 && charStart < source.length) {
      let cursor = charStart;
      if (source[cursor] === '\\') {
        cursor += 2;
        if (source[cursor - 1] === 'u' && source[cursor] === '{') {
          const brace = source.indexOf('}', cursor + 1);
          cursor = brace < 0 ? source.length : brace + 1;
        }
      } else {
        const scalar = source.codePointAt(cursor);
        cursor += scalar !== undefined && scalar > 0xffff ? 2 : 1;
      }
      if (source[cursor] === "'") {
        index = cursor + 1;
        continue;
      }
    }
    if (source[index] === '{') depth += 1;
    else if (source[index] === '}' && --depth === 0) return index;
    index += 1;
  }
  return -1;
}

/**
 * Finds the bounds and body of a rust item matching the declaration.
 */
export function findRustItem(source, declaration) {
  let start = -1;
  let matches = 0;
  let searchIndex = 0;
  while (true) {
    const index = source.indexOf(declaration, searchIndex);
    if (index === -1) break;
    start = index;
    matches++;
    searchIndex = index + declaration.length;
  }
  
  if (matches === 0) throw new Error(`missing ${declaration}`);
  if (matches > 1) throw new Error(`ambiguous ${declaration}: found ${matches} occurrences`);
  
  start = source.indexOf(declaration);
  const open = source.indexOf('{', start + declaration.length);
  if (open === -1) throw new Error(`missing body for ${declaration}`);
  
  const close = matchingRustBrace(source, open);
  if (close === -1) throw new Error(`unterminated body for ${declaration}`);
  
  return {
    start,
    open,
    close,
    text: source.slice(start, close + 1),
    body: source.slice(open + 1, close)
  };
}

/**
 * Returns the body string of a matching rust item.
 */
export function rustItemBody(source, declaration) {
  return findRustItem(source, declaration).body;
}

/**
 * Returns a rust item found across all files of a module.
 */
export function moduleItem(modulePath, declaration, options) {
  const source = readModule(modulePath, options);
  return findRustItem(source, declaration);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    let args = process.argv.slice(2);
    if (args.length === 0) {
      process.stderr.write('Usage: source-module.mjs <files|cat|item> [--production] <module.rs> [declaration]\n');
      process.exit(2);
    }
    const subcommand = args[0];
    args = args.slice(1);
    
    let includeTests = true;
    if (args[0] === '--production') {
      includeTests = false;
      args = args.slice(1);
    }
    
    if (subcommand === 'files') {
      if (args.length !== 1) {
        process.stderr.write('Usage: source-module.mjs files [--production] <module.rs>\n');
        process.exit(2);
      }
      const files = moduleFiles(args[0], { root: repositoryRoot, includeTests });
      for (const file of files) {
        process.stdout.write(file + '\n');
      }
    } else if (subcommand === 'cat') {
      if (args.length !== 1) {
        process.stderr.write('Usage: source-module.mjs cat [--production] <module.rs>\n');
        process.exit(2);
      }
      const source = readModule(args[0], { root: repositoryRoot, includeTests });
      process.stdout.write(source);
    } else if (subcommand === 'item') {
      if (args.length !== 2) {
        process.stderr.write('Usage: source-module.mjs item [--production] <module.rs> <declaration>\n');
        process.exit(2);
      }
      const item = moduleItem(args[0], args[1], { root: repositoryRoot, includeTests });
      process.stdout.write(item.text + '\n');
    } else {
      process.stderr.write(`Unknown subcommand: ${subcommand}\n`);
      process.stderr.write('Usage: source-module.mjs <files|cat|item> [--production] <module.rs> [declaration]\n');
      process.exit(2);
    }
  } catch (err) {
    process.stderr.write(err.message + '\n');
    process.exit(1);
  }
}
