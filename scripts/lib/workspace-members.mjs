import fs from 'node:fs';
import path from 'node:path';

/**
 * Reads <root>/Cargo.toml, takes the `members` array of the `[workspace]` table,
 * and returns the member paths as written (forward slashes, relative to root),
 * in file order, without `"."`.
 *
 * @param {string} root - Path to the workspace root directory.
 * @returns {string[]} Member directory paths relative to root.
 */
export function workspaceMemberDirectories(root) {
  const manifestPath = path.join(root, 'Cargo.toml');
  const manifestContent = fs.readFileSync(manifestPath, 'utf8');

  const lines = manifestContent.split(/\r?\n/);
  let inWorkspace = false;
  const workspaceLines = [];

  for (const line of lines) {
    if (/^\s*\[/.test(line)) {
      if (/^\s*\[\s*workspace\s*\]\s*(?:#.*)?$/.test(line)) {
        inWorkspace = true;
        continue;
      } else if (inWorkspace) {
        break;
      }
    }
    if (inWorkspace) {
      workspaceLines.push(line);
    }
  }

  if (!inWorkspace) {
    throw new Error('Cargo.toml: workspace members not found');
  }

  const workspaceText = workspaceLines.join('\n');
  const membersMatch = /(?:^|\n)[ \t]*members[ \t]*=[ \t]*(?:\r?\n[ \t]*)?\[/m.exec(workspaceText);
  if (!membersMatch) {
    throw new Error('Cargo.toml: workspace members not found');
  }

  const startIdx = membersMatch.index + membersMatch[0].length;
  const members = [];
  let inComment = false;
  let inString = false;
  let currentString = '';
  let closed = false;

  for (let i = startIdx; i < workspaceText.length; i++) {
    const char = workspaceText[i];
    if (inComment) {
      if (char === '\n') {
        inComment = false;
      }
      continue;
    }
    if (inString) {
      if (char === '"') {
        inString = false;
        if (currentString !== '.') {
          members.push(currentString);
        }
        currentString = '';
      } else if (char === '\\') {
        i++;
        if (i < workspaceText.length) {
          const nextChar = workspaceText[i];
          if (nextChar === '"' || nextChar === '\\') {
            currentString += nextChar;
          } else if (nextChar === 'n') {
            currentString += '\n';
          } else if (nextChar === 't') {
            currentString += '\t';
          } else {
            currentString += '\\' + nextChar;
          }
        }
      } else {
        currentString += char;
      }
      continue;
    }

    if (char === '#') {
      inComment = true;
    } else if (char === '"') {
      inString = true;
      currentString = '';
    } else if (char === ']') {
      closed = true;
      break;
    }
  }

  if (!closed) {
    throw new Error('Cargo.toml: workspace members not found');
  }

  return members;
}

/**
 * Returns a Map from the crate directory name (the last path segment of each
 * member directory) to that relative directory.
 *
 * @param {string} root - Path to the workspace root directory.
 * @returns {Map<string, string>} Map from crate name to relative directory.
 */
export function workspaceCrateDirectories(root) {
  const members = workspaceMemberDirectories(root);
  const crateDirectories = new Map();

  for (const directory of members) {
    const name = directory.split('/').filter(Boolean).pop();
    if (crateDirectories.has(name)) {
      throw new Error(`Cargo.toml: duplicate workspace crate directory name ${name}`);
    }
    crateDirectories.set(name, directory);
  }

  return crateDirectories;
}
