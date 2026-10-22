import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

import {
  workspaceMemberDirectories,
  workspaceCrateDirectories,
} from './lib/workspace-members.mjs';

test('members with ".", comments, a trailing comma and nested directories give the expected list and map', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'workspace-members-'));
  try {
    fs.writeFileSync(
      path.join(root, 'Cargo.toml'),
      `[workspace]
# Header comment
members = [
  ".",
  # Kernel crate
  "crates/kernel/northstar-xep-core", # inline comment
  "crates/contexts/auth/northstar-auth-core",
  "tools/architecture-validator",
]
`,
    );
    assert.deepEqual(workspaceMemberDirectories(root), [
      'crates/kernel/northstar-xep-core',
      'crates/contexts/auth/northstar-auth-core',
      'tools/architecture-validator',
    ]);
    assert.deepEqual(
      workspaceCrateDirectories(root),
      new Map([
        ['northstar-xep-core', 'crates/kernel/northstar-xep-core'],
        ['northstar-auth-core', 'crates/contexts/auth/northstar-auth-core'],
        ['architecture-validator', 'tools/architecture-validator'],
      ]),
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('a manifest without a members array throws workspace members not found', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'workspace-members-'));
  try {
    fs.writeFileSync(
      path.join(root, 'Cargo.toml'),
      `[workspace]
resolver = "2"
`,
    );
    assert.throws(
      () => workspaceMemberDirectories(root),
      /workspace members not found/,
    );
    assert.throws(
      () => workspaceCrateDirectories(root),
      /workspace members not found/,
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('two members crates/kernel/a and tools/a throw duplicate workspace crate directory name a', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'workspace-members-'));
  try {
    fs.writeFileSync(
      path.join(root, 'Cargo.toml'),
      `[workspace]
members = [
  "crates/kernel/a",
  "tools/a",
]
`,
    );
    assert.throws(
      () => workspaceCrateDirectories(root),
      /duplicate workspace crate directory name a/,
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
