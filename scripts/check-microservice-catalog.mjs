#!/usr/bin/env node

// Compatibility entry point. The structured Rust validator is the only source
// of catalog validation rules; this wrapper keeps existing CI and local commands
// stable while avoiding a second, divergent YAML parser.
import { spawnSync } from 'node:child_process';

const forwarded = process.argv.slice(2);
const args = ['run', '--locked', '-q', '-p', 'catalog-validator', '--', 'validate', '--strict', ...forwarded];
const result = spawnSync('cargo', args, { stdio: 'inherit', shell: process.platform === 'win32' });
if (result.error) {
  console.error(`catalog-validator could not be started: ${result.error.message}`);
  process.exit(1);
}
process.exit(result.status ?? 1);
