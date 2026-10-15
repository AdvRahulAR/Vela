#!/usr/bin/env node
// Cross-platform test runner: lists tests/*.test.ts explicitly instead of relying
// on glob expansion (Node < 21 can't expand globs; Windows shells don't either).
import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const dir = 'tests';
const files = readdirSync(dir)
  .filter((f) => f.endsWith('.test.ts'))
  .sort()
  .map((f) => join(dir, f));

if (files.length === 0) {
  console.error('No test files found in tests/');
  process.exit(1);
}

const r = spawnSync(process.execPath, ['--import', 'tsx', '--test', ...process.argv.slice(2), ...files], {
  stdio: 'inherit',
});
process.exit(r.status ?? 1);
