#!/usr/bin/env node
// Generates apps/server/assets/aaguid when it is missing. The server zip and the web build both include it, and it
// is gitignored, so a new checkout starts without it.
import { spawnSync } from 'node:child_process';
import { statSync } from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const serverDir = path.join(repoRoot, 'apps/server');
const indexFile = path.join(serverDir, 'assets/aaguid/combined.json');

if (!statSync(indexFile, { throwIfNoEntry: false })?.isFile()) {
   console.log(`ensure-aaguids: generating ${path.relative(repoRoot, indexFile)}`);
   // extractimg.py reads and writes paths relative to apps/server
   const result = spawnSync('python3', ['extractimg.py'], { cwd: serverDir, stdio: 'inherit' });
   if (result.error || result.status !== 0) {
      console.error(`ensure-aaguids: extractimg.py failed: ${result.error?.message ?? `exit ${result.status}`}`);
      process.exit(1);
   }
}
