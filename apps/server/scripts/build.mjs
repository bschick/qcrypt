#!/usr/bin/env node
/**
 * build.mjs
 *
 * The single place that decides where a server build lands and whether it is
 * minified, so `pnpm build:server`, `pnpm build:server:prod`, and deploy.mjs
 * cannot disagree. The nx `build` / `build-min` targets stay the primitives;
 * this owns the policy around them.
 *
 *   build.mjs            test, unminified, into dist/server-test
 *   build.mjs --prod     prod, minified, into dist/server
 *
 * Either mode takes --min / --no-min. QC_SERVER_OUT overrides the output
 * directory, which is how deploy.mjs pins the build to the directory it is
 * about to upload from.
 */

import { spawnSync } from 'node:child_process';
import { statSync } from 'node:fs';

const argv = process.argv.slice(2);
const prod = argv.includes('--prod');

// Minification is the only thing that differs by default between the two
// modes: a prod artifact is minified unless asked otherwise.
let min = prod;
if (argv.includes('--min')) {
   min = true;
}
if (argv.includes('--no-min')) {
   min = false;
}

const defaultOut = prod
   ? (process.env.QC_PROD_SERVER_DIST ?? 'dist/server')
   : (process.env.QC_TEST_SERVER_DIST ?? 'dist/server-test');
const outDir = process.env.QC_SERVER_OUT ?? defaultOut;

function run(command, args, env = {}) {
   const result = spawnSync(command, args, { stdio: 'inherit', env: { ...process.env, ...env } });
   if (result.error) {
      console.error(`build:server: failed to spawn ${command}: ${result.error.message}`);
      process.exit(1);
   }
   if (result.status !== 0) {
      process.exit(result.status ?? 1);
   }
}

// zip only warns when an input is missing, so an absent generated asset would otherwise ship a
// silently incomplete artifact
const AAGUID_INDEX = 'apps/server/assets/aaguid/combined.json';
try {
   if (!statSync(AAGUID_INDEX).isFile()) {
      throw new Error('not a file');
   }
} catch {
   console.error(`build:server: missing ${AAGUID_INDEX}, which is bundled into server.zip.`);
   console.error('build:server: generate it by running `./extractimg.py` from apps/server.');
   process.exit(1);
}

console.log(`build:server: ${prod ? 'prod' : 'test'}, ${min ? 'minified' : 'unminified'}, into ${outDir}`);

run('pnpm', ['check']);
run('pnpm', ['nx', min ? 'build-min' : 'build', 'server'], { QC_SERVER_OUT: outDir });
