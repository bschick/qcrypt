import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import * as fs from 'node:fs';
import * as path from 'node:path';

// Rebuilds the vendored libsodium and libsodium-wrappers packages and manifest.json from the pinned commits, in the
// Docker image that Dockerfile defines. With --check, rebuilds and verifies the committed files match, without
// writing them.

// Branch feat/stackzero-stable: libsodium's stable branch, which libsodium.js builds, plus the sodium_stackzero and
// emscripten_stack_get_free exports
const LIBSODIUM_REPO = 'https://github.com/bschick/libsodium.git';
const LIBSODIUM_COMMIT = '6432bd2fc7688af29bfdb9c23ba1b3b2cf882118';
// Branch feat/stackzero: libsodium.js master plus the stackzero() helper
const LIBSODIUM_JS_REPO = 'https://github.com/bschick/libsodium.js.git';
const LIBSODIUM_JS_COMMIT = 'e8f6411500386a30f80f296fc9091b2d416647eb';

const IMAGE = 'qcrypt-sodium';
// git archive dates each tree by its commit, so make would treat the older tree as stale. Every extracted file gets
// this time instead.
const SOURCE_TIME = 946684800;

// The files npm publishes in each package, minus the CommonJS build
const PACKAGES = {
   libsodium: {
      packageJson: 'package-libsodium.json',
      files: ['dist/modules-esm/libsodium.mjs'],
   },
   'libsodium-wrappers': {
      packageJson: 'package-libsodium-wrappers.json',
      files: ['dist/modules-esm/libsodium-wrappers.mjs', 'dist/modules-esm/libsodium-wrappers.d.mts'],
   },
};

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const sodiumDir = path.join(repoRoot, 'libs/crypto/sodium');
const buildDir = path.join(sodiumDir, 'build');
const srcDir = path.join(buildDir, 'src');
const manifestPath = path.join(sodiumDir, 'manifest.json');
const check = process.argv.includes('--check');

const sha256 = (data) => createHash('sha256').update(data).digest('hex');
const relative = (file) => path.relative(repoRoot, file);
const run = (tool, args, options = {}) =>
   execFileSync(tool, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'], ...options }).trim();

const dockerfile = fs.readFileSync(path.join(sodiumDir, 'Dockerfile'), 'utf8');
const toolchain = {
   image: dockerfile.match(/^FROM (\S+)$/m)[1],
   bun: dockerfile.match(/^ARG BUN_VERSION=(\S+)$/m)[1],
};

function exportCommit(repo, commit, name, dest) {
   const gitDir = path.join(buildDir, `${name}.git`);
   const tarFile = path.join(buildDir, `${name}.tar`);
   run('git', ['init', '-q', gitDir]);
   run('git', ['-C', gitDir, 'fetch', '-q', '--depth', '1', repo, commit]);
   run('git', ['-C', gitDir, 'archive', '-o', tarFile, commit]);
   fs.mkdirSync(dest, { recursive: true });
   run('tar', ['-x', '-f', tarFile, '-C', dest]);
}

function buildPackages() {
   fs.rmSync(buildDir, { recursive: true, force: true });
   exportCommit(LIBSODIUM_JS_REPO, LIBSODIUM_JS_COMMIT, 'libsodium.js', srcDir);
   // The libsodium submodule archives as an empty directory, and the committed dist/ would keep make from rebuilding
   fs.rmSync(path.join(srcDir, 'libsodium'), { recursive: true, force: true });
   fs.rmSync(path.join(srcDir, 'dist'), { recursive: true, force: true });
   exportCommit(LIBSODIUM_REPO, LIBSODIUM_COMMIT, 'libsodium', path.join(srcDir, 'libsodium'));
   for (const entry of ['', ...fs.readdirSync(srcDir, { recursive: true })]) {
      fs.lutimesSync(path.join(srcDir, entry), SOURCE_TIME, SOURCE_TIME);
   }

   run('docker', ['build', '-q', '-t', IMAGE, '-'], { input: dockerfile, stdio: ['pipe', 'pipe', 'inherit'] });
   // The container runs as root, so chown gives the files it writes back to the host user
   const script = [
      'set -euo pipefail',
      `trap 'chown -R ${process.getuid()}:${process.getgid()} /work' EXIT`,
      '(cd libsodium && ./autogen.sh -s -b) > build.log 2>&1',
      '(bun install --frozen-lockfile && make pack) >> build.log 2>&1',
      'bun test > test.log 2>&1',
   ].join('\n');
   const dockerArgs = ['run', '--rm', '-v', `${srcDir}:/work`, '-w', '/work', IMAGE, 'bash', '-c', script];
   const build = spawnSync('docker', dockerArgs, { stdio: 'inherit' });
   if (build.error) {
      throw build.error;
   }
   if (build.status !== 0) {
      for (const log of ['build.log', 'test.log']) {
         const logPath = path.join(srcDir, log);
         if (fs.existsSync(logPath)) {
            console.error(`--- last lines of ${relative(logPath)}`);
            console.error(fs.readFileSync(logPath, 'utf8').split('\n').slice(-40).join('\n'));
         }
      }
      throw new Error(`regen: the build in ${IMAGE} exited with status ${build.status}`);
   }

   const outputs = {};
   for (const [name, pkg] of Object.entries(PACKAGES)) {
      const pkgDir = path.join(sodiumDir, name);
      outputs[path.join(pkgDir, 'package.json')] = fs.readFileSync(path.join(srcDir, pkg.packageJson));
      outputs[path.join(pkgDir, 'LICENSE')] = fs.readFileSync(path.join(srcDir, 'LICENSE'));
      for (const file of pkg.files) {
         outputs[path.join(pkgDir, file)] = fs.readFileSync(path.join(srcDir, file));
      }
   }
   return outputs;
}

const outputs = buildPackages();

// What went in and what came out, checked by sodium.spec.ts
const manifest = {
   sources: {
      libsodium: `${LIBSODIUM_REPO}#${LIBSODIUM_COMMIT}`,
      'libsodium.js': `${LIBSODIUM_JS_REPO}#${LIBSODIUM_JS_COMMIT}`,
   },
   toolchain,
   inputs: Object.fromEntries(
      ['Dockerfile', 'regen.mjs'].map((file) => [
         relative(path.join(sodiumDir, file)),
         sha256(fs.readFileSync(path.join(sodiumDir, file))),
      ]),
   ),
   outputs: Object.fromEntries(Object.entries(outputs).map(([file, content]) => [relative(file), sha256(content)])),
};

function manifestChanges() {
   const flatten = (entries) =>
      Object.fromEntries(
         Object.entries(entries).flatMap(([section, values]) =>
            Object.entries(values ?? {}).map(([key, value]) => [`${section} ${key}`, value]),
         ),
      );
   const before = fs.existsSync(manifestPath) ? flatten(JSON.parse(fs.readFileSync(manifestPath, 'utf8'))) : {};
   const after = flatten(manifest);
   return [...new Set([...Object.keys(before), ...Object.keys(after)])]
      .filter((key) => before[key] !== after[key])
      .map((key) => `   ${key}: ${before[key] ?? '(none)'} -> ${after[key] ?? '(none)'}`);
}

const files = { ...outputs, [manifestPath]: Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`) };
const changes = manifestChanges();

if (check) {
   const differ = Object.entries(files)
      .filter(([file, content]) => !fs.existsSync(file) || !fs.readFileSync(file).equals(content))
      .map(([file]) => relative(file));
   if (differ.length > 0) {
      console.error(`sodium check: a rebuild from source does not match ${differ.join(', ')}`);
      if (changes.length > 0) {
         console.error(`sodium check: manifest entries that differ:\n${changes.join('\n')}`);
      }
      process.exit(1);
   }
   console.log('sodium check: committed packages and manifest match a rebuild from source');
} else {
   for (const name of Object.keys(PACKAGES)) {
      fs.rmSync(path.join(sodiumDir, name), { recursive: true, force: true });
   }
   for (const [file, content] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, content);
   }
   console.log(`sodium regenerated: ${Object.keys(outputs).length} package files + manifest`);
   if (changes.length > 0) {
      console.log(`sodium manifest changes:\n${changes.join('\n')}`);
   }
}
