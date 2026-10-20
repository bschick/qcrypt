import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

// Rebuilds the committed crux artifacts and manifest.json from source, in the Docker image that Dockerfile defines.
// With --check, rebuilds into a temp directory and verifies the committed files match, without writing anything.

const IMAGE = 'qcrypt-crux';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const crateDir = path.join(repoRoot, 'libs/crypto/crux');
const outDir = path.join(repoRoot, 'libs/crypto/src/lib/crux');
const manifestPath = path.join(crateDir, 'manifest.json');
const check = process.argv.includes('--check');

const sha256 = (data) => createHash('sha256').update(data).digest('hex');
const relative = (file) => path.relative(repoRoot, file);
const readCrate = (file) => fs.readFileSync(path.join(crateDir, file), 'utf8');

// Every crate file whose content can change the artifacts, relative to the crate directory
function inputFiles() {
   const sources = fs
      .readdirSync(path.join(crateDir, 'src'), { recursive: true })
      .filter((file) => file.endsWith('.rs'))
      .map((file) => path.join('src', file))
      .sort();
   return ['Cargo.lock', 'Cargo.toml', 'Dockerfile', 'regen.mjs', 'rust-toolchain.toml', ...sources];
}

execFileSync('docker', ['build', '-q', '-t', IMAGE, '-'], {
   input: readCrate('Dockerfile'),
   stdio: ['pipe', 'ignore', 'inherit'],
});

// Runs a bash script in the image with the crate at /crux as the working directory, so rustup applies
// rust-toolchain.toml. RUSTUP_AUTO_INSTALL=0 makes rustup fail instead of downloading a toolchain the image lacks.
function inImage(script, mounts = []) {
   const volumes = [`${crateDir}:/crux`, ...mounts].flatMap((mount) => ['-v', mount]);
   const args = ['run', '--rm', '-e', 'RUSTUP_AUTO_INSTALL=0', ...volumes, '-w', '/crux', IMAGE, 'bash', '-c', script];
   return spawnSync('docker', args, { encoding: 'utf8' });
}

const versions = inImage('rustc --version && wasm-pack --version && wasm-opt --version && wasm-bindgen --version');
if (versions.status !== 0) {
   throw new Error(`regen: could not read tool versions in ${IMAGE}: ${versions.stderr}`);
}
const [rustcVersion, wasmPackVersion, wasmOptVersion, wasmBindgenVersion] = versions.stdout.trim().split('\n');

const toolchain = {
   rustc: rustcVersion.split(' ')[1],
   'wasm-pack': wasmPackVersion.split(' ')[1],
   'wasm-opt': wasmOptVersion.match(/version (\d+)/)[1],
   'wasm-bindgen': readCrate('Cargo.lock').match(/name = "wasm-bindgen"\nversion = "([^"]+)"/)[1],
};

const pinnedRustc = readCrate('rust-toolchain.toml').match(/channel = "([^"]+)"/)[1];
const imageWasmBindgen = wasmBindgenVersion.split(' ')[1];
const problems = [
   toolchain.rustc !== pinnedRustc && `rustc ${pinnedRustc} is pinned, the image has ${toolchain.rustc}`,
   imageWasmBindgen !== toolchain['wasm-bindgen'] &&
      `Cargo.lock has wasm-bindgen ${toolchain['wasm-bindgen']}, the image has ${imageWasmBindgen}`,
   fs.existsSync(path.join(crateDir, '.cargo')) &&
      `${relative(path.join(crateDir, '.cargo'))} can change build settings that the manifest does not record`,
].filter(Boolean);
if (problems.length > 0) {
   throw new Error(`regen: ${problems.join('; ')}`);
}

// Builds into pkgDir and returns the contents of the committed artifacts
function buildArtifacts(pkgDir) {
   // Remaps local paths in panic messages compiled into the wasm. rustc applies the last matching remap, so the
   // registry remaps follow the cargo home remap for correct precedence. Container paths have no spaces, so
   // RUSTFLAGS can hold them. The container runs as root, so chown gives the files it writes back to the host user.
   const script = [
      'set -euo pipefail',
      `trap 'chown -R ${process.getuid()}:${process.getgid()} /pkg /crux/target 2>/dev/null || true' EXIT`,
      'cargo fetch --locked',
      'flags=--remap-path-prefix=/usr/local/cargo=/cargo',
      'for dir in /usr/local/cargo/registry/src/*; do flags="$flags --remap-path-prefix=$dir=/registry"; done',
      'export RUSTFLAGS="$flags" CARGO_INCREMENTAL=0',
      'wasm-pack build --target web --release --out-dir /pkg -- --locked',
   ].join('\n');
   const build = inImage(script, [`${pkgDir}:/pkg`]);
   process.stdout.write(build.stdout ?? '');
   process.stderr.write(build.stderr ?? '');
   if (build.error) {
      throw build.error;
   }
   if (build.status !== 0) {
      throw new Error(`regen: the build in ${IMAGE} exited with status ${build.status}`);
   }
   if (!`${build.stdout}${build.stderr}`.includes('Optimizing wasm binaries with')) {
      throw new Error('regen: wasm-pack did not run wasm-opt');
   }

   const assetLine = "module_or_path = new URL('qc_crux_bg.wasm', import.meta.url);";
   const glue = fs.readFileSync(path.join(pkgDir, 'qc_crux.js'), 'utf8');
   if (!glue.includes(assetLine)) {
      throw new Error(
         'regen: default-init asset line not found — wasm-bindgen glue format changed, update the neutering step',
      );
   }
   const wasmBase64 = fs.readFileSync(path.join(pkgDir, 'qc_crux_bg.wasm')).toString('base64url');
   return {
      'qc_crux.d.ts': fs.readFileSync(path.join(pkgDir, 'qc_crux.d.ts'), 'utf8'),
      'qc_crux.js': glue.replace(assetLine, "throw new Error('crux: call cruxReady() instead of the default init');"),
      'wasm.ts': `export const CRUX_WASM_BASE64 =\n   '${wasmBase64}';\n`,
   };
}

const pkgDir = check ? fs.mkdtempSync(path.join(os.tmpdir(), 'crux-check-')) : path.join(crateDir, 'pkg');
fs.mkdirSync(pkgDir, { recursive: true });
let artifacts;
try {
   artifacts = buildArtifacts(pkgDir);
} finally {
   if (check) {
      fs.rmSync(pkgDir, { recursive: true, force: true });
   }
}

// Hashes of what went in and what came out, checked by crux.spec.ts
const manifest = {
   toolchain,
   inputs: Object.fromEntries(
      inputFiles().map((file) => [
         relative(path.join(crateDir, file)),
         sha256(fs.readFileSync(path.join(crateDir, file))),
      ]),
   ),
   outputs: Object.fromEntries(
      Object.entries(artifacts).map(([name, content]) => [relative(path.join(outDir, name)), sha256(content)]),
   ),
};

// Manifest entries that differ from the committed manifest.json
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

const files = Object.fromEntries(
   Object.entries(artifacts).map(([name, content]) => [path.join(outDir, name), content]),
);
files[manifestPath] = `${JSON.stringify(manifest, null, 2)}\n`;
const changes = manifestChanges();

if (check) {
   const differ = Object.entries(files)
      .filter(([file, content]) => !fs.existsSync(file) || fs.readFileSync(file, 'utf8') !== content)
      .map(([file]) => relative(file));
   if (differ.length > 0) {
      console.error(`crux check: a rebuild from source does not match ${differ.join(', ')}`);
      if (changes.length > 0) {
         console.error(`crux check: manifest entries that differ:\n${changes.join('\n')}`);
      }
      process.exit(1);
   }
   console.log('crux check: committed artifacts and manifest match a rebuild from source');
} else {
   fs.mkdirSync(outDir, { recursive: true });
   for (const [file, content] of Object.entries(files)) {
      fs.writeFileSync(file, content);
   }
   const wasmKb = (artifacts['wasm.ts'].length / 1024).toFixed(0);
   console.log(`crux regenerated: glue + types + ${wasmKb} KB wasm + manifest`);
   if (changes.length > 0) {
      console.log(`crux manifest changes:\n${changes.join('\n')}`);
   }
}
