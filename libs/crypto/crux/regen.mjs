import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

// Rebuilds the committed crux artifacts and manifest.json from source, in the Docker image that Dockerfile defines.
// With --check, rebuilds into a temp directory and verifies the committed files match, without writing anything.
// Verified reproducible on arm64 only.

const IMAGE = 'qcrypt-crux';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const crateDir = path.join(repoRoot, 'libs/crypto/crux');
const outDir = path.join(repoRoot, 'libs/crypto/src/lib/crux');
const manifestPath = path.join(crateDir, 'manifest.json');
const check = process.argv.includes('--check');

const sha256 = (data) => createHash('sha256').update(data).digest('hex');
const relative = (file) => path.relative(repoRoot, file);
const readCrate = (file) => fs.readFileSync(path.join(crateDir, file), 'utf8');

// Every crate file the build can read, except build outputs and macOS .DS_Store files
function inputFiles() {
   return fs
      .readdirSync(crateDir, { recursive: true, withFileTypes: true })
      .filter((entry) => entry.isFile() && entry.name !== '.DS_Store')
      .map((entry) => path.relative(crateDir, path.join(entry.parentPath, entry.name)))
      .filter((file) => !['manifest.json', 'pkg', 'target'].includes(file.split(path.sep)[0]))
      .sort();
}

console.log('crux: building the Docker image');
execFileSync('docker', ['build', '-q', '-t', IMAGE, '-'], {
   input: readCrate('Dockerfile'),
   stdio: ['pipe', 'ignore', 'inherit'],
});

// Runs a bash script in the image with the crate at /crux as the working directory, so rustup applies
// rust-toolchain.toml. RUSTUP_AUTO_INSTALL=0 makes rustup fail instead of downloading a toolchain the image lacks.
function inImage(script, { mounts = [], offline = false } = {}) {
   const args = [
      'run',
      '--rm',
      '--user',
      `${process.getuid()}:${process.getgid()}`,
      '-e',
      'HOME=/tmp',
      '-e',
      'RUSTUP_AUTO_INSTALL=0',
      ...(offline ? ['--network', 'none'] : []),
      ...[`${crateDir}:/crux:ro`, ...mounts].flatMap((mount) => ['-v', mount]),
      '-w',
      '/crux',
      IMAGE,
      'bash',
      '-c',
      script,
   ];
   return spawnSync('docker', args, { encoding: 'utf8' });
}

// Outside the crate, rustc is the image's default toolchain rather than the one rust-toolchain.toml selects
const versions = inImage(
   'cd / && rustc --version && wasm-pack --version && wasm-opt --version && wasm-bindgen --version',
   { offline: true },
);
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
].filter(Boolean);
if (problems.length > 0) {
   throw new Error(`regen: ${problems.join('; ')}`);
}

function buildStep(name, script, options) {
   console.log(`crux: running ${name}`);
   const step = inImage(script, options);
   if (step.error) {
      throw step.error;
   }
   if (step.status !== 0) {
      process.stderr.write(`${step.stdout}${step.stderr}`);
      throw new Error(`regen: ${name} in ${IMAGE} exited with status ${step.status}`);
   }
   return `${step.stdout}${step.stderr}`;
}

// Builds into pkgDir and returns the contents of the committed artifacts. Only cargo fetch --locked has network access.
function buildArtifacts(pkgDir, registryDir) {
   const registry = `${registryDir}:/usr/local/cargo/registry`;
   buildStep('cargo fetch', 'cargo fetch --locked', { mounts: [registry] });
   // Remaps local paths in panic messages compiled into the wasm. rustc applies the last matching remap, so the
   // registry remaps follow the cargo home remap for correct precedence. Container paths have no spaces, so
   // RUSTFLAGS can hold them.
   const script = [
      'set -euo pipefail',
      'flags=--remap-path-prefix=/usr/local/cargo=/cargo',
      'for dir in /usr/local/cargo/registry/src/*; do flags="$flags --remap-path-prefix=$dir=/registry"; done',
      'export RUSTFLAGS="$flags" CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/target',
      // Offline, wasm-pack's update check prints the harmless warning "failed to get wasm-pack version"
      'wasm-pack build --target web --release --out-dir /pkg -- --frozen',
   ].join('\n');
   const output = buildStep('wasm-pack build', script, {
      mounts: [`${registry}:ro`, `${pkgDir}:/pkg`],
      offline: true,
   });
   if (!output.includes('Optimizing wasm binaries with')) {
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

const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'crux-'));
const pkgDir = check ? path.join(workDir, 'pkg') : path.join(crateDir, 'pkg');
const registryDir = path.join(workDir, 'registry');
// Docker would create missing mount sources owned by root
for (const dir of [pkgDir, registryDir]) {
   fs.mkdirSync(dir, { recursive: true });
}
let artifacts;
try {
   artifacts = buildArtifacts(pkgDir, registryDir);
} finally {
   fs.rmSync(workDir, { recursive: true, force: true });
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
      console.error(`crux check: a rebuild from source on ${os.machine()} does not match ${differ.join(', ')}`);
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
