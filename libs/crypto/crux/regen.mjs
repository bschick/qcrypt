import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

// Rebuilds the committed crux artifacts and manifest.json from source. With --check, rebuilds into a
// temp directory and verifies the committed files match, without writing anything.

// rustc is pinned by rust-toolchain.toml. WASM_OPT_VERSION must equal the binaryen version that
// WASM_PACK_VERSION downloads, which it uses unless a wasm-opt is on PATH that must match instead
const WASM_PACK_VERSION = '0.15.0';
const WASM_OPT_VERSION = '117';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const crateDir = path.join(repoRoot, 'libs/crypto/crux');
const outDir = path.join(repoRoot, 'libs/crypto/src/lib/crux');
const manifestPath = path.join(crateDir, 'manifest.json');
const cargoHome = process.env.CARGO_HOME ?? path.join(os.homedir(), '.cargo');
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
   return ['Cargo.lock', 'Cargo.toml', 'regen.mjs', 'rust-toolchain.toml', ...sources];
}

// Removes rustflags, profile, and compiler overrides and turns off incremental builds, so Cargo.toml
// and the remap flags set before the build are the only build settings
function buildEnv() {
   const env = { ...process.env };
   for (const name of Object.keys(env)) {
      const targetSetting = name.startsWith('CARGO_TARGET_') && name !== 'CARGO_TARGET_DIR';
      if (
         targetSetting ||
         /^(RUSTFLAGS|RUSTC|RUSTC_.+|CARGO_ENCODED_RUSTFLAGS|CARGO_BUILD_.+|CARGO_PROFILE_.+)$/.test(name)
      ) {
         delete env[name];
      }
   }
   env.CARGO_INCREMENTAL = '0';
   return env;
}

const env = buildEnv();

// Run in the crate directory so rustup applies rust-toolchain.toml
const run = (tool, args) => execFileSync(tool, args, { cwd: crateDir, env, encoding: 'utf8' }).trim();

// Cargo config files with release profile, compiler, or wasm32 target settings in any TOML form, none
// of which the manifest records. Comment lines are skipped
function cargoConfigOverrides() {
   const configDirs = new Set([cargoHome]);
   for (let dir = crateDir; dir !== path.dirname(dir); dir = path.dirname(dir)) {
      configDirs.add(path.join(dir, '.cargo'));
   }
   return [...configDirs]
      .flatMap((dir) => [path.join(dir, 'config.toml'), path.join(dir, 'config')])
      .filter((file) => fs.existsSync(file) && fs.statSync(file).isFile())
      .filter((file) =>
         /^(?!\s*#).*(\bprofile\.release\b|\bprofile\s*=|\brustc(-wrapper|-workspace-wrapper)?\s*=|wasm32)/m.test(
            fs.readFileSync(file, 'utf8'),
         ),
      );
}

// Version of the wasm-opt on PATH, or undefined when there is none
function pathWasmOptVersion() {
   try {
      return run('wasm-opt', ['--version']).match(/version (\d+)/)?.[1] ?? 'unknown';
   } catch (err) {
      if (err.code === 'ENOENT') {
         return undefined;
      }
      throw err;
   }
}

const toolchain = {
   rustc: run('rustc', ['--version']).split(' ')[1],
   'wasm-pack': run('wasm-pack', ['--version']).split(' ')[1],
   'wasm-opt': WASM_OPT_VERSION,
   'wasm-bindgen': readCrate('Cargo.lock').match(/name = "wasm-bindgen"\nversion = "([^"]+)"/)[1],
};

const pinnedRustc = readCrate('rust-toolchain.toml').match(/channel = "([^"]+)"/)[1];
const pathWasmOpt = pathWasmOptVersion();
const configOverrides = cargoConfigOverrides();
const problems = [
   toolchain.rustc !== pinnedRustc && `rustc ${pinnedRustc} is pinned, found ${toolchain.rustc}`,
   toolchain['wasm-pack'] !== WASM_PACK_VERSION &&
      `wasm-pack ${WASM_PACK_VERSION} is pinned, found ${toolchain['wasm-pack']}`,
   pathWasmOpt !== undefined &&
      pathWasmOpt !== WASM_OPT_VERSION &&
      `wasm-opt ${WASM_OPT_VERSION} is pinned, found version ${pathWasmOpt} on PATH`,
   configOverrides.length > 0 &&
      `cargo config sets release profile, compiler, or wasm32 target settings in ${configOverrides.join(', ')}`,
].filter(Boolean);
if (problems.length > 0) {
   throw new Error(`regen: ${problems.join('; ')}`);
}

// wasm-pack runs cargo without --locked, so first confirm Cargo.lock needs no update
const metadata = JSON.parse(
   execFileSync('cargo', ['metadata', '--locked', '--format-version', '1'], {
      cwd: crateDir,
      env,
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'inherit'],
   }),
);

// Collect source directories so registry paths can be remapped below, since they vary by registry
// protocol or mirror
const registryDirs = new Set(
   metadata.packages
      .filter((pkg) => pkg.source?.startsWith('registry+') || pkg.source?.startsWith('sparse+'))
      .map((pkg) => path.dirname(path.dirname(pkg.manifest_path))),
);

// Remaps local paths in panic messages compiled into the wasm. rustc applies the last matching remap,
// so list the registry remaps after the cargo home remap for correct precedence
env.CARGO_ENCODED_RUSTFLAGS = [
   `--remap-path-prefix=${cargoHome}=/cargo`,
   ...[...registryDirs].map((dir) => `--remap-path-prefix=${dir}=/registry`),
   `--remap-path-prefix=${crateDir}=/crux`,
].join('\x1f');

// Builds into pkgDir and returns the contents of the committed artifacts
function buildArtifacts(pkgDir) {
   const build = spawnSync(
      'wasm-pack',
      ['build', '--target', 'web', '--release', '--out-dir', pkgDir, '--', '--locked'],
      {
         cwd: crateDir,
         env,
         encoding: 'utf8',
      },
   );
   process.stdout.write(build.stdout ?? '');
   process.stderr.write(build.stderr ?? '');
   if (build.error) {
      throw build.error;
   }
   if (build.status !== 0) {
      throw new Error(`regen: wasm-pack exited with status ${build.status}`);
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
