import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

// Rebuilds the committed crux artifacts and manifest.json from source. With --check, rebuilds into a
// temp directory and verifies the committed files match, without writing anything.

// wasm-pack also fixes the wasm-opt version it downloads. rustc is pinned by rust-toolchain.toml
const WASM_PACK_VERSION = '0.15.0';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const crateDir = path.join(repoRoot, 'libs/crypto/crux');
const outDir = path.join(repoRoot, 'libs/crypto/src/lib/crux');
const manifestPath = path.join(crateDir, 'manifest.json');
const inputs = ['Cargo.lock', 'Cargo.toml', 'rust-toolchain.toml', 'src/lib.rs'];
const check = process.argv.includes('--check');

const sha256 = (data) => createHash('sha256').update(data).digest('hex');
const relative = (file) => path.relative(repoRoot, file);
const readCrate = (file) => fs.readFileSync(path.join(crateDir, file), 'utf8');
// Run in the crate directory so rustup applies rust-toolchain.toml
const version = (tool) => execFileSync(tool, ['--version'], { cwd: crateDir, encoding: 'utf8' }).trim().split(' ')[1];

const toolchain = {
   rustc: version('rustc'),
   'wasm-pack': version('wasm-pack'),
   'wasm-bindgen': readCrate('Cargo.lock').match(/name = "wasm-bindgen"\nversion = "([^"]+)"/)[1],
};
const pinnedRustc = readCrate('rust-toolchain.toml').match(/channel = "([^"]+)"/)[1];
if (toolchain.rustc !== pinnedRustc || toolchain['wasm-pack'] !== WASM_PACK_VERSION) {
   throw new Error(
      `regen: requires rustc ${pinnedRustc} and wasm-pack ${WASM_PACK_VERSION}, ` +
         `found ${toolchain.rustc} and ${toolchain['wasm-pack']}`,
   );
}

// Builds into pkgDir and returns the contents of the committed artifacts
function buildArtifacts(pkgDir) {
   execFileSync('wasm-pack', ['build', '--target', 'web', '--release', '--out-dir', pkgDir], {
      cwd: crateDir,
      stdio: 'inherit',
   });

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
      inputs.map((file) => [relative(path.join(crateDir, file)), sha256(fs.readFileSync(path.join(crateDir, file)))]),
   ),
   outputs: Object.fromEntries(
      Object.entries(artifacts).map(([name, content]) => [relative(path.join(outDir, name)), sha256(content)]),
   ),
};

const files = Object.fromEntries(
   Object.entries(artifacts).map(([name, content]) => [path.join(outDir, name), content]),
);
files[manifestPath] = `${JSON.stringify(manifest, null, 2)}\n`;

if (check) {
   const differ = Object.entries(files)
      .filter(([file, content]) => !fs.existsSync(file) || fs.readFileSync(file, 'utf8') !== content)
      .map(([file]) => relative(file));
   if (differ.length > 0) {
      console.error(`crux check: a rebuild from source does not match ${differ.join(', ')}`);
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
}
