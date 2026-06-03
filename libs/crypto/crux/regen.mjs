import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as fs from 'node:fs';
import * as path from 'node:path';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const pkgDir = path.join(repoRoot, 'libs/crypto/crux/pkg');
const outDir = path.join(repoRoot, 'libs/crypto/src/lib/crux');

execSync('wasm-pack build libs/crypto/crux --target web --release', { cwd: repoRoot, stdio: 'inherit' });

fs.mkdirSync(outDir, { recursive: true });

const assetLine = "module_or_path = new URL('qc_crux_bg.wasm', import.meta.url);";
let glue = fs.readFileSync(path.join(pkgDir, 'qc_crux.js'), 'utf8');
if (!glue.includes(assetLine)) {
   throw new Error('regen: default-init asset line not found — wasm-bindgen glue format changed, update the neutering step');
}
glue = glue.replace(assetLine, "throw new Error('crux: call cruxReady() instead of the default init');");
fs.writeFileSync(path.join(outDir, 'qc_crux.js'), glue);
fs.copyFileSync(path.join(pkgDir, 'qc_crux.d.ts'), path.join(outDir, 'qc_crux.d.ts'));

const wasmBase64 = fs.readFileSync(path.join(pkgDir, 'qc_crux_bg.wasm')).toString('base64url');
fs.writeFileSync(path.join(outDir, 'wasm.ts'), `export const CRUX_WASM_BASE64 =\n   '${wasmBase64}';\n`);

console.log(`crux regenerated: glue + types + ${(wasmBase64.length / 1024).toFixed(0)} KB base64 wasm`);
