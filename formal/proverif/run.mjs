import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

// Builds every variant of every *.pv.m4 model, runs ProVerif on each, and compares its RESULT lines
// with the EXPECTPV block that m4 places in the generated file. Exits non-zero on any mismatch,
// timeout, or error.
//
//   node formal/proverif/run.mjs [--print] [filter ...]
//
// A filter keeps the variants whose name contains it. --print shows each variant's actual RESULT
// lines as an EXPECTPV block, for reviewing and pasting into the template; it never edits a file.

const modelDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(modelDir, '../..');
const outDir = path.join(repoRoot, 'dist/proverif');
const libPath = path.join(modelDir, 'lib/qcrypt');
const timeoutSecs = Number(process.env.QC_PROVERIF_TIMEOUT ?? 900);
const args = process.argv.slice(2);
const printMode = args.includes('--print');
const filters = args.filter((arg) => !arg.startsWith('--'));

function findProverif() {
   const candidates = [process.env.PROVERIF, 'proverif', path.join(os.homedir(), '.opam/default/bin/proverif')];
   const found = candidates.find((cmd) => cmd && spawnSync(cmd, ['-help']).status === 0);
   if (!found) {
      throw new Error('proverif not found: install it with `opam install proverif` or set PROVERIF');
   }
   return found;
}

// Each template lists its variants between "VARIANTS:" and "END VARIANTS", one per line, as a
// name followed by the m4 flags that select it
function readVariants(template) {
   const text = fs.readFileSync(template, 'utf8');
   const block = text.match(/VARIANTS:\n([\s\S]*?)\n\s*END VARIANTS/);
   if (!block) {
      throw new Error(`${path.basename(template)} has no VARIANTS block`);
   }
   return block[1]
      .split('\n')
      .map((line) => line.trim().split(/\s+/))
      .filter((fields) => fields[0])
      .map(([name, ...flags]) => ({ template, name, flags }));
}

// The flag VARIANT_<name> selects the variant's EXPECTPV block in the template
function generate(variant) {
   const defines = [...variant.flags, `VARIANT_${variant.name.replaceAll('-', '_')}`].map((flag) => `-D${flag}`);
   const result = spawnSync('m4', ['-P', ...defines, variant.template], { encoding: 'utf8' });
   if (result.status !== 0) {
      throw new Error(`m4 failed for ${variant.name}: ${result.stderr}`);
   }
   const base = path.basename(variant.template, '.pv.m4');
   const pvFile = path.join(outDir, `${base}-${variant.name}.pv`);
   fs.writeFileSync(pvFile, result.stdout);
   return pvFile;
}

function expectedResults(pvFile) {
   const block = fs.readFileSync(pvFile, 'utf8').match(/EXPECTPV\n([\s\S]*?)\nEND/);
   return block
      ? block[1]
           .split('\n')
           .map((line) => line.trim())
           .filter((line) => line.startsWith('RESULT'))
      : null;
}

function runProverif(proverif, pvFile) {
   return new Promise((resolve) => {
      const started = Date.now();
      const child = spawn(proverif, ['-lib', libPath, pvFile]);
      let output = '';
      let timedOut = false;
      const timer = setTimeout(() => {
         timedOut = true;
         child.kill('SIGKILL');
      }, timeoutSecs * 1000);
      child.stdout.on('data', (data) => {
         output += data;
      });
      child.stderr.on('data', (data) => {
         output += data;
      });
      child.on('close', (code) => {
         clearTimeout(timer);
         fs.writeFileSync(pvFile.replace(/\.pv$/, '.out'), output);
         const results = output
            .split('\n')
            .map((line) => line.trim())
            .filter((line) => line.startsWith('RESULT'));
         resolve({ code, timedOut, results, output, secs: (Date.now() - started) / 1000 });
      });
   });
}

function compare(expected, actual) {
   const missing = expected.filter((line) => !actual.includes(line));
   const unexpected = actual.filter((line) => !expected.includes(line));
   return { missing, unexpected };
}

// Runs up to `limit` variants at once; ProVerif itself is single threaded
async function runAll(proverif, variants, limit) {
   const outcomes = new Array(variants.length);
   let next = 0;
   async function worker() {
      while (next < variants.length) {
         const index = next;
         next += 1;
         const variant = variants[index];
         const pvFile = generate(variant);
         const run = await runProverif(proverif, pvFile);
         outcomes[index] = { variant, pvFile, expected: expectedResults(pvFile), ...run };
         console.error(`  ${variant.name} done in ${run.secs.toFixed(1)}s`);
      }
   }
   await Promise.all(Array.from({ length: Math.min(limit, variants.length) }, worker));
   return outcomes;
}

function report(outcome) {
   const problems = [];
   if (outcome.timedOut) {
      problems.push(`timed out after ${timeoutSecs}s`);
   } else if (outcome.code !== 0) {
      const error = outcome.output.split('\n').find((line) => line.startsWith('Error')) ?? `exit ${outcome.code}`;
      problems.push(error);
   } else if (!outcome.expected) {
      problems.push('no EXPECTPV block');
   } else {
      const { missing, unexpected } = compare(outcome.expected, outcome.results);
      for (const line of missing) {
         problems.push(`expected: ${line}`);
      }
      for (const line of unexpected) {
         problems.push(`actual:   ${line}`);
      }
   }
   return problems;
}

async function main() {
   const proverif = findProverif();
   fs.mkdirSync(outDir, { recursive: true });

   const templates = fs
      .readdirSync(modelDir)
      .filter((file) => file.endsWith('.pv.m4'))
      .sort()
      .map((file) => path.join(modelDir, file));
   const variants = templates
      .flatMap(readVariants)
      .filter((variant) => !filters.length || filters.some((filter) => variant.name.includes(filter)));

   const limit = Math.max(1, Math.floor(os.availableParallelism() / 2));
   console.error(
      `Running ${variants.length} variants, ${limit} at a time (output in ${path.relative(repoRoot, outDir)})`,
   );
   const outcomes = await runAll(proverif, variants, limit);

   let failures = 0;
   for (const outcome of outcomes) {
      const label = `${path.basename(outcome.variant.template, '.pv.m4')}/${outcome.variant.name}`;
      if (printMode) {
         console.log(`m4_ifdef({{VARIANT_${outcome.variant.name.replaceAll('-', '_')}}}, {{(* EXPECTPV`);
         console.log(outcome.results.join('\n'));
         console.log('END *)}})');
      } else {
         const problems = report(outcome);
         console.log(`${problems.length ? 'FAIL' : 'ok  '}  ${outcome.secs.toFixed(1).padStart(6)}s  ${label}`);
         for (const problem of problems) {
            console.log(`        ${problem}`);
         }
         failures += problems.length ? 1 : 0;
      }
   }

   if (!printMode) {
      console.log(
         failures ? `\n${failures} of ${outcomes.length} variants failed` : `\nAll ${outcomes.length} variants passed`,
      );
      process.exitCode = failures ? 1 : 0;
   }
}

await main();
