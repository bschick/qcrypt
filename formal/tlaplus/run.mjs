import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

// Translates the PlusCal in every *.tla model, runs TLC once per variant and property, and
// compares each outcome with the VARIANTS block at the end of the model. Exits non-zero on any
// mismatch, timeout, or error.
//
//   node formal/tlaplus/run.mjs [--print] [filter ...]
//
// A filter keeps the variants whose "model/name" contains it. --print shows each variant's actual
// outcomes as a VARIANTS line, for reviewing and pasting into the model; it never edits a model.
//
// QC_TLC_TIMEOUT sets the per-run timeout in seconds. QC_TLC_WORKERS sets TLC's worker threads and
// QC_TLC_HEAP the JVM heap as an -Xmx value. The TLA+ tools jar is downloaded once into
// $XDG_CACHE_HOME/qcrypt (default ~/.cache/qcrypt), or taken from QC_TLC_JAR, and checked against
// its SHA-256 on every run.

const TOOLS_VERSION = '1.7.4';
const TOOLS_URL = `https://github.com/tlaplus/tlaplus/releases/download/v${TOOLS_VERSION}/tla2tools.jar`;
const TOOLS_SHA256 = '936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88';
const MIN_JAVA = 11;

const modelDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(modelDir, '../..');
const outDir = path.join(repoRoot, 'dist/tlaplus');
const cacheDir = process.env.XDG_CACHE_HOME ?? path.join(os.homedir(), '.cache');
const jarPath = process.env.QC_TLC_JAR ?? path.join(cacheDir, 'qcrypt', `tla2tools-${TOOLS_VERSION}.jar`);
const timeoutSecs = Number(process.env.QC_TLC_TIMEOUT ?? 600);
const workers = Math.max(1, Math.floor(Number(process.env.QC_TLC_WORKERS ?? os.availableParallelism() / 2)));
const heap = process.env.QC_TLC_HEAP ?? '2g';
const args = process.argv.slice(2);
const printMode = args.includes('--print');
const filters = args.filter((arg) => !arg.startsWith('--'));

function javaMajor(java) {
   const probe = spawnSync(java, ['-version'], { encoding: 'utf8' });
   const match = probe.status === 0 ? /version "(\d+)(?:\.(\d+))?/.exec(probe.stderr + probe.stdout) : null;
   // Java 8 and earlier print the version as 1.x
   return match ? Number(match[1] === '1' ? match[2] : match[1]) : 0;
}

function findJava() {
   const fromHome = process.env.JAVA_HOME ? path.join(process.env.JAVA_HOME, 'bin/java') : undefined;
   const candidates = [process.env.JAVA, fromHome, 'java'];
   const found = candidates.find((cmd) => cmd && javaMajor(cmd) >= MIN_JAVA);
   if (!found) {
      throw new Error(
         `Java ${MIN_JAVA} or later not found: install a JRE (for example openjdk-21-jre-headless) or set JAVA`,
      );
   }
   return found;
}

async function ensureJar() {
   fs.mkdirSync(outDir, { recursive: true });
   if (!fs.existsSync(jarPath)) {
      fs.mkdirSync(path.dirname(jarPath), { recursive: true });
      console.error(`Downloading TLA+ tools ${TOOLS_VERSION} to ${jarPath}`);
      const response = await fetch(TOOLS_URL);
      if (!response.ok) {
         throw new Error(`download failed with ${response.status}: ${TOOLS_URL}`);
      }
      fs.writeFileSync(jarPath, Buffer.from(await response.arrayBuffer()));
   }
   const actual = createHash('sha256').update(fs.readFileSync(jarPath)).digest('hex');
   if (actual !== TOOLS_SHA256) {
      fs.rmSync(jarPath);
      throw new Error(`${path.basename(jarPath)} has SHA-256 ${actual}, expected ${TOOLS_SHA256}; it was deleted`);
   }
}

function findModels() {
   return fs
      .readdirSync(modelDir)
      .filter((file) => file.endsWith('.tla'))
      .sort()
      .map((file) => path.join(modelDir, file));
}

function modelId(modelFile) {
   return path.basename(modelFile, '.tla').toLowerCase();
}

// A variant's constants start from the DEFAULTS line. Each NAME=value is copied into the TLC
// configuration as written, so a set value must contain no spaces.
function readVariants(modelFile) {
   const text = fs.readFileSync(modelFile, 'utf8');
   const block = text.match(/VARIANTS\n([\s\S]*?)\nEND VARIANTS/);
   if (!block) {
      throw new Error(`${path.basename(modelFile)} has no VARIANTS block`);
   }
   const defaults = {};
   const variants = [];
   for (const line of block[1].split('\n')) {
      const [name, ...tokens] = line.trim().split(/\s+/);
      const given = Object.fromEntries(
         tokens.filter((token) => token.includes('=')).map((token) => token.split(/=(.*)/s).slice(0, 2)),
      );
      const expected = Object.fromEntries(
         tokens.filter((token) => /^\w+:(holds|violated)$/.test(token)).map((token) => token.split(':')),
      );
      if (name === 'DEFAULTS') {
         Object.assign(defaults, given);
      } else if (name) {
         variants.push({
            modelFile,
            model: modelId(modelFile),
            name,
            given,
            constants: { ...defaults, ...given },
            expected,
         });
      }
   }
   return variants;
}

// pcal.trans rewrites the module in place, so it runs on a copy under dist/
function translate(java, modelFile) {
   const copy = path.join(outDir, path.basename(modelFile));
   fs.copyFileSync(modelFile, copy);
   const result = spawnSync(java, ['-cp', jarPath, 'pcal.trans', '-nocfg', copy], { encoding: 'utf8' });
   if (result.status !== 0 || !/Translation completed/.test(result.stdout)) {
      throw new Error(`PlusCal translation failed for ${path.basename(modelFile)}:\n${result.stdout}${result.stderr}`);
   }
   return copy;
}

function runTlc(java, module, variant, property) {
   return new Promise((resolve) => {
      const started = Date.now();
      const runId = `${variant.model}-${variant.name}-${property}`;
      const cfg = path.join(outDir, `${runId}.cfg`);
      const constants = Object.entries(variant.constants).map(([name, value]) => `${name} = ${value}`);
      fs.writeFileSync(
         cfg,
         `${['SPECIFICATION Spec', 'CONSTANTS', ...constants, `INVARIANT ${property}`].join('\n')}\n`,
      );
      // TLC keeps its state queue under the metadir and deletes it on cleanup, so two runs sharing
      // one directory delete each other's files
      const metadir = path.join(outDir, 'states', runId);
      const tlcArgs = [
         '-deadlock',
         '-cleanup',
         '-workers',
         String(workers),
         '-metadir',
         metadir,
         '-config',
         cfg,
         module,
      ];
      const child = spawn(java, [`-Xmx${heap}`, '-XX:+UseParallelGC', '-cp', jarPath, 'tlc2.TLC', ...tlcArgs], {
         cwd: outDir,
      });
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
      child.on('close', (code, signal) => {
         clearTimeout(timer);
         fs.writeFileSync(path.join(outDir, `${runId}.out`), output);
         let outcome = null;
         if (/No error has been found/.test(output)) {
            outcome = 'holds';
         } else if (output.includes(`Invariant ${property} is violated`)) {
            outcome = 'violated';
         }
         const progress = [...output.matchAll(/([\d,]+) distinct states found/g)].at(-1);
         const states = progress ? Number(progress[1].replaceAll(',', '')) : 0;
         resolve({ property, outcome, states, timedOut, code, signal, output, secs: (Date.now() - started) / 1000 });
      });
   });
}

function problemsOf(variant, runs) {
   const problems = [];
   for (const run of runs) {
      if (run.timedOut) {
         problems.push(`${run.property}: timed out after ${timeoutSecs}s`);
      } else if (run.outcome === null) {
         const error =
            run.output.split('\n').find((line) => line.startsWith('Error')) ?? `exit ${run.code ?? run.signal}`;
         problems.push(`${run.property}: ${error}`);
      } else if (run.outcome !== variant.expected[run.property]) {
         problems.push(`${run.property}: expected ${variant.expected[run.property]}, got ${run.outcome}`);
      }
   }
   return problems;
}

async function main() {
   const java = findJava();
   await ensureJar();

   const selected = findModels()
      .flatMap(readVariants)
      .filter(
         (variant) => !filters.length || filters.some((filter) => `${variant.model}/${variant.name}`.includes(filter)),
      );
   const modules = new Map();
   for (const modelFile of new Set(selected.map((variant) => variant.modelFile))) {
      modules.set(modelFile, translate(java, modelFile));
   }
   console.error(
      `Running ${selected.length} variants with ${workers} TLC workers (output in ${path.relative(repoRoot, outDir)})`,
   );

   let failures = 0;
   for (const variant of selected) {
      const label = `${variant.model}/${variant.name}`;
      const runs = [];
      for (const property of Object.keys(variant.expected)) {
         runs.push(await runTlc(java, modules.get(variant.modelFile), variant, property));
      }
      const secs = runs.reduce((sum, run) => sum + run.secs, 0);
      const largest = Math.max(...runs.map((run) => run.states));
      if (printMode) {
         const given = Object.entries(variant.given).map(([name, value]) => `${name}=${value}`);
         const outcomes = runs.map((run) => `${run.property}:${run.outcome ?? 'error'}`);
         console.log([variant.name, ...given, ...outcomes].join(' '));
      } else {
         const problems = problemsOf(variant, runs);
         const status = problems.length ? 'FAIL' : 'ok  ';
         console.log(
            `${status}  ${secs.toFixed(1).padStart(6)}s  ${largest.toLocaleString().padStart(10)} states  ${label}`,
         );
         for (const problem of problems) {
            console.log(`        ${problem}`);
         }
         failures += problems.length ? 1 : 0;
      }
   }

   if (!printMode) {
      console.log(
         failures ? `\n${failures} of ${selected.length} variants failed` : `\nAll ${selected.length} variants passed`,
      );
      process.exitCode = failures ? 1 : 0;
   }
}

await main();
