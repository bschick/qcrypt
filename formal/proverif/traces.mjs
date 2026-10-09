import { fileURLToPath } from 'node:url';
import * as fs from 'node:fs';
import * as path from 'node:path';

// Lists every trace in the ProVerif output that run.mjs saved, query by query, with each query's
// result, so that each trace can be read and checked against what its variant claims.
//
//   node formal/proverif/traces.mjs [--compact] [--all-steps] [--width=N] [filter ...]
//
// A filter keeps the output files whose name contains it, for example `account-login-net`.
// Each trace lists its events, the messages received from the attacker or over a private channel,
// and its table operations, in trace order. A failed reconstruction prints the partial trace it
// built. --compact shortens each message to its channel and label, keeps only the writes to the
// users, recov, creds and pins tables, and drops Rcv events. --all-steps adds outputs to the
// attacker and fresh names. --width sets where long lines are cut (default 220).

const modelDir = path.dirname(fileURLToPath(import.meta.url));
const outDir = path.resolve(modelDir, '../../dist/proverif');
const args = process.argv.slice(2);
const compact = args.includes('--compact');
const allSteps = args.includes('--all-steps');
const widthArg = args.find((arg) => arg.startsWith('--width='));
const width = widthArg ? Number(widthArg.slice('--width='.length)) : 220;
const filters = args.filter((arg) => !arg.startsWith('--'));

const keptInserts = /^insert (users|recov|creds|pins)\(/;

function clip(line) {
   return line.length > width ? `${line.slice(0, width)} …` : line;
}

// Shortens "in(c, m)" or "out(c, m)" to the channel and the message's label: the first
// upper-case constant of 3+ characters that is not part of a "~M_n" placeholder
function shortMessage(step) {
   const verb = step.slice(0, step.indexOf('('));
   const channel = step.slice(verb.length + 1, step.indexOf(','));
   const label = step.match(/(?<![~\w])([A-Z][A-Z0-9_]{2,})\b/);
   return `${verb}(${channel}) ${label ? label[1] : '?'}`;
}

function summarizeStep(line) {
   const step = line.trim().replace(/ in copy \w+(, \w+)*/g, '');
   if (step.startsWith('event ')) {
      return compact && step.startsWith('event Rcv(') ? null : step;
   }
   // A message on a private channel is printed as one "out(...) received at" step
   const delivered = step.startsWith('out(') && step.includes(' received at ');
   if (step.startsWith('in(') || delivered) {
      return compact ? shortMessage(step) : step;
   }
   if (step.startsWith('insert ') || step.startsWith('get ')) {
      return !compact || keptInserts.test(step) ? step : null;
   }
   if (allSteps && (step.startsWith('out(') || step.startsWith('new '))) {
      return step;
   }
   return null;
}

// ProVerif prints each reconstructed trace between the "set traceDisplay = long." hint and
// "A trace has been found."; a failed reconstruction ends with "Could not find a trace".
function printTraces(file) {
   console.log(`\n######## ${path.basename(file, '.out')}`);
   let traceSteps = null;
   let traceCount = 0;
   let failedReconstructions = 0;
   for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
      if (line.startsWith('Starting query ')) {
         traceCount = 0;
         failedReconstructions = 0;
         console.log(`\n== ${clip(line.slice('Starting query '.length))}`);
      } else if (line.startsWith('  set traceDisplay = long.')) {
         traceSteps = [];
      } else if (line.startsWith('A trace has been found.')) {
         traceCount++;
         console.log(`   trace ${traceCount}:`);
         for (const step of traceSteps ?? []) {
            console.log(`     ${clip(step)}`);
         }
         traceSteps = null;
      } else if (line.startsWith('Could not find a trace')) {
         // The steps before "Blocked!" show how far the reconstruction got
         failedReconstructions++;
         console.log(`   failed reconstruction ${failedReconstructions}, partial trace:`);
         for (const step of traceSteps ?? []) {
            console.log(`     ${clip(step)}`);
         }
         traceSteps = null;
      } else if (line.startsWith('RESULT ')) {
         const failed = failedReconstructions ? ` [${failedReconstructions} failed reconstruction(s)]` : '';
         console.log(`   ${clip(line)}${failed}`);
         traceSteps = null;
      } else if (traceSteps) {
         const summary = summarizeStep(line);
         if (summary) {
            traceSteps.push(summary);
         }
      }
   }
}

const files = fs
   .readdirSync(outDir)
   .filter((name) => name.endsWith('.out'))
   .filter((name) => filters.length === 0 || filters.some((filter) => name.includes(filter)))
   .sort();
if (files.length === 0) {
   console.error(`no ProVerif output in ${outDir} matches; run run.mjs first`);
   process.exitCode = 1;
}
for (const name of files) {
   printTraces(path.join(outDir, name));
}
