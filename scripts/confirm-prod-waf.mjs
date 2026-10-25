#!/usr/bin/env node
// Runs a prod test command once the user confirms the prod WAF rate-limit rule is set to Count. A rule set to
// Block makes many prod tests fail. `echo y | pnpm test:server:prod` answers the prompt, and CI is not asked.
import { spawn } from 'node:child_process';
import * as readline from 'node:readline';

const RULE = 'APIRateLimit';
const [command, ...args] = process.argv.slice(2);

async function confirmed() {
   const prompt = readline.createInterface({ input: process.stdin, output: process.stdout });
   const answer = await new Promise((resolve) => {
      prompt.question(`Is the prod WAF ${RULE} rule set to Count? [y/N] `, resolve);
      // Resolves with no answer when input ends first
      prompt.on('close', () => resolve(''));
   });
   prompt.close();
   // A terminal echoes what the user typed, but piped input is not echoed
   if (!process.stdin.isTTY) {
      console.log(answer.trim());
   }
   return ['y', 'yes'].includes(answer.trim().toLowerCase());
}

if (process.env.CI) {
   console.log(`prod tests: not asking in CI. The prod WAF ${RULE} rule must be set to Count.`);
} else if (!(await confirmed())) {
   console.error(`prod tests: set the prod WAF ${RULE} rule to Count, then run again.`);
   process.exit(1);
}

// The command handles Ctrl-C itself, so the reminder below still prints after an interrupted run
process.on('SIGINT', () => {});
const child = spawn(command, args, { stdio: 'inherit' });
child.on('error', (error) => {
   console.error(`prod tests: could not run ${command}: ${error.message}`);
   process.exit(1);
});
child.on('exit', (code) => {
   console.log(`\nprod tests: set the prod WAF ${RULE} rule back to Block.`);
   process.exit(code ?? 1);
});
