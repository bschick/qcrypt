// AI-Assist: 100% Claude Code Generated
//
// Replaces generated vector blocks in spec files, matched by name rather than by
// position or brace counting, so a renamed or reordered block fails loudly instead
// of overwriting the wrong vectors.
//
// A spec file marks each replaceable region as:
//
//    // BEGIN GENERATED: <name>
//    ...anything...
//    // END GENERATED: <name>
//
// Generators collect blocks with collectBlock() in gen_helpers.ts and call
// spliceInto() when run with --write.

import { readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

export type GeneratedBlock = {
   readonly name: string;
   readonly lines: string[];
};

function markerPattern(name: string): RegExp {
   const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
   return new RegExp(`([ \\t]*// BEGIN GENERATED: ${escaped}\\n)[\\s\\S]*?([ \\t]*// END GENERATED: ${escaped}\\n)`);
}

/**
 * Rewrites every named region of specPath with the matching block. Throws when a block
 * has no region or a region no block, since a silent skip would leave stale vectors that
 * still pass their tests.
 */
export function spliceInto(specPath: string, blocks: GeneratedBlock[], only?: string[]): void {
   let text = readFileSync(specPath, 'utf8');

   // Both directions are checked against every block, before any --only filter, so a
   // narrowed run still reports drift in the regions it is not about to rewrite
   // A block with no region is a version that has not been pinned here yet, so open one just
   // after the newest region sharing its base name. Anchoring to a sibling keeps the entry in
   // the array it belongs to; without a sibling there is nothing to infer a location from.
   for (const block of blocks.filter((candidate) => !markerPattern(candidate.name).test(text))) {
      const base = block.name.slice(block.name.indexOf(':') + 1);
      const siblings = [...text.matchAll(/([ \t]*)\/\/ END GENERATED: (v(\d+):.+)\n/g)].filter(
         (match) => match[2].slice(match[2].indexOf(':') + 1).trim() === base,
      );
      const anchor = siblings.sort((left, right) => Number(left[3]) - Number(right[3])).pop();
      if (!anchor) {
         throw new Error(
            `${specPath} has no region for ${block.name} and none for any other version of ` +
               `"${base}" to place it after, so add the BEGIN/END GENERATED pair by hand`,
         );
      }
      const indent = anchor[1];
      const opened = `${indent}// BEGIN GENERATED: ${block.name}\n${indent}// END GENERATED: ${block.name}\n`;
      text = text.replace(anchor[0], `${anchor[0]}${opened}`);
      console.error(`opened new region ${block.name} after ${anchor[2].trim()}`);
   }

   // Regions for versions this run does not generate are earlier versions' pinned vectors,
   // which must survive untouched, so only same-version regions are held to having a block
   const versions = new Set(blocks.map((block) => block.name.split(':')[0]));
   const present = [...text.matchAll(/\/\/ BEGIN GENERATED: (.+)\n/g)].map((match) => match[1].trim());
   const unfilled = present
      .filter((name) => versions.has(name.split(':')[0]))
      .filter((name) => !blocks.some((block) => block.name === name));
   if (unfilled.length) {
      throw new Error(`${specPath} marks regions this generator does not produce: ${unfilled.join(', ')}`);
   }

   let writing = blocks;
   if (only?.length) {
      const unknown = only.filter((name) => !blocks.some((block) => block.name === name));
      if (unknown.length) {
         throw new Error(`no generated block named: ${unknown.join(', ')}`);
      }
      writing = blocks.filter((block) => only.includes(block.name));
   }

   for (const block of writing) {
      text = text.replace(markerPattern(block.name), `$1${block.lines.join('\n')}\n$2`);
   }

   writeFileSync(specPath, text);
   console.error(`spliced ${writing.length} block(s) into ${specPath}: ${writing.map((b) => b.name).join(', ')}`);

   // Generated arrays are emitted on one line; formatting here keeps the spec committable
   // without a follow up command
   try {
      execFileSync('pnpm', ['exec', 'biome', 'check', '--write', specPath], { stdio: 'pipe' });
   } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      console.error(`WARNING: could not format ${specPath}, run pnpm check:fix by hand (${detail})`);
   }
}
