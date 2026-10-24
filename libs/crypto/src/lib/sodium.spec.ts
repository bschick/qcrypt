import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

describe('sodium manifest', () => {
   const repoRoot = fileURLToPath(new URL('../../../../', import.meta.url));
   const manifest = JSON.parse(readFileSync(`${repoRoot}libs/crypto/sodium/manifest.json`, 'utf8'));
   const recorded: [string, string][] = Object.entries({ ...manifest.inputs, ...manifest.outputs });

   it('lists every sodium input and vendored package file', () => {
      expect(Object.keys(manifest.inputs).sort()).toEqual(
         ['Containerfile', 'bun.lock', 'regen.mjs'].map((file) => `libs/crypto/sodium/${file}`),
      );
      const packaged = ['libsodium', 'libsodium-wrappers'].flatMap((name) =>
         readdirSync(`${repoRoot}libs/crypto/sodium/${name}`, { recursive: true, withFileTypes: true })
            .filter((entry) => entry.isFile())
            .map((entry) => relative(repoRoot, join(entry.parentPath, entry.name))),
      );
      expect(Object.keys(manifest.outputs).sort()).toEqual(packaged.sort());
   });

   // A mismatch means the sodium inputs or packages changed without running pnpm build:libs:sodium
   it.each(recorded)('%s matches manifest.json', (file, hash) => {
      const actual = createHash('sha256')
         .update(readFileSync(`${repoRoot}${file}`))
         .digest('hex');
      expect(actual).toBe(hash);
   });
});
