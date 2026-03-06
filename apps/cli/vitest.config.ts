import { defineConfig } from 'vitest/config';

export default defineConfig({
   test: {
      include: ['apps/cli/tests/**/*.spec.ts'],
      testTimeout: 60000,
   },
});
