import { defineConfig } from 'vitest/config';

export default defineConfig({
   test: {
      include: ['apps/qcrypt-server/spec/**/*.spec.ts'],
      testTimeout: 60000,
   },
});
