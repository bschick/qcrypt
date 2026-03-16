import { defineConfig } from 'vitest/config';

export default defineConfig({
   test: {
      globals: true,
      include: ['libs/crypto/src/**/*.spec.ts'],
      testTimeout: 60000,
   },
});
