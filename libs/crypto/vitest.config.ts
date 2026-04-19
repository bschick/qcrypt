import { defineConfig, configDefaults } from 'vitest/config';

export default defineConfig({
   test: {
      exclude: [...configDefaults.exclude, 'tmp/**'],
      globals: true,
      include: ['libs/crypto/src/**/*.spec.ts'],
      testTimeout: 60000,
   },
});
