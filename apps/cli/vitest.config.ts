import { defineConfig, configDefaults } from 'vitest/config';

export default defineConfig({
   test: {
      exclude: [...configDefaults.exclude, 'tmp/**'],
      include: ['apps/cli/tests/**/*.spec.ts'],
      testTimeout: 60000,
   },
});
