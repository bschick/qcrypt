import { defineConfig, configDefaults } from 'vitest/config';

export default defineConfig({
   test: {
      exclude: [...configDefaults.exclude, 'tmp/**'],
      include: ['apps/server/spec/**/*.spec.ts'],
      testTimeout: 60000,
   },
});
