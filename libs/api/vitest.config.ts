import { defineConfig, configDefaults } from 'vitest/config';

export default defineConfig({
   resolve: {
      alias: {
         '@qcrypt/crypto/consts': './libs/crypto/src/lib/cipher.consts.ts',
         '@qcrypt/crypto': './libs/crypto/src/index.ts'
      }
   },
   test: {
      exclude: [...configDefaults.exclude, 'tmp/**'],
      globals: true,
      include: ['libs/api/src/**/*.spec.ts'],
      testTimeout: 60000,
   },
});
