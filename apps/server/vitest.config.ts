import { defineConfig, configDefaults } from 'vitest/config';

export default defineConfig({
   resolve: {
      alias: {
         '@qcrypt/api': './libs/api/src/index.ts',
         '@qcrypt/crypto/consts': './libs/crypto/src/lib/cipher.consts.ts',
         '@qcrypt/crypto': './libs/crypto/src/index.ts'
      }
   },
   test: {
      exclude: [...configDefaults.exclude, 'tmp/**'],
      include: ['apps/server/spec/**/*.spec.ts'],
      testTimeout: 60000,
   },
});
