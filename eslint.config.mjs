import playwright from 'eslint-plugin-playwright';
import tsParser from '@typescript-eslint/parser';

export default [
   {
      files: ['apps/web/tests/**/*.ts'],
      languageOptions: { parser: tsParser },
      plugins: { playwright },
      rules: {
         'playwright/missing-playwright-await': 'error',
      },
   },
];
