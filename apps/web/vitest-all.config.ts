import { defineConfig } from 'vitest/config';
import { playwright } from '@vitest/browser-playwright';

export default defineConfig({
   optimizeDeps: {
      include: ['@angular/core/testing'],
   },
   test: {
      globals: true,
      testTimeout: 30000,
      browser: {
         enabled: true,
         headless: true,
         screenshotFailures: false,
         provider: playwright(),
         instances: [{ browser: 'chromium' }, { browser: 'firefox' }, { browser: 'webkit' }],
      },
   },
});
