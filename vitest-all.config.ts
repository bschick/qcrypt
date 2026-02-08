import { defineConfig } from 'vitest/config';
import { playwright } from '@vitest/browser-playwright';

export default defineConfig({
  optimizeDeps: {
    include: [
      '@angular/core/testing',
      '@angular/platform-browser-dynamic/testing',
    ],
  },
  test: {
    globals: true,
    testTimeout: 30000,
    exclude: ['tmp/**', 'node_modules/**'],
    browser: {
      enabled: true,
      headless: true,
      provider: playwright(),
      instances: [
        { browser: 'chromium' },
        { browser: 'firefox' },
      ],
    },
  },
});
