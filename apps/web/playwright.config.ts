import { defineConfig, devices } from '@playwright/test';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

/**
 * Read environment variables from file.
 * https://github.com/motdotla/dotenv
 */
// import dotenv from 'dotenv';
// import path from 'path';
// dotenv.config({ path: path.resolve(__dirname, '.env') });

/* Anchor report + artifact paths to the project root regardless of cwd or
   config-file location. outputFolder (HTML report) is resolved relative to
   the config file, but outputDir (test artifacts) is resolved relative to
   the nearest package.json — they disagree when the config lives in apps/web
   but the test runner is invoked from the monorepo root. */
const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const runStamp = new Date().toISOString().replace(/[:.]/g, '-');
const runRoot = resolve(projectRoot, 'playwright-report', runStamp);

/**
 * See https://playwright.dev/docs/test-configuration.
 */
export default defineConfig({
  testDir: './tests',
  /* Run tests in files in parallel */
  fullyParallel: true,
  /* Fail the build on CI if you accidentally left test.only in the source code. */
  forbidOnly: !!process.env.CI,
  /* Retry once locally (and twice on CI) so flakes surface a trace instead
     of an opaque timeout. */
  retries: process.env.CI ? 2 : 1,
  /* Opt out of parallel tests on CI. */
  workers: process.env.CI ? 1 : 4,
  /* Each run gets its own timestamped folder containing both the HTML
     report and per-test artifacts (trace/video/screenshot), so historical
     runs are preserved side-by-side. */
  reporter: [
    ['html', {
      outputFolder: resolve(runRoot, 'html'),
      open: 'on-failure',
    }],
  ],
  outputDir: resolve(runRoot, 'artifacts'),
  /* Shared settings for all the projects below. See https://playwright.dev/docs/api/class-testoptions. */
  use: {
    /* Base URL to use in actions like `await page.goto('/')`. */
    // baseURL: 'http://localhost:3000',

    /* Keep trace/screenshot/video from the first failed attempt even if a
       retry later succeeds — critical for debugging flakes where the
       failure disappears on retry. */
    trace: 'retain-on-first-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },

  /* Configure projects for major browsers */
  projects: [
    {
      name: 'local',
      use: {
        ...devices['Desktop Chrome'],
        // QCTestClient marker lets the server's PWTesty_ prefix guard
        // recognize these e2e tests as a known test client.
        userAgent: `${devices['Desktop Chrome'].userAgent} QCTestClient`,
        baseURL: 'https://t1.quickcrypt.org:4200',
        apiURL: 'https://test.quickcrypt.org/v1', // should lookup from project environment
        ignoreHTTPSErrors: true
      }
    },

    {
      name: 'prod',
      use: {
        ...devices['Desktop Chrome'],
        userAgent: `${devices['Desktop Chrome'].userAgent} QCTestClient`,
        baseURL: 'https://quickcrypt.org',
        apiURL: 'https://quickcrypt.org/v1', // should lookup from project environment
        ignoreHTTPSErrors: true
      },
    },

    {
      name: 'unit chrome',
      use: {
        ...devices['Desktop Chrome'],
        baseURL: 'https://t1.quickcrypt.org:9876',
        ignoreHTTPSErrors: true
      }
    },

    {
      name: 'unit safari',
      use: {
        ...devices['Desktop Safari'],
        baseURL: 'https://t1.quickcrypt.org:9876',
        ignoreHTTPSErrors: true
      }
    },

    {
      name: 'unit firefox',
      use: {
        ...devices['Desktop Firefox'],
        baseURL: 'https://t1.quickcrypt.org:9876',
        ignoreHTTPSErrors: true
      }
    },

    // {
    //   name: 'firefox',
    //   use: { ...devices['Desktop Firefox'] },
    // },

    // {
    //   name: 'webkit',
    //   use: { ...devices['Desktop Safari'] },
    // },

    /* Test against mobile viewports. */
    // {
    //   name: 'Mobile Chrome',
    //   use: { ...devices['Pixel 5'] },
    // },
    // {
    //   name: 'Mobile Safari',
    //   use: { ...devices['iPhone 12'] },
    // },

    /* Test against branded browsers. */
    // {
    //   name: 'Microsoft Edge',
    //   use: { ...devices['Desktop Edge'], channel: 'msedge' },
    // },
    // {
    //   name: 'Google Chrome',
    //   use: { ...devices['Desktop Chrome'], channel: 'chrome' },
    // },
  ],

  /* Run your local dev server before starting the tests */
  // webServer: {
  //   command: 'npm run start',
  //   url: 'http://localhost:3000',
  //   reuseExistingServer: !process.env.CI,
  // },
});
