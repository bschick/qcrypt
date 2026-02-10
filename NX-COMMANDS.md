# Nx Command Reference

This is an Nx monorepo. The app source lives in `apps/web/`, with shared library stubs in `libs/`. Your existing `pnpm` commands still work — the scripts in `package.json` call `nx` under the hood. You can use either form:

| What | pnpm script (unchanged) | Direct Nx equivalent |
|------|------------------------|---------------------|
| Build | `pnpm build` | `pnpm nx build web` |
| Serve | `pnpm serve` | `pnpm nx serve web` |
| Unit tests (chromium) | `pnpm test` | `pnpm nx test web` |
| Unit tests (watch) | `pnpm test:watch` | `pnpm nx test web --watch` |
| Unit tests (all browsers) | `pnpm test:all` | `pnpm nx test web --runnerConfig=apps/web/vitest-all.config.ts` |
| E2E tests | `pnpm test:e2e` | *(no Nx equivalent — Playwright runs directly)* |
| Fuzz tests | `pnpm test:fuzz` | *(no Nx equivalent — Playwright runs directly)* |
| Build CLI | `pnpm build:cli` | `pnpm nx build cli` |
| Build CLI (minified) | `pnpm build:cli:min` | `pnpm nx build-min cli` |
| Build server | `pnpm build:server` | `pnpm nx build server` |
| Build server (minified) | `pnpm build:server:min` | `pnpm nx build-min server` |
| Server tests | `pnpm test:server` | `pnpm nx test server` |
| Server tests (prod) | `pnpm test:server:prod` | `pnpm nx test-prod server` |

The `pnpm nx` form is useful when you want to pass extra flags (like `--skip-nx-cache` or `--configuration development`) or when you have multiple projects later.

One thing to note: `--runner-config` (kebab-case) doesn't work with `nx` — you must use `--runnerConfig=` (camelCase). The `pnpm test:all` script already has this fixed.
