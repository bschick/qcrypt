# Nx Command Reference

This is an Nx monorepo. The app source lives in `apps/qcrypt/`, with shared library stubs in `libs/`. Your existing `pnpm` commands still work — the scripts in `package.json` call `nx` under the hood. You can use either form:

| What | pnpm script (unchanged) | Direct Nx equivalent |
|------|------------------------|---------------------|
| Build | `pnpm build` | `pnpm nx build qcrypt` |
| Serve | `pnpm serve` | `pnpm nx serve qcrypt` |
| Unit tests (chromium) | `pnpm test` | `pnpm nx test qcrypt` |
| Unit tests (watch) | `pnpm test:watch` | `pnpm nx test qcrypt --watch` |
| Unit tests (all browsers) | `pnpm test:all` | `pnpm nx test qcrypt --runnerConfig=apps/qcrypt/vitest-all.config.ts` |
| E2E tests | `pnpm test:e2e` | *(no Nx equivalent — Playwright runs directly)* |
| Fuzz tests | `pnpm test:fuzz` | *(no Nx equivalent — Playwright runs directly)* |

The `pnpm nx` form is useful when you want to pass extra flags (like `--skip-nx-cache` or `--configuration development`) or when you have multiple projects later.

One thing to note: `--runner-config` (kebab-case) doesn't work with `nx` — you must use `--runnerConfig=` (camelCase). The `pnpm test:all` script already has this fixed.
