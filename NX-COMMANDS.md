# Nx Command Reference

This is an Nx monorepo. The app source lives in `apps/web/`, with shared library stubs in `libs/`. Your existing `pnpm` commands still work — the scripts in `package.json` call `nx` under the hood. You can use either form:

| What | pnpm script (unchanged) | Direct Nx equivalent |
|------|------------------------|---------------------|
| All unit tests | `pnpm test` | *(runs test:web, test:server, test:lib, test:cli)* |
| Web build | `pnpm build:web` | `pnpm nx build web` |
| Web unit tests (chromium) | `pnpm test:web` | `pnpm nx test web` |
| Web unit tests (watch) | `pnpm test:web:watch` | `pnpm nx test web --watch` |
| Web unit tests (all browsers) | `pnpm test:web:all` | `pnpm nx test web --runnerConfig=apps/web/vitest-all.config.ts` |
| Web E2E tests | `pnpm test:e2e` | *(no Nx equivalent — Playwright runs directly)* |
| Server build | `pnpm build:server` | `pnpm nx build server` |
| Server build (minified) | `pnpm build:server:min` | `pnpm nx build-min server` |
| Server serve local | `pnpm serve` | `pnpm nx serve web` |
| Server unit tests | `pnpm test:server` | `pnpm nx test server` |
| Server unit tests (prod) | `pnpm test:server:prod` | `pnpm nx test-prod server` |
| Server API fuzz tests | `pnpm test:fuzz` | *(no Nx equivalent — Playwright runs directly)* |
| CLI build | `pnpm build:cli` | `pnpm nx build cli` |
| CLI build (minified) | `pnpm build:cli:min` | `pnpm nx build-min cli` |
| CLI unit tests | `pnpm test:cli` | `pnpm nx test cli` |
| Library unit tests (all libs) | `pnpm test:lib` | *(runs test:lib:crypto)* |
| Crypto library unit tests | `pnpm test:lib:crypto` | `pnpm nx test crypto` |

The `pnpm nx` form is useful when you want to pass extra flags (like `--skip-nx-cache` or `--configuration development`) or when you have multiple projects later.

One thing to note: `--runner-config` (kebab-case) doesn't work with `nx` — you must use `--runnerConfig=` (camelCase). The `pnpm test:all` script already has this fixed.

## Upgrading Packages

| What | Command |
|------|---------|
| Check outdated | `pnpm outdated` |
| Upgrade interactively (pick & choose) | `pnpm update --interactive --latest` |
| Upgrade all to latest | `pnpm update --latest` |
| Upgrade a specific package | `pnpm update <package> --latest` |
| **Upgrade Nx** (use Nx migrate tool) | `pnpm nx migrate latest && pnpm install && pnpm nx migrate --run-migrations --if-exists` |

Notes:
- `--latest` allows major version bumps; without it, pnpm stays within existing semver ranges in `package.json`.
- Always upgrade Nx via `nx migrate` rather than `pnpm update` — it runs code migrations (schematics) that update config files and source code for breaking changes.
- After any upgrade, run `pnpm build:target` and `pnpm test:target` to verify nothing broke.
