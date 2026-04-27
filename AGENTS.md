# Agent Instructions for qcrypt Monorepo

This document provides instructions for Human or AI agents working on the `qcrypt` monorepo. For app-specific details, see the `AGENTS.md` in each app directory.

## 1. Monorepo Overview

`qcrypt` is an Nx monorepo managed with pnpm. It contains:

| Directory | Description |
|-----------|-------------|
| `apps/web/` | Angular single-page application for client-side text encryption/decryption ([AGENTS.md](apps/web/AGENTS.md)) |
| `apps/server/` | AWS Lambda backend API server for user auth, passkeys, and recovery ([AGENTS.md](apps/server/AGENTS.md)) |
| `apps/cli/` | Command-line interface for encryption/decryption |
| `libs/crypto/` | Shared cryptographic library used by `web` and `cli` |
| `libs/api/` | Shared API request/response types used by `web` and `server` |

- **Source Repository:** [qcrypt on GitHub](https://github.com/bschick/qcrypt)
- **Package Manager:** pnpm (version pinned in `package.json` via `packageManager` field)
- **Build System:** Nx

---

## 2. One-time Dev/Test Environment Setup

### a. Create an Ubuntu VM

Create an up-to-date Ubuntu 24.04 (or similar) VM.

### b. (Optional) LXC Container

To simplify version testing, log into the Ubuntu VM as a user with sudo permission and run:

```bash
sudo snap install lxd
sudo adduser $USER lxd
newgrp lxd
lxd init --auto
lxc launch ubuntu:24.04 qcrypt
lxc exec qcrypt -- /bin/bash
```

### c. Install Dependencies

Log into either the LXC container (via `lxc exec` above) or the Ubuntu VM as a user with sudo permission and run:

```bash
sudo apt update && sudo apt dist-upgrade -y
sudo apt install -y git ca-certificates
cd ~
git clone https://github.com/bschick/qcrypt.git && cd qcrypt
./ubsetup.sh 2>&1 | tee ubsetup.log
```

### d. Background Environment (Non-Interactive Shells)

When AI agents or automated tooling execute commands, they often spawn non-interactive background shells. These environments typically ignore `.zshrc`, `.bashrc`, and `.zprofile` and dynamically linked binaries (like Homebrew's `pnpm` or NVM's `node`) may fail to resolve.

To ensure non-interactive shells works, export the required paths in a profile evaluated by all execution modes:
- **Zsh:** Add the exports to `~/.zshenv` (e.g., `echo 'export PATH="/opt/homebrew/bin:/opt/homebrew/opt/node@24/bin:$PATH"' >> ~/.zshenv`).
- **Bash:** Use `~/.bash_env` and ensure `BASH_ENV` points to it.

**Very important (particularly for AI agents):** After setup, you must successfully run both the Unit and End-to-End test suites described in [`apps/web/AGENTS.md`](apps/web/AGENTS.md) with all tests passing *before* making any other changes. This helps distinguish environment setup problems from errors introduced by your changes.

---

## 3. Command Reference

The `pnpm` scripts in `package.json` call `nx` under the hood. You can use either form.

### Build Commands

| What | pnpm script | Direct Nx equivalent |
|------|------------|---------------------|
| Web build (production + SRI) | `pnpm build:web` | `pnpm nx build web --configuration production --subresource-integrity` |
| Server build | `pnpm build:server` | `pnpm nx build server` |
| Server build (minified) | `pnpm build:server:min` | `pnpm nx build-min server` |
| CLI build | `pnpm build:cli` | `pnpm nx build cli` |
| CLI build (minified) | `pnpm build:cli:min` | `pnpm nx build-min cli` |

### Serve Commands

| What | pnpm script |
|------|------------|
| Serve web locally (HTTPS, all interfaces) | `pnpm serve` |

### Test Commands

| What | pnpm script | Direct Nx equivalent | Notes |
|------|------------|---------------------|-------|
| **All unit tests** | `pnpm test` | | *runs test:web, test:server, test:lib, test:cli* |
| Web unit tests (chromium) | `pnpm test:web` | `pnpm nx test web` | |
| Web unit tests (watch mode) | `pnpm test:web:watch` | `pnpm nx test web --watch` | |
| Web unit tests (all browsers) | `pnpm test:web:all` | `pnpm nx test web --runnerConfig=apps/web/vitest-all.config.ts` | |
| Web E2E tests (local) | `pnpm test:e2e` | | *Playwright, requires `pnpm serve`* |
| Web E2E tests (prod) | `pnpm test:e2e:prod` | | *Playwright against quickcrypt.org* |
| API fuzz tests (local) | `pnpm test:fuzz` | | *Playwright, requires `pnpm serve`* |
| API fuzz tests (prod) | `pnpm test:fuzz:prod` | | *Playwright against quickcrypt.org* |
| Server unit tests | `pnpm test:server` | `pnpm nx test server` | |
| Server unit tests (prod) | `pnpm test:server:prod` | `pnpm nx test-prod server` | |
| All library unit tests | `pnpm test:lib` | | *runs test:lib:crypto* |
| Crypto library unit tests | `pnpm test:lib:crypto` | `pnpm nx test crypto` | |
| CLI unit tests | `pnpm test:cli` | `pnpm nx test cli` | |

> **Note:** When passing flags through `nx`, use camelCase for config options (e.g., `--runnerConfig=` not `--runner-config`).
> **Note:** To run a specific test files user `--include`. For example `pnpm test:web -- --include='**/keystore.service.spec.ts'`

### Deploy Commands

Both apps deploy through wrapper shell scripts (`apps/<app>/scripts/deploy.sh`) that invoke matching `deploy.mjs` orchestrators. The wrappers handle the SSO liveness probe, env-var resolution, and per-subcommand defaults; the .mjs files do the AWS work via the `aws` CLI. Shared bash helpers live in `scripts/deploy-common.sh`.

| Command | Description |
|---------|-------------|
| `pnpm deploy:web:prod [command] [flags]` | Defaults to `deploy` command. Web is only prod on AWS |
| `pnpm rollback:web:prod` | Shortcut for `pnpm deploy:web:prod rollback` |
| `pnpm deploy:server [command] [flags]` | Defaults to `deploy` command for test server |
| `pnpm deploy:server:prod [command] [flags]` | Defaults to `deploy` command for prod server |
| `pnpm rollback:server:prod` | Shortcut for `pnpm deploy:server:prod rollback` |

Examples:

```bash
pnpm deploy:web:prod bdeploy --comment "v1.2.3 hotfix"
pnpm deploy:server:prod info --print-limit 30
pnpm deploy:web:prod prune --expiration-days 7 --dry-run
```

Run any command with `--help` to see the full subcommand list and per-flag docs.

**Web commands (`apps/web/scripts/deploy.mjs`):** `deploy` (default), `bdeploy`, `rollback`, `bootstrap`, `manifest`, `leaks`, `info`, `expect`, `unexpect`, `prune`, `reset`.

**Server commands (`apps/server/scripts/deploy.mjs`):** `deploy` (default), `bdeploy`, `rollback`, `info`.

`bdeploy` runs the project build then executes `deploy`. `info` is read-only and shows current state. The header docstring at the top of each `deploy.mjs` explains design rationale, retention semantics (web), and version/alias semantics (server).

#### Required Env Vars

| Var | CLI flag | Used by | Purpose |
|-----|----------|---------|---------|
| `QC_PROD_AWS_PROFILE` | `--profile` | web; server (with `--prod`) | AWS CLI profile for prod account |
| `QC_PROD_AWS_REGION` | `--region` | web; server (with `--prod`) | AWS region for prod account |
| `QC_PROD_LAMBDA` | `--lambda` | server (with `--prod`) | Lambda function name or ARN |
| `QC_PROD_BUCKET` | *(none — bucket is positional)* | web | S3 bucket name |
| `QC_TEST_AWS_PROFILE` | `--profile` | server (no `--prod`) | AWS CLI profile for test account |
| `QC_TEST_AWS_REGION` | `--region` | server (no `--prod`) | AWS region for test account |
| `QC_TEST_LAMBDA` | `--lambda` | server (no `--prod`) | Lambda function name or ARN |

The wrappers exit with a clear error when a required var is missing. The AWS CLI's own `AWS_PROFILE` / `AWS_REGION` env vars are intentionally never consulted — keeps the active account explicit and prevents an unrelated env from silently routing a deploy to the wrong account.

#### Optional Env Vars

| Var | CLI flag | Used by | Purpose |
|-----|----------|---------|---------|
| `QC_PROD_CF_DISTRIBUTION` | `--cf-distribution` | web | CloudFront distribution ID; when set, web deploys invalidate `/*` after upload. Pass `--cf-distribution ''` to suppress invalidation for a single run. |
| `QC_PROD_CHROME_PROFILE` | *(none — wrapper-only)* | web; server (with `--prod`) | Chrome profile directory name (e.g. `Default`, `Profile 3`) — when set, the wrapper prints a copy-pasteable `open -na "Google Chrome" ...` command alongside the SSO device-code URL so the right Identity Center user signs in |
| `QC_TEST_CHROME_PROFILE` | *(none — wrapper-only)* | server (no `--prod`) | Same as above, for the test SSO session |

#### Notable Behavior

- **`--comment`** — recorded in the deploy manifest (web `deployComment` field) or in `publish-version` / `update-alias` `Description` (server). Defaults to the latest git tag (`git describe --tags --abbrev=0`) when not passed; pass `--comment ''` to suppress the git-tag fallback for a single run. `info` surfaces the current value.
- **`--dry-run`** (alias `--dryrun`) — logs every mutating `aws` call as `[dry-run] aws ...` instead of executing it. Read-only AWS calls (manifest fetch, list-versions, etc.) still run so the diagnostic output is accurate.
- **Web requires `--prod <alias>`** — single-environment design. Pass any alias name; the value isn't currently used by the web `deploy.mjs` but is kept symmetric with the server.
- **Server `--prod <alias>`** — optional. Presence enables prod-mode (publish-version + alias bump); the value is the alias name to point at (typically `prod`). Without `--prod`, server deploy hits `$LATEST` only (test mode).

---

## 4. Upgrading Packages

| What | Command |
|------|---------|
| Check outdated | `pnpm outdated` |
| Upgrade interactively (pick & choose) | `pnpm update --interactive --latest` |
| Upgrade all to latest | `pnpm update --latest` |
| Upgrade a specific package | `pnpm update <package> --latest` |
| **Upgrade Nx** (use Nx migrate tool) | `pnpm nx migrate latest && pnpm install && pnpm nx migrate --run-migrations --if-exists` |

- `--latest` allows major version bumps; without it, pnpm stays within existing semver ranges.
- Always upgrade Nx via `nx migrate` rather than `pnpm update` — it runs code migrations that update config files and source code for breaking changes.
- After any upgrade, run the appropriate `pnpm build:<target>` and `pnpm test:<target>` commands to verify nothing broke.

---

## 5. Shared Conventions

- **GitHub workflow:** All changes must be submitted as a GitHub pull request from a cloned repository.
- **AWS server resources:** The test API server at `https://test.quickcrypt.org` is intended only for those contributing to the Quick Crypt project. Unnecessary or excessive usage that drives up AWS costs will be blocked. Do not run invasive tests against the production API server.
- **Testing:** Any new feature or bug fix should be accompanied by corresponding unit or e2e tests to prevent regressions.
