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
| Serve SSR build | `pnpm serve:ssr:web` |

### Test Commands

| What | pnpm script | Direct Nx equivalent |
|------|------------|---------------------|
| **All unit tests** | `pnpm test` | *(runs test:web, test:server, test:lib, test:cli)* |
| Web unit tests (chromium) | `pnpm test:web` | `pnpm nx test web` |
| Web unit tests (watch mode) | `pnpm test:web:watch` | `pnpm nx test web --watch` |
| Web unit tests (all browsers) | `pnpm test:web:all` | `pnpm nx test web --runnerConfig=apps/web/vitest-all.config.ts` |
| Web E2E tests (local) | `pnpm test:e2e` | *(Playwright, requires `pnpm serve`)* |
| Web E2E tests (prod) | `pnpm test:e2e:prod` | *(Playwright against quickcrypt.org)* |
| API fuzz tests (local) | `pnpm test:fuzz` | *(Playwright, requires `pnpm serve`)* |
| API fuzz tests (prod) | `pnpm test:fuzz:prod` | *(Playwright against quickcrypt.org)* |
| Server unit tests | `pnpm test:server` | `pnpm nx test server` |
| Server unit tests (prod) | `pnpm test:server:prod` | `pnpm nx test-prod server` |
| All library unit tests | `pnpm test:lib` | *(runs test:lib:crypto)* |
| Crypto library unit tests | `pnpm test:lib:crypto` | `pnpm nx test crypto` |
| CLI unit tests | `pnpm test:cli` | `pnpm nx test cli` |

> **Note:** When passing flags through `nx`, use camelCase for config options (e.g., `--runnerConfig=` not `--runner-config`).

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
