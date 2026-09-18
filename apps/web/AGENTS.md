# Agent Instructions for web client

This document provides instructions for Human or AI agents working on the `web` client codebase. For monorepo-wide information (environment setup, command reference, shared conventions), see the root [`AGENTS.md`](../../AGENTS.md).

## 1. Project Overview

`web` is a single-page browser application for client-side text encryption and decryption. It is designed to be easy to use, trustworthy, and secure, leveraging the Web Crypto API (SubtleCrypto) and libsodium for all cryptographic operations. The primary use case is to encrypt text for storage on insecure media.

This `web` client can built, served, and tested locally. It depends on a backend API server called [qcrypt-server](https://github.com/bschick/qcrypt-server). Currently the API server cannot be deployed locally and must run in AWS. Separate test and production `server` instances are deployed in AWS. The vast majority of dev/test work should be against the test server `https://test.quickcrypt.org`. This is configured automatically.


- **Source Repository:** Project source code, issues tracking, and releases are at [qcrypt github](https://github.com/bschick/qcrypt)
- **Core Logic:** The main application logic, including key derivation, encryption, and decryption, is located in `src/`.
- **Technology Stack:** The application is built with Angular using pnpm as its package manager. It uses `libsodium-wrappers` and `@simplewebauthn/browser` for cryptographic and WebAuthn functionalities.
- **Crypto Details:** The cryptographic protocol is detailed in `src/assets/protocol6.pdf` and online at [https://quickcrypt.org/help/protocol](https://quickcrypt.org/help/protocol).
- **API Interaction:** The client communicates with the `server` for user management and passkey operations. Server code is at [qcrypt-server github](https://github.com/bschick/qcrypt-server) and deployed at `https://test.quickcrypt.org`

---

## 2. Architecture and Data Flow

- **Frontend Framework:** The application is built using the Angular framework.
- **Cryptography:** All cryptographic operations are performed client-side in the browser using a combination of the SubtleCrypto API and libsodium. This includes key derivation (PBKDF2), and authenticated encryption with associated data (AEAD) using AES-GCM, XChaCha20-Poly1305 (X20-PLY), and AEGIS-256.
- **User Interface:** The main user interface page component is located in `src/app/core`.

---

## 3. Important Files & Directories

- `src/app/qcrypt.component.ts`: The main Angular component containing the core application logic.
- `src/app/services/ciphers-current.ts`: Contains the implementation of the most recent encryption and decryption ciphers.
- `src/app/services/deciphers-old.ts`: Contains the implementation of previous decryption ciphers versions.
- `src/app/services/authenticator.service.ts`: Handles WebAuthn authenticator logic.
- `src/assets/protocol6.pdf`: Detailed documentation of the cryptographic protocol.
- `package.json`: Lists project dependencies and pnpm scripts for building, serving, and testing the application.
- `vitest-base.config.ts`: Vitest configuration for chromium-only unit tests.
- `vitest-all.config.ts`: Vitest configuration for chromium + firefox unit tests.
- `playwright.config.ts`: Configuration for Playwright (used for end-to-end tests).
- `tests/`: Contains Playwright e2e test specifications.
- `scripts/gen_*_vectors.ts`: Generators for the pinned test vectors in `libs/crypto` and this project's specs, run via `pnpm vectors:*` (see the root AGENTS.md "Test Vector Commands").
- `scripts/splice_vectors.ts`: Replaces the named `BEGIN GENERATED` regions those generators target when `--write` is passed.

---

## 4. Developer Workflows

**Very important (particularly for AI agents)**: You must set up a development environment and successfully run both the Unit and End-to-End test suites described below, with all tests passing, *before* making any other changes. This helps you distinguish between environment setup problems and errors introduced by changes you make to the project.

### a. One-time Setup of Dev/Test Environment

Follow the setup instructions in the root [`AGENTS.md`](../../AGENTS.md#2-one-time-devtest-environment-setup).

### b. Running Automated Tests

**Unit Tests locally:**
```bash
# You must first run the One-time setup steps above
pnpm test
```

**End-to-End Tests using AWS hosted test API backend:**
```bash
# You must first run the One-time setup steps above.
# No separate serve is needed: for --project local (the default), run_e2e.sh starts a frozen
# dev serve itself (no watch, no live-reload, so a file save mid-run cannot restart it), waits
# for the port, and tears the whole process tree down on exit.
pnpm test:e2e

# Append --reporter=list when the output is captured rather than shown in a terminal
# (background jobs, pipes, CI logs), so results stay parseable.
pnpm test:e2e --reporter=list
```

E2E is the **only** check that covers rendered output: user-visible strings, element labels,
stacking and clipping, and anything that repaints in response to an async event. `pnpm check` and
`pnpm test` cannot see any of it. Run e2e alongside them before finishing a piece of work, not only
before a release.

### c. Running Manual Tests

- Start the development server as described above with `pnpm serve`. The server will listen on all IP addresses on that system.
- If you plan to run a web browser on a different system than the development server, you must edit that system's `hosts` file to set the name of the primary IP address where the development server is running to `t1.quickcrypt.org`. Ensure you can `ping t1.quickcrypt.org`.
- To avoid security warnings, you must also import the project's local CA certificate on the system running your browser. You can find the CA certificate in the `./localssl` directory relative to where you ran the `pnpm serve` command. Import this certificate into your system's or browser's trusted certificate store. This process is dependent on your operating system.
- Finally, start a web browser and navigate to `https://t1.quickcrypt.org:4200`. The test front-end uses a test back-end API server running in AWS with a URL of `https://test.quickcrypt.org`. The test API server is intended **only for those contributing to the Quick Crypt project**. Unnecessary or excessive usage that drives up AWS costs will be blocked. Do not run invasive tests against the production API server.

### d. Build project for production deployment

```bash
pnpm build:web
```
The output will be placed in the `dist/web/` directory.


---

## 5. Programmatic Checks

Before submitting any changes, run the following test suites to ensure that the application is working correctly.

### a. Unit Tests
```bash
pnpm test
```

### b. End-to-End Tests (starts and stops its own dev serve, see 4.b)
```bash
pnpm test:e2e
```
If a test fails, view the trace with `pnpm exec playwright show-trace playwright-report/<path-to-trace>`

Treat this as part of the normal gate, not a release-only step. It is the only check that sees
rendered output, so a renamed label, a restyled control or a binding that stops repainting passes
`pnpm check` and `pnpm test` unnoticed.
---

## 6. Key Patterns & Conventions

- **Component-Based Architecture:** The application follows Angular's component-based architecture. New features should be encapsulated in their own components where appropriate.
- **Forms:** Reactive forms (`FormControl`) remain the default. Signal Forms (`@angular/forms/signals`) were evaluated and deliberately not adopted: `form()` wraps a whole *model* object and returns a field tree, which pays off for forms with real structure — several fields, cross-field rules, async validation, submit/dirty/touched state. Every form in this app is a single standalone control running a trivial check, with no `FormGroup`, no `Validators` and no `ControlValueAccessor` anywhere, so the model object, schema callback and field-access indirection cost more readability than they return. Reach for Signal Forms only if a genuinely multi-field form with cross-field or async validation appears; otherwise a plain `FormControl` is the simpler and preferred choice.
- **Client-Side Logic:** All sensitive operations, especially cryptography, must remain strictly on the client-side. No sensitive data should be sent to any server.
- **Testing:** Any new feature or bug fix should be accompanied by corresponding unit or e2e tests to prevent regressions.
- **Immutability:** Follow best practices for immutability, especially when dealing with application state.
- **Security:** Adhere to the security principles outlined in `src/assets/protocol6.pdf`, including the use of strong cryptographic primitives and secure coding practices.
- **Cross-origin isolation:** The deployed site sets `Cross-Origin-Embedder-Policy: require-corp` alongside `COOP: same-origin` and `CORP: same-origin` (configured at CloudFront). This puts the page in a cross-origin-isolated context, which is what enables `SharedArrayBuffer` and high-resolution timers — appropriate for a crypto app. The tradeoff: every third-party asset (font, image, script, iframe, `fetch` target) must return `Cross-Origin-Resource-Policy: cross-origin` (or a matching CORS response) or the browser will refuse to load it and the page will break. Currently compatible: `fonts.gstatic.com` and `api.pwnedpasswords.com`. Before adding any new third-party dependency, confirm it returns CORP/CORS-friendly headers.

See the root [`AGENTS.md`](../../AGENTS.md#5-shared-conventions) for additional shared conventions (GitHub workflow, AWS resource policies).
