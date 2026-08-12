# Agent Instructions for server

This document provides instructions for AI agents working on the `server` codebase. This project lives in `apps/server/` within the `qcrypt` Nx monorepo. For monorepo-wide information (environment setup, command reference, shared conventions), see the root [`AGENTS.md`](../../AGENTS.md).

## 1. Project Overview

`server` is the backend API server for Quick Crypt, a service that handles user authentication, passkey (WebAuthn) registration, and account recovery workflows.

This `server` can be built locally but currently is not setup to run locally and must be deployed to AWS for testing and production. Separate test and production instances are deployed in AWS. Deployment to AWS is not yet well documented. The vast majority of dev/test work should be against the test server `https://test.quickcrypt.org`.

- **Core Logic:** `apps/server/src/server.ts` contains the main application logic and handler functions for API endpoints.
- **URL Routing:** API URL routing is defined in `apps/server/src/urls.ts`.
- **Technology Stack:** It uses AWS KMS for cryptographic operations and ElectroDB for DynamoDB access.
- **API:** The server exposes HTTPS endpoints, which are defined in the `METHODMAP` object in `apps/server/src/server.ts` and described in `apps/server/API.md`

---

## 2. Architecture and Data Flow

- **Data Models:** All database entities (`User`, `Authenticator`, `Challenge`, `AuthEvent`, `AAGUID`) are defined in `src/models.ts`. These models are used for all database operations.
- **Authentication:** The server uses the SimpleWebAuthn library to handle WebAuthn registration and authentication flows.
- **Cryptography:** All sensitive data is encrypted using AWS KMS. The AWS SDK is used for all cryptographic operations.
- **Database:** User and credential data is stored in DynamoDB, accessed via the ElectroDB models.
- **Static Assets:** Authenticator images and metadata are located in `assets/aaguid/img/` and `assets/combined_aaguid.json`.

---

## 3. Important Files & Directories

- `apps/server/src/server.ts`: The main file containing all API endpoint logic and handler functions.
- `apps/server/src/urls.ts`: Defines the URL patterns and routing for all API endpoints.
- `apps/server/src/models.ts`: Defines the ElectroDB models for all DynamoDB tables.
- `apps/server/src/utils.ts`: Contains utility functions and custom error classes (`ParamError`, `AuthError`, `NotFoundError`).
- `apps/server/src/nonce/`: **Note:** This directory contains a backup of a separate AWS Lambda function and is not used by this project directly.
- `package.json` (root): Lists project dependencies. Dependencies are managed at the monorepo root.
- `apps/server/API.md`: Detailed documentation for all API endpoints, including request/response formats.
- `apps/server/assets/`: Contains static assets, including authenticator metadata.

---

## 4. Developer Workflows

### a. One-time Setup of Dev/Test Environment

Follow the setup instructions in the root [`AGENTS.md`](../../AGENTS.md#2-one-time-devtest-environment-setup).

### b. Building the Project

To create a test build, run from the monorepo root:

```bash
pnpm build:server
```

That writes an unminified build to `dist/server-test/`. For production:

```bash
pnpm build:server:prod
```

That writes a minified build to `dist/server/`. Either command takes `--min` or `--no-min` to
override the minification default, and reads `QC_SERVER_OUT` to override the output directory.
Both run `pnpm check` first, so a lint or format error blocks the build.

### c. Deployment

Each build directory contains `server.mjs` and `server.zip`. Deploy with the project scripts rather
than uploading by hand:

```bash
pnpm deploy:server                      # build + upload to the test function ($LATEST)
pnpm deploy:server:prod                 # build + upload, publish a version, move the prod alias

pnpm deploy:server:prod --no-alias      # publish the version, leave the alias where it is
pnpm deploy:server:prod deploy          # upload an existing build without rebuilding
pnpm deploy:server:prod version 42      # point the prod alias at version 42
pnpm rollback:server:prod               # move the prod alias back one version
```

Both `deploy:server` scripts default to `bdeploy`, which builds and then deploys. Name a command
explicitly to do otherwise.

`--no-alias` is how a new version goes live only after something else has run against it — a data
migration, for example. See the flag notes in the root [`AGENTS.md`](../../AGENTS.md#notable-behavior).

### d. Testing

Server-specific tests can be run from the monorepo root:

```bash
pnpm test:server        # run against test.quickcrypt.org (includes the small input fuzz)
pnpm test:server:prod   # run against quickcrypt.org
pnpm test:fuzz          # full input fuzz against test.quickcrypt.org (sets QC_FULL_FUZZ=true)
pnpm test:fuzz:prod     # full input fuzz against quickcrypt.org
```

Direct HTTP API tests — contract, negative, and input fuzzing — live in `apps/server/spec/` (`api.spec.ts`, `fuzz.spec.ts`). The full fuzz is gated behind `QC_FULL_FUZZ`; a small fuzz subset runs on every `pnpm test:server`. Backend behavior is also exercised end-to-end through the web client in `apps/web/`; see the root `AGENTS.md` for those.

When adding or modifying an endpoint, you must also add corresponding tests.

---

## 5. Programmatic Checks

Before submitting any changes, you must run the server tests (`pnpm test:server`) and the frontend test suites described in the root `AGENTS.md` to ensure that the backend is working correctly with the client.

---

## 6. Key Patterns & Conventions

- **Endpoint Logic:** All API logic is located in `apps/server/src/server.ts`. Each endpoint should have its own handler function.
- **Input Sanitization:** Always use the `sanitizeString` utility from `apps/server/src/utils.ts` for all user-provided input before processing or storing it.
- **Database Updates:** Use the `.patch().set({...}).go()` pattern for updating records in DynamoDB.
- **Security:** Never store plaintext secrets. Credentials and recovery IDs must be encrypted before being stored.
- **Error Handling:** Use the custom `ParamError` and `AuthError` classes from `apps/server/src/utils.ts` for handling errors gracefully.

See the root [`AGENTS.md`](../../AGENTS.md#5-shared-conventions) for additional shared conventions (GitHub workflow, AWS resource policies).

---

## 7. API Endpoints

For detailed information on request/response formats and data models, see `apps/server/API.md`.
