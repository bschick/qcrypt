# Agent Instructions for server

This document provides instructions for AI agents working on the `server` codebase. This project lives in `apps/server/` within the `qcrypt` Nx monorepo.

## 1. Project Overview

`server` is the backend API server for Quick Crypt, a service that handles user authentication, passkey (WebAuthn) registration, and account recovery workflows.

This `server` can be built locally but currently is not setup to run locally and must be deployed to AWS for testing and production. Separate test and production instances are deployed in AWS. Deployment to AWS is not yet well documented. The vast majority of dev/test work should be against the test server `https://test.quickcrypt.org`.

- **Core Logic:** `apps/server/src/index.ts` contains the main application logic and handler functions for API endpoints.
- **URL Routing:** API URL routing is defined in `apps/server/src/urls.ts`.
- **Technology Stack:** It uses AWS KMS for cryptographic operations and ElectroDB for DynamoDB access.
- **API:** The server exposes HTTPS endpoints, which are defined in the `METHODMAP` object in `apps/server/src/index.ts` and described in `apps/server/API.md`

---

## 2. Architecture and Data Flow

- **Data Models:** All database entities (`User`, `Authenticator`, `Challenge`, `AuthEvent`, `AAGUID`) are defined in `src/models.ts`. These models are used for all database operations.
- **Authentication:** The server uses the SimpleWebAuthn library to handle WebAuthn registration and authentication flows.
- **Cryptography:** All sensitive data is encrypted using AWS KMS. The AWS SDK is used for all cryptographic operations.
- **Database:** User and credential data is stored in DynamoDB, accessed via the ElectroDB models.
- **Static Assets:** Authenticator images and metadata are located in `assets/aaguid/img/` and `assets/combined_aaguid.json`.

---

## 3. Important Files & Directories

- `apps/server/src/index.ts`: The main file containing all API endpoint logic and handler functions.
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

This project is part of the `qcrypt` monorepo. Follow the setup instructions in the root `AGENTS.md` or `README.md` for the monorepo. Once the monorepo is set up, `pnpm install` at the root will install all dependencies including those needed for `server`.

### b. Building the Project

To create a non-minimized build for debugging, run from the monorepo root:

```bash
pnpm build:server
```

For production builds, use the following command to create a minimized version:

```bash
pnpm build:server:min
```

The output will be placed in the `apps/server/build/` directory.

### c. Deployment

The `apps/server/build/` directory will contain `index.js` and `index.zip`. To deploy, upload `index.zip` to the appropriate AWS Lambda function. This may be documented in detail later.

### d. Testing

Server-specific tests can be run from the monorepo root:

```bash
pnpm test:server        # run against test.quickcrypt.org
pnpm test:server:prod   # run against quickcrypt.org
```

Unit and end-to-end tests for this API backend are also done through the client-side web application in `apps/web/`. See the root `AGENTS.md` for test execution instructions.

When adding or modifying an endpoint, you must also add corresponding tests.

---

## 5. Programmatic Checks

Before submitting any changes, you must run the server tests (`pnpm test:server`) and the frontend test suites described in the root `AGENTS.md` to ensure that the backend is working correctly with the client.

---

## 6. Key Patterns & Conventions

- **Endpoint Logic:** All API logic is located in `apps/server/src/index.ts`. Each endpoint should have its own handler function.
- **Input Sanitization:** Always use the `sanitizeString` utility from `apps/server/src/utils.ts` for all user-provided input before processing or storing it.
- **Database Updates:** Use the `.patch().set({...}).go()` pattern for updating records in DynamoDB.
- **Security:** Never store plaintext secrets. Credentials and recovery IDs must be encrypted before being stored.
- **Error Handling:** Use the custom `ParamError` and `AuthError` classes from `apps/server/src/utils.ts` for handling errors gracefully.
- **Github workflow:** All changes must be submitted as a github pull request from a cloned repository.
- **AWS server resources:** The test API server at `https://test.quickcrypt.org` is intended only for those contributing to the Quick Crypt project. Unnecessary or excessive usage that drives up AWS costs will be blocked.

---

## 7. API Endpoints

For detailed information on request/response formats and data models, see `apps/server/API.md`.
