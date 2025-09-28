# Agent Instructions for qcrypt

This document provides instructions for AI agents working on the `qcrypt` client-side codebase.

## 1. Project Overview

`qcrypt` is the client-side single-page application for Quick Crypt, a service that encrypts and decrypts data using cryptographic features available in modern browsers to ensure **confidential data never leaves the user's system**. It handles user authentication, passkey (WebAuthn) registration, and account recovery workflows by communicating with a backend server.

- **Core Logic:** The main application logic is within the `src/` directory, organized by Angular components and services.
- **Technology Stack:** It is an Angular application using TypeScript, Angular Material for UI components, and various cryptographic libraries.
- **API Interaction:** The client communicates with the `qcrypt-server` for user management and passkey operations.

---

## 2. Architecture and Data Flow

- **Components:** The application is built with Angular components, each responsible for a piece of the UI. Key components are in `src/app/`.
- **Authentication:** The client uses the [@simplewebauthn/browser](https://github.com/MasterKale/SimpleWebAuthn) library to handle WebAuthn registration and authentication flows, interacting with the `qcrypt-server` backend.
- **Cryptography:** All sensitive data is encrypted/decrypted in the browser using `libsodium-wrappers` and the Web Crypto API. Unencrypted data and passwords never leave the user's system.
- **Offline Capability:** After sign-in, Quick Crypt works even with network access disabled.

---

## 3. Important Files & Directories

- `src/app/`: Contains the core Angular application components, services, and modules.
- `qcrypt.ts`: Contains the main encryption/decryption logic for the qcrypt cipher format.
- `server.ts`: A server-side rendering (SSR) entry point.
- `angular.json`: The main configuration file for the Angular project, including build and test settings.
- `package.json`: Lists project dependencies and available npm scripts.
- `tests/`: Contains the Playwright end-to-end tests for the application.
- `README.md`: Provides a high-level overview of the project.

---

## 4. Developer Workflows

### a. Initial Setup
To set up the development environment, run:
```bash
npm install
```

### b. Building the Project
To create a production build, run:
```bash
npm run build
```
The output will be placed in the `dist/` directory.

### c. Local SSL Setup (One-Time)
Before running the development server for the first time, you must generate the local SSL certificates.
```bash
cd localssl
./localssl.sh
cd ..
```

### d. Running the Development Server
For development with a local SSL certificate (required for some WebAuthn features), use:
```bash
npm run serve
```

### e. Testing
Before submitting any changes, run the relevant tests to ensure the client is working correctly.

**Note on Test Configuration:** The repository's testing configuration was fixed to be runnable. This included setting a browser (`ChromeHeadless`) and a valid local hostname in `karma.conf.js`, and updating the `test` script in `package.json` to use `--no-watch`.

**Note on Test Environment:** The following unit test instructions are for a standard developer machine. They may not be fully executable in a minimal sandboxed environment that lacks a `ChromeHeadless` browser binary. Attempts to install Chrome may fail due to environment constraints.

**One-Time Setup for Local Testing**
Before running any local tests (Unit or E2E), you must perform a one-time setup of your `/etc/hosts` file. Note that the Local SSL Setup (step 4c) is also a prerequisite for all local testing.
1.  **Configure `/etc/hosts`**: Add an entry for `t1.quickcrypt.org` pointing to the IP address of the machine running the tests. For example, if running locally:
    ```
    127.0.0.1 t1.quickcrypt.org
    ```

**Unit Test Workflow**
1.  Start the Karma test server:
    ```bash
    npm run test
    ```
2.  Connect a browser to the Karma server URL to execute the tests: `https://t1.quickcrypt.org:9876/`

**End-to-End (E2E) Test Workflow**
1.  Ensure the Karma server is not running.
2.  Start the development server:
    ```bash
    npm run serve
    ```
3.  In a separate terminal, run the E2E tests:
    ```bash
    npm run ete
    ```

**E2E Tests Against Production**
To run E2E tests against the production environment (which does not require local setup), run:
```bash
npm run ete:prod
```

---

## 5. Key Patterns & Conventions

- **Component-Based Architecture:** Follow Angular's component-based architecture. Keep components focused on a single responsibility.
- **Services for Shared Logic:** Use Angular services for shared logic, such as API calls or state management.
- **Reactive Programming:** Use RxJS for handling asynchronous operations.
- **Security:** Ensure that no unencrypted data or passwords are ever sent to the server. All cryptography must happen client-side.
- **Type Safety:** Use TypeScript and strive for strong type safety throughout the application.

---

## 6. Server API Context

The client interacts with the `qcrypt-server`. For details on the server-side API endpoints, data models, and workflows, refer to the server's agent instructions document:
[https://raw.githubusercontent.com/bschick/qcrypt-server/refs/heads/main/AGENTS.md](https://raw.githubusercontent.com/bschick/qcrypt-server/refs/heads/main/AGENTS.md)

When adding features that require new server interactions, ensure the corresponding server-side changes are implemented and tested. The server repository is available at: [https://github.com/bschick/qcrypt-server](https://github.com/bschick/qcrypt-server).