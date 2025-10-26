# Agent Instructions for qcrypt client

This document provides instructions for AI agents working on the `qcrypt client` codebase.

## 1. Project Overview

`qcrypt client` is a single-page browser application for client-side text encryption and decryption. It is designed to be easy to use, trustworthy, and secure, leveraging the Web Crypto API (SubtleCrypto) and libsodium for all cryptographic operations. The primary use case is to encrypt text for storage on insecure media.

- **Core Logic:** The main application logic, including key derivation, encryption, and decryption, is located in `src/app/qcrypt.component.ts`.
- **Technology Stack:** The application is built with Angular. It uses `libsodium-wrappers` and `@simplewebauthn/browser` for cryptographic and WebAuthn functionalities.
- **Crypto Details:** The cryptographic protocol is detailed in `src/assets/protocol5.pdf`.

---

## 2. Architecture and Data Flow

- **Frontend Framework:** The application is built using the Angular framework.
- **Cryptography:** All cryptographic operations are performed client-side in the browser using a combination of the SubtleCrypto API and libsodium. This includes key derivation (PBKDF2), and authenticated encryption with associated data (AEAD) using AES-GCM, XChaCha20-Poly1305 (X20-PLY), and AEGIS-256.
- **User Interface:** The main user interface and application logic are encapsulated within the `QcryptComponent` in `src/app/qcrypt.component.ts`.
- **State Management:** Application state is managed within the Angular components.

---

## 3. Important Files & Directories

- `src/app/qcrypt.component.ts`: The main Angular component containing the core application logic.
- `src/app/services/ciphers.ts`: Contains the implementation of the different encryption and decryption ciphers.
- `src/app/services/authenticator.service.ts`: Handles WebAuthn authenticator logic.
- `src/assets/protocol5.pdf`: Detailed documentation of the cryptographic protocol.
- `package.json`: Lists project dependencies and npm scripts for building, serving, and testing the application.
- `angular.json`: The configuration file for the Angular project, defining build and test targets.
- `karma.conf.cjs`: Configuration for the Karma test runner (used for unit tests).
- `playwright.config.ts`: Configuration for Playwright (used for end-to-end and unit tests).
- `tests/`: Contains Playwright test specifications, including `unit.spec.ts`, `sequential.spec.ts`, and `parallel.spec.ts`.

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

### c. Running the Development Server
To serve the application locally for development, run:
```bash
npm run serve
```

### d. Testing
The project has both unit and end-to-end (e2e) tests.

**Unit Tests:**
Run unit tests using Playwright:
```bash
npm run test
```
To run unit tests across multiple browsers:
```bash
npm run test:all
```

**End-to-End (E2E) Tests:**
Run the full suite of e2e tests locally:
```bash
npm run test:e2e
```
To run e2e tests against a production-like environment:
```bash
npm run test:e2e:prod
```

---

## 5. Programmatic Checks

Before submitting any changes, run the following test suites to ensure that the application is working correctly.

### a. Unit Tests
```bash
npm run test:all
```

### b. End-to-End Tests
```bash
npm run test:e2e
```

---

## 6. Key Patterns & Conventions

- **Component-Based Architecture:** The application follows Angular's component-based architecture. New features should be encapsulated in their own components where appropriate.
- **Client-Side Logic:** All sensitive operations, especially cryptography, must remain strictly on the client-side. No sensitive data should be sent to any server.
- **Testing:** Any new feature or bug fix should be accompanied by corresponding unit or e2e tests to prevent regressions.
- **Immutability:** Follow best practices for immutability, especially when dealing with application state.
- **Security:** Adhere to the security principles outlined in `src/assets/protocol5.pdf`, including the use of strong cryptographic primitives and secure coding practices.