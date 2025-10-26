# Agent Instructions for qcrypt client

This document provides instructions for AI agents working on the `qcrypt` client codebase.

## 1. Project Overview

`qcrypt` is a single-page browser application for client-side text encryption and decryption. It is designed to be easy to use, trustworthy, and secure, leveraging the Web Crypto API (SubtleCrypto) and libsodium for all cryptographic operations. The primary use case is to encrypt text for storage on insecure media.

This `qcrypt` client can built, served, and tested locally. It depends on a backend API server called [qcrypt-server](https://github.com/bschick/qcrypt-server). Currently the API server cannot be deployed locally and must run in AWS. Separate test and production `qcrypt-server` instances are deployed in AWS. The vast majority of dev/test work should be against the test server `https://test.quickcrypt.org`. This is configured automatically.


- **Source Repository:** Project source code, issues tracking, and releases are at [qcrypt github](https://github.com/bschick/qcrypt)
- **Core Logic:** The main application logic, including key derivation, encryption, and decryption, is located in `src/`.
- **Technology Stack:** The application is built with Angular. It uses `libsodium-wrappers` and `@simplewebauthn/browser` for cryptographic and WebAuthn functionalities.
- **Crypto Details:** The cryptographic protocol is detailed in `src/assets/protocol5.pdf` and online at [https://quickcrypt.org/help/protocol](https://quickcrypt.org/help/protocol).
- **API Interaction:** The client communicates with the `qcrypt-server` for user management and passkey operations. Server code is at [qcrypt-server github](https://github.com/bschick/qcrypt-server) and deployed at `https://test.quickcrypt.org`

---

## 2. Architecture and Data Flow

- **Frontend Framework:** The application is built using the Angular framework.
- **Cryptography:** All cryptographic operations are performed client-side in the browser using a combination of the SubtleCrypto API and libsodium. This includes key derivation (PBKDF2), and authenticated encryption with associated data (AEAD) using AES-GCM, XChaCha20-Poly1305 (X20-PLY), and AEGIS-256.
- **User Interface:** The main user interface page component is located in `src/app/core`.

---

## 3. Important Files & Directories

- `src/app/qcrypt.component.ts`: The main Angular component containing the core application logic.
- `src/app/services/ciphers.ts`: Contains the implementation of the different encryption and decryption ciphers.
- `src/app/services/authenticator.service.ts`: Handles WebAuthn authenticator logic.
- `src/assets/protocol5.pdf`: Detailed documentation of the cryptographic protocol.
- `package.json`: Lists project dependencies and npm scripts for building, serving, and testing the application.
- `karma.conf.cjs`: Configuration for the Karma test runner (used for unit tests).
- `playwright.config.ts`: Configuration for Playwright (used for end-to-end and unit tests).
- `tests/`: Contains Playwright test specifications, including `unit.spec.ts`, `sequential.spec.ts`, and `parallel.spec.ts`.

---

## 4. Developer Workflows

### a. One-time Setup of Dev/Test Environment

- Create an up-to-date Ubuntu 24.04 (or similar) VM
- (Optional) Setup an LXC container to simplify version testing by logging into the Ubuntu VM as a user with sudo permission and run the following:
```bash
sudo sudo snap install lxd
sudo adduser $USER lxd
newgrp lxd
lxd init --auto
lxc launch ubuntu:24.04 qcrypt
lxc exec qcrypt -- /bin/bash
```
- Log into either the LXC container (exec above) or the Ubuntu VM as a user with sudo permission and run the following:
```bash
sudo apt update && sudo apt dist-upgrade -y
sudo apt install -y git ca-certificates
cd ~
git clone https://github.com/bschick/qcrypt.git && cd qcrypt
./ubsetup.sh
```

### b. Running Tests

**Unit Tests:**
```bash
tmux
ctrl-b c
npm run karma
ctrl-b n
sleep 15s
npm run test
ctrl-b : kill-session
```

**End-to-End Tests with Test AWS hosted API backend:**
```bash
tmux
ctrl-b c
npm run serve
ctrl-b n
sleep 15s
npm run test:e2e
ctrl-b : kill-session
```

### c. Build project for production deployment

```bash
npm run build
```
The output will be placed in the `dist/` directory.


---

## 5. Programmatic Checks

Before submitting any changes, run the following test suites to ensure that the application is working correctly.

### a. Unit Tests (requires start of Karma server, see 4.b)
```bash
npm run test
```

### b. End-to-End Tests (requires start of Local server, see 4.b)
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
- **Github workflow:** All changes must be submitted as a github pull request from a cloned repository.
- **AWS server resources:** The test API server at `https://test.quickcrypt.org` is intended only for those contributing to the Quick Crypt project. Unnecessary or excessive usage that drives up AWS costs will be blocked.