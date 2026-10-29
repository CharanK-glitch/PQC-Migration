# pgcrypto PQC Scanner & Migration Suite

[![Post-Quantum Cryptography](https://img.shields.io/badge/Cryptography-Post--Quantum-blueviolet.svg?style=flat-square)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![PostgreSQL Support](https://img.shields.io/badge/PostgreSQL-12--17-336791.svg?style=flat-square&logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![NIST FIPS Compliance](https://img.shields.io/badge/NIST-FIPS_203_|_204_|_205-green.svg?style=flat-square)](https://csrc.nist.gov/)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-3776AB.svg?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Playwright Tests](https://img.shields.io/badge/Playwright-E2E_Passing-2ea44f.svg?style=flat-square&logo=playwright&logoColor=white)](https://playwright.dev/)
[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-red.svg?style=flat-square)](LICENSE)

The **pgcrypto PQC Scanner** is an enterprise-grade post-quantum cryptography (PQC) auditing engine and migration toolkit. It inspects PostgreSQL database infrastructures, `pgcrypto` usage, schema migrations, package dependency manifests, live database instances, server configurations, TLS parameters, and application source code.

It provides security engineers, compliance officers, and database architects with automated cryptographic inventories, standard-compliant **CycloneDX Cryptographic Bill of Materials (CBOM)**, deterministic readiness scores, and actionable migration roadmaps mapped directly to NIST PQC standards (**FIPS 203**, **FIPS 204**, and **FIPS 205**).

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Toolkit Modules & Scanners](#toolkit-modules--scanners)
- [Quick Start](#quick-start)
- [CLI Reference Guide](#cli-reference-guide)
  - [1. Core Scanner (`pgcrypto_scanner.py`)](#1-core-scanner-pgcrypto_scannerpy)
  - [2. Dependency Scanner (`dependency_scanner.py`)](#2-dependency-scanner-dependency_scannerpy)
  - [3. Database Introspection Scanner (`db_introspection_scanner.py`)](#3-database-introspection-scanner-db_introspection_scannerpy)
  - [4. SME Profile Estimator (`sme_estimator.py`)](#4-sme-profile-estimator-sme_estimatorpy)
- [Interactive Web Dashboard](#interactive-web-dashboard)
  - [Running the Server](#running-the-server)
  - [Multi-Repo Audits](#multi-repo-audits)
  - [Website & SME URL Scanner](#website--sme-url-scanner)
  - [PQC Readiness Assessment (35 Questions)](#pqc-readiness-assessment-35-questions)
  - [Protected Deployments (API Key Auth)](#protected-deployments-api-key-auth)
- [NIST PQC Standards & Compliance Mapping](#nist-pqc-standards--compliance-mapping)
- [Quantum Readiness Scoring Model](#quantum-readiness-scoring-model)
- [Executive Reports & PDF Generation](#executive-reports--pdf-generation)
- [Verification & Automated Test Suites](#verification--automated-test-suites)
- [License & Usage Restrictions](#license--usage-restrictions)

---

## Overview

Modern cryptographic deployments face imminent exposure to quantum threats under the **Harvest Now, Decrypt Later (HNDL)** paradigm. Adversaries capture encrypted database traffic, stored credentials, and encrypted records today to decrypt them once cryptanalytically relevant quantum computers (CRQCs) become viable.

Shor's algorithm breaks legacy public-key schemes (**RSA, DSA, ECDSA, ECDH**), while Grover's algorithm halves effective symmetric key entropy (**AES-128, 3DES, Blowfish**). 

The `PQC-Migration` suite automates the discovery, classification, scoring, and remediation planning across both source code and active database deployments.

---

## Key Features

- **Multi-Layer Static Code Analysis**: Scans SQL migrations, stored procedures, `pgcrypto` function calls (`digest`, `hmac`, `pgp_sym_encrypt`, `crypt`), server configuration (`postgresql.conf`, `pg_hba.conf`), TLS certificates, and source files across Python, C/C++, Rust, Go, Java, TypeScript, and PHP.
- **Live Database Introspection**: Connects directly to running PostgreSQL instances to inspect active extensions, tablespace encryption, password hashes, and SSL configurations without requiring source code access.
- **Dependency Manifest Auditing**: Analyzes `package.json`, `requirements.txt`, `Gemfile`, and `go.mod` for known cryptographic packages with deprecated versions or algorithms.
- **SME Technology Stack Profiler**: Generates instant synthetic readiness estimates for small/medium enterprises across common frameworks (Django, Node.js, Spring, Laravel, Rails, .NET).
- **CycloneDX 1.7 CBOM Export**: Emits machine-readable Cryptographic Bill of Materials adhering to standard software supply chain formats.
- **Full-Featured Web Dashboard**: Real-time dark/light interface with live scanning logs, CBOM search and filtering, multi-repo aggregation, URL vulnerability scanner, and PDF exports.
- **35-Question PQC Readiness Assessment**: Interactive evaluation covering Infrastructure, Application Layer, Data Protection, and Governance.
- **Automated Verification**: End-to-end Playwright tests, Python unittests, and security regression verification suites.

---

## Architecture

```
                                 ┌────────────────────────────────────────────────────────┐
                                 │                      Audit Targets                     │
                                 │  • PostgreSQL Configs     • Live DB Instances          │
                                 │  • GitHub Repositories    • Dependency Manifests       │
                                 │  • SQL Migrations         • SME Technology Profiles    │
                                 └───────────────────────────┬────────────────────────────┘
                                                             │
                                                             ▼
                                 ┌────────────────────────────────────────────────────────┐
                                 │                 Unified Scanner Engine                 │
                                 └─────────┬───────────────────────────┬──────────────────┘
                                           │                           │
                   ┌───────────────────────┴──────────────┐            │
                   ▼                                      ▼            ▼
      ┌─────────────────────────┐            ┌─────────────────────────┐
      │     PostgresScanner     │            │     GenericScanner      │
      │ (SQL, pgcrypto, confs)  │            │ (C++, Rust, Python, Go) │
      └────────────┬────────────┘            └────────────┬────────────┘
                   │                                      │
                   └───────────────────┬──────────────────┘
                                       │
                                       ▼
                          ┌─────────────────────────┐
                          │ AST & Pattern Normalizer│
                          └────────────┬────────────┘
                                       │
                   ┌───────────────────┴───────────────────┐
                   ▼                                       ▼
      ┌─────────────────────────┐             ┌─────────────────────────┐
      │  Weight Scoring Engine  │             │ NIST Compliance Engine  │
      │  (Deterministic PQR)    │             │ (FIPS 203 / 204 / 205)  │
      └────────────┬────────────┘             └────────────┬────────────┘
                   │                                       │
                   └───────────────────┬───────────────────┘
                                       │
                                       ▼
                          ┌─────────────────────────┐
                          │   CBOM & Report Gen     │
                          └────────────┬────────────┘
                                       │
            ┌──────────────────────────┼──────────────────────────┐
            ▼                          ▼                          ▼
 ┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
 │      cbom.json      │    │ readiness_score.json│    │    Web Dashboard    │
 │  (CycloneDX v1.7)   │    │  (PQC Risk Metrics) │    │  (FastAPI + Web UI) │
 └─────────────────────┘    └─────────────────────┘    └─────────────────────┘
```

---

## Toolkit Modules & Scanners

| Script | Purpose | Input Modes | Output |
| :--- | :--- | :--- | :--- |
| [`pgcrypto_scanner.py`](file:///Users/user/PQC-Migration/pgcrypto_scanner.py) | Primary CLI scanner engine | Single/Multi GitHub repos, SQL dirs, configs, live DB | `cbom.json`, `readiness_score.json`, HTML dashboard |
| [`dependency_scanner.py`](file:///Users/user/PQC-Migration/dependency_scanner.py) | Dependency manifest scanner | `package.json`, `requirements.txt`, `Gemfile`, `go.mod` | Manifest findings JSON, CLI score report |
| [`db_introspection_scanner.py`](file:///Users/user/PQC-Migration/db_introspection_scanner.py) | Live DB introspection | Host, port, user, password, DB name | Introspected schema crypto report JSON |
| [`sme_estimator.py`](file:///Users/user/PQC-Migration/sme_estimator.py) | SME stack profile estimator | Stack profile name (e.g. `django_postgres`) | Synthetic PQC readiness evaluation JSON |
| [`server.py`](file:///Users/user/PQC-Migration/server.py) | FastAPI application server | REST API, WebSocket-like polling, file uploads | Real-time interactive dashboard on port `8765` |
| [`generate_pdf_report.py`](file:///Users/user/PQC-Migration/generate_pdf_report.py) | Dynamic technical PDF export | Reads current `readiness_score.json` | `pqc_audit_report.pdf` |
| [`start_server.sh`](file:///Users/user/PQC-Migration/start_server.sh) | Safe daemon launcher script | Environment variables (`PQC_API_KEY`) | Manages process lifecycle with health checks |

---

## Quick Start

### 1. Prerequisites

- **Python**: Version `3.8` or higher (virtual environment recommended)
- **Node.js**: Version `18+` (required only for Playwright E2E browser tests)
- **PostgreSQL Client (Optional)**: `psycopg2-binary` (required for live database connections)

### 2. Setup

```bash
# Clone the repository
git clone https://github.com/CharanK-glitch/PQC-Migration.git
cd PQC-Migration

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install Python requirements
pip install fastapi uvicorn fpdf2 psycopg2-binary qrcode requests
```

---

## CLI Reference Guide

### 1. Core Scanner (`pgcrypto_scanner.py`)

```bash
python3 pgcrypto_scanner.py [TARGET_OPTIONS] [EXECUTION_FLAGS]
```

#### Supported Arguments

| Flag | Type | Description |
| :--- | :--- | :--- |
| `-g`, `--github` | URL | Target GitHub repository URL to clone and audit |
| `-m`, `--multi` | URLs | Scan multiple GitHub repositories in a single run |
| `-b`, `--batch` | File | Text file containing GitHub URLs (one per line) |
| `-c`, `--config` | Path | PostgreSQL configuration directory (`postgresql.conf`, `pg_hba.conf`) |
| `-s`, `--sql` | Path | Directory containing SQL scripts, schemas, or migrations |
| `--host` | String | Live PostgreSQL host (requires `--user` and `psycopg2`) |
| `-p`, `--port` | Int | PostgreSQL port (default: `5432`) |
| `-u`, `--user` | String | PostgreSQL username (default: `postgres`) |
| `-n`, `--name` | String | Custom project name label |
| `-o`, `--output` | Path | Output directory (default: current directory) |
| `--timeout` | Seconds | Timeout for remote git operations (default: `300`) |
| `--no-dashboard` | Flag | Skip generating HTML dashboard files |
| `--json` | Flag | Output structured JSON only |
| `-v`, `--verbose` | Flag | Enable verbose execution logging |

#### Examples

```bash
# Scan a remote GitHub repository
python3 pgcrypto_scanner.py --github https://github.com/owner/repo -n "MyApplication"

# Scan multiple repositories in one pass
python3 pgcrypto_scanner.py --multi https://github.com/owner/repo1 https://github.com/owner/repo2

# Scan local database configurations and migrations
python3 pgcrypto_scanner.py --config /etc/postgresql/16/main/ --sql ./migrations/ -n "ProdDB"
```

---

### 2. Dependency Scanner (`dependency_scanner.py`)

Scans software manifest files to detect cryptographic packages (OpenSSL, PyCryptodome, BouncyCastle, WebCrypto, etc.) and flag vulnerable versions.

```bash
# Scan a project directory for manifests
python3 dependency_scanner.py ./my-project --verbose

# Scan a specific package file and save report
python3 dependency_scanner.py ./my-project/package.json -o ./dep_report.json
```

---

### 3. Database Introspection Scanner (`db_introspection_scanner.py`)

Introspects a live PostgreSQL instance for cryptographic configurations, enabled extensions (`pgcrypto`), authentication methods, and SSL cipher suites without source access.

```bash
python3 db_introspection_scanner.py \
  --host localhost \
  --port 5432 \
  --user postgres \
  --database mydb \
  --verbose
```

---

### 4. SME Profile Estimator (`sme_estimator.py`)

Enables small/medium enterprises to quickly estimate migration timelines, cost, and complexity based on predefined architectural archetypes.

```bash
# List available stack profiles
python3 sme_estimator.py --list

# Run estimate for a Django + PostgreSQL stack
python3 sme_estimator.py --profile django_postgres --verbose -o ./sme_estimate.json
```

Supported profiles include `django_postgres`, `node_mongodb`, `java_spring`, `php_laravel`, `rails_postgres`, and `dotnet_sqlserver`.

---

## Interactive Web Dashboard

The repository includes a modern, high-contrast, responsive FastAPI dashboard with full PQC lifecycle management.

### Running the Server

Start the dashboard using the automated startup script:

```bash
./start_server.sh
```

Or run the server directly:

```bash
python3 server.py
```

- **Local URL**: [http://127.0.0.1:8765](http://127.0.0.1:8765)
- **Local Network**: Accessible via your machine's LAN IP (displayed in console at launch)

### Dashboard Features

1. **Overview & Metrics**: Live PQC score gauge (0–100), letter grade (A–F), readiness category, risk distribution, and NIST compliance status.
2. **Interactive CBOM**: Filterable table with full search across algorithm primitives, families, locations, and migration priorities (P0 to P4).
3. **Multi-Repo Scanner**: Paste multiple GitHub URLs, initiate asynchronous scans, inspect live per-repo progress, and review aggregated multi-repo scorecards.
4. **Website / SME Scanner**: Enter any public HTTPS website URL to test TLS protocol versions, cipher suites, certificate key types (RSA vs. ECDSA), and security headers (HSTS).
5. **35-Question Assessment Framework**: An interactive self-audit across four critical domains:
   - **Infrastructure**: TLS versions, certificates, HSTS, ciphers.
   - **Application Layer**: Public key usages, JWTs, hashing algorithms, crypto agility.
   - **Data Protection**: Storage encryption, database field-level ciphers, key management.
   - **Compliance & Governance**: Quantum risk register, vendor audits, timeline planning.
6. **Dynamic Reports**: Download `cbom.json`, `readiness_score.json`, and dynamic PDF technical reports generated on demand.

### Protected Deployments (API Key Auth)

For non-local or shared server environments, secure the endpoints using an environment variable:

```bash
export PQC_API_KEY='your-secure-random-token'
./start_server.sh
```

- When configured, sensitive operations (`/api/scan`, `/api/scan/multi`, `/api/assessment`) require authentication via the `X-API-Key` HTTP header.
- Users can input their session key securely through the key icon modal in the dashboard UI. Keys are kept exclusively in `sessionStorage` and never logged or exposed in URLs.

---

## NIST PQC Standards & Compliance Mapping

Findings are benchmarked against official NIST post-quantum cryptographic standards:

| Primitive Family | NIST Standard | Approved Standard | Migration Status |
| :--- | :--- | :--- | :--- |
| **Key Encapsulation (KEM)** | FIPS 203 | **ML-KEM** (Kyber) | Non-Compliant if RSA / ECC / DH |
| **Digital Signatures (DSA)** | FIPS 204 | **ML-DSA** (Dilithium) | Non-Compliant if RSA / ECDSA / EdDSA |
| **Stateless Hash Signatures** | FIPS 205 | **SLH-DSA** (SPHINCS+) | Non-Compliant if legacy signature |
| **Stateful Hash Signatures** | NIST SP 800-208 | **LMS / XMSS** | Special approval / firmware use |
| **Symmetric Encryption** | NIST SP 800-38D | **AES-256-GCM** | Advisory warning for AES-128, 3DES, Blowfish |
| **Hashing & Integrity** | FIPS 202 | **SHA-3 / SHAKE-256** | Critical failure for MD5, SHA-1 |

---

## Quantum Readiness Scoring Model

The **Post-Quantum Readiness (PQR) Score** evaluates cryptographic risk density normalized to a range of **0 to 100**:

$$\text{PQR} = \text{clamp}\left(100 - \sum (W_{\text{risk}} \times C_{\text{asset}}) + B_{\text{pqc}} - P_{\text{critical}}, 0, 100\right)$$

### Risk Weight Allocations

- **P0 - Critical (30 pts)**: Shor-vulnerable asymmetric algorithms (RSA < 2048, ECC, ECDSA, ECDH) and broken primitives (MD5, DES, RC4).
- **P1 - High (20 pts)**: Legacy asymmetric primitives (RSA-2048/4096) and deprecated hashing (SHA-1).
- **P2 - Medium (10 pts)**: Symmetric ciphers with degraded quantum margins (AES-128, Blowfish).
- **P3 - Low / Safe (0 pts)**: Quantum-resistant symmetric schemes (AES-256-GCM, SHA-256, SHA-384, SHA-512, ChaCha20).
- **P4 - PQC Standard (+Bonus)**: Native post-quantum primitives (ML-KEM, ML-DSA, SLH-DSA).

---

## Executive Reports & PDF Generation

Generate publication-ready PDF audit briefs using Python:

```bash
# Generate technical audit report from current readiness_score.json
python3 generate_pdf_report.py

# Generate executive presentation brief
python3 generate_script_pdf.py

# Generate operational guide
python3 generate_guide.py
```

Generated outputs:
- `pqc_audit_report.pdf`: Complete technical analysis with mathematical formulations, CBOM table summaries, and NIST compliance matrices.
- `presentation_script.pdf`: Slide deck and talking points for executive leadership.
- `pgcrypto_scanner_guide.pdf`: Step-by-step administrator guide.

---

## Verification & Automated Test Suites

The repository is covered by three complementary validation suites:

### 1. Fix Verification & Security Regression Suite
Verifies XSS sanitization, authentication decorators, URL validations, subprocess timeouts, and scanner extensions:
```bash
python3 verify_fixes.py
```
*(33 checks covering core security and functionality).*

### 2. Python Unit Tests
Validates aggregation logic, score engines, and multi-repo calculations:
```bash
python3 -m unittest discover tests
```

### 3. Playwright End-to-End Browser Tests
Validates dashboard accessibility, keyboard navigation, theme switching, API key handling, and scanner UI workflows:
```bash
# Install test dependencies (first time only)
npm install
npx playwright install chromium

# Run E2E suite
npm run test:e2e
```

---

## License & Usage Restrictions

Copyright (c) 2026 Charan Kasimahanti. All Rights Reserved.

This software is released under the **Business Source License 1.1 (BUSL-1.1)**:
- **Permitted**: Non-commercial internal testing, evaluation, and security research.
- **Prohibited**: Commercial redistribution, hosting as a managed SaaS service, or public commercial derivatives without explicit written licensing.

See [LICENSE](LICENSE) for complete licensing terms.
