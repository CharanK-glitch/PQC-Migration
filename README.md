# pgcrypto PQC Scanner & Audit Suite

[![Post-Quantum Cryptography](https://img.shields.io/badge/Cryptography-Post--Quantum-blueviolet.svg?style=flat-square)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![PostgreSQL Support](https://img.shields.io/badge/PostgreSQL-12--17-336791.svg?style=flat-square&logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![NIST FIPS Compliance](https://img.shields.io/badge/NIST-FIPS_203_|_204_|_205-green.svg?style=flat-square)](https://csrc.nist.gov/)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-3776AB.svg?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-red.svg?style=flat-square)](LICENSE)

The **pgcrypto PQC Scanner** is an enterprise post-quantum cryptography (PQC) auditing engine for PostgreSQL infrastructure, `pgcrypto` SQL usage, server configurations, network parameters, C-extensions, and application migration scripts. It assists database administrators, security teams, and compliance officers in evaluating quantum vulnerability profiles and preparing migration roadmaps aligned with NIST PQC standards.

---

## Table of Contents

- [Overview](#overview)
- [Key Capabilities](#key-capabilities)
- [Post-Quantum Risk Context](#post-quantum-risk-context)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Command-Line Reference](#command-line-reference)
- [Audit Modes](#audit-modes)
- [CBOM Standard & Output Artifacts](#cbom-standard--output-artifacts)
- [NIST Compliance Framework Mapping](#nist-compliance-framework-mapping)
- [Quantum Readiness Scoring Model](#quantum-readiness-scoring-model)
- [Reporting Tools & Executive Exports](#reporting-tools--executive-exports)
- [Web Dashboard](#web-dashboard)
- [License](#license)

---

## Overview

Modern database deployments rely heavily on legacy public-key cryptography (RSA, ECC, Diffie-Hellman) and legacy symmetric primitive configurations. As quantum processing capabilities advance, these algorithms face fundamental security degradation.

The `pgcrypto PQC Scanner` performs automated static analysis across database schemas, SQL migrations, configuration files, and live instances to identify quantum-vulnerable cryptographic implementations, produce standard Cryptographic Bill of Materials (CBOM) inventories, and calculate deterministic readiness scores.

---

## Key Capabilities

- **Multi-Layer Analysis**: Scans SQL scripts, stored procedures, `pgcrypto` calls (`digest`, `hmac`, `pgp_sym_encrypt`, `encrypt_iv`), server settings (`postgresql.conf`, `pg_hba.conf`), TLS suites, and native extension source code.
- **CBOM Generation**: Generates structured JSON Cryptographic Bill of Materials (CBOM) artifacts compliant with supply chain security practices.
- **NIST Standard Mapping**: Maps findings to NIST FIPS PQC standards (**FIPS 203 ML-KEM**, **FIPS 204 ML-DSA**, and **FIPS 205 SLH-DSA**).
- **Quantitative Readiness Scoring**: Evaluates risk density, primitive usage, and exposure surfaces to generate a normalized 0–100 Readiness Index.
- **Local Web Visualization**: Serves a lightweight web interface for detailed findings navigation, algorithm distribution analysis, and remediation planning.
- **Automated Report Generation**: Supports automated LaTeX rendering to produce executive audit PDFs and technical presentation briefs.

---

## Post-Quantum Risk Context

Advances in quantum computing impact current cryptographic primitives through two principal theoretical mechanisms:

1. **Shor's Algorithm**: Solves prime factorization and discrete logarithm problems in polynomial time, compromising public-key schemes such as RSA, DSA, ECDSA, and ECDH.
2. **Grover's Algorithm**: Accelerates brute-force search against symmetric ciphers and hash functions, effectively halving key security (e.g., AES-128 offers 64 bits of quantum security).

| Legacy Cryptographic Primitive | Primary Risk Vector | Target PQC Standard |
| :--- | :--- | :--- |
| **RSA-2048 / RSA-4096** | Asymmetric Key Exchange & Signatures | NIST FIPS 203 (ML-KEM) / FIPS 204 (ML-DSA) |
| **ECC / ECDSA / ECDH** | Asymmetric Key Exchange & Signatures | NIST FIPS 203 (ML-KEM) / FIPS 204 (ML-DSA) |
| **AES-128 / Blowfish** | Reduced Symmetric Key Margin | AES-256-GCM / NIST SP 800-38D |
| **SHA-1 / MD5** | Collision Degradation | SHA-3 / SHAKE-256 (FIPS 202) |

---

## Architecture

```
                                ┌─────────────────────────┐
                                │      Scan Targets       │
                                │ (Config / SQL / GitHub) │
                                └────────────┬────────────┘
                                             │
                                             ▼
                                ┌─────────────────────────┐
                                │     Scanner Engine      │
                                └────────────┬────────────┘
                                             │
                       ┌─────────────────────┴─────────────────────┐
                       ▼                                           ▼
          ┌─────────────────────────┐                 ┌─────────────────────────┐
          │     PostgresScanner     │                 │     GenericScanner      │
          └────────────┬────────────┘                 └────────────┬────────────┘
                       │                                           │
                       └─────────────────────┬─────────────────────┘
                                             │
                                             ▼
                                ┌─────────────────────────┐
                                │ AST & Pattern Normalizer│
                                └────────────┬────────────┘
                                             │
                       ┌─────────────────────┴─────────────────────┐
                       ▼                                           ▼
          ┌─────────────────────────┐                 ┌─────────────────────────┐
          │ Weight Scoring Engine   │                 │ NIST Compliance Engine  │
          └────────────┬────────────┘                 └────────────┬────────────┘
                       │                                           │
                       └─────────────────────┬─────────────────────┘
                                             │
                                             ▼
                                ┌─────────────────────────┐
                                │     CBOM Generator      │
                                └────────────┬────────────┘
                                             │
                ┌────────────────────────────┼────────────────────────────┐
                ▼                            ▼                            ▼
     ┌───────────────────┐        ┌───────────────────┐        ┌───────────────────┐
     │     cbom.json     │        │ readiness_score   │        │   Web Dashboard   │
     └───────────────────┘        └───────────────────┘        └───────────────────┘
```

---

## Quick Start

### Prerequisites

- **Python**: Version `3.8` or higher
- **PostgreSQL Client Library (Optional)**: `psycopg2` (required only for live database host connections)
- **LaTeX Distribution (Optional)**: `pdflatex` (required only for PDF report compilation)

### Setup

```bash
# Clone the repository
git clone https://github.com/CharanK-glitch/PQC-Migration.git
cd PQC-Migration

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install optional live database dependencies
pip install psycopg2-binary
```

---

## Command-Line Reference

```bash
python3 pgcrypto_scanner.py [TARGET_OPTIONS] [EXECUTION_FLAGS]
```

### Options Overview

| Parameter | Type | Description | Default |
| :--- | :--- | :--- | :--- |
| `-c`, `--config` | Path | Directory path to PostgreSQL configuration files | `None` |
| `-g`, `--github` | URL | Remote GitHub repository URL to clone and audit | `None` |
| `-s`, `--sql` | Path | Directory containing SQL scripts and migration files | `None` |
| `--host` | String | PostgreSQL hostname or IP for live schema inspection | `None` |
| `-p`, `--port` | Integer | PostgreSQL service port | `5432` |
| `-u`, `--user` | String | PostgreSQL database username | `postgres` |
| `-n`, `--name` | String | Project descriptor label | Target Directory / Repo |
| `-o`, `--output` | Path | Output directory for audit artifacts | `./output` |
| `--no-dashboard` | Flag | Suppress visual dashboard output generation | `False` |
| `--json` | Flag | Restrict output to machine-readable JSON format | `False` |
| `-v`, `--verbose` | Flag | Enable detailed execution logging | `False` |

---

## Audit Modes

### 1. Local Configuration Directory Scan
Analyzes database configuration settings, TLS context, and authentication parameters:
```bash
python3 pgcrypto_scanner.py --config /etc/postgresql/16/main/ --name "ProductionCluster"
```

### 2. Remote Repository Audit
Clones and evaluates SQL scripts, application code, and deployment manifests from source control:
```bash
python3 pgcrypto_scanner.py --github https://github.com/organization/database-repo --name "AppRepository"
```

### 3. Static SQL File Scan
Inspects migration folders, schema files, and stored procedures:
```bash
python3 pgcrypto_scanner.py --sql ./database/migrations/ --name "MigrationAudit"
```

---

## CBOM Standard & Output Artifacts

Running an audit generates structured findings in the designated output directory:

- **`cbom.json`**: Standardized Cryptographic Bill of Materials containing asset metadata, file locations, primitive classifications, and vulnerability designations.
- **`readiness_score.json`**: Score evaluation summary detailing overall rating, algorithm counts, compliance statuses, and penalty distributions.
- **`dashboard/`**: Static HTML/CSS/JS asset bundle for local dashboard inspection.

---

## NIST Compliance Framework Mapping

Findings are benchmarked against formal PQC specifications published by NIST:

| Target Primitive | NIST Specification | Modern Standard | Assessment Status |
| :--- | :--- | :--- | :--- |
| Key Encapsulation (KEM) | NIST SP 800-203 | **ML-KEM** (FIPS 203) | Non-Compliant if Legacy |
| Digital Signatures (DSA) | NIST SP 800-204 | **ML-DSA** (FIPS 204) | Non-Compliant if Legacy |
| Stateless Hash Signatures | NIST SP 800-205 | **SLH-DSA** (FIPS 205) | Non-Compliant if Legacy |
| Symmetric Encryption | NIST SP 800-38D | **AES-256-GCM** | Advisory Warning if < 256 bits |

---

## Quantum Readiness Scoring Model

The **Quantum Readiness Score** ($S$) is calculated as a normalized metric from **0** to **100**:

$$S = 100 - \min\left(100, \sum_{i=1}^{N} W(A_i) \times C(A_i)\right)$$

Where:
- $W(A_i)$ represents the risk weight assigned to algorithm $A_i$:
  - **Critical Risk (30 pts)**: RSA, ECC, ECDSA, Diffie-Hellman
  - **High Risk (20 pts)**: MD5, SHA-1, Blowfish, DES
  - **Medium Risk (10 pts)**: AES-128, SHA-256 (in key derivation contexts)
  - **Quantum Safe (0 pts)**: AES-256, SHA-3, ML-KEM, ML-DSA
- $C(A_i)$ represents the occurrence frequency of algorithm $A_i$.

---

## Reporting Tools & Executive Exports

The framework includes dedicated utilities for producing executive-ready documentation:

```bash
# Compile LaTeX technical audit report
python3 generate_pdf_report.py

# Generate executive presentation brief
python3 generate_script_pdf.py

# Generate scanner operational guide
python3 generate_guide.py
```

Generated outputs:
- `pqc_audit_report.pdf`
- `presentation_script.pdf`
- `pgcrypto_scanner_guide.pdf`

---

## Web Dashboard

The framework provides an optional HTTP server interface to visually inspect audit results:

```bash
python3 server.py --port 8000 --dir dashboard
```

Navigate to `http://localhost:8000` to review summary metrics, risk distribution breakdowns, compliance matrices, and code remediation recommendations.

---

## License & Usage Restrictions

Copyright (c) 2026 Charan Kasimahanti. All Rights Reserved.

This repository is licensed under the **Business Source License 1.1 (BUSL-1.1)** / Proprietary terms:
- **Permitted**: Non-commercial internal testing, security code inspection, and evaluation.
- **Prohibited**: Copying, distribution, hosting as a commercial service/SaaS, selling, sublicensing, or creating commercial derivative works without explicit written permission from the copyright owner.

Refer to the full [LICENSE](LICENSE) file for complete legal terms.

