#!/usr/bin/env python3
"""
Verification script for all PQC-Migration fixes and features.

Run this script to verify that all bug fixes and new features are working correctly.
"""

import sys
import os
import re
import json
import subprocess
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

BASE_DIR = Path(__file__).parent

class VerificationResult:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.warnings = 0
        self.results = []

    def check(self, name: str, condition: bool, details: str = ""):
        status = "PASS" if condition else "FAIL"
        if condition:
            self.passed += 1
        else:
            self.failed += 1
        self.results.append((name, status, details))
        print(f"  [{status}] {name}" + (f" - {details}" if details else ""))

    def warn(self, name: str, details: str = ""):
        self.warnings += 1
        self.results.append((name, "WARN", details))
        print(f"  [WARN] {name}" + (f" - {details}" if details else ""))

    def summary(self):
        print(f"\n{'='*60}")
        print(f"Verification Summary")
        print(f"{'='*60}")
        print(f"  Passed:  {self.passed}")
        print(f"  Failed:  {self.failed}")
        print(f"  Warnings: {self.warnings}")
        print(f"{'='*60}")
        return self.failed == 0


def verify_xss_fixes(result: VerificationResult):
    """Verify XSS fixes in dashboard."""
    print("\n--- XSS Fixes ---")
    dashboard_path = BASE_DIR / "dashboard" / "index.html"
    content = dashboard_path.read_text()

    result.check(
        "XSS: esc() function defined",
        "function esc(s)" in content,
        "HTML escape function should be defined"
    )

    result.check(
        "XSS: renderCBOM uses esc()",
        "esc(r.name)" in content and "esc(r.snippet)" in content,
        "CBOM rendering should escape user data"
    )

    result.check(
        "XSS: renderRoadmap uses esc()",
        "esc(it.algorithm)" in content and "esc(it.replacement)" in content,
        "Roadmap rendering should escape user data"
    )

    result.check(
        "XSS: renderCompliance uses esc()",
        "esc(ci.name)" in content and "esc(ci.description)" in content,
        "Compliance rendering should escape user data"
    )


def verify_server_auth(result: VerificationResult):
    """Verify server authentication and input validation."""
    print("\n--- Server Security ---")
    server_path = BASE_DIR / "server.py"
    content = server_path.read_text()

    result.check(
        "Auth: API key header defined",
        "APIKeyHeader" in content,
        "API key authentication should be implemented"
    )

    result.check(
        "Auth: verify_api_key function",
        "def verify_api_key" in content,
        "API key verification function should exist"
    )

    result.check(
        "Auth: scan endpoint uses Depends",
        "Depends(verify_api_key)" in content,
        "Scan endpoint should require authentication"
    )

    result.check(
        "Validation: GitHub URL regex",
        "_GITHUB_URL_RE" in content,
        "GitHub URL validation should be implemented"
    )

    result.check(
        "Validation: local path validation",
        "_validate_local_path" in content,
        "Local path validation should be implemented"
    )

    result.check(
        "Security: subprocess timeout",
        "proc.wait(timeout=" in content,
        "Subprocess should have timeout"
    )


def verify_weight_engine(result: VerificationResult):
    """Verify weight engine fixes."""
    print("\n--- Weight Engine ---")
    weight_path = BASE_DIR / "scoring" / "weight_engine.py"
    content = weight_path.read_text()

    result.check(
        "Weight: language_breakdown populated",
        'language_breakdown[language]["total"]' in content,
        "Language breakdown should be populated"
    )

    result.check(
        "Weight: language in aggregate",
        '"language": f.get("language"' in content,
        "Language should be extracted from findings"
    )


def verify_postgres_scanner(result: VerificationResult):
    """Verify PostgreSQL scanner fixes."""
    print("\n--- PostgreSQL Scanner ---")
    scanner_path = BASE_DIR / "scanner" / "postgres_scanner.py"
    content = scanner_path.read_text()

    result.check(
        "Scanner: .rs in PG_EXTENSION_MAP",
        '".rs": "rust"' in content,
        "Rust files should be scannable"
    )

    result.check(
        "Scanner: .php in PG_EXTENSION_MAP",
        '".php": "php"' in content,
        "PHP files should be scannable"
    )

    result.check(
        "Scanner: check_hba_password handler",
        '"check_hba_password"' in content,
        "Missing check_func should be implemented"
    )

    result.check(
        "Scanner: check_digest_md5 handler",
        '"check_digest_md5"' in content,
        "Missing check_func should be implemented"
    )

    result.check(
        "Scanner: check_wal_level handler",
        '"check_wal_level"' in content,
        "Missing check_func should be implemented"
    )


def verify_pgcrypto_scanner(result: VerificationResult):
    """Verify pgcrypto scanner fixes."""
    print("\n--- pgcrypto Scanner ---")
    scanner_path = BASE_DIR / "pgcrypto_scanner.py"
    content = scanner_path.read_text()

    result.check(
        "Scanner: password parameter",
        "password=args.password" in content,
        "Connection should include password parameter"
    )

    result.check(
        "Scanner: try/finally for connection",
        "finally:" in content and "conn.close()" in content,
        "Connection should be closed in finally block"
    )


def verify_regex_fixes(result: VerificationResult):
    """Verify regex pattern fixes."""
    print("\n--- Regex Fixes ---")
    hashes_path = BASE_DIR / "rules" / "generic" / "hashes.py"
    content = hashes_path.read_text()

    result.check(
        "Regex: MD5 config pattern narrowed",
        r"password_encryption|ssl_ciphers" in content,
        "MD5 config pattern should be more specific"
    )

    ciphers_path = BASE_DIR / "rules" / "generic" / "ciphers.py"
    content = ciphers_path.read_text()

    result.check(
        "Regex: DES config pattern narrowed",
        r"ssl_ciphers" in content,
        "DES config pattern should be more specific"
    )


def verify_output_fixes(result: VerificationResult):
    """Verify output module fixes."""
    print("\n--- Output Fixes ---")
    reporter_path = BASE_DIR / "output" / "score_reporter.py"
    content = reporter_path.read_text()

    result.check(
        "Output: score color used",
        "score_color}PQC READINESS SCORE" in content,
        "Score color should be used in output"
    )

    cbom_path = BASE_DIR / "output" / "cbom_generator.py"
    content = cbom_path.read_text()

    result.check(
        "Output: _relative_path safe",
        'filepath.split("/")[-1]' in content,
        "Relative path should not expose absolute paths"
    )


def verify_new_features(result: VerificationResult):
    """Verify new features are implemented."""
    print("\n--- New Features ---")

    result.check(
        "Feature: SME estimator exists",
        (BASE_DIR / "sme_estimator.py").exists(),
        "SME profile-based estimator should exist"
    )

    result.check(
        "Feature: Dependency scanner exists",
        (BASE_DIR / "dependency_scanner.py").exists(),
        "Dependency manifest scanner should exist"
    )

    result.check(
        "Feature: DB introspection scanner exists",
        (BASE_DIR / "db_introspection_scanner.py").exists(),
        "Database introspection scanner should exist"
    )

    result.check(
        "Feature: Batch scanning args",
        "--batch" in (BASE_DIR / "pgcrypto_scanner.py").read_text(),
        "Batch scanning argument should be added"
    )

    result.check(
        "Feature: Multi scanning args",
        "--multi" in (BASE_DIR / "pgcrypto_scanner.py").read_text(),
        "Multi-repo scanning argument should be added"
    )


def verify_sme_estimator(result: VerificationResult):
    """Verify SME estimator functionality."""
    print("\n--- SME Estimator Functionality ---")
    try:
        from sme_estimator import estimate_migration, STACK_PROFILES

        result.check(
            "SME: profiles available",
            len(STACK_PROFILES) >= 5,
            f"Should have at least 5 stack profiles, found {len(STACK_PROFILES)}"
        )

        report = estimate_migration("django_postgres")
        result.check(
            "SME: estimation produces score",
            "score" in report and 0 <= report["score"] <= 100,
            f"Score should be 0-100, got {report.get('score')}"
        )

        result.check(
            "SME: estimation produces roadmap",
            "migration_roadmap" in report,
            "Report should include migration roadmap"
        )

    except Exception as e:
        result.check("SME: estimator runs", False, str(e))


def verify_dependency_scanner(result: VerificationResult):
    """Verify dependency scanner functionality."""
    print("\n--- Dependency Scanner Functionality ---")
    try:
        from dependency_scanner import scan_package_json, CRYPTO_LIBRARIES

        result.check(
            "DepScan: crypto libraries defined",
            len(CRYPTO_LIBRARIES) >= 5,
            f"Should have at least 5 crypto libraries, found {len(CRYPTO_LIBRARIES)}"
        )

        test_pkg = {
            "dependencies": {
                "cryptography": "^3.0.0",
                "pycryptodome": "^3.15.0",
                "express": "^4.18.0",
            }
        }
        test_path = BASE_DIR / "test_package.json"
        with open(test_path, "w") as f:
            json.dump(test_pkg, f)

        findings = scan_package_json(str(test_path))
        result.check(
            "DepScan: finds crypto libraries",
            len(findings) >= 2,
            f"Should find at least 2 crypto libraries, found {len(findings)}"
        )

        test_path.unlink()

    except Exception as e:
        result.check("DepScan: scanner runs", False, str(e))


def main():
    print("="*60)
    print("PQC-Migration Fix Verification")
    print("="*60)

    result = VerificationResult()

    verify_xss_fixes(result)
    verify_server_auth(result)
    verify_weight_engine(result)
    verify_postgres_scanner(result)
    verify_pgcrypto_scanner(result)
    verify_regex_fixes(result)
    verify_output_fixes(result)
    verify_new_features(result)
    verify_sme_estimator(result)
    verify_dependency_scanner(result)

    success = result.summary()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
