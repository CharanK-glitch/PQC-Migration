#!/usr/bin/env python3
"""
SME Profile-Based PQC Migration Estimator

Estimates post-quantum cryptography migration complexity for small/medium
enterprises without requiring access to source codebases.

Uses technology stack profiles to generate synthetic findings that are then
scored using the standard weight engine.
"""

import json
import argparse
from typing import List, Dict
from pathlib import Path

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scoring.weight_engine import compute_readiness_score
from scoring.nist_compliance import check_nist_compliance
from output.score_reporter import generate_score_report, save_score_report, print_terminal_report


STACK_PROFILES = {
    "django_postgres": {
        "name": "Django + PostgreSQL",
        "description": "Python Django web application with PostgreSQL database",
        "typical_findings": [
            {"algorithm": "SHA-256", "primitive": "hash", "family": "SHA-2", "count": 15, "risk": 2},
            {"algorithm": "AES-256", "primitive": "encryption", "family": "AES", "count": 8, "risk": 2},
            {"algorithm": "RSA-2048", "primitive": "digital-signature", "family": "RSA", "count": 5, "risk": 0},
            {"algorithm": "ECDSA P-256", "primitive": "digital-signature", "family": "ECDSA", "count": 3, "risk": 0},
            {"algorithm": "PBKDF2", "primitive": "kdf", "family": "PBKDF2", "count": 10, "risk": 1},
            {"algorithm": "HMAC-SHA256", "primitive": "mac", "family": "HMAC", "count": 12, "risk": 2},
            {"algorithm": "TLS 1.2", "primitive": "certificate", "family": "TLS", "count": 4, "risk": 1},
            {"algorithm": "bcrypt", "primitive": "kdf", "family": "bcrypt", "count": 6, "risk": 2},
        ],
    },
    "node_mongodb": {
        "name": "Node.js + MongoDB",
        "description": "Node.js application with MongoDB database",
        "typical_findings": [
            {"algorithm": "SHA-256", "primitive": "hash", "family": "SHA-2", "count": 20, "risk": 2},
            {"algorithm": "AES-256", "primitive": "encryption", "family": "AES", "count": 10, "risk": 2},
            {"algorithm": "RSA-2048", "primitive": "digital-signature", "family": "RSA", "count": 8, "risk": 0},
            {"algorithm": "ECDSA P-256", "primitive": "digital-signature", "family": "ECDSA", "count": 5, "risk": 0},
            {"algorithm": "PBKDF2", "primitive": "kdf", "family": "PBKDF2", "count": 15, "risk": 1},
            {"algorithm": "HMAC-SHA256", "primitive": "mac", "family": "HMAC", "count": 18, "risk": 2},
            {"algorithm": "TLS 1.2", "primitive": "certificate", "family": "TLS", "count": 6, "risk": 1},
            {"algorithm": "MD5", "primitive": "hash", "family": "MD5", "count": 3, "risk": 0},
        ],
    },
    "java_spring": {
        "name": "Java Spring + PostgreSQL",
        "description": "Java Spring Boot application with PostgreSQL",
        "typical_findings": [
            {"algorithm": "SHA-256", "primitive": "hash", "family": "SHA-2", "count": 25, "risk": 2},
            {"algorithm": "AES-256", "primitive": "encryption", "family": "AES", "count": 12, "risk": 2},
            {"algorithm": "RSA-2048", "primitive": "digital-signature", "family": "RSA", "count": 10, "risk": 0},
            {"algorithm": "ECDSA P-256", "primitive": "digital-signature", "family": "ECDSA", "count": 8, "risk": 0},
            {"algorithm": "PBKDF2", "primitive": "kdf", "family": "PBKDF2", "count": 20, "risk": 1},
            {"algorithm": "HMAC-SHA256", "primitive": "mac", "family": "HMAC", "count": 22, "risk": 2},
            {"algorithm": "TLS 1.2", "primitive": "certificate", "family": "TLS", "count": 8, "risk": 1},
            {"algorithm": "SHA-1", "primitive": "hash", "family": "SHA-1", "count": 5, "risk": 0},
        ],
    },
    "php_laravel": {
        "name": "PHP Laravel + MySQL",
        "description": "PHP Laravel application with MySQL database",
        "typical_findings": [
            {"algorithm": "SHA-256", "primitive": "hash", "family": "SHA-2", "count": 18, "risk": 2},
            {"algorithm": "AES-256", "primitive": "encryption", "family": "AES", "count": 8, "risk": 2},
            {"algorithm": "RSA-2048", "primitive": "digital-signature", "family": "RSA", "count": 6, "risk": 0},
            {"algorithm": "ECDSA P-256", "primitive": "digital-signature", "family": "ECDSA", "count": 4, "risk": 0},
            {"algorithm": "bcrypt", "primitive": "kdf", "family": "bcrypt", "count": 12, "risk": 2},
            {"algorithm": "HMAC-SHA256", "primitive": "mac", "family": "HMAC", "count": 15, "risk": 2},
            {"algorithm": "TLS 1.2", "primitive": "certificate", "family": "TLS", "count": 5, "risk": 1},
            {"algorithm": "MD5", "primitive": "hash", "family": "MD5", "count": 8, "risk": 0},
        ],
    },
    "rails_postgres": {
        "name": "Ruby on Rails + PostgreSQL",
        "description": "Ruby on Rails application with PostgreSQL",
        "typical_findings": [
            {"algorithm": "SHA-256", "primitive": "hash", "family": "SHA-2", "count": 16, "risk": 2},
            {"algorithm": "AES-256", "primitive": "encryption", "family": "AES", "count": 7, "risk": 2},
            {"algorithm": "RSA-2048", "primitive": "digital-signature", "family": "RSA", "count": 4, "risk": 0},
            {"algorithm": "ECDSA P-256", "primitive": "digital-signature", "family": "ECDSA", "count": 3, "risk": 0},
            {"algorithm": "bcrypt", "primitive": "kdf", "family": "bcrypt", "count": 14, "risk": 2},
            {"algorithm": "HMAC-SHA256", "primitive": "mac", "family": "HMAC", "count": 16, "risk": 2},
            {"algorithm": "TLS 1.2", "primitive": "certificate", "family": "TLS", "count": 4, "risk": 1},
            {"algorithm": "PBKDF2", "primitive": "kdf", "family": "PBKDF2", "count": 8, "risk": 1},
        ],
    },
    "dotnet_sqlserver": {
        "name": ".NET + SQL Server",
        "description": "C# .NET application with SQL Server database",
        "typical_findings": [
            {"algorithm": "SHA-256", "primitive": "hash", "family": "SHA-2", "count": 22, "risk": 2},
            {"algorithm": "AES-256", "primitive": "encryption", "family": "AES", "count": 10, "risk": 2},
            {"algorithm": "RSA-2048", "primitive": "digital-signature", "family": "RSA", "count": 12, "risk": 0},
            {"algorithm": "ECDSA P-256", "primitive": "digital-signature", "family": "ECDSA", "count": 6, "risk": 0},
            {"algorithm": "PBKDF2", "primitive": "kdf", "family": "PBKDF2", "count": 18, "risk": 1},
            {"algorithm": "HMAC-SHA256", "primitive": "mac", "family": "HMAC", "count": 20, "risk": 2},
            {"algorithm": "TLS 1.2", "primitive": "certificate", "family": "TLS", "count": 7, "risk": 1},
            {"algorithm": "3DES", "primitive": "encryption", "family": "3DES", "count": 4, "risk": 0},
        ],
    },
}


def profile_to_findings(profile: Dict) -> List[Dict]:
    """Convert a stack profile into synthetic findings."""
    findings = []
    for item in profile["typical_findings"]:
        findings.append({
            "rule_id": f"profile_{item['algorithm'].lower().replace('-', '_')}",
            "rule_name": item["algorithm"],
            "category": "profile",
            "file": "profile_estimate",
            "line_number": 0,
            "content": f"Estimated from stack profile: {profile['name']}",
            "language": "unknown",
            "algorithm": {
                "algorithmFamily": item["family"],
                "algorithmName": item["algorithm"],
                "primitive": item["primitive"],
                "risk": item["risk"],
                "nistQuantumSecurityLevel": 1 if item["risk"] == 2 else 0,
                "classicalSecurityLevel": 256 if item["risk"] == 2 else 112,
                "securityProperties": ["quantum-resistant"] if item["risk"] == 2 else ["quantum-vulnerable"],
            },
            "replacement": "See NIST PQC standards",
            "priority": "P4-Safe" if item["risk"] == 2 else "P0-Critical",
            "effort": "Low" if item["risk"] == 2 else "High",
            "source": "generic",
        })
    return findings


def estimate_migration(profile_name: str, output_path: str = None) -> Dict:
    """Run migration estimation for a given stack profile."""
    if profile_name not in STACK_PROFILES:
        available = ", ".join(STACK_PROFILES.keys())
        raise ValueError(f"Unknown profile '{profile_name}'. Available: {available}")

    profile = STACK_PROFILES[profile_name]
    findings = profile_to_findings(profile)

    score_data = compute_readiness_score(findings)
    compliance = check_nist_compliance(findings)

    report = generate_score_report(
        score_data=score_data,
        compliance=compliance,
        findings=findings,
        project_name=profile["name"],
        scan_mode="profile",
    )

    report["profile_description"] = profile["description"]
    report["estimation_method"] = "stack_profile"

    if output_path:
        save_score_report(report, output_path)

    return report


def list_profiles():
    """List all available stack profiles."""
    print("\nAvailable Technology Stack Profiles:")
    print("=" * 60)
    for key, profile in STACK_PROFILES.items():
        print(f"\n  {key}")
        print(f"    Name: {profile['name']}")
        print(f"    Description: {profile['description']}")
        print(f"    Typical algorithms: {len(profile['typical_findings'])}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="SME PQC Migration Estimator - Estimate migration complexity without source code",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--profile", "-p",
        help="Technology stack profile to estimate (e.g., django_postgres)"
    )
    parser.add_argument(
        "--list", "-l",
        action="store_true",
        help="List all available stack profiles"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output path for the estimation report JSON"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print detailed terminal report"
    )

    args = parser.parse_args()

    if args.list:
        list_profiles()
        return

    if not args.profile:
        parser.error("Please specify --profile or use --list to see available profiles")

    try:
        report = estimate_migration(args.profile, args.output)
        print(f"\nEstimation complete for: {report['project_name']}")
        print(f"  PQC Readiness Score: {report['score']}/100 (Grade: {report['grade']})")
        print(f"  Total Assets: {report['total_assets']}")
        print(f"  Vulnerable: {report['vulnerable_assets']}")
        print(f"  Safe: {report['safe_assets']}")

        if args.verbose:
            print_terminal_report(report, f"profile:{args.profile}")

        if args.output:
            print(f"\n  Report saved to: {args.output}")

    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
