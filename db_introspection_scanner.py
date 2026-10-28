#!/usr/bin/env python3
"""
Database Introspection Scanner

Queries a live PostgreSQL instance to detect cryptographic usage patterns
without requiring access to source code. Analyzes pgcrypto functions,
SSL configuration, authentication methods, and stored procedure definitions.
"""

import json
import argparse
from typing import List, Dict, Optional
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scoring.weight_engine import compute_readiness_score
from scoring.nist_compliance import check_nist_compliance
from output.score_reporter import generate_score_report, save_score_report, print_terminal_report


def scan_postgresql_connection(
    host: str = "localhost",
    port: int = 5432,
    user: str = "postgres",
    password: str = None,
    database: str = "postgres",
) -> List[Dict]:
    """Connect to PostgreSQL and introspect crypto usage."""
    try:
        import psycopg2
    except ImportError:
        print("ERROR: psycopg2 not installed. Install with: pip install psycopg2-binary")
        return []

    findings = []

    try:
        conn = psycopg2.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            dbname=database,
        )
        cur = conn.cursor()

        findings.extend(_check_pgcrypto_functions(cur))
        findings.extend(_check_ssl_config(cur))
        findings.extend(_check_auth_methods(cur))
        findings.extend(_check_stored_procedures(cur))
        findings.extend(_check_password_encryption(cur))

        conn.close()
    except Exception as e:
        print(f"ERROR: Could not connect to PostgreSQL: {e}")
        return []

    return findings


def _check_pgcrypto_functions(cur) -> List[Dict]:
    """Check for pgcrypto extension and function usage."""
    findings = []

    try:
        cur.execute("SELECT extname FROM pg_extension WHERE extname = 'pgcrypto'")
        if cur.fetchone():
            findings.append({
                "rule_id": "db_pgcrypto_installed",
                "rule_name": "pgcrypto Extension Installed",
                "category": "pgcrypto",
                "file": "database",
                "line_number": 0,
                "content": "pgcrypto extension is installed",
                "language": "sql",
                "algorithm": {
                    "algorithmFamily": "pgcrypto",
                    "algorithmName": "pgcrypto Extension",
                    "primitive": "encryption",
                    "risk": 2,
                    "nistQuantumSecurityLevel": 1,
                    "classicalSecurityLevel": 256,
                    "securityProperties": ["pgcrypto-installed"],
                },
                "replacement": "Review pgcrypto function usage for RSA/ECDSA",
                "priority": "P3-Low",
                "effort": "Low",
                "source": "database",
            })

            cur.execute("""
                SELECT routine_name, routine_type
                FROM information_schema.routines
                WHERE routine_schema = 'public'
                AND routine_name IN (
                    'pgp_pub_encrypt', 'pgp_pub_decrypt',
                    'pgp_sym_encrypt', 'pgp_sym_decrypt',
                    'digest', 'hmac', 'gen_salt'
                )
            """)
            for row in cur.fetchall():
                func_name = row[0]
                is_vulnerable = func_name in ('pgp_pub_encrypt', 'pgp_pub_decrypt')

                findings.append({
                    "rule_id": f"db_pgcrypto_{func_name}",
                    "rule_name": f"pgcrypto: {func_name}()",
                    "category": "pgcrypto",
                    "file": "database",
                    "line_number": 0,
                    "content": f"Function {func_name}() is defined",
                    "language": "sql",
                    "algorithm": {
                        "algorithmFamily": "pgcrypto",
                        "algorithmName": f"pgcrypto {func_name}()",
                        "primitive": "encryption",
                        "risk": 0 if is_vulnerable else 2,
                        "nistQuantumSecurityLevel": 0 if is_vulnerable else 1,
                        "classicalSecurityLevel": 112 if is_vulnerable else 256,
                        "securityProperties": ["quantum-vulnerable"] if is_vulnerable else ["quantum-safe"],
                    },
                    "replacement": "Migrate to ML-KEM for key wrapping" if is_vulnerable else "None needed",
                    "priority": "P0-Critical" if is_vulnerable else "P4-Safe",
                    "effort": "High" if is_vulnerable else "None",
                    "source": "database",
                })
    except Exception:
        pass

    return findings


def _check_ssl_config(cur) -> List[Dict]:
    """Check SSL/TLS configuration."""
    findings = []

    ssl_settings = [
        ("ssl", "SSL Enabled", "certificate"),
        ("ssl_min_protocol_version", "SSL Min Protocol", "certificate"),
        ("ssl_ciphers", "SSL Ciphers", "encryption"),
        ("ssl_cert_file", "SSL Certificate", "certificate"),
        ("ssl_key_file", "SSL Key", "certificate"),
        ("ssl_ca_file", "SSL CA", "certificate"),
    ]

    for setting, name, primitive in ssl_settings:
        try:
            cur.execute(f"SHOW {setting}")
            value = cur.fetchone()[0]

            is_vulnerable = False
            if setting == "ssl" and value == "off":
                is_vulnerable = True
            elif setting == "ssl_min_protocol_version" and "1.2" in value:
                is_vulnerable = True
            elif setting == "ssl_ciphers" and any(c in value.upper() for c in ["RC4", "DES", "3DES", "MD5"]):
                is_vulnerable = True

            findings.append({
                "rule_id": f"db_ssl_{setting}",
                "rule_name": f"Database: {name}",
                "category": "ssl_config",
                "file": "database",
                "line_number": 0,
                "content": f"{setting} = {value}",
                "language": "config",
                "algorithm": {
                    "algorithmFamily": "TLS",
                    "algorithmName": name,
                    "primitive": primitive,
                    "risk": 0 if is_vulnerable else 2,
                    "nistQuantumSecurityLevel": 0 if is_vulnerable else 1,
                    "classicalSecurityLevel": 112 if is_vulnerable else 256,
                    "securityProperties": ["quantum-vulnerable"] if is_vulnerable else ["quantum-safe"],
                },
                "replacement": "Enable SSL and use TLS 1.3" if is_vulnerable else "None needed",
                "priority": "P0-Critical" if is_vulnerable else "P4-Safe",
                "effort": "Medium" if is_vulnerable else "None",
                "source": "database",
            })
        except Exception:
            pass

    return findings


def _check_auth_methods(cur) -> List[Dict]:
    """Check authentication methods in pg_hba.conf."""
    findings = []

    try:
        cur.execute("SELECT type, database, user_name, address, auth_method FROM pg_hba_file_rules")
        for row in cur.fetchall():
            hba_type, db, user_name, address, auth_method = row

            is_vulnerable = auth_method in ("password", "md5", "trust")
            is_safe = auth_method in ("scram-sha-256", "cert", "peer")

            findings.append({
                "rule_id": f"db_hba_{auth_method}",
                "rule_name": f"Auth Method: {auth_method}",
                "category": "pg_hba",
                "file": "pg_hba.conf",
                "line_number": 0,
                "content": f"{hba_type} {db} {user_name} {address} {auth_method}",
                "language": "config",
                "algorithm": {
                    "algorithmFamily": "Authentication",
                    "algorithmName": f"pg_hba: {auth_method}",
                    "primitive": "authentication",
                    "risk": 0 if is_vulnerable else (2 if is_safe else 1),
                    "nistQuantumSecurityLevel": 0 if is_vulnerable else 1,
                    "classicalSecurityLevel": 0 if is_vulnerable else 256,
                    "securityProperties": ["quantum-vulnerable"] if is_vulnerable else ["quantum-safe"],
                },
                "replacement": "Use scram-sha-256 or cert auth" if is_vulnerable else "None needed",
                "priority": "P0-Critical" if is_vulnerable else "P4-Safe",
                "effort": "Low" if is_vulnerable else "None",
                "source": "database",
            })
    except Exception:
        pass

    return findings


def _check_stored_procedures(cur) -> List[Dict]:
    """Check stored procedures for crypto function calls."""
    findings = []

    try:
        cur.execute("""
            SELECT routine_name, routine_definition
            FROM information_schema.routines
            WHERE routine_schema = 'public'
            AND routine_definition IS NOT NULL
        """)
        for row in cur.fetchall():
            func_name, definition = row
            if not definition:
                continue

            crypto_patterns = [
                ("pgp_pub_encrypt", "RSA", True),
                ("pgp_pub_decrypt", "RSA", True),
                ("pgp_sym_encrypt", "AES", False),
                ("pgp_sym_decrypt", "AES", False),
                ("digest", "SHA", False),
                ("hmac", "HMAC", False),
            ]

            for pattern, algo, is_vulnerable in crypto_patterns:
                if pattern in definition.lower():
                    findings.append({
                        "rule_id": f"db_proc_{func_name}_{pattern}",
                        "rule_name": f"Procedure {func_name} uses {pattern}",
                        "category": "stored_procedure",
                        "file": "database",
                        "line_number": 0,
                        "content": f"Function {func_name}() calls {pattern}()",
                        "language": "sql",
                        "algorithm": {
                            "algorithmFamily": algo,
                            "algorithmName": f"{pattern} in {func_name}",
                            "primitive": "encryption",
                            "risk": 0 if is_vulnerable else 2,
                            "nistQuantumSecurityLevel": 0 if is_vulnerable else 1,
                            "classicalSecurityLevel": 112 if is_vulnerable else 256,
                            "securityProperties": ["quantum-vulnerable"] if is_vulnerable else ["quantum-safe"],
                        },
                        "replacement": "Migrate to ML-KEM" if is_vulnerable else "None needed",
                        "priority": "P0-Critical" if is_vulnerable else "P4-Safe",
                        "effort": "High" if is_vulnerable else "None",
                        "source": "database",
                    })
    except Exception:
        pass

    return findings


def _check_password_encryption(cur) -> List[Dict]:
    """Check password encryption setting."""
    findings = []

    try:
        cur.execute("SHOW password_encryption")
        value = cur.fetchone()[0]

        is_vulnerable = value == "md5"

        findings.append({
            "rule_id": "db_password_encryption",
            "rule_name": f"Password Encryption: {value}",
            "category": "password",
            "file": "database",
            "line_number": 0,
            "content": f"password_encryption = {value}",
            "language": "config",
            "algorithm": {
                "algorithmFamily": "Password",
                "algorithmName": f"password_encryption: {value}",
                "primitive": "kdf",
                "risk": 0 if is_vulnerable else 2,
                "nistQuantumSecurityLevel": 0 if is_vulnerable else 1,
                "classicalSecurityLevel": 0 if is_vulnerable else 256,
                "securityProperties": ["quantum-vulnerable"] if is_vulnerable else ["quantum-safe"],
            },
            "replacement": "Set password_encryption = 'scram-sha-256'" if is_vulnerable else "None needed",
            "priority": "P0-Critical" if is_vulnerable else "P4-Safe",
            "effort": "Low" if is_vulnerable else "None",
            "source": "database",
        })
    except Exception:
        pass

    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Database Introspection Scanner - Detect crypto usage without source code",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--host", default="localhost", help="PostgreSQL host")
    parser.add_argument("--port", type=int, default=5432, help="PostgreSQL port")
    parser.add_argument("--user", default="postgres", help="PostgreSQL user")
    parser.add_argument("--password", default=None, help="PostgreSQL password")
    parser.add_argument("--database", default="postgres", help="PostgreSQL database")
    parser.add_argument("--output", "-o", help="Output path for the scan report JSON")
    parser.add_argument("--verbose", "-v", action="store_true", help="Print detailed terminal report")

    args = parser.parse_args()

    print(f"Connecting to PostgreSQL at {args.host}:{args.port}...")
    findings = scan_postgresql_connection(
        host=args.host,
        port=args.port,
        user=args.user,
        password=args.password,
        database=args.database,
    )

    if not findings:
        print("No cryptographic usage detected in database.")
        return

    score_data = compute_readiness_score(findings)
    compliance = check_nist_compliance(findings)

    report = generate_score_report(
        score_data=score_data,
        compliance=compliance,
        findings=findings,
        project_name=f"Database:{args.host}:{args.port}",
        scan_mode="database",
    )

    print(f"\nDatabase Introspection Complete")
    print(f"  PQC Readiness Score: {report['score']}/100 (Grade: {report['grade']})")
    print(f"  Total Findings: {report['total_assets']}")
    print(f"  Vulnerable: {report['vulnerable_assets']}")
    print(f"  Safe: {report['safe_assets']}")

    if args.verbose:
        print_terminal_report(report, f"{args.host}:{args.port}")

    if args.output:
        save_score_report(report, args.output)
        print(f"\n  Report saved to: {args.output}")


if __name__ == "__main__":
    main()
