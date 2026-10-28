#!/usr/bin/env python3
"""
Dependency Manifest Scanner

Scans package dependency files (package.json, requirements.txt, Gemfile, go.mod)
for known cryptographic libraries and flags versions using deprecated algorithms.
"""

import json
import re
import argparse
from pathlib import Path
from typing import List, Dict, Optional
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scoring.weight_engine import compute_readiness_score
from scoring.nist_compliance import check_nist_compliance
from output.score_reporter import generate_score_report, save_score_report, print_terminal_report


CRYPTO_LIBRARIES = {
    "openssl": {
        "name": "OpenSSL",
        "vulnerable_versions": ["1.0.2", "1.1.0", "1.1.1"],
        "safe_versions": ["3.0", "3.1", "3.2"],
        "algorithms": ["RSA", "ECDSA", "AES", "SHA-256"],
        "risk": 1,
    },
    "boringssl": {
        "name": "BoringSSL",
        "vulnerable_versions": [],
        "safe_versions": ["all"],
        "algorithms": ["RSA", "ECDSA", "AES", "SHA-256"],
        "risk": 2,
    },
    "libressl": {
        "name": "LibreSSL",
        "vulnerable_versions": ["2.0", "2.1", "2.2"],
        "safe_versions": ["3.0", "3.1", "3.2", "3.3", "3.4", "3.5"],
        "algorithms": ["RSA", "ECDSA", "AES", "SHA-256"],
        "risk": 1,
    },
    "pycryptodome": {
        "name": "PyCryptodome",
        "vulnerable_versions": [],
        "safe_versions": ["all"],
        "algorithms": ["AES", "DES", "3DES", "RC4", "RSA", "ECDSA"],
        "risk": 2,
    },
    "cryptography": {
        "name": "cryptography (Python)",
        "vulnerable_versions": ["2.0", "2.1", "2.2", "2.3", "2.4", "2.5", "2.6", "2.7", "2.8", "2.9", "3.0", "3.1", "3.2", "3.3"],
        "safe_versions": ["3.4", "35.0", "36.0", "37.0", "38.0", "39.0", "40.0", "41.0", "42.0", "43.0"],
        "algorithms": ["RSA", "ECDSA", "AES", "SHA-256", "SHA-384", "SHA-512"],
        "risk": 2,
    },
    "bouncycastle": {
        "name": "BouncyCastle",
        "vulnerable_versions": [],
        "safe_versions": ["all"],
        "algorithms": ["RSA", "ECDSA", "AES", "SHA-256"],
        "risk": 2,
    },
    "libsodium": {
        "name": "libsodium",
        "vulnerable_versions": [],
        "safe_versions": ["all"],
        "algorithms": ["ChaCha20", "Poly1305", "Curve25519", "Ed25519"],
        "risk": 2,
    },
    "node-forge": {
        "name": "node-forge",
        "vulnerable_versions": [],
        "safe_versions": ["all"],
        "algorithms": ["RSA", "ECDSA", "AES", "SHA-256"],
        "risk": 2,
    },
    "crypto-js": {
        "name": "CryptoJS",
        "vulnerable_versions": [],
        "safe_versions": ["all"],
        "algorithms": ["AES", "DES", "3DES", "RC4", "MD5", "SHA-1", "SHA-256"],
        "risk": 2,
    },
}


def scan_package_json(filepath: str) -> List[Dict]:
    """Scan package.json for crypto libraries."""
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, IOError):
        return findings

    deps = {}
    deps.update(data.get("dependencies", {}))
    deps.update(data.get("devDependencies", {}))

    for dep_name, version_spec in deps.items():
        dep_lower = dep_name.lower()
        for lib_key, lib_info in CRYPTO_LIBRARIES.items():
            if lib_key in dep_lower or dep_lower in lib_key:
                version = _extract_version(version_spec)
                is_vulnerable = _is_vulnerable_version(version, lib_info)

                findings.append({
                    "rule_id": f"dep_{lib_key}",
                    "rule_name": f"{lib_info['name']} ({dep_name})",
                    "category": "dependency",
                    "file": filepath,
                    "line_number": 0,
                    "content": f"{dep_name}@{version_spec}",
                    "language": "json",
                    "algorithm": {
                        "algorithmFamily": lib_info["name"],
                        "algorithmName": lib_info["name"],
                        "primitive": "encryption",
                        "risk": 0 if is_vulnerable else 2,
                        "nistQuantumSecurityLevel": 0 if is_vulnerable else 1,
                        "classicalSecurityLevel": 112 if is_vulnerable else 256,
                        "securityProperties": ["quantum-vulnerable"] if is_vulnerable else ["quantum-resistant"],
                    },
                    "replacement": "Upgrade to latest version" if is_vulnerable else "None needed",
                    "priority": "P0-Critical" if is_vulnerable else "P4-Safe",
                    "effort": "Low" if is_vulnerable else "None",
                    "source": "dependency",
                    "dependency": dep_name,
                    "version": version,
                })

    return findings


def scan_requirements_txt(filepath: str) -> List[Dict]:
    """Scan requirements.txt for crypto libraries."""
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except IOError:
        return findings

    for idx, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        match = re.match(r'^([a-zA-Z0-9_-]+)\s*([<>=!~]+)?\s*([0-9.]+)?', line)
        if not match:
            continue

        dep_name = match.group(1)
        version = match.group(3) or "unknown"

        for lib_key, lib_info in CRYPTO_LIBRARIES.items():
            if lib_key in dep_name.lower() or dep_name.lower() in lib_key:
                is_vulnerable = _is_vulnerable_version(version, lib_info)

                findings.append({
                    "rule_id": f"dep_{lib_key}",
                    "rule_name": f"{lib_info['name']} ({dep_name})",
                    "category": "dependency",
                    "file": filepath,
                    "line_number": idx,
                    "content": line,
                    "language": "python",
                    "algorithm": {
                        "algorithmFamily": lib_info["name"],
                        "algorithmName": lib_info["name"],
                        "primitive": "encryption",
                        "risk": 0 if is_vulnerable else 2,
                        "nistQuantumSecurityLevel": 0 if is_vulnerable else 1,
                        "classicalSecurityLevel": 112 if is_vulnerable else 256,
                        "securityProperties": ["quantum-vulnerable"] if is_vulnerable else ["quantum-resistant"],
                    },
                    "replacement": "Upgrade to latest version" if is_vulnerable else "None needed",
                    "priority": "P0-Critical" if is_vulnerable else "P4-Safe",
                    "effort": "Low" if is_vulnerable else "None",
                    "source": "dependency",
                    "dependency": dep_name,
                    "version": version,
                })

    return findings


def scan_gemfile(filepath: str) -> List[Dict]:
    """Scan Gemfile for crypto libraries."""
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except IOError:
        return findings

    for idx, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        match = re.match(r"gem\s+['\"]([^'\"]+)['\"](?:,\s*['\"]([^'\"]+)['\"])?", line)
        if not match:
            continue

        dep_name = match.group(1)
        version = match.group(2) or "unknown"

        for lib_key, lib_info in CRYPTO_LIBRARIES.items():
            if lib_key in dep_name.lower() or dep_name.lower() in lib_key:
                is_vulnerable = _is_vulnerable_version(version, lib_info)

                findings.append({
                    "rule_id": f"dep_{lib_key}",
                    "rule_name": f"{lib_info['name']} ({dep_name})",
                    "category": "dependency",
                    "file": filepath,
                    "line_number": idx,
                    "content": line,
                    "language": "ruby",
                    "algorithm": {
                        "algorithmFamily": lib_info["name"],
                        "algorithmName": lib_info["name"],
                        "primitive": "encryption",
                        "risk": 0 if is_vulnerable else 2,
                        "nistQuantumSecurityLevel": 0 if is_vulnerable else 1,
                        "classicalSecurityLevel": 112 if is_vulnerable else 256,
                        "securityProperties": ["quantum-vulnerable"] if is_vulnerable else ["quantum-resistant"],
                    },
                    "replacement": "Upgrade to latest version" if is_vulnerable else "None needed",
                    "priority": "P0-Critical" if is_vulnerable else "P4-Safe",
                    "effort": "Low" if is_vulnerable else "None",
                    "source": "dependency",
                    "dependency": dep_name,
                    "version": version,
                })

    return findings


def scan_go_mod(filepath: str) -> List[Dict]:
    """Scan go.mod for crypto libraries."""
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except IOError:
        return findings

    for idx, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("//"):
            continue

        match = re.match(r'require\s+(\S+)\s+(v\S+)', line)
        if not match:
            continue

        dep_name = match.group(1)
        version = match.group(2)

        for lib_key, lib_info in CRYPTO_LIBRARIES.items():
            if lib_key in dep_name.lower() or dep_name.lower() in lib_key:
                is_vulnerable = _is_vulnerable_version(version, lib_info)

                findings.append({
                    "rule_id": f"dep_{lib_key}",
                    "rule_name": f"{lib_info['name']} ({dep_name})",
                    "category": "dependency",
                    "file": filepath,
                    "line_number": idx,
                    "content": line,
                    "language": "go",
                    "algorithm": {
                        "algorithmFamily": lib_info["name"],
                        "algorithmName": lib_info["name"],
                        "primitive": "encryption",
                        "risk": 0 if is_vulnerable else 2,
                        "nistQuantumSecurityLevel": 0 if is_vulnerable else 1,
                        "classicalSecurityLevel": 112 if is_vulnerable else 256,
                        "securityProperties": ["quantum-vulnerable"] if is_vulnerable else ["quantum-resistant"],
                    },
                    "replacement": "Upgrade to latest version" if is_vulnerable else "None needed",
                    "priority": "P0-Critical" if is_vulnerable else "P4-Safe",
                    "effort": "Low" if is_vulnerable else "None",
                    "source": "dependency",
                    "dependency": dep_name,
                    "version": version,
                })

    return findings


def _extract_version(version_spec: str) -> str:
    """Extract version number from version specifier."""
    match = re.search(r'(\d+\.\d+(?:\.\d+)?)', version_spec)
    return match.group(1) if match else "unknown"


def _is_vulnerable_version(version: str, lib_info: Dict) -> bool:
    """Check if a version is in the vulnerable list."""
    if version == "unknown":
        return False
    for vuln_ver in lib_info.get("vulnerable_versions", []):
        if version.startswith(vuln_ver):
            return True
    return False


def scan_directory(directory: str) -> List[Dict]:
    """Scan a directory for dependency manifest files."""
    all_findings = []
    dir_path = Path(directory)

    manifest_files = {
        "package.json": scan_package_json,
        "requirements.txt": scan_requirements_txt,
        "Gemfile": scan_gemfile,
        "go.mod": scan_go_mod,
    }

    for manifest_name, scanner_func in manifest_files.items():
        manifest_path = dir_path / manifest_name
        if manifest_path.exists():
            findings = scanner_func(str(manifest_path))
            all_findings.extend(findings)

    return all_findings


def main():
    parser = argparse.ArgumentParser(
        description="Dependency Manifest Scanner - Scan package files for crypto libraries",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "path",
        help="Path to directory containing dependency manifests, or path to a specific manifest file"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output path for the scan report JSON"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print detailed terminal report"
    )

    args = parser.parse_args()

    path = Path(args.path)
    if path.is_file():
        findings = []
        if path.name == "package.json":
            findings = scan_package_json(str(path))
        elif path.name == "requirements.txt":
            findings = scan_requirements_txt(str(path))
        elif path.name == "Gemfile":
            findings = scan_gemfile(str(path))
        elif path.name == "go.mod":
            findings = scan_go_mod(str(path))
    else:
        findings = scan_directory(str(path))

    if not findings:
        print("No crypto libraries found in dependency manifests.")
        return

    score_data = compute_readiness_score(findings)
    compliance = check_nist_compliance(findings)

    report = generate_score_report(
        score_data=score_data,
        compliance=compliance,
        findings=findings,
        project_name=path.name if path.is_file() else path.name,
        scan_mode="dependency",
    )

    print(f"\nDependency Scan Complete")
    print(f"  PQC Readiness Score: {report['score']}/100 (Grade: {report['grade']})")
    print(f"  Total Libraries: {report['total_assets']}")
    print(f"  Vulnerable: {report['vulnerable_assets']}")
    print(f"  Safe: {report['safe_assets']}")

    if args.verbose:
        print_terminal_report(report, str(path))

    if args.output:
        save_score_report(report, args.output)
        print(f"\n  Report saved to: {args.output}")


if __name__ == "__main__":
    main()
