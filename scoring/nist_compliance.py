"""NIST PQC compliance checker for FIPS 203/204/205 standards."""

from typing import List, Dict


# NIST PQC compliance checks
NIST_CHECKS = [
    {
        "id": "fips_203_ml_kem",
        "name": "FIPS 203 ML-KEM",
        "standard": "NIST SP 800-203",
        "description": "Using ML-KEM (Kyber) for key exchange",
        "check_patterns": ["ML-KEM", "Kyber", "ml_kem", "MLKEM"],
        "required": False,
    },
    {
        "id": "fips_204_ml_dsa",
        "name": "FIPS 204 ML-DSA",
        "standard": "NIST SP 800-204",
        "description": "Using ML-DSA (Dilithium) for signatures",
        "check_patterns": ["ML-DSA", "Dilithium", "ml_dsa", "MLDSA"],
        "required": False,
    },
    {
        "id": "fips_205_sphincs",
        "name": "FIPS 205 SLH-DSA",
        "standard": "NIST SP 800-205",
        "description": "Using SPHINCS+ for conservative signatures",
        "check_patterns": ["SPHINCS", "SLH-DSA", "sphincs"],
        "required": False,
    },
    {
        "id": "no_broken_algorithms",
        "name": "No Broken Algorithms",
        "standard": "Best Practice",
        "description": "No MD5, SHA-1, DES, RC4 in codebase",
        "vulnerable_patterns": ["MD5", "SHA-1", "DES", "RC4"],
        "required": True,
    },
    {
        "id": "no_deprecated_algorithms",
        "name": "No Deprecated Algorithms",
        "standard": "NIST SP 800-131A",
        "description": "No algorithms deprecated by NIST",
        "vulnerable_patterns": ["RSA-1024", "DSA", "DH-2048"],
        "required": True,
    },
    {
        "id": "tls_1_3_enabled",
        "name": "TLS 1.3 Enabled",
        "standard": "NIST SP 800-52 Rev 2",
        "description": "Using TLS 1.3 for transport security",
        "check_patterns": ["TLSv1.3", "TLS 1.3", "tls1_3"],
        "required": True,
    },
    {
        "id": "scram_sha_256_used",
        "name": "SCRAM-SHA-256 Authentication",
        "standard": "PostgreSQL Best Practice",
        "description": "Using SCRAM-SHA-256 for password authentication",
        "check_patterns": ["scram-sha-256", "SCRAM-SHA-256"],
        "required": True,
    },
]


def check_nist_compliance(findings: List[Dict], cbom_components: List[Dict] = None) -> Dict:
    """Check NIST PQC compliance based on findings.

    Args:
        findings: List of scan findings
        cbom_components: Optional CBOM components list

    Returns:
        Dictionary with compliance check results
    """
    compliance = {}

    # Build searchable content from findings
    finding_content = " ".join([
        f.get("content", "") + " " + f.get("rule_name", "") + " " + f.get("rule_id", "")
        for f in findings
    ]).lower()

    for check in NIST_CHECKS:
        check_id = check["id"]
        passed = False

        if "check_patterns" in check:
            # Check if any required patterns are present
            for pattern in check["check_patterns"]:
                if pattern.lower() in finding_content:
                    passed = True
                    break

        elif "vulnerable_patterns" in check:
            # Check if NO vulnerable patterns are present
            passed = True
            for pattern in check["vulnerable_patterns"]:
                if pattern.lower() in finding_content:
                    passed = False
                    break

        compliance[check_id] = {
            "name": check["name"],
            "standard": check["standard"],
            "description": check["description"],
            "passed": passed,
            "required": check["required"],
        }

    return compliance


def get_compliance_summary(compliance: Dict) -> Dict:
    """Get compliance summary statistics.

    Args:
        compliance: Compliance check results

    Returns:
        Summary with pass/fail counts
    """
    total = len(compliance)
    passed = sum(1 for c in compliance.values() if c["passed"])
    failed = total - passed
    required_failed = sum(
        1 for c in compliance.values()
        if not c["passed"] and c["required"]
    )

    return {
        "total_checks": total,
        "passed": passed,
        "failed": failed,
        "required_failed": required_failed,
        "compliant": required_failed == 0,
        "compliance_percentage": round((passed / total * 100) if total > 0 else 100, 1),
    }


def get_remediation_steps(compliance: Dict) -> List[Dict]:
    """Get remediation steps for failed checks.

    Args:
        compliance: Compliance check results

    Returns:
        List of remediation steps
    """
    steps = []

    remediation_map = {
        "fips_203_ml_kem": "Integrate ML-KEM (Kyber) library (e.g., liboqs, OQS-OpenSSL) for key exchange",
        "fips_204_ml_dsa": "Integrate ML-DSA (Dilithium) library for digital signatures",
        "fips_205_sphincs": "Consider adding SPHINCS+ for conservative hash-based signatures",
        "no_broken_algorithms": "Remove MD5, SHA-1, DES, RC4 usage and replace with SHA-256+, AES-256-GCM",
        "no_deprecated_algorithms": "Remove RSA-1024, DSA, DH-2048 and replace with ML-KEM/ML-DSA",
        "tls_1_3_enabled": "Configure PostgreSQL and application to use TLS 1.3 minimum",
        "scram_sha_256_used": "Set password_encryption = scram-sha-256 in postgresql.conf and update pg_hba.conf",
    }

    for check_id, info in compliance.items():
        if not info["passed"]:
            steps.append({
                "check": info["name"],
                "standard": info["standard"],
                "severity": "critical" if info["required"] else "recommended",
                "action": remediation_map.get(check_id, "Review and update configuration"),
            })

    return steps
