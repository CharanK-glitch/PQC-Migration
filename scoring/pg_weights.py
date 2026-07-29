"""PostgreSQL-specific scoring weights and adjustments."""

from typing import List, Dict


# PostgreSQL-specific risk weights
PG_RISK_WEIGHTS = {
    # Highest risk - asymmetric crypto in pgcrypto
    "pgp_pub_encrypt": 1.2,
    "pgp_pub_decrypt": 1.2,

    # High risk - weak auth methods
    "pg_hba_md5": 1.0,
    "pg_hba_password": 1.0,
    "pg_hba_ident": 1.0,

    # Medium risk - connection security
    "conn_sslmode_disable": 1.0,
    "conn_sslmode_allow": 0.8,
    "conn_sslmode_prefer": 0.6,
    "conn_sslmode_require": 0.4,

    # Low risk - config improvements
    "pg_ssl_min_protocol": 0.6,
    "pg_ssl_ecdh_curve": 0.6,
    "pg_ssl_dh_params": 0.6,
    "pg_password_encryption": 0.8,

    # Safe - good practices
    "pg_hba_scram_sha256": 0.0,
    "conn_sslmode_verify_full": 0.0,
    "pgp_sym_encrypt": 0.0,
    "digest_sha256": 0.0,
    "hmac_sha256": 0.0,
    "gen_salt_xsha256": 0.0,
}

# PostgreSQL category weights
PG_CATEGORY_WEIGHTS = {
    "pg_ssl": 0.9,        # SSL/TLS is critical for transport security
    "pg_auth": 1.0,       # Authentication is highest priority
    "pgcrypto": 1.1,      # pgcrypto directly handles data encryption
    "pg_conn": 0.8,       # Connection strings affect all clients
    "pg_c_ext": 0.9,      # C extensions are high-impact
    "pg_wal": 0.7,        # WAL/backup encryption is important
    "pg_cert": 0.8,       # Certificate management
}


def get_pg_risk_weight(rule_id: str) -> float:
    """Get PostgreSQL-specific risk weight for a rule.

    Args:
        rule_id: Rule identifier

    Returns:
        Risk weight multiplier (higher = more risk)
    """
    return PG_RISK_WEIGHTS.get(rule_id, 0.5)


def get_pg_category_weight(category: str) -> float:
    """Get PostgreSQL category weight.

    Args:
        category: Category name

    Returns:
        Category weight multiplier
    """
    return PG_CATEGORY_WEIGHTS.get(category, 0.5)


def compute_pg_adjustment(findings: List[Dict]) -> Dict:
    """Compute PostgreSQL-specific scoring adjustments.

    Args:
        findings: List of PostgreSQL findings

    Returns:
        Dictionary with adjustment details
    """
    adjustments = {
        "ssl_downgrade_penalty": 0,
        "auth_weak_penalty": 0,
        "pgcrypto_asymmetric_penalty": 0,
        "conn_string_penalty": 0,
        "cert_exposure_penalty": 0,
    }

    for f in findings:
        rule_id = f.get("rule_id", "")
        source = f.get("source", "")

        if source != "postgresql":
            continue

        # SSL downgrade
        if rule_id == "pg_ssl_min_protocol":
            content = f.get("content", "").lower()
            if "1.2" in content:
                adjustments["ssl_downgrade_penalty"] += 1
            elif "1.1" in content or "1.0" in content:
                adjustments["ssl_downgrade_penalty"] += 2

        # Weak authentication
        elif rule_id in ("pg_hba_md5", "pg_hba_password", "pg_hba_ident"):
            adjustments["auth_weak_penalty"] += 2

        # pgcrypto asymmetric
        elif rule_id in ("pgp_pub_encrypt", "pgp_pub_decrypt"):
            adjustments["pgcrypto_asymmetric_penalty"] += 3

        # Connection string issues
        elif rule_id.startswith("conn_sslmode_"):
            if rule_id == "conn_sslmode_disable":
                adjustments["conn_string_penalty"] += 2
            elif rule_id == "conn_sslmode_allow":
                adjustments["conn_string_penalty"] += 1

        # Certificate exposure
        elif rule_id in ("pg_server_key", "pg_client_key"):
            adjustments["cert_exposure_penalty"] += 1

    return adjustments


def get_pg_severity(findings: List[Dict]) -> str:
    """Determine overall PostgreSQL-specific severity.

    Args:
        findings: List of PostgreSQL findings

    Returns:
        Severity level: critical, high, medium, low
    """
    adjustments = compute_pg_adjustment(findings)
    total = sum(adjustments.values())

    if total >= 10:
        return "critical"
    elif total >= 6:
        return "high"
    elif total >= 3:
        return "medium"
    else:
        return "low"
