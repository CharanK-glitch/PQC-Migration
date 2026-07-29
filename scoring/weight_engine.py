"""PQC Readiness Score calculator with weighted scoring formula."""

from collections import defaultdict
from typing import List, Dict

RISK_CRITICAL = 0
RISK_HIGH = 1
RISK_SAFE = 2

# Context weights: how critical is the crypto primitive
CTX_WEIGHT = {
    "key-exchange": 1.0,
    "digital-signature": 1.0,
    "key-encapsulation": 1.0,
    "encryption": 0.7,
    "hash": 0.4,
    "mac": 0.5,
    "kdf": 0.5,
    "random": 0.3,
    "certificate": 0.9,
}


def compute_readiness_score(findings: List[Dict]) -> Dict:
    """Compute weighted PQC Readiness Score from findings.

    Formula:
        Final Score = Base + PQC Bonus - Critical Penalty - Diversity Penalty - PG Penalty

    Args:
        findings: List of scan findings with algorithm info

    Returns:
        Dictionary with score, grade, breakdown, and roadmap
    """
    if not findings:
        return _empty_score()

    # Aggregate by unique algorithm
    algo_map = _aggregate_algorithms(findings)

    total_weight = 0
    safe_weight = 0
    vulnerable_count = 0
    safe_count = 0
    critical_count = 0
    high_count = 0
    pqc_count = 0
    total_occurrences = 0

    primitive_breakdown = defaultdict(lambda: {
        "total": 0, "vulnerable": 0, "safe": 0, "weight": 0, "safe_weight": 0
    })
    family_breakdown = defaultdict(lambda: {"total": 0, "vulnerable": 0, "safe": 0})
    risk_distribution = {"critical": 0, "high": 0, "safe": 0}
    language_breakdown = defaultdict(lambda: {"total": 0, "vulnerable": 0, "safe": 0})
    source_breakdown = {"generic": {"total": 0, "vulnerable": 0, "safe": 0},
                        "postgresql": {"total": 0, "vulnerable": 0, "safe": 0}}

    for algo_name, algo_info in algo_map.items():
        alg = algo_info["algorithm"]
        risk = alg.get("risk", RISK_CRITICAL)
        primitive = alg.get("primitive", "unknown")
        family = alg.get("algorithmFamily", "unknown")
        occ_count = algo_info["count"]
        source = algo_info.get("source", "generic")

        ctx_w = CTX_WEIGHT.get(primitive, 0.5)
        asset_weight = ctx_w * occ_count

        total_weight += asset_weight
        total_occurrences += occ_count

        is_pq = "quantum-resistant" in alg.get("securityProperties", []) or \
                "nist-standardized" in alg.get("securityProperties", [])
        is_vulnerable = alg.get("nistQuantumSecurityLevel", 0) == 0

        if is_pq:
            pqc_count += 1

        if risk == RISK_CRITICAL:
            critical_count += 1
            risk_distribution["critical"] += occ_count
        elif risk == RISK_HIGH:
            high_count += 1
            risk_distribution["high"] += occ_count
        else:
            safe_count += 1
            risk_distribution["safe"] += occ_count
            safe_weight += asset_weight

        if is_vulnerable:
            vulnerable_count += 1
            primitive_breakdown[primitive]["vulnerable"] += occ_count
            family_breakdown[family]["vulnerable"] += occ_count
        else:
            primitive_breakdown[primitive]["safe"] += occ_count
            family_breakdown[family]["safe"] += occ_count

        primitive_breakdown[primitive]["total"] += occ_count
        primitive_breakdown[primitive]["weight"] += asset_weight
        if not is_vulnerable:
            primitive_breakdown[primitive]["safe_weight"] += asset_weight

        source_breakdown[source]["total"] += occ_count
        if is_vulnerable:
            source_breakdown[source]["vulnerable"] += occ_count
        else:
            source_breakdown[source]["safe"] += occ_count

    # Base score
    base_score = (safe_weight / total_weight * 100) if total_weight > 0 else 100

    # PQC adoption bonus: up to +5 points
    pqc_bonus = min(5, (pqc_count / max(len(algo_map), 1)) * 10)

    # Critical vulnerability penalty: up to -15 points
    critical_penalty = min(15, (critical_count / max(len(algo_map), 1)) * 20)

    # Diversity penalty: crypto in many languages increases migration complexity
    lang_count = len([l for l, v in language_breakdown.items() if v["total"] > 0])
    diversity_penalty = min(5, max(0, (lang_count - 2) * 1.5))

    # PostgreSQL-specific penalty
    pg_penalty = _compute_pg_penalty(findings)

    raw_score = base_score + pqc_bonus - critical_penalty - diversity_penalty - pg_penalty
    final_score = max(0, min(100, round(raw_score)))

    grade, label = _get_grade(final_score)

    # Build migration roadmap
    roadmap = _build_roadmap(algo_map)

    # Timeline estimation
    timeline = _estimate_timeline(roadmap)

    return {
        "score": final_score,
        "grade": grade,
        "label": label,
        "total_assets": len(algo_map),
        "total_occurrences": total_occurrences,
        "vulnerable_assets": vulnerable_count,
        "safe_assets": safe_count,
        "critical_assets": critical_count,
        "high_risk_assets": high_count,
        "pqc_assets": pqc_count,
        "risk_distribution": risk_distribution,
        "primitive_breakdown": dict(primitive_breakdown),
        "family_breakdown": dict(family_breakdown),
        "language_breakdown": dict(language_breakdown),
        "source_breakdown": source_breakdown,
        "timeline": timeline,
        "migration_roadmap": roadmap,
        "scoring_details": {
            "base_score": round(base_score, 1),
            "pqc_bonus": round(pqc_bonus, 1),
            "critical_penalty": round(critical_penalty, 1),
            "diversity_penalty": round(diversity_penalty, 1),
            "pg_penalty": round(pg_penalty, 1),
            "total_weight": round(total_weight, 1),
            "safe_weight": round(safe_weight, 1),
        },
    }


def _aggregate_algorithms(findings: List[Dict]) -> Dict:
    """Aggregate findings by unique algorithm."""
    algo_map = {}

    for f in findings:
        algo_name = f.get("algorithm", {}).get("algorithmName", "Unknown")
        key = algo_name

        if key not in algo_map:
            algo_map[key] = {
                "algorithm": f["algorithm"],
                "count": 0,
                "files": set(),
                "source": f.get("source", "generic"),
                "priority": f.get("priority", "P4-Safe"),
                "replacement": f.get("replacement", "See NIST SP 800-208"),
                "category": f.get("category", "unknown"),
            }

        algo_map[key]["count"] += 1
        algo_map[key]["files"].add(f["file"])

    return algo_map


def _get_grade(score: int) -> tuple:
    """Get letter grade and label from score."""
    if score >= 95:
        return "A+", "PQC Ready"
    elif score >= 85:
        return "A", "Nearly PQC Ready"
    elif score >= 70:
        return "B", "Partial PQC Coverage"
    elif score >= 50:
        return "C", "Significant PQC Gaps"
    elif score >= 30:
        return "D", "Major PQC Deficiencies"
    else:
        return "F", "PQC Non-Compliant"


def _compute_pg_penalty(findings: List[Dict]) -> float:
    """Compute PostgreSQL-specific penalties."""
    penalty = 0

    for f in findings:
        rule_id = f.get("rule_id", "")

        # pgp_pub_encrypt uses RSA - highest risk
        if rule_id == "pgp_pub_encrypt":
            penalty += 5

        # password_encryption = md5
        elif rule_id == "pg_password_encryption" and "md5" in f.get("content", "").lower():
            penalty += 3

        # ssl_min_protocol_version < 1.3
        elif rule_id == "pg_ssl_min_protocol":
            content = f.get("content", "").lower()
            if "1.2" in content or "1.1" in content or "1.0" in content:
                penalty += 2

        # No pgcrypto extension
        # (handled elsewhere)

    return min(10, penalty)


def _build_roadmap(algo_map: Dict) -> List[Dict]:
    """Build prioritized migration roadmap."""
    roadmap = []

    priority_order = {
        "P0-Critical": 0,
        "P1-High": 1,
        "P2-Medium": 2,
        "P3-Low": 3,
        "P4-Safe": 4,
    }

    effort_weeks = {"None": 0, "Low": 1, "Medium": 3, "High": 8}

    for algo_name, info in algo_map.items():
        if info["priority"] == "P4-Safe":
            continue

        alg = info["algorithm"]
        roadmap.append({
            "algorithm": algo_name,
            "current": algo_name,
            "replacement": info["replacement"],
            "priority": info["priority"],
            "priority_order": priority_order.get(info["priority"], 5),
            "effort": _get_effort_for_replacement(info["replacement"]),
            "effort_weeks": effort_weeks.get(_get_effort_for_replacement(info["replacement"]), 3),
            "occurrences": info["count"],
            "files": list(info["files"]),
            "primitive": alg.get("primitive", "unknown"),
            "risk": alg.get("risk", 0),
            "file_count": len(info["files"]),
        })

    # Sort by priority, then by occurrence count
    roadmap.sort(key=lambda x: (x["priority_order"], -x["occurrences"]))

    return roadmap


def _get_effort_for_replacement(replacement: str) -> str:
    """Estimate migration effort based on replacement type."""
    if "None needed" in replacement or "already PQC" in replacement:
        return "None"
    elif "SHA-256" in replacement or "SHA-3" in replacement:
        return "Low"
    elif "AES-256" in replacement:
        return "Low"
    elif "ML-KEM" in replacement or "ML-DSA" in replacement:
        return "High"
    elif "TLS 1.3" in replacement:
        return "Medium"
    else:
        return "Medium"


def _estimate_timeline(roadmap: List[Dict]) -> Dict:
    """Estimate total migration timeline."""
    total_weeks = sum(r.get("effort_weeks", 0) for r in roadmap)

    if total_weeks <= 2:
        label = "Quick Fix"
        desc = "1-2 weeks of work"
    elif total_weeks <= 8:
        label = "Short-term"
        desc = "1-2 months of work"
    elif total_weeks <= 24:
        label = "Medium-term"
        desc = "3-6 months of work"
    else:
        label = "Long-term"
        desc = "6+ month transformation initiative"

    return {
        "weeks": total_weeks,
        "label": label,
        "description": desc,
    }


def _empty_score() -> Dict:
    """Return empty score when no findings."""
    return {
        "score": 100,
        "grade": "A+",
        "label": "No Crypto Detected",
        "total_assets": 0,
        "total_occurrences": 0,
        "vulnerable_assets": 0,
        "safe_assets": 0,
        "critical_assets": 0,
        "high_risk_assets": 0,
        "pqc_assets": 0,
        "risk_distribution": {"critical": 0, "high": 0, "safe": 0},
        "primitive_breakdown": {},
        "family_breakdown": {},
        "language_breakdown": {},
        "source_breakdown": {},
        "timeline": {"weeks": 0, "label": "None", "description": "No migration needed"},
        "migration_roadmap": [],
        "scoring_details": {
            "base_score": 100, "pqc_bonus": 0, "critical_penalty": 0,
            "diversity_penalty": 0, "pg_penalty": 0, "total_weight": 0, "safe_weight": 0,
        },
    }
