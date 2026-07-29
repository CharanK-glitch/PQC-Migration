"""Merge and deduplicate findings from generic and PostgreSQL scanners."""

from typing import List, Dict


def merge_findings(generic: List[Dict], postgres: List[Dict]) -> List[Dict]:
    """Merge and deduplicate findings from both scan layers.

    PostgreSQL-specific findings take priority over generic findings.
    Deduplication is based on (algorithm, file, line_number).

    Args:
        generic: Findings from generic crypto scanner
        postgres: Findings from PostgreSQL-specific scanner

    Returns:
        Merged and deduplicated list of findings
    """
    merged = []
    seen = set()

    # PostgreSQL findings take priority
    for f in postgres:
        key = (f.get("algorithm", {}).get("algorithmName", ""), f["file"], f["line_number"])
        if key not in seen:
            f["source"] = "postgresql"
            merged.append(f)
            seen.add(key)

    # Add generic findings (skip duplicates)
    for f in generic:
        key = (f.get("algorithm", {}).get("algorithmName", ""), f["file"], f["line_number"])
        if key not in seen:
            f["source"] = "generic"
            merged.append(f)
            seen.add(key)

    return merged


def deduplicate_by_algorithm(findings: List[Dict]) -> List[Dict]:
    """Deduplicate findings by algorithm, keeping all occurrences.

    Args:
        findings: List of findings

    Returns:
        Deduplicated list with occurrences aggregated
    """
    algo_map = {}

    for f in findings:
        algo_name = f.get("algorithm", {}).get("algorithmName", "Unknown")
        key = (algo_name, f.get("category", ""))

        if key not in algo_map:
            algo_map[key] = {
                "rule_id": f["rule_id"],
                "rule_name": f["rule_name"],
                "category": f["category"],
                "algorithm": f["algorithm"],
                "replacement": f["replacement"],
                "priority": f["priority"],
                "effort": f["effort"],
                "source": f["source"],
                "occurrences": [],
            }

        algo_map[key]["occurrences"].append({
            "file": f["file"],
            "line": f["line_number"],
            "snippet": f["content"],
            "language": f.get("language", "unknown"),
        })

    return list(algo_map.values())


def categorize_findings(findings: List[Dict]) -> Dict[str, List[Dict]]:
    """Categorize findings by category.

    Args:
        findings: List of findings

    Returns:
        Dictionary of category -> findings
    """
    categories = {}

    for f in findings:
        cat = f.get("category", "unknown")
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(f)

    return categories


def filter_by_risk(findings: List[Dict], min_risk: int = 0, max_risk: int = 2) -> List[Dict]:
    """Filter findings by risk level.

    Args:
        findings: List of findings
        min_risk: Minimum risk level (inclusive)
        max_risk: Maximum risk level (inclusive)

    Returns:
        Filtered list of findings
    """
    filtered = []
    for f in findings:
        risk = f.get("algorithm", {}).get("risk", 0)
        if min_risk <= risk <= max_risk:
            filtered.append(f)
    return filtered


def filter_by_source(findings: List[Dict], source: str) -> List[Dict]:
    """Filter findings by source (generic or postgresql).

    Args:
        findings: List of findings
        source: Source to filter by

    Returns:
        Filtered list of findings
    """
    return [f for f in findings if f.get("source") == source]


def sort_by_priority(findings: List[Dict]) -> List[Dict]:
    """Sort findings by priority (P0 first, P4 last).

    Args:
        findings: List of findings

    Returns:
        Sorted list of findings
    """
    priority_order = {
        "P0-Critical": 0,
        "P1-High": 1,
        "P2-Medium": 2,
        "P3-Low": 3,
        "P4-Safe": 4,
    }

    return sorted(findings, key=lambda f: priority_order.get(f.get("priority", "P4-Safe"), 5))


def get_unique_algorithms(findings: List[Dict]) -> List[Dict]:
    """Get unique algorithms from findings with occurrence counts.

    Args:
        findings: List of findings

    Returns:
        List of unique algorithms with occurrence info
    """
    algo_counts = {}

    for f in findings:
        algo_name = f.get("algorithm", {}).get("algorithmName", "Unknown")
        if algo_name not in algo_counts:
            algo_counts[algo_name] = {
                "algorithm": f["algorithm"],
                "count": 0,
                "files": set(),
                "source": f["source"],
                "priority": f["priority"],
                "replacement": f["replacement"],
            }
        algo_counts[algo_name]["count"] += 1
        algo_counts[algo_name]["files"].add(f["file"])

    # Convert sets to lists for JSON serialization
    result = []
    for algo_name, info in algo_counts.items():
        info["files"] = list(info["files"])
        info["algorithmName"] = algo_name
        result.append(info)

    return result
