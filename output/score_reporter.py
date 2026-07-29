"""Score reporter - generates readiness_score.json and terminal output."""

import json
from datetime import datetime, timezone
from typing import List, Dict


def generate_score_report(
    score_data: Dict,
    compliance: Dict,
    findings: List[Dict],
    project_name: str = "Unknown",
    scan_mode: str = "local",
    repo_url: str = None,
    pg_detection: Dict = None,
) -> Dict:
    """Generate comprehensive score report.

    Args:
        score_data: Score computation results
        compliance: NIST compliance check results
        findings: List of scan findings
        project_name: Project name
        scan_mode: Scan mode (local, github, live)
        repo_url: GitHub repository URL (if applicable)
        pg_detection: PostgreSQL detection results (if applicable)

    Returns:
        Complete score report dictionary
    """
    report = {
        "project_name": project_name,
        "scan_mode": scan_mode,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scanner_version": "1.0.0",
    }

    if repo_url:
        report["repo_url"] = repo_url

    if pg_detection:
        report["postgresql_detection"] = {
            "has_pg_config": pg_detection.get("has_pg_config", False),
            "has_pg_hba": pg_detection.get("has_pg_hba", False),
            "has_sql_files": pg_detection.get("has_sql_files", False),
            "has_pgcrypto_usage": pg_detection.get("has_pgcrypto_usage", False),
            "has_conn_strings": pg_detection.get("has_conn_strings", False),
            "sql_files_count": len(pg_detection.get("sql_files", [])),
            "config_files_count": len(pg_detection.get("config_files", [])),
        }

    # Merge score data
    report.update(score_data)

    # Add compliance
    report["compliance"] = compliance

    return report


def save_score_report(report: Dict, output_path: str):
    """Save score report to JSON file.

    Args:
        report: Score report dictionary
        output_path: Path to save the file
    """
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)


def print_terminal_report(report: Dict, scan_target: str):
    """Print formatted terminal report.

    Args:
        report: Score report dictionary
        scan_target: What was scanned (path, URL, etc.)
    """
    score = report.get("score", 0)
    grade = report.get("grade", "F")
    label = report.get("label", "Unknown")

    print()
    print("=" * 64)
    print("  pgcrypto PQC Scanner v1.0")
    print(f"  Project: {report.get('project_name', 'Unknown')}")
    print(f"  Target:  {scan_target}")
    print(f"  Mode:    {report.get('scan_mode', 'local')}")
    print("=" * 64)

    # Score display
    score_color = _get_score_color(score)
    print(f"\n  PQC READINESS SCORE: {score}/100 (Grade: {grade})")
    print(f"  Status: {label}")

    print("\n" + "-" * 64)
    print("  Summary:")
    print(f"    Total Crypto Assets:     {report.get('total_assets', 0)}")
    print(f"    Total Occurrences:       {report.get('total_occurrences', 0)}")
    print(f"    Quantum Vulnerable:      {report.get('vulnerable_assets', 0)} assets")
    print(f"    Quantum Safe:            {report.get('safe_assets', 0)} assets")
    print(f"    Critical Risk:           {report.get('critical_assets', 0)} assets")
    print(f"    PQC Algorithms Found:    {report.get('pqc_assets', 0)} assets")

    # Source breakdown
    source_breakdown = report.get("source_breakdown", {})
    if source_breakdown:
        print("\n  By Source:")
        for source, counts in source_breakdown.items():
            print(f"    {source:15s}: {counts.get('total', 0):4d} total, "
                  f"{counts.get('vulnerable', 0):4d} vulnerable")

    # Timeline
    timeline = report.get("timeline", {})
    if timeline:
        print(f"\n  Migration Timeline:       {timeline.get('label', 'Unknown')} "
              f"({timeline.get('weeks', 0)} weeks)")

    # Scoring details
    details = report.get("scoring_details", {})
    if details:
        print("\n  Scoring Breakdown:")
        print(f"    Base Score:             {details.get('base_score', 0)}")
        print(f"    PQC Bonus:              +{details.get('pqc_bonus', 0)}")
        print(f"    Critical Penalty:       -{details.get('critical_penalty', 0)}")
        print(f"    Diversity Penalty:      -{details.get('diversity_penalty', 0)}")
        if details.get('pg_penalty', 0) > 0:
            print(f"    PostgreSQL Penalty:     -{details.get('pg_penalty', 0)}")

    # Compliance
    compliance = report.get("compliance", {})
    if compliance:
        print("\n  NIST Compliance:")
        for check_id, info in compliance.items():
            status = "PASS" if info["passed"] else "FAIL"
            marker = "+" if info["passed"] else "x"
            print(f"    [{marker}] {info['name']}: {status}")

    # Top migration items
    roadmap = report.get("migration_roadmap", [])
    if roadmap:
        print("\n  Top Migration Items:")
        for i, item in enumerate(roadmap[:5], 1):
            print(f"    #{i} [{item['priority']}] {item['algorithm']}")
            print(f"       Replacement: {item['replacement']}")
            print(f"       Effort: {item['effort']} | Occurrences: {item['occurrences']}")

    print("\n" + "=" * 64)
    print()


def _get_score_color(score: int) -> str:
    """Get ANSI color code for score."""
    if score >= 85:
        return "\033[92m"  # Green
    elif score >= 70:
        return "\033[93m"  # Yellow
    elif score >= 50:
        return "\033[33m"  # Orange
    else:
        return "\033[91m"  # Red
