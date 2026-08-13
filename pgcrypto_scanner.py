#!/usr/bin/env python3
"""
pgcrypto PQC Scanner v1.0
PostgreSQL-focused Post-Quantum Cryptography audit tool.

Scans PostgreSQL configurations, pgcrypto SQL, connection strings,
and C extensions for quantum-vulnerable cryptographic patterns.
Supports local directories, GitHub repositories, and live instances.

Usage:
    python3 pgcrypto_scanner.py --config /etc/postgresql/16/main/
    python3 pgcrypto_scanner.py --github https://github.com/user/repo
    python3 pgcrypto_scanner.py --config /path --host localhost
"""

import os
import sys
import argparse
import json
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.git_cloner import RepoCloner
from scanner.repo_detector import RepoDetector
from scanner.generic_scanner import GenericScanner
from scanner.postgres_scanner import PostgresScanner
from scanner.merger import merge_findings, deduplicate_by_algorithm
from scoring.weight_engine import compute_readiness_score
from scoring.nist_compliance import check_nist_compliance, get_compliance_summary
from output.cbom_generator import generate_cbom, save_cbom
from output.score_reporter import generate_score_report, save_score_report, print_terminal_report


def main():
    parser = argparse.ArgumentParser(
        description="pgcrypto PQC Scanner - PostgreSQL Post-Quantum Readiness Audit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan local PostgreSQL config directory
  %(prog)s --config /etc/postgresql/16/main/ -n "MyPGServer"

  # Scan a GitHub repository
  %(prog)s --github https://github.com/user/pg-app -n "PGApp"

  # Scan both config directory and live instance
  %(prog)s --config /etc/postgresql/16/main/ --host localhost -n "FullAudit"

  # Scan SQL files only
  %(prog)s --sql /path/to/migrations/ -n "SQLAudit"
        """
    )

    # Input modes
    input_group = parser.add_argument_group("Input Modes")
    input_group.add_argument(
        "--config", "-c",
        help="PostgreSQL config directory to scan"
    )
    input_group.add_argument(
        "--github", "-g",
        help="GitHub repository URL to clone and scan"
    )
    input_group.add_argument(
        "--sql", "-s",
        help="Directory containing SQL files to scan"
    )
    input_group.add_argument(
        "--host",
        help="PostgreSQL host for live instance scanning (requires psycopg2)"
    )
    input_group.add_argument(
        "--port", "-p",
        type=int, default=5432,
        help="PostgreSQL port (default: 5432)"
    )
    input_group.add_argument(
        "--user", "-u",
        default="postgres",
        help="PostgreSQL user (default: postgres)"
    )

    # Options
    parser.add_argument(
        "--name", "-n",
        default=None,
        help="Project name (default: directory name or repo name)"
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output directory for results"
    )
    parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Skip dashboard generation"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON only (no dashboard, no terminal report)"
    )
    parser.add_argument(
        "--timeout",
        type=int, default=300,
        help="GitHub clone timeout in seconds (default: 300)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )

    args = parser.parse_args()

    # Validate input
    if not any([args.config, args.github, args.sql, args.host]):
        parser.error("At least one input mode required: --config, --github, --sql, or --host")

    # Determine project name
    project_name = args.name
    scan_target = None

    # Setup output directory
    if args.output:
        output_dir = args.output
        os.makedirs(output_dir, exist_ok=True)
    else:
        output_dir = os.getcwd()

    print()
    print("=" * 64)
    print("  pgcrypto PQC Scanner v1.0")
    print("  PostgreSQL Post-Quantum Cryptography Audit")
    print("=" * 64)

    # ===== MODE 1: GitHub Clone =====
    cloned_dir = None
    if args.github:
        print(f"\n[1/4] Cloning repository: {args.github}")
        try:
            cloner = RepoCloner(timeout=args.timeout)
            cloned_dir = cloner.clone(args.github)
            scan_target = args.github
            if not project_name:
                # Extract repo name from URL
                project_name = args.github.rstrip("/").split("/")[-1].replace(".git", "")
            print(f"      Cloned to: {cloned_dir}")
        except Exception as e:
            print(f"      ERROR: {e}")
            sys.exit(1)

    # ===== MODE 2: Detect PostgreSQL Structure =====
    scan_path = cloned_dir or args.config or args.sql or "."
    pg_detection = None

    print(f"\n[2/4] Analyzing repository structure...")
    detector = RepoDetector()
    pg_detection = detector.detect(scan_path)
    print(detector.get_scan_summary())

    # ===== MODE 3: Scan for Crypto Patterns =====
    print(f"\n[3/4] Scanning for cryptographic patterns...")

    all_findings = []
    files_scanned = 0

    # Generic scanner
    generic_scanner = GenericScanner()

    # PostgreSQL scanner
    pg_scanner = PostgresScanner()

    if args.config or cloned_dir:
        # Scan config directory
        config_path = args.config or cloned_dir
        if not project_name:
            project_name = os.path.basename(config_path) if config_path else "Unknown"
        if not scan_target:
            scan_target = config_path

        print(f"      Scanning: {config_path}")

        # Generic scan
        gen_findings, gen_files = generic_scanner.scan_directory(config_path)
        all_findings.extend(gen_findings)
        files_scanned += gen_files

        # PostgreSQL-specific scan
        pg_findings, pg_files = pg_scanner.scan_directory(config_path)
        all_findings.extend(pg_findings)
        files_scanned += pg_files

        # Deep scan of config files
        if pg_detection.get("has_pg_config"):
            for config_file in pg_detection.get("config_files", []):
                full_path = os.path.join(config_path, config_file)
                if os.path.exists(full_path):
                    config_findings = pg_scanner.scan_config_file(full_path)
                    all_findings.extend(config_findings)

    elif args.sql:
        # Scan SQL files only
        if not project_name:
            project_name = os.path.basename(args.sql) if args.sql else "Unknown"
        if not scan_target:
            scan_target = args.sql

        print(f"      Scanning SQL: {args.sql}")

        # SQL-specific scan
        pg_findings, pg_files = pg_scanner.scan_directory(args.sql)
        all_findings.extend(pg_findings)
        files_scanned += pg_files

    elif args.host:
        # Live instance scanning
        if not project_name:
            project_name = f"PG-{args.host}"
        if not scan_target:
            scan_target = f"{args.host}:{args.port}"

        print(f"      Scanning live instance: {args.host}:{args.port}")
        # Live scanning would require psycopg2
        try:
            import psycopg2
            conn = psycopg2.connect(
                host=args.host,
                port=args.port,
                user=args.user
            )
            cur = conn.cursor()

            # Query SSL settings
            ssl_settings = [
                "ssl", "ssl_cert_file", "ssl_key_file", "ssl_ca_file",
                "ssl_min_protocol_version", "ssl_ciphers",
                "password_encryption", "wal_level"
            ]

            for setting in ssl_settings:
                try:
                    cur.execute(f"SHOW {setting}")
                    value = cur.fetchone()[0]
                    all_findings.append({
                        "rule_id": f"pg_live_{setting}",
                        "rule_name": f"Live: {setting}",
                        "category": "pg_live",
                        "file": f"postgresql://{args.host}:{args.port}",
                        "line_number": 0,
                        "content": f"{setting} = {value}",
                        "language": "config",
                        "algorithm": {
                            "algorithmFamily": "PostgreSQL",
                            "algorithmName": setting,
                            "primitive": "configuration",
                            "risk": 0 if "on" in value.lower() or "scram" in value.lower() else 1,
                            "nistQuantumSecurityLevel": 1,
                            "classicalSecurityLevel": 256,
                            "securityProperties": [],
                        },
                        "replacement": "",
                        "priority": "P3-Low",
                        "effort": "None",
                        "source": "postgresql",
                    })
                except Exception:
                    pass

            # Check for pgcrypto extension
            try:
                cur.execute("SELECT extname FROM pg_extension WHERE extname = 'pgcrypto'")
                if cur.fetchone():
                    all_findings.append({
                        "rule_id": "pg_live_pgcrypto",
                        "rule_name": "Live: pgcrypto Extension",
                        "category": "pg_live",
                        "file": f"postgresql://{args.host}:{args.port}",
                        "line_number": 0,
                        "content": "pgcrypto extension installed",
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
                        "replacement": "",
                        "priority": "P4-Safe",
                        "effort": "None",
                        "source": "postgresql",
                    })
            except Exception:
                pass

            # Check SSL status
            try:
                cur.execute("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()")
                ssl_used = cur.fetchone()[0]
                all_findings.append({
                    "rule_id": "pg_live_ssl_status",
                    "rule_name": "Live: SSL Connection Status",
                    "category": "pg_live",
                    "file": f"postgresql://{args.host}:{args.port}",
                    "line_number": 0,
                    "content": f"SSL in use: {ssl_used}",
                    "language": "config",
                    "algorithm": {
                        "algorithmFamily": "TLS",
                        "algorithmName": "Live SSL Status",
                        "primitive": "certificate",
                        "risk": 2 if ssl_used else 0,
                        "nistQuantumSecurityLevel": 1 if ssl_used else 0,
                        "classicalSecurityLevel": 256 if ssl_used else 0,
                        "securityProperties": ["ssl-active"] if ssl_used else ["no-ssl"],
                    },
                    "replacement": "" if ssl_used else "Enable SSL connections",
                    "priority": "P4-Safe" if ssl_used else "P0-Critical",
                    "effort": "None",
                    "source": "postgresql",
                })
            except Exception:
                pass

            conn.close()
            print(f"      Live scan complete")

        except ImportError:
            print("      WARNING: psycopg2 not installed. Install with: pip install psycopg2-binary")
        except Exception as e:
            print(f"      WARNING: Could not connect to {args.host}:{args.port}: {e}")

    # ===== Merge findings =====
    generic_only = [f for f in all_findings if f.get("source") == "generic"]
    postgres_only = [f for f in all_findings if f.get("source") == "postgresql"]
    merged = merge_findings(generic_only, postgres_only)

    print(f"      Scanned {files_scanned} files, found {len(merged)} crypto occurrences")
    print(f"      Generic: {len(generic_only)} | PostgreSQL: {len(postgres_only)}")

    # ===== Compute Score =====
    print(f"\n[4/4] Computing PQC Readiness Score...")

    score_data = compute_readiness_score(merged)

    # NIST compliance
    compliance = check_nist_compliance(merged)
    compliance_summary = get_compliance_summary(compliance)

    # Generate outputs
    project_name = project_name or "Unknown"

    # CBOM
    cbom = generate_cbom(merged, project_name, scan_path or ".")
    cbom_path = os.path.join(output_dir, "cbom.json")
    save_cbom(cbom, cbom_path)

    # Score report
    report = generate_score_report(
        score_data=score_data,
        compliance=compliance,
        findings=merged,
        project_name=project_name,
        scan_mode="github" if cloned_dir else "local",
        repo_url=args.github,
        pg_detection=pg_detection,
    )
    score_path = os.path.join(output_dir, "readiness_score.json")
    save_score_report(report, score_path)

    # Terminal output
    if not args.json:
        print_terminal_report(report, scan_target or "Unknown")

    # JSON output
    if args.json:
        print(json.dumps(report, indent=2))

    # Dashboard
    if not args.no_dashboard and not args.json:
        _generate_dashboard(output_dir, cbom_path, score_path)

    print(f"  Output files:")
    print(f"    CBOM:      {cbom_path}")
    print(f"    Score:     {score_path}")
    if not args.no_dashboard and not args.json:
        print(f"    Dashboard: {os.path.join(output_dir, 'index.html')}")
    print()

    # Cleanup cloned repo
    if cloned_dir:
        import shutil
        shutil.rmtree(cloned_dir, ignore_errors=True)


def _generate_dashboard(output_dir: str, cbom_path: str, score_path: str):
    """Generate dashboard files."""
    dashboard_dir = os.path.join(output_dir, "dashboard")
    os.makedirs(dashboard_dir, exist_ok=True)

    # Copy dashboard files from package
    pkg_dashboard = os.path.join(os.path.dirname(__file__), "output", "dashboard")
    if os.path.exists(pkg_dashboard):
        for filename in os.listdir(pkg_dashboard):
            src = os.path.join(pkg_dashboard, filename)
            dst = os.path.join(dashboard_dir, filename)
            if os.path.isfile(src):
                import shutil
                shutil.copy2(src, dst)

    # Also create a simple index.html that loads the data
    index_html = os.path.join(dashboard_dir, "index.html")
    _create_simple_dashboard(dashboard_dir, cbom_path, score_path)


def _create_simple_dashboard(dashboard_dir: str, cbom_path: str, score_path: str):
    """Create a simple HTML dashboard if index.html does not exist."""
    index_html = os.path.join(dashboard_dir, "index.html")
    if os.path.exists(index_html):
        return
    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>pgcrypto PQC Scanner - Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
               background: #0a0a0f; color: #e0e0e0; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #00d4ff; margin-bottom: 20px; }
        .score-ring { text-align: center; margin: 30px 0; }
        .score-value { font-size: 72px; font-weight: bold; color: #00d4ff; }
        .score-grade { font-size: 24px; color: #888; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 20px; margin-top: 20px; }
        .card { background: #1a1a2e; border-radius: 12px; padding: 20px;
                border: 1px solid #2a2a4a; }
        .card h2 { color: #00d4ff; font-size: 18px; margin-bottom: 15px; }
        .stat { display: flex; justify-content: space-between; padding: 8px 0;
                border-bottom: 1px solid #2a2a4a; }
        .stat-label { color: #888; }
        .stat-value { font-weight: bold; }
        .critical { color: #ff4444; }
        .high { color: #ffaa00; }
        .safe { color: #44ff44; }
        .roadmap-item { background: #0d0d1a; padding: 12px; border-radius: 8px;
                        margin: 8px 0; border-left: 4px solid #ff4444; }
        .roadmap-item.p1 { border-left-color: #ffaa00; }
        .roadmap-item.p2 { border-left-color: #ffdd00; }
        .roadmap-item.p3 { border-left-color: #44ff44; }
        .priority { font-size: 12px; padding: 2px 8px; border-radius: 4px;
                    display: inline-block; margin-bottom: 8px; }
        .priority.p0 { background: #ff444433; color: #ff4444; }
        .priority.p1 { background: #ffaa0033; color: #ffaa00; }
        .priority.p2 { background: #ffdd0033; color: #ffdd00; }
        .priority.p3 { background: #44ff4433; color: #44ff44; }
        #data-note { text-align: center; color: #666; margin-top: 20px; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>pgcrypto PQC Scanner</h1>
        <div id="dashboard">Loading...</div>
        <p id="data-note">Load cbom.json and readiness_score.json to see results</p>
    </div>
    <script>
        async function loadData() {
            try {
                const scoreResp = await fetch('../readiness_score.json');
                const score = await scoreResp.json();
                renderDashboard(score);
            } catch (e) {
                document.getElementById('dashboard').innerHTML =
                    '<p style="color:#ff4444">Could not load data. Run the scanner first.</p>';
            }
        }

        function renderDashboard(data) {
            document.getElementById('data-note').style.display = 'none';
            var roadmapItems = (data.migration_roadmap || []).slice(0, 5).map(function(item) {
                var pClass = (item.priority || '').split('-')[0].toLowerCase();
                return '<div class="roadmap-item ' + pClass + '">' +
                    '<span class="priority ' + pClass + '">' + item.priority + '</span>' +
                    '<strong>' + item.algorithm + '</strong><br>' +
                    '<small>Replace with: ' + item.replacement + '</small><br>' +
                    '<small>Effort: ' + item.effort + ' | Files: ' + item.file_count + '</small>' +
                    '</div>';
            }).join('');

            var html = '<div class="score-ring">' +
                '<div class="score-value">' + data.score + '</div>' +
                '<div class="score-grade">Grade: ' + data.grade + ' - ' + data.label + '</div>' +
                '</div>' +
                '<div class="grid">' +
                '<div class="card"><h2>Summary</h2>' +
                '<div class="stat"><span class="stat-label">Total Assets</span><span class="stat-value">' + data.total_assets + '</span></div>' +
                '<div class="stat"><span class="stat-label">Occurrences</span><span class="stat-value">' + data.total_occurrences + '</span></div>' +
                '<div class="stat"><span class="stat-label">Vulnerable</span><span class="stat-value critical">' + data.vulnerable_assets + '</span></div>' +
                '<div class="stat"><span class="stat-label">Safe</span><span class="stat-value safe">' + data.safe_assets + '</span></div>' +
                '<div class="stat"><span class="stat-label">Critical</span><span class="stat-value critical">' + data.critical_assets + '</span></div>' +
                '<div class="stat"><span class="stat-label">PQC Found</span><span class="stat-value safe">' + data.pqc_assets + '</span></div>' +
                '</div>' +
                '<div class="card"><h2>Timeline</h2>' +
                '<div class="stat"><span class="stat-label">Estimated</span><span class="stat-value">' + (data.timeline ? data.timeline.label : 'N/A') + '</span></div>' +
                '<div class="stat"><span class="stat-label">Weeks</span><span class="stat-value">' + (data.timeline ? data.timeline.weeks : 0) + '</span></div>' +
                '</div>' +
                '<div class="card"><h2>Migration Roadmap</h2>' + roadmapItems + '</div>' +
                '</div>';
            document.getElementById('dashboard').innerHTML = html;
        }

        loadData();
    </script>
</body>
</html>"""

    with open(index_html, "w") as f:
        f.write(html)


if __name__ == "__main__":
    main()
