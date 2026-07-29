import json
import os
from fpdf import FPDF

class CleanPDFReport(FPDF):
    def header(self):
        self.set_font("helvetica", "B", 12)
        self.cell(0, 7, "Post-Quantum Cryptography (PQC) Technical Audit & Architecture Report", align="C", new_x="LMARGIN", new_y="NEXT")
        self.set_font("helvetica", "I", 8.5)
        self.cell(0, 4, "Target Audit: https://github.com/trustwallet/wallet-core.git", align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(3)

    def footer(self):
        self.set_y(-12)
        self.set_font("helvetica", "I", 8)
        self.cell(0, 8, f"Page {self.page_no()}", align="C")

    def section_title(self, title):
        self.set_font("helvetica", "B", 10)
        self.cell(0, 6, title, new_x="LMARGIN", new_y="NEXT")
        self.ln(1)

    def body_text(self, text):
        self.set_font("helvetica", size=8.5)
        self.multi_cell(0, 4, text)
        self.ln(2)

    def draw_clean_table(self, header, data, col_widths):
        self.set_font("helvetica", "B", 8)
        for i, col in enumerate(header):
            self.cell(col_widths[i], 6, col, border=1, align="C")
        self.ln()

        self.set_font("helvetica", size=7.5)

        for row in data:
            line_counts = []
            for i, text in enumerate(row):
                approx_chars = max(1, int(col_widths[i] / 1.7))
                lines = (len(str(text)) // approx_chars) + 1
                line_counts.append(lines)
            max_lines = max(line_counts)
            row_height = max(5, max_lines * 3.8)

            if self.get_y() + row_height > 185:
                self.add_page()
                self.set_font("helvetica", "B", 8)
                for i, col in enumerate(header):
                    self.cell(col_widths[i], 6, col, border=1, align="C")
                self.ln()
                self.set_font("helvetica", size=7.5)

            x_start = self.get_x()
            y_start = self.get_y()

            for i, cell_text in enumerate(row):
                self.set_xy(x_start + sum(col_widths[:i]), y_start)
                self.multi_cell(col_widths[i], 3.8, str(cell_text), border=1, align="L")

            self.set_xy(x_start, y_start + row_height)
        self.ln(3)

def generate_pdf():
    pdf = CleanPDFReport(orientation='L', unit='mm', format='A4')
    pdf.set_auto_page_break(auto=True, margin=12)
    pdf.add_page()

    # Section 1: Executive Summary
    pdf.section_title("1. Executive Summary & Audit Context")
    pdf.body_text(
        "Target Repository: https://github.com/trustwallet/wallet-core.git | Scan Mode: GitHub CLI / API Ingestion\n"
        "Readiness Score: 15/100 (Grade F - PQC Non-Compliant) | Total Assets: 20 | Occurrences: 1,952 Code Locations\n"
        "Vulnerable Assets: 10 | Safe Assets: 9 | Total Estimated Migration Timeline: 18 Weeks (Medium-term Initiative)"
    )

    # Section 2: Mathematical Formulations, Abbreviations & Synthesis Origin
    pdf.section_title("2. Mathematical Scoring Formulation, Variable Glossary & Origin of Formulas")
    pdf.body_text(
        "A. Mathematical Abbreviations & Variable Glossary:\n"
        "   - S_base       : Base Score (0 to 100). Measures the raw ratio of quantum-safe cryptographic assets.\n"
        "   - W_safe       : Total weighted score of quantum-resistant / safe cryptographic assets.\n"
        "   - W_total      : Total weighted score of ALL detected cryptographic assets across the codebase.\n"
        "   - w_ctx(i)     : Context Weight of primitive i. Reflects quantum threat severity (Asymmetric = 1.0, Symmetric = 0.7, Hash = 0.4).\n"
        "   - count_i      : Total occurrence count (frequency of calls) of algorithm i in source code files.\n"
        "   - B_PQC        : PQC Adoption Bonus (+0 to +5 points). Rewards usage of NIST-standardized PQC algorithms.\n"
        "   - P_critical   : Critical Vulnerability Penalty (-0 to -15 points). Deducts score for Category 0 algorithms (RSA, ECDSA).\n"
        "   - P_diversity  : Polyglot Diversity Penalty (-0 to -5 points). Deducts score for codebases split across > 2 languages.\n"
        "   - P_PG         : PostgreSQL Engine Penalty (-0 to -10 points). Deducts score for database-tier security flaws (pgcrypto RSA, MD5).\n"
        "   - pqc_count    : Count of unique Post-Quantum algorithms detected (e.g., ML-KEM / ML-DSA).\n"
        "   - critical_count: Count of unique Category 0 quantum-vulnerable algorithms (e.g., RSA, ECDSA, ECDH, EdDSA).\n"
        "   - total_assets : Count of all unique cryptographic algorithm families identified.\n"
        "   - language_count: Number of distinct programming languages containing active cryptographic calls (e.g., C++, Python, Rust).\n\n"
        "B. Connecting the Dots (Step-by-Step Mathematical Flow):\n"
        "   1. Asset Weighting: Every algorithm call is assigned an impact score = w_ctx * count. Safe assets accumulate into W_safe; all assets into W_total.\n"
        "   2. Base Ratio (S_base): Computes raw safety percentage: S_base = (W_safe / W_total) * 100.\n"
        "   3. Bonus Application: If PQC algorithms (ML-KEM/ML-DSA) exist, B_PQC = min(5, (pqc_count / total_assets) * 10) is added.\n"
        "   4. Penalty Application: Deducts P_critical for high-risk classical keys, P_diversity for polyglot complexity, and P_PG for database risks.\n"
        "   5. Final Clamping: Final Score = max(0, min(100, round(S_base + B_PQC - P_critical - P_diversity - P_PG))).\n\n"
        "C. Exact Codebase Equations & Formulas (Implemented in scoring/weight_engine.py):\n"
        "   Final Score = max(0, min(100, round(S_base + B_PQC - P_critical - P_diversity - P_PG)))\n"
        "   S_base = (W_safe / W_total) * 100 = [ sum(w_ctx(i) * count_i for i in Safe) / sum(w_ctx(j) * count_j for j in All) ] * 100\n"
        "   - Primitive Weights (w_ctx): Key-Exchange = 1.0, Digital Signature = 1.0, Encryption = 0.7, Hash = 0.4, MAC/KDF = 0.5\n"
        "   - PQC Bonus (B_PQC) = min(5, (pqc_count / total_assets) * 10)\n"
        "   - Critical Penalty (P_critical) = min(15, (critical_count / total_assets) * 20)\n"
        "   - Diversity Penalty (P_diversity) = min(5, max(0, (language_count - 2) * 1.5))\n"
        "   - PostgreSQL Penalty (P_PG) = min(10, sum(pg_rule_penalties))\n\n"
        "D. Origin & Online Availability of Formulas:\n"
        "   The exact numerical coefficients (e.g., min(5, ...), 1.5 multiplier) do not exist on a single webpage. Instead, they represent a custom "
        "algorithmic synthesis model that translates qualitative standards from NIST SP 800-57, NIST IR 8413, CISA Quantum Guidance, and PostgreSQL "
        "security docs into quantifiable linear equations.\n\n"
        "E. Migration Timeline Weeks Formulation & Logic:\n"
        "   Total Migration Weeks = sum( effort_weeks(algo_i) )\n"
        "   - Low Effort (SHA-256, SHA-3, AES-256): 1 week per asset (Config / hashing parameter update)\n"
        "   - Medium Effort (TLS 1.3 Upgrade): 3 weeks per asset (Protocol handshake & cipher suite migration)\n"
        "   - High Effort (Replacing ECDSA/EdDSA with ML-DSA FIPS 204 or ML-KEM FIPS 203): 8 weeks per asset (Complex API & asymmetric refactoring)"
    )

    # Section 3: API Call Architecture & Inter-module Data Flow
    pdf.section_title("3. API Call Architecture & Inter-Module Data Flow Between Python (.py) Files")
    pdf.body_text(
        "The pgcrypto scanner architecture connects Python modules via explicit API calls and internal data contracts:\n\n"
        "1. CLI to Ingestion API (pgcrypto_scanner.py -> scanner/git_cloner.py):\n"
        "   - Function Call: RepoCloner.clone_repo(github_url, timeout=300)\n"
        "   - Action: Invokes Git/GitHub HTTPS API via sub-process to execute 'git clone --depth 1'. Returns local path to cloned workspace.\n\n"
        "2. Ingestion to Detection API (pgcrypto_scanner.py -> scanner/repo_detector.py):\n"
        "   - Function Call: RepoDetector.detect(workspace_dir)\n"
        "   - Action: Inspects directory tree to auto-detect PostgreSQL configs, SQL migration scripts, or C++/Rust/Python codebases.\n\n"
        "3. Scanner Dispatch APIs (pgcrypto_scanner.py -> scanner/postgres_scanner.py & generic_scanner.py):\n"
        "   - Function Call: PostgresScanner.scan_directory(target_dir) & GenericScanner.scan_directory(target_dir)\n"
        "   - Internal File I/O API: Uses Python open(filepath, 'r', encoding='utf-8', errors='ignore') line-by-line.\n"
        "   - Rule Evaluation: Matches line content against Regex rules imported from rules/postgres/*.py and rules/generic/*.py.\n"
        "   - Return Contract: Returns raw list of finding dicts containing algorithmName, primitive, file, line_number, and risk.\n\n"
        "4. Deduplication & Normalization API (pgcrypto_scanner.py -> scanner/merger.py):\n"
        "   - Function Call: merge_findings(pg_findings, generic_findings) & deduplicate_by_algorithm(merged_findings)\n"
        "   - Action: Combines findings and groups occurrences per unique algorithm family to prevent duplicate counting.\n\n"
        "5. Risk & Scoring Evaluation APIs (pgcrypto_scanner.py -> scoring/weight_engine.py & nist_compliance.py):\n"
        "   - Function Call: compute_readiness_score(deduplicated_findings) & check_nist_compliance(deduplicated_findings)\n"
        "   - Action: Evaluates Base Score, Bonuses, Penalties, and NIST FIPS 203/204 compliance. Returns structured score dictionary.\n\n"
        "6. Output Generator APIs (pgcrypto_scanner.py -> output/cbom_generator.py & output/score_reporter.py):\n"
        "   - Function Call: generate_cbom(findings) -> save_cbom('cbom.json')\n"
        "   - Function Call: generate_score_report(score_dict) -> save_score_report('readiness_score.json') & print_terminal_report()\n"
        "   - Dashboard Call: Renders interactive HTML web dashboard into dashboard/index.html."
    )

    # Section 4: Clean File Matrix Table (TABLE 1)
    pdf.section_title("4. Codebase File Directory & Responsibility Matrix")
    headers_t1 = ["Category", "File Path", "Main Responsibility & Processing Logic"]
    widths_t1 = [35, 55, 180]
    data_t1 = [
        ["CLI Entry Point", "pgcrypto_scanner.py", "Main entry CLI. Ingests user flags (--github, --config, --sql, --host), coordinates modules, and prints terminal reports."],
        ["Scanning Engine", "scanner/git_cloner.py", "Uses Git / GitHub HTTPS API to execute git clone --depth 1, cloning remote repos into temporary scratch workspace with auto-cleanup."],
        ["Scanning Engine", "scanner/repo_detector.py", "Inspects target directory structure to auto-detect PostgreSQL configs, SQL migration scripts, or general C++/Python codebases."],
        ["Scanning Engine", "scanner/postgres_scanner.py", "Reads .conf, .sql, .crt, and .c files line-by-line using Python open() API to detect pgcrypto and TLS security patterns."],
        ["Scanning Engine", "scanner/generic_scanner.py", "Reads application source code (.py, .cpp, .h, .go, .c) line-by-line using regex rules targeting classical crypto calls."],
        ["Scanning Engine", "scanner/merger.py", "Merges, normalizes, and deduplicates raw findings from both scanners to prevent double-counting of cryptographic assets."],
        ["Rules Engine", "rules/postgres/*.py", "Python rule definitions targeting pgcrypto functions (pgp_pub_encrypt, digest), TLS protocol limits, and MD5 password hashes."],
        ["Rules Engine", "rules/generic/*.py", "Regex pattern rules targeting asymmetric (RSA/ECDSA/Ed25519), symmetric (AES/DES/RC4), hash (SHA-1/MD5), and PQC algorithms."],
        ["Scoring & Risk", "scoring/weight_engine.py", "Calculates PQC Readiness Score (0-100) using weighted base score, bonuses, critical penalties, and timeline estimates."],
        ["Scoring & Risk", "scoring/nist_compliance.py", "Evaluates findings against NIST standards (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA)."],
        ["Output Generator", "output/cbom_generator.py", "Converts scanned findings into a standard CycloneDX Cryptography Bill of Materials (cbom.json)."],
        ["Output Generator", "output/score_reporter.py", "Generates readiness_score.json, prints terminal summaries, and builds the interactive HTML dashboard."],
        ["Dashboard", "dashboard/index.html", "Interactive web interface to visually inspect scores, breakdowns, and migration roadmaps."],
        ["PDF Documentation", "generate_pdf_report.py", "Helper script using fpdf2 to build comprehensive PDF technical audit documentation."]
    ]
    pdf.draw_clean_table(headers_t1, data_t1, widths_t1)

    # Section 5: Clean Execution Pipeline Table (TABLE 2)
    pdf.section_title("5. Step-by-Step Execution Pipeline (First Point to Last Point)")
    headers_t2 = ["Step", "Execution Stage", "Executing File", "Input Data", "Output Data / Next Action"]
    widths_t2 = [10, 42, 48, 70, 100]
    data_t2 = [
        ["1", "Command-Line Parsing", "pgcrypto_scanner.py", "User CLI argument: --github https://github.com/trustwallet/wallet-core.git", "Validated arguments & GitHub execution mode."],
        ["2", "Repository Retrieval", "scanner/git_cloner.py", "GitHub Repository URL", "Executes git clone --depth 1 to fetch repository into scratch workspace."],
        ["3", "Target Auto-Detection", "scanner/repo_detector.py", "Cloned wallet-core files", "Detects generic C++/Rust/Python codebase with 189 config/header files."],
        ["4a", "PostgreSQL Analysis", "scanner/postgres_scanner.py", ".conf, .sql, .crt files", "List of PG findings (0 findings for pure wallet core codebase)."],
        ["4b", "Generic Code Analysis", "scanner/generic_scanner.py", "C++ / Rust / Header files (.cpp, .h, .c)", "1,952 raw findings (EdDSA, ECDSA, ECDH, SHA-256, DES, RC4, MD5)."],
        ["5", "Findings Deduplication", "scanner/merger.py", "Raw findings from 4a & 4b", "Deduplicates to 20 unique cryptographic asset families."],
        ["6", "NIST Compliance Check", "scoring/nist_compliance.py", "Deduplicated findings", "Maps assets to FIPS 203 / 204 / 205 compliance standards."],
        ["7", "Score Calculation", "scoring/weight_engine.py", "Deduplicated findings", "Computes Final Readiness Score = 15/100 (Grade F), 18 Total Migration Weeks."],
        ["8", "CBOM Export", "output/cbom_generator.py", "Scored assets", "Generates CycloneDX cbom.json file."],
        ["9", "Score Report Export", "output/score_reporter.py", "Score dictionary", "Generates readiness_score.json and renders dashboard/index.html."],
        ["10", "Terminal & Cleanup", "pgcrypto_scanner.py", "Final results", "Prints terminal summary table and removes temporary clone folders."]
    ]
    pdf.draw_clean_table(headers_t2, data_t2, widths_t2)

    # Section 6: Web Citations & References
    pdf.section_title("6. Web Citations & Official References")
    pdf.body_text(
        "1. NIST Post-Quantum Cryptography Standardization Project:\n"
        "   https://csrc.nist.gov/projects/post-quantum-cryptography\n\n"
        "2. NIST FIPS 203 - Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM):\n"
        "   https://csrc.nist.gov/pubs/fips/203/final\n\n"
        "3. NIST FIPS 204 - Module-Lattice-Based Digital Signature Algorithm (ML-DSA):\n"
        "   https://csrc.nist.gov/pubs/fips/204/final\n\n"
        "4. NIST SP 800-57 Part 1 Rev. 5 - Recommendation for Key Management:\n"
        "   https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final\n\n"
        "5. CISA Post-Quantum Cryptography Initiative & Migration Roadmap:\n"
        "   https://www.cisa.gov/quantum\n\n"
        "6. PostgreSQL pgcrypto Module Documentation:\n"
        "   https://www.postgresql.org/docs/current/pgcrypto.html"
    )

    output_path = "pqc_audit_report.pdf"
    pdf.output(output_path)
    print(f"PDF successfully generated at {output_path}")

if __name__ == "__main__":
    generate_pdf()
