import json
import os
from fpdf import FPDF

class ScriptPDFReport(FPDF):
    def header(self):
        self.set_font("helvetica", "B", 11)
        self.cell(0, 6, "Post-Quantum Cryptography (PQC) Keynote & Technical Presentation Script", align="C", new_x="LMARGIN", new_y="NEXT")
        self.set_font("helvetica", "I", 8.5)
        self.cell(0, 4, "Duration: 15-20 Minutes | Case Study: trustwallet/wallet-core | Ref: Migration and Agility in Cryptographic Systems", align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(3)

    def footer(self):
        self.set_y(-12)
        self.set_font("helvetica", "I", 8)
        self.cell(0, 8, f"Page {self.page_no()}", align="C")

    def section_title(self, title):
        self.set_font("helvetica", "B", 10)
        self.cell(0, 5, title, new_x="LMARGIN", new_y="NEXT")
        self.ln(1)

    def speech_text(self, text):
        self.set_font("helvetica", "I", 8.5)
        clean_text = text.replace("—", "-").replace("“", '"').replace("”", '"').replace("’", "'")
        self.multi_cell(0, 4, clean_text)
        self.ln(2)

    def body_text(self, text):
        self.set_font("helvetica", size=8.5)
        clean_text = text.replace("—", "-").replace("“", '"').replace("”", '"').replace("’", "'")
        self.multi_cell(0, 4, clean_text)
        self.ln(2)

def generate_script_pdf():
    pdf = ScriptPDFReport(orientation='P', unit='mm', format='A4')
    pdf.set_auto_page_break(auto=True, margin=12)
    pdf.add_page()

    # Part 1
    pdf.section_title("PART 1: THE IMPENDING CRISIS & THE AGILITY IMPERATIVE (Minutes 0:00 - 3:30)")
    pdf.speech_text(
        "\"Good morning, everyone. Thank you for joining this session today.\n\n"
        "I want to open our discussion with a simple yet stark reality: The cryptographic foundations underlying modern software infrastructure are operating on borrowed time.\n\n"
        "For decades, our security protocols - from TLS handshakes and SSH connections to digital signatures and database encryption - have relied on the mathematical hardness of prime factorization and discrete logarithms. Algorithms like RSA, Diffie-Hellman, ECDSA, and Ed25519 form the bedrock of digital trust.\n\n"
        "However, with the rapid advancement of Cryptanalytically Relevant Quantum Computers (CRQCs), Shor's Algorithm will render these classical asymmetric algorithms obsolete. A quantum computer will not merely increase brute-force speeds - it will reduce the complexity of solving RSA and Elliptic Curve Cryptography from exponential time to polynomial time.\n\n"
        "As highlighted in the seminal proceedings 'Migration and Agility in Cryptographic Systems', the fundamental challenge facing software engineering today is NOT just algorithm replacement - it is Cryptographic Agility. Most modern codebases are cryptographically rigid: cryptographic primitives are hardcoded, deeply coupled with business logic, and spread across multi-language stacks.\n\n"
        "To solve this, we cannot rely on manual code reviews. We need automated, mathematically sound auditing frameworks that can ingest codebases, measure quantum risk, evaluate cryptographic agility, and build concrete migration roadmaps before quantum advantage is realized. Today, I am presenting the architecture and real-world audit findings of our automated PQC Readiness Scanner.\""
    )

    # Part 2
    pdf.section_title("PART 2: CASE STUDY - AUDITING trustwallet/wallet-core (Minutes 3:30 - 8:00)")
    pdf.speech_text(
        "\"To demonstrate the scanner in action on a production, multi-language codebase, we conducted an automated audit of a major open-source repository: trustwallet/wallet-core (available at https://github.com/trustwallet/wallet-core.git).\n\n"
        "wallet-core is an enterprise cross-platform cryptographic library written in C++, C, Rust, and Python. It powers key generation, transaction signing, and address derivation across dozens of blockchain protocols.\n\n"
        "Let's look at what our automated pipeline discovered:\n"
        "1. Scale of Cryptographic Footprint: The scanner identified 1,952 active cryptographic call locations across 189 configuration and header files, mapping to 20 unique algorithm families.\n"
        "2. Vulnerability Breakdown: 10 out of 20 algorithm families are critically vulnerable to quantum attack. Over 1,005 occurrences were high-risk signature operations (Ed25519, Secp256k1 ECDSA). 190 occurrences were critical-risk key exchange routines.\n"
        "3. Audit Result: PQC Readiness Score = 15/100 (Grade F - PQC Non-Compliant), with an estimated migration timeline of 18 Weeks of dedicated engineering effort.\n\n"
        "Why did wallet-core score a 15/100 despite being high-quality software? Because modern blockchain infrastructure is almost entirely built on classical asymmetric signatures (ECDSA/Ed25519). Under quantum threat models defined by NIST, asymmetric signatures carry zero bits of quantum security. This case study underscores the core thesis of 'Migration and Agility in Cryptographic Systems': Security today does not equal Post-Quantum readiness tomorrow.\""
    )

    # Part 3
    pdf.section_title("PART 3: MATHEMATICAL MODEL & UNIFIED ENGINE MAPPING (Minutes 8:00 - 13:00)")
    pdf.speech_text(
        "\"Now, I would like to walk through how we quantify this risk - and I want to emphasize upfront: The mathematical model we are presenting is an active research project that we are continuously refining and evolving.\n\n"
        "Right now, our readiness calculation is implemented in scoring/weight_engine.py via the formula:\n\n"
        "Final Score = max(0, min(100, round(S_base + B_PQC - P_critical - P_diversity - P_PG)))\n\n"
        "Where Base Score S_base measures the safe asset ratio, B_PQC rewards NIST FIPS 203/204 adoption, P_critical penalizes NIST Category 0 keys, and P_diversity penalizes multi-language complexity.\n\n"
        "Our Next Major Engineering Goal: Unified Engine Mapping\n"
        "While our current formula provides strong quantitative baseline metrics, our primary upcoming milestone is to map our auditing work into a Unified Mapping of Engines and Models.\n\n"
        "What does this mean?\n"
        "1. Unifying Detection Engines: Merging static AST code parsing, live database query inspection (pgcrypto), and runtime network protocol evaluation into a single unified telemetry layer.\n"
        "2. Unifying Risk Models: Mapping our local mathematical weights directly to standardized enterprise threat frameworks (such as NIST IR 8413, ISO/IEC 27001 crypto controls, and CISA PQC roadmaps).\n\n"
        "By mapping our scanner output into a unified engine-and-model framework, we can achieve standardized, deterministic PQC readiness scores across heterogeneous enterprise environments.\""
    )

    # Part 4 & 5
    pdf.section_title("PART 4: INTER-MODULE API ARCHITECTURE & PIPELINE (Minutes 13:00 - 17:00)")
    pdf.speech_text(
        "\"To execute this complex analysis end-to-end, how do our underlying Python modules interact? The system is architected as a 5-stage pipeline with strict inter-module API contracts:\n\n"
        "1. Ingestion API (pgcrypto_scanner.py -> scanner/git_cloner.py): CLI calls RepoCloner.clone_repo(), invoking Git HTTPS API via 'git clone --depth 1' into a scratch workspace.\n"
        "2. Target Detection API (scanner/repo_detector.py): RepoDetector.detect() auto-classifies target directories.\n"
        "3. Dual Scanner Engine (postgres_scanner.py & generic_scanner.py): Opens files line-by-line using Python open() API and matches compiled Regex rules from rules/generic/*.py.\n"
        "4. Deduplication & Merger API (scanner/merger.py): merge_findings() and deduplicate_by_algorithm() normalize findings.\n"
        "5. Scoring & Output APIs (scoring/weight_engine.py -> output/*): compute_readiness_score() evaluates equations, generate_cbom() exports cbom.json, and score_reporter.py renders index.html and readiness_score.json.\""
    )

    pdf.section_title("PART 5: CONCLUSION & Q&A PREPARATION (Minutes 17:00 - 20:00)")
    pdf.speech_text(
        "\"In conclusion, achieving Post-Quantum Cryptographic Agility is not a luxury - it is an incoming engineering mandate.\n\n"
        "As emphasized in 'Migration and Agility in Cryptographic Systems', organizations that delay inventorying and abstracting their cryptographic layers will face catastrophic migration debt when classical algorithms are deprecated by NIST and CISA.\n\n"
        "Our PQC Scanner provides automated discovery across local code, PostgreSQL databases, and remote GitHub repos; a mathematical scoring model that we are actively refining to map into a Unified Mapping of Engines and Models; and standardized CBOM JSON generation with estimated engineering timelines in weeks. Thank you, and I welcome any questions.\""
    )

    output_path = "presentation_script.pdf"
    pdf.output(output_path)
    print(f"Script PDF successfully generated at {output_path}")

if __name__ == "__main__":
    generate_script_pdf()
