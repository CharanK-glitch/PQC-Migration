from fpdf import FPDF

class PDF(FPDF):
    def header(self):
        self.set_font("helvetica", "B", 16)
        self.cell(0, 10, "pgcrypto PQC Scanner - Complete Guide", align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font("helvetica", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")

def main():
    pdf = PDF()
    pdf.add_page()
    pdf.set_font("helvetica", size=11)

    sections = [
        ("1. Introduction", "The pgcrypto PQC Scanner is a specialized audit tool designed to evaluate PostgreSQL projects for Post-Quantum Cryptography (PQC) readiness. It scans for legacy cryptographic patterns (like MD5, DES, RSA) and checks if the project aligns with NIST standards like FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA)."),
        
        ("2. Setup & Installation", "Ensure you have Python 3 installed. If you want to scan live PostgreSQL databases, you'll need the 'psycopg2' module. No other dependencies are strictly required for file scanning."),
        
        ("3. Automated Scanning (GitHub)", "You can scan any public GitHub repository automatically. The tool will clone the repository, scan the files, and clean up afterwards.\n\nCommand:\npython3 pgcrypto_scanner.py --github https://github.com/<user>/<repo> -n \"ProjectName\""),
        
        ("4. Manual Scanning (Local Folders)", "If you have a cloned repository or a local PostgreSQL configuration folder, you can scan it directly using the --config flag (which acts as a root directory scanner).\n\nCommand:\npython3 pgcrypto_scanner.py --config /path/to/project -n \"ProjectName\""),
        
        ("5. Scanning SQL Files Only", "If you only want to scan specific database migrations or SQL files, use the --sql flag.\n\nCommand:\npython3 pgcrypto_scanner.py --sql /path/to/sql_files -n \"SQLAudit\""),
        
        ("6. Understanding the Results", "The tool produces three main outputs:\n- Terminal Report: A summary of findings, the overall PQC readiness score, and a top priority migration list.\n- readiness_score.json: A detailed JSON file containing the scoring breakdown and asset analysis.\n- cbom.json: A Cryptography Bill of Materials (CBOM) file.\n- index.html (Dashboard): A web-based visual dashboard generated in the dashboard/ directory."),
        
        ("7. Using the Dashboard", "To view the interactive dashboard, start a local web server from the project root directory and navigate to the dashboard:\n\nCommand:\npython3 -m http.server 8080\n\nThen, open http://localhost:8080/dashboard/index.html in your browser.")
    ]

    for title, content in sections:
        pdf.set_font("helvetica", "B", 14)
        pdf.cell(0, 10, title, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", size=11)
        pdf.multi_cell(0, 8, content)
        pdf.ln(5)

    pdf.output("pgcrypto_scanner_guide.pdf")
    print("PDF guide generated successfully!")

if __name__ == "__main__":
    main()
