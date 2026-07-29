"""Generic cryptographic algorithm scanner - scans all languages for crypto patterns."""

import os
import re
from pathlib import Path
from typing import List, Dict, Optional

# Import all generic rules
from rules.generic.hashes import HASH_RULES
from rules.generic.ciphers import CIPHER_RULES
from rules.generic.asymmetric import ASYMMETRIC_RULES
from rules.generic.kdf import KDF_RULES
from rules.generic.mac import MAC_RULES
from rules.generic.pqc import PQC_RULES
from rules.generic.tls_cert import TLS_CERT_RULES

# Combine all generic rules
ALL_GENERIC_RULES = (
    HASH_RULES + CIPHER_RULES + ASYMMETRIC_RULES +
    KDF_RULES + MAC_RULES + PQC_RULES + TLS_CERT_RULES
)

# File extension to language mapping
EXTENSION_MAP = {
    ".py": "python", ".pyw": "python",
    ".java": "java", ".kt": "java",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "javascript", ".tsx": "javascript", ".jsx": "javascript",
    ".go": "go",
    ".c": "c", ".h": "c", ".cpp": "c", ".cc": "c", ".cxx": "c", ".hpp": "c",
    ".rs": "c",  # Rust uses similar crypto patterns
    ".rb": "python",  # Ruby similar to Python patterns
    ".conf": "config", ".cfg": "config", ".ini": "config",
    ".yaml": "config", ".yml": "config", ".toml": "config",
    ".cnf": "config", ".xml": "config", ".json": "config",
    ".sql": "sql", ".psql": "sql", ".pgsql": "sql",
}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "env",
    "vendor", ".next", "dist", "build", ".cache", ".idea", ".vscode",
    "target", "bin", "obj", ".gradle", ".m2", "Pods",
}


class GenericScanner:
    """Scan source code files for cryptographic algorithm usage."""

    def __init__(self, rules: Optional[List[Dict]] = None):
        self.rules = rules or ALL_GENERIC_RULES

    def scan_file(self, filepath: str) -> List[Dict]:
        """Scan a single file for crypto patterns.

        Args:
            filepath: Path to the file to scan

        Returns:
            List of finding dictionaries
        """
        ext = Path(filepath).suffix.lower()
        lang = EXTENSION_MAP.get(ext)
        if not lang:
            return []

        findings = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except (IOError, PermissionError):
            return []

        for rule in self.rules:
            pattern = rule["patterns"].get(lang)
            if not pattern:
                continue

            for idx, line in enumerate(lines):
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "category": rule["category"],
                        "file": filepath,
                        "line_number": idx + 1,
                        "content": line.strip(),
                        "language": lang,
                        "algorithm": rule["algorithm"],
                        "replacement": rule["replacement"],
                        "priority": rule["priority"],
                        "effort": rule["effort"],
                        "source": "generic",
                    })

        return findings

    def scan_directory(self, directory: str, exclude_dirs: Optional[set] = None) -> tuple:
        """Recursively scan a directory for crypto patterns.

        Args:
            directory: Root directory to scan
            exclude_dirs: Directories to skip

        Returns:
            Tuple of (findings list, files scanned count)
        """
        if exclude_dirs is None:
            exclude_dirs = SKIP_DIRS

        all_findings = []
        files_scanned = 0

        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]

            for filename in files:
                filepath = os.path.join(root, filename)
                ext = Path(filename).suffix.lower()

                if ext in EXTENSION_MAP:
                    files_scanned += 1
                    findings = self.scan_file(filepath)
                    all_findings.extend(findings)

        return all_findings, files_scanned

    def scan_file_content(self, content: str, filename: str, lang: str) -> List[Dict]:
        """Scan file content directly (for in-memory scanning).

        Args:
            content: File content as string
            filename: Filename for context
            lang: Language identifier

        Returns:
            List of finding dictionaries
        """
        findings = []
        lines = content.split("\n")

        for rule in self.rules:
            pattern = rule["patterns"].get(lang)
            if not pattern:
                continue

            for idx, line in enumerate(lines):
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "category": rule["category"],
                        "file": filename,
                        "line_number": idx + 1,
                        "content": line.strip(),
                        "language": lang,
                        "algorithm": rule["algorithm"],
                        "replacement": rule["replacement"],
                        "priority": rule["priority"],
                        "effort": rule["effort"],
                        "source": "generic",
                    })

        return findings
