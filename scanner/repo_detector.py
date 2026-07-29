"""Repository structure detector - auto-detects PostgreSQL-related files."""

import os
import re
from pathlib import Path
from typing import Dict, List


class RepoDetector:
    """Detects PostgreSQL-related files and patterns in a repository."""

    # PostgreSQL config file patterns
    PG_CONFIG_PATTERNS = [
        "postgresql.conf",
        "postgresql.auto.conf",
        "pg_hba.conf",
        "pg_ident.conf",
        "postgresql.conf.*",
    ]

    # SQL file extensions
    SQL_EXTENSIONS = {".sql", ".psql", ".pgsql"}

    # Source code extensions
    SOURCE_EXTENSIONS = {
        ".py", ".java", ".js", ".ts", ".go", ".c", ".h",
        ".rb", ".php", ".rs", ".cpp", ".cc", ".cxx",
    }

    # Config file extensions
    CONFIG_EXTENSIONS = {".conf", ".cfg", ".ini", ".yaml", ".yml", ".toml", ".cnf"}

    # Dependency file patterns
    DEPENDENCY_FILES = {
        "requirements.txt", "setup.py", "pyproject.toml",
        "package.json", "go.mod", "pom.xml", "build.gradle",
        "Gemfile", "Cargo.toml", "composer.json",
    }

    def __init__(self):
        self.detection = {
            "has_pg_config": False,
            "has_pg_hba": False,
            "has_sql_files": False,
            "has_c_extensions": False,
            "has_pgcrypto_usage": False,
            "has_conn_strings": False,
            "has_ssl_config": False,
            "pg_version_hint": None,
            "sql_files": [],
            "config_files": [],
            "c_files": [],
            "source_files": [],
            "dependency_files": [],
            "total_files": 0,
        }

    def detect(self, path: str) -> Dict:
        """Walk repository and detect PostgreSQL-related structure.

        Args:
            path: Root directory to scan

        Returns:
            Detection dictionary with findings
        """
        for root, dirs, files in os.walk(path):
            # Skip hidden dirs and common non-source dirs
            dirs[:] = [
                d for d in dirs
                if not d.startswith(".")
                and d not in {"node_modules", "__pycache__", "venv", ".venv",
                              "vendor", "dist", "build", ".git", "target"}
            ]

            for filename in files:
                filepath = os.path.join(root, filename)
                rel_path = os.path.relpath(filepath, path)
                ext = Path(filename).suffix.lower()

                self.detection["total_files"] += 1

                # Check for PostgreSQL config files
                if filename in self.PG_CONFIG_PATTERNS or any(
                    re.match(p, filename) for p in self.PG_CONFIG_PATTERNS
                ):
                    self.detection["has_pg_config"] = True
                    self.detection["config_files"].append(rel_path)

                    if filename == "pg_hba.conf":
                        self.detection["has_pg_hba"] = True

                # Check for SQL files
                if ext in self.SQL_EXTENSIONS:
                    self.detection["has_sql_files"] = True
                    self.detection["sql_files"].append(rel_path)

                    # Check content for pgcrypto patterns
                    self._check_sql_content(filepath, rel_path)

                # Check for C extension files
                if ext in {".c", ".h", ".cpp", ".cc", ".cxx"}:
                    self.detection["has_c_extensions"] = True
                    self.detection["c_files"].append(rel_path)

                    # Check content for OpenSSL patterns
                    self._check_c_content(filepath, rel_path)

                # Check for source code files
                if ext in self.SOURCE_EXTENSIONS:
                    self.detection["source_files"].append(rel_path)

                    # Check for connection string patterns
                    self._check_source_content(filepath, rel_path)

                # Check for config files
                if ext in self.CONFIG_EXTENSIONS:
                    if filename not in self.detection["config_files"]:
                        self.detection["config_files"].append(rel_path)

                # Check for dependency files
                if filename in self.DEPENDENCY_FILES:
                    self.detection["dependency_files"].append(rel_path)

                # Check for SSL-related config
                if ext in self.CONFIG_EXTENSIONS or filename.startswith("ssl"):
                    self._check_ssl_content(filepath, rel_path)

        return self.detection

    def _check_sql_content(self, filepath: str, rel_path: str):
        """Check SQL file for pgcrypto usage patterns."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            pgcrypto_patterns = [
                r"pgp_sym_encrypt",
                r"pgp_pub_encrypt",
                r"pgp_pub_decrypt",
                r"pgp_sym_decrypt",
                r"\bdigest\s*\(",
                r"\bhmac\s*\(",
                r"\bcrypt\s*\(",
                r"\bgen_salt\s*\(",
            ]

            for pattern in pgcrypto_patterns:
                if re.search(pattern, content):
                    self.detection["has_pgcrypto_usage"] = True
                    break

        except (IOError, PermissionError):
            pass

    def _check_c_content(self, filepath: str, rel_path: str):
        """Check C file for OpenSSL patterns."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            openssl_patterns = [
                r"EVP_EncryptInit",
                r"EVP_DecryptInit",
                r"EVP_DigestInit",
                r"RSA_generate_key",
                r"SSL_CTX_new",
                r"TLS_server_method",
                r"EVP_PKEY_keygen",
            ]

            for pattern in openssl_patterns:
                if re.search(pattern, content):
                    self.detection["has_c_extensions"] = True
                    break

        except (IOError, PermissionError):
            pass

    def _check_source_content(self, filepath: str, rel_path: str):
        """Check source file for connection string patterns."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            conn_patterns = [
                r"sslmode\s*=",
                r"postgresql://",
                r"jdbc:postgresql",
                r"sslcert\s*=",
                r"sslkey\s*=",
                r"sslrootcert\s*=",
                r"scram-sha-256",
            ]

            for pattern in conn_patterns:
                if re.search(pattern, content):
                    self.detection["has_conn_strings"] = True
                    break

        except (IOError, PermissionError):
            pass

    def _check_ssl_content(self, filepath: str, rel_path: str):
        """Check config file for SSL-related patterns."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            ssl_patterns = [
                r"ssl\s*=\s*(on|off)",
                r"ssl_min_protocol_version",
                r"ssl_ciphers",
                r"ssl_cert_file",
                r"ssl_key_file",
                r"ssl_ca_file",
            ]

            for pattern in ssl_patterns:
                if re.search(pattern, content):
                    self.detection["has_ssl_config"] = True
                    break

        except (IOError, PermissionError):
            pass

    def get_scan_summary(self) -> str:
        """Return a human-readable summary of detection results."""
        lines = ["Repository Structure Analysis:"]

        if self.detection["has_pg_config"]:
            lines.append(f"  [+] PostgreSQL config files found: {len(self.detection['config_files'])}")
        if self.detection["has_pg_hba"]:
            lines.append(f"  [+] pg_hba.conf found")
        if self.detection["has_sql_files"]:
            lines.append(f"  [+] SQL files found: {len(self.detection['sql_files'])}")
        if self.detection["has_pgcrypto_usage"]:
            lines.append(f"  [+] pgcrypto usage detected")
        if self.detection["has_c_extensions"]:
            lines.append(f"  [+] C extension files found: {len(self.detection['c_files'])}")
        if self.detection["has_conn_strings"]:
            lines.append(f"  [+] Connection string patterns detected")
        if self.detection["has_ssl_config"]:
            lines.append(f"  [+] SSL configuration detected")

        lines.append(f"\n  Total files: {self.detection['total_files']}")
        lines.append(f"  Source files: {len(self.detection['source_files'])}")
        lines.append(f"  SQL files: {len(self.detection['sql_files'])}")
        lines.append(f"  Config files: {len(self.detection['config_files'])}")

        return "\n".join(lines)
