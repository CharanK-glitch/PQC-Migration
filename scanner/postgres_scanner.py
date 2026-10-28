"""PostgreSQL-specific crypto scanner - scans for PG configs, pgcrypto, connection strings."""

import os
import re
from pathlib import Path
from typing import List, Dict, Optional

# Import all PostgreSQL-specific rules
from rules.postgres.ssl_config import PG_SSL_RULES
from rules.postgres.pg_hba import PG_HBA_RULES
from rules.postgres.pgcrypto_sql import PGCRYPTO_SQL_RULES
from rules.postgres.connection_strings import PG_CONN_STRING_RULES
from rules.postgres.c_extensions import PG_C_EXT_RULES
from rules.postgres.wal_backup import PG_WAL_BACKUP_RULES
from rules.postgres.certificates import PG_CERT_RULES

# Combine all PostgreSQL rules
ALL_PG_RULES = (
    PG_SSL_RULES + PG_HBA_RULES + PGCRYPTO_SQL_RULES +
    PG_CONN_STRING_RULES + PG_C_EXT_RULES + PG_WAL_BACKUP_RULES +
    PG_CERT_RULES
)

# File extension to language mapping (PostgreSQL-focused)
PG_EXTENSION_MAP = {
    ".py": "python", ".pyw": "python",
    ".java": "java", ".kt": "java",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "javascript", ".tsx": "javascript", ".jsx": "javascript",
    ".go": "go",
    ".c": "c", ".h": "c", ".cpp": "c", ".cc": "c", ".cxx": "c", ".hpp": "c",
    ".rs": "rust",
    ".php": "php",
    ".rb": "python",
    ".conf": "config", ".cfg": "config", ".ini": "config",
    ".yaml": "config", ".yml": "config", ".toml": "config",
    ".cnf": "config", ".xml": "config", ".json": "config",
    ".sql": "sql", ".psql": "sql", ".pgsql": "sql",
    ".sh": "config", ".bash": "config",
}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "env",
    "vendor", ".next", "dist", "build", ".cache", ".idea", ".vscode",
    "target", "bin", "obj", ".gradle", ".m2", "Pods",
}


class PostgresScanner:
    """Scan for PostgreSQL-specific cryptographic patterns."""

    def __init__(self, rules: Optional[List[Dict]] = None):
        self.rules = rules or ALL_PG_RULES

    def _get_file_category(self, filename: str) -> str:
        """Determine file category for rule matching."""
        basename = os.path.basename(filename)

        if basename in ("postgresql.conf", "postgresql.auto.conf"):
            return "pg_config"
        elif basename == "pg_hba.conf":
            return "pg_hba"
        elif basename == "pg_ident.conf":
            return "pg_ident"
        elif basename.endswith((".crt", ".pem", ".key")):
            return "certificate"
        elif basename.endswith((".c", ".h")):
            return "c_source"
        elif basename.endswith((".sql", ".psql", ".pgsql")):
            return "sql"
        elif basename.endswith((".sh", ".bash")):
            return "shell"
        else:
            return "other"

    def _matches_file_pattern(self, filename: str, file_patterns: List[str]) -> bool:
        """Check if filename matches any of the rule's file patterns."""
        basename = os.path.basename(filename)

        for pattern in file_patterns:
            if pattern.startswith("*"):
                if basename.endswith(pattern[1:]):
                    return True
            elif basename == pattern:
                return True

        return False

    def scan_file(self, filepath: str) -> List[Dict]:
        """Scan a single file for PostgreSQL crypto patterns.

        Args:
            filepath: Path to the file to scan

        Returns:
            List of finding dictionaries
        """
        filename = os.path.basename(filepath)
        ext = Path(filepath).suffix.lower()
        lang = PG_EXTENSION_MAP.get(ext)

        if not lang:
            return []

        findings = []

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.split("\n")
        except (IOError, PermissionError):
            return []

        for rule in self.rules:
            # Check if rule applies to this file type
            file_patterns = rule.get("file_patterns", [])
            if file_patterns and not self._matches_file_pattern(filename, file_patterns):
                continue

            # Get language-specific pattern
            pattern = rule["patterns"].get(lang)
            if not pattern:
                continue

            # Scan each line
            for idx, line in enumerate(lines):
                if re.search(pattern, line, re.IGNORECASE):
                    finding = {
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
                        "source": "postgresql",
                    }

                    # Add check function result if available
                    if "check_func" in rule:
                        finding["check_func"] = rule["check_func"]
                        finding["check_result"] = self._run_check(rule, line, content)

                    findings.append(finding)

            # Also run config-specific checks
            if "check_func" in rule:
                check_result = self._run_config_check(rule, content, filepath)
                if check_result:
                    findings.append(check_result)

        return findings

    def _run_check(self, rule: Dict, line: str, content: str) -> Optional[Dict]:
        """Run a rule's check function against a matched line."""
        check_func = rule.get("check_func")

        if check_func == "check_ssl_enabled":
            return self._check_ssl_enabled(line)
        elif check_func == "check_ssl_min_protocol":
            return self._check_ssl_min_protocol(line)
        elif check_func == "check_ssl_ciphers":
            return self._check_ssl_ciphers(line)
        elif check_func == "check_ssl_cert_configured":
            return {"status": "safe", "detail": "SSL certificate is configured"} if re.search(r"=\s*['\"]?.+['\"]?", line) else {"status": "vulnerable", "detail": "SSL certificate not configured"}
        elif check_func == "check_ssl_key_configured":
            return {"status": "safe", "detail": "SSL key is configured"} if re.search(r"=\s*['\"]?.+['\"]?", line) else {"status": "vulnerable", "detail": "SSL key not configured"}
        elif check_func == "check_ssl_ca_configured":
            return {"status": "safe", "detail": "SSL CA is configured"} if re.search(r"=\s*['\"]?.+['\"]?", line) else {"status": "vulnerable", "detail": "SSL CA not configured"}
        elif check_func == "check_ssl_prefer_server_ciphers":
            return {"status": "safe", "detail": "Server cipher preference enabled"} if re.search(r"=\s*(on|1)", line) else {"status": "warning", "detail": "Server cipher preference disabled"}
        elif check_func == "check_ssl_ecdh_curve":
            match = re.search(r"=\s*['\"](.+?)['\"]", line)
            if match:
                curve = match.group(1)
                if "secp256k1" in curve or "prime256v1" in curve:
                    return {"status": "vulnerable", "detail": f"ECDSA curve {curve} is quantum-vulnerable"}
                return {"status": "safe", "detail": f"ECDH curve: {curve}"}
            return None
        elif check_func == "check_ssl_dh_params":
            return {"status": "safe", "detail": "DH parameters configured"} if re.search(r"=\s*['\"]?.+['\"]?", line) else {"status": "vulnerable", "detail": "DH parameters not configured"}
        elif check_func == "check_ssl_max_protocol":
            match = re.search(r"=\s*['\"]?(\w+)['\"]?", line)
            if match:
                version = match.group(1)
                if "1.3" in version:
                    return {"status": "safe", "detail": f"Maximum TLS version: {version}"}
                return {"status": "warning", "detail": f"Consider setting max TLS version to 1.3: {version}"}
            return None
        elif check_func == "check_hba_md5":
            return {"status": "vulnerable", "detail": "MD5 auth is quantum-vulnerable"}
        elif check_func == "check_hba_password":
            return {"status": "vulnerable", "detail": "Password auth transmits credentials in plaintext"}
        elif check_func == "check_hba_scram":
            return {"status": "safe", "detail": "SCRAM-SHA-256 is quantum-safe"}
        elif check_func == "check_hba_cert":
            return {"status": "safe", "detail": "Certificate-based auth is quantum-safe"}
        elif check_func == "check_hba_ldap":
            return {"status": "warning", "detail": "LDAP auth - depends on LDAP server configuration"}
        elif check_func == "check_hba_gss":
            return {"status": "warning", "detail": "GSSAPI auth - depends on Kerberos configuration"}
        elif check_func == "check_hba_ident":
            return {"status": "vulnerable", "detail": "Ident auth is insecure and deprecated"}
        elif check_func == "check_password_encryption":
            return self._check_password_encryption(line)
        elif check_func == "check_pgcrypto_pub":
            return {"status": "vulnerable", "detail": "pgp_pub_encrypt uses RSA - quantum-vulnerable"}
        elif check_func == "check_pgcrypto_sym":
            return {"status": "safe", "detail": "pgp_sym_encrypt uses AES - quantum-safe"}
        elif check_func == "check_pgcrypto_pub_decrypt":
            return {"status": "vulnerable", "detail": "pgp_pub_decrypt uses RSA - quantum-vulnerable"}
        elif check_func == "check_pgcrypto_sym_decrypt":
            return {"status": "safe", "detail": "pgp_sym_decrypt uses AES - quantum-safe"}
        elif check_func == "check_pgcrypto_sym_bytea":
            return {"status": "safe", "detail": "pgp_sym_encrypt_bytea uses AES - quantum-safe"}
        elif check_func == "check_digest_md5":
            return {"status": "vulnerable", "detail": "MD5 digest is quantum-vulnerable"}
        elif check_func == "check_digest_sha1":
            return {"status": "vulnerable", "detail": "SHA-1 digest is quantum-vulnerable"}
        elif check_func == "check_digest_sha256":
            return {"status": "safe", "detail": "SHA-256 digest is quantum-safe"}
        elif check_func == "check_hmac_sha256":
            return {"status": "safe", "detail": "HMAC-SHA256 is quantum-safe"}
        elif check_func == "check_hmac_md5":
            return {"status": "vulnerable", "detail": "HMAC-MD5 is quantum-vulnerable"}
        elif check_func == "check_gen_salt_bf":
            return {"status": "safe", "detail": "gen_salt with bcrypt is quantum-safe"}
        elif check_func == "check_gen_salt_md5":
            return {"status": "vulnerable", "detail": "gen_salt with md5 is quantum-vulnerable"}
        elif check_func == "check_gen_salt_xsha256":
            return {"status": "safe", "detail": "gen_salt with scram-sha-256 is quantum-safe"}
        elif check_func == "check_wal_level":
            match = re.search(r"=\s*(\w+)", line)
            if match:
                level = match.group(1)
                if level in ("logical", "replica"):
                    return {"status": "safe", "detail": f"WAL level: {level}"}
                return {"status": "warning", "detail": f"WAL level {level} - consider logical for PITR"}
            return None
        elif check_func == "check_wal_encryption":
            return {"status": "safe", "detail": "WAL encryption is enabled"} if re.search(r"=\s*(on|1)", line) else {"status": "vulnerable", "detail": "WAL encryption is disabled"}
        elif check_func == "check_tablespace_encrypt":
            return {"status": "safe", "detail": "Tablespace encryption is enabled"} if re.search(r"=\s*(on|1)", line) else {"status": "vulnerable", "detail": "Tablespace encryption is disabled"}

        return None

    def _run_config_check(self, rule: Dict, content: str, filepath: str) -> Optional[Dict]:
        """Run a rule's check function against full file content."""
        check_func = rule.get("check_func")

        if check_func == "check_ssl_min_protocol":
            for line in content.split("\n"):
                if re.search(r"ssl_min_protocol_version", line):
                    return self._check_ssl_min_protocol(line)

        elif check_func == "check_password_encryption":
            for line in content.split("\n"):
                if re.search(r"password_encryption", line):
                    return self._check_password_encryption(line)

        return None

    def _check_ssl_enabled(self, line: str) -> Dict:
        """Check if SSL is enabled."""
        if re.search(r"=\s*(on|1)", line):
            return {"status": "safe", "detail": "SSL is enabled"}
        return {"status": "vulnerable", "detail": "SSL is disabled"}

    def _check_ssl_min_protocol(self, line: str) -> Dict:
        """Check minimum TLS protocol version."""
        match = re.search(r"=\s*['\"]?(\w+)['\"]?", line)
        if match:
            version = match.group(1)
            if "1.3" in version:
                return {"status": "safe", "detail": f"Minimum TLS version: {version}"}
            elif "1.2" in version:
                return {"status": "warning", "detail": f"TLS 1.2 minimum - consider upgrading to 1.3: {version}"}
            else:
                return {"status": "vulnerable", "detail": f"Outdated TLS minimum: {version}"}
        return None

    def _check_ssl_ciphers(self, line: str) -> Dict:
        """Check SSL cipher configuration."""
        match = re.search(r"=\s*['\"](.+?)['\"]", line)
        if match:
            ciphers = match.group(1)
            vulnerable = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT"]
            found_vuln = [v for v in vulnerable if v in ciphers.upper()]
            if found_vuln:
                return {"status": "vulnerable", "detail": f"Weak ciphers found: {', '.join(found_vuln)}"}
            return {"status": "safe", "detail": "Cipher configuration appears secure"}
        return None

    def _check_password_encryption(self, line: str) -> Dict:
        """Check password encryption setting."""
        if "scram-sha-256" in line.lower():
            return {"status": "safe", "detail": "Using SCRAM-SHA-256"}
        elif "md5" in line.lower():
            return {"status": "vulnerable", "detail": "Using MD5 - upgrade to scram-sha-256"}
        return None

    def scan_directory(self, directory: str, exclude_dirs: Optional[set] = None) -> tuple:
        """Recursively scan a directory for PostgreSQL crypto patterns.

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

                if ext in PG_EXTENSION_MAP:
                    files_scanned += 1
                    findings = self.scan_file(filepath)
                    all_findings.extend(findings)

        return all_findings, files_scanned

    def scan_config_file(self, filepath: str) -> List[Dict]:
        """Scan a PostgreSQL config file with full context awareness.

        Args:
            filepath: Path to postgresql.conf or pg_hba.conf

        Returns:
            List of findings with config-specific analysis
        """
        findings = []

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except (IOError, PermissionError):
            return []

        filename = os.path.basename(filepath)

        if filename in ("postgresql.conf", "postgresql.auto.conf"):
            findings.extend(self._analyze_postgresql_conf(content, filepath))
        elif filename == "pg_hba.conf":
            findings.extend(self._analyze_pg_hba_conf(content, filepath))

        return findings

    def _analyze_postgresql_conf(self, content: str, filepath: str) -> List[Dict]:
        """Analyze postgresql.conf for crypto settings."""
        findings = []

        ssl_patterns = [
            (r"^\s*ssl\s*=\s*(\w+)", "pg_ssl_enabled"),
            (r"^\s*ssl_min_protocol_version\s*=\s*['\"]?(\w+)['\"]?", "pg_ssl_min_protocol"),
            (r"^\s*ssl_ciphers\s*=\s*['\"](.+?)['\"]", "pg_ssl_ciphers"),
            (r"^\s*ssl_cert_file\s*=\s*['\"](.+?)['\"]", "pg_ssl_cert_file"),
            (r"^\s*ssl_key_file\s*=\s*['\"](.+?)['\"]", "pg_ssl_key_file"),
            (r"^\s*ssl_ca_file\s*=\s*['\"](.+?)['\"]", "pg_ssl_ca_file"),
            (r"^\s*ssl_prefer_server_ciphers\s*=\s*(\w+)", "pg_ssl_prefer_server_ciphers"),
            (r"^\s*ssl_ecdh_curve\s*=\s*['\"](.+?)['\"]", "pg_ssl_ecdh_curve"),
            (r"^\s*password_encryption\s*=\s*(\w+)", "pg_password_encryption"),
            (r"^\s*wal_level\s*=\s*(\w+)", "pg_wal_level"),
        ]

        lines = content.split("\n")
        for line in lines:
            for pattern, rule_id in ssl_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    # Find the matching rule
                    rule = next((r for r in ALL_PG_RULES if r["id"] == rule_id), None)
                    if rule:
                        findings.append({
                            "rule_id": rule["id"],
                            "rule_name": rule["name"],
                            "category": rule["category"],
                            "file": filepath,
                            "line_number": 0,
                            "content": line.strip(),
                            "language": "config",
                            "algorithm": rule["algorithm"],
                            "replacement": rule["replacement"],
                            "priority": rule["priority"],
                            "effort": rule["effort"],
                            "source": "postgresql",
                        })

        return findings

    def _analyze_pg_hba_conf(self, content: str, filepath: str) -> List[Dict]:
        """Analyze pg_hba.conf for authentication methods."""
        findings = []

        auth_patterns = [
            (r"^\s*(host|local)\s+.+\s+md5\s*$", "pg_hba_md5"),
            (r"^\s*(host|local)\s+.+\s+password\s*$", "pg_hba_password"),
            (r"^\s*(host|local)\s+.+\s+scram-sha-256\s*$", "pg_hba_scram_sha256"),
            (r"^\s*(hostssl|host)\s+.+\s+cert\s*$", "pg_hba_cert"),
            (r"^\s*(host|local)\s+.+\s+ldap\s*$", "pg_hba_ldap"),
            (r"^\s*(host|local)\s+.+\s+gss\s*$", "pg_hba_gss"),
            (r"^\s*(host|local)\s+.+\s+ident\s*$", "pg_hba_ident"),
        ]

        lines = content.split("\n")
        for idx, line in enumerate(lines):
            # Skip comments and empty lines
            if line.strip().startswith("#") or not line.strip():
                continue

            for pattern, rule_id in auth_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    rule = next((r for r in ALL_PG_RULES if r["id"] == rule_id), None)
                    if rule:
                        findings.append({
                            "rule_id": rule["id"],
                            "rule_name": rule["name"],
                            "category": rule["category"],
                            "file": filepath,
                            "line_number": idx + 1,
                            "content": line.strip(),
                            "language": "config",
                            "algorithm": rule["algorithm"],
                            "replacement": rule["replacement"],
                            "priority": rule["priority"],
                            "effort": rule["effort"],
                            "source": "postgresql",
                        })

        return findings
