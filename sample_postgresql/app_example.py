#!/usr/bin/env python3
"""
Sample Python backend with PostgreSQL connection patterns.
Demonstrates vulnerable and safe crypto usage for scanning.
"""

import hashlib
import hmac
import os
from datetime import datetime

# PostgreSQL connection patterns
# VULNERABLE: sslmode=disable
# DATABASE_URL = "postgresql://user:pass@localhost/db?sslmode=disable"

# VULNERABLE: sslmode=allow
# DATABASE_URL = "postgresql://user:pass@localhost/db?sslmode=allow"

# VULNERABLE: sslmode=prefer
# DATABASE_URL = "postgresql://user:pass@localhost/db?sslmode=prefer"

# SAFE: sslmode=verify-full
DATABASE_URL = "postgresql://user:pass@localhost/db?sslmode=verify-full&sslcert=/path/client.crt&sslkey=/path/client.key&sslrootcert=/path/ca.crt"


def connect_postgres():
    """Connect to PostgreSQL with various sslmode settings."""
    import psycopg2

    # VULNERABLE: sslmode=disable (no encryption)
    # conn = psycopg2.connect("postgresql://localhost/db", sslmode="disable")

    # VULNERABLE: sslmode=allow (optional SSL)
    # conn = psycopg2.connect("postgresql://localhost/db", sslmode="allow")

    # VULNERABLE: sslmode=require (no cert verification)
    # conn = psycopg2.connect("postgresql://localhost/db", sslmode="require")

    # SAFE: sslmode=verify-full
    conn = psycopg2.connect(
        "postgresql://localhost/db",
        sslmode="verify-full",
        sslcert="/path/to/client.crt",
        sslkey="/path/to/client.key",
        sslrootcert="/path/to/ca.crt"
    )
    return conn


def hash_password_md5(password: str) -> str:
    """VULNERABLE: MD5 password hashing."""
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_sha256(password: str) -> str:
    """SAFE: SHA-256 password hashing."""
    return hashlib.sha256(password.encode()).hexdigest()


def verify_webhook(payload: bytes, signature: str, secret: str) -> bool:
    """SAFE: HMAC-SHA256 for webhook verification."""
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def encrypt_data_aes(data: str, key: bytes) -> bytes:
    """SAFE: AES-256-GCM encryption."""
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return cipher.nonce + tag + ciphertext


# PQC example (if liboqs is installed)
def pqc_key_exchange():
    """SAFE: Post-quantum key exchange using ML-KEM."""
    try:
        import oqs
        kem = oqs.KeyEncapsulation("ML-KEM-768")
        public_key = kem.generate_keypair()
        ciphertext, shared_secret = kem.encap_secret(public_key)
        return shared_secret
    except ImportError:
        return None
