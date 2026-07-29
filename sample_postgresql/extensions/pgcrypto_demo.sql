-- pgcrypto Demo: Mixed PQC Readiness SQL
-- Contains both vulnerable and safe crypto usage

-- ============================================
-- VULNERABLE: Asymmetric encryption (RSA-based)
-- pgp_pub_encrypt uses RSA - quantum-vulnerable!
-- ============================================

-- Encrypting sensitive data with public key
INSERT INTO encrypted_data (id, data_encrypted)
VALUES (
    1,
    pgp_pub_encrypt(
        'Sensitive PII data',
        dearmor('-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----')
    )
);

-- Decrypting with private key
SELECT pgp_pub_decrypt(
    data_encrypted,
    dearmor('-----BEGIN PGP PRIVATE KEY BLOCK-----\n...\n-----END PGP PRIVATE KEY BLOCK-----')
) FROM encrypted_data WHERE id = 1;


-- ============================================
-- SAFE: Symmetric encryption (AES-256)
-- pgp_sym_encrypt uses AES - quantum-safe
-- ============================================

-- Encrypting with symmetric key
INSERT INTO symmetric_encrypted (id, data_encrypted)
VALUES (
    1,
    pgp_sym_encrypt(
        'Data encrypted with AES-256',
        'my-secret-symmetric-key'
    )
);

-- Decrypting with symmetric key
SELECT pgp_sym_decrypt(
    data_encrypted,
    'my-secret-symmetric-key'
) FROM symmetric_encrypted WHERE id = 1;


-- ============================================
-- VULNERABLE: MD5 hashing
-- digest() with MD5 is quantum-vulnerable
-- ============================================

-- Creating MD5 hash (BAD - should use SHA-256)
INSERT INTO hashes (id, hash_value)
VALUES (
    1,
    digest('password_to_hash', 'md5')
);

-- VULNERABLE: HMAC with MD5
SELECT hmac('data', 'key', 'md5');


-- ============================================
-- SAFE: SHA-256 hashing
-- digest() with SHA-256 is quantum-safe
-- ============================================

-- Creating SHA-256 hash (GOOD)
INSERT INTO hashes (id, hash_value)
VALUES (
    2,
    digest('password_to_hash', 'sha256')
);

-- SAFE: HMAC with SHA-256
SELECT hmac('data', 'key', 'sha256');


-- ============================================
-- VULNERABLE: Password hashing with MD5 salt
-- gen_salt('md5') is quantum-vulnerable
-- ============================================

-- BAD: Using MD5 for password hashing
INSERT INTO users (id, username, password_hash)
VALUES (
    1,
    'admin',
    crypt('password123', gen_salt('md5'))
);

-- BAD: Using Blowfish (legacy)
INSERT INTO users (id, username, password_hash)
VALUES (
    2,
    'user2',
    crypt('password456', gen_salt('bf'))
);


-- ============================================
-- SAFE: Password hashing with SHA-256 salt
-- gen_salt('xsha256') is quantum-safe
-- ============================================

-- GOOD: Using SHA-256 for password hashing
INSERT INTO users (id, username, password_hash)
VALUES (
    3,
    'user3',
    crypt('password789', gen_salt('xsha256'))
);


-- ============================================
-- VULNERABLE: Direct RSA usage
-- RSA-2048 is quantum-vulnerable
-- ============================================

-- Creating RSA key pair (BAD)
-- This would typically be done in application code
-- SELECT pgp_pub_encrypt('data', rsa_public_key);


-- ============================================
-- SAFE: SHA-384 and SHA-512 hashing
-- ============================================

SELECT digest('data', 'sha384');
SELECT digest('data', 'sha512');
