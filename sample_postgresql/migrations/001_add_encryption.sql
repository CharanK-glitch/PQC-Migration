-- Migration Example: Converting from RSA to AES encryption
-- This shows a typical pgcrypto migration pattern

-- ============================================
-- BEFORE: Using pgp_pub_encrypt (RSA-based)
-- This is quantum-vulnerable and should be migrated
-- ============================================

-- Original table with RSA encryption
CREATE TABLE IF NOT EXISTS sensitive_data_legacy (
    id SERIAL PRIMARY KEY,
    data_encrypted BYTEA,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Encrypting with RSA public key (VULNERABLE)
-- INSERT INTO sensitive_data_legacy (data_encrypted)
-- VALUES (pgp_pub_encrypt('secret data', public_key));


-- ============================================
-- AFTER: Using pgp_sym_encrypt (AES-based)
-- This is quantum-safe
-- ============================================

-- New table with AES encryption
CREATE TABLE IF NOT EXISTS sensitive_data (
    id SERIAL PRIMARY KEY,
    data_encrypted BYTEA,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Encrypting with AES symmetric key (SAFE)
-- INSERT INTO sensitive_data (data_encrypted)
-- VALUES (pgp_sym_encrypt('secret data', current_setting('app.encryption_key')));


-- ============================================
-- Migration function: Convert RSA to AES
-- ============================================

CREATE OR REPLACE FUNCTION migrate_rsa_to_aes(
    old_data BYTEA,
    rsa_private_key TEXT,
    aes_key TEXT
) RETURNS BYTEA AS $$
DECLARE
    decrypted_data TEXT;
    encrypted_data BYTEA;
BEGIN
    -- Decrypt RSA-encrypted data
    decrypted_data := pgp_pub_decrypt(old_data, dearmor(rsa_private_key));

    -- Re-encrypt with AES
    encrypted_data := pgp_sym_encrypt(decrypted_data, aes_key);

    RETURN encrypted_data;
END;
$$ LANGUAGE plpgsql;


-- ============================================
-- Migration: Update password hashing from MD5 to SHA-256
-- ============================================

-- Function to upgrade MD5 password to SHA-256
CREATE OR REPLACE FUNCTION upgrade_md5_to_sha256(
    md5_hash TEXT,
    plain_password TEXT
) RETURNS TEXT AS $$
BEGIN
    -- Verify MD5 hash matches
    IF crypt(plain_password, md5_hash) = md5_hash THEN
        -- Return new SHA-256 hash
        RETURN crypt(plain_password, gen_salt('xsha256'));
    ELSE
        -- Password doesn't match, return original
        RETURN md5_hash;
    END IF;
END;
$$ LANGUAGE plpgsql;


-- ============================================
-- View: Identify rows needing migration
-- ============================================

CREATE OR REPLACE VIEW migration_candidates AS
SELECT
    id,
    CASE
        WHEN password_hash LIKE '$1$%' THEN 'md5'
        WHEN password_hash LIKE '$2a$%' OR password_hash LIKE '$2b$%' THEN 'blowfish'
        WHEN password_hash LIKE '$5$%' THEN 'sha256'
        ELSE 'unknown'
    END as hash_type,
    created_at
FROM users
WHERE password_hash LIKE '$1$%'
   OR password_hash LIKE '$2a$%'
   OR password_hash LIKE '$2b$%';
