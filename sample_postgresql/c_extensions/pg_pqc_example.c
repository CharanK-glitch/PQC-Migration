/*
 * Example PostgreSQL C Extension with Crypto Operations
 * This demonstrates vulnerable crypto patterns in PG extensions
 */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/hmac.h>

/* ============================================
 * VULNERABLE: Direct MD5 usage
 * MD5 is quantum-vulnerable and should not be used
 * ============================================ */
void compute_md5_hash(const char* data, char* output) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_md5();  /* VULNERABLE: MD5 */
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, data, strlen(data));
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);

    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(&output[i*2], "%02x", hash[i]);
    }
}

/* ============================================
 * SAFE: SHA-256 hashing
 * SHA-256 is quantum-safe (128-bit effective security)
 * ============================================ */
void compute_sha256_hash(const char* data, char* output) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();  /* SAFE: SHA-256 */
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, data, strlen(data));
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);

    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(&output[i*2], "%02x", hash[i]);
    }
}

/* ============================================
 * VULNERABLE: RSA key generation
 * RSA-2048 is quantum-vulnerable (Shor's algorithm)
 * ============================================ */
RSA* generate_rsa_key(int bits) {
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4);
    RSA_generate_key_ex(rsa, bits, bn, NULL);  /* VULNERABLE: RSA */
    BN_free(bn);
    return rsa;
}

/* ============================================
 * VULNERABLE: ECDH key exchange
 * ECDH P-256 is quantum-vulnerable
 * ============================================ */
EC_KEY* generate_ecdh_key() {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256r1);  /* VULNERABLE: P-256 */
    EC_KEY_generate_key(key);
    return key;
}

/* ============================================
 * SAFE: HMAC-SHA256
 * HMAC with SHA-256 is quantum-safe
 * ============================================ */
void compute_hmac_sha256(const char* data, const char* key,
                         unsigned char* output, unsigned int* output_len) {
    HMAC(EVP_sha256(),  /* SAFE: SHA-256 */
         key, strlen(key),
         (unsigned char*)data, strlen(data),
         output, output_len);
}

/* ============================================
 * SAFE: AES-256-GCM encryption
 * AES-256 is quantum-safe
 * ============================================ */
int encrypt_aes256_gcm(const unsigned char *plaintext, int plaintext_len,
                       const unsigned char *key, const unsigned char *iv,
                       unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);  /* SAFE: AES-256-GCM */
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

/* ============================================
 * VULNERABLE: Direct MD5 HMAC
 * HMAC-MD5 is quantum-vulnerable
 * ============================================ */
void compute_hmac_md5(const char* data, const char* key,
                      unsigned char* output, unsigned int* output_len) {
    HMAC(EVP_md5(),  /* VULNERABLE: MD5 */
         key, strlen(key),
         (unsigned char*)data, strlen(data),
         output, output_len);
}

/* PG extension entry point */
void _PG_init(void) {
    fprintf(stderr, "pg_pqc_example: Extension loaded\n");
    fprintf(stderr, "  - Uses SHA-256 (quantum-safe)\n");
    fprintf(stderr, "  - Uses AES-256-GCM (quantum-safe)\n");
    fprintf(stderr, "  - WARNING: Contains RSA and ECDH (quantum-vulnerable)\n");
}
