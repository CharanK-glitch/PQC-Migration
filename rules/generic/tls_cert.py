"""TLS and certificate detection rules."""

RISK_CRITICAL = 0
RISK_HIGH = 1
RISK_SAFE = 2

TLS_CERT_RULES = [
    {
        "id": "tls1_2_only",
        "name": "TLS 1.2 Only Configuration",
        "category": "tls",
        "patterns": {
            "python": r"\b(ssl\.PROTOCOL_TLSv1_2|PROTOCOL_TLSv1_2)",
            "java": r"\b(TLSv1\.2|TLS_1_2)",
            "javascript": r"\b(secureProtocol:\s*['\"]TLSv1_2|tls\.VERSION_TLS_1_2)",
            "go": r"\b(tls\.VersionTLS12|VersionTLS12)",
            "c": r"\b(TLS1_2|TLSv1_2|SSL_CTX_set_min_proto_version.*TLS1_2)",
            "config": r"\b(ssl_protocols\s+TLSv1[\.\s]?2|ssl_min_protocol_version\s*=\s*['\"]?TLSv1\.2|MinProtocol\s*=\s*TLSv1\.2)",
            "sql": r"\b(TLSv1\.2|TLS_1_2)",
        },
        "algorithm": {
            "algorithmFamily": "TLS",
            "algorithmName": "TLS 1.2 (RSA key exchange)",
            "primitive": "certificate",
            "risk": RISK_HIGH,
            "nistQuantumSecurityLevel": 0,
            "classicalSecurityLevel": 112,
            "securityProperties": ["quantum-vulnerable", "rsa-key-exchange", "no-pfs"],
        },
        "replacement": "TLS 1.3 with PQC hybrid",
        "priority": "P1-High",
        "effort": "Medium",
    },
    {
        "id": "tls1_3_pqc",
        "name": "TLS 1.3 with PQC Support",
        "category": "tls",
        "patterns": {
            "config": r"\b(tls1_3|TLS_1_3|ssl_protocols\s+TLSv1\.3|ML_KEM|Kyber|ssl_min_protocol_version\s*=\s*['\"]?TLSv1\.3)",
            "go": r"\b(tls\.VersionTLS13|VersionTLS13)",
            "c": r"\b(TLS1_3|TLSv1_3|SSL_CTX_set_min_proto_version.*TLS1_3)",
            "java": r"\b(TLSv1\.3|TLS_1_3)",
            "python": r"\b(ssl\.PROTOCOL_TLSv1_3|PROTOCOL_TLSv1_3)",
            "javascript": r"\b(secureProtocol:\s*['\"]TLSv1_3|tls\.VERSION_TLS_1_3)",
            "sql": r"\b(TLSv1\.3|TLS_1_3)",
        },
        "algorithm": {
            "algorithmFamily": "TLS",
            "algorithmName": "TLS 1.3 (PQC-ready)",
            "primitive": "certificate",
            "risk": RISK_SAFE,
            "nistQuantumSecurityLevel": 1,
            "classicalSecurityLevel": 256,
            "securityProperties": ["quantum-ready", "modern-tls", "perfect-forward-secrecy"],
        },
        "replacement": "None needed",
        "priority": "P4-Safe",
        "effort": "None",
    },
    {
        "id": "cert_rsa_2048",
        "name": "RSA-2048 Certificate",
        "category": "certificate",
        "patterns": {
            "config": r"\b(default_bits\s*=\s*2048|RSA-2048|rsa[_\-]?2048)",
            "c": r"\b(RSA_generate_key_ex.*2048)",
            "python": r"\b(RSA\.generate\(\s*2048)",
            "java": r"\b(KeyPairGenerator\.getInstance\(['\"]RSA['\"]).*2048",
            "javascript": r"\b(generateKeyPairSync\(['\"]rsa['\"].*2048)",
            "go": r"\b(rsa\.GenerateKey.*2048)",
            "sql": r"\b(RSA-?2048)",
        },
        "algorithm": {
            "algorithmFamily": "RSA",
            "algorithmName": "RSA-2048 Certificate",
            "primitive": "certificate",
            "risk": RISK_CRITICAL,
            "nistQuantumSecurityLevel": 0,
            "classicalSecurityLevel": 112,
            "securityProperties": ["quantum-vulnerable", "shor-breakable"],
        },
        "replacement": "ML-KEM-1024 (FIPS 203) or ECDSA P-384",
        "priority": "P0-Critical",
        "effort": "High",
    },
]
