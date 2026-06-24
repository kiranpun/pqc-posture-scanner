# Vulnerable library registry
# Covers: Python · Node/JS · Java/Maven · Go · Rust · Ruby · PHP · .NET

VULNERABLE_LIBRARIES = {

    # ── Python ────────────────────────────────────────────────────────────────
    "python-rsa": {
        "risk":      "CRITICAL",
        "ecosystem": "Python",
        "reason":    "Pure RSA library — entirely quantum-vulnerable",
        "fix":       "oqs-python (Open Quantum Safe)",
    },
    "pycrypto": {
        "risk":      "CRITICAL",
        "ecosystem": "Python",
        "reason":    "Abandoned, unpatched, quantum-vulnerable",
        "fix":       "oqs-python",
    },
    "pycryptodome": {
        "risk":      "HIGH",
        "ecosystem": "Python",
        "reason":    "Provides RSA, ECC, DES, MD5 — depends on usage",
        "fix":       "oqs-python",
    },
    "cryptography": {
        "risk":      "MEDIUM",
        "ecosystem": "Python",
        "reason":    "Classical APIs still present — must audit usage",
        "fix":       "cryptography>=42 with explicit PQC primitives",
    },
    "paramiko": {
        "risk":      "HIGH",
        "ecosystem": "Python",
        "reason":    "SSH with RSA/ECDSA host keys by default",
        "fix":       "Monitor for PQC SSH RFC adoption",
    },
    "pyopenssl": {
        "risk":      "HIGH",
        "ecosystem": "Python",
        "reason":    "Wraps classical OpenSSL — cipher suite config critical",
        "fix":       "Enforce TLS 1.3 + PQC cipher suites",
    },
    "python-ecdsa": {
        "risk":      "CRITICAL",
        "ecosystem": "Python",
        "reason":    "Pure ECDSA library — entirely quantum-vulnerable",
        "fix":       "oqs-python",
    },
    "pyjwt": {
        "risk":      "HIGH",
        "ecosystem": "Python",
        "reason":    "RS256/ES256 JWT signing is quantum-vulnerable",
        "fix":       "Use HS384+ short-term; watch PQC JWT standards",
    },
    "python-jwt": {
        "risk":      "HIGH",
        "ecosystem": "Python",
        "reason":    "RS256/ES256 JWT signing is quantum-vulnerable",
        "fix":       "Use HS384+ short-term",
    },
    "m2crypto": {
        "risk":      "HIGH",
        "ecosystem": "Python",
        "reason":    "Wraps OpenSSL classical crypto",
        "fix":       "oqs-python",
    },
    "tlslite-ng": {
        "risk":      "HIGH",
        "ecosystem": "Python",
        "reason":    "TLS implementation with classical algorithms",
        "fix":       "Enforce TLS 1.3 configuration",
    },

    # ── JavaScript / Node ─────────────────────────────────────────────────────
    "node-rsa": {
        "risk":      "CRITICAL",
        "ecosystem": "Node",
        "reason":    "Pure RSA JS library — entirely quantum-vulnerable",
        "fix":       "@noble/post-quantum",
    },
    "elliptic": {
        "risk":      "CRITICAL",
        "ecosystem": "Node",
        "reason":    "ECDSA/ECDH JS library — entirely quantum-vulnerable",
        "fix":       "@noble/post-quantum",
    },
    "jsonwebtoken": {
        "risk":      "HIGH",
        "ecosystem": "Node",
        "reason":    "RS256/ES256 JWT signing is quantum-vulnerable",
        "fix":       "HS384+ short-term; watch PQC JWT standards",
    },
    "crypto-js": {
        "risk":      "HIGH",
        "ecosystem": "Node",
        "reason":    "Provides MD5, SHA-1, DES, RC4",
        "fix":       "Web Crypto API with AES-256-GCM",
    },
    "forge": {
        "risk":      "HIGH",
        "ecosystem": "Node",
        "reason":    "Full classical crypto stack",
        "fix":       "@noble/post-quantum for PQC primitives",
    },
    "jsrsasign": {
        "risk":      "CRITICAL",
        "ecosystem": "Node",
        "reason":    "RSA/ECDSA JS library — entirely quantum-vulnerable",
        "fix":       "@noble/post-quantum",
    },
    "keypair": {
        "risk":      "CRITICAL",
        "ecosystem": "Node",
        "reason":    "RSA key pair generation — quantum-vulnerable",
        "fix":       "@noble/post-quantum",
    },
    "bcrypt": {
        "risk":      "MEDIUM",
        "ecosystem": "Node",
        "reason":    "Uses Blowfish cipher internally — weakened by Grover",
        "fix":       "Argon2 or scrypt for password hashing",
    },
    "md5": {
        "risk":      "CRITICAL",
        "ecosystem": "Node",
        "reason":    "MD5 is broken classically and weak post-quantum",
        "fix":       "SHA-384 or SHA-512",
    },
    "sha1": {
        "risk":      "CRITICAL",
        "ecosystem": "Node",
        "reason":    "SHA-1 is broken (SHAttered) and weak post-quantum",
        "fix":       "SHA-384 or SHA-512",
    },
    "des": {
        "risk":      "CRITICAL",
        "ecosystem": "Node",
        "reason":    "DES is broken — 56-bit key, trivially brute forced",
        "fix":       "AES-256-GCM",
    },
    "triple-des": {
        "risk":      "CRITICAL",
        "ecosystem": "Node",
        "reason":    "3DES is below post-quantum requirements",
        "fix":       "AES-256-GCM",
    },

    # ── Java / Maven ──────────────────────────────────────────────────────────
    "bcprov-jdk15on": {
        "risk":      "HIGH",
        "ecosystem": "Java",
        "reason":    "Bouncy Castle — classical crypto APIs present, audit usage",
        "fix":       "Bouncy Castle PQC module (bcpqc-jdk15on)",
    },
    "bcprov-jdk18on": {
        "risk":      "HIGH",
        "ecosystem": "Java",
        "reason":    "Bouncy Castle — classical crypto APIs present, audit usage",
        "fix":       "Bouncy Castle PQC module (bcpqc-jdk18on)",
    },
    "bcpkix-jdk15on": {
        "risk":      "HIGH",
        "ecosystem": "Java",
        "reason":    "Bouncy Castle PKIX — RSA/ECC certificate handling",
        "fix":       "Bouncy Castle PQC module",
    },
    "nimbus-jose-jwt": {
        "risk":      "HIGH",
        "ecosystem": "Java",
        "reason":    "JWT with RS256/ES256 support — quantum-vulnerable signing",
        "fix":       "Use HS384+ or watch for PQC JWT support",
    },
    "java-jwt": {
        "risk":      "HIGH",
        "ecosystem": "Java",
        "reason":    "JWT with RSA/EC signing — quantum-vulnerable",
        "fix":       "Use HS384+ short-term",
    },
    "spring-security-crypto": {
        "risk":      "MEDIUM",
        "ecosystem": "Java",
        "reason":    "Spring crypto — classical algorithms, audit configuration",
        "fix":       "Audit cipher suite configuration",
    },

    # ── Go ────────────────────────────────────────────────────────────────────
    "golang.org/x/crypto": {
        "risk":      "MEDIUM",
        "ecosystem": "Go",
        "reason":    "Contains classical crypto — depends on which packages imported",
        "fix":       "Audit imports: avoid crypto/rsa, crypto/ecdsa, crypto/dh",
    },
    "github.com/dgrijalva/jwt-go": {
        "risk":      "HIGH",
        "ecosystem": "Go",
        "reason":    "Deprecated JWT library with RSA/ECDSA signing",
        "fix":       "github.com/golang-jwt/jwt with HS384+",
    },
    "github.com/golang-jwt/jwt": {
        "risk":      "HIGH",
        "ecosystem": "Go",
        "reason":    "JWT with RSA/ECDSA signing support",
        "fix":       "Use HS384+ short-term",
    },
    "github.com/square/go-jose": {
        "risk":      "HIGH",
        "ecosystem": "Go",
        "reason":    "JOSE/JWT with RSA/EC support",
        "fix":       "Use symmetric signing short-term",
    },

    # ── Rust ──────────────────────────────────────────────────────────────────
    "rust-rsa": {
        "risk":      "CRITICAL",
        "ecosystem": "Rust",
        "reason":    "RSA crate — entirely quantum-vulnerable",
        "fix":       "pqcrypto or oqs crate",
    },
    "p256": {
        "risk":      "CRITICAL",
        "ecosystem": "Rust",
        "reason":    "NIST P-256 elliptic curve — quantum-vulnerable",
        "fix":       "pqcrypto-kyber or ml-kem crate",
    },
    "p384": {
        "risk":      "CRITICAL",
        "ecosystem": "Rust",
        "reason":    "NIST P-384 elliptic curve — quantum-vulnerable",
        "fix":       "pqcrypto-kyber or ml-kem crate",
    },
    "k256": {
        "risk":      "CRITICAL",
        "ecosystem": "Rust",
        "reason":    "secp256k1 elliptic curve — quantum-vulnerable",
        "fix":       "pqcrypto-kyber or ml-kem crate",
    },
    "rust-ecdsa": {
        "risk":      "CRITICAL",
        "ecosystem": "Rust",
        "reason":    "ECDSA crate — entirely quantum-vulnerable",
        "fix":       "pqcrypto-dilithium or ml-dsa crate",
    },
    "ed25519-dalek": {
        "risk":      "HIGH",
        "ecosystem": "Rust",
        "reason":    "Ed25519 — elliptic curve based, quantum-vulnerable",
        "fix":       "pqcrypto-dilithium",
    },
    "x25519-dalek": {
        "risk":      "CRITICAL",
        "ecosystem": "Rust",
        "reason":    "X25519 key exchange — quantum-vulnerable",
        "fix":       "pqcrypto-kyber",
    },
    "ring": {
        "risk":      "HIGH",
        "ecosystem": "Rust",
        "reason":    "Contains RSA, ECDH, ECDSA — depends on usage",
        "fix":       "Audit usage; migrate to pqcrypto for new systems",
    },

    # ── Ruby ──────────────────────────────────────────────────────────────────
    "openssl": {
        "risk":      "HIGH",
        "ecosystem": "Ruby",
        "reason":    "Ruby OpenSSL bindings — classical crypto, audit usage",
        "fix":       "Enforce TLS 1.3 configuration",
    },
    "ruby-jwt": {
        "risk":      "HIGH",
        "ecosystem": "Ruby",
        "reason":    "JWT gem with RS256/ES256 support",
        "fix":       "Use HS384+ short-term",
    },
    "rbnacl": {
        "risk":      "HIGH",
        "ecosystem": "Ruby",
        "reason":    "NaCl bindings — uses Curve25519 (quantum-vulnerable)",
        "fix":       "Monitor for PQC NaCl alternatives",
    },

    # ── PHP ───────────────────────────────────────────────────────────────────
    "firebase/php-jwt": {
        "risk":      "HIGH",
        "ecosystem": "PHP",
        "reason":    "JWT with RS256/ES256 support — quantum-vulnerable",
        "fix":       "Use HS384+ short-term",
    },
    "phpseclib/phpseclib": {
        "risk":      "HIGH",
        "ecosystem": "PHP",
        "reason":    "PHP RSA/ECC/AES library — classical crypto",
        "fix":       "Audit usage; no PQC alternative yet",
    },
    "paragonie/halite": {
        "risk":      "HIGH",
        "ecosystem": "PHP",
        "reason":    "Uses libsodium with Curve25519 — quantum-vulnerable KEX",
        "fix":       "Monitor for PQC libsodium support",
    },

    # ── .NET / NuGet ──────────────────────────────────────────────────────────
    "bouncycastle": {
        "risk":      "HIGH",
        "ecosystem": ".NET",
        "reason":    "Classical crypto APIs — audit usage for RSA/ECC",
        "fix":       "Bouncy Castle PQC namespace (Org.BouncyCastle.Pqc)",
    },
    "system.security.cryptography": {
        "risk":      "MEDIUM",
        "ecosystem": ".NET",
        "reason":    "Built-in .NET crypto — audit for RSA/ECDSA usage",
        "fix":       "Use .NET 9+ PQC APIs when available",
    },
    "jose-jwt": {
        "risk":      "HIGH",
        "ecosystem": ".NET",
        "reason":    "JWT with RS256/ES256 support",
        "fix":       "Use HS384+ short-term",
    },
    "identitymodel": {
        "risk":      "HIGH",
        "ecosystem": ".NET",
        "reason":    "Token handling with RSA/EC signing",
        "fix":       "Monitor for PQC JWT support",
    },

    # ── PQC Positive signals ──────────────────────────────────────────────────
    "oqs": {
        "risk":      "INFO",
        "ecosystem": "Python",
        "reason":    "Open Quantum Safe — already using PQC",
        "fix":       "Already using PQC",
    },
    "liboqs": {
        "risk":      "INFO",
        "ecosystem": "Multi",
        "reason":    "Open Quantum Safe C library — already using PQC",
        "fix":       "Already using PQC",
    },
    "pqcrypto": {
        "risk":      "INFO",
        "ecosystem": "Rust",
        "reason":    "PQC Rust crate — already using PQC",
        "fix":       "Already using PQC",
    },
    "pqcrypto-kyber": {
        "risk":      "INFO",
        "ecosystem": "Rust",
        "reason":    "ML-KEM implementation — already using PQC",
        "fix":       "Already using PQC",
    },
    "pqcrypto-dilithium": {
        "risk":      "INFO",
        "ecosystem": "Rust",
        "reason":    "ML-DSA implementation — already using PQC",
        "fix":       "Already using PQC",
    },
    "@noble/post-quantum": {
        "risk":      "INFO",
        "ecosystem": "Node",
        "reason":    "PQC JS library — already using PQC",
        "fix":       "Already using PQC",
    },
    "bcpqc-jdk15on": {
        "risk":      "INFO",
        "ecosystem": "Java",
        "reason":    "Bouncy Castle PQC — already using PQC",
        "fix":       "Already using PQC",
    },
}


def check_package(name: str, version: str, filepath: str):
    """
    Look up a package name in the registry.
    Returns a dict if vulnerable, None if clean.
    Handles naming variations across ecosystems.
    """
    # Normalise: lowercase, replace underscores with hyphens
    key = name.lower().strip().replace("_", "-")

    if key in VULNERABLE_LIBRARIES:
        info = VULNERABLE_LIBRARIES[key]
        return {
            "package":      name,
            "version":      version,
            "file":         filepath,
            "ecosystem":    info["ecosystem"],
            "risk":         info["risk"],
            "reason":       info["reason"],
            "fix":          info["fix"],
            "is_pqc":       info["risk"] == "INFO",
        }
    return None