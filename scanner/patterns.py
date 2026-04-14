from dataclasses import dataclass
from enum import Enum
from typing import List


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


class MigrationCategory(str, Enum):
    KEX_KEM   = "Key Exchange / KEM"
    SIGNATURE = "Digital Signature"
    SYMMETRIC = "Symmetric Encryption"
    HASH      = "Hash Function"
    UNKNOWN   = "Unknown"


@dataclass
class CryptoPattern:
    name:             str
    pattern:          str
    algorithm:        str
    risk:             RiskLevel
    category:         MigrationCategory
    cwe:              str
    description:      str
    recommendation:   str
    nist_replacement: str
    harvest_now_risk: bool = False
    deprecated_after: str  = "2030"
    disallowed_after: str  = "2035"
    regulations:      str  = "CNSA 2.0, NIST IR 8547, UK NCSC, NIS2, DORA"


ALL_PATTERNS: List[CryptoPattern] = [

    # ─── RSA ──────────────────────────────────────────────────────────────────
    # Python · Java · Kotlin · Go · Rust · JS/TS · C · C++ · Ruby · PHP
    # .NET/C# · Swift · Obj-C · Terraform · YAML/JSON config
    CryptoPattern(
        name      = "RSA",
        pattern   = (
            r'rsa\.generate_private_key'
            r'|RSA\.generate'
            r'|Crypto\.PublicKey\.RSA'
            r'|from cryptography.*import.*\brsa\b'
            r'|KeyPairGenerator\.getInstance\s*\(\s*["\']RSA["\']'
            r'|RSAKeyGenParameterSpec'
            r'|RSAPublicKeySpec|RSAPrivateKeySpec'
            r'|rsa\.GenerateKey\s*\('
            r'|\"crypto/rsa\"'
            r'|RsaPrivateKey::new'
            r'|use\s+rsa::'
            r'|generateKeyPair\s*\(\s*["\']rsa["\']'
            r'|RS256|RS384|RS512'
            r'|PS256|PS384|PS512'
            r'|RSA_generate_key\s*\('
            r'|RSA_generate_key_ex\s*\('
            r'|RSA_new\s*\(\s*\)'
            r'|EVP_PKEY_RSA\b'
            r'|EVP_RSA_gen\s*\('
            r'|OpenSSL::PKey::RSA\.new'
            r'|OpenSSL::PKey::RSA\.generate'
            r'|openssl_pkey_new.*OPENSSL_KEYTYPE_RSA'
            r'|new\s+RSACryptoServiceProvider'
            r'|RSA\.Create\s*\('
            r'|RSACng\s*\('
            r'|kSecAttrKeyTypeRSA'
            r'|key_type\s*=\s*["\']RSA["\']'
            r'|algorithm\s*=\s*["\']RSA["\']'
        ),
        algorithm        = "RSA",
        risk             = RiskLevel.CRITICAL,
        category         = MigrationCategory.KEX_KEM,
        cwe              = "CWE-327",
        description      = "RSA is broken by Shor's algorithm on a cryptographically relevant quantum computer. Data encrypted today can be harvested and decrypted later.",
        recommendation   = "Replace with ML-KEM (CRYSTALS-Kyber) per NIST FIPS 203.",
        nist_replacement = "ML-KEM (FIPS 203 / CRYSTALS-Kyber)",
        harvest_now_risk = True,
        deprecated_after = "2030",
        disallowed_after = "2035",
        regulations      = "CNSA 2.0, NIST IR 8547, UK NCSC, NIS2, DORA",
    ),

    # ─── ECDH ─────────────────────────────────────────────────────────────────
    # Python · Java · Kotlin · Go · Rust · JS/TS · C · C++ · Ruby · .NET · Swift
    CryptoPattern(
        name      = "ECDH / Elliptic Curve Key Exchange",
        pattern   = (
            r'ec\.ECDH\b'
            r'|ec\.generate_private_key'
            r'|from cryptography.*asymmetric.*import.*\bec\b'
            r'|KeyAgreement\.getInstance\s*\(\s*["\']ECDH["\']'
            r'|KeyPairGenerator\.getInstance\s*\(\s*["\']EC["\']'
            r'|ECGenParameterSpec'
            r'|ecdh\.P256\s*\(\)'
            r'|ecdh\.P384\s*\(\)'
            r'|ecdh\.P521\s*\(\)'
            r'|ecdh\.X25519\s*\(\)'
            r'|elliptic\.P256\s*\(\)'
            r'|\"crypto/elliptic\"'
            r'|\"crypto/ecdh\"'
            r'|EphemeralSecret::new'
            r'|use\s+p256::'
            r'|use\s+p384::'
            r'|use\s+k256::'
            r'|createECDH\s*\('
            r'|generateKeyPair\s*\(\s*["\']ec["\']'
            r'|namedCurve\s*[=:]\s*["\']P-256["\']'
            r'|namedCurve\s*[=:]\s*["\']P-384["\']'
            r'|namedCurve\s*[=:]\s*["\']P-521["\']'
            r'|namedCurve\s*[=:]\s*["\']secp'
            r'|EC_KEY_new_by_curve_name\s*\('
            r'|ECDH_compute_key\s*\('
            r'|EVP_PKEY_EC\b'
            r'|NID_X9_62_prime256v1'
            r'|NID_secp384r1'
            r'|NID_secp521r1'
            r'|OpenSSL::PKey::EC\.new'
            r'|ECDiffieHellman\.Create\s*\('
            r'|new\s+ECDiffieHellmanCng'
            r'|kSecAttrKeyTypeECSECPrimeRandom'
        ),
        algorithm        = "ECDH",
        risk             = RiskLevel.CRITICAL,
        category         = MigrationCategory.KEX_KEM,
        cwe              = "CWE-327",
        description      = "Elliptic curve Diffie-Hellman is broken by Shor's algorithm. All variants (P-256, P-384, P-521, X25519) are vulnerable.",
        recommendation   = "Replace with ML-KEM (CRYSTALS-Kyber) per NIST FIPS 203.",
        nist_replacement = "ML-KEM (FIPS 203 / CRYSTALS-Kyber)",
        harvest_now_risk = True,
        deprecated_after = "2030",
        disallowed_after = "2035",
        regulations      = "CNSA 2.0, NIST IR 8547, UK NCSC, NIS2",
    ),

    # ─── ECDSA ────────────────────────────────────────────────────────────────
    CryptoPattern(
        name      = "ECDSA",
        pattern   = (
            r'ec\.ECDSA\b'
            r'|from cryptography.*asymmetric.*ec.*import.*ECDSA'
            r'|Signature\.getInstance\s*\(\s*["\']SHA\d+withECDSA["\']'
            r'|SHA256withECDSA|SHA384withECDSA|SHA512withECDSA'
            r'|ecdsa\.Sign\s*\('
            r'|ecdsa\.GenerateKey\s*\('
            r'|\"crypto/ecdsa\"'
            r'|use\s+ecdsa::'
            r'|ES256|ES384|ES512'
            r'|ECDSA_sign\s*\('
            r'|ECDSA_do_sign\s*\('
            r'|EVP_DigestSign.*EC'
            r'|OpenSSL::PKey::EC.*\.sign'
            r'|ECDsa\.Create\s*\('
            r'|new\s+ECDsaCng'
            r'|SecKeyCreateSignature.*ecdsaSignature'
            r'|ecdsa-sha2-nistp256'
            r'|ecdsa-sha2-nistp384'
            r'|ecdsa-sha2-nistp521'
        ),
        algorithm        = "ECDSA",
        risk             = RiskLevel.CRITICAL,
        category         = MigrationCategory.SIGNATURE,
        cwe              = "CWE-327",
        description      = "ECDSA signatures are broken by Shor's algorithm.",
        recommendation   = "Replace with ML-DSA (CRYSTALS-Dilithium) per NIST FIPS 204.",
        nist_replacement = "ML-DSA (FIPS 204 / CRYSTALS-Dilithium)",
        harvest_now_risk = False,
        deprecated_after = "2030",
        disallowed_after = "2035",
        regulations      = "CNSA 2.0, NIST IR 8547, UK NCSC",
    ),

    # ─── DSA ──────────────────────────────────────────────────────────────────
    CryptoPattern(
        name      = "DSA",
        pattern   = (
            r'from cryptography.*import.*\bdsa\b'
            r'|dsa\.generate_private_key'
            r'|Crypto\.PublicKey\.DSA'
            r'|KeyPairGenerator\.getInstance\s*\(\s*["\']DSA["\']'
            r'|DSAParameterSpec'
            r'|SHA256withDSA|SHA1withDSA'
            r'|dsa\.GenerateKey\s*\('
            r'|\"crypto/dsa\"'
            r'|DSA_generate_key\s*\('
            r'|DSA_new\s*\(\s*\)'
            r'|EVP_PKEY_DSA\b'
            r'|new\s+DSACryptoServiceProvider'
            r'|DSA\.Create\s*\('
            r'|ssh-dss\b'
        ),
        algorithm        = "DSA",
        risk             = RiskLevel.CRITICAL,
        category         = MigrationCategory.SIGNATURE,
        cwe              = "CWE-327",
        description      = "DSA relies on discrete logarithm — broken by Shor's algorithm.",
        recommendation   = "Replace with ML-DSA (CRYSTALS-Dilithium) per NIST FIPS 204.",
        nist_replacement = "ML-DSA (FIPS 204 / CRYSTALS-Dilithium)",
        harvest_now_risk = False,
        deprecated_after = "2030",
        disallowed_after = "2035",
        regulations      = "CNSA 2.0, NIST IR 8547",
    ),

    # ─── Diffie-Hellman ───────────────────────────────────────────────────────
    CryptoPattern(
        name      = "Diffie-Hellman (DH/DHE)",
        pattern   = (
            r'from cryptography.*import.*\bdh\b'
            r'|dh\.generate_parameters'
            r'|KeyPairGenerator\.getInstance\s*\(\s*["\']DH["\']'
            r'|KeyAgreement\.getInstance\s*\(\s*["\']DH["\']'
            r'|DHParameterSpec'
            r'|DH_generate_key\s*\('
            r'|DH_new\s*\(\s*\)'
            r'|EVP_PKEY_DH\b'
            r'|DH_generate_parameters_ex\s*\('
            r'|TLS_DHE_'
            r'|TLS_DH_'
        ),
        algorithm        = "DH / DHE",
        risk             = RiskLevel.CRITICAL,
        category         = MigrationCategory.KEX_KEM,
        cwe              = "CWE-327",
        description      = "Classic Diffie-Hellman key exchange is broken by Shor's algorithm.",
        recommendation   = "Replace with ML-KEM (CRYSTALS-Kyber) per NIST FIPS 203.",
        nist_replacement = "ML-KEM (FIPS 203 / CRYSTALS-Kyber)",
        harvest_now_risk = True,
        deprecated_after = "2030",
        disallowed_after = "2035",
        regulations      = "CNSA 2.0, NIST IR 8547",
    ),

    # ─── MD5 ──────────────────────────────────────────────────────────────────
    # Python · Java · Go · Rust · JS/TS · C · C++ · Ruby · PHP · .NET · Swift · R
    CryptoPattern(
        name      = "MD5",
        pattern   = (
            r'hashlib\.md5\s*\('
            r'|Crypto\.Hash\.MD5'
            r'|MD5\.new\s*\('
            r'|MessageDigest\.getInstance\s*\(\s*["\']MD5["\']'
            r'|DigestUtils\.md5'
            r'|md5\.New\s*\(\)'
            r'|md5\.Sum\s*\('
            r'|\"crypto/md5\"'
            r'|use\s+md5::'
            r'|md5::compute'
            r'|createHash\s*\(\s*["\']md5["\']'
            r'|MD5\s*\(\s*\w'
            r'|MD5_Init\s*\('
            r'|EVP_md5\s*\(\)'
            r'|Digest::MD5\.'
            r'|OpenSSL::Digest::MD5'
            r'|md5\s*\('
            r'|hash\s*\(\s*["\']md5["\']'
            r'|MD5\.Create\s*\('
            r'|new\s+MD5CryptoServiceProvider'
            r'|CC_MD5\s*\('
        ),
        algorithm        = "MD5",
        risk             = RiskLevel.CRITICAL,
        category         = MigrationCategory.HASH,
        cwe              = "CWE-328",
        description      = "MD5 is cryptographically broken (collision attacks since 2004) and has only ~64 bits of post-quantum security.",
        recommendation   = "Replace with SHA-384 or SHA-512.",
        nist_replacement = "SHA-384 or SHA-512",
        harvest_now_risk = False,
        deprecated_after = "2030",
        disallowed_after = "2035",
        regulations      = "CNSA 2.0, NIST SP 800-131A, PCI-DSS 4.0",
    ),

    # ─── SHA-1 ────────────────────────────────────────────────────────────────
    CryptoPattern(
        name      = "SHA-1",
        pattern   = (
            r'hashlib\.sha1\s*\('
            r'|hashes\.SHA1\b'
            r'|Crypto\.Hash\.SHA\b'
            r'|MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']'
            r'|DigestUtils\.sha1'
            r'|SHA1withRSA|SHA1withECDSA|SHA1withDSA'
            r'|sha1\.New\s*\(\)'
            r'|sha1\.Sum\s*\('
            r'|\"crypto/sha1\"'
            r'|use\s+sha1::'
            r'|Sha1::new\s*\(\)'
            r'|createHash\s*\(\s*["\']sha1["\']'
            r'|SHA1\s*\(\s*\w'
            r'|SHA1_Init\s*\('
            r'|EVP_sha1\s*\(\)'
            r'|Digest::SHA1\.'
            r'|OpenSSL::Digest::SHA1'
            r'|sha1\s*\('
            r'|hash\s*\(\s*["\']sha1["\']'
            r'|SHA1\.Create\s*\('
            r'|new\s+SHA1CryptoServiceProvider'
            r'|CC_SHA1\s*\('
            r'|ssh-rsa\b'
        ),
        algorithm        = "SHA-1",
        risk             = RiskLevel.CRITICAL,
        category         = MigrationCategory.HASH,
        cwe              = "CWE-328",
        description      = "SHA-1 is broken (SHAttered collision attack 2017) and has only ~80 bits of post-quantum security.",
        recommendation   = "Replace with SHA-384 or SHA-512.",
        nist_replacement = "SHA-384 or SHA-512",
        harvest_now_risk = False,
        deprecated_after = "2030",
        disallowed_after = "2035",
        regulations      = "CNSA 2.0, NIST SP 800-131A, PCI-DSS 4.0",
    ),

    # ─── AES-128 ──────────────────────────────────────────────────────────────
    CryptoPattern(
        name      = "AES-128 (insufficient post-quantum)",
        pattern   = (
            r'AES-?128\b'
            r'|AES_128\b'
            r'|key_size\s*=\s*128\b'
            r'|key_length\s*=\s*16\b'
            r'|KeySize\s*=\s*128\b'
            r'|KeyGenerator\.getInstance\s*\(\s*["\']AES["\'].*128'
            r'|aes\.NewCipher\s*\(.*\b16\b'
            r'|AES_128_CBC|AES_128_GCM|AES_128_CTR'
            r'|EVP_aes_128_'
            r'|TLS_AES_128_GCM_SHA256'
        ),
        algorithm        = "AES-128",
        risk             = RiskLevel.HIGH,
        category         = MigrationCategory.SYMMETRIC,
        cwe              = "CWE-326",
        description      = "AES-128 provides only ~64 bits of security against Grover's algorithm. CNSA 2.0 mandates AES-256 for all new systems.",
        recommendation   = "Upgrade to AES-256.",
        nist_replacement = "AES-256",
        harvest_now_risk = True,
        deprecated_after = "2025",
        disallowed_after = "2030",
        regulations      = "CNSA 2.0, NIST SP 800-131A",
    ),

    # ─── 3DES / DES ───────────────────────────────────────────────────────────
    CryptoPattern(
        name      = "3DES / DES",
        pattern   = (
            r'Crypto\.Cipher\.DES3'
            r'|algorithms\.TripleDES'
            r'|DES\.new\s*\('
            r'|Cipher\.getInstance\s*\(\s*["\']DESede'
            r'|Cipher\.getInstance\s*\(\s*["\']DES["\']'
            r'|DESedeKeySpec'
            r'|des\.NewTripleDESCipher\s*\('
            r'|des\.NewCipher\s*\('
            r'|\"crypto/des\"'
            r'|use\s+des::'
            r'|TdesEde3::'
            r'|createCipheriv\s*\(\s*["\']des'
            r'|createCipheriv\s*\(\s*["\']3des'
            r'|DES_set_key\s*\('
            r'|EVP_des_ede3\s*\(\)'
            r'|EVP_des_cbc\s*\(\)'
            r'|DES_EDE3_CBC'
            r'|new\s+TripleDESCryptoServiceProvider'
            r'|TripleDES\.Create\s*\('
            r'|new\s+DESCryptoServiceProvider'
            r'|OpenSSL::Cipher.*des'
        ),
        algorithm        = "3DES / DES",
        risk             = RiskLevel.CRITICAL,
        category         = MigrationCategory.SYMMETRIC,
        cwe              = "CWE-326",
        description      = "3DES/DES are far below post-quantum requirements. Also vulnerable to Sweet32 (3DES) and brute force (DES at 56-bit).",
        recommendation   = "Replace with AES-256 immediately.",
        nist_replacement = "AES-256",
        harvest_now_risk = True,
        deprecated_after = "2023",
        disallowed_after = "2024",
        regulations      = "CNSA 2.0, NIST SP 800-131A, PCI-DSS 4.0",
    ),

    # ─── RC4 ──────────────────────────────────────────────────────────────────
    CryptoPattern(
        name      = "RC4",
        pattern   = (
            r'Crypto\.Cipher\.ARC4'
            r'|algorithms\.ARC4'
            r'|ARC4\.new\s*\('
            r'|Cipher\.getInstance\s*\(\s*["\']RC4["\']'
            r'|Cipher\.getInstance\s*\(\s*["\']ARCFOUR["\']'
            r'|rc4\.NewCipher\s*\('
            r'|\"crypto/rc4\"'
            r'|use\s+rc4::'
            r'|createCipheriv\s*\(\s*["\']rc4["\']'
            r'|RC4_set_key\s*\('
            r'|EVP_rc4\s*\(\)'
            r'|RC4-SHA\b|RC4-MD5\b'
            r'|TLS_RSA_WITH_RC4'
        ),
        algorithm        = "RC4",
        risk             = RiskLevel.CRITICAL,
        category         = MigrationCategory.SYMMETRIC,
        cwe              = "CWE-327",
        description      = "RC4 is broken classically (NOMORE, BEAST attacks) and has zero quantum resistance.",
        recommendation   = "Replace with AES-256-GCM immediately.",
        nist_replacement = "AES-256-GCM",
        harvest_now_risk = True,
        deprecated_after = "2015",
        disallowed_after = "2015",
        regulations      = "CNSA 2.0, PCI-DSS, RFC 7465",
    ),

    # ─── TLS 1.0 / 1.1 / SSLv3 ───────────────────────────────────────────────
    CryptoPattern(
        name      = "TLS 1.0 / 1.1 / SSLv3",
        pattern   = (
            r'ssl\.PROTOCOL_TLSv1\b'
            r'|ssl\.PROTOCOL_TLSv1_1\b'
            r'|ssl\.PROTOCOL_SSLv3\b'
            r'|SSLContext\.getInstance\s*\(\s*["\']TLSv1["\']'
            r'|SSLContext\.getInstance\s*\(\s*["\']TLSv1\.1["\']'
            r'|tls\.VersionTLS10'
            r'|tls\.VersionTLS11'
            r'|SslProtocols\.Tls\b(?!12|13)'
            r'|SslProtocols\.Ssl3'
            r'|SecurityProtocolType\.Tls\b(?!12|13)'
            r'|secureProtocol.*TLSv1_method'
            r'|SSL_CTX_new\s*\(\s*TLSv1_method'
            r'|SSLv3\b'
            r'|TLSv1\.1\b'
        ),
        algorithm        = "TLS 1.0 / 1.1 / SSLv3",
        risk             = RiskLevel.HIGH,
        category         = MigrationCategory.KEX_KEM,
        cwe              = "CWE-326",
        description      = "TLS 1.0/1.1 and SSLv3 are deprecated (RFC 8996). Vulnerable to POODLE, BEAST, CRIME. No quantum-safe cipher suites.",
        recommendation   = "Enforce TLS 1.3 minimum.",
        nist_replacement = "TLS 1.3 + ML-KEM hybrid",
        harvest_now_risk = True,
        deprecated_after = "2020",
        disallowed_after = "2024",
        regulations      = "CNSA 2.0, PCI-DSS 4.0, NIST SP 800-52",
    ),

    # ─── Weak key sizes ───────────────────────────────────────────────────────
    CryptoPattern(
        name      = "Weak RSA/DH key size (< 2048 bits)",
        pattern   = (
            r'RSA\.generate\s*\(\s*(?:512|768|1024)\b'
            r'|rsa\.generate_private_key\s*\(.*key_size\s*=\s*(?:512|768|1024)\b'
            r'|RSA_generate_key\s*\(\s*(?:512|768|1024)\b'
            r'|RSA_generate_key_ex\s*\(.*(?:512|768|1024)\b'
            r'|KeyPairGenerator.*initialize\s*\(\s*(?:512|768|1024)\b'
            r'|RSAKeyGenParameterSpec\s*\(\s*(?:512|768|1024)\b'
            r'|rsa\.GenerateKey\s*\(.*,\s*(?:512|768|1024)\b'
            r'|RSACryptoServiceProvider\s*\(\s*(?:512|768|1024)\b'
            r'|key_size\s*=\s*(?:512|768|1024)\b'
            r'|bits\s*=\s*(?:512|768|1024)\b'
        ),
        algorithm        = "RSA/DH < 2048-bit",
        risk             = RiskLevel.CRITICAL,
        category         = MigrationCategory.KEX_KEM,
        cwe              = "CWE-326",
        description      = "Key sizes below 2048-bit are classically weak (NIST deprecated 2013). Any RSA is quantum-vulnerable regardless of size.",
        recommendation   = "Immediate: RSA-3072+ transitionally. Long-term: replace with ML-KEM.",
        nist_replacement = "ML-KEM (FIPS 203)",
        harvest_now_risk = True,
        deprecated_after = "2013",
        disallowed_after = "2030",
        regulations      = "CNSA 2.0, NIST SP 800-131A, PCI-DSS 4.0",
    ),

    # ─── Hardcoded secrets ────────────────────────────────────────────────────
    CryptoPattern(
        name      = "Hardcoded cryptographic secret",
        pattern   = (
            r'-----BEGIN RSA PRIVATE KEY-----'
            r'|-----BEGIN EC PRIVATE KEY-----'
            r'|-----BEGIN PRIVATE KEY-----'
            r'|-----BEGIN OPENSSH PRIVATE KEY-----'
            r'|-----BEGIN DSA PRIVATE KEY-----'
            r'|(?:private_key|secret_key|api_secret|jwt_secret|signing_key)'
            r'\s*[=:]\s*["\'][A-Za-z0-9+/]{20,}["\']'
            r'|AKIA[0-9A-Z]{16}'
        ),
        algorithm        = "Hardcoded Secret",
        risk             = RiskLevel.CRITICAL,
        category         = MigrationCategory.UNKNOWN,
        cwe              = "CWE-321",
        description      = "Hardcoded cryptographic secrets are exposed in source code and version history.",
        recommendation   = "Use a secrets manager: AWS Secrets Manager, HashiCorp Vault, or runtime environment variables.",
        nist_replacement = "Secrets management system",
        harvest_now_risk = True,
        deprecated_after = "N/A",
        disallowed_after = "N/A",
        regulations      = "CNSA 2.0, PCI-DSS 4.0, SOC2, ISO 27001",
    ),

]