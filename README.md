# PQC Posture Scanner

Scans any codebase for quantum-vulnerable cryptography and produces
a compliance-mapped posture report.

Built to be language agnostic, regulation aware,
production grade.

---

## What it scans for

| Algorithm | Risk | Broken by | NIST Replacement | Regulated deadline |
|-----------|------|-----------|------------------|--------------------|
| RSA | CRITICAL | Shor's algorithm | ML-KEM (FIPS 203) | Disallowed 2035 |
| ECDH | CRITICAL | Shor's algorithm | ML-KEM (FIPS 203) | Disallowed 2035 |
| ECDSA | CRITICAL | Shor's algorithm | ML-DSA (FIPS 204) | Disallowed 2035 |
| DSA | CRITICAL | Shor's algorithm | ML-DSA (FIPS 204) | Disallowed 2035 |
| DH / DHE | CRITICAL | Shor's algorithm | ML-KEM (FIPS 203) | Disallowed 2035 |
| MD5 | CRITICAL | Grover's + broken | SHA-384 / SHA-512 | Disallowed 2035 |
| SHA-1 | CRITICAL | Grover's + broken | SHA-384 / SHA-512 | Disallowed 2035 |
| 3DES / DES | CRITICAL | Grover's + Sweet32 | AES-256 | Disallowed 2024 |
| RC4 | CRITICAL | Classically broken | AES-256-GCM | Disallowed 2015 |
| AES-128 | HIGH | Grover's algorithm | AES-256 | Deprecated 2025 |
| TLS 1.0/1.1 | HIGH | POODLE/BEAST | TLS 1.3 | Disallowed 2024 |
| Weak key sizes | CRITICAL | Classical + quantum | ML-KEM | Disallowed 2030 |
| Hardcoded secrets | CRITICAL | Direct exposure | Secrets manager | Immediate |

## Languages covered

Every pattern covers all major languages and ecosystems:

Python · Java · Kotlin · Go · Rust · JavaScript · TypeScript ·
C · C++ · C# / .NET · Ruby · PHP · Swift · Objective-C ·
Terraform · YAML · JSON · Dockerfile · Shell scripts

## Regulations mapped

- **CNSA 2.0** — NSA Commercial National Security Algorithm Suite
- **NIST IR 8547** — Transition away from RSA/ECC by 2030–2035
- **NIST SP 800-131A** — Transitioning cryptographic algorithms
- **UK NCSC** — Endorses FIPS 203/204/205 for UK organisations
- **NIS2 Directive** — EU critical infrastructure cybersecurity
- **DORA** — EU financial sector digital operational resilience
- **PCI-DSS 4.0** — Payment card industry data security
- **ISO 27001** — Information security management

## Posture scoring

| Grade | Score | Meaning |
|-------|-------|---------|
| A | 90-100 | Minimal quantum exposure |
| B | 75-89 | Low exposure, minor remediation needed |
| C | 55-74 | Moderate exposure, plan migration |
| D | 35-54 | High exposure, immediate action needed |
| F | 0-34 | Critical exposure, urgent remediation |

## Coming next

- [ ] GitHub dependency scanner
- [ ] Live TLS certificate scanner
- [ ] Terraform / IaC scanner
- [ ] REST API (FastAPI)
- [ ] GitHub Action for CI/CD
- [ ] CBOM output (CycloneDX format)
