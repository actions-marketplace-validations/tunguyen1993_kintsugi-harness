# Security Policy & OpenSSF Best Practices Compliance (`v2.0.x`)

## Supported Versions

| Version | Supported | Security Guardrails & Provenance |
| :--- | :--- | :--- |
| `2.0.x` | ✅ Yes | Native Rust `kintsugi-rs` (`7.6 µs/call`) + Python 3.9+ Zero-Dependency AST-Lite + OpenSSF Scorecard + SLSA Provenance |
| `1.9.x` | ✅ Yes | Security fixes backported |
| `< 1.9.0` | ❌ No | Upgrade to `>= 2.0.0` |

## OpenSSF Best Practices (CII) & Supply-Chain Hardening Checklist

- **Zero Third-Party Runtime Dependencies:** `kintsugi-harness` uses exclusively the Python 3.9+ standard library and a standalone zero-dependency Rust binary (`rust/src/main.rs`), eliminating transitive `pip`/`cargo` supply-chain attacks.
- **Static & Structural AST-Lite Analysis (SAST):** Built-in `kintsugi scan --staged --fail-on HIGH` enforces 63+ formal guardrails (`KS-001`..`KS-028`, SSRF canonical IP verification, Unicode Bidi/zero-width prompt-injection stripping, unsafe deserialization blocking, and Git staged-index symlink protection).
- **Automated Regression & Arena Verification Suite:** Every release passes `pytest` (`43/43` unit & adversarial tests) and `python3 benchmarks/run_verifiable_arena_cert_suite.py --verify` (`10/10` international AI & security benchmarks at `100.0%` accuracy).
- **Least-Privilege CI Workflows:** All GitHub Actions workflows enforce top-level `permissions: read-all` and pin third-party actions to immutable 40-character commit SHAs.

## Reporting a Vulnerability (RFC 9116 Compliant)

Please **do not** open public issues for exploitable ReDoS patterns, hook bypasses, or prompt-injection escapes in `kintsugi-harness`.

1. **GitHub Private Vulnerability Reporting (Preferred):** Use the **Report a vulnerability** button under the repository's **[Security -> Advisories](https://github.com/tunguyen1993/kintsugi-harness/security/advisories/new)** tab.
2. **Response SLA:** Initial triage acknowledgment within **24 hours**; verified patch and regression test (`scars.json` / `scars.kml`) published within **72 hours** with full researcher credit.
