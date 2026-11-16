# Domain Shard 01: Application Security, Cryptography & Secrets (`security`)

> **Domain ID:** `security` · **Shard Path:** `docs/domains/01_security_appsec.md` · **License:** `Apache-2.0`
> **Scope:** Secret detection, unsafe deserialization/eval prevention, cryptographic randomness (CSPRNG), TLS verification, JWT signature enforcement, Trojan Source Unicode defense, and memory-safety guards.

## 1. Domain-Routed `KMI/1` Wire Header (`security`)

```text
<!-- KINTSUGI:KMI/1:DOMAIN=security START -->
# KMI/1;domain=security;doc=docs/domains/01_security_appsec.md;jit=pre-tool-use
@CRIT: KS-001(secret!=literal->os.environ) | KS-006(no_eval_exec_pickle->literal_eval) | KS-014(tls!rejectUnauthorized=true) | KS-018(torch!load->weights_only=True) | KS-019(bidi_unicode!strip_trojan_source) | KS-020(jwt!verify_signature=True) | KS-021(c!bounds_checked_snprintf) | KS-022(c!constant_format_string) | KS-023(rs!safe_slice_no_transmute) | KS-024(java!safe_json_no_objectinputstream)
@HIGH: KS-011(crypto!random->secrets)
<!-- KINTSUGI:KMI/1:DOMAIN=security END -->
```

## 2. Enforced Guardrails in This Shard

| Scar ID | Severity | Languages | Anti-Pattern (`❌ Bad`) | Verified Remediation (`✅ Good`) |
| :--- | :--- | :--- | :--- | :--- |
| `KS-001` | `CRITICAL` | `py,js,ts,go,rs,sh` | Hardcoded `sk-`, `ghp_`, `AKIA`, or PEM private key literals | Read from `os.environ["SERVICE_API_KEY"]` or secret manager |
| `KS-006` | `CRITICAL` | `python` | `eval()`, `exec()`, `pickle.loads()`, or `yaml.load()` without `SafeLoader` | `json.loads()`, `ast.literal_eval()`, or `yaml.safe_load()` |
| `KS-011` | `HIGH` | `python` | `random.randint()` / `random.choice()` for tokens, nonces, or OTPs | `secrets.token_urlsafe(32)` or `secrets.randbelow()` |
| `KS-014` | `CRITICAL` | `js,ts,sh` | `NODE_TLS_REJECT_UNAUTHORIZED = '0'` or `rejectUnauthorized: false` | Configure per-agent custom CA bundle (`new https.Agent({ ca })`) |
| `KS-018` | `CRITICAL` | `python` | `torch.load(model_path)` without `weights_only=True` | `torch.load(model_path, weights_only=True)` |
| `KS-019` | `CRITICAL` | `all` | Trojan Source bidirectional Unicode control characters (`U+202A..U+202E`) | Strip Bidi overrides and enforce NFKC/ASCII identifier hygiene |
| `KS-020` | `CRITICAL` | `python,js,ts` | `jwt.decode(..., options={"verify_signature": False})` or `alg="none"` | `jwt.decode(tok, pub_key, algorithms=["RS256"])` |
| `KS-021` | `CRITICAL` | `c,cpp` | Unbounded `gets()`, `strcpy()`, `strcat()`, `sprintf()` | Bounded `snprintf(buf, sizeof(buf), "%s", src)` |
| `KS-022` | `CRITICAL` | `c,cpp` | Non-literal format string `printf(user_msg)` (`CWE-134`) | Constant format specifier `printf("%s", user_msg)` |
| `KS-023` | `CRITICAL` | `rust` | Unchecked `unsafe { *ptr }` or `std::mem::transmute` | Safe slice indexing `v.first().copied()` and checked conversions |
| `KS-024` | `CRITICAL` | `java,kotlin` | `new ObjectInputStream(s).readObject()` or string `Runtime.exec()` | Typed JSON deserialization and `new ProcessBuilder(argv).start()` |

## 3. Reproducible CLI Commands

```bash
# Render only the security domain KMI/1 shard:
kintsugi token-report --domain security

# Scan repository against security guardrails:
kintsugi scan . --min-severity HIGH
```
