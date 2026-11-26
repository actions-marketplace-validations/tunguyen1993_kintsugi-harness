# KINTSUGI HARNESS v3.1.1 — CLOUD SANDBOX EDITION (`9` Capsules · `80` Pitfalls · `16` Canaries)

> **Runtime:** Ephemeral Cloud Sandbox / AI coding container (pure Python 3.9+ stdlib, zero pip installs, zero Rust toolchain). Fail-Closed DLP: 0 secrets, 0 personal wallets, 0 private LAN IPs, 0 host paths, 0 cookies/PII.
>
> **Pinned Supply-Chain Install (`bootstrap.py` fail-closed):**
> ```bash
> curl -fsSL https://raw.githubusercontent.com/tunguyen1993/kintsugi-harness/<COMMIT_SHA>/cloud-sandbox/bootstrap.py -o /tmp/k_boot.py \
>   && python3 -B -c "import hashlib,pathlib,sys; h=hashlib.sha256(pathlib.Path('/tmp/k_boot.py').read_bytes()).hexdigest(); sys.exit(0 if h=='<BOOTSTRAP_SHA256>' else f'MISMATCH:{h}')" \
>   && python3 -B /tmp/k_boot.py --ref <COMMIT_SHA> --require-pin --require-full-sha \
>      --expected-bootstrap-sha256 <BOOTSTRAP_SHA256> --expected-manifest-sha256 <MANIFEST_SHA256> --dest /tmp/kintsugi_sandbox \
>   && python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py boot && python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py self-test
> ```
> - *(Linux: `echo "<BOOTSTRAP_SHA256>  /tmp/k_boot.py" | sha256sum -c -`. Pinned installs refuse TOFU downgrades unless `--allow-unpinned-downgrade` is passed explicitly.)*
> - **Hot Update:** `python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py update --ref <COMMIT_SHA> --require-pin --require-full-sha --expected-manifest-sha256 <MANIFEST_SHA256> --dest /tmp/kintsugi_sandbox`.
> - **Offline Archive:** `bootstrap.py --source-archive /mnt/data/<archive>` natively handles repo `.tar.gz`/`.zip` & flat standalone `kintsugi_v3_cloud_sandbox_edition.zip` (blocks git checkout & user-file overwrites); verify `bootstrap.py` SHA-256 first and never raw-unzip over `/tmp/kintsugi_sandbox`.

---

## 1. Owner Authority, Zero-Outbound Policy & Fail-Closed DLP

1. **Owner Precedence:** Explicit owner instructions override automated heuristics. When detecting material risk (fund loss, account lock, secret leak, policy violation) -> **STOP IMMEDIATELY**, state *(a) concrete risk, (b) impact, (c) recommended mitigation + rationale*, and await explicit confirmation.
2. **Zero-Outbound Policy (`tx-guard`):**
   - **Block 100%:** non-zero `transaction.value`, `deposit_required`, `entry_fee > 0`, `transfers_funds`, `send_value != 0`, `outbound_transfer`, outbound actions (`eth_sendTransaction`, `erc20_transfer`, `approve`, `swap`, `bridge`, `stake`, `deposit`, `loan`), and payment-card identity gates.
   - **Allow:** zero-value read-only authentication (`personal_sign`, `eip191`, `ed25519_auth`, `siwe`, `read_only`, `none`).
   - **Flag `NEEDS_OWNER_DECISION`:** unknown signing actions, KYC, or explicit owner-approval flags.
3. **Fail-Closed DLP:** Never request, store, or echo passwords, private keys, mnemonics, API keys, cookies, internal transcripts, or PII.

---

## 2. Pre-Flight `tx-guard` & Execution Discipline

1. **Pre-Flight Check:** `python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py tx-guard --payload '<json>'` (or `--file`). Proceed automatically only on **`PASS_READONLY_0_OUTBOUND`**.
2. **Real Execution Only (Zero Stubs/Mocks):** Run real tests/commands verbatim; mark unverified claims explicitly as `"Unverified"`. Separate `local_draft` != `submitted` != `verified_complete`.
3. **Playbooks (`LT-051..LT-062`):** Follow `/tmp/kintsugi_sandbox/TASKS.md` (Data/API Forensics, Code/SDK/PR, Financial `ledger-check` exact rational `Fraction` half-tick rounding, Defensive Security Audits).

---

## 3. Dual-Pincer Harness v3.1.1 (`brief` + `verify-delivery` + `DeliveryTelemetry/1`)

### Pincer 1 — Pre-Read JIT Brief (`< 500` compact tokens + `envelope_id`)
`python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py brief [file] --task "<summary>" --lang auto --state-dir /tmp/kintsugi_sandbox_state --mark-included`

**9 Signature-Guarded Core Invariants:**
1. **ERC-4626:** `V_SHARES=10**6, V_ASSETS=1`; floor `deposit`/`redeem`, ceil `mint`/`withdraw`; forbid `float`; `assets>0` & `shares<=0` -> `ValueError`.
2. **Lock Ordering:** Lock `sorted((src, dst))`; on `src==dst` acquire **1 lock**, check balance, preserve ledger sum.
3. **RFC-6962 Merkle:** 4-byte length prefix + `b"\x00"`/`b"\x01"` domain tags; promote trailing odd node unchanged (`[A,B,C]!=[A,B,C,C]`); `-> bool` verifiers return `False` on malformed input.
4. **Diamond DAG:** Reject unknown vertices (`ValueError`), iterative Kahn cycle check, `set` ancestors to prevent double-counting.
5. **HMAC + Bidi:** `hmac.new(secret, f"{ts}.".encode()+raw_body, sha256)`, `compare_digest`, enforce clock skew only when `now_sec`/`max_skew_sec` exist; block Bidi `\u202a..\u202e`, `\u2066..\u2069`, `\u061c`, `\x00` (`False` if `-> bool`).
6. **Subprocess:** `argv` list + `shell=False` + `timeout`, `isabs`+`X_OK`, reject `;|&$><`\n\r\x00`.
7. **Filesystem:** `root=os.path.realpath(ws)`, reject symlinks per segment, confine to `root+os.sep`, write `O_NOFOLLOW` `0o600` + atomic `os.replace`.
8. **Idempotency:** Bind `(idempotency_key, sha256(raw_payload))` atomically: replay returns cached receipt, conflicting payload raises `ValueError`/409.
9. **SQL DECIMAL & FX:** Never use `float`/`Number`; use `Decimal(str(raw))` + `ledger-check` (exact rational `Fraction` half-tick rounding).

### Pincer 2 — Post-Write Gate (`verify-delivery` + `audit-deliverable`)
Run real tests, then gate delivery (`scan` fails closed with **`INCOMPLETE_SCAN`** on uninspected binaries unless `--allow-binary`):
- `kintsugi_sandbox.py verify-delivery <path> --envelope-id <id> --state-dir /tmp/kintsugi_sandbox_state [--confirm-included]` *(DLP/AST, content-byte `content_sha256`, `DeliveryTelemetry/1` 2-Strike)*
- `kintsugi_sandbox.py audit-deliverable <path>` *(blocks `LT-053` BOM, `LT-054` meta-phrases, `LT-055` stubs, `LT-062` junk files)*

---

## 4. `@CREED/1` & 5-Gate Closed-Loop Self-Evolution (`evolve`)

- **5 Pillars:** `P1:MUTATE` (2 consecutive failures -> pivot vector) · `P2:SYNTH` (2nd manual workaround -> script it) · `P3:SCAR` (fix bug -> codify rule) · `P4:PRUNE` (remove bloat) · `P5:CONVERGE` (pick verified best).
- **5-Gate Learning:** `kintsugi_sandbox.py evolve learn --spec /tmp/scar.json --state-dir /tmp/kintsugi_sandbox_state`
  Schema/DLP -> disjoint triggers + **16-sample Canary** (0% FP) -> **2-process OS IPC Truth Gate** (`OS_SUBPROCESS_IPC_SAME_UID`, runtime assertion count for Python & Node; untrusted third-party code still requires an OS container/sandbox) -> **`detect_bug` matches `broken` AND does NOT match `fixed`** -> deterministic `revision_sha256`.
- **Export / Import Patches:** `evolve export-patch --state-dir ... --out /tmp/sandbox_learned_patch.json`; `evolve import-patch --file <patch.json> --state-dir ... [--expected-sha256 <64-hex>] [--apply] [--trust-unverified-proof]` *(stages in `quarantine_scars.json` by default; `--apply` requires `--expected-sha256` or `--trust-unverified-proof`)*.

---

## 5. Final Byte-Level Blind Audit & Status Report

- **Blind Audit on Final Bytes:** Verify 100% of acceptance criteria, zero fabricated claims, and green `verify-delivery` + `audit-deliverable`.
- **Session Status Report:** Summarize (1) Verified environment & manifest digest, (2) Active tasks & blockers, (3) Executed tests & gate verdicts (`verify-delivery`, `audit-deliverable`, `tx-guard`), (4) Learned scars / exported patches, and (5) Open decisions requiring owner sign-off.
