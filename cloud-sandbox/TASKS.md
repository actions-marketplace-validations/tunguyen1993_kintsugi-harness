# TASKS.md — ENGINEERING PLAYBOOK & OPERATIONAL RUNBOOK (KINTSUGI CLOUD SANDBOX v3.1.1)

> **Scope:** General-purpose operational handbook for autonomous coding and auditing agents running `Kintsugi Harness v3.1.1 — Cloud Sandbox Edition` (`9` Capsules · `80` Pitfalls · `16` Canaries · `17/17` Self-Test) inside ephemeral Linux/macOS cloud sandboxes.
> **Fail-Closed DLP Standard:** 100% clean open-source bundle — zero secrets, zero private keys, zero cookies, zero API tokens, zero private RFC-1918 LAN IPs, zero host filesystem paths, and zero PII.

---

## 0. Governance Laws & Session Bootstrap (15 Seconds)

### Core Non-Negotiable Principles
1. **Owner Decision Authority:** Explicit instructions from the workspace owner supersede automated heuristics. Whenever a material risk appears (asset loss, credential exposure, destructive overwrites, policy violations, ambiguous authorization), **STOP the affected step immediately**, report *(a) concrete risk, (b) impact, (c) recommended mitigation + rationale*, and wait for explicit confirmation.
2. **Zero-Outbound Policy (`tx-guard`):**
   - **Block 100%:** non-zero `transaction.value`, `deposit_required=true`, `entry_fee > 0`, `transfers_funds=true`, `send_value != 0`, `outbound_transfer=true`, outbound methods (`eth_sendTransaction`, `eth_sendRawTransaction`, `erc20_transfer`, `erc20_approve`, `transferWithAuthorization`, `swap`, `bridge`, `stake`, `deposit`, `loan`), and payment-card identity gates.
   - **Allow Read-Only / Zero-Value Auth:** `personal_sign`, `eip191`, `ed25519_auth`, `siwe`, `read_only`, `none`.
   - **Require Owner Decision (`NEEDS_OWNER_DECISION`):** unknown signing/transaction actions, KYC flows, or explicit `owner_approval_required=true`.
3. **Fail-Closed Data Loss Prevention (DLP):** Never request, persist, or emit passwords, seed phrases, private keys, API tokens, cookies, internal transcripts, or user PII.

### Supply-Chain Bootstrap & Self-Update (`bootstrap.py` v3.1.1)
```bash
# Option 1A — Pinned Supply-Chain Install (RECOMMENDED · Verify bootstrap.py SHA-256 BEFORE execution):
# Obtain <40-hex-commit-sha>, <64-hex-bootstrap-sha256>, and <64-hex-manifest-sha256> out-of-band:
curl -fsSL https://raw.githubusercontent.com/tunguyen1993/kintsugi-harness/<40-hex-commit-sha>/cloud-sandbox/bootstrap.py -o /tmp/k_boot.py \
  && python3 -B -c "import hashlib,pathlib,sys; h=hashlib.sha256(pathlib.Path('/tmp/k_boot.py').read_bytes()).hexdigest(); sys.exit(0 if h=='<64-hex-bootstrap-sha256>' else f'BOOTSTRAP_SHA256_MISMATCH: {h}')" \
  && python3 -B /tmp/k_boot.py \
     --ref <40-hex-commit-sha> \
     --require-pin --require-full-sha \
     --expected-bootstrap-sha256 <64-hex-bootstrap-sha256> \
     --expected-manifest-sha256 <64-hex-manifest-sha256> \
     --dest /tmp/kintsugi_sandbox \
  && python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py boot \
  && python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py self-test

# (On Linux sandboxes you can verify the launcher with:
#   echo "<64-hex-bootstrap-sha256>  /tmp/k_boot.py" | sha256sum -c -
#  `--expected-bootstrap-sha256` also makes bootstrap.py self-hash via O_NOFOLLOW as a second layer.)

# Option 1B — Standard TOFU Install on `main` (quick prototyping, unpinned):
curl -fsSL https://raw.githubusercontent.com/tunguyen1993/kintsugi-harness/main/cloud-sandbox/bootstrap.py -o /tmp/k_boot.py \
  && python3 -B /tmp/k_boot.py --ref main --dest /tmp/kintsugi_sandbox \
  && python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py boot \
  && python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py self-test

# Hot Update within a Session (preserves pin continuity):
# Note: A pinned install (`PINNED_MANIFEST_SHA256`) refuses unpinned TOFU downgrades (`REFUSING_PIN_DOWNGRADE_TO_TOFU`)
# unless `--allow-unpinned-downgrade` is explicitly passed to `bootstrap.py`.
python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py update \
  --ref <40-hex-commit-sha> \
  --expected-manifest-sha256 <64-hex-manifest-sha256> \
  --require-pin --require-full-sha \
  --dest /tmp/kintsugi_sandbox
# Explicit opt-in downgrade to TOFU (only with owner approval):
python3 -B /tmp/k_boot.py --ref main --allow-unpinned-downgrade --dest /tmp/kintsugi_sandbox

# Option 2 — Offline Archive Install (when sandbox blocks outbound network):
# `bootstrap.py --source-archive` natively supports both:
#   (a) GitHub repo archive `.tar.gz`/`.zip` (`<root>/cloud-sandbox/...` + `<root>/src/kintsugi/*.py`), AND
#   (b) Flat standalone offline bundle `kintsugi_v3_cloud_sandbox_edition.zip` (`<prefix>/kintsugi_sandbox.py`, `manifest.json`, `bootstrap.py`, `data/`, `src/kintsugi/*.py`).
python3 -B -c "import hashlib,pathlib,sys,zipfile; zf=zipfile.ZipFile('/mnt/data/kintsugi_v3_cloud_sandbox_edition.zip'); m=[n for n in zf.namelist() if n.endswith('/bootstrap.py')][0]; data=zf.read(m); h=hashlib.sha256(data).hexdigest(); sys.exit(f'BOOTSTRAP_SHA256_MISMATCH: {h}') if h!='<64-hex-bootstrap-sha256>' else pathlib.Path('/tmp/k_boot.py').write_bytes(data)" \
  && python3 -B /tmp/k_boot.py \
     --source-archive /mnt/data/kintsugi_v3_cloud_sandbox_edition.zip \
     --require-pin \
     --expected-bootstrap-sha256 <64-hex-bootstrap-sha256> \
     --expected-manifest-sha256 <64-hex-manifest-sha256> \
     --dest /tmp/kintsugi_sandbox \
  && python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py verify-manifest --expected-sha256 <64-hex-manifest-sha256> \
  && python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py self-test
```
> **Safety Notes:**
> - **Never** raw-extract (`unzip`/`tar`) directly over a live `/tmp/kintsugi_sandbox` directory; always install via `bootstrap.py --source-archive` to enforce Tar/Zip-Slip guards, symlink rejection, SHA-256 verification, clean-env smoke tests, atomic swap with rollback, git checkout protection (`REFUSING_GIT_CHECKOUT_DEST`), and user-file protection (`REFUSING_DEST_WITH_USER_FILES`).
> - Always invoke Python with `-B` (`PYTHONDONTWRITEBYTECODE=1`) so `__pycache__`/`.pyc` files are not created inside the verified bundle (`verify-manifest` enforces strict `allow_pycache=False`).
> - Begin task execution only after `boot` reports `READY` (`9` Capsules, `80` Pitfalls `LT-001..LT-080`, `24` CRS scars) and `self-test` reports **`PASS_100` (`17/17`)**.

---

## 1. Standard 6-Step Engineering Workflow

### Step 1 — Pre-Flight Policy Check (`tx-guard`)
Before invoking any external signing, payment, or transaction policy workflow, run `tx-guard`:
```bash
python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py tx-guard --payload '{
  "status": "open",
  "deposit_required": false,
  "entry_fee": 0,
  "transfers_funds": false,
  "signing": {"action": "personal_sign", "value": 0},
  "description": "Read-only session authentication"
}'
```
*(Or read from a file: `kintsugi_sandbox.py tx-guard --file /tmp/tx_policy.json`.)*
- [ ] Require **`PASS_READONLY_0_OUTBOUND`** (`tx-guard` normalizes NFKC, strips zero-width format characters, recursively inspects nested objects/lists, rejects duplicate keys and alias conflicts, blocks non-zero `transaction.value`, `deposit_required`, `entry_fee`, `transfers_funds`, `send_value`, `outbound_transfer`, outbound methods, and payment-card gates, and flags unknown signing actions or KYC as `NEEDS_OWNER_DECISION`).
- [ ] If `BLOCKED` -> abort the operation and report exact block reasons; if `NEEDS_OWNER_DECISION` -> escalate to the owner.

### Step 2 — Spec Grounding & Pincer 1 (`brief` + Auto-Telemetry)
- [ ] Read 100% of the specification, acceptance criteria, output schema, and constraints verbatim.
- [ ] Use token-saving discovery tools before reading large repositories or documents:
  ```bash
  python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py scout <repo_dir>
  python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py compact <long_doc.md> --max-lines 120
  ```
- [ ] **Run Pincer 1 (`brief`)** with `--state-dir` to load matched invariants & pitfalls (`< 500` compact tokens) and allocate an `envelope_id` for `verify-delivery` (pass `--mark-included` when injecting the brief into context):
  ```bash
  python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py brief [target_file] \
    --task "<task description>" --lang auto --state-dir /tmp/kintsugi_sandbox_state --mark-included
  ```

### Step 3 — Acceptance Checklist & Evidence Grounding
- [ ] Translate every requirement into a verifiable checklist backed by real command output, unit tests, or source citations.
- [ ] Never fabricate numbers, URLs, test results, or `_simulated=True` outputs (`LT-055`). Mark any missing evidence explicitly as `"Unverified"`.

### Step 4 — Domain Execution Playbooks (`LT-051..LT-062`)

#### Playbook A — Data Engineering, HTTP API Forensics & Research
- [ ] **Raw Byte Fidelity (`LT-053`):** Hash `raw_sha256` over exact `raw_body_bytes` before JSON parsing; decode with `utf-8-sig` (handles UTF-8 BOM `\xef\xbb\xbf`); slice `excerpt` verbatim from raw text (never reformat with `json.dumps`); emit clean UTF-8 without BOM for output JSON/CSV files.
- [ ] **HTTP Freshness Verification (RFC 9111 / `LT-053`):** Send `Cache-Control: no-cache`, verify `|http_date - retrieved_utc| <= 5.0s`, inspect `Age` headers for proxy caching, and cross-check `ETag` or payload-level timestamps.
- [ ] **Multi-Pull Dataset Parity (`LT-054`):** Assert exact ordered CSV header equality (`list(h2) == list(h1)`, never `set()`), full ID parity, and row-count equality. Keep deliverable prose objective without meta-rubric wording (`evaluator`, `dispute`, `appeal`, `requirements met`).
- [ ] **Safe Retries & Redirects (`LT-058`, `LT-059`):** Retry only transient `{429, 502, 503, 504}` with `Idempotency-Key` and `Retry-After`; strip `Authorization`, `Cookie`, `X-API-Key`, and `Proxy-Authorization` across cross-origin redirects.

#### Playbook B — Software, SDK, CLI, MCP & GitHub PR Engineering
- [ ] **Contract & Signature Fidelity (`LT-001`):** Never invent nonexistent kwargs; `-> bool` verifiers must return `False` on malformed inputs instead of raising `ValueError`.
- [ ] **Core Security Invariants (`9 Capsules` + `LT-056`, `LT-060`, `LT-061`):**
  - Parameterized static SQL queries only (`?` / `%s` + tuple `(x,)`), never string interpolation.
  - Subprocess calls with `argv` lists, explicit `shell=False`, `timeout`, and metacharacter filtering (`;|&$><`\n\r\x00`).
  - Workspace path confinement via `os.path.realpath(root)`, per-segment symlink rejection, `target == root or target.startswith(root + os.sep)`, and atomic `O_NOFOLLOW` `0o600` + `os.replace`.
  - Domain-separated RFC-6962 Merkle trees (`CAP-CRYPTO-RFC6962-MERKLE`): 4-byte length prefix, `b"\x00"` leaf / `b"\x01"` internal prefix, odd trailing node promoted unchanged (`root([A,B,C]) != root([A,B,C,C])`).
  - Multi-tenant patch allowlists (`LT-056`), `'\n'` git path splitting & fenced-code-aware Markdown parsing (`LT-060`), and `fcntl.flock` + `try...finally` resource cleanup (`LT-061`).
- [ ] **Real Tests & Clean Artifacts (`LT-055`, `LT-062`):** Run full unit test suites and linters verbatim; strip `.env`, `.DS_Store`, `__pycache__`, and `.coverage` before packaging.

#### Playbook C — Financial Ledgers, Spreadsheets & Smart Contracts
- [ ] **Zero Binary Floats (`LT-002`, `LT-057`):** Use `Decimal(str(val))` with explicit quantization (`ROUND_HALF_UP`) or live spreadsheet formulas; compute atomic basis-point fees via multiply-before-divide `(amount_atomic * fee_bps) // 10_000` rejecting `bool`, negative amounts, and `fee_bps > 10_000`.
- [ ] **Exact Rational Conservation Check (`Fraction` half-tick rounding):**
  ```bash
  python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py ledger-check --lines '["0.10","0.20","19.99"]' --total '20.29' --fx 1 --quant 0.01
  ```
- [ ] **Share Vaults (`ERC-4626`):** Apply virtual offsets `V_SHARES=10**6, V_ASSETS=1`, floor on `deposit`/`redeem`, ceil on `mint`/`withdraw`, and explicitly reject `assets > 0 and shares <= 0`.
- [ ] **Cryptographic Key Derivation (`LT-051`):** Never fall back to random hex on crypto errors; fail closed (`RuntimeError`) and verify `sign -> recover == address`.

#### Playbook D — Defensive Security Auditing
- [ ] Report a vulnerability only when all 5 criteria hold:
  1. Reproducible inside a local isolated sandbox test (`100%` passing unit/invariant test — never test against live third-party systems without authorization).
  2. Reachable under realistic public/production configurations.
  3. Concrete impact on funds, data integrity, or critical access controls.
  4. Not an admin-only self-inflicted misconfiguration (`onlyOwner` footgun).
  5. Verified non-duplicate against repository history and existing disclosures.

### Step 5 — Pincer 2 (`verify-delivery` + `audit-deliverable`) & Final Blind Audit
Before handoff (and **after every single edit**):
1. Re-run all relevant automated tests on the final artifact bytes.
2. Run both v3.1.1 delivery gates (`scan` fails closed with `INCOMPLETE_SCAN` on uninspected binaries unless `--allow-binary` is passed explicitly):
   ```bash
   python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py verify-delivery <target_path> \
     --envelope-id <envelope_id_from_brief> --state-dir /tmp/kintsugi_sandbox_state [--confirm-included]

   python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py audit-deliverable <target_path>

   # When scanning a directory that intentionally includes non-text binary assets:
   python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py scan <target_dir> --allow-binary
   ```
   Require **`DELIVERY_VERIFIED_PASS`** and **`PASS_DELIVERABLE_AUDIT`** (`blocking_count == 0`, `deliverable_findings == []`).
3. Perform a blind review on the final bytes verifying 100% spec coverage, clean formatting, zero placeholders, and zero regressions.

### Step 6 — Closed-Loop Self-Evolution (`@CREED/1` + 5-Gate `evolve`)
- **`@CREED/1` 5 Pillars:** `P1:MUTATE` (2 fails -> pivot) · `P2:SYNTH` (2nd manual step -> script) · `P3:SCAR` (fix -> codify rule) · `P4:PRUNE` (trim bloat) · `P5:CONVERGE` (pick verified best).
- **Forge, Export & Import Scars:**
  ```bash
  # 1. Learn from JSON spec (or full CLI flags; supports runner auto|python|node|sqlite & role detect_bug|context_reminder):
  python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py evolve learn \
    --spec /tmp/scar_spec.json --state-dir /tmp/kintsugi_sandbox_state

  python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py evolve learn \
    --state-dir /tmp/kintsugi_sandbox_state \
    --id CSB-001 --slug my_bug_class --category logic --languages python \
    --role detect_bug --runner auto \
    --triggers '[["parse_tag","normalize_tag"],["lstrip","swapcase"]]' \
    --bad "<bug pattern>" --good "<verified fix>" --when "<precondition>" \
    --broken /tmp/broken.py --fixed /tmp/fixed.py --test /tmp/oracle_test.py

  # 2. Check status & export SHA-256 integrity-hashed DLP-clean delta patch:
  python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py evolve status --state-dir /tmp/kintsugi_sandbox_state
  python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py evolve export-patch \
    --state-dir /tmp/kintsugi_sandbox_state --out /tmp/sandbox_learned_patch.json

  # 3. Import patch (stages in quarantine_scars.json by default; live --apply requires --expected-sha256 or --trust-unverified-proof):
  python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py evolve import-patch \
    --file /tmp/sandbox_learned_patch.json \
    --expected-sha256 <64-hex-patch-sha256> \
    --state-dir /tmp/kintsugi_sandbox_state [--apply]
  ```
  A learned scar reaches **`PROMOTED_TO_LIVE_EVOLUTION_STORE`** only after passing all 5 fail-closed gates:
  1. Schema / allowlisted languages / fail-closed DLP check,
  2. `2..6` disjoint trigger groups verified against the **16-sample Canary** (`0%` FP),
  3. **2-Process OS IPC Truth Gate** (`OS_SUBPROCESS_IPC_SAME_UID` for Python & Node with runtime assertion counting, plus SQLite runner; untrusted third-party code still requires an OS container/sandbox),
  4. **Matcher-on-Broken + Negative Control on `fixed`:** for `role=detect_bug`, triggers must match `broken` AND must NOT match `fixed` (with strict single-language proof lock),
  5. Deterministic content-only `revision_sha256` + `parent_revision_sha256` + 64-revision downgrade history persisted atomically under lock. Two consecutive attributed delivery failures trigger **2-Strike Auto-Freeze**.

---

## 2. Quick Reference: 12 Operational Pitfalls (`LT-051..LT-062`) & CLI Commands

| ID | Risk Area | Mandatory Rule |
| :---: | :--- | :--- |
| `LT-051` | Wallet derivation | Never fall back to random hex; fail closed & verify `sign -> recover == address`. |
| `LT-052` | Zero-outbound guard | Block deposits/fees/card gates/non-zero `value`/`transfers_funds`/outbound actions; allow zero-value read-only auth. |
| `LT-053` | HTTP evidence | Hash `raw_body_bytes`, decode `utf-8-sig`, check RFC 9111 (`Date`+`Age`+`ETag`), verbatim `excerpt`, no BOM on output JSON/CSV. |
| `LT-054` | Multi-pull & prose | Enforce ordered CSV header equality & ID parity; ban meta-rubric words (`evaluator`, `dispute`, `appeal`, `requirements met`). |
| `LT-055` | Honest output | Never fabricate `_simulated=True`, never truncate `stdout`, reject soft-404/login walls & guessed keys. |
| `LT-056` | Multi-tenant API | Verify `tenant_id` ownership + strict field allowlist; never mutate objects in place. |
| `LT-057` | Basis-point math | Reject `bool`/negative/`>10000`; multiply before dividing `(amount * fee_bps) // 10_000`. |
| `LT-058` | HTTP 429 retries | Retry only `{429,502,503,504}`, send `Idempotency-Key`, obey `Retry-After`. |
| `LT-059` | Cross-origin redirect | Resolve via `urljoin`, cap `max_hops`, strip `Authorization`/`Cookie`/`X-API-Key` on origin change. |
| `LT-060` | Git & Markdown | Split git stdout strictly on `'\n'`; ignore Markdown headings inside fenced code blocks. |
| `LT-061` | Locks & cleanup | Use exclusive non-blocking `fcntl.flock` and close resources inside `try...finally`. |
| `LT-062` | Release hygiene | Block `.env`, `.DS_Store`, `__pycache__`, `.coverage`, PEM/API keys, RFC-1918 LAN IPs, and host user paths. |

### CLI Summary (`bootstrap.py` & `kintsugi_sandbox.py` v3.1.1)
| Operation | Command |
| :--- | :--- |
| Pinned install (`PINNED` + self-SHA check) | `python3 -B /tmp/k_boot.py --ref <40-hex> --require-pin --require-full-sha --expected-bootstrap-sha256 <64-hex> --expected-manifest-sha256 <64-hex> --dest /tmp/kintsugi_sandbox` |
| Explicit downgrade `PINNED` -> `TOFU` | `python3 -B /tmp/k_boot.py --ref main --allow-unpinned-downgrade --dest /tmp/kintsugi_sandbox` |
| Offline archive install (`.tar.gz` / `.zip`) | `python3 -B /tmp/k_boot.py --source-archive /mnt/data/<archive> --require-pin --expected-bootstrap-sha256 <64-hex> --expected-manifest-sha256 <64-hex> --dest /tmp/kintsugi_sandbox` |
| Hot update (`PINNED`) | `python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py update --ref <40-hex> --expected-manifest-sha256 <64-hex> --require-pin --require-full-sha --dest /tmp/kintsugi_sandbox` |
| Verify manifest SHA-256 (`allow_pycache=False`) | `python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py verify-manifest [--expected-sha256 <64-hex>]` |
| Boot & full self-test (`17/17`) | `python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py boot && python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py self-test` |
| Zero-outbound policy guard (`tx-guard`) | `python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py tx-guard --payload '<json>'` *(or `--file policy.json`)* |
| Pincer 1 JIT brief + `envelope_id` | `python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py brief [file] --task "<summary>" --state-dir /tmp/kintsugi_sandbox_state [--mark-included]` |
| Pincer 2 delivery gate + telemetry | `python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py verify-delivery <path> --envelope-id <id> --state-dir /tmp/kintsugi_sandbox_state [--confirm-included]` |
| Deliverable hygiene audit (`LT-053..062`) | `python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py audit-deliverable <path>` |
| Security/DLP/AST scan | `python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py scan <path> [--exclude-build-dirs] [--allow-binary]` |
| 5-gate scar learning | `python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py evolve learn --spec /tmp/scar.json --state-dir /tmp/kintsugi_sandbox_state` |
| Export integrity-hashed patch | `python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py evolve export-patch --state-dir /tmp/kintsugi_sandbox_state --out /tmp/sandbox_learned_patch.json` |
| Import patch (quarantine default) | `python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py evolve import-patch --file /tmp/patch.json --state-dir /tmp/kintsugi_sandbox_state [--expected-sha256 <64-hex>] [--apply] [--trust-unverified-proof]` |
| Exact rational ledger check (`Fraction`) | `python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py ledger-check --lines '[...]' --total '...' --fx 1 --quant 0.01` |
| 2-process IPC Truth Gate | `python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py truth-gate --broken a.py --fixed b.py --test t.py --runner auto` |
| Repository symbol scout | `python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py scout <dir> [--symbol <name>]` |
| DLP-safe document compactor | `python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py compact <file.md> --max-lines 120` |
| Telemetry report (`DeliveryTelemetry/1`) | `python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py telemetry report --state-dir /tmp/kintsugi_sandbox_state` |
