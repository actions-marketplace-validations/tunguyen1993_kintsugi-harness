# Kintsugi Harness v3.1.1 — Cloud Sandbox Edition (Modular · GitHub Self-Update · Zero-Dependency)

Apache-2.0 pure Python 3.9+ standard-library distribution (`0` external packages, no Rust toolchain required) engineered for ephemeral cloud sandboxes and AI coding-agent containers. Fail-closed DLP guarantees zero secrets, zero personal wallets, zero private LAN IPs, zero host paths, and zero PII in public bundles.

---

## 1. Modular Architecture (`cloud-sandbox/` v3.1.1)

| Component | Responsibility |
| :--- | :--- |
| `security_io.py` | Fail-closed I/O & DLP primitives: POSIX `dir_fd` + `O_NOFOLLOW\|O_NONBLOCK` containment (`os.supports_dir_fd` per-syscall), post-read `(st_dev, st_ino)` identity verification, `fcntl.flock` cross-process locking, atomic `0o600` writes + `fsync`, strict JSON parser (rejects duplicate keys & `NaN`/`Infinity`), NFKC-normalized multiline PEM + sensitive key/value DLP scanner/redactor, and bounded `iter_safe_files` with `stat_errors`/`special_inodes`. |
| `bootstrap.py` | 100% standalone stdlib supply-chain installer & self-updater (`sys.dont_write_bytecode = True`): HTTPS allowlist (`github.com`, `codeload.github.com`, `raw.githubusercontent.com`), self-SHA-256 verification (`--expected-bootstrap-sha256`), pin continuity (`REFUSING_PIN_DOWNGRADE_TO_TOFU` + `--allow-unpinned-downgrade`), git checkout & user-file protection (`REFUSING_GIT_CHECKOUT_DEST`, `REFUSING_NON_KINTSUGI_NONEMPTY_DEST`, `REFUSING_DEST_WITH_USER_FILES`), dual `.tar.gz`/`.zip` layout (GitHub repo `cloud-sandbox/` + flat standalone offline `.zip`), per-file SHA-256 verification (`allow_pycache=False`), clean-env smoke test, and atomic swap with rollback. |
| `truth_gate.py` | **Universal Truth Gate** (`python`, `node`, `sqlite`): true 2-process OS-level IPC isolation (`OS_SUBPROCESS_IPC_SAME_UID`) with hidden `oracle_path`, runtime-counted assertions (`_AssertInstrumenter` + real `unittest.main` adapter), isolated candidate stdout, private `O_CLOEXEC` verdict pipe FD + nonce, Node.js async `beforeExit` handling, Linux `VmRSS <= 384 MiB` watchdog, pre-truncation DLP redaction, and 4 built-in falsifiable contracts (`idempotency`, `decimal_fx`, `erc4626`, `ledger`). |
| `evolution_loop.py` | **5-Gate Closed-Loop Self-Evolution Engine (`evolve`)**: (1) Schema/language/DLP -> (2) 2..6 disjoint trigger groups verified against **16-sample Canary** (0% FP) -> (3) Internal Truth Gate + strict single-language proof lock for `detect_bug` -> (4) Matcher-on-Broken + negative control on `fixed` (`REJECTED_TRIGGERS_STILL_MATCH_FIXED`) -> (5) deterministic content-only `revision_sha256` + `parent_revision_sha256` + 64 `previous_revisions` downgrade shield. Supports `learn`, `status`, `export-patch`, and `import-patch` (quarantines by default; live `--apply` requires `--expected-sha256` or `--trust-unverified-proof`). |
| `scanner_sandbox.py` | Language-aware comment/string masker (`tokenize` preserves Python `//`), symbol-scoped structural AST extractor, alias-aware Python AST auditor (`SEC-SHELL-DYNAMIC`, `MAX_CONST_STR_LEN = 4096`), fail-closed `INCOMPLETE_SCAN` coverage gate on uninspected binaries (unless `--allow-binary`) / `stat_errors` / `special_inodes`, exact byte `content_sha256`, DLP-redacted findings, non-truncating `pack_brief_within_budget`, and `audit_deliverable` (`LT-053` BOM, `LT-054` meta-phrases, `LT-055` stubs, `LT-062` junk). |
| `kintsugi_sandbox.py` | Single-command CLI (`sys.dont_write_bytecode = True`): `boot`, `self-test` (`17/17`), `verify-manifest` (`allow_pycache=False`), `update`, `brief`, `verify-delivery`, `scan`, `audit-deliverable`, `tx-guard` (Zero-Outbound Agent Transaction & Policy Guard), `truth-gate`, `ledger-check` (exact rational `Fraction` half-tick rounding), `evolve`, `scout`, `compact` (pre-strip multiline PEM redaction), and `telemetry`. |
| `manifest.json` | Integrity manifest (`KintsugiCloudSandboxManifest/1`) pinning SHA-256 hashes of all files in `cloud-sandbox/` and `src/kintsugi/*.py`. |
| `AGENT_INSTRUCTIONS.md` | Compact system-prompt / project instructions (`<= 7,800` chars) ready to paste once into any Cloud Sandbox agent. |
| `QUICK_START_PROMPT.md` | One-shot activation & pinned-update prompt for any fresh Cloud Sandbox session. |
| `TASKS.md` | End-to-end engineering playbook covering 4 technical playbooks, `LT-051..LT-062`, and complete CLI reference. |
| `data/invariant_capsules_v3.json` | `9/9` Signature-Guarded Invariant Capsules. |
| `data/low_tier_pitfall_lexicon_v3.json` | `80/80` Pitfall Lexicon entries (`LT-001..LT-080`) with `trigger_groups`. |
| `data/canary_corpus_v3.json` | `16/16` clean multi-language benign samples preventing false positives in learned scars. |

---

## 2. Installation, Trust Modes & Offline Fallback

### Pinned High-Trust Install (`PINNED_MANIFEST_SHA256` — Recommended)
Obtain `<40-hex-commit-sha>`, `<64-hex-bootstrap-sha256>`, and `<64-hex-manifest-sha256>` out-of-band from the release announcement:
```bash
curl -fsSL https://raw.githubusercontent.com/tunguyen1993/kintsugi-harness/<40-hex-commit-sha>/cloud-sandbox/bootstrap.py -o /tmp/k_boot.py \
  && python3 -B -c "import hashlib,pathlib,sys; h=hashlib.sha256(pathlib.Path('/tmp/k_boot.py').read_bytes()).hexdigest(); sys.exit(0 if h=='<64-hex-bootstrap-sha256>' else f'BOOTSTRAP_SHA256_MISMATCH:{h}')" \
  && python3 -B /tmp/k_boot.py \
     --ref <40-hex-commit-sha> \
     --require-pin --require-full-sha \
     --expected-bootstrap-sha256 <64-hex-bootstrap-sha256> \
     --expected-manifest-sha256 <64-hex-manifest-sha256> \
     --dest /tmp/kintsugi_sandbox \
  && python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py boot \
  && python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py self-test
```

### Standard TOFU Install (`TOFU_UNPINNED_GITHUB_HTTPS` on `main`)
```bash
curl -fsSL https://raw.githubusercontent.com/tunguyen1993/kintsugi-harness/main/cloud-sandbox/bootstrap.py -o /tmp/k_boot.py \
  && python3 -B /tmp/k_boot.py --ref main --dest /tmp/kintsugi_sandbox \
  && python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py boot \
  && python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py self-test
```

### Offline Archive Fallback (`.tar.gz` or `.zip` via `bootstrap.py`)
If the sandbox restricts outbound network access, `bootstrap.py` returns `NETWORK_BLOCKED_USE_CLOUD_BROWSER` with direct archive URLs. Always install through `--source-archive` (never raw-unzip over `/tmp/kintsugi_sandbox`):
```bash
python3 -B /tmp/k_boot.py --source-archive /mnt/data/kintsugi-harness-main.tar.gz --dest /tmp/kintsugi_sandbox
# Or with a flat standalone offline bundle .zip (supports --expected-manifest-sha256 & --require-pin):
python3 -B /tmp/k_boot.py --source-archive /mnt/data/kintsugi_v3_cloud_sandbox_edition.zip --dest /tmp/kintsugi_sandbox
```

---

## 3. Core Agent Workflow (v3.1.1)

1. **Zero-Outbound Policy Check:** `tx-guard --payload '<json>'` -> require `PASS_READONLY_0_OUTBOUND`.
2. **Pincer 1 (Pre-Read JIT Brief):** `brief [file] --task "<summary>" --state-dir /tmp/kintsugi_sandbox_state --mark-included` -> receive `envelope_id` and `< 500`-token compact guidance.
3. **Pincer 2 (Post-Write Gate):** `verify-delivery <path> --envelope-id <id> --state-dir /tmp/kintsugi_sandbox_state [--confirm-included]` + `audit-deliverable <path>` -> verify DLP/AST, content-byte digest, deliverable hygiene, and 2-Strike telemetry.
4. **Closed-Loop Self-Evolution:** `evolve learn --spec /tmp/scar.json --state-dir /tmp/kintsugi_sandbox_state` -> `evolve export-patch --out /tmp/sandbox_learned_patch.json` -> `evolve import-patch --file <patch.json> --expected-sha256 <64-hex> [--apply]`.
