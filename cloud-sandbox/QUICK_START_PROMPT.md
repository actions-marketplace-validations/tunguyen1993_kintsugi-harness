# ONE-SHOT ACTIVATION & PINNED UPDATE PROMPT (KINTSUGI v3.1.1 · CLOUD SANDBOX EDITION)

> Paste this prompt into **any fresh Cloud Sandbox or AI coding-agent session** to bootstrap `Kintsugi Harness v3.1.1` from a pinned GitHub commit (`tunguyen1993/kintsugi-harness`), **verify `bootstrap.py`'s SHA-256 BEFORE executing it**, validate `manifest.json` fail-closed (`allow_pycache=False`), run the `17/17` self-test suite, and enforce Dual-Pincer verification for the entire session.
> *(Replace `<40-hex-commit-sha>`, `<64-hex-bootstrap-sha256>`, and `<64-hex-manifest-sha256>` with the out-of-band digests from the GitHub release.)*

---

```text
Bootstrap and verify Kintsugi Harness v3.1.1 (Cloud Sandbox Edition) from the pinned GitHub commit inside this sandbox:

1. Download `bootstrap.py` from the pinned commit, verify its SHA-256 BEFORE executing it, install fail-closed, and run the 17/17 self-test:
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
   (Pinned installs refuse downgrading to TOFU unless `--allow-unpinned-downgrade` is passed explicitly.
   If outbound network access is blocked, use the offline bundle `/mnt/data/kintsugi_v3_cloud_sandbox_edition.zip` or a repo `.tar.gz`/`.zip`,
   extract `bootstrap.py` to `/tmp/k_boot.py`, verify its SHA-256 matches `<64-hex-bootstrap-sha256>`, and install strictly via:
   `python3 -B /tmp/k_boot.py --source-archive /mnt/data/<archive> --require-pin --expected-bootstrap-sha256 <64-hex-bootstrap-sha256> --expected-manifest-sha256 <64-hex-manifest-sha256> --dest /tmp/kintsugi_sandbox`
   — never raw-unzip directly over `/tmp/kintsugi_sandbox`.)

2. Read `/tmp/kintsugi_sandbox/AGENT_INSTRUCTIONS.md` and `/tmp/kintsugi_sandbox/TASKS.md`, and enforce them strictly for the entire session:
   - Owner instructions have highest precedence; if any material risk is detected, stop immediately, explain risk + impact + mitigation, and wait for explicit approval.
   - Zero-Outbound Policy: run `kintsugi_sandbox.py tx-guard` before any transaction or signing flow (blocks non-zero `transaction.value`, `deposit_required`, `entry_fee`, `transfers_funds`, `send_value`, `outbound_transfer`, outbound actions, and card gates; flags unknown signing actions as `NEEDS_OWNER_DECISION`; only `PASS_READONLY_0_OUTBOUND` passes automatically).
   - Financial verification always uses `ledger-check` (exact rational `Fraction` half-tick rounding).
   - Dual-Pincer Kintsugi v3.1.1:
     + Pre-Read: `brief [file] --task "<summary>" --state-dir /tmp/kintsugi_sandbox_state --mark-included` (<500 compact tokens, allocates `envelope_id`, draws from 9 Capsules + 80 Pitfalls `LT-001..LT-080` + active learned scars).
     + Post-Write: real tests + `verify-delivery <path> --envelope-id <id> --state-dir /tmp/kintsugi_sandbox_state [--confirm-included]` (DLP/AST, fail-closed `INCOMPLETE_SCAN` on uninspected binaries unless `scan --allow-binary`, exact `content_sha256` + `DeliveryTelemetry/1` 2-Strike) + `audit-deliverable <path>` (`LT-053/054/055/062`).
   - 5-Gate Closed-Loop Self-Evolution: after fixing a novel bug class, run `evolve learn --spec /tmp/scar.json --state-dir /tmp/kintsugi_sandbox_state` (16-sample Canary + 2-process OS IPC Truth Gate `OS_SUBPROCESS_IPC_SAME_UID` with runtime assertion counting for Python & Node + `detect_bug` matching `broken` and NOT matching `fixed`); export deltas with `evolve export-patch --state-dir /tmp/kintsugi_sandbox_state --out /tmp/sandbox_learned_patch.json` (live `evolve import-patch --apply` requires `--expected-sha256 <64-hex>` or `--trust-unverified-proof`; default stages safely in `quarantine_scars.json`).
   - When asked to "update harness", run `kintsugi_sandbox.py update --ref <40-hex-commit-sha> --require-pin --require-full-sha --expected-manifest-sha256 <64-hex-manifest-sha256> --dest /tmp/kintsugi_sandbox`.

3. Report the concise `boot` + `self-test` (`17/17 PASS_100`), `bootstrap_sha256`, and `manifest_sha256` summary, then wait for the first task.
```
