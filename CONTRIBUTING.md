# Contributing to Kintsugi Harness

Thank you for helping make AI coding agents safer, more deterministic, and genuinely self-improving!

## Core Invariants for Pull Requests

1. **Zero Mandatory Runtime Dependencies:** Keep `src/kintsugi/` strictly on the Python 3.9+ standard library so `PreToolUse` hooks maintain `< 25ms` cold-start latency.
2. **Self-Verifying Scars Only:** Every `GoldenScar` added to `starter_pack.py` or `.kintsugi/scars.json` **must** pass `kintsugi verify-ledger`:
   - `scan(scar.bad_code)` returns **at least 1 finding** (True Positive).
   - `scan(scar.good_code)` returns **0 findings** (Zero False Positive).
3. **Dogfood Cleanliness:** Running `kintsugi scan src --fail-on LOW` must exit `0` with zero violations.

## Local Development Workflow

```bash
git clone https://github.com/tunguyen1993/kintsugi-harness.git
cd kintsugi-harness

# Run the full zero-dependency test suite
PYTHONPATH=src python3 -m unittest discover -s tests -v

# Verify all Golden Scars and dogfood scanner
PYTHONPATH=src python3 -m kintsugi verify-ledger
PYTHONPATH=src python3 -m kintsugi scan src --fail-on LOW
```

## Submitting a New Golden Scar

1. Open an issue using the **Golden Scar Proposal** template or submit a PR directly.
2. Provide a real-world failure root cause, minimal `bad_code`, idiomatic `good_code`, and either an `ast_rule` or a linear-time `regex_pattern`.
3. Add a corresponding unit test in `tests/`.
