---
name: kintsugi-fintech-web3
description: "Focused fintech-web3 anti-patterns and verified code templates compiled by Kintsugi Harness."
tags: ["auditability", "concurrency", "cryptography", "decimal-rounding", "eip712", "financial-modeling", "fintech", "fintech-web3", "hmac", "ledger"]
# kintsugi: ignore-file (generated guardrail reference containing bad_code examples)
---

# kintsugi-fintech-web3 (`@KML/1` Machine-Native AST-IR)

```bash
kintsugi scan --staged --fail-on HIGH
```

## `@KML/1` Symbolic Guardrail Specifications (`NEG_AST => POS_AST`)

### `KL-FIN-005` · `Deterministic Wallet Derivation & Closed-Loop Sign-Recover Gate`
- `@WIRE`: `@KML/1|id=KL-FIN-005|sev=C|cat=fintech-web3|lang=py|op=DETERMINISTIC_WALLET_DERIVATION_CLOS|guard=RX#da25d8c0|neg=«except ImportError: ; wallet_addr = '0x' + os.urandom(16).hex()  # UNBACKED_RANDOM_WALLET_»|pos=«from eth_account import Account  # Fail hard if missing ; acct = Account.from_key(private_»|fp=65b20f5eabd99892`
- `@TRAP`: `[Cognitive Trap] Added an `except ImportError:` fallback that generated random hex bytes when `eth_account` was missing in a virtualenv, creating unbacked payout addresses with no matching private key.`
- `@LAW`: `[Mental Model] Never fallback to random bytes when deriving cryptographic addresses; fail hard if signing libraries are missing and require a closed-loop `recover(sign(msg, pk)) == address` assertion before registering any payout address.`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
except ImportError:
    wallet_addr = '0x' + os.urandom(16).hex()  # UNBACKED_RANDOM_WALLET_FALLBACK
```

`@POS_AST` (`✅ REQUIRED`):
```python
from eth_account import Account  # Fail hard if missing
acct = Account.from_key(private_key)
```

### `KL-FIN-003` · `Atomic Ledger Locking (TOCTOU) & Symmetric Decimal Scaling Guard`
- `@WIRE`: `@KML/1|id=KL-FIN-003|sev=C|cat=fintech-web3|lang=py,deci|op=ATOMIC_LEDGER_LOCKING_TOCTOU_SYMMETR|guard=RX#a27a16c6|neg=«bal = db.query('SELECT balance FROM accounts WHERE id = :id')  # TOCTOU_UNLOCKED_LEDGER_DE»|pos=«rows = db.execute('UPDATE accounts SET balance = balance - :amt WHERE id = :id AND balance»|fp=644ebe7e94a98f96`
- `@TRAP`: `[Cognitive Trap] Checked account balance at t1 (`SELECT balance`) and deducted at t2 without row-level locking or atomic conditional debit, while rounding 18-decimal internal units down on debit and up on 6-decimal payout.`
- `@LAW`: `[Mental Model] Concurrent withdrawals race between unlocked reads and writes (`TOCTOU_UNLOCKED_LEDGER_DEBIT`). Enforce atomic `UPDATE ... WHERE balance >= amount` (or `SELECT ... FOR UPDATE`) and use identical floor-quantized atomic units for both debit and payout.`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
bal = db.query('SELECT balance FROM accounts WHERE id = :id')  # TOCTOU_UNLOCKED_LEDGER_DEBIT
```

`@POS_AST` (`✅ REQUIRED`):
```python
rows = db.execute('UPDATE accounts SET balance = balance - :amt WHERE id = :id AND balance >= :amt')
```

### `KL-FIN-004` · `Bind cryptographic signatures to (chainId, verifyingContract, nonce, deadline) and update vault shares before external calls`
- `@WIRE`: `@KML/1|id=KL-FIN-004|sev=C|cat=fintech-web3|lang=py,deci|op=BIND_CRYPTOGRAPHIC_SIGNATURES_TO_CHA|guard=RX#59883754|neg=«digest = keccak256(user, amount)  # UNSCOPED_SIGNATURE_MISSING_NONCE_CHAINID»|pos=«digest = keccak256(chain_id, verifying_contract, user, amount, nonce, deadline)»|fp=876ac058f9334f23`
- `@TRAP`: `[Cognitive Trap] Verified a withdrawal signature without binding `(chainId, verifyingContract, nonce, deadline)` and transferred vault assets before burning shares, exposing mid-callback share price skew.`
- `@LAW`: `[Mental Model] Unscoped signatures enable cross-context replay, and transferring assets before burning shares creates a read-only reentrancy window where `totalAssets / totalSupply` is artificially depressed.`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
digest = keccak256(user, amount)  # UNSCOPED_SIGNATURE_MISSING_NONCE_CHAINID
```

`@POS_AST` (`✅ REQUIRED`):
```python
digest = keccak256(chain_id, verifying_contract, user, amount, nonce, deadline)
```

### `KL-FIN-001` · `Use constant-time hmac.compare_digest() for webhook and payment signatures`
- `@WIRE`: `@KML/1|id=KL-FIN-001|sev=H|cat=fintech-web3|lang=py|op=USE_CONSTANT-TIME_HMAC_COMPARE_DIGES|guard=RX#d5495195|neg=«if webhook_signature == expected_hmac_digest: ; credit_ledger()»|pos=«import hmac ; if hmac.compare_digest(webhook_signature, expected_hmac_digest): ; credit_le»|fp=d85dcb056ccc2b4a`
- `@TRAP`: `[Cognitive Trap] Compared `webhook_signature == expected_hmac_digest` using standard string equality `==`.`
- `@LAW`: `[Mental Model] Standard `==` short-circuits on the first mismatched byte, leaking signature bytes via microsecond timing side channels; always use `hmac.compare_digest`.`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
if webhook_signature == expected_hmac_digest:
    credit_ledger()
```

`@POS_AST` (`✅ REQUIRED`):
```python
import hmac
if hmac.compare_digest(webhook_signature, expected_hmac_digest):
    credit_ledger()
```

### `KL-FIN-002` · `Never hardcode calculated sum/margin totals into financial spreadsheet cells; emit live Excel formulas`
- `@WIRE`: `@KML/1|id=KL-FIN-002|sev=H|cat=fintech-web3|lang=py|op=NEVER_HARDCODE_CALCULATED_SUM_MARGIN|guard=RX#9275c080|neg=«ws["B10"] = 48500.0  # HARDCODED_XLSX_TOTAL»|pos=«ws["B10"] = "=SUM(B2:B9)"»|fp=4acc30583b7fb417`
- `@TRAP`: `[Cognitive Trap] Computed `total = sum(rows)` in Python and wrote the static float `ws['B10'] = 48500.0` into the `.xlsx` cell, breaking spreadsheet recalculation when inputs change.`
- `@LAW`: `[Mental Model] Harvested from anthropics/skills (xlsx): Financial workbooks must remain dynamically auditable; write live Excel formulas (`=SUM(B2:B9)`) for all subtotal, tax, and margin cells.`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
ws["B10"] = 48500.0  # HARDCODED_XLSX_TOTAL
```

`@POS_AST` (`✅ REQUIRED`):
```python
ws["B10"] = "=SUM(B2:B9)"
```
