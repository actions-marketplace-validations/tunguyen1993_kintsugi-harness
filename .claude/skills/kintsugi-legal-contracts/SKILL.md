---
name: kintsugi-legal-contracts
description: "Focused legal-contracts anti-patterns and verified code templates compiled by Kintsugi Harness."
tags: ["contracts", "freelance", "indemnification", "intellectual-property", "legal", "legal-contracts", "liability-cap", "licensing", "model:gemini-pro", "model:gpt-6-frontier"]
# kintsugi: ignore-file (generated guardrail reference containing bad_code examples)
---

# kintsugi-legal-contracts (`@KML/1` Machine-Native AST-IR)

```bash
kintsugi scan --staged --fail-on HIGH
```

## `@KML/1` Symbolic Guardrail Specifications (`NEG_AST => POS_AST`)

### `KL-LEG-001` · `Contract Liability Cap: Never sign agreements with uncapped consequential damages or unilateral indemnity`
- `@WIRE`: `@KML/1|id=KL-LEG-001|sev=C|cat=legal-contracts|lang=cont,deci,mark|op=CONTRACT_LIABILITY_CAP_NEVER_SIGN_AG|guard=RX#e7fd2226|neg=«CLAUSE: ACCEPT_UNLIMITED_CONSEQUENTIAL_LIABILITY(liability_cap='UNCAPPED')»|pos=«CLAUSE: ENFORCE_MUTUAL_LIABILITY_CAP(liability_cap='12_MONTHS_FEES_PAID', exclude_conseque»|fp=4d5d5e1e88fdcf7b`
- `@TRAP`: `[Cognitive Trap] Signed a standard enterprise vendor MSA without checking the limitation of liability clause, exposing personal or company assets to unlimited consequential damages.`
- `@LAW`: `[Mental Model] Every commercial contract must cap aggregate liability to a deterministic multiple of fees actually paid (typically 12 months of fees) and exclude indirect/consequential damages.`

`@NEG_AST` (`❌ FORBIDDEN`):
```contract
CLAUSE: ACCEPT_UNLIMITED_CONSEQUENTIAL_LIABILITY(liability_cap='UNCAPPED')
```

`@POS_AST` (`✅ REQUIRED`):
```contract
CLAUSE: ENFORCE_MUTUAL_LIABILITY_CAP(liability_cap='12_MONTHS_FEES_PAID', exclude_consequential=True)
```

### `KL-LEG-002` · `Background IP Retention: Carve out pre-existing tools, frameworks, and harnesses from client IP assignment clauses`
- `@WIRE`: `@KML/1|id=KL-LEG-002|sev=C|cat=legal-contracts|lang=cont,deci,mark|op=BACKGROUND_IP_RETENTION_CARVE_OUT_PR|guard=RX#bf6624a1|neg=«IP_CLAUSE: ASSIGN_ALL_BACKGROUND_TOOLS_AND_FRAMEWORKS_TO_CLIENT()»|pos=«IP_CLAUSE: RETAIN_BACKGROUND_IP_AND_ASSIGN_CUSTOM_DELIVERABLES_ONLY(license='non_exclusive»|fp=f0159a1b4d2311ae`
- `@TRAP`: `[Cognitive Trap] Signed a work-for-hire agreement assigning 'all tools, scripts, and know-how used during the engagement', accidentally transferring ownership of your proprietary harness.`
- `@LAW`: `[Mental Model] Always separate Background IP (your reusable engines, libraries, and methodologies) from Foreground Deliverables: retain 100% ownership of Background IP and grant the client a non-exclusive license.`

`@NEG_AST` (`❌ FORBIDDEN`):
```contract
IP_CLAUSE: ASSIGN_ALL_BACKGROUND_TOOLS_AND_FRAMEWORKS_TO_CLIENT()
```

`@POS_AST` (`✅ REQUIRED`):
```contract
IP_CLAUSE: RETAIN_BACKGROUND_IP_AND_ASSIGN_CUSTOM_DELIVERABLES_ONLY(license='non_exclusive_perpetual')
```
