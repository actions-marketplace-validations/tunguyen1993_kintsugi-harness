---
name: kintsugi-crypto-auth-logic
description: "Focused crypto-auth-logic anti-patterns and verified code templates compiled by Kintsugi Harness."
tags: ["audience-binding", "canonical-delimiter", "constant-time-compare", "cross-tenant-auth", "gemini38-deepseek", "hash-length-extension", "kml:v1", "logic-evolution", "timing-side-channel"]
---

# kintsugi-crypto-auth-logic (`@KML/1` Machine-Native AST-IR)

```bash
kintsugi scan --staged --fail-on HIGH
```

## `@KML/1` Symbolic Guardrail Specifications (`NEG_AST => POS_AST`)

### `KS-LOGIC-019` · `@OP/1[ID:KS-LOGIC-019|SEV:CRITICAL|CAT:crypto-auth-logic|LANG:py|OP:DIRECT_STRING_EQ_MAC_VERIFY->HMAC_CO]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-019|sev=C|cat=crypto-auth-logic|lang=py|op=DIRECT_STRING_EQ_MAC_VERIFY->HMAC_CO|guard=RX#b40ad976|neg=«if computed_hmac_hex == header_signature_hex:  # NON_CONSTANT_TIME_SIGNATURE_EQUALITY ; al»|pos=«if hmac.compare_digest(computed_hmac_hex, header_signature_hex): ; allow_request()»|fp=85762c2b23a7c55d`
- `@TRAP`: `@TRAP/1{guard:RX#b40ad976,fault:CRYPTO-AUTH-LOGIC_VIOLATION,origin:OP/1,tags:[logic-evolution,timing-side-channel,constant-time-compare,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:if_hmac.compare_digest_computed_hmac_hex,_he,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
if computed_hmac_hex == header_signature_hex:  # NON_CONSTANT_TIME_SIGNATURE_EQUALITY
    allow_request()
```

`@POS_AST` (`✅ REQUIRED`):
```python
if hmac.compare_digest(computed_hmac_hex, header_signature_hex):
    allow_request()
```

### `KS-LOGIC-020` · `@OP/1[ID:KS-LOGIC-020|SEV:CRITICAL|CAT:crypto-auth-logic|LANG:py|OP:UNSCOPED_TOKEN_SUBJECT_TRUST->STRICT]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-020|sev=C|cat=crypto-auth-logic|lang=py|op=UNSCOPED_TOKEN_SUBJECT_TRUST->STRICT|guard=RX#4e3f56c3|neg=«if jwt_claims.get('sub') and jwt_claims.get('exp') > now_ts:  # MISSING_TENANT_SCOPE_BINDI»|pos=«if jwt_claims.get('sub') and jwt_claims.get('exp') > now_ts and jwt_claims.get('tenant_id'»|fp=dc015707cdaa1873`
- `@TRAP`: `@TRAP/1{guard:RX#4e3f56c3,fault:CRYPTO-AUTH-LOGIC_VIOLATION,origin:OP/1,tags:[logic-evolution,cross-tenant-auth,audience-binding,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:if_jwt_claims.get_sub_and_jwt_claims.get_exp,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
if jwt_claims.get('sub') and jwt_claims.get('exp') > now_ts:  # MISSING_TENANT_SCOPE_BINDING_CHECK
    return load_tenant_vault(req.tenant_id)
```

`@POS_AST` (`✅ REQUIRED`):
```python
if jwt_claims.get('sub') and jwt_claims.get('exp') > now_ts and jwt_claims.get('tenant_id') == req.tenant_id:
    return load_tenant_vault(req.tenant_id)
```

### `KS-LOGIC-021` · `@OP/1[ID:KS-LOGIC-021|SEV:CRITICAL|CAT:crypto-auth-logic|LANG:py|OP:UNSEPARATED_FIELD_CONCAT_HASH->LENGT]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-021|sev=C|cat=crypto-auth-logic|lang=py|op=UNSEPARATED_FIELD_CONCAT_HASH->LENGT|guard=RX#0e5b679c|neg=«digest = hashlib.sha256((role + resource + action).encode()).hexdigest()  # AMBIGUOUS_CONC»|pos=«digest = hashlib.sha256(json.dumps([role, resource, action]).encode()).hexdigest()»|fp=c5b2c40cda9fb807`
- `@TRAP`: `@TRAP/1{guard:RX#0e5b679c,fault:CRYPTO-AUTH-LOGIC_VIOLATION,origin:OP/1,tags:[logic-evolution,hash-length-extension,canonical-delimiter,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:digest_hashlib.sha256_json.dumps_role,_resou,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
digest = hashlib.sha256((role + resource + action).encode()).hexdigest()  # AMBIGUOUS_CONCATENATION_HASH_COLLISION
```

`@POS_AST` (`✅ REQUIRED`):
```python
digest = hashlib.sha256(json.dumps([role, resource, action]).encode()).hexdigest()
```
