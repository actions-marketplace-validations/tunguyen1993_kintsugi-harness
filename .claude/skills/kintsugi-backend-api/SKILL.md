---
name: kintsugi-backend-api
description: "Focused backend-api anti-patterns and verified code templates compiled by Kintsugi Harness."
tags: ["github-opensource", "github-roamer", "learn-and-practice"]
---

# kintsugi-backend-api (`@KML/1` Machine-Native AST-IR)

```bash
kintsugi scan --staged --fail-on HIGH
```

## `@KML/1` Symbolic Guardrail Specifications (`NEG_AST => POS_AST`)

### `KS-WILD-501` · `@OP/1[ID:KS-WILD-501|SEV:HIGH|CAT:backend-api|LANG:py|OP:http!429->retry_after_jitter]`
- `@WIRE`: `@KML/1|id=KS-WILD-501|sev=H|cat=backend-api|lang=py|op=http!429->retry_after_jitter|guard=RX#7a24a794|neg=«if resp.status_code == 429: ; time.sleep(1)  # FIXED_BLIND_429_SLEEP»|pos=«if resp.status_code == 429: ; time.sleep(float(resp.headers.get('Retry-After', 5)) + 0.5)»|fp=b06a70642a48acdb`
- `@TRAP`: `@TRAP/1{guard:RX#7a24a794,fault:BACKEND-API_VIOLATION,origin:OP/1,tags:[github-roamer,learn-and-practice,github-opensource]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:if_resp.status_code_429:,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
if resp.status_code == 429:
    time.sleep(1)  # FIXED_BLIND_429_SLEEP
```

`@POS_AST` (`✅ REQUIRED`):
```python
if resp.status_code == 429:
    time.sleep(float(resp.headers.get('Retry-After', 5)) + 0.5)
```

### `KS-WILD-506` · `@OP/1[ID:KS-WILD-506|SEV:HIGH|CAT:backend-api|LANG:py|OP:sha256!raw_bytes->no_bom_strip]`
- `@WIRE`: `@KML/1|id=KS-WILD-506|sev=H|cat=backend-api|lang=py|op=sha256!raw_bytes->no_bom_strip|guard=RX#d88ab699|neg=«proof_sha = hashlib.sha256(raw_bytes.decode('utf-8-sig').encode('utf-8')).hexdigest()  # B»|pos=«proof_sha = hashlib.sha256(raw_bytes).hexdigest() ; parsed = json.loads(raw_bytes.decode('»|fp=a307ce1e2eee3bac`
- `@TRAP`: `@TRAP/1{guard:RX#d88ab699,fault:BACKEND-API_VIOLATION,origin:OP/1,tags:[github-roamer,learn-and-practice,github-opensource]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:proof_sha_hashlib.sha256_raw_bytes_.hexdiges,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
proof_sha = hashlib.sha256(raw_bytes.decode('utf-8-sig').encode('utf-8')).hexdigest()  # BOM_STRIP_BEFORE_HASH
```

`@POS_AST` (`✅ REQUIRED`):
```python
proof_sha = hashlib.sha256(raw_bytes).hexdigest()
parsed = json.loads(raw_bytes.decode('utf-8-sig'))
```

### `KS-WILD-507` · `@OP/1[ID:KS-WILD-507|SEV:HIGH|CAT:backend-api|LANG:py|OP:http!wild->explicit_timeout]`
- `@WIRE`: `@KML/1|id=KS-WILD-507|sev=H|cat=backend-api|lang=py|op=http!wild->explicit_timeout|guard=RX#ec3c84de|neg=«resp = httpx_client_get(endpoint_url)  # WILD_HTTP_NO_TIMEOUT»|pos=«resp = httpx_client_get(endpoint_url, timeout=10.0)»|fp=6da2ae52043067b1`
- `@TRAP`: `@TRAP/1{guard:RX#ec3c84de,fault:BACKEND-API_VIOLATION,origin:OP/1,tags:[github-roamer,learn-and-practice,github-opensource]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:resp_httpx_client_get_endpoint_url,_timeout_,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
resp = httpx_client_get(endpoint_url)  # WILD_HTTP_NO_TIMEOUT
```

`@POS_AST` (`✅ REQUIRED`):
```python
resp = httpx_client_get(endpoint_url, timeout=10.0)
```
