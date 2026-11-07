---
name: kintsugi-backend-api
description: "Focused backend-api anti-patterns and verified code templates compiled by Kintsugi Harness."
tags: ["asyncio", "backend-api", "cache-poisoning", "cdn-cache", "concurrency", "data-integrity", "data-leakage", "event-loop", "http-redirect", "latency"]
# kintsugi: ignore-file (generated guardrail reference containing bad_code examples)
---

# kintsugi-backend-api (`@KML/1` Machine-Native AST-IR)

```bash
kintsugi scan --staged --fail-on HIGH
```

## `@KML/1` Symbolic Guardrail Specifications (`NEG_AST => POS_AST`)

### `KL-API-002` · `Multi-Tenant Cache & Secondary Query Isolation: Always prefix cache keys with tenant_id`
- `@WIRE`: `@KML/1|id=KL-API-002|sev=C|cat=backend-api|lang=py,ts|op=MULTI-TENANT_CACHE_SECONDARY_QUERY_I|guard=RX#43051a0a|neg=«cached = redis_client.get(f"record:{record_id}")  # UNSCOPED_MULTI_TENANT_CACHE_KEY»|pos=«cached = redis_client.get(f"tenant:{tenant_id}:record:{record_id}")»|fp=f0b833c7f6a70e70`
- `@TRAP`: `[Cognitive Trap] Filtered the primary SQL query by `tenant_id`, but keyed the Redis cache lookup by bare `record_id` (`cache.get(f'record:{record_id}')`), leaking cached records across tenants.`
- `@LAW`: `[Mental Model] Every secondary retrieval path, cache key, and export job must bind the authenticated `tenant_id` (`f'tenant:{tenant_id}:record:{record_id}'`); row-level security on the DB does not protect an unscoped cache hit.`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
cached = redis_client.get(f"record:{record_id}")  # UNSCOPED_MULTI_TENANT_CACHE_KEY
```

`@POS_AST` (`✅ REQUIRED`):
```python
cached = redis_client.get(f"tenant:{tenant_id}:record:{record_id}")
```

### `KL-API-001` · `Never call synchronous time.sleep() inside an async def coroutine`
- `@WIRE`: `@KML/1|id=KL-API-001|sev=H|cat=backend-api|lang=py|op=fn:backoff!enforce_invariant|guard=RX#c488f400|neg=«async def backoff(): ; time.sleep(2)  # BLOCKING_ASYNC_SLEEP»|pos=«async def backoff(): ; await asyncio.sleep(2)»|fp=99df83bef59038ab`
- `@TRAP`: `[Cognitive Trap] Used `time.sleep(seconds)` for retry backoff inside an `async def` handler thinking it only pauses the current request.`
- `@LAW`: `[Mental Model] Cooperative event loops run on a single OS thread; a synchronous `time.sleep()` freezes every concurrent WebSocket and HTTP request on the worker.`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
async def backoff():
    time.sleep(2)  # BLOCKING_ASYNC_SLEEP
```

`@POS_AST` (`✅ REQUIRED`):
```python
async def backoff():
    await asyncio.sleep(2)
```

### `KL-API-003` · `HTTP Redirect Effective-Host Verification & Verbatim Raw-Byte Archival`
- `@WIRE`: `@KML/1|id=KL-API-003|sev=H|cat=backend-api|lang=py|op=HTTP_REDIRECT_EFFECTIVE-HOST_VERIFIC|guard=RX#8027d188|neg=«if resp.status == 200: ; mark_fulltext_valid(json.dumps(json.loads(raw), indent=2))  # UNV»|pos=«assert urlparse(resp.geturl()).hostname == expected_host ; Path(raw_path).write_bytes(raw_»|fp=5234a125516b3363`
- `@TRAP`: `[Cognitive Trap] Treated `resp.status == 200` after redirects as valid full-text retrieval even when redirected to an `/unblock` or captcha interstitial, and re-serialized JSON via `json.dumps(indent=2)` instead of slicing raw bytes.`
- `@LAW`: `[Mental Model] Always verify `urllib.parse.urlparse(resp.geturl()).hostname == expected_host`, send `Cache-Control: no-cache`, and archive/slice the verbatim `raw_bytes` before parsing.`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
if resp.status == 200:
    mark_fulltext_valid(json.dumps(json.loads(raw), indent=2))  # UNVERIFIED_REDIRECT_AND_RESERIALIZED_RAW
```

`@POS_AST` (`✅ REQUIRED`):
```python
assert urlparse(resp.geturl()).hostname == expected_host
Path(raw_path).write_bytes(raw_bytes)
```
