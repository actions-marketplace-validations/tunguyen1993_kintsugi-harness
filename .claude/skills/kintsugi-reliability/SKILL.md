---
name: kintsugi-reliability
description: "Focused reliability anti-patterns and verified code templates compiled by Kintsugi Harness."
tags: ["ast", "browser", "debugging", "exceptions", "golang", "hang", "http", "memory-leak", "observability", "playwright"]
# kintsugi: ignore-file (generated guardrail reference containing bad_code examples)
---

# kintsugi-reliability (`@KML/1` Machine-Native AST-IR)

```bash
kintsugi scan --staged --fail-on HIGH
```

## `@KML/1` Symbolic Guardrail Specifications (`NEG_AST => POS_AST`)

### `KS-005` · `Silent exception swallowing (bare except or except-pass)`
- `@WIRE`: `@KML/1|id=KS-005|sev=H|cat=reliability|lang=py|op=py!bare_except_pass->log_raise|guard=AST:py_silent_except_swallow|neg=«try: ; sync_records() ; except Exception: ; pass»|pos=«try: ; sync_records() ; except ConnectionError as exc: ; logger.warning('Transient sync fa»|fp=110ea00c5093d1c6`
- `@TRAP`: `Agents wrap failing blocks in bare `except:` or `except Exception: pass` to make tests turn green while hiding real data corruption or network failures.`
- `@LAW`: `Preserves KeyboardInterrupt/SystemExit propagation and forces explicit failure handling.`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
try:
    sync_records()
except Exception:
    pass
```

`@POS_AST` (`✅ REQUIRED`):
```python
try:
    sync_records()
except ConnectionError as exc:
    logger.warning('Transient sync failure: %s', exc)
    raise
```

### `KS-008` · `Unbounded synchronous HTTP call missing explicit timeout`
- `@WIRE`: `@KML/1|id=KS-008|sev=H|cat=reliability|lang=py|op=http!no_timeout->timeout=10|guard=AST:py_http_missing_timeout|neg=«import urllib.request ; resp = urllib.request.urlopen("https://example.com/api/health")»|pos=«import urllib.request ; resp = urllib.request.urlopen("https://example.com/api/health", ti»|fp=77bfd07f80230141`
- `@TRAP`: `requests.get/post and urllib.request.urlopen default to waiting indefinitely on stalled sockets, hanging CI pipelines and agent workers forever.`
- `@LAW`: `Every outbound network call must enforce a bounded socket timeout.`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
import urllib.request
resp = urllib.request.urlopen("https://example.com/api/health")
```

`@POS_AST` (`✅ REQUIRED`):
```python
import urllib.request
resp = urllib.request.urlopen("https://example.com/api/health", timeout=10)
```

### `KS-016` · `Go net/http DefaultClient call without bounded timeout`
- `@WIRE`: `@KML/1|id=KS-016|sev=H|cat=reliability|lang=go|op=go!http_client_timeout|guard=RX#de1d3b37|neg=«resp, err := http.Get("https://api.example.com/status")»|pos=«client := &http.Client{Timeout: 10 * time.Second} ; resp, err := client.Get("https://api.e»|fp=8b1dbce1e6759d33`
- `@TRAP`: `Go's package-level http.Get and http.Post helpers use http.DefaultClient, which has a default Timeout of 0 (infinite wait).`
- `@LAW`: `Explicit http.Client{Timeout: ...} prevents goroutine leaks on unresponsive upstream servers.`

`@NEG_AST` (`❌ FORBIDDEN`):
```go
resp, err := http.Get("https://api.example.com/status")
```

`@POS_AST` (`✅ REQUIRED`):
```go
client := &http.Client{Timeout: 10 * time.Second}
resp, err := client.Get("https://api.example.com/status")
```

### `KS-010` · `Headless browser launch without deterministic finally teardown`
- `@WIRE`: `@KML/1|id=KS-010|sev=M|cat=reliability|lang=js,ts,py|op=browser!launch->close_in_finally|guard=RX#0d96a8a2|neg=«const browser = await puppeteer.launch(); ; await runScrape(browser); ; await browser.clos»|pos=«const browser = await puppeteer.launch(); ; try { ; await runScrape(browser); ; } finally »|fp=4ae853304c8e8aa7`
- `@TRAP`: `Launching Puppeteer or Playwright without wrapping page work in a try/finally block leaves orphaned Chromium renderer processes consuming gigabytes of RAM when assertions fail.`
- `@LAW`: `Guarantees browser process cleanup even when exceptions occur mid-session.`

`@NEG_AST` (`❌ FORBIDDEN`):
```javascript
const browser = await puppeteer.launch();
await runScrape(browser);
await browser.close();
```

`@POS_AST` (`✅ REQUIRED`):
```javascript
const browser = await puppeteer.launch();
try {
  await runScrape(browser);
} finally {
  await browser.close();
}
```
