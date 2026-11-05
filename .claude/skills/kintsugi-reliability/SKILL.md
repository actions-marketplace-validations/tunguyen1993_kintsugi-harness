---
name: kintsugi-reliability
description: "Focused reliability anti-patterns and verified code templates compiled by Kintsugi Harness."
tags: ["ast", "base-image", "browser", "debugging", "docker", "exceptions", "golang", "hang", "http", "memory-leak"]
---

# kintsugi-reliability

Use this skill before writing, refactoring, or reviewing code in this repository.
Every rule below was compiled from a verified failure trace and is enforced deterministically via `kintsugi scan`.

## Verification Gate

```bash
kintsugi scan --staged --fail-on HIGH
```

## Verified Golden Scars (`❌ Anti-Pattern` vs `✅ Verified Fix`)

### `KS-005` · [HIGH] Silent exception swallowing (bare except or except-pass)
- **Root cause:** Agents wrap failing blocks in bare `except:` or `except Exception: pass` to make tests turn green while hiding real data corruption or network failures.
- **Why this matters:** Preserves KeyboardInterrupt/SystemExit propagation and forces explicit failure handling.

**Avoid (`❌ Anti-Pattern`):**
```python
try:
    sync_records()
except Exception:
    pass
```

**Prefer (`✅ Verified Pattern`):**
```python
try:
    sync_records()
except ConnectionError as exc:
    logger.warning('Transient sync failure: %s', exc)
    raise
```

### `KS-008` · [HIGH] Unbounded synchronous HTTP call missing explicit timeout
- **Root cause:** requests.get/post and urllib.request.urlopen default to waiting indefinitely on stalled sockets, hanging CI pipelines and agent workers forever.
- **Why this matters:** Every outbound network call must enforce a bounded socket timeout.

**Avoid (`❌ Anti-Pattern`):**
```python
import urllib.request
resp = urllib.request.urlopen("https://example.com/api/health")
```

**Prefer (`✅ Verified Pattern`):**
```python
import urllib.request
resp = urllib.request.urlopen("https://example.com/api/health", timeout=10)
```

### `KS-016` · [HIGH] Go net/http DefaultClient call without bounded timeout
- **Root cause:** Go's package-level http.Get and http.Post helpers use http.DefaultClient, which has a default Timeout of 0 (infinite wait).
- **Why this matters:** Explicit http.Client{Timeout: ...} prevents goroutine leaks on unresponsive upstream servers.

**Avoid (`❌ Anti-Pattern`):**
```go
resp, err := http.Get("https://api.example.com/status")
```

**Prefer (`✅ Verified Pattern`):**
```go
client := &http.Client{Timeout: 10 * time.Second}
resp, err := client.Get("https://api.example.com/status")
```

### `KS-010` · [MEDIUM] Headless browser launch without deterministic finally teardown
- **Root cause:** Launching Puppeteer or Playwright without wrapping page work in a try/finally block leaves orphaned Chromium renderer processes consuming gigabytes of RAM when assertions fail.
- **Why this matters:** Guarantees browser process cleanup even when exceptions occur mid-session.

**Avoid (`❌ Anti-Pattern`):**
```javascript
const browser = await puppeteer.launch();
await runScrape(browser);
await browser.close();
```

**Prefer (`✅ Verified Pattern`):**
```javascript
const browser = await puppeteer.launch();
try {
  await runScrape(browser);
} finally {
  await browser.close();
}
```

### `KS-018` · [MEDIUM] Pin Docker base images to an immutable digest
- **Root cause:** The Dockerfile uses the mutable python:latest tag, whose image contents can change between builds.
- **Why this matters:** An image digest pins the exact base image content, making builds reproducible and preventing unexpected changes from a mutable tag. Replace the placeholder with the verified digest for the intended Python image, and update it deliberately for security fixes.

**Avoid (`❌ Anti-Pattern`):**
```dockerfile
FROM python:latest
WORKDIR /app
```

**Prefer (`✅ Verified Pattern`):**
```dockerfile
FROM python:3.12.9@sha256:<verified-image-digest>
WORKDIR /app
```
