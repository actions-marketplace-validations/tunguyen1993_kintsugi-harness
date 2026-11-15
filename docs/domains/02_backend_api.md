# Domain Shard 02: Backend APIs, HTTP Resilience & Concurrency (`backend`)

> **Domain ID:** `backend` · **Shard Path:** `docs/domains/02_backend_api.md` · **License:** `Apache-2.0`
> **Scope:** Bounded HTTP timeouts, exception propagation, mutable default argument prevention, async event-loop non-blocking invariants, and numerical/concurrency correctness.

## 1. Domain-Routed `KMI/1` Wire Header (`backend`)

```text
<!-- KINTSUGI:KMI/1:DOMAIN=backend START -->
# KMI/1;domain=backend;doc=docs/domains/02_backend_api.md;jit=pre-tool-use
@HIGH: KS-005(py!bare_except_pass->log_raise) | KS-008(http!no_timeout->timeout=10) | KS-016(go!http_client_timeout)
@MED : KS-004(py!mutable_default->None)
<!-- KINTSUGI:KMI/1:DOMAIN=backend END -->
```

## 2. Enforced Guardrails in This Shard

| Scar ID | Severity | Languages | Anti-Pattern (`❌ Bad`) | Verified Remediation (`✅ Good`) |
| :--- | :--- | :--- | :--- | :--- |
| `KS-004` | `MEDIUM` | `python` | Mutable default argument `def append_event(ev, history=[]):` | Use `history: list \| None = None` and initialize inside function body |
| `KS-005` | `HIGH` | `python` | Bare `except:` or `except Exception: pass` swallowing errors | Catch specific exceptions, log structured context, and re-raise |
| `KS-008` | `HIGH` | `python` | `requests.get(url)` or `urllib.request.urlopen(url)` without `timeout=` | Always pass explicit `timeout=10` to outbound HTTP calls |
| `KS-016` | `HIGH` | `go` | `http.Get(url)` / `http.Post(url)` using infinite-wait `http.DefaultClient` | Use `&http.Client{Timeout: 10 * time.Second}` |

## 3. Reproducible CLI Commands

```bash
# Render only the backend domain KMI/1 shard:
kintsugi token-report --domain backend
```
