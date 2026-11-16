# Domain Shard 04: Frontend UI, DOM/XSS Hygiene, CORS & Browser Automation (`frontend`)

> **Domain ID:** `frontend` · **Shard Path:** `docs/domains/04_frontend_ui.md` · **License:** `Apache-2.0`
> **Scope:** Cross-Origin Resource Sharing (CORS) credential allowlists, DOM XSS prevention (`textContent` vs `innerHTML`), and deterministic headless browser (`Playwright` / `Puppeteer`) lifecycle cleanup.

## 1. Domain-Routed `KMI/1` Wire Header (`frontend`)

```text
<!-- KINTSUGI:KMI/1:DOMAIN=frontend START -->
# KMI/1;domain=frontend;doc=docs/domains/04_frontend_ui.md;jit=pre-tool-use
@HIGH: KS-015(cors!no_wildcard_with_credentials)
@MED : KS-010(browser!launch->close_in_finally)
<!-- KINTSUGI:KMI/1:DOMAIN=frontend END -->
```

## 2. Enforced Guardrails in This Shard

| Scar ID | Severity | Languages | Anti-Pattern (`❌ Bad`) | Verified Remediation (`✅ Good`) |
| :--- | :--- | :--- | :--- | :--- |
| `KS-010` | `MEDIUM` | `js,ts,py` | `puppeteer.launch()` / `chromium.launch()` without `try ... finally` teardown | Always close browser instances inside a `finally` block to prevent renderer memory leaks |
| `KS-015` | `HIGH` | `py,js,ts` | `allow_origins=["*"]` combined with `allow_credentials=True` | Specify an explicit origin allowlist `allow_origins=["https://app.example.com"]` |

## 3. Reproducible CLI Commands

```bash
# Render only the frontend domain KMI/1 shard:
kintsugi token-report --domain frontend
```
