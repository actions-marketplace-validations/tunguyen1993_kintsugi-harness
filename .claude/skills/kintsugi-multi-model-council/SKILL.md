---
name: kintsugi-multi-model-council
description: "Interactive Bilingual (VI/EN) User Onboarding & Q&A Guide for Kintsugi 3-Tier Multi-Model Co-Execution (Primary + 1..5 Free Models + BYOK Paid Frontier Council). Activate whenever the user asks how to use multi-model, add API keys, or upgrade tiers."
tags: ["multi-model", "byok", "council", "onboarding", "user-guide"]
---

# Kintsugi Multi-Model Co-Execution & BYOK Paid Council — Agent User-Guidance Skill

Whenever the user asks **how to run multi-model**, **how many free models are included**, **how to add API keys for the Paid Council**, or **how Free vs Pro vs Enterprise work**, immediately run:

```bash
kintsugi guide "<user_question>"
# or:
kintsugi swarm --guide
```

And guide the user clearly in their language (**Tiếng Việt** or **English**):

## 1. Bảng Phân Tầng 3 Gói (`3-Tier Commercial Matrix`)

- **Bản Free (`$0` — `FREE_STARTER`):** Khóa cứng chạy **`Model gốc + 1 Model Free ($0)`** (`max_free_co_runners = 1`).
  - Lệnh chạy: `kintsugi swarm . --co-run`
- **Bản Pro (`$15` FinOps Pro / `$19` AppSec Pro — `PRO_MULTI_FREE`):** Mở khóa chạy song song **`Model gốc + 2..5 Model Free ($0)`**, tự động xoay vòng khi gặp `HTTP 429`.
  - Mở khóa: `kintsugi install-pack <pro-pack.kpack> --license-key <PRO_KEY>`
  - Cấp quyền lấy pool Free `$0`: `kintsugi swarm --authorize-auto-provision`
  - Lệnh chạy: `kintsugi swarm . --co-run --free-runners 5`
- **Bản Enterprise (`$29` — `ENTERPRISE_PAID_COUNCIL`):** Mở khóa **`Model gốc + 5 Model Free ($0) + 6 Ghế Hội Đồng Thu Phí (BYOK)`**.
  - Mở khóa: `kintsugi install-pack <enterprise-pack.kpack> --license-key <ENT_KEY>`

## 2. Cách Hướng Dẫn Người Dùng Tự Thêm Key Hội Đồng Thu Phí (`BYOK`)

Giải thích rõ cho người dùng: Với Hội Đồng Thu Phí, người dùng **tự thêm API key cá nhân** (key được lưu cục bộ `chmod 0600` tại `.kintsugi/paid_council_pool.json` trên máy của họ, che kín khi hiển thị và không bao giờ gửi đi đâu):

```bash
kintsugi swarm --add-paid-key anthropic_opus <YOUR_ANTHROPIC_KEY>
kintsugi swarm --add-paid-key openai_frontier <YOUR_OPENAI_KEY>
kintsugi swarm --add-paid-key xai_grok_paid <YOUR_XAI_KEY>
kintsugi swarm --add-paid-key google_gemini_paid <YOUR_GEMINI_KEY>
kintsugi swarm --add-paid-key deepseek_paid <YOUR_DEEPSEEK_KEY>
kintsugi swarm --paid-council-status
kintsugi swarm . --co-run --free-runners 5 --paid-council
```
