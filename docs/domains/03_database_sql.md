# Domain Shard 03: Database Queries, Parameterized SQL & Persistence (`database`)

> **Domain ID:** `database` · **Shard Path:** `docs/domains/03_database_sql.md` · **License:** `Apache-2.0`
> **Scope:** SQL injection prevention via parameterized bind variables, transaction safety, non-blocking schema migrations, and append-only audit log integrity.

## 1. Domain-Routed `KMI/1` Wire Header (`database`)

```text
<!-- KINTSUGI:KMI/1:DOMAIN=database START -->
# KMI/1;domain=database;doc=docs/domains/03_database_sql.md;jit=pre-tool-use
@CRIT: KS-007(sql!fstring->param_query)
@HIGH: KS-WILD-514(sql!wild_interp->param_tuple)
<!-- KINTSUGI:KMI/1:DOMAIN=database END -->
```

## 2. Enforced Guardrails in This Shard

| Scar ID | Severity | Languages | Anti-Pattern (`❌ Bad`) | Verified Remediation (`✅ Good`) |
| :--- | :--- | :--- | :--- | :--- |
| `KS-007` | `CRITICAL` | `py,js,ts` | Raw SQL f-string or template literal interpolation `SELECT ... WHERE email = '{email}'` | Parameterized bind query `cursor.execute("SELECT ... WHERE email = ?", (email,))` |
| `KS-WILD-514` | `HIGH` | `python` | String-formatted ` INSERT` / `UPDATE` / `DELETE` statements | Parameterized tuple binding or ORM query parameters |

## 3. Reproducible CLI Commands

```bash
# Render only the database domain KMI/1 shard:
kintsugi token-report --domain database
```
