# Domain Shard 05: DevOps, Shell/Git Safety, Subprocess & Containers (`devops`)

> **Domain ID:** `devops` · **Shard Path:** `docs/domains/05_devops_cloud.md` · **License:** `Apache-2.0`
> **Scope:** Blocking destructive git/shell commands (`git reset --hard`, `git push --force`, `rm -rf /`), eliminating `shell=True` and interpolated `child_process.exec` command injection, and container/archive extraction safety.

## 1. Domain-Routed `KMI/1` Wire Header (`devops`)

```text
<!-- KINTSUGI:KMI/1:DOMAIN=devops START -->
# KMI/1;domain=devops;doc=docs/domains/05_devops_cloud.md;jit=pre-tool-use
@CRIT: KS-002(sh!no_force_push_or_rm_rf) | KS-017(py!no_os_system->subprocess_argv)
@HIGH: KS-003(subprocess!shell=True->argv_list) | KS-013(js!exec_interp->execFile)
<!-- KINTSUGI:KMI/1:DOMAIN=devops END -->
```

## 2. Enforced Guardrails in This Shard

| Scar ID | Severity | Languages | Anti-Pattern (`❌ Bad`) | Verified Remediation (`✅ Good`) |
| :--- | :--- | :--- | :--- | :--- |
| `KS-002` | `CRITICAL` | `sh,py,js,ts` | `git reset --hard`, `git push --force origin main`, or `rm -rf /` | Use `git stash push -u` and `git push --force-with-lease` |
| `KS-003` | `HIGH` | `python` | `subprocess.run(f"tar -czf out.tgz {dir}", shell=True)` | Pass argument array `subprocess.run(["tar", "-czf", "out.tgz", dir], check=True)` |
| `KS-013` | `HIGH` | `js,ts` | `child_process.exec(\`convert ${userFile} out.png\`)` | Use `child_process.execFile("convert", [userFile, "out.png"])` |
| `KS-017` | `CRITICAL` | `python` | `os.system(f"ping {host}")` or `os.popen(...)` | Use `subprocess.run(["ping", "-c", "1", host], shell=False, check=True)` |

## 3. Reproducible CLI Commands

```bash
# Render only the devops domain KMI/1 shard:
kintsugi token-report --domain devops
```
