---
name: kintsugi-devops-cloud
description: "Focused devops-cloud anti-patterns and verified code templates compiled by Kintsugi Harness."
tags: ["cdp", "concurrency", "daemon", "devops", "devops-cloud", "event-driven", "flock", "indexeddb", "memory-leak", "mitm"]
# kintsugi: ignore-file (generated guardrail reference containing bad_code examples)
---

# kintsugi-devops-cloud (`@KML/1` Machine-Native AST-IR)

```bash
kintsugi scan --staged --fail-on HIGH
```

## `@KML/1` Symbolic Guardrail Specifications (`NEG_AST => POS_AST`)

### `KL-OPS-003` · `Complete Browser Origin Storage Teardown (IndexedDB + ServiceWorkers) & Scoped Profile Cleanup`
- `@WIRE`: `@KML/1|id=KL-OPS-003|sev=H|cat=devops-cloud|lang=js,ts|op=COMPLETE_BROWSER_ORIGIN_STORAGE_TEAR|guard=RX#72ff0ab6|neg=«await client.send('Network.clearBrowserCookies');  // MISSING_INDEXEDDB_ORIGIN_CLEAR»|pos=«await client.send('Page.navigate', { url: 'about:blank' }); ; await client.send('Storage.c»|fp=0718d22daab27ef2`
- `@TRAP`: `[Cognitive Trap] Cleared browser cookies when switching accounts (`Network.clearBrowserCookies`) while leaving stale IndexedDB cryptographic keys (`cvm_chip_pin_unavailable`), or ran an unscoped global browser process kill.`
- `@LAW`: `[Mental Model] Navigate to `about:blank` and call `Storage.clearDataForOrigin` for `indexeddb,local_storage,cache_storage,service_workers` before clearing cookies, and terminate only the isolated `--user-data-dir` in `finally`.`

`@NEG_AST` (`❌ FORBIDDEN`):
```javascript
await client.send('Network.clearBrowserCookies');  // MISSING_INDEXEDDB_ORIGIN_CLEAR
```

`@POS_AST` (`✅ REQUIRED`):
```javascript
await client.send('Page.navigate', { url: 'about:blank' });
await client.send('Storage.clearDataForOrigin', { origin, storageTypes: 'indexeddb,local_storage,cache_storage,service_workers' });
```

### `KL-OPS-001` · `Enforce SSH StrictHostKeyChecking=yes in automated deployment pipelines`
- `@WIRE`: `@KML/1|id=KL-OPS-001|sev=H|cat=devops-cloud|lang=sh,py|op=ENFORCE_SSH_STRICTHOSTKEYCHECKING_YE|guard=RX#37d86683|neg=«ssh -o StrictHostKeyChecking=no deploy@edge.example.com "systemctl restart api"»|pos=«ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/etc/ssh/known_hosts deploy@edge.ex»|fp=c5fe24d690714946`
- `@TRAP`: `[Cognitive Trap] Passed `-o StrictHostKeyChecking=no` in CI/CD scripts to suppress interactive host key prompts on first connect.`
- `@LAW`: `[Mental Model] Disabling host key verification surrenders SSH authentication to active network MITM interception; pre-populate `known_hosts` and enforce `StrictHostKeyChecking=yes`.`

`@NEG_AST` (`❌ FORBIDDEN`):
```shell
ssh -o StrictHostKeyChecking=no deploy@edge.example.com "systemctl restart api"
```

`@POS_AST` (`✅ REQUIRED`):
```shell
ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/etc/ssh/known_hosts deploy@edge.example.com "systemctl restart api"
```

### `KL-OPS-002` · `Singleton Daemon Flock & Event-Driven Wakeup: Never run unlocked overlapping daemons or busy-poll loops`
- `@WIRE`: `@KML/1|id=KL-OPS-002|sev=H|cat=devops-cloud|lang=py|op=SINGLETON_DAEMON_FLOCK_EVENT-DRIVEN_|guard=RX#92048ad1|neg=«while task_running: ; poll_status_immediately()  # UNLOCKED_BUSY_POLL_LOOP»|pos=«fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB) ; wait_for_reactive_event_notification»|fp=f458595453d28ceb`
- `@TRAP`: `[Cognitive Trap] Spawned multiple cron/CLI worker instances without an exclusive file lock (`fcntl.flock`) and busy-polled task status in a tight loop, causing duplicate executions and resource waste.`
- `@LAW`: `[Mental Model] Acquire a non-blocking exclusive lock (`fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)`) at daemon startup and yield to event-driven reactive wakeup instead of polling.`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
while task_running:
    poll_status_immediately()  # UNLOCKED_BUSY_POLL_LOOP
```

`@POS_AST` (`✅ REQUIRED`):
```python
fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
wait_for_reactive_event_notification()
```
