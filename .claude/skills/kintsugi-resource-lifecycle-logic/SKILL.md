---
name: kintsugi-resource-lifecycle-logic
description: "Focused resource-lifecycle-logic anti-patterns and verified code templates compiled by Kintsugi Harness."
tags: ["communicate-timeout", "crash-truncation", "db-transaction-rollback", "exception-hygiene", "gemini38-deepseek", "kml:v1", "logic-evolution", "non-atomic-file-write", "subprocess-pipe-deadlock"]
---

# kintsugi-resource-lifecycle-logic (`@KML/1` Machine-Native AST-IR)

```bash
kintsugi scan --staged --fail-on HIGH
```

## `@KML/1` Symbolic Guardrail Specifications (`NEG_AST => POS_AST`)

### `KS-LOGIC-025` · `@OP/1[ID:KS-LOGIC-025|SEV:CRITICAL|CAT:resource-lifecycle-logic|LANG:py|OP:DIRECT_IN_PLACE_STATE_OVERWRITE->WRI]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-025|sev=C|cat=resource-lifecycle-logic|lang=py|op=DIRECT_IN_PLACE_STATE_OVERWRITE->WRI|guard=RX#1dcc747f|neg=«with open(state_json_path, 'w') as f:  # NON_ATOMIC_INPLACE_STATE_TRUNCATION ; json.dump(s»|pos=«tmp_path = f'{state_json_path}.tmp' ; with open(tmp_path, 'w') as f: ; json.dump(state_pay»|fp=2fffd75688c2c8a7`
- `@TRAP`: `@TRAP/1{guard:RX#1dcc747f,fault:RESOURCE-LIFECYCLE-LOGIC_VIOLATION,origin:OP/1,tags:[logic-evolution,non-atomic-file-write,crash-truncation,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:tmp_path_f_state_json_path_.tmp,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
with open(state_json_path, 'w') as f:  # NON_ATOMIC_INPLACE_STATE_TRUNCATION
    json.dump(state_payload, f)
```

`@POS_AST` (`✅ REQUIRED`):
```python
tmp_path = f'{state_json_path}.tmp'
with open(tmp_path, 'w') as f:
    json.dump(state_payload, f)
    f.flush()
os.replace(tmp_path, state_json_path)
```

### `KS-LOGIC-026` · `@OP/1[ID:KS-LOGIC-026|SEV:HIGH|CAT:resource-lifecycle-logic|LANG:py|OP:POPEN_WAIT_WITH_STDOUT_PIPE->POPEN_C]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-026|sev=H|cat=resource-lifecycle-logic|lang=py|op=POPEN_WAIT_WITH_STDOUT_PIPE->POPEN_C|guard=RX#5beb097e|neg=«proc = subprocess.Popen(cmd_args, stdout=subprocess.PIPE) ; proc.wait()  # POPEN_WAIT_PIPE»|pos=«proc = subprocess.Popen(cmd_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE) ; stdout»|fp=de15092ac66df79f`
- `@TRAP`: `@TRAP/1{guard:RX#5beb097e,fault:RESOURCE-LIFECYCLE-LOGIC_VIOLATION,origin:OP/1,tags:[logic-evolution,subprocess-pipe-deadlock,communicate-timeout,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:proc_subprocess.Popen_cmd_args,_stdout_subpr,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
proc = subprocess.Popen(cmd_args, stdout=subprocess.PIPE)
proc.wait()  # POPEN_WAIT_PIPE_BUFFER_DEADLOCK
```

`@POS_AST` (`✅ REQUIRED`):
```python
proc = subprocess.Popen(cmd_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
stdout_data, stderr_data = proc.communicate(timeout=30)
```

### `KS-LOGIC-027` · `@OP/1[ID:KS-LOGIC-027|SEV:HIGH|CAT:resource-lifecycle-logic|LANG:py|OP:DANGLING_CONNECTION_ON_EXCEPTION->EX]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-027|sev=H|cat=resource-lifecycle-logic|lang=py|op=DANGLING_CONNECTION_ON_EXCEPTION->EX|guard=RX#bc388cc9|neg=«try: ; cursor.execute(update_sql, params) ; conn.commit() ; except Exception as exc:  # MI»|pos=«try: ; cursor.execute(update_sql, params) ; conn.commit() ; except Exception as exc: ; con»|fp=7a4de2abc10d0cfe`
- `@TRAP`: `@TRAP/1{guard:RX#bc388cc9,fault:RESOURCE-LIFECYCLE-LOGIC_VIOLATION,origin:OP/1,tags:[logic-evolution,db-transaction-rollback,exception-hygiene,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:try:,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
try:
    cursor.execute(update_sql, params)
    conn.commit()
except Exception as exc:  # MISSING_TX_ROLLBACK_ON_EXCEPTION
    logger.error(exc)
    raise
```

`@POS_AST` (`✅ REQUIRED`):
```python
try:
    cursor.execute(update_sql, params)
    conn.commit()
except Exception as exc:
    conn.rollback()
    logger.error(exc)
    raise
```
