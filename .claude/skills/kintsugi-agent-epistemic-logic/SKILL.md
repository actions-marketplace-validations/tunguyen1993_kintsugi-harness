---
name: kintsugi-agent-epistemic-logic
description: "Focused agent-epistemic-logic anti-patterns and verified code templates compiled by Kintsugi Harness."
tags: ["ast-parse-gate", "codemod-syntax-guard", "gemini38-deepseek", "goalpost-moving-cegis", "grounding-gate", "kml:v1", "lakatos-domain-cut", "logic-evolution", "unverified-tool-claim"]
---

# kintsugi-agent-epistemic-logic (`@KML/1` Machine-Native AST-IR)

```bash
kintsugi scan --staged --fail-on HIGH
```

## `@KML/1` Symbolic Guardrail Specifications (`NEG_AST => POS_AST`)

### `KS-LOGIC-031` · `@OP/1[ID:KS-LOGIC-031|SEV:CRITICAL|CAT:agent-epistemic-logic|LANG:py|OP:TRUST_LLM_SELF_REPORTED_PASS->INDEPE]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-031|sev=C|cat=agent-epistemic-logic|lang=py|op=TRUST_LLM_SELF_REPORTED_PASS->INDEPE|guard=RX#e7e93e90|neg=«if 'TESTS_PASSED' in agent_response_text:  # UNVERIFIED_LLM_SELF_REPORTED_SUCCESS ; mark_t»|pos=«if test_proc.returncode == 0 and verify_test_artifacts_exist(): ; mark_task_completed()»|fp=bf34787d836909d1`
- `@TRAP`: `@TRAP/1{guard:RX#e7e93e90,fault:AGENT-EPISTEMIC-LOGIC_VIOLATION,origin:OP/1,tags:[logic-evolution,unverified-tool-claim,grounding-gate,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:if_test_proc.returncode_0_and_verify_test_ar,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
if 'TESTS_PASSED' in agent_response_text:  # UNVERIFIED_LLM_SELF_REPORTED_SUCCESS
    mark_task_completed()
```

`@POS_AST` (`✅ REQUIRED`):
```python
if test_proc.returncode == 0 and verify_test_artifacts_exist():
    mark_task_completed()
```

### `KS-LOGIC-032` · `@OP/1[ID:KS-LOGIC-032|SEV:HIGH|CAT:agent-epistemic-logic|LANG:py|OP:SILENT_COUNTEREXAMPLE_DROP->PRESERVE]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-032|sev=H|cat=agent-epistemic-logic|lang=py|op=SILENT_COUNTEREXAMPLE_DROP->PRESERVE|guard=RX#89428dc6|neg=«valid_cases = [x for x in domain if hypothesis(x)]  # SILENT_COUNTEREXAMPLE_DOMAIN_PRUNING»|pos=«counterexamples = [x for x in domain if not hypothesis(x)] ; return 'PROVED' if not counte»|fp=6331b99fe22fefad`
- `@TRAP`: `@TRAP/1{guard:RX#89428dc6,fault:AGENT-EPISTEMIC-LOGIC_VIOLATION,origin:OP/1,tags:[logic-evolution,goalpost-moving-cegis,lakatos-domain-cut,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:counterexamples_x_for_x_in_domain_if_not_hyp,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
valid_cases = [x for x in domain if hypothesis(x)]  # SILENT_COUNTEREXAMPLE_DOMAIN_PRUNING
return 'PROVED'
```

`@POS_AST` (`✅ REQUIRED`):
```python
counterexamples = [x for x in domain if not hypothesis(x)]
return 'PROVED' if not counterexamples else 'REFUTED'
```

### `KS-LOGIC-033` · `@OP/1[ID:KS-LOGIC-033|SEV:HIGH|CAT:agent-epistemic-logic|LANG:py|OP:BLIND_REGEX_FILE_WRITE->AST_PARSE_CA]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-033|sev=H|cat=agent-epistemic-logic|lang=py|op=BLIND_REGEX_FILE_WRITE->AST_PARSE_CA|guard=RX#93615333|neg=«patched_src = re.sub(pattern, repl, orig_src) ; source_file.write_text(patched_src)  # UNG»|pos=«patched_src = re.sub(pattern, repl, orig_src) ; ast.parse(patched_src) ; source_file.write»|fp=bb5c739ca43263b0`
- `@TRAP`: `@TRAP/1{guard:RX#93615333,fault:AGENT-EPISTEMIC-LOGIC_VIOLATION,origin:OP/1,tags:[logic-evolution,codemod-syntax-guard,ast-parse-gate,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:patched_src_re.sub_pattern,_repl,_orig_src,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
patched_src = re.sub(pattern, repl, orig_src)
source_file.write_text(patched_src)  # UNGUARDED_CODEMOD_SYNTAX_WRITE
```

`@POS_AST` (`✅ REQUIRED`):
```python
patched_src = re.sub(pattern, repl, orig_src)
ast.parse(patched_src)
source_file.write_text(patched_src)
```
