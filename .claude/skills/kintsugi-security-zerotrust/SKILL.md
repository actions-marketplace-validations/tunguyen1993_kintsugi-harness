---
name: kintsugi-security-zerotrust
description: "Focused security-zerotrust anti-patterns and verified code templates compiled by Kintsugi Harness."
tags: ["auth", "auth-bypass", "authentication", "file-io", "idor", "jwt", "mass-assignment", "model:gpt-6-frontier", "model:grok-frontier", "path-traversal"]
# kintsugi: ignore-file (generated guardrail reference containing bad_code examples)
---

# kintsugi-security-zerotrust (`@KML/1` Machine-Native AST-IR)

```bash
kintsugi scan --staged --fail-on HIGH
```

## `@KML/1` Symbolic Guardrail Specifications (`NEG_AST => POS_AST`)

### `KL-ZTR-002` · `Cross-Layer Path Seam Containment: Never concatenate unvalidated user filenames into open()`
- `@WIRE`: `@KML/1|id=KL-ZTR-002|sev=C|cat=security-zerotrust|lang=py|op=CROSS-LAYER_PATH_SEAM_CONTAINMENT_NE|guard=RX#649853b2|neg=«fh = open(base_dir + "/" + user_filename, "rb")  # UNSAFE_PATH_CONCAT_SEAM»|pos=«target = (Path(base_dir) / user_filename).resolve() ; assert target.is_relative_to(Path(ba»|fp=db4f1888387de259`
- `@TRAP`: `[Cognitive Trap] Assumed a surface string filter on a user filename prevents directory traversal when concatenated via `open(base_dir + '/' + filename)`.`
- `@LAW`: `[Mental Model] Surface string filters fail against encoding/traversal seams across layers; resolve the canonical path via `Path(base_dir).joinpath(filename).resolve()` and enforce `.is_relative_to(base_root)` before opening.`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
fh = open(base_dir + "/" + user_filename, "rb")  # UNSAFE_PATH_CONCAT_SEAM
```

`@POS_AST` (`✅ REQUIRED`):
```python
target = (Path(base_dir) / user_filename).resolve()
assert target.is_relative_to(Path(base_dir).resolve())
fh = target.open("rb")
```

### `KL-ZTR-003` · `Anti-Mass-Assignment Privilege Boundary: Never merge raw request dicts into user/account records`
- `@WIRE`: `@KML/1|id=KL-ZTR-003|sev=C|cat=security-zerotrust|lang=py,js,ts|op=ANTI-MASS-ASSIGNMENT_PRIVILEGE_BOUND|guard=RX#50e08031|neg=«user_record.update(request_json)  # UNFILTERED_PRIVILEGE_MASS_ASSIGNMENT»|pos=«ALLOWED = {'display_name', 'bio'} ; user_record.update({k: request_json[k] for k in ALLOWE»|fp=bfad08aa50d9594c`
- `@TRAP`: `[Cognitive Trap] Merged parsed HTTP body parameters directly into the stored user model (`user_record.update(request_json)`), allowing callers to inject `is_admin=True` or `balance=999999`.`
- `@LAW`: `[Mental Model] Privilege flags (`is_admin`, `role`, `balance`, `tenant_id`) must never share a merge dictionary with user-editable profile fields; project input through an explicit field allowlist.`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
user_record.update(request_json)  # UNFILTERED_PRIVILEGE_MASS_ASSIGNMENT
```

`@POS_AST` (`✅ REQUIRED`):
```python
ALLOWED = {'display_name', 'bio'}
user_record.update({k: request_json[k] for k in ALLOWED if k in request_json})
```

### `KL-ZTR-001` · `Reject JWT verification calls that disable signature checking or allow alg='none'`
- `@WIRE`: `@KML/1|id=KL-ZTR-001|sev=C|cat=security-zerotrust|lang=py,js,ts|op=REJECT_JWT_VERIFICATION_CALLS_THAT_D|guard=RX#bd115d88|neg=«claims = jwt.decode(token, options={"verify_signature": False})»|pos=«claims = jwt.decode(token, public_key, algorithms=["RS256"])»|fp=d3f363ed1eda721a`
- `@TRAP`: `[Cognitive Trap] Set `verify_signature: False` during local debugging to inspect JWT claims and left the option in the authentication middleware.`
- `@LAW`: `[Mental Model] Disabling JWT signature verification or permitting `alg='none'` allows any caller to forge arbitrary admin identities; always pin explicit asymmetric algorithms and verify signatures.`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
claims = jwt.decode(token, options={"verify_signature": False})
```

`@POS_AST` (`✅ REQUIRED`):
```python
claims = jwt.decode(token, public_key, algorithms=["RS256"])
```
