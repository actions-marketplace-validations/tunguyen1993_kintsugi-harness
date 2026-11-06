---
name: kintsugi-path-canonicalization-logic
description: "Focused path-canonicalization-logic anti-patterns and verified code templates compiled by Kintsugi Harness."
tags: ["gemini38-deepseek", "homograph-bypass", "is-relative-to", "kml:v1", "logic-evolution", "prefix-traversal-bypass", "ssrf-host-parse", "unicode-nfkc-normalization", "url-authority-confusion"]
---

# kintsugi-path-canonicalization-logic (`@KML/1` Machine-Native AST-IR)

```bash
kintsugi scan --staged --fail-on HIGH
```

## `@KML/1` Symbolic Guardrail Specifications (`NEG_AST => POS_AST`)

### `KS-LOGIC-028` · `@OP/1[ID:KS-LOGIC-028|SEV:CRITICAL|CAT:path-canonicalization-lo|LANG:py|OP:STRING_STARTSWITH_PATH_PREFIX->RESOL]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-028|sev=C|cat=path-canonicalization-logic|lang=py|op=STRING_STARTSWITH_PATH_PREFIX->RESOL|guard=RX#6d4af46d|neg=«if str(candidate_path).startswith(str(base_dir)):  # STRING_STARTSWITH_PATH_PREFIX_BYPASS »|pos=«if candidate_path.resolve().is_relative_to(base_dir.resolve()): ; return open_artifact(can»|fp=c83f239221c84cc1`
- `@TRAP`: `@TRAP/1{guard:RX#6d4af46d,fault:PATH-CANONICALIZATION-LO_VIOLATION,origin:OP/1,tags:[logic-evolution,prefix-traversal-bypass,is-relative-to,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:if_candidate_path.resolve_.is_relative_to_ba,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
if str(candidate_path).startswith(str(base_dir)):  # STRING_STARTSWITH_PATH_PREFIX_BYPASS
    return open_artifact(candidate_path)
```

`@POS_AST` (`✅ REQUIRED`):
```python
if candidate_path.resolve().is_relative_to(base_dir.resolve()):
    return open_artifact(candidate_path.resolve())
```

### `KS-LOGIC-029` · `@OP/1[ID:KS-LOGIC-029|SEV:HIGH|CAT:path-canonicalization-lo|LANG:py|OP:RAW_UNNORMALIZED_IDENTIFIER_FILTER->]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-029|sev=H|cat=path-canonicalization-logic|lang=py|op=RAW_UNNORMALIZED_IDENTIFIER_FILTER->|guard=RX#4e930c7f|neg=«if user_handle not in reserved_admin_names:  # UNNORMALIZED_UNICODE_FILTER_BYPASS ; regist»|pos=«canon_handle = unicodedata.normalize('NFKC', user_handle).casefold() ; if canon_handle not»|fp=55c9880c9771c537`
- `@TRAP`: `@TRAP/1{guard:RX#4e930c7f,fault:PATH-CANONICALIZATION-LO_VIOLATION,origin:OP/1,tags:[logic-evolution,unicode-nfkc-normalizati,homograph-bypass,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:canon_handle_unicodedata.normalize_NFKC_,_us,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
if user_handle not in reserved_admin_names:  # UNNORMALIZED_UNICODE_FILTER_BYPASS
    register_handle(user_handle)
```

`@POS_AST` (`✅ REQUIRED`):
```python
canon_handle = unicodedata.normalize('NFKC', user_handle).casefold()
if canon_handle not in reserved_admin_names:
    register_handle(canon_handle)
```

### `KS-LOGIC-030` · `@OP/1[ID:KS-LOGIC-030|SEV:HIGH|CAT:path-canonicalization-lo|LANG:py|OP:SUBSTRING_HOST_IN_URL_CHECK->URLPARS]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-030|sev=H|cat=path-canonicalization-logic|lang=py|op=SUBSTRING_HOST_IN_URL_CHECK->URLPARS|guard=RX#5f619695|neg=«if 'example.com' in target_url:  # SUBSTRING_URL_HOST_SSRF_BYPASS ; fetch_remote(target_ur»|pos=«parsed_u = urllib.parse.urlparse(target_url) ; if parsed_u.scheme == 'https' and parsed_u.»|fp=df78eb2825493263`
- `@TRAP`: `@TRAP/1{guard:RX#5f619695,fault:PATH-CANONICALIZATION-LO_VIOLATION,origin:OP/1,tags:[logic-evolution,url-authority-confusion,ssrf-host-parse,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:parsed_u_urllib.parse.urlparse_target_url,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
if 'example.com' in target_url:  # SUBSTRING_URL_HOST_SSRF_BYPASS
    fetch_remote(target_url)
```

`@POS_AST` (`✅ REQUIRED`):
```python
parsed_u = urllib.parse.urlparse(target_url)
if parsed_u.scheme == 'https' and parsed_u.hostname in {'example.com', 'api.example.com'}:
    fetch_remote(target_url)
```
