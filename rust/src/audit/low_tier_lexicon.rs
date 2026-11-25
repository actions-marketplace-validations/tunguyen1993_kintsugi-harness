//! Low-Tier / Budget Model Failure Lexicon (`rust/src/audit/low_tier_lexicon.rs`).
//!
//! Compact, symbol-scoped, zero-bloat dictionary of the 18 highest-frequency failure modes
//! committed by budget / fast / low-tier LLMs (`GLM-4-Flash`, `DeepSeek Flash`, `Budget-Reasoning-Model`,
//! `Haiku`, `Mini`, `Qwen`), distilled from empirical blind A/B runs and real production scars.
//!
//! Design laws:
//!   - JIT-only injection: `0` tokens on clean/unrelated files; capped at `max_entries` (default 4).
//!   - Every entry is Signature-Guarded & Falsifiable (paired bad vs good pattern + precondition).

use std::path::Path;
use std::time::Instant;

use crate::audit::capsules::extract_code_capsule_signals;
use crate::io_json::{read_regular_file_fd_verified, JsonArr, JsonObj, ENGINE_VERSION};
use crate::rules::detect_language;
use crate::scanner::MAX_SOURCE_FILE_BYTES;
use crate::token_est::estimate_tokens;

#[derive(Debug, Clone, Copy)]
pub struct PitfallEntry {
    pub id: &'static str,
    pub slug: &'static str,
    pub category: &'static str,
    pub languages: &'static [&'static str],
    /// Conjunction of disjunctive trigger groups over symbol-scoped signals (`ALL` groups must match).
    pub trigger_groups: &'static [&'static [&'static str]],
    pub bad_pattern: &'static str,
    pub good_pattern: &'static str,
    pub precondition: &'static str,
}

impl PitfallEntry {
    pub fn render_compact(&self) -> String {
        format!(
            "@PITFALL[{}|{}|{}] AVOID: {} -> DO: {} | WHEN: {}",
            self.id, self.slug, self.category, self.bad_pattern, self.good_pattern, self.precondition
        )
    }

    fn supports_lang(&self, lang: &str) -> bool {
        lang == "*" || lang == "other" || self.languages.contains(&"*") || self.languages.contains(&lang)
    }
}

pub const LOW_TIER_PITFALL_LEXICON: &[PitfallEntry] = &[
    PitfallEntry {
        id: "LT-001",
        slug: "signature_drift",
        category: "api",
        languages: &["*"],
        trigger_groups: &[&["verify", "validate", "check", "parse", "bool", "return"]],
        bad_pattern: "Inventing nonexistent kwargs or raising ValueError inside a `-> bool` verifier",
        good_pattern: "Preserve exact method/kwarg signatures; for `-> bool` verifiers return False on malformed input",
        precondition: "Function signature or interface contract is specified by caller/tests",
    },
    PitfallEntry {
        id: "LT-002",
        slug: "float_money",
        category: "fintech",
        languages: &["python", "typescript", "javascript"],
        trigger_groups: &[
            &["@struct_decimal_currency_math", "price", "amount", "balance", "vnd", "usd", "usdc", "fx", "tax", "invoice", "fee"],
            &["float", "round", "decimal", "number", "total", "rate", "cost", "subtotal"],
        ],
        bad_pattern: "Binary `float(amount)` / JS `Number(decimal)` or banker's `round()` causing 0.01 drift",
        good_pattern: "Use `Decimal(str(raw)).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)` or integer minor units",
        precondition: "Any currency, tax, FX conversion, or financial ledger calculation",
    },
    PitfallEntry {
        id: "LT-003",
        slug: "sql_concat_and_tuple",
        category: "sql",
        languages: &["python", "typescript", "javascript"],
        trigger_groups: &[&["execute", "executemany", "query", "select", "cursor", "sqlite", "mysql", "sql"]],
        bad_pattern: "`f\"SELECT ... {x}\"`, `\"%s\" % x`, or scalar `cursor.execute(sql, uid)` instead of 1-tuple",
        good_pattern: "Static SQL literal (or immutable local `sql = \"... ?\"`) with explicit tuple/array `(uid,)` / `[uid]`",
        precondition: "Every SQL query execution sink",
    },
    PitfallEntry {
        id: "LT-004",
        slug: "path_prefix_bypass",
        category: "security",
        languages: &["python", "typescript", "javascript", "rust"],
        trigger_groups: &[
            &["@struct_fs_persistence", "realpath", "abspath", "path", "workspace", "root", "rel"],
            &["startswith", "open", "save", "write", "read", "join", "file", "receipt"],
        ],
        bad_pattern: "`target.startswith(root)` without `+ os.sep` (allows `/ws_evil`) or skipping `islink` per segment",
        good_pattern: "Canonicalize `root = os.path.realpath(ws)`, reject symlinks per segment, check `target == root or target.startswith(root + os.sep)`",
        precondition: "Resolving user/relative file paths under a confined workspace root",
    },
    PitfallEntry {
        id: "LT-005",
        slug: "subprocess_shell",
        category: "security",
        languages: &["python", "typescript", "javascript"],
        trigger_groups: &[&["@struct_subprocess_exec", "subprocess", "popen", "spawn", "exec", "command"]],
        bad_pattern: "`subprocess.run(f\"{bin} {arg}\", shell=True)` or omitting `shell=False` / `timeout` / metachar check",
        good_pattern: "Pass argv list `[bin_real, flag, arg]` with explicit `shell=False`, `timeout=N`, and reject `;|&$><`\\n\\r\\x00`",
        precondition: "Spawning any external binary or CLI subprocess",
    },
    PitfallEntry {
        id: "LT-006",
        slug: "lock_order_self_deadlock",
        category: "concurrency",
        languages: &["python", "typescript", "rust"],
        trigger_groups: &[
            &["@struct_multi_lock_transfer", "lock", "rlock", "mutex"],
            &["transfer", "move", "debit", "credit", "rebalance", "acct", "account"],
        ],
        bad_pattern: "Acquiring locks in caller `(src, dst)` order (AB-BA deadlock) or locking `src` twice when `src == dst`",
        good_pattern: "Lock sorted `(min(src,dst), max(src,dst))`; when `src == dst` acquire ONE lock, verify balance, preserve sum",
        precondition: "Multi-entity transfer or swap using per-key locks",
    },
    PitfallEntry {
        id: "LT-007",
        slug: "silent_except_swallow",
        category: "reliability",
        languages: &["python", "typescript", "javascript"],
        trigger_groups: &[&["except", "catch", "try", "error", "raise", "throw"]],
        bad_pattern: "Broad `except Exception: pass` / `return {}` masking real security or invariant failures",
        good_pattern: "Catch specific exception types only; fail closed on security, parse, or state-corruption errors",
        precondition: "Error handling around validation, persistence, crypto, or I/O",
    },
    PitfallEntry {
        id: "LT-008",
        slug: "mutable_default_arg",
        category: "python",
        languages: &["python"],
        trigger_groups: &[&["def", "init", "class"], &["list", "dict", "set", "cache", "items", "opts", "config"]],
        bad_pattern: "`def fn(items=[], seen={}):` or shared mutable class attributes leaking across calls/tests",
        good_pattern: "Default to `None` (`items: list | None = None`) and initialize fresh container inside function/`__init__`",
        precondition: "Python functions or classes accepting optional containers",
    },
    PitfallEntry {
        id: "LT-009",
        slug: "boundary_odd_empty",
        category: "algo",
        languages: &["*"],
        trigger_groups: &[&["@struct_halving_hash_tree", "merkle", "len", "range", "slice", "index", "items", "nodes"]],
        bad_pattern: "Indexing `items[0]` on empty input, duplicating odd trailing Merkle node (`[A,B,C]==[A,B,C,C]`), or `<` vs `<=` off-by-one",
        good_pattern: "Guard empty/single-item inputs explicitly; promote odd Merkle trailing node unchanged without duplication",
        precondition: "Loop indexing, tree reduction, pagination, or inclusive/exclusive bounds",
    },
    PitfallEntry {
        id: "LT-010",
        slug: "toctou_idempotency",
        category: "concurrency",
        languages: &["*"],
        trigger_groups: &[&["@struct_idempotent_state_write", "idempotency", "replay", "dedupe", "order", "stock", "webhook"]],
        bad_pattern: "Checking `if key in seen` without payload-hash binding, or reading balance outside atomic lock/TX",
        good_pattern: "Bind `(idempotency_key, sha256(raw_payload))` atomically inside lock/TX; conflict on same key + different payload",
        precondition: "Idempotent webhook, order fulfillment, stock movement, or payout endpoints",
    },
    PitfallEntry {
        id: "LT-011",
        slug: "timing_and_boundary_mac",
        category: "security",
        languages: &["python", "typescript", "javascript"],
        trigger_groups: &[&["hmac", "signature", "sig", "mac", "secret", "digest", "token"]],
        bad_pattern: "`sig == expected` (timing side-channel) or un-delimited `f\"{ts}{body}\"` (`1230+x == 123+0x`)",
        good_pattern: "Use `hmac.compare_digest` / `crypto.timingSafeEqual` and explicit delimiter `f\"{ts}.\".encode() + raw_body`",
        precondition: "Any MAC, webhook signature, OTP, or API secret verification",
    },
    PitfallEntry {
        id: "LT-012",
        slug: "naive_datetime_tz",
        category: "time",
        languages: &["python", "typescript", "javascript"],
        trigger_groups: &[&["datetime", "timestamp", "epoch", "skew", "expire", "ttl", "utc", "now"]],
        bad_pattern: "Mixing naive `datetime.now()` with UTC-aware timestamps or skipping skew bounds when `max_skew` param exists",
        good_pattern: "Use UTC epoch int/float or `datetime.now(timezone.utc)`; enforce skew ONLY when `now_sec`/`max_skew` params exist",
        precondition: "Expiry, replay window, audit logs, or scheduled job timestamps",
    },
    PitfallEntry {
        id: "LT-013",
        slug: "recursion_and_diamond_dag",
        category: "algo",
        languages: &["*"],
        trigger_groups: &[&["dag", "graph", "edges", "prereq", "ancestor", "topological", "cycle", "node", "tree"]],
        bad_pattern: "Recursive DFS (hits Python 1000-frame `RecursionError`) or summing ancestor weights twice in Diamond DAGs",
        good_pattern: "Use iterative Kahn topological sort + `set` union `anc[v] |= anc[u] | {u}` for distinct transitive ancestors",
        precondition: "Graph/DAG traversal, dependency resolution, or critical-path makespan",
    },
    PitfallEntry {
        id: "LT-014",
        slug: "noop_test_shortcut",
        category: "testing",
        languages: &["*"],
        trigger_groups: &[&["test", "assert", "mock", "stub", "fixture", "verify"]],
        bad_pattern: "Making failing tests pass by deleting assertions, returning hardcoded constants, or skipping real mutation",
        good_pattern: "Ensure positive control (real state change happens), negative control (bug fails), and conservation check all pass",
        precondition: "Any patch proposed under automated test verification",
    },
    PitfallEntry {
        id: "LT-015",
        slug: "untrusted_json_bool_int_bidi",
        category: "security",
        languages: &["python", "typescript", "javascript"],
        trigger_groups: &[&["@struct_json_untrusted_input", "json", "payload", "memo", "note", "body", "request"]],
        bad_pattern: "`isinstance(x, int)` accepting Python `bool` (`True == 1`), or allowing Bidi `\\u202e` / NUL `\\x00` in decoded strings",
        good_pattern: "Check `isinstance(x, int) and not isinstance(x, bool)` and reject Bidi (`\\u202a-\\u202e`, `\\u2066-\\u2069`, `\\u061c`) + `\\x00`",
        precondition: "Parsing untrusted JSON payloads, webhooks, or user-supplied strings",
    },
    PitfallEntry {
        id: "LT-016",
        slug: "ts_async_truthy_trap",
        category: "typescript",
        languages: &["typescript", "javascript"],
        trigger_groups: &[&["async", "await", "promise", "foreach", "number", "amount", "qty", "price"]],
        bad_pattern: "`items.forEach(async ...)` (unawaited promises!) or `if (!amount)` dropping valid `0`",
        good_pattern: "Use `for (const item of items) { await ... }` / `Promise.all` and explicit `amount === undefined || amount === null`",
        precondition: "TypeScript/Node async loops and numeric zero-value validation",
    },
    PitfallEntry {
        id: "LT-017",
        slug: "floor_zero_div_precondition",
        category: "fintech",
        languages: &["*"],
        trigger_groups: &[&["@struct_share_vault_ratio", "shares", "vault", "mint", "redeem", "stake", "ratio", "denom"]],
        bad_pattern: "Assuming floor-divided shares `(a * (S + V_S)) // (A + V_A)` is always `> 0` after arbitrary donations or omitting `denom == 0`",
        good_pattern: "Check `denom > 0`, verify precondition `A + V_A <= a * (S + V_S)`, and explicitly reject `shares <= 0` (`ValueError`)",
        precondition: "ERC-4626 vaults, share mint/redeem math, or integer ratio splits",
    },
    PitfallEntry {
        id: "LT-018",
        slug: "non_atomic_file_write",
        category: "security",
        languages: &["python", "typescript", "javascript", "rust"],
        trigger_groups: &[&["@struct_fs_persistence", "write_text", "writefilesync", "dump", "save", "persist", "receipt"]],
        bad_pattern: "Direct `open(path, 'w')` / `writeFileSync(path)` corrupting state on crash and leaving `0o644` permissions",
        good_pattern: "Write to temp file with `O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW` mode `0o600`, `fsync`, then atomic `os.replace`",
        precondition: "Persisting receipts, credentials, ledgers, or JSON state files",
    },
    PitfallEntry {
        id: "LT-019",
        slug: "ssrf_ipv4_mapped_global_crlf",
        category: "security",
        languages: &["*"],
        trigger_groups: &[
            &["url", "webhook", "outbound", "ssrf", "fetch"],
            &["ipaddress", "resolved", "headers", "host", "localhost", "http"],
        ],
        bad_pattern: "Checking `'127.0.0.1' in url` or only `is_private` (misses CGNAT `100.64.0.0/10`, `::ffff:127.0.0.1`, empty IPs, `file://`, and `\\r\\n` CRLF)",
        good_pattern: "Allow only `http`/`https`, reject `\\r`/`\\n` in URL & headers, require non-empty `resolved_ips`, unwrap `ip.ipv4_mapped or ip`, and require `ip.is_global`",
        precondition: "Validating outbound URLs, webhooks, HTTP headers, or resolved destination IPs",
    },
    PitfallEntry {
        id: "LT-020",
        slug: "zip_slip_symlink_bomb",
        category: "security",
        languages: &["*"],
        trigger_groups: &[&["zipfile", "extract", "extractall", "tarfile", "archive", "zip", "unzip"]],
        bad_pattern: "Calling `extractall()`, checking only `..`, or ignoring Unix symlink entries and decompression bomb size",
        good_pattern: "Reject symlink members (`stat.S_ISLNK(info.external_attr >> 16)`), confine via `realpath` + `root + os.sep`, and stream-read enforcing cumulative `max_total_bytes`",
        precondition: "Extracting any untrusted zip/tar archive",
    },
    PitfallEntry {
        id: "LT-021",
        slug: "jwt_alg_pin_claims",
        category: "security",
        languages: &["*"],
        trigger_groups: &[
            &["jwt", "hs256", "b64decode", "urlsafe"],
            &["alg", "aud", "exp", "token", "secret", "payload"],
        ],
        bad_pattern: "Trusting untrusted header `alg` (`alg: none`), using `==` on signature, or skipping `exp`/`aud` checks and crashing on bad base64",
        good_pattern: "Pin exact `hdr.get('alg') == 'HS256'`, verify via `hmac.compare_digest`, enforce `exp > now_ts` & `aud == expected_aud`, and return `None` on decode errors",
        precondition: "Verifying JWT or signed bearer tokens",
    },
    PitfallEntry {
        id: "LT-022",
        slug: "redos_and_dollar_newline",
        category: "security",
        languages: &["python", "typescript", "javascript"],
        trigger_groups: &[
            &["re", "regex", "compile", "match", "fullmatch"],
            &["slug", "pattern", "valid", "validate", "text"],
        ],
        bad_pattern: "Nested quantifiers `(a+)+$` (ReDoS freeze) or Python `re.match(r'...$', s)` where `$` matches before trailing `\\n` (`'admin\\n'` passes!)",
        good_pattern: "Use linear non-backtracking regex (`^[a-z0-9]+(?:-[a-z0-9]+)*\\Z` or `re.fullmatch`), explicit length bound, and reject `'\\n'`",
        precondition: "Validating slugs, usernames, emails, or untrusted strings via regex",
    },
    PitfallEntry {
        id: "LT-023",
        slug: "deep_merge_proto_dunder_pollution",
        category: "security",
        languages: &["python", "typescript", "javascript"],
        trigger_groups: &[
            &["merge", "deep", "patch", "proto", "setattr"],
            &["dict", "config", "base", "patch", "items"],
        ],
        bad_pattern: "Mutating `base` in-place or allowing `__proto__`, `constructor`, `prototype`, `__class__`, `__globals__`, `__dict__`, `__init__` in untrusted patches",
        good_pattern: "Recursively reject dangerous/dunder keys (`__proto__`, `constructor`, `prototype`, any `__*__`) and `copy.deepcopy` nested dicts/lists so callers are never mutated",
        precondition: "Merging or applying untrusted JSON/config patches",
    },
    PitfallEntry {
        id: "LT-024",
        slug: "csv_formula_injection",
        category: "security",
        languages: &["*"],
        trigger_groups: &[&["csv", "writer", "writerow", "spreadsheet", "excel"]],
        bad_pattern: "Writing raw user cells to CSV where leading `=`, `+`, `-`, `@`, `\\t`, `\\r` execute spreadsheet formulas",
        good_pattern: "Prefix any string cell whose value (or whitespace-stripped value) begins with `=`, `+`, `-`, `@`, `\\t`, or `\\r` with `'` before `writerow`",
        precondition: "Exporting user-supplied data to CSV/TSV/Excel spreadsheets",
    },
    PitfallEntry {
        id: "LT-025",
        slug: "xml_xxe_dtd_bomb",
        category: "security",
        languages: &["*"],
        trigger_groups: &[&["xml", "etree", "fromstring", "minidom", "doctype", "elementtree"]],
        bad_pattern: "Passing raw XML directly to `ET.fromstring` without size limit or `<!DOCTYPE`/`<!ENTITY` rejection",
        good_pattern: "Enforce `len(raw_xml) <= max_bytes` and reject `<!DOCTYPE` or `<!ENTITY` (case-insensitive) with `SecurityViolationError` before parsing",
        precondition: "Parsing untrusted XML documents or configuration payloads",
    },
    PitfallEntry {
        id: "LT-026",
        slug: "oauth_redirect_exact_origin",
        category: "security",
        languages: &["*"],
        trigger_groups: &[
            &["redirect", "oauth", "callback"],
            &["origin", "origins", "uri", "url", "allowed", "startswith"],
        ],
        bad_pattern: "`redirect_uri.startswith(origin)` (bypassed by `https://ok.com.evil.com`, `https://ok.com@evil.com`, `\\\\@`, `//evil.com`)",
        good_pattern: "Reject backslashes/userinfo (`@`), parse with `urlsplit`, and require exact `(scheme, hostname, port)` match against parsed `allowed_origins`",
        precondition: "Validating OAuth `redirect_uri` or post-login redirect URLs",
    },
    PitfallEntry {
        id: "LT-027",
        slug: "monotonic_rate_bucket",
        category: "concurrency",
        languages: &["*"],
        trigger_groups: &[
            &["bucket", "refill", "limiter", "ratelimit"],
            &["tokens", "capacity", "clock", "allow", "cost"],
        ],
        bad_pattern: "Using `time.time()` without lock, failing on backward clock jump, forgetting `cost <= 0` check, or rejecting valid `refill_per_sec == 0`",
        good_pattern: "Default `clock_fn=time.monotonic`, guard with `threading.Lock`, clamp `elapsed = max(0.0, now - self._last)`, allow `refill_per_sec >= 0`, reject `cost <= 0` (`ValueError`)",
        precondition: "Implementing rate limiters, token buckets, or burst controllers",
    },
    PitfallEntry {
        id: "LT-028",
        slug: "sql_cursor_tiebreaker_limit",
        category: "sql",
        languages: &["*"],
        trigger_groups: &[
            &["paginate", "pagination", "offset", "after"],
            &["limit", "cursor", "order", "orders", "created"],
        ],
        bad_pattern: "Allowing `limit <= 0` (SQLite `LIMIT -1` returns ALL rows!) or paginating by non-unique `created_at` alone (drops tied rows)",
        good_pattern: "Reject `bool`/non-positive `limit` (`ValueError`), cap `min(limit, 100)`, and use deterministic `(created_at ASC, id ASC)` with `(created_at > ? OR (created_at = ? AND id > ?))`",
        precondition: "SQL cursor pagination or bounded list queries",
    },
    PitfallEntry {
        id: "LT-029",
        slug: "domain_exception_hierarchy_and_finally",
        category: "reliability",
        languages: &["python"],
        trigger_groups: &[
            &["domain", "unit", "cycle", "exit"],
            &["error", "commit", "rollback", "close", "exception"],
        ],
        bad_pattern: "Subclassing bare `Exception` for validation/cycle errors (breaks callers catching `ValueError`) or skipping `try...finally` around `on_commit`/`on_close`",
        good_pattern: "Inherit domain validation/cycle errors from `ValueError`, and wrap `__exit__` commit/rollback in `try: ... finally: self._on_close()`",
        precondition: "Defining domain validation exceptions or resource/transaction context managers",
    },
    PitfallEntry {
        id: "LT-030",
        slug: "late_binding_closure_and_deepcopy",
        category: "python",
        languages: &["python"],
        trigger_groups: &[
            &["lambda", "adders", "closure", "snapshot"],
            &["tiers", "cfg", "config", "dict", "list"],
        ],
        bad_pattern: "`[lambda x: x + t for t in tiers]` (late-binds every lambda to final `t`) or `dict(cfg)` shallow copy aliasing nested dicts/lists",
        good_pattern: "Bind loop var by value `[lambda x, t=t: x + t for t in tiers]` and use `copy.deepcopy(cfg)` for isolated snapshots",
        precondition: "Creating closures inside loops or snapshotting nested dicts/lists",
    },
    PitfallEntry {
        id: "LT-031",
        slug: "nan_inf_bool_risk_poisoning",
        category: "fintech",
        languages: &["python", "typescript", "javascript"],
        trigger_groups: &[
            &["risk", "nan", "inf", "isfinite", "max"],
            &["limit", "amount", "float", "decimal", "range"],
        ],
        bad_pattern: "`if val <= 0 or val > max_limit:` on `float('nan')` evaluates BOTH branches to `False`, bypassing the limit guard completely",
        good_pattern: "Reject `bool`, convert via `Decimal(str(amount))` (never `float`), and require `val.is_finite()` / `math.isfinite()` before checking `0 < val <= max_limit`",
        precondition: "Validating numeric amounts, risk caps, scores, or thresholds from untrusted inputs",
    },
    PitfallEntry {
        id: "LT-032",
        slug: "unicode_nfkc_casefold_zwsp",
        category: "security",
        languages: &["*"],
        trigger_groups: &[
            &["username", "usernames", "blocklist", "denylist", "normalize", "unicodedata"],
            &["blocked", "banned", "allowlist", "in", "casefold", "nfkc"],
        ],
        bad_pattern: "Raw `username in blocked` bypassed by `'Admin'`, zero-width `'a\\u200bdmin'`, fullwidth `'\\uff41dmin'`, or `'stra\\u00dfe'`",
        good_pattern: "Strip zero-width/format chars (`\\u200b\\u200c\\u200d\\u2060\\ufeff\\u00ad`) and apply `unicodedata.normalize('NFKC', s).casefold()` to BOTH input and blocklist",
        precondition: "Comparing usernames, identifiers, or strings against security blocklists/allowlists",
    },
    PitfallEntry {
        id: "LT-033",
        slug: "sqlite_atomic_fk_rollback",
        category: "sql",
        languages: &["python"],
        trigger_groups: &[
            &["sqlite3", "transfers", "accounts"],
            &["commit", "rollback", "balance", "update", "insert"],
        ],
        bad_pattern: "Executing multi-statement SQLite debit/credit without `PRAGMA foreign_keys = ON`, rowcount/balance check, or `rollback()` on exception",
        good_pattern: "Enable `PRAGMA foreign_keys = ON`, verify `amount > 0` + `rowcount == 1` + balance inside `try: ... conn.commit() except Exception: conn.rollback(); raise`",
        precondition: "Multi-statement SQLite balance/inventory/ledger transfers",
    },
    PitfallEntry {
        id: "LT-034",
        slug: "ttl_lru_composite_tuple_key",
        category: "reliability",
        languages: &["python", "typescript", "javascript"],
        trigger_groups: &[
            &["cache", "lru", "evict", "ordereddict"],
            &["maxsize", "ttl", "namespace", "key", "store"],
        ],
        bad_pattern: "String-joined cache key `f'{ns}_{key}'` (`('a_b','c') == ('a','b_c')`), unbounded dict OOM, or returning TTL-expired entries",
        good_pattern: "Key by typed tuple `(namespace, key)` in `OrderedDict`, purge expired entries (`now >= exp`) on `get()`, move hit to end, and pop oldest when `len > maxsize`",
        precondition: "Implementing in-memory TTL/LRU caches with namespaced keys",
    },
    PitfallEntry {
        id: "LT-035",
        slug: "ts_bigint_json_serialize",
        category: "typescript",
        languages: &["typescript", "javascript"],
        trigger_groups: &[
            &["bigint", "serialize", "stringify"],
            &["json", "order", "record", "response", "vnd", "id"],
        ],
        bad_pattern: "`JSON.stringify(obj)` throwing `TypeError` on `BigInt`, or `Number(bigint)` corrupting IDs `> Number.MAX_SAFE_INTEGER` (`2^53 - 1`)",
        good_pattern: "Use `JSON.stringify(obj, (_k, v) => (typeof v === 'bigint' ? v.toString() : v))` to preserve exact decimal precision recursively",
        precondition: "Serializing MySQL BIGINT IDs or financial amounts to JSON in Node.js/NestJS",
    },
    PitfallEntry {
        id: "LT-036",
        slug: "mysql_json_column_dual_shape",
        category: "typescript",
        languages: &["typescript", "javascript"],
        trigger_groups: &[
            &["mysql", "column", "encode", "decode", "parse"],
            &["json", "stringify", "raw", "null", "undefined"],
        ],
        bad_pattern: "Blindly calling `JSON.parse(raw)` when `mysql2` already returned an object (`'[object Object]'` crash) or `String(val)` on encode",
        good_pattern: "Return `null` on `null`/`undefined`; on decode check `typeof raw === 'string' ? JSON.parse(raw) : raw`; on encode use `JSON.stringify(val)`",
        precondition: "Reading or writing MySQL JSON columns in Node.js/TypeScript",
    },
    PitfallEntry {
        id: "LT-037",
        slug: "ts_bounded_async_concurrency",
        category: "typescript",
        languages: &["typescript", "javascript"],
        trigger_groups: &[
            &["concurrency", "maxconcurrency", "batches", "worker", "foreach"],
            &["async", "promise", "items", "await", "sync"],
        ],
        bad_pattern: "`items.forEach(async ...)` (unawaited empty array!) or unbounded `Promise.all(items.map(worker))` exhausting DB connection pools",
        good_pattern: "Run `Math.min(maxConcurrency, items.length)` async workers pulling `nextIdx++` and storing `results[idx] = await worker(items[idx])` to cap in-flight calls and preserve order",
        precondition: "Processing async batches against MySQL/HTTP with a concurrency cap",
    },
    PitfallEntry {
        id: "LT-038",
        slug: "js_proto_pollution_immutable_merge",
        category: "typescript",
        languages: &["typescript", "javascript"],
        trigger_groups: &[
            &["merge", "settings", "tenant", "deep", "patch"],
            &["record", "object", "keys", "base", "proto"],
        ],
        bad_pattern: "Mutating `base` in-place or copying `__proto__`, `constructor`, `prototype` keys (polluting `Object.prototype` via `JSON.parse`)",
        good_pattern: "Clone into fresh objects/arrays (`structuredClone` or recursive copy) without mutating `base`, and reject/throw on `__proto__`, `constructor`, or `prototype` at every depth",
        precondition: "Merging untrusted tenant/user JSON config objects in JavaScript/TypeScript",
    },
    PitfallEntry {
        id: "LT-039",
        slug: "ts_nullish_preserve_default_strict_eq",
        category: "typescript",
        languages: &["typescript", "javascript"],
        trigger_groups: &[
            &["discount", "coupon", "subtotal", "cents", "bonus"],
            &["number", "string", "total", "effective", "compute"],
        ],
        bad_pattern: "Using `discount || 100` (drops explicit `0`), over-fixing to `discount ?? 0` (breaks `undefined` default `100`!), or loose `coupon == 0` (`'' == 0` is `true`)",
        good_pattern: "Preserve the original fallback via nullish coalescing `discountCents ?? 100` (keeps `0` as `0`, defaults `undefined`/`null` to `100`) and use strict `===`",
        precondition: "Handling optional numeric defaults or string comparisons in JS/TS",
    },
    PitfallEntry {
        id: "LT-040",
        slug: "ts_allsettled_timeout_return_values",
        category: "typescript",
        languages: &["typescript", "javascript"],
        trigger_groups: &[
            &["webhooks", "dispatch", "timeout", "timeoutms", "targets"],
            &["promise", "async", "succeeded", "failed", "send"],
        ],
        bad_pattern: "`Promise.all` aborting all targets on 1 error, missing `clearTimeout`, or pushing target URLs into `succeeded` instead of resolved `sendFn(t)` return values",
        good_pattern: "Use `Promise.allSettled` with per-call `Promise.race` + `clearTimeout` in `finally`; push fulfilled `r.value` into `succeeded` and failed/timed-out targets into `failed`",
        precondition: "Fan-out async dispatchers with per-request timeouts",
    },
    PitfallEntry {
        id: "LT-041",
        slug: "ts_sql_params_and_strict_orderby_allowlist",
        category: "typescript",
        languages: &["typescript", "javascript"],
        trigger_groups: &[
            &["sortcol", "sortdir", "orderby", "buildorder", "query"],
            &["sql", "params", "select", "orders", "status"],
        ],
        bad_pattern: "Interpolating `'${status}'` or `${sortCol}`, rewriting `status` via an invented enum, or silently falling back on injected `sortCol`/`sortDir` instead of throwing",
        good_pattern: "Bind `status` directly via `?` (`params: [status]`) without mutating its case/value, and validate `sortCol` (`id`/`status`/`total_vnd`) & `sortDir` (`ASC`/`DESC`) against strict allowlists throwing `Error` on mismatch",
        precondition: "Building dynamic SQL queries with parameterized filters and ORDER BY clauses in TS/JS",
    },
    PitfallEntry {
        id: "LT-042",
        slug: "ts_async_eventloop_per_key_mutex",
        category: "typescript",
        languages: &["typescript", "javascript"],
        trigger_groups: &[
            &["allocator", "reserve", "stock", "sku", "delay"],
            &["async", "await", "map", "promise", "qty"],
        ],
        bad_pattern: "Reading `this.stock.get(sku)` before `await ioDelayFn()` and writing back after `await`, allowing concurrent calls to double-spend inventory",
        good_pattern: "Chain a per-SKU Promise mutex (`tail.then(() => run(), () => run())`) so concurrent `reserveStockAsync` calls for the same SKU execute strictly serially",
        precondition: "Check-then-act async state transitions across `await` boundaries in Node.js",
    },
    PitfallEntry {
        id: "LT-043",
        slug: "sol_fee_on_transfer_delta_credit",
        category: "solidity",
        languages: &["solidity"],
        trigger_groups: &[
            &["transferfrom", "balanceof", "deposit", "feevault"],
            &["balances", "token", "amount", "withdraw"],
        ],
        bad_pattern: "Crediting `balances[msg.sender] += amount` or reverting `require(received == amount)` (breaks Fee-on-Transfer tokens)",
        good_pattern: "Measure `balBefore = token.balanceOf(address(this))`, transfer, compute `received = token.balanceOf(address(this)) - balBefore`, `require(received > 0)`, and credit `balances[msg.sender] += received`",
        precondition: "Depositing arbitrary ERC-20 tokens into a vault or pool",
    },
    PitfallEntry {
        id: "LT-044",
        slug: "sol_cross_function_reentrancy_cei",
        category: "solidity",
        languages: &["solidity"],
        trigger_groups: &[
            &["rewardvault", "transferbalance", "withdraw", "call"],
            &["balances", "value", "msg", "payable"],
        ],
        bad_pattern: "Sending ETH via `msg.sender.call{value: bal}('')` before zeroing `balances[msg.sender] = 0` or leaving `transferBalance` unguarded against cross-function reentrancy",
        good_pattern: "Apply CEI (`balances[msg.sender] = 0` BEFORE external call) AND guard ALL balance-mutating functions (`withdraw`, `transferBalance`, `deposit`) with a shared `nonReentrant` lock",
        precondition: "Solidity contracts making external ETH/token calls while tracking user balances",
    },
    PitfallEntry {
        id: "LT-045",
        slug: "sol_readonly_reentrancy_view_lock",
        category: "solidity",
        languages: &["solidity"],
        trigger_groups: &[
            &["getvirtualprice", "removeliquidity", "liquiditypool", "totalsupply"],
            &["balance", "shares", "call", "view"],
        ],
        bad_pattern: "Sending ETH before updating `shares`/`totalSupply` and exposing `getVirtualPrice()` without checking the reentrancy lock (stale price oracle during callback)",
        good_pattern: "Update `shares` and `totalSupply` BEFORE sending ETH under `nonReentrant`, AND enforce `require(_locked == 1, 'REENTRANT')` inside `getVirtualPrice()`",
        precondition: "Liquidity pools exposing view pricing/share-ratio functions alongside ETH/callback withdrawals",
    },
    PitfallEntry {
        id: "LT-046",
        slug: "sol_eip712_permit_dynamic_domain_low_s",
        category: "solidity",
        languages: &["solidity"],
        trigger_groups: &[
            &["permit", "ecrecover", "computedigest", "nonces"],
            &["deadline", "allowance", "spender", "owner"],
        ],
        bad_pattern: "Declaring `constant DOMAIN_SEPARATOR` with `block.chainid`/`address(this)` (Solc Error 8349!), skipping `nonces[owner]++`/`deadline`/`chainid`, or allowing EIP-2 malleable high-`s`",
        good_pattern: "Compute digest dynamically in `view` with `block.chainid`, `address(this)`, `nonce`, `deadline`; enforce `block.timestamp <= deadline`, `nonces[owner]++`, `v == 27 || v == 28`, `uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0`, and `recovered != address(0) && recovered == owner`",
        precondition: "Implementing `permit()` or `ecrecover`-based gasless signatures in Solidity",
    },
    PitfallEntry {
        id: "LT-047",
        slug: "sol_erc4626_zero_share_and_ceil_withdraw",
        category: "solidity",
        languages: &["solidity"],
        trigger_groups: &[
            &["totalshares", "totalassets", "sharebalance", "simplesharevault"],
            &["deposit", "withdraw", "shares", "assets"],
        ],
        bad_pattern: "Allowing `deposit()` to mint `0` shares after large donation, or rounding `sharesBurned` DOWN in `withdraw(assets)` (free 1-wei withdrawal drain)",
        good_pattern: "In `deposit()`, `require(shares > 0, 'ZERO_SHARES')`; in `withdraw(assets)`, round UP: `sharesBurned = (assets * (totalShares + 1e6) + totalAssets) / (totalAssets + 1)` (`ceilDiv`)",
        precondition: "Solidity ERC-4626 / share-accounting vaults converting assets and shares",
    },
    PitfallEntry {
        id: "LT-048",
        slug: "sol_safe_erc20_lowlevel_call",
        category: "solidity",
        languages: &["solidity"],
        trigger_groups: &[
            &["safeescrow", "deposittoken", "releasetoken", "ierc20like"],
            &["transferfrom", "transfer", "token", "deposits"],
        ],
        bad_pattern: "Ignoring ERC-20 `bool` return (accepts silent `false`!) or typed interface call reverting on USDT-style non-returning ERC-20s",
        good_pattern: "Use low-level `token.call(abi.encodeWithSelector(IERC20Like.transferFrom.selector, ...))` and `require(ok && (data.length == 0 || abi.decode(data, (bool))), 'SAFE_ERC20_FAIL')`",
        precondition: "Escrows or vaults interacting with arbitrary / USDT-style ERC-20 tokens",
    },
    PitfallEntry {
        id: "LT-049",
        slug: "sol_access_fee_cap_slippage_deadline",
        category: "solidity",
        languages: &["solidity"],
        trigger_groups: &[
            &["setfeebps", "tokenswap", "minamountout", "feebps"],
            &["swap", "owner", "deadline", "amountin"],
        ],
        bad_pattern: "Unprotected `setFeeBps` without `onlyOwner` or upper bound (`<= 1000` bps), or `swap()` ignoring `minAmountOut` and `deadline`",
        good_pattern: "Enforce `msg.sender == owner` + `newFeeBps <= 1000` on `setFeeBps`, and enforce `block.timestamp <= deadline` + `amountOut >= minAmountOut` in `swap()`",
        precondition: "Admin parameter setters and AMM/swap entrypoints in Solidity",
    },
    PitfallEntry {
        id: "LT-050",
        slug: "sol_pull_over_push_and_msg_sender",
        category: "solidity",
        languages: &["solidity"],
        trigger_groups: &[
            &["batchpayout", "distribute", "claimable", "origin"],
            &["recipients", "amounts", "claim", "owner"],
        ],
        bad_pattern: "Authenticating with `tx.origin == owner` (phishable!) and pushing ETH inside a loop with `require(ok)` (1 reverting receiver DoS-bricks everyone)",
        good_pattern: "Check `msg.sender == owner` (never `tx.origin`), require `msg.value == totalAmount`, credit `claimable[recipients[i]] += amounts[i]` in `distribute()`, and pay via CEI in `claim()`",
        precondition: "Batch ETH/token payout contracts and owner authentication in Solidity",
    },
    // === ROUND 4: REAL-WORLD BOUNTY / RECEIVABLES / RELEASE-HYGIENE SCARS (LT-051..LT-062) ===
    PitfallEntry {
        id: "LT-051",
        slug: "mm_wallet_no_random_fallback_sign_recover",
        category: "fintech",
        languages: &["python", "typescript", "javascript"],
        trigger_groups: &[
            &["payout", "wallet", "private_key", "privatekey", "derive"],
            &["recover", "sign", "getrandbits", "token_hex", "urandom"],
        ],
        bad_pattern: "Falling back to random 20-byte hex (`token_hex(20)`/`getrandbits(160)`/`urandom(20)`) when crypto libs fail, or skipping `sign -> recover == address` verification",
        good_pattern: "Fail closed (`RuntimeError`) if derivation fails or returns `None`, validate address format, and assert `recover_fn(challenge, sign_fn(pk, challenge)).lower() == addr.lower()` before returning",
        precondition: "Deriving or registering any EVM/Solana payout wallet address from a private key",
    },
    PitfallEntry {
        id: "LT-052",
        slug: "mm_zero_deposit_and_cosign_safety_gate",
        category: "fintech",
        languages: &["*"],
        trigger_groups: &[
            &["depositRequired", "stake_required", "deposit_required", "transfersFunds", "moves_sol", "submissioncount", "submissions", "cosign"],
            &["escrow", "bounty", "tx_payload", "job_meta", "verifiedby", "verified_by"],
        ],
        bad_pattern: "Allowing `depositRequired=True`, `deposit_required>0`, `entry_fee>0`, `submissionCount>=50`, `tap:identity:*` card gates (in str OR list `verifiedBy`), `UNESCROWED`, missing/`None` `transfersFunds`, `value>0`, or `ERC20.transfer`/`approve`/`transferWithAuthorization`; or over-blocking valid `ESCROWED` + `personal_sign` (`value==0, transfersFunds is False`)",
        good_pattern: "Fail closed returning `(False, reason)` if ANY deposit/fee/cap(`>=50`)/any `verifiedBy` item (str or list) containing `tap:identity:`/`escrow_status!='ESCROWED'`/`value!=0`/`transfersFunds is not False`/outbound method (`ERC20.transfer`, `ERC20.approve`, `transferWithAuthorization`, `eth_sendRawTransaction`) appears; return `(True, 'SAFE')` when all checks pass",
        precondition: "Evaluating bounty job eligibility or co-sign transaction payloads under receive-only zero-deposit rules",
    },
    PitfallEntry {
        id: "LT-053",
        slug: "mm_forensic_raw_http_bom_cdn_freshness",
        category: "reliability",
        languages: &["python", "typescript", "javascript"],
        trigger_groups: &[
            &["raw_body_bytes", "raw_body", "http_date_epoch", "http_date", "retrieved_utc"],
            &["forensic", "excerpt", "raw_sha256", "drift_sec", "entity_id"],
        ],
        bad_pattern: "Decoding raw bytes with plain `utf-8` (crashes on UTF-8 BOM `\\xef\\xbb\\xbf`), hashing `json.dumps()` instead of `raw_body_bytes`, reformatting excerpts via `json.dumps`, or accepting CDN drift `> 5s`",
        good_pattern: "Reject `abs(http_date - retrieved_utc) > 5.0` (`ValueError`), hash exact `raw_body_bytes` for `raw_sha256`, decode with `utf-8-sig` for `json.loads`, require `entity_id` in raw text, and slice `excerpt` verbatim from original raw text",
        precondition: "Capturing verifiable HTTP API evidence, checksums, and raw excerpts",
    },
    PitfallEntry {
        id: "LT-054",
        slug: "mm_multipull_id_csv_parity_and_meta_ban",
        category: "reliability",
        languages: &["*"],
        trigger_groups: &[
            &["pull1_ids", "pull1_headers", "pull2_headers", "pull2_rows", "multipull"],
            &["report_markdown", "deliverable", "headers", "pull1", "pull2"],
        ],
        bad_pattern: "Checking CSV headers with unordered `set()` (misses reordered columns), ignoring missing/added IDs between Pull 1 and Pull 2, or allowing meta-evaluator/dispute words in deliverable prose",
        good_pattern: "Require exact ordered header equality `list(pull2_headers) == list(pull1_headers)`, exact ID set match `{r['id'] for r in pull2_rows} == set(pull1_ids)` + row count, and reject case-insensitive meta words (`evaluator`, `revision`, `dispute`, `appeal`, `requirements met`)",
        precondition: "Validating multi-pull audit datasets and deliverable markdown reports",
    },
    PitfallEntry {
        id: "LT-055",
        slug: "mm_no_stub_verbatim_cli_and_soft404",
        category: "reliability",
        languages: &["*"],
        trigger_groups: &[
            &["cmd_result", "returncode", "mock_tx_hash", "_simulated", "recentjobs"],
            &["html_body", "api_payload", "http_status", "stdout", "stderr"],
        ],
        bad_pattern: "Fabricating `_simulated=True`/`mock_tx_hash` when `returncode != 0`, truncating `stdout[:80]`, accepting HTTP 200 login-wall/Request-Access HTML, or silently guessing nonexistent keys like `recentJobs`",
        good_pattern: "Raise `RuntimeError`/`ValueError` on `returncode != 0`, keep 100% verbatim `stdout`/`stderr`, reject `http_status != 200` or soft-404/auth walls (`request access`, `sign in`, `404 not found`), and require exact `'jobs' in api_payload`",
        precondition: "Normalizing CLI execution output, fetched HTML pages, and JSON API responses",
    },
    PitfallEntry {
        id: "LT-056",
        slug: "mm_mass_assignment_allowlist_and_tenant",
        category: "security",
        languages: &["python", "typescript", "javascript"],
        trigger_groups: &[
            &["untrusted_patch", "existing_user", "caller_tenant_id", "allowed_profile_fields", "mass_assignment"],
            &["tenant_id", "tenant", "profile", "update"],
        ],
        bad_pattern: "Calling `existing_user.update(untrusted_patch)` (in-place mutation + mass-assignment of `role`/`is_admin`/`tenant_id`), silently ignoring forbidden keys, or skipping `existing_user['tenant_id'] == caller_tenant_id`",
        good_pattern: "Verify `existing_user['tenant_id'] == caller_tenant_id` (`PermissionError`), reject ANY key not in `ALLOWED_PROFILE_FIELDS` (`ValueError`), and return a new copy without mutating `existing_user`",
        precondition: "Applying user-supplied update patches in multi-tenant profile/account APIs",
    },
    PitfallEntry {
        id: "LT-057",
        slug: "mm_atomic_integer_mul_before_div",
        category: "fintech",
        languages: &["python", "typescript", "javascript", "solidity"],
        trigger_groups: &[
            &["amount_atomic", "fee_bps", "bps_rate", "micro_usdc", "split_micro"],
            &["10000", "bps", "atomic", "fee", "net"],
        ],
        bad_pattern: "Premature integer floor division `(amount_atomic // 10000) * fee_bps` (loses 100% of small fees), `float()` precision loss on `10**18` ints, rounding UP instead of floor, or accepting `bool`/negative/`fee_bps > 10000`",
        good_pattern: "Reject `isinstance(x, bool)` or non-`int` or `amount_atomic < 0` or not `0 <= fee_bps <= 10000` (`ValueError`), then compute exact integer floor `fee = (amount_atomic * fee_bps) // 10_000` and `net = amount_atomic - fee`",
        precondition: "Computing basis-point splits or fee deductions on integer atomic token units",
    },
    PitfallEntry {
        id: "LT-058",
        slug: "mm_http_429_retry_after_and_idempotency",
        category: "reliability",
        languages: &["python", "typescript", "javascript"],
        trigger_groups: &[
            &["retry_after", "max_retries", "max_wait_s", "sleep_fn", "backoff"],
            &["idempotency_key", "idempotency", "request_fn", "post", "429"],
        ],
        bad_pattern: "Hardcoding `sleep(1.0)` ignoring `Retry-After` inside `resp['headers']`, retrying non-transient `400`/`401`/`403`/`404` errors, omitting `Idempotency-Key` header, or accepting empty `idempotency_key`",
        good_pattern: "Reject empty/blank `idempotency_key` (`ValueError`), send `'Idempotency-Key': idempotency_key` on every attempt, retry ONLY `{429, 502, 503, 504}` up to `max_retries`, and read `Retry-After` case-insensitively from `resp.get('headers', {})` (clamped to `[0.0, max_wait_s]`)",
        precondition: "Implementing HTTP POST retry loops against rate-limited external APIs",
    },
    PitfallEntry {
        id: "LT-059",
        slug: "mm_redirect_strip_auth_cross_origin",
        category: "security",
        languages: &["python", "typescript", "javascript"],
        trigger_groups: &[
            &["follow_safe_redirects", "max_hops", "redirect", "location"],
            &["fetch_once", "headers", "authorization", "start_url", "302"],
        ],
        bad_pattern: "Forwarding `Authorization`/`Cookie`/`X-API-Key`/`Proxy-Authorization` across cross-origin redirects, omitting `urljoin` for relative `Location`, or looping infinitely without `max_hops`",
        good_pattern: "Resolve `urljoin(url, location)`, enforce `http`/`https` and `hops <= max_hops` (`RuntimeError`/`ValueError`), keep headers on identical `(scheme, host, port)` origin, and case-insensitively strip `authorization`/`cookie`/`x-api-key`/`proxy-authorization` on cross-origin hops",
        precondition: "Following HTTP 301/302/303/307/308 redirects with authenticated request headers",
    },
    PitfallEntry {
        id: "LT-060",
        slug: "mm_git_lf_split_u2028_and_md_code_fence",
        category: "reliability",
        languages: &["python", "typescript", "javascript"],
        trigger_groups: &[
            &["git_stdout", "splitlines", "markdown_text", "section_heading"],
            &["paths", "section_body", "markdown", "split"],
        ],
        bad_pattern: "Using `str.splitlines()` on git paths (corrupts Unicode `U+2028`/`U+2029`/`U+0085` filenames) or `markdown_text.split(heading, 1)` (falsely matches headings inside fenced code blocks)",
        good_pattern: "Split `git_stdout` strictly on `'\\n'` (never `.splitlines()`), strip only trailing `'\\r'`, and parse markdown line-by-line toggling fenced-block state on triple-backtick/tilde fences so headings inside code blocks are ignored",
        precondition: "Parsing git file path output or extracting sections from Markdown documents",
    },
    PitfallEntry {
        id: "LT-061",
        slug: "mm_flock_single_instance_and_finally_cleanup",
        category: "concurrency",
        languages: &["python"],
        trigger_groups: &[
            &["lock_file_path", "open_resource_fn", "work_fn", "flock", "worker_session"],
            &["close", "lock", "resource", "session"],
        ],
        bad_pattern: "Running daemon/browser sessions without an exclusive non-blocking `fcntl.flock` lock or calling `res.close()` outside `try...finally` (leaking handles/RAM when `work_fn` raises)",
        good_pattern: "Open `lock_file_path` (`O_CREAT|O_RDWR`, `0o600`), acquire `fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)` (fail fast if held), and release `res.close()` + `flock(LOCK_UN)` + `os.close(fd)` inside `try...finally`",
        precondition: "Guarding worker daemons and managed browser/subprocess resources",
    },
    PitfallEntry {
        id: "LT-062",
        slug: "mm_public_release_dlp_and_placeholder_exempt",
        category: "security",
        languages: &["*"],
        trigger_groups: &[
            &["sanitize_public_release_bundle", "file_map", "release_bundle", "public_release"],
            &["violations", "path", "bundle", "sanitize"],
        ],
        bad_pattern: "Allowing `.env`/`.DS_Store`/`__pycache__`/`.coverage`, PEM private-key blocks, `sk-live-`/`ghp_`/`AKIA` tokens, or RFC-1918 LAN IPs (`192.168.x.x`/`10.x.x.x`) & local `/Users/<name>/` paths into public releases — OR false-flagging benign `EXAMPLE_PLACEHOLDER_0000` constants",
        good_pattern: "Flag dirty paths (`.env`, `.DS_Store`, `__pycache__`, `.coverage`), PEM private-key headers, concrete token prefixes (`sk-live-`, `ghp_`, `AKIA`), and RFC-1918 LAN IPs / `/Users/<user>/` host paths, while NOT flagging benign `EXAMPLE_PLACEHOLDER` fixtures",
        precondition: "Scanning public PR/export file maps for secret leaks, internal paths, and dirty build artifacts",
    },
];

#[derive(Debug, Clone)]
pub struct LexiconMatchReport {
    pub target: String,
    pub lang: String,
    pub elapsed_us: u64,
    pub total_lexicon_entries: usize,
    pub matched_entries: Vec<&'static PitfallEntry>,
    pub compact_text: String,
    pub estimated_tokens: usize,
}

pub fn match_low_tier_lexicon_for_source(
    target_label: &str,
    code: &str,
    lang_hint: &str,
    max_entries: usize,
) -> LexiconMatchReport {
    let t0 = Instant::now();
    let (signals, _struct_tags) = extract_code_capsule_signals(code);
    let mut scored: Vec<(usize, &'static PitfallEntry)> = Vec::new();

    for entry in LOW_TIER_PITFALL_LEXICON {
        if !entry.supports_lang(lang_hint) {
            continue;
        }
        let mut hits = 0usize;
        let mut all_matched = true;
        for grp in entry.trigger_groups {
            let group_hits = grp.iter().filter(|tok| signals.contains(**tok)).count();
            if group_hits == 0 {
                all_matched = false;
                break;
            }
            hits += group_hits;
        }
        if all_matched {
            // Boost entries with structural tag matches so specific pitfalls rank first
            let struct_bonus = entry
                .trigger_groups
                .iter()
                .flat_map(|g| g.iter())
                .filter(|t| t.starts_with("@struct_") && signals.contains(**t))
                .count()
                * 4;
            scored.push((hits + struct_bonus, entry));
        }
    }

    scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.id.cmp(b.1.id)));
    let matched: Vec<&'static PitfallEntry> = scored.into_iter().take(max_entries).map(|(_, e)| e).collect();
    let compact_text = matched.iter().map(|e| e.render_compact()).collect::<Vec<_>>().join("\n");
    let estimated_tokens = if compact_text.is_empty() { 0 } else { estimate_tokens(&compact_text) };

    LexiconMatchReport {
        target: target_label.to_string(),
        lang: lang_hint.to_string(),
        elapsed_us: t0.elapsed().as_micros() as u64,
        total_lexicon_entries: LOW_TIER_PITFALL_LEXICON.len(),
        matched_entries: matched,
        compact_text,
        estimated_tokens,
    }
}

pub fn match_low_tier_lexicon_for_file(
    path: &Path,
    lang_override: Option<&str>,
    max_entries: usize,
) -> Result<LexiconMatchReport, String> {
    let content = read_regular_file_fd_verified(path, MAX_SOURCE_FILE_BYTES)?;
    let lang = lang_override
        .unwrap_or_else(|| detect_language(path).unwrap_or("other"));
    Ok(match_low_tier_lexicon_for_source(&path.to_string_lossy(), &content, lang, max_entries))
}

pub fn render_lexicon_entries_json(entries: &[&PitfallEntry]) -> JsonArr {
    let mut arr = JsonArr::with_capacity(entries.len().saturating_mul(240));
    for e in entries {
        let mut langs = JsonArr::new();
        for &l in e.languages {
            langs = langs.str(l);
        }
        arr = arr.obj(
            JsonObj::new()
                .str("id", e.id)
                .str("slug", e.slug)
                .str("category", e.category)
                .arr("languages", langs)
                .str("bad_pattern", e.bad_pattern)
                .str("good_pattern", e.good_pattern)
                .str("precondition", e.precondition)
                .str("compact", &e.render_compact()),
        );
    }
    arr
}

pub fn render_lexicon_report_json(rep: &LexiconMatchReport) -> String {
    JsonObj::with_capacity(rep.compact_text.len() + 360)
        .bool("ok", true)
        .str("schema_version", ENGINE_VERSION)
        .str("engine", "kintsugi-rs")
        .str("lexicon_version", "low_tier_lexicon_v1")
        .str("target", &rep.target)
        .str("lang", &rep.lang)
        .u64("elapsed_us", rep.elapsed_us)
        .f64_3("elapsed_ms", (rep.elapsed_us as f64) / 1000.0)
        .usize("total_lexicon_entries", rep.total_lexicon_entries)
        .usize("matched_count", rep.matched_entries.len())
        .usize("estimated_tokens", rep.estimated_tokens)
        .arr("entries", render_lexicon_entries_json(&rep.matched_entries))
        .str("compact", &rep.compact_text)
        .finish()
}

pub fn render_all_lexicon_json() -> String {
    let all_refs: Vec<&PitfallEntry> = LOW_TIER_PITFALL_LEXICON.iter().collect();
    let compact = all_refs.iter().map(|e| e.render_compact()).collect::<Vec<_>>().join("\n");
    JsonObj::with_capacity(compact.len() + 2048)
        .bool("ok", true)
        .str("schema_version", ENGINE_VERSION)
        .str("engine", "kintsugi-rs")
        .str("lexicon_version", "low_tier_lexicon_v1")
        .usize("total_lexicon_entries", all_refs.len())
        .usize("estimated_full_tokens", estimate_tokens(&compact))
        .arr("entries", render_lexicon_entries_json(&all_refs))
        .finish()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use super::*;
    use crate::json_dom::parse_json_value;

    #[test]
    fn lexicon_has_18_unique_ids_and_jit_matches_cheap_model_pitfalls_with_zero_bloat() {
        let mut ids = BTreeSet::new();
        for e in LOW_TIER_PITFALL_LEXICON {
            assert!(ids.insert(e.id), "duplicate lexicon id {}", e.id);
            assert!(!e.bad_pattern.is_empty() && !e.good_pattern.is_empty() && !e.precondition.is_empty());
        }
        assert_eq!(LOW_TIER_PITFALL_LEXICON.len(), 62);

        // Clean unrelated dataclass -> 0 lexicon bloat!
        let benign = "from dataclasses import dataclass\n@dataclass\nclass Point:\n    x: int\n    y: int\n";
        let r0 = match_low_tier_lexicon_for_source("point.py", benign, "python", 4);
        assert_eq!(r0.matched_entries.len(), 0);
        assert_eq!(r0.estimated_tokens, 0);

        // Fintech SQL + Decimal code -> fires LT-002 & LT-003 cleanly within tight token cap
        let fin = "from decimal import Decimal\ndef settle_invoice(cursor, amount, vnd_rate):\n    total = Decimal(str(amount)) * Decimal(str(vnd_rate))\n    sql = 'SELECT id FROM invoices WHERE total = ?'\n    cursor.execute(sql, (str(total),))\n";
        let r1 = match_low_tier_lexicon_for_source("settle.py", fin, "python", 4);
        assert!(r1.matched_entries.iter().any(|e| e.id == "LT-002"));
        assert!(r1.matched_entries.iter().any(|e| e.id == "LT-003"));
        assert!(r1.estimated_tokens <= 220, "lexicon tokens bloated: {}", r1.estimated_tokens);
        assert!(parse_json_value(&render_lexicon_report_json(&r1)).is_ok());
        assert!(parse_json_value(&render_all_lexicon_json()).is_ok());
    }
}
