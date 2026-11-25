//! Pre-Read JIT Symbol-Scoped AST-Fingerprint & Sub-Token Invariant Capsule Engine (`rust/src/audit/capsules.rs`).
//!
//! Sub-millisecond (`< 0.5 ms`), rename-resistant **symbol-scoped** structural AST + sub-token (`snake_case` / `camelCase`)
//! capsule matcher with 2-strike consecutive regression circuit-breaker (`consecutive_losses >= 2`),
//! dead-scar auto-freeze (`trials >= 30 && win_rate < 15%`), and `O_NOFOLLOW` dynamic JSON loading.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Instant;

use crate::audit::ct2_seams::StatefulMasker;
use crate::io_json::{read_regular_file_fd_verified, JsonArr, JsonObj, ENGINE_VERSION};
use crate::json_dom::{parse_json_value, JsonValue};
use crate::scanner::MAX_SOURCE_FILE_BYTES;
use crate::token_est::estimate_tokens;

pub const MAX_CAPSULE_FILE_BYTES: u64 = 512 * 1024;
pub const MAX_DYNAMIC_CAPSULES: usize = 256;

#[derive(Debug, Clone)]
pub struct InvariantCapsule {
    pub id: String,
    pub domain: String,
    /// Conjunction of disjunctive trigger groups: EVERY group must match >=1 extracted signal.
    pub trigger_groups: Vec<Vec<String>>,
    pub when_clause: String,
    pub invariant: String,
    pub pos_ast: String,
    pub wins: u32,
    pub losses: u32,
    pub trials: u32,
    pub consecutive_losses: u32,
    pub frozen: bool,
}

impl InvariantCapsule {
    #[inline]
    pub fn is_auto_frozen(&self) -> bool {
        self.frozen
            || self.consecutive_losses >= 2
            || (self.trials >= 30 && (self.wins as u64) * 100 < (self.trials as u64) * 15)
    }

    /// Deterministic Beta posterior mean `(1 + wins) / (2 + wins + losses)` scaled to `0..=10000`.
    #[inline]
    pub fn efficacy_bp(&self) -> u32 {
        let num = 1u64 + (self.wins as u64);
        let den = 2u64 + (self.wins as u64) + (self.losses as u64);
        ((num * 10_000) / den) as u32
    }

    pub fn render_compact(&self) -> String {
        format!(
            "@CAPSULE[{}|dom={}|eff={}%]\n  WHEN: {}\n  INVARIANT: {}\n  @POS_AST: {}",
            self.id,
            self.domain,
            self.efficacy_bp() / 100,
            self.when_clause,
            self.invariant,
            self.pos_ast
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolBlock {
    pub name: String,
    pub start_line: usize,
    pub end_line: usize,
}

#[derive(Debug, Clone)]
pub struct CapsuleMatchReport {
    pub target: String,
    pub elapsed_us: u64,
    pub extracted_signals_count: usize,
    pub structural_tags: Vec<String>,
    pub matched_capsules: Vec<InvariantCapsule>,
    pub compact_text: String,
    pub estimated_tokens: usize,
}

/// Split an identifier across `snake_case`, `camelCase`, and `PascalCase` boundaries into lowercase sub-tokens.
pub fn push_ident_subtokens(ident: &str, out: &mut BTreeSet<String>) {
    if ident.len() < 2 {
        return;
    }
    let full_low = ident.to_ascii_lowercase();
    out.insert(full_low);

    let bytes = ident.as_bytes();
    let mut seg_start = 0usize;
    for i in 0..=bytes.len() {
        let boundary = if i == bytes.len() || bytes[i] == b'_' || bytes[i] == b'$' {
            true
        } else if i > seg_start {
            let prev = bytes[i - 1];
            let cur = bytes[i];
            let camel = prev.is_ascii_lowercase() && cur.is_ascii_uppercase();
            let acro = prev.is_ascii_uppercase()
                && cur.is_ascii_uppercase()
                && bytes.get(i + 1).is_some_and(|n| n.is_ascii_lowercase());
            camel || acro
        } else {
            false
        };
        if boundary {
            if i > seg_start {
                let sub = &ident[seg_start..i];
                if sub.len() >= 2 && !sub.bytes().all(|b| b.is_ascii_digit()) {
                    out.insert(sub.to_ascii_lowercase());
                }
            }
            seg_start = if i < bytes.len() && (bytes[i] == b'_' || bytes[i] == b'$') { i + 1 } else { i };
        }
    }
}

fn line_indent(line: &str) -> usize {
    line.bytes().take_while(|&b| b == b' ' || b == b'\t').count()
}

fn extract_symbol_name_after<'a>(mt: &'a str, prefix: &str) -> Option<String> {
    let rest = mt.strip_prefix(prefix)?.trim_start();
    let name: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
        .collect();
    if name.is_empty() { None } else { Some(name) }
}

fn detect_symbol_header(mt: &str) -> Option<(String, bool)> {
    // Python defs (indentation-scoped)
    for pref in ["def ", "async def "] {
        if let Some(name) = extract_symbol_name_after(mt, pref) {
            return Some((name, true));
        }
    }
    // JS/TS/Rust/Go/Java functions (brace-scoped)
    for pref in [
        "function ",
        "async function ",
        "export function ",
        "export async function ",
        "pub fn ",
        "pub(crate) fn ",
        "pub async fn ",
        "async fn ",
        "fn ",
        "func ",
    ] {
        if let Some(name) = extract_symbol_name_after(mt, pref) {
            return Some((name, false));
        }
    }
    // TS/JS class methods: `async handleOrder(...) {` or `public async debit(...) {`
    let stripped = mt
        .trim_start_matches("public ")
        .trim_start_matches("private ")
        .trim_start_matches("protected ")
        .trim_start_matches("static ")
        .trim_start_matches("async ")
        .trim_start();
    if stripped.ends_with('{') || stripped.contains(") {") || stripped.contains("): ") {
        if let Some(open_p) = stripped.find('(') {
            let head = stripped[..open_p].trim();
            if !head.is_empty()
                && head.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'$')
                && !matches!(head, "if" | "for" | "while" | "switch" | "catch" | "with" | "return")
            {
                return Some((head.to_string(), false));
            }
        }
    }
    None
}

/// Partition source into symbol/function blocks (1-indexed inclusive line spans) so structural
/// AST fingerprints NEVER bleed across unrelated functions in the same file.
pub fn extract_symbol_blocks(code: &str) -> Vec<SymbolBlock> {
    let raw_lines: Vec<&str> = code.lines().collect();
    let masked_lines = StatefulMasker::mask_file_lines(code);
    let n = raw_lines.len();
    if n == 0 {
        return Vec::new();
    }

    let mut blocks: Vec<SymbolBlock> = Vec::new();
    let mut i = 0usize;
    while i < n {
        let mt = masked_lines[i].trim();
        if let Some((name, is_py_indent)) = detect_symbol_header(mt) {
            let start = i;
            if is_py_indent {
                let hdr_indent = line_indent(raw_lines[i]);
                let mut j = i + 1;
                while j < n {
                    let rt = raw_lines[j].trim();
                    let mjt = masked_lines[j].trim();
                    if !rt.is_empty() && !mjt.is_empty() && line_indent(raw_lines[j]) <= hdr_indent {
                        break;
                    }
                    j += 1;
                }
                blocks.push(SymbolBlock {
                    name,
                    start_line: start + 1,
                    end_line: j.max(start + 1),
                });
                i = j;
                continue;
            } else {
                let mut depth: i32 = 0;
                let mut seen_open = false;
                let mut j = i;
                while j < n {
                    for b in masked_lines[j].bytes() {
                        if b == b'{' {
                            depth += 1;
                            seen_open = true;
                        } else if b == b'}' {
                            depth -= 1;
                        }
                    }
                    if seen_open && depth <= 0 {
                        j += 1;
                        break;
                    }
                    j += 1;
                }
                blocks.push(SymbolBlock {
                    name,
                    start_line: start + 1,
                    end_line: j.min(n).max(start + 1),
                });
                i = j.max(start + 1);
                continue;
            }
        }
        i += 1;
    }

    // Cover any top-level script code outside functions as a `<module>` block (only non-function lines)
    if blocks.is_empty() {
        blocks.push(SymbolBlock {
            name: "<module>".to_string(),
            start_line: 1,
            end_line: n,
        });
    }
    blocks
}

fn has_bare_open_call(mt: &str) -> bool {
    let mut from = 0usize;
    while let Some(rel) = mt[from..].find("open(") {
        let idx = from + rel;
        if idx == 0 || !matches!(mt.as_bytes()[idx - 1], b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'.') {
            return true;
        }
        from = idx + 5;
    }
    false
}

fn is_write_mode_open(raw_l: &str, mt: &str) -> bool {
    if mt.contains("os.open(") {
        return mt.contains("O_WRONLY") || mt.contains("O_CREAT") || mt.contains("O_RDWR") || mt.contains("O_APPEND");
    }
    if mt.contains("json.dump(") || mt.contains("write_text(") || mt.contains("write_bytes(") || mt.contains("writeFileSync(") {
        return true;
    }
    if has_bare_open_call(mt) {
        // Inspect string literal mode flags only when bare `open(` actually exists in masked code!
        const WRITE_MODES: &[&str] = &[
            "'w'", "\"w\"", "'wb'", "\"wb\"", "'wt'", "\"wt\"", "'a'", "\"a\"", "'ab'", "\"ab\"",
            "'x'", "\"x\"", "'xb'", "\"xb\"", "'r+'", "\"r+\"", "'w+'", "\"w+\"", "'a+'", "\"a+\"",
            "O_WRONLY", "O_CREAT",
        ];
        return WRITE_MODES.iter().any(|m| raw_l.contains(m));
    }
    false
}

fn extract_block_signals(
    raw_lines: &[&str],
    masked_lines: &[String],
    line_indices: &[usize],
) -> (BTreeSet<String>, Vec<String>) {
    let mut signals = BTreeSet::new();
    let mut cur = String::with_capacity(32);

    let mut has_loop = false;
    let mut has_pair_step = false;
    let mut has_plus_assign = false;
    let mut has_minus_assign = false;
    let mut has_mul_div = false;
    let mut has_with_or_acquire = false;
    let mut has_json_parse = false;
    let mut has_subprocess = false;
    let mut has_fs_open_write = false;
    let mut has_idempotent_lookup = false;
    let mut has_state_write = false;
    let mut has_decimal_or_round = false;

    for &idx in line_indices {
        let raw_l = raw_lines[idx];
        let mt = masked_lines[idx].trim();
        if mt.is_empty() {
            continue;
        }
        cur.clear();
        for ch in mt.chars().chain(std::iter::once(' ')) {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '$' {
                cur.push(ch);
            } else if !cur.is_empty() {
                if !cur.as_bytes()[0].is_ascii_digit() {
                    push_ident_subtokens(&cur, &mut signals);
                }
                cur.clear();
            }
        }

        if mt.starts_with("while ") || mt.starts_with("for ") || mt.contains(" while ") || mt.contains(" for ") {
            has_loop = true;
        }
        if mt.contains("% 2") || mt.contains("%2") || mt.contains("// 2") || mt.contains("//= 2")
            || mt.contains(">> 1") || mt.contains(">>= 1") || mt.contains("+= 2")
            || (mt.contains("range(") && mt.contains(", 2)"))
        {
            has_pair_step = true;
        }
        if mt.contains("+=") {
            has_plus_assign = true;
        }
        if mt.contains("-=") {
            has_minus_assign = true;
        }
        if mt.contains('*') && (mt.contains("//") || mt.contains('/')) {
            has_mul_div = true;
        }
        if mt.starts_with("with ") || mt.contains(".acquire(") || mt.contains(".lock(") {
            has_with_or_acquire = true;
        }
        if mt.contains("json.loads(") || mt.contains("json.load(") || mt.contains("JSON.parse(") || mt.contains("serde_json::from_") {
            has_json_parse = true;
        }
        if mt.contains("subprocess.") || mt.contains("os.system(") || mt.contains("os.popen(")
            || mt.contains("Command::new(") || mt.contains("child_process.")
        {
            has_subprocess = true;
        }
        if is_write_mode_open(raw_l, mt) {
            has_fs_open_write = true;
        }
        if mt.contains("idempotency") || mt.contains("processed_") || mt.contains("seen_") || mt.contains("ON DUPLICATE") {
            has_idempotent_lookup = true;
        }
        if mt.contains(".execute(") || mt.contains(".query(") || mt.contains(".insert(") || mt.contains(".save(") || mt.contains("+=") || mt.contains("-=") {
            has_state_write = true;
        }
        if mt.contains("Decimal(") || mt.contains("quantize(") || mt.contains("ROUND_HALF_UP") || mt.contains("toFixed(") || mt.contains("float(") {
            has_decimal_or_round = true;
        }
    }

    let has_hash_prim = [
        "sha256", "sha512", "sha1", "md5", "blake2", "blake2b", "keccak", "xxhash", "murmur3", "createhash",
    ]
    .iter()
    .any(|h| signals.contains(*h));
    let has_lock_prim = ["lock", "locks", "rlock", "mutex", "rwlock", "semaphore"]
        .iter()
        .any(|l| signals.contains(*l));
    let has_vault_ratio_terms = (signals.contains("shares") || signals.contains("share") || signals.contains("vault"))
        && (signals.contains("assets") || signals.contains("staked") || signals.contains("total"));

    let mut struct_tags = Vec::new();
    if has_loop && has_pair_step && has_hash_prim {
        struct_tags.push("@struct_halving_hash_tree".to_string());
    }
    if (has_plus_assign && has_minus_assign && has_mul_div) || (has_mul_div && has_vault_ratio_terms) {
        struct_tags.push("@struct_share_vault_ratio".to_string());
    }
    if has_lock_prim && has_with_or_acquire && (has_plus_assign || has_minus_assign) {
        struct_tags.push("@struct_multi_lock_transfer".to_string());
    }
    if has_json_parse {
        struct_tags.push("@struct_json_untrusted_input".to_string());
    }
    if has_subprocess {
        struct_tags.push("@struct_subprocess_exec".to_string());
    }
    if has_fs_open_write {
        struct_tags.push("@struct_fs_persistence".to_string());
    }
    if has_idempotent_lookup && has_state_write {
        struct_tags.push("@struct_idempotent_state_write".to_string());
    }
    if has_decimal_or_round && (has_mul_div || has_plus_assign || has_minus_assign) {
        struct_tags.push("@struct_decimal_currency_math".to_string());
    }
    for st in &struct_tags {
        signals.insert(st.clone());
    }
    (signals, struct_tags)
}

/// Extract comment-masked sub-tokens AND **symbol-scoped** rename-resistant `@struct_*` AST/operator fingerprints.
///
/// Structural tags are computed independently within each function/method block (and within a separate
/// module-level block for lines outside functions), eliminating false cross-function signal bleed.
pub fn extract_code_capsule_signals(code: &str) -> (BTreeSet<String>, Vec<String>) {
    let raw_lines: Vec<&str> = code.lines().collect();
    let masked_lines = StatefulMasker::mask_file_lines(code);
    let blocks = extract_symbol_blocks(code);

    let mut covered = vec![false; raw_lines.len()];
    let mut all_signals = BTreeSet::new();
    let mut all_tags = BTreeSet::new();

    for blk in &blocks {
        let indices: Vec<usize> = (blk.start_line.saturating_sub(1)..blk.end_line.min(raw_lines.len())).collect();
        for &idx in &indices {
            covered[idx] = true;
        }
        let (sigs, tags) = extract_block_signals(&raw_lines, &masked_lines, &indices);
        all_signals.extend(sigs);
        all_tags.extend(tags);
    }

    let top_indices: Vec<usize> = covered
        .iter()
        .enumerate()
        .filter_map(|(i, &c)| if !c { Some(i) } else { None })
        .collect();
    if !top_indices.is_empty() {
        let (sigs, tags) = extract_block_signals(&raw_lines, &masked_lines, &top_indices);
        all_signals.extend(sigs);
        all_tags.extend(tags);
    }

    (all_signals, all_tags.into_iter().collect())
}

fn s_vec(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_string()).collect()
}

pub fn builtin_invariant_capsules() -> Vec<InvariantCapsule> {
    vec![
        InvariantCapsule {
            id: "CAP-FIN-ERC4626".to_string(),
            domain: "fintech-vault".to_string(),
            trigger_groups: vec![
                s_vec(&["@struct_share_vault_ratio"]),
                s_vec(&["shares", "share", "vault", "stake", "staked", "mint", "redeem", "unstake"]),
            ],
            when_clause: "Share/staking vault converting assets <-> shares with yield/reward donations".to_string(),
            invariant: "Use ERC-4626 virtual offset (`V_SHARES=10**6, V_ASSETS=1`): mint `shares = (assets * (total_shares + V_SHARES)) // (total_assets + V_ASSETS)`; redeem `assets = (shares * (total_assets + V_ASSETS)) // (total_shares + V_SHARES)` (floor-divide BOTH directions; never `round()` up). PRECONDITION: `shares > 0` holds ONLY when `total_assets + V_ASSETS <= assets * (total_shares + V_SHARES)`; if donation exceeds `V_SHARES * assets`, floor-division yields 0 shares so callers MUST explicitly reject `shares <= 0` (`ValueError`/revert) rather than assuming `shares > 0` unconditionally.".to_string(),
            pos_ast: "V_S, V_A = 10**6, 1; shares = (assets * (self.total_shares + V_S)) // (self.total_assets + V_A); if shares <= 0: raise ValueError('zero shares')".to_string(),
            wins: 18, losses: 1, trials: 19, consecutive_losses: 0, frozen: false,
        },
        InvariantCapsule {
            id: "CAP-CONC-LOCK-SELF".to_string(),
            domain: "concurrency".to_string(),
            trigger_groups: vec![
                s_vec(&["@struct_multi_lock_transfer"]),
                s_vec(&["transfer", "rebalance", "move", "debit", "credit", "acct", "tranche"]),
            ],
            when_clause: "Concurrent multi-entity transfer/rebalance with per-key locks".to_string(),
            invariant: "Acquire distinct account locks in sorted order `(first, second) = sorted((src, dst))`; when `src == dst` (self-transfer), acquire ONLY ONE lock, check `0 < amount <= balance[src]` (raise `ValueError` if insufficient), preserve total ledger sum conservation, and return cleanly without deadlocking.".to_string(),
            pos_ast: "if src == dst:\n    with self._lock(src):\n        if bal.get(src, 0) < amt: raise ValueError('insufficient')\n        return".to_string(),
            wins: 16, losses: 0, trials: 16, consecutive_losses: 0, frozen: false,
        },
        InvariantCapsule {
            id: "CAP-CRYPTO-RFC6962-MERKLE".to_string(),
            domain: "crypto-merkle".to_string(),
            trigger_groups: vec![
                s_vec(&["@struct_halving_hash_tree", "merkle"]),
                s_vec(&["sha256", "blake2", "keccak", "digest"]),
            ],
            when_clause: "Binary hash/Merkle tree & inclusion proof verification (even under custom names)".to_string(),
            invariant: "Reject empty `items` (`ValueError`). Length-prefix leaf fields (`len(id_bytes_4B_be) + id_bytes + int_str`) with RFC-6962 `b'\\x00'` leaf prefix and `b'\\x01'` internal-node prefix. When a level has odd length (`len(nodes) % 2 == 1`), REMOVE any existing `nodes.append(nodes[-1])` duplication and promote `nodes[-1]` unchanged (`[A,B,C]` root != `[A,B,C,C]` root); for `-> bool` proof verifiers return `False` (do NOT raise `ValueError`) when proof directions are not in `('L', 'R')` or sibling hex is malformed.".to_string(),
            pos_ast: "leaf = sha256(b'\\x00' + len(rb).to_bytes(4, 'big') + rb + str(qty).encode()).digest() # odd node promoted unchanged".to_string(),
            wins: 17, losses: 1, trials: 18, consecutive_losses: 0, frozen: false,
        },
        InvariantCapsule {
            id: "CAP-ALGO-DAG-DIAMOND".to_string(),
            domain: "graph-dag".to_string(),
            trigger_groups: vec![
                s_vec(&["dag", "prereq", "prereqs", "ancest", "ancestors", "makespan", "topological", "edges"]),
                s_vec(&["edges", "cycle", "depend", "milestone", "milestones"]),
            ],
            when_clause: "Directed Acyclic Graph (DAG) prerequisite evaluation, ancestor aggregation & critical path".to_string(),
            invariant: "Validate unknown endpoints (`ValueError`), use iterative Kahn's topological sort (no deep recursion `RecursionError` on 500+ nodes, raise `ValueError` or a `CycleError(ValueError)` subclass if `processed < len(nodes)`), and propagate `set[node_id]` of distinct transitive ancestors so Diamond DAGs (`A->B, A->C, B->D, C->D`) NEVER double-count shared ancestor `A`.".to_string(),
            pos_ast: "anc[v] |= anc[u] | {u}  # iterative Kahn topological order; sum(base[x] for x in anc[m])".to_string(),
            wins: 14, losses: 0, trials: 14, consecutive_losses: 0, frozen: false,
        },
        InvariantCapsule {
            id: "CAP-SEC-RUNTIME-BIDI-MAC".to_string(),
            domain: "sec-webhook-input".to_string(),
            trigger_groups: vec![
                s_vec(&["@struct_json_untrusted_input", "webhook", "packet"]),
                s_vec(&["secret", "hmac", "mac", "signature", "idempotency"]),
            ],
            when_clause: "Authenticated JSON webhook/packet verification & string field parsing".to_string(),
            invariant: "Sign with `hmac.new(secret, f'{ts_or_epoch}.'.encode() + raw_body, sha256)` (explicit `.` delimiter prevents `1230+pkt == 123+'0'+pkt` boundary collision), verify via `hmac.compare_digest` (check `abs(now - ts) <= max_skew` ONLY if `now_sec`/`max_skew_sec` parameters exist on the method; bind idempotency key to `sha256(raw_body)` if idempotency parameter exists), and reject Trojan Source Bidi chars (`\\u202a..\\u202e`, `\\u2066..\\u2069`, `\\u061c`, `\\x00`) in ALL decoded JSON string fields (`memo`/`note`) — SIGNATURE-GUARDED: for `-> bool` verifiers return `False` (do NOT raise `SecurityViolationError` or `JSONDecodeError`); otherwise raise `SecurityViolationError`.".to_string(),
            pos_ast: "if any('\\u202a'<=c<='\\u202e' or '\\u2066'<=c<='\\u2069' or c in '\\u061c\\x00' for c in text): return False  # if -> bool else raise SecurityViolationError".to_string(),
            wins: 15, losses: 0, trials: 15, consecutive_losses: 0, frozen: false,
        },
        InvariantCapsule {
            id: "CAP-SEC-SUBPROCESS-ARGV".to_string(),
            domain: "sec-subprocess".to_string(),
            trigger_groups: vec![s_vec(&["@struct_subprocess_exec"])],
            when_clause: "Subprocess / external CLI binary execution".to_string(),
            invariant: "Before calling `subprocess.run([bin_real, flag, target_real], shell=False, check=False, timeout=5)`, reject shell/control metacharacters (`;|&$><`\\n\\r\\x00`) in BOTH binary & argument strings (`SecurityViolationError`/`ValueError`), require `os.path.isabs(bin)` + `os.access(bin_real, os.X_OK)` + `os.path.isfile(target_real)`.".to_string(),
            pos_ast: "if any(c in arg for c in ';|&$><`\\n\\r\\x00') or not os.path.isfile(arg): raise SecurityViolationError('unsafe arg')".to_string(),
            wins: 19, losses: 0, trials: 19, consecutive_losses: 0, frozen: false,
        },
        InvariantCapsule {
            id: "CAP-SEC-PATH-NOFOLLOW-0600".to_string(),
            domain: "sec-filesystem".to_string(),
            trigger_groups: vec![
                s_vec(&["@struct_fs_persistence"]),
                s_vec(&["workspace", "root", "receipt", "rel_path", "save"]),
            ],
            when_clause: "Writing files under a workspace root directory".to_string(),
            invariant: "Canonicalize root once via `root = os.path.realpath(workspace_root)` (allows macOS `/var -> /private/var`), reject symlinks on every relative segment (`os.path.islink`), enforce sibling-safe confinement `target == root or target.startswith(root + os.sep)` (blocks `/ws_evil`), and write atomically via `os.open(..., O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW, 0o600)` + `os.replace`.".to_string(),
            pos_ast: "if not target.startswith(root + os.sep) or os.path.islink(cand): raise SecurityViolationError('escape')".to_string(),
            wins: 15, losses: 0, trials: 15, consecutive_losses: 0, frozen: false,
        },
        InvariantCapsule {
            id: "CAP-CM-ORDER-IDEMPOTENCY".to_string(),
            domain: "erp-order-fulfillment".to_string(),
            trigger_groups: vec![
                s_vec(&["@struct_idempotent_state_write"]),
                s_vec(&["order", "stock", "inventory", "warehouse", "movement", "fulfillment"]),
            ],
            when_clause: "ERP order/stock state transition with idempotency key deduplication".to_string(),
            invariant: "First delivery for `(idempotency_key, payload_hash)` MUST create exactly 1 stock movement and debit/credit inventory; duplicate replay with identical key+payload returns stored receipt with 0 extra movements; same key with conflicting payload MUST fail closed (`ValueError`/409).".to_string(),
            pos_ast: "if key in seen: return seen[key] if seen[key].payload_hash == ph else raise ValueError('idempotency conflict')".to_string(),
            wins: 10, losses: 0, trials: 10, consecutive_losses: 0, frozen: false,
        },
        InvariantCapsule {
            id: "CAP-CM-MYSQL-DECIMAL-FX".to_string(),
            domain: "erp-finance-fx".to_string(),
            trigger_groups: vec![
                s_vec(&["@struct_decimal_currency_math"]),
                s_vec(&["vnd", "usd", "fx", "currency", "invoice", "subtotal", "tax", "ledger"]),
            ],
            when_clause: "MySQL DECIMAL money round-trip and multi-currency FX rounding conservation".to_string(),
            invariant: "Never parse MySQL DECIMAL/money columns via binary `float`/`Number`; construct `Decimal(str(raw))`, quantize at explicit currency precision (`ROUND_HALF_UP`), and verify `sum(line_totals) == grand_total` conservation with remainder allocated deterministically.".to_string(),
            pos_ast: "amt = Decimal(str(raw_val)).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)".to_string(),
            wins: 10, losses: 0, trials: 10, consecutive_losses: 0, frozen: false,
        },
    ]
}

pub fn load_custom_capsules_json(path: &Path) -> Result<Vec<InvariantCapsule>, String> {
    let raw = read_regular_file_fd_verified(path, MAX_CAPSULE_FILE_BYTES)?;
    let dom = parse_json_value(&raw)?;
    let arr = match &dom {
        JsonValue::Array(a) => a.as_slice(),
        JsonValue::Object(m) => m.get("capsules").and_then(|v| v.as_array()).ok_or_else(|| "Capsule JSON object must contain 'capsules' array".to_string())?,
        _ => return Err("Capsule JSON must be array or object".to_string()),
    };
    if arr.len() > MAX_DYNAMIC_CAPSULES {
        return Err(format!("Capsule count {} exceeds MAX_DYNAMIC_CAPSULES ({MAX_DYNAMIC_CAPSULES})", arr.len()));
    }
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let obj = item.as_object().ok_or_else(|| "Each capsule must be a JSON object".to_string())?;
        let id = obj.get("id").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
        if id.is_empty() {
            return Err("Capsule missing non-empty 'id'".to_string());
        }
        let tg_arr = obj.get("trigger_groups").and_then(|v| v.as_array()).ok_or_else(|| format!("Capsule '{id}' missing 'trigger_groups'"))?;
        let mut groups = Vec::with_capacity(tg_arr.len());
        for g in tg_arr {
            let sub = g.as_array().ok_or_else(|| format!("Capsule '{id}' trigger group must be array"))?;
            let toks: Vec<String> = sub.iter().filter_map(|v| v.as_str().map(|s| s.trim().to_ascii_lowercase())).filter(|s| !s.is_empty()).collect();
            if !toks.is_empty() {
                groups.push(toks);
            }
        }
        if groups.is_empty() {
            return Err(format!("Capsule '{id}' must have >=1 non-empty trigger group"));
        }
        let parse_u32 = |key: &str, default_val: u32| -> u32 {
            match obj.get(key) {
                Some(JsonValue::Number(s)) => s.parse::<u32>().unwrap_or_else(|_| s.parse::<f64>().unwrap_or(default_val as f64).max(0.0) as u32),
                _ => default_val,
            }
        };
        let wins = parse_u32("wins", 1);
        let losses = parse_u32("losses", 0);
        let trials = parse_u32("trials", wins.saturating_add(losses));
        let consecutive_losses = parse_u32("consecutive_losses", 0);
        let frozen = obj.get("frozen").and_then(|v| v.as_bool()).unwrap_or(false);
        out.push(InvariantCapsule {
            id,
            domain: obj.get("domain").and_then(|v| v.as_str()).unwrap_or("custom").to_string(),
            trigger_groups: groups,
            when_clause: obj.get("when_clause").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            invariant: obj.get("invariant").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            pos_ast: obj.get("pos_ast").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            wins,
            losses,
            trials,
            consecutive_losses,
            frozen,
        });
    }
    Ok(out)
}

pub fn match_capsules_for_source(
    target_label: &str,
    code: &str,
    extra_capsules: &[InvariantCapsule],
    max_capsules: usize,
) -> CapsuleMatchReport {
    let t0 = Instant::now();
    let (signals, structural_tags) = extract_code_capsule_signals(code);
    let mut pool = builtin_invariant_capsules();
    for ext in extra_capsules {
        if let Some(existing) = pool.iter_mut().find(|c| c.id == ext.id) {
            *existing = ext.clone();
        } else {
            pool.push(ext.clone());
        }
    }

    let mut matched: Vec<InvariantCapsule> = pool
        .into_iter()
        .filter(|cap| {
            !cap.is_auto_frozen()
                && cap
                    .trigger_groups
                    .iter()
                    .all(|grp| grp.iter().any(|tok| signals.contains(tok)))
        })
        .collect();

    matched.sort_by(|a, b| b.efficacy_bp().cmp(&a.efficacy_bp()).then_with(|| a.id.cmp(&b.id)));
    if matched.len() > max_capsules {
        matched.truncate(max_capsules);
    }

    let compact_text = matched.iter().map(InvariantCapsule::render_compact).collect::<Vec<_>>().join("\n\n");
    let estimated_tokens = if compact_text.is_empty() { 0 } else { estimate_tokens(&compact_text) };
    CapsuleMatchReport {
        target: target_label.to_string(),
        elapsed_us: t0.elapsed().as_micros() as u64,
        extracted_signals_count: signals.len(),
        structural_tags,
        matched_capsules: matched,
        compact_text,
        estimated_tokens,
    }
}

pub fn match_capsules_for_file(
    path: &Path,
    extra_capsules: &[InvariantCapsule],
    max_capsules: usize,
) -> Result<CapsuleMatchReport, String> {
    let content = read_regular_file_fd_verified(path, MAX_SOURCE_FILE_BYTES)?;
    Ok(match_capsules_for_source(&path.to_string_lossy(), &content, extra_capsules, max_capsules))
}

pub fn render_capsule_report_json(rep: &CapsuleMatchReport) -> String {
    let mut st_arr = JsonArr::new();
    for st in &rep.structural_tags {
        st_arr = st_arr.str(st);
    }
    let mut c_arr = JsonArr::new();
    for c in &rep.matched_capsules {
        c_arr = c_arr.obj(
            JsonObj::new()
                .str("id", &c.id)
                .str("domain", &c.domain)
                .usize("efficacy_pct", (c.efficacy_bp() / 100) as usize)
                .usize("wins", c.wins as usize)
                .usize("losses", c.losses as usize)
                .usize("consecutive_losses", c.consecutive_losses as usize)
                .str("when", &c.when_clause)
                .str("invariant", &c.invariant)
                .str("pos_ast", &c.pos_ast),
        );
    }
    JsonObj::with_capacity(rep.compact_text.len() + 320)
        .bool("ok", true)
        .str("schema_version", ENGINE_VERSION)
        .str("engine", "kintsugi-rs")
        .str("target", &rep.target)
        .u64("elapsed_us", rep.elapsed_us)
        .f64_3("elapsed_ms", (rep.elapsed_us as f64) / 1000.0)
        .usize("extracted_signals_count", rep.extracted_signals_count)
        .arr("structural_tags", st_arr)
        .usize("matched_count", rep.matched_capsules.len())
        .usize("estimated_tokens", rep.estimated_tokens)
        .arr("capsules", c_arr)
        .str("compact", &rep.compact_text)
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subtoken_splitting_and_obfuscated_merkle_ast_fingerprint_match() {
        let mut s = BTreeSet::new();
        push_ident_subtokens("build_airdrop_claim_root", &mut s);
        push_ident_subtokens("unstakeSharesV2", &mut s);
        assert!(s.contains("airdrop") && s.contains("claim") && s.contains("unstake") && s.contains("shares"));

        let obfuscated_tree = "import hashlib\ndef fn_x1(arr):\n    while len(arr) > 1:\n        if len(arr) % 2 == 1: arr.append(arr[-1])\n        arr = [hashlib.sha256(arr[i] + arr[i+1]).digest() for i in range(0, len(arr), 2)]\n    return arr[0]\n";
        let rep = match_capsules_for_source("obf.py", obfuscated_tree, &[], 6);
        assert!(rep.structural_tags.iter().any(|t| t == "@struct_halving_hash_tree"));
        assert!(rep.matched_capsules.iter().any(|c| c.id == "CAP-CRYPTO-RFC6962-MERKLE"));
    }

    #[test]
    fn symbol_scoping_blocks_cross_function_bleed_and_read_only_open() {
        // Loop in fn_a, `% 2` in fn_b, sha256 in fn_c -> MUST NOT fire @struct_halving_hash_tree!
        let split_fns = "\
import hashlib
def fn_a(items):
    while items:
        items.pop()

def fn_b(n):
    return n % 2

def fn_c(data):
    # open(path, 'w') inside comment must never trigger @struct_fs_persistence
    with open('readme.txt', 'r') as fh:
        return hashlib.sha256(fh.read().encode()).hexdigest()
";
        let rep = match_capsules_for_source("split.py", split_fns, &[], 8);
        assert!(
            !rep.structural_tags.iter().any(|t| t == "@struct_halving_hash_tree"),
            "Cross-function bleed must not emit @struct_halving_hash_tree: {:?}",
            rep.structural_tags
        );
        assert!(
            !rep.structural_tags.iter().any(|t| t == "@struct_fs_persistence"),
            "Read-only open() or commented open('w') must not emit @struct_fs_persistence: {:?}",
            rep.structural_tags
        );
        assert!(
            !rep.matched_capsules.iter().any(|c| c.id == "CAP-CRYPTO-RFC6962-MERKLE"),
            "Cross-function split must not match Merkle capsule"
        );
    }

    #[test]
    fn clean_unrelated_code_emits_zero_capsules_and_2_strike_freeze_prunes() {
        let benign = "from dataclasses import dataclass\n@dataclass\nclass Item:\n    name: str\n    qty: int\ndef total(items):\n    return sum(x.qty for x in items)\n";
        let dead_noise = InvariantCapsule {
            id: "CAP-DEAD".to_string(),
            domain: "noise".to_string(),
            trigger_groups: vec![vec!["def".to_string()]],
            when_clause: "always".to_string(),
            invariant: "noise".to_string(),
            pos_ast: "pass".to_string(),
            wins: 2, losses: 33, trials: 35, consecutive_losses: 0, frozen: false,
        };
        let two_strike = InvariantCapsule {
            id: "CAP-2STRIKE".to_string(),
            domain: "noise".to_string(),
            trigger_groups: vec![vec!["def".to_string()]],
            when_clause: "always".to_string(),
            invariant: "noise".to_string(),
            pos_ast: "pass".to_string(),
            wins: 8, losses: 2, trials: 10, consecutive_losses: 2, frozen: false,
        };
        assert!(two_strike.is_auto_frozen());
        let rep = match_capsules_for_source("benign.py", benign, &[dead_noise, two_strike], 6);
        assert_eq!(rep.matched_capsules.len(), 0);
        assert_eq!(rep.estimated_tokens, 0);
        assert_eq!(estimate_tokens(""), 0);
        assert!(parse_json_value(&render_capsule_report_json(&rep)).is_ok());

        // Verify CAP-FIN-ERC4626 contains explicit mathematical precondition (no false unconditional `>0` claim)
        let erc = builtin_invariant_capsules().into_iter().find(|c| c.id == "CAP-FIN-ERC4626").unwrap();
        assert!(erc.invariant.contains("PRECONDITION"));
        assert!(erc.invariant.contains("total_assets + V_ASSETS <= assets * (total_shares + V_SHARES)"));
    }
}
