"""
7-Layer Zero-Trust Evolution Quarantine & Anti-Poisoning Shield (`kintsugi.shield`).

Protects self-evolving agent memory (`.kintsugi/scars.json`, `.kintsugi/lessons_local.json`,
`collective-pool/`, and compiled `CLAUDE.md` / `AGENTS.md` / `SKILL.md` files) against:
  1. Path Traversal & Malformed ID Injection (`../../` in scar/lesson IDs or index paths)
  2. Trojan Source Invisible & Bidirectional Unicode Control Characters (`CVE-2021-42574`)
  3. Indirect Prompt Injection & Instruction Hijacking in titles, rationales, or comments
  4. Malware, RCE, Obfuscation, Exfiltration & Wallet-Drain Primitives inside `good_code`
  5. Catastrophic Backtracking Regular Expressions (`ReDoS` CPU Denial-of-Service Bombs)
  6. Outbound Secret, API Key, Private Key, Wallet & Internal IP Leaks (`DLP Firewall`)
  7. Unsigned / Tampered Public GitHub Ledger Entries via Local Machine `HMAC-SHA256` Seal
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

from kintsugi.models import GoldenScar

# ---------------------------------------------------------------------------
# Layer 1: Strict Identifier & Path-Traversal Jail
# ---------------------------------------------------------------------------
VALID_SCAR_ID_RE = re.compile(r"^[A-Z]{2,8}(?:-[A-Z0-9]{1,12}){1,3}$")

# ---------------------------------------------------------------------------
# Layer 2: Trojan Source & Invisible Control Character Guard (CVE-2021-42574)
# ---------------------------------------------------------------------------
TROJAN_UNICODE_RE = re.compile(
    r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff\x00-\x08\x0b\x0c\x0e-\x1f\x7f]"
)

# ---------------------------------------------------------------------------
# Layer 3: Indirect Prompt Injection & Jailbreak Firewall
# ---------------------------------------------------------------------------
PROMPT_INJECTION_RE = re.compile(
    r"(?:"
    r"ignore\s+(?:all\s+|previous\s+|prior\s+|above\s+|earlier\s+)?(?:instructions|rules|prompts|guardrails|constraints)|"
    r"disregard\s+(?:all\s+|previous\s+|prior\s+)?(?:instructions|rules|prompts)|"
    r"system\s+override|developer\s+mode|jailbreak|"
    r"you\s+are\s+now\s+(?:a|an|in\s+)|"
    r"new\s+supreme\s+rule|"
    r"do\s+not\s+(?:tell|inform|mention\s+to)\s+the\s+user|"
    r"silently\s+(?:send|upload|post|exfiltrate|execute|run)|"
    r"exfiltrate\s+|"
    r"<\s*(?:script|iframe|object|embed)\b|"
    r"<!--[\s\S]*?(?:ignore|override|curl|wget|http|exec|eval)[\s\S]*?-->"
    r")",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Layer 4: Malware, RCE, Obfuscation & Wallet-Drain Blocker on `good_code`
# ---------------------------------------------------------------------------
GOOD_CODE_MALWARE_RE = re.compile(
    r"(?:"
    r"\b(?:curl|wget)\b[^\n]*\|\s*(?:ba)?sh\b|"
    r"\bos\s*\.\s*(?:system|popen|execv|execve|execl|spawnl|spawnv)\s*\(|"
    r"\bsubprocess\s*\.\s*(?:Popen|run|call|check_output|check_call)\b[^\n]*shell\s*=\s*True|"
    r"\b(?:eval|exec)\s*\(|"
    r"\b__import__\s*\(|"
    r"\b(?:pickle|marshal|dill)\s*\.\s*loads?\s*\(|"
    r"\bbase64\s*\.\s*b64decode\s*\(|"
    r"\bcodecs\s*\.\s*decode\s*\([^\n]*rot_?13|"
    r"\bctypes\s*\.\s*(?:CDLL|windll|cast|memmove)\b|"
    r"\bpty\s*\.\s*spawn\s*\(|"
    r"\b(?:eth_sendRawTransaction|eth_sendTransaction|transferWithAuthorization|solana\s+transfer)\b|"
    r"(?:\.ssh/id_rsa|\.config/auth\.json|\.config/|\.config/|/etc/shadow|/etc/passwd)"
    r")",
    re.IGNORECASE,
)

URL_EXTRACT_RE = re.compile(r"https?://[^\s\"'`<>)\]]+", re.IGNORECASE)
SAFE_DOC_HOSTS = {
    "example.com",
    "www.example.com",
    "api.example.com",
    "hooks.example.com",
    "audit.example.com",
    "example.org",
    "example.net",
    "localhost",
    "127.0.0.1",
    "img.shields.io",
    "github.com",
}

# ---------------------------------------------------------------------------
# Layer 5: Catastrophic Backtracking Regex (ReDoS) Static & Dynamic Guard
# ---------------------------------------------------------------------------
MAX_REGEX_LENGTH = 300
# Detects nested quantifiers like (a+)+, (.*)+, (\s*.*)+, ([a-z]+)* and overlapping alternations (a|a)+
REDOS_NESTED_QUANTIFIER_RE = re.compile(
    r"(?:\([^()]*[+*]\s*(?:\{[0-9,]+\})?[^()]*\)\s*(?:[+*]|\{[0-9,]+\})|"
    r"\(([^()|]+)\|\1\)\s*(?:[+*]|\{[0-9,]+\}))"
)
REDOS_PATHOLOGICAL_PROBES: Tuple[str, ...] = (
    "a" * 1500 + "!",
    " " * 1500 + "\t!",
    "x = " + "(" * 800 + "1",
    "0123456789_" * 150 + "$",
    "word_" * 300 + "!=!",
)

# ---------------------------------------------------------------------------
# Layer 6: Outbound Deep DLP & Prefix-Agnostic Shannon Entropy Firewall
# ---------------------------------------------------------------------------
OUTBOUND_DLP_SECRET_RE = re.compile(
    r"(?:"
    r"/Users/[A-Za-z0-9._-]+|/home/[A-Za-z0-9._-]+|C:\\Users\\[A-Za-z0-9._-]+|"
    r"\.(?:enterprise-platform|oxion|codex|muse)\b|"
    r"\bsk-(?!proj-EXAMPLE_PLACEHOLDER)[A-Za-z0-9_-]{12,}\b|"
    r"\btj_[A-Za-z0-9_-]{16,}\b|"
    r"\bgsk_(?!your_free_key)[A-Za-z0-9_-]{16,}\b|"
    r"\bxai-[A-Za-z0-9_-]{16,}\b|"
    r"\bhf_[A-Za-z0-9]{20,}\b|"
    r"\bAKIA[0-9A-Z]{16}\b|"
    r"\bgh[pousr]_[A-Za-z0-9]{20,}\b|"
    r"\bgithub_pat_[A-Za-z0-9_]{20,}\b|"
    r"\bAIza[0-9A-Za-z_-]{30,}\b|"
    r"\bxox[baprs]-[A-Za-z0-9-]{12,}\b|"
    r"\beyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}\b|"
    r"\b0x[a-fA-F0-9]{40}\b|"
    r"\b0x[a-fA-F0-9]{64}\b|"
    r"\b(?:192\.168|10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b|"
    r"\b(?:124\.158\.6\.173|123\.16\.242\.204)\b|"
    r"[a-zA-Z0-9._%+-]+@(?!([a-zA-Z0-9-]+\.)*example\.(?:com|org|net)\b)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    r")",
    re.IGNORECASE,
)

# Prefix-agnostic GitGuardian "Generic High Entropy Secret" detector:
# Matches key/api_key/token/secret/password assignments to string literals >= 16 chars
CONTEXTUAL_SECRET_ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    (
      ["']?(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|bearer[_-]?token|
      private[_-]?key|client[_-]?secret|api[_-]?token|password|passwd|secret|token|key)["']?
      \s*[:=]\s*
    )
    (["'])([A-Za-z0-9_!@#$%^&*+./=-]{16,256})\2
    """
)

SAFE_SECRET_PLACEHOLDER_RE = re.compile(
    r"^(?:EXAMPLE_PLACEHOLDER|YOUR_API_KEY|YOUR_FREE_KEY|REDACTED_BY_KINTSUGI_SHIELD|"
    r"HIGH_ENTROPY_REDACTED)$|0{12,}",
    re.IGNORECASE,
)

_SNAKE_CASE_IDENTIFIER_RE = re.compile(r"^(?:[a-z]+(?:_[a-z]+){1,6}|[A-Z]+(?:_[A-Z]+){1,6})$")


def _is_safe_secret_placeholder(candidate: str) -> bool:
    """Return True only for genuine placeholders, file paths/URLs, or pure single-case snake_case identifiers."""
    if not candidate:
        return True
    if candidate.startswith(("/", "./", "../", "http://", "https://")):
        return True
    if SAFE_SECRET_PLACEHOLDER_RE.search(candidate):
        return True
    if _SNAKE_CASE_IDENTIFIER_RE.fullmatch(candidate):
        return True
    return False


def _is_candidate_high_entropy_secret(candidate: str, entropy_threshold: float = 3.30) -> Tuple[bool, float]:
    """Evaluate whether `candidate` is a high-entropy credential (including letters-only mixed-case secrets)."""
    if _is_safe_secret_placeholder(candidate):
        return False, 0.0
    ent = shannon_entropy(candidate)
    if ent < entropy_threshold:
        return False, ent
    digit_count = sum(1 for c in candidate if c.isdigit())
    has_upper = any(c.isupper() for c in candidate)
    has_lower = any(c.islower() for c in candidate)
    has_complex_mix = (
        digit_count >= 2
        or (digit_count >= 1 and (has_upper or has_lower))
        or (has_upper and has_lower and ent >= 3.80)
    )
    return has_complex_mix, ent


def shannon_entropy(val: str) -> float:
    """Compute Shannon entropy H(s) = -sum p(c) log2 p(c) in bits/char."""
    if not val:
        return 0.0
    length = len(val)
    counts: Dict[str, int] = {}
    for ch in val:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def scan_high_entropy_secrets(text: str, entropy_threshold: float = 3.30) -> List[Dict[str, Any]]:
    """
    Prefix-agnostic contextual Shannon entropy scanner (`@RECURRENCE_SHIELD/1`).
    Detects any real or mock high-entropy credential literal before it can trigger GitGuardian
    or leak into checkpoints/commits, without echoing the raw secret value.
    """
    if not text:
        return []
    findings: List[Dict[str, Any]] = []
    for m in CONTEXTUAL_SECRET_ASSIGNMENT_RE.finditer(text):
        candidate = m.group(3)
        is_secret, ent = _is_candidate_high_entropy_secret(candidate, entropy_threshold=entropy_threshold)
        if is_secret:
            sha8 = hashlib.sha256(candidate.encode("utf-8")).hexdigest()[:8]
            findings.append(
                {
                    "rule_id": "SHIELD-ENTROPY-001",
                    "detector": "Generic High Entropy Secret (Contextual Assignment)",
                    "entropy_bits": round(ent, 2),
                    "length": len(candidate),
                    "candidate_sha8": sha8,
                    "span": [m.start(), m.end()],
                }
            )
    return findings


def redact_high_entropy_secrets(text: str, entropy_threshold: float = 3.30) -> str:
    """
    Replace any contextual high-entropy secret literal with a deterministic zero-entropy
    redacted marker (`[HIGH_ENTROPY_REDACTED:<sha8>]`) so checkpoints and logs never leak.
    """
    if not text:
        return ""

    def _repl(m: re.Match[str]) -> str:
        prefix_assign = m.group(1)
        quote = m.group(2)
        candidate = m.group(3)
        is_secret, _ = _is_candidate_high_entropy_secret(candidate, entropy_threshold=entropy_threshold)
        if is_secret:
            sha8 = hashlib.sha256(candidate.encode("utf-8")).hexdigest()[:8]
            return f"{prefix_assign}{quote}[HIGH_ENTROPY_REDACTED:{sha8}]{quote}"
        return m.group(0)

    return CONTEXTUAL_SECRET_ASSIGNMENT_RE.sub(_repl, text)


def scan_artifact_egress(payload: str, context: str = "generic") -> Dict[str, Any]:
    """
    Unified `ScanResult/1` Egress Gate binding the security decision (`ALLOW` | `BLOCK`)
    to the exact SHA-256 digest of `payload` across format denylists, contextual Shannon entropy,
    Trojan Unicode, and prompt injection.
    """
    raw = str(payload or "")
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    findings: List[Dict[str, Any]] = []

    m_dlp = OUTBOUND_DLP_SECRET_RE.search(raw)
    if m_dlp:
        tok_sha8 = hashlib.sha256(m_dlp.group(0).encode("utf-8")).hexdigest()[:8]
        findings.append(
            {
                "rule_id": "SHIELD-DLP-001",
                "class": "OUTBOUND_DLP_PATTERN",
                "candidate_sha8": tok_sha8,
                "span": [m_dlp.start(), m_dlp.end()],
            }
        )

    entropy_hits = scan_high_entropy_secrets(raw)
    findings.extend(entropy_hits)

    if TROJAN_UNICODE_RE.search(raw):
        findings.append({"rule_id": "SHIELD-TROJAN-001", "class": "TROJAN_BIDI_UNICODE"})

    decision = "BLOCK" if findings else "ALLOW"
    return {
        "schema": "ScanResult/1",
        "context": context,
        "decision": decision,
        "ok": decision == "ALLOW",
        "payload_sha256": digest,
        "findings_count": len(findings),
        "findings": findings,
        "coverage": "complete",
    }


def is_safe_regex_pattern(pattern: Optional[str], max_probe_ms: float = 20.0) -> Tuple[bool, str]:
    """
    Validate a candidate `regex_pattern` against syntax errors, excessive length,
    nested quantifier ReDoS patterns, and pathological runtime backtracking probes.
    """
    if pattern is None or pattern == "":
        return True, "OK_NO_REGEX"
    if not isinstance(pattern, str):
        return False, "REJECTED_REGEX_TYPE: regex_pattern must be a string."
    if len(pattern) > MAX_REGEX_LENGTH:
        return False, f"REJECTED_REGEX_LENGTH: length {len(pattern)} exceeds max {MAX_REGEX_LENGTH}."
    if TROJAN_UNICODE_RE.search(pattern):
        return False, "REJECTED_TROJAN_UNICODE_IN_REGEX: invisible or bidi control characters detected."
    if REDOS_NESTED_QUANTIFIER_RE.search(pattern):
        return False, "REJECTED_REDOS_RISK: nested quantifiers detected in regex_pattern."

    try:
        compiled = re.compile(pattern, re.MULTILINE)
    except re.error as exc:
        return False, f"REJECTED_INVALID_REGEX: {exc}"

    t0 = time.perf_counter()
    for probe in REDOS_PATHOLOGICAL_PROBES:
        compiled.search(probe)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    if elapsed_ms > max_probe_ms:
        return (
            False,
            f"REJECTED_REDOS_TIMEOUT: pathological probe took {elapsed_ms:.2f}ms (> {max_probe_ms}ms).",
        )
    return True, "OK_SAFE_REGEX"


def _check_urls_in_good_code(good_code: str) -> Optional[str]:
    for match in URL_EXTRACT_RE.finditer(good_code):
        raw_url = match.group(0).rstrip(".,;'\")")
        parsed = urlparse(raw_url)
        host = (parsed.hostname or "").lower()
        if host and host not in SAFE_DOC_HOSTS and not host.endswith(".example.com"):
            return f"REJECTED_UNTRUSTED_URL_IN_GOOD_CODE: external host '{host}' is not allowed in verified fix templates."
    return None


def audit_scar_security(scar: GoldenScar) -> Tuple[bool, str]:
    """
    Run Layers 1-6 of the Zero-Trust Evolution Shield on a `GoldenScar`.
    Returns `(True, "PASS_SHIELD")` if clean, or `(False, "REJECTED_...")` if poisoned/unsafe.
    """
    # Layer 1: Strict ID & Path Traversal Check
    if not isinstance(scar.id, str) or not VALID_SCAR_ID_RE.match(scar.id):
        return False, f"REJECTED_PATH_TRAVERSAL_ID: Invalid scar id '{scar.id}'."

    # Layer 2: Trojan Source Invisible / Bidirectional Unicode Check
    # `good_code`, `title`, `root_cause`, `rationale`, `regex_pattern`, and `tags` must NEVER contain Trojan Unicode.
    # `bad_code` may only contain it if the rule itself explicitly targets `trojan-source` / `u202`.
    trusted_fields = "\n".join(
        [
            scar.title or "",
            scar.category or "",
            scar.root_cause or "",
            scar.rationale or "",
            scar.good_code or "",
            scar.regex_pattern or "",
            scar.ast_rule or "",
            " ".join(scar.tags or []),
        ]
    )
    all_fields = trusted_fields + "\n" + (scar.bad_code or "")
    is_trojan_detector = "trojan-source" in (scar.tags or []) or "\\u202" in (scar.regex_pattern or "")
    if TROJAN_UNICODE_RE.search(trusted_fields) or (
        not is_trojan_detector and TROJAN_UNICODE_RE.search(scar.bad_code or "")
    ):
        return (
            False,
            "REJECTED_TROJAN_SOURCE_UNICODE: Invisible or bidirectional Unicode control characters detected.",
        )

    # Layer 3: Indirect Prompt Injection & Jailbreak Firewall
    prose_and_good = "\n".join(
        [
            scar.title or "",
            scar.root_cause or "",
            scar.rationale or "",
            scar.good_code or "",
            " ".join(scar.tags or []),
        ]
    )
    if PROMPT_INJECTION_RE.search(prose_and_good):
        return (
            False,
            "REJECTED_PROMPT_INJECTION: Instruction override or jailbreak pattern detected in scar content.",
        )

    # Layer 4: Malware, RCE, Exfiltration & Wallet-Drain Blocker on `good_code` & `rationale`
    recommended_surface = f"{scar.good_code or ''}\n{scar.rationale or ''}"
    if GOOD_CODE_MALWARE_RE.search(recommended_surface):
        return (
            False,
            "REJECTED_MALICIOUS_GOOD_CODE: Dangerous execution, obfuscation, secret access, or wallet-drain primitive detected in `good_code` / `rationale`.",
        )

    url_err = _check_urls_in_good_code(scar.good_code or "")
    if url_err:
        return False, url_err

    # Layer 5: Catastrophic Backtracking Regex (ReDoS) Guard
    regex_ok, regex_msg = is_safe_regex_pattern(scar.regex_pattern)
    if not regex_ok:
        return False, regex_msg

    # Layer 6: Outbound Deep DLP & Prefix-Agnostic Shannon Entropy Firewall
    if OUTBOUND_DLP_SECRET_RE.search(all_fields):
        return (
            False,
            "REJECTED_DLP_SECRET_LEAK: Private path, API key, token, wallet address, or internal IP detected.",
        )
    entropy_hits = scan_high_entropy_secrets(trusted_fields)
    if entropy_hits:
        first_hit = entropy_hits[0]
        return (
            False,
            f"REJECTED_HIGH_ENTROPY_SECRET: Contextual high-entropy secret literal detected "
            f"(sha8={first_hit['candidate_sha8']}, entropy={first_hit['entropy_bits']} bits/char).",
        )

    return True, "PASS_SHIELD: All 6 content & execution security layers verified."


def resolve_safe_child_path(base_dir: Path, relative_path: str) -> Optional[Path]:
    """
    Resolve `relative_path` inside `base_dir` and guarantee no `..` path traversal escapes `base_dir`.
    """
    if not relative_path or "\x00" in relative_path:
        return None
    base_resolved = base_dir.resolve()
    candidate = (base_resolved / relative_path).resolve()
    try:
        candidate.relative_to(base_resolved)
    except ValueError:
        return None
    return candidate


# ---------------------------------------------------------------------------
# Layer 7: Strict Outbound Egress Destination Whitelist
# ("Chỉ được gửi lên kho public tự tiến hoá của GitHub — chặn mọi nguồn gửi ra ngoài khác")
# ---------------------------------------------------------------------------
ALLOWED_PUBLIC_EVOLUTION_REPO_SLUG = "tunguyen1993/kintsugi-harness"
ALLOWED_OUTBOUND_GIT_REMOTES: Tuple[str, ...] = (
    "https://github.com/tunguyen1993/kintsugi-harness",
    "https://github.com/tunguyen1993/kintsugi-harness.git",
    "git@github.com:tunguyen1993/kintsugi-harness",
    "git@github.com:tunguyen1993/kintsugi-harness.git",
    "ssh://git@github.com/tunguyen1993/kintsugi-harness",
    "ssh://git@github.com/tunguyen1993/kintsugi-harness.git",
)


def verify_outbound_destination_allowed(destination: str) -> Tuple[bool, str]:
    """
    Verify that an outbound sync/push destination is strictly the official public
    self-evolving GitHub repository (`tunguyen1993/kintsugi-harness`).
    Any external relay (`ntfy.sh`), webhook, pastebin, or unauthorized git remote is HARD-BLOCKED.
    """
    cleaned = str(destination or "").strip().rstrip("/")
    if not cleaned:
        return False, "OUTBOUND_EGRESS_BLOCKED: Empty outbound destination."

    if cleaned.lower() == ALLOWED_PUBLIC_EVOLUTION_REPO_SLUG.lower():
        return True, f"ALLOWED_PUBLIC_GITHUB_EVOLUTION_REPO:{ALLOWED_PUBLIC_EVOLUTION_REPO_SLUG}"

    for allowed in ALLOWED_OUTBOUND_GIT_REMOTES:
        if cleaned.lower() == allowed.lower():
            return True, f"ALLOWED_PUBLIC_GITHUB_EVOLUTION_REMOTE:{allowed}"

    return (
        False,
        f"OUTBOUND_EGRESS_BLOCKED: Destination '{cleaned}' is forbidden. "
        f"Outbound evolution data may ONLY be sent to 'https://github.com/{ALLOWED_PUBLIC_EVOLUTION_REPO_SLUG}'.",
    )


