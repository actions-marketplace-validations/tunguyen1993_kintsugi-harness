"""
Three-Agent Adversarial Self-Evolution Council + Deterministic Self-Verification Gate.

Architecture:
1. Architect Agent (e.g. Gemini)   -> Diagnoses root cause & extracts clean bad/good code pairs.
2. Synthesizer Agent (e.g. DeepSeek)-> Synthesizes deterministic AST or Regex rule + GoldenScar JSON.
3. Red-Team Critic (e.g. Muse)      -> Challenges false positives, evasion vectors, and context bloat.
4. Deterministic Verification Gate  -> Runs KintsugiScanner in-memory:
     - `scan(bad_code)` MUST detect >= 1 violation (True Positive guaranteed).
     - `scan(good_code)` MUST detect 0 violations (Zero False Positive guaranteed).
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from kintsugi.models import FailureTrace, GoldenScar, Severity
from kintsugi.scanner import KintsugiScanner


@dataclass
class AgentEndpoint:
    """OpenAI-compatible chat completion endpoint configuration for one Council seat."""

    role: str
    model: str
    base_url: str
    api_key: str
    timeout_sec: int = 45


def verify_candidate_scar(scar: GoldenScar) -> Tuple[bool, str]:
    """
    Deterministic self-check gate: a GoldenScar is only accepted if its executable
    AST/Regex rule catches `scar.bad_code` AND stays silent on `scar.good_code`.
    """
    if not scar.regex_pattern and not scar.ast_rule:
        return False, "Candidate scar must define either `regex_pattern` or `ast_rule`."
    if not scar.bad_code.strip() or not scar.good_code.strip():
        return False, "Candidate scar must include non-empty `bad_code` and `good_code`."

    try:
        scanner = KintsugiScanner([scar])
    except re.error as exc:
        return False, f"Invalid regex_pattern: {exc}"

    primary_lang = scar.languages[0] if scar.languages else "python"
    bad_hits = scanner.scan_text(scar.bad_code, file_path=f"<bad.{primary_lang}>", language=primary_lang)
    if not bad_hits:
        return False, "True-positive check failed: scanner produced 0 findings on `bad_code`."

    good_hits = scanner.scan_text(scar.good_code, file_path=f"<good.{primary_lang}>", language=primary_lang)
    if good_hits:
        return False, (
            f"False-positive check failed: scanner matched `good_code` on line {good_hits[0].line}."
        )

    return True, "PASS: True-positive and zero-false-positive invariants verified."


def _extract_json_object(raw_text: str) -> Dict[str, Any]:
    """
    Robustly locate and parse a GoldenScar JSON dictionary even when surrounding
    model reasoning contains `${template}` braces or non-JSON code blocks.
    """
    cleaned = re.sub(r"<think(?:ing)?>[\s\S]*?</think(?:ing)?>", "", raw_text, flags=re.IGNORECASE)
    decoder = json.JSONDecoder()
    best_dict: Optional[Dict[str, Any]] = None

    for match in re.finditer(r"\{", cleaned):
        start_idx = match.start()
        try:
            obj, _ = decoder.raw_decode(cleaned, start_idx)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            if "title" in obj and ("bad_code" in obj or "regex_pattern" in obj or "ast_rule" in obj):
                return obj
            best_dict = obj

    if best_dict is not None:
        return best_dict
    raise ValueError("Model response did not contain a valid JSON object.")


def call_openai_compatible(endpoint: AgentEndpoint, system_prompt: str, user_prompt: str) -> str:
    """Invoke any OpenAI-compatible `/chat/completions` API using pure stdlib urllib."""
    url = endpoint.base_url.rstrip("/") + "/chat/completions"
    body = json.dumps(
        {
            "model": endpoint.model,
            "temperature": 0.1,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {endpoint.api_key}",
            "User-Agent": "kintsugi-harness/0.1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=endpoint.timeout_sec) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    choices = data.get("choices") or []
    if not choices:
        raise ValueError("Empty choices returned by model endpoint.")
    msg = choices[0].get("message") or {}
    return str(msg.get("content") or "")


class EvolutionCouncil:
    """
    Coordinates 3 specialized LLM seats (or deterministic offline fallback) to
    compile a `FailureTrace` into a verified `GoldenScar`.
    """

    def __init__(
        self,
        endpoints: Optional[List[AgentEndpoint]] = None,
        *,
        completion_fn: Optional[Callable[[AgentEndpoint, str, str], str]] = None,
    ) -> None:
        self.endpoints = endpoints if endpoints is not None else self.from_env()
        self._complete = completion_fn or call_openai_compatible

    @staticmethod
    def from_env() -> List[AgentEndpoint]:
        """Auto-discover Architect (Gemini), Synthesizer (DeepSeek), and Critic (Muse/OpenAI) seats."""
        seats: List[AgentEndpoint] = []
        gemini_key = os.environ.get("GEMINI_API_KEY")
        if gemini_key:
            seats.append(
                AgentEndpoint(
                    role="architect",
                    model=os.environ.get("KINTSUGI_ARCHITECT_MODEL", "gemini-2.5-pro"),
                    base_url=os.environ.get(
                        "KINTSUGI_ARCHITECT_BASE_URL",
                        "https://generativelanguage.googleapis.com/v1beta/openai",
                    ),
                    api_key=gemini_key,
                )
            )

        deepseek_key = os.environ.get("DEEPSEEK_API_KEY")
        if deepseek_key:
            seats.append(
                AgentEndpoint(
                    role="synthesizer",
                    model=os.environ.get("KINTSUGI_SYNTHESIZER_MODEL", "deepseek-reasoner"),
                    base_url=os.environ.get(
                        "KINTSUGI_SYNTHESIZER_BASE_URL", "https://api.deepseek.com/v1"
                    ),
                    api_key=deepseek_key,
                )
            )

        critic_key = os.environ.get("MUSE_API_KEY") or os.environ.get("OPENAI_API_KEY")
        if critic_key:
            seats.append(
                AgentEndpoint(
                    role="critic",
                    model=os.environ.get("KINTSUGI_CRITIC_MODEL", "gpt-4.1"),
                    base_url=os.environ.get("KINTSUGI_CRITIC_BASE_URL", "https://api.openai.com/v1"),
                    api_key=critic_key,
                )
            )
        return seats

    def evolve(
        self,
        trace: FailureTrace,
        *,
        scar_id: str = "KS-900",
        max_attempts: int = 2,
    ) -> Tuple[GoldenScar, str]:
        """
        Synthesize and deterministically verify a GoldenScar from `trace`.
        Uses the 3-Agent Council when configured, otherwise falls back to offline heuristics.
        """
        if not self.endpoints:
            scar = self.evolve_offline(trace, scar_id=scar_id)
            ok, msg = verify_candidate_scar(scar)
            if not ok:
                raise ValueError(f"Offline scar synthesis failed self-verification: {msg}")
            return scar, msg

        by_role = {ep.role: ep for ep in self.endpoints}
        architect = by_role.get("architect", self.endpoints[0])
        synthesizer = by_role.get("synthesizer", self.endpoints[min(1, len(self.endpoints) - 1)])
        critic = by_role.get("critic", self.endpoints[-1])

        arch_notes = self._complete(
            architect,
            "You are the Kintsugi Architect Agent. Diagnose the exact root cause of the coding agent failure and output concise minimal bad_code vs good_code examples.",
            f"Language: {trace.language}\nSummary: {trace.error_summary}\nRaw Trace:\n{trace.raw_trace}\nOffending Snippet:\n{trace.offending_snippet}",
        )

        feedback = ""
        last_error = "No attempts run"
        for _ in range(max_attempts):
            synth_prompt = (
                f"Failure Summary: {trace.error_summary}\n"
                f"Language: {trace.language}\n"
                f"Architect Analysis:\n{arch_notes}\n"
                f"{feedback}\n"
                "Return ONLY valid JSON with keys: "
                "title, severity (CRITICAL|HIGH|MEDIUM|LOW), category, languages (list), tags (list), "
                "root_cause, bad_code, good_code, rationale, regex_pattern (string or null), ast_rule (string or null).\n"
                "Note: regex_pattern MUST match `bad_code` and MUST NOT match `good_code`. "
                "Supported Python ast_rule values: py_subprocess_shell_true, py_mutable_default_arg, "
                "py_silent_except_swallow, py_unsafe_dynamic_exec, py_http_missing_timeout, "
                "py_insecure_random_for_secret, call:<dotted_fn>, missing_kwarg:<dotted_fn>:<kwarg>."
            )
            raw_json_reply = self._complete(
                synthesizer,
                "You are the Kintsugi Synthesizer Agent. Emit strictly valid JSON defining a deterministic GoldenScar.",
                synth_prompt,
            )

            critic_reply = self._complete(
                critic,
                "You are the Kintsugi Red-Team Critic Agent. Audit the proposed GoldenScar JSON for false positives on idiomatic code, bypass vectors, or broken regex syntax. Return the refined GoldenScar JSON only.",
                f"Proposed GoldenScar:\n{raw_json_reply}\nOriginal Trace:\n{trace.error_summary}",
            )

            try:
                try:
                    parsed = _extract_json_object(critic_reply)
                    if "title" not in parsed or "bad_code" not in parsed:
                        parsed = _extract_json_object(raw_json_reply)
                except ValueError:
                    parsed = _extract_json_object(raw_json_reply)
                candidate = GoldenScar(
                    id=scar_id,
                    title=str(parsed["title"]),
                    severity=Severity(str(parsed.get("severity", "HIGH")).upper()),
                    category=str(parsed.get("category", "reliability")),
                    languages=list(parsed.get("languages") or [trace.language]),
                    tags=list(parsed.get("tags") or ["evolved"]),
                    root_cause=str(parsed["root_cause"]),
                    bad_code=str(parsed["bad_code"]),
                    good_code=str(parsed["good_code"]),
                    rationale=str(parsed["rationale"]),
                    regex_pattern=parsed.get("regex_pattern"),
                    ast_rule=parsed.get("ast_rule"),
                    verified_by=[
                        f"architect:{architect.model}",
                        f"synthesizer:{synthesizer.model}",
                        f"critic:{critic.model}",
                        "self-check",
                    ],
                )
            except (KeyError, ValueError, TypeError) as exc:
                last_error = f"JSON schema parse error: {exc}"
                feedback = f"Previous attempt failed schema parsing: {last_error}"
                continue

            ok, msg = verify_candidate_scar(candidate)
            if ok:
                return candidate, msg
            last_error = msg
            feedback = f"Previous attempt failed deterministic self-check: {msg}. Fix regex_pattern/ast_rule and snippets."

        raise ValueError(f"Council failed to produce a self-verifying scar: {last_error}")

    @staticmethod
    def evolve_offline(trace: FailureTrace, *, scar_id: str = "KS-900") -> GoldenScar:
        """
        Deterministic zero-API-key heuristic synthesis from common failure traces
        and offending/fixed snippet pairs.
        """
        combined = f"{trace.error_summary}\n{trace.raw_trace}\n{trace.offending_snippet}"

        if "yaml.load(" in combined and "Loader" not in combined:
            return GoldenScar(
                id=scar_id,
                title="Unsafe yaml.load() call without SafeLoader",
                severity=Severity.CRITICAL,
                category="security",
                languages=["python"],
                tags=["yaml", "deserialization", "rce", "offline-evolved"],
                root_cause="Calling PyYAML yaml.load() without SafeLoader permits arbitrary Python object instantiation.",
                bad_code="import yaml\ncfg = yaml.load(raw_yaml)",
                good_code="import yaml\ncfg = yaml.safe_load(raw_yaml)",
                rationale="Enforces yaml.safe_load() to block arbitrary object execution.",
                ast_rule="py_unsafe_dynamic_exec",
                verified_by=["offline-heuristic", "self-check"],
            )

        if "shell=True" in combined:
            return GoldenScar(
                id=scar_id,
                title="Unsafe subprocess invocation with shell=True",
                severity=Severity.HIGH,
                category="security",
                languages=["python"],
                tags=["subprocess", "shell", "offline-evolved"],
                root_cause="Passing shell=True invokes /bin/sh on interpolated command strings.",
                bad_code='import subprocess\nsubprocess.run("ls " + user_dir, shell=True)',
                good_code='import subprocess\nsubprocess.run(["ls", user_dir], check=True)',
                rationale="Passes argument vectors directly to execve without shell expansion.",
                ast_rule="py_subprocess_shell_true",
                verified_by=["offline-heuristic", "self-check"],
            )

        if trace.offending_snippet.strip() and trace.fixed_snippet.strip():
            bad_line = next(
                (ln.strip() for ln in trace.offending_snippet.splitlines() if ln.strip()),
                trace.offending_snippet.strip(),
            )
            escaped = re.escape(bad_line)
            return GoldenScar(
                id=scar_id,
                title=trace.error_summary[:90] or "Regression pattern captured from failure trace",
                severity=Severity.MEDIUM,
                category="correctness",
                languages=[trace.language],
                tags=["regression", "offline-evolved"],
                root_cause=trace.error_summary or "Captured from failing execution trace.",
                bad_code=trace.offending_snippet.strip(),
                good_code=trace.fixed_snippet.strip(),
                rationale="Prevents re-introducing an exact verified regression line.",
                regex_pattern=escaped,
                verified_by=["offline-heuristic", "self-check"],
            )

        # Fallback: extract fatal call pattern from Python traceback line if present
        tb_code_lines = [
            ln.strip()
            for ln in trace.raw_trace.splitlines()
            if ln.startswith("    ") and not ln.strip().startswith(("File ", "^", "~"))
        ]
        if tb_code_lines:
            culprit = tb_code_lines[-1]
            return GoldenScar(
                id=scar_id,
                title=f"Prevent recurring crash: {trace.error_summary[:64]}",
                severity=Severity.MEDIUM,
                category="reliability",
                languages=[trace.language],
                tags=["traceback", "offline-evolved"],
                root_cause=trace.error_summary,
                bad_code=culprit,
                good_code=trace.fixed_snippet.strip() or f"# Guarded replacement for: {culprit.split('(')[0]}_safe()",
                rationale="Compiled directly from unhandled runtime traceback.",
                regex_pattern=re.escape(culprit),
                verified_by=["offline-heuristic", "self-check"],
            )

        raise ValueError(
            "Offline evolution requires either a recognized anti-pattern, a traceback code line, "
            "or both `offending_snippet` and `fixed_snippet`."
        )
