"""Build #3 SMT Neuro-Symbolic Formal Plan Verifier (`SMTPlanVerifier/1`).

Provides machine-checkable proof certificates and concrete counterexample
witnesses for `CompositionPlan/1` DAGs using Microsoft Z3 (`z3-solver`) when
available, with a sound exact pure-Python constraint-solver fallback when `z3`
is unavailable in the active interpreter.

Properties verified:
  1. `prove_acyclic_and_total_order(plan)`:
     Strict topological rank synthesis / cycle detection with UNSAT edge core
     and explicit cycle path witness.
  2. `prove_no_secret_escalation(plan, security_context)`:
     4-level sensitivity lattice (`PUBLIC <= INTERNAL <= SECRET <= RESTRICTED`)
     across nodes, adapters, input bindings, and goal outputs, requiring
     attested declassifiers for downward sensitivity flow.
  3. `prove_permission_monotonicity(plan, security_context)`:
     Bitvector constraint verification proving `security_context.allowed_permissions`
     (and non-empty `plan.permission_union`) cover all node, adapter, and chained
     DAG requirements without privilege amplification.
  4. `prove_effect_idempotency(plan)`:
     WAL crash-replay and retry/fan-in multiplicity arithmetic proving
     non-idempotent side-effect nodes never run with effective multiplicity > 1
     without explicit WAL checkpointing (`idempotency_key` / `wal_protected=True`).
  5. `verify_plan_formal(plan, security_context)`:
     Executes all four checks and emits an aggregated `FormalVerificationBundle`.
"""

from __future__ import annotations

import heapq
import hmac
import sys
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple, Union

from kintsugi.capability.contracts_v2 import AdapterSpec, CompositionPlan, EffectContract, PortContract
from kintsugi.capability.schemas import (
    SecurityContext,
    SecurityProfile,
    ToolSpec,
    TrustStatus,
    assert_no_raw_secrets,
    canonical_json_dumps,
    has_valid_verification_attestation,
    is_valid_sha256,
    normalize_sha256,
    redact_secrets_in_value,
    sha256_digest,
    validate_safe_text,
)
from kintsugi.capability.tool_registry import AttestationAuthority, ToolRegistry
from kintsugi.runtime.secure_runner import _verify_context_policy_integrity
from kintsugi.shield import TROJAN_UNICODE_RE
from kintsugi.tools.proof_pack import FormalProofArtifact

SMT_CERTIFICATE_SCHEMA = "SMTProofCertificate/1"
FORMAL_BUNDLE_SCHEMA = "FormalVerificationBundle/1"

STATUS_PROVEN = "PROVEN"
STATUS_COUNTEREXAMPLE = "COUNTEREXAMPLE"
STATUS_ERROR = "ERROR"
VALID_PROOF_STATUSES = frozenset({STATUS_PROVEN, STATUS_COUNTEREXAMPLE, STATUS_ERROR})

BACKEND_Z3 = "z3_smt"
BACKEND_PYTHON = "exact_python_fallback"
VALID_BACKENDS = frozenset({BACKEND_Z3, BACKEND_PYTHON})

SENSITIVITY_LATTICE: Dict[str, int] = {"public": 0, "internal": 1, "secret": 2, "restricted": 3}
SENSITIVITY_NAMES: Dict[int, str] = {v: k for k, v in SENSITIVITY_LATTICE.items()}

_DECLASSIFICATION_HINTS = ("redact", "mask", "hash", "tokenize", "anonymize", "declassify", "sanitize")
_NETWORK_PERMISSION_PREFIXES = ("net.", "network.", "http.", "https.", "socket.", "outbound.")


def _detect_z3() -> Tuple[bool, Optional[Any], str]:
    """Dynamically detect Microsoft Z3 (`z3-solver`) without hard import failure."""
    try:
        import z3 as _z3_mod  # type: ignore[import-not-found]
    except ImportError:
        return False, None, ""
    required = (
        "Solver",
        "Int",
        "IntVal",
        "BoolVal",
        "BitVec",
        "BitVecVal",
        "And",
        "Or",
        "Not",
        "If",
        "Distinct",
        "is_true",
        "sat",
        "unsat",
    )
    if not all(hasattr(_z3_mod, attr) for attr in required):
        return False, None, ""
    ver = str(_z3_mod.get_version_string()) if hasattr(_z3_mod, "get_version_string") else "unknown"
    return True, _z3_mod, ver


def is_z3_available() -> bool:
    """Return True iff `z3-solver` is importable in the current Python runtime."""
    available, _, _ = _detect_z3()
    return available


def _resolve_backend(backend: str = "auto") -> Tuple[str, Optional[Any], str]:
    """Resolve active verification backend (`z3_smt` or `exact_python_fallback`)."""
    norm = str(backend or "auto").strip().lower()
    py_ver = f"python-{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if norm in ("auto", ""):
        available, z3_mod, z3_ver = _detect_z3()
        return (BACKEND_Z3, z3_mod, f"z3-{z3_ver}") if available and z3_mod is not None else (BACKEND_PYTHON, None, py_ver)
    if norm in ("z3", "z3_smt"):
        available, z3_mod, z3_ver = _detect_z3()
        if not available or z3_mod is None:
            raise RuntimeError("Z3_BACKEND_UNAVAILABLE: z3-solver is not available in this interpreter.")
        return BACKEND_Z3, z3_mod, f"z3-{z3_ver}"
    if norm in ("python", "fallback", "exact_python_fallback"):
        return BACKEND_PYTHON, None, py_ver
    raise ValueError(f"INVALID_SOLVER_BACKEND: '{backend}' not supported.")


def _validate_no_trojan(value: Any, *, field_name: str) -> None:
    if isinstance(value, str):
        if "\x00" in value or TROJAN_UNICODE_RE.search(value):
            raise ValueError(f"REJECTED_TROJAN_UNICODE ({field_name}): control or bidi character detected.")
    elif isinstance(value, Mapping):
        for k, v in value.items():
            _validate_no_trojan(str(k), field_name=field_name)
            _validate_no_trojan(v, field_name=field_name)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            _validate_no_trojan(item, field_name=field_name)


@dataclass
class SMTProofCertificate:
    """Machine-checkable SMT / constraint-solver certificate (`SMTProofCertificate/1`)."""

    status: str
    backend: str
    property_name: str
    unsat_core_or_witness: Any
    proof_sha256: str = ""
    elapsed_ms: float = 0.0
    plan_id: str = ""
    plan_hash: str = ""
    solver_version: str = ""
    smtlib2_sha256: str = ""
    schema: str = SMT_CERTIFICATE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SMT_CERTIFICATE_SCHEMA:
            raise ValueError(f"INVALID_SCHEMA: expected {SMT_CERTIFICATE_SCHEMA}, got '{self.schema}'.")
        norm_status = validate_safe_text(self.status, field_name="status").upper()
        if norm_status not in VALID_PROOF_STATUSES:
            raise ValueError(f"INVALID_PROOF_STATUS: '{self.status}' not in {sorted(VALID_PROOF_STATUSES)}.")
        self.status = norm_status

        norm_backend = validate_safe_text(self.backend, field_name="backend").lower()
        if norm_backend not in VALID_BACKENDS:
            raise ValueError(f"INVALID_PROOF_BACKEND: '{self.backend}' not in {sorted(VALID_BACKENDS)}.")
        self.backend = norm_backend

        self.property_name = validate_safe_text(self.property_name, field_name="property_name")
        self.unsat_core_or_witness = redact_secrets_in_value(self.unsat_core_or_witness)
        _validate_no_trojan(self.unsat_core_or_witness, field_name="unsat_core_or_witness")
        self.elapsed_ms = max(0.0, round(float(self.elapsed_ms), 6))
        self.plan_id = validate_safe_text(self.plan_id, field_name="plan_id", allow_empty=True)
        self.solver_version = validate_safe_text(self.solver_version, field_name="solver_version", allow_empty=True)

        if self.plan_hash:
            self.plan_hash = normalize_sha256(self.plan_hash, field_name="plan_hash")
        if self.smtlib2_sha256:
            self.smtlib2_sha256 = normalize_sha256(self.smtlib2_sha256, field_name="smtlib2_sha256")

        expected = self.compute_proof_sha256()
        if self.proof_sha256:
            provided = normalize_sha256(self.proof_sha256, field_name="proof_sha256")
            if not hmac.compare_digest(provided, expected):
                raise ValueError("PROOF_CERTIFICATE_DIGEST_MISMATCH: proof_sha256 does not match certificate.")
            self.proof_sha256 = provided
        else:
            self.proof_sha256 = expected

    def _digest_basis(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "property_name": self.property_name,
            "status": self.status,
            "backend": self.backend,
            "plan_id": self.plan_id,
            "plan_hash": self.plan_hash,
            "solver_version": self.solver_version,
            "smtlib2_sha256": self.smtlib2_sha256,
            "unsat_core_or_witness": self.unsat_core_or_witness,
        }

    def compute_proof_sha256(self) -> str:
        """Compute canonical SHA-256 digest over certificate proof content."""
        return sha256_digest(self._digest_basis())

    def verify_integrity(self) -> bool:
        """Return True iff certificate fields and `proof_sha256` match without tampering."""
        if self.schema != SMT_CERTIFICATE_SCHEMA:
            return False
        if self.status not in VALID_PROOF_STATUSES or self.backend not in VALID_BACKENDS:
            return False
        if not is_valid_sha256(self.proof_sha256):
            return False
        return hmac.compare_digest(self.proof_sha256.lower(), self.compute_proof_sha256().lower())

    @property
    def proven(self) -> bool:
        return self.status == STATUS_PROVEN and self.verify_integrity()

    def to_dict(self) -> Dict[str, Any]:
        payload = self._digest_basis()
        payload["elapsed_ms"] = self.elapsed_ms
        payload["proof_sha256"] = self.proof_sha256
        return redact_secrets_in_value(payload)

    def to_canonical_json(self) -> str:
        serialized = canonical_json_dumps(self.to_dict())
        assert_no_raw_secrets(serialized, context=f"SMTProofCertificate:{self.property_name}")
        return serialized

    def to_formal_proof_artifact(self) -> FormalProofArtifact:
        """Convert a verified `PROVEN` certificate into a `FormalProofArtifact/1`."""
        if not self.proven:
            raise ValueError(
                f"CANNOT_EXPORT_UNPROVEN_ARTIFACT: property '{self.property_name}' has status '{self.status}'."
            )
        return FormalProofArtifact(
            solver_name="z3" if self.backend == BACKEND_Z3 else "exact_python_constraint_solver",
            solver_version=self.solver_version or "1.0",
            assumptions=[
                f"property={self.property_name}",
                f"backend={self.backend}",
                f"plan_hash={self.plan_hash or 'none'}",
            ],
            proof_scope=f"CompositionPlan/{self.property_name}",
            proof_digest=self.proof_sha256,
            verified=True,
            evidence_kind="formal_solver",
        )

    @classmethod
    def from_dict(cls, data: Union["SMTProofCertificate", Mapping[str, Any]]) -> "SMTProofCertificate":
        if isinstance(data, SMTProofCertificate):
            if not data.verify_integrity():
                raise ValueError("PROOF_CERTIFICATE_DIGEST_MISMATCH: in-memory certificate tampered.")
            return data
        if not isinstance(data, Mapping):
            raise ValueError("INVALID_SMT_PROOF_CERTIFICATE: expected mapping.")
        required = ("status", "backend", "property_name", "unsat_core_or_witness", "proof_sha256")
        missing = [k for k in required if k not in data]
        if missing:
            raise ValueError(f"MISSING_CERTIFICATE_FIELDS: {','.join(missing)}")
        return cls(
            status=data["status"],
            backend=data["backend"],
            property_name=data["property_name"],
            unsat_core_or_witness=data["unsat_core_or_witness"],
            proof_sha256=data["proof_sha256"],
            elapsed_ms=data.get("elapsed_ms", 0.0),
            plan_id=data.get("plan_id", ""),
            plan_hash=data.get("plan_hash", ""),
            solver_version=data.get("solver_version", ""),
            smtlib2_sha256=data.get("smtlib2_sha256", ""),
            schema=data.get("schema", SMT_CERTIFICATE_SCHEMA),
        )


@dataclass
class FormalVerificationBundle:
    """Aggregated formal verification result across all DAG safety properties."""

    all_proven: bool
    certificates: Dict[str, SMTProofCertificate]
    certificate_sha256: str = ""
    plan_id: str = ""
    plan_hash: str = ""
    backend: str = ""
    total_elapsed_ms: float = 0.0
    schema: str = FORMAL_BUNDLE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != FORMAL_BUNDLE_SCHEMA:
            raise ValueError(f"INVALID_SCHEMA: expected {FORMAL_BUNDLE_SCHEMA}, got '{self.schema}'.")
        if not isinstance(self.all_proven, bool):
            raise ValueError("INVALID_ALL_PROVEN: expected strict bool.")
        if not isinstance(self.certificates, Mapping) or not self.certificates:
            raise ValueError("INVALID_CERTIFICATES: expected non-empty mapping of certificates.")

        normalized_certs: Dict[str, SMTProofCertificate] = {}
        for key, raw_cert in self.certificates.items():
            normalized_certs[validate_safe_text(str(key), field_name="certificate_key")] = SMTProofCertificate.from_dict(raw_cert)
        self.certificates = normalized_certs

        expected_all = all(c.status == STATUS_PROVEN and c.verify_integrity() for c in self.certificates.values())
        if self.all_proven != expected_all:
            raise ValueError(f"INVALID_BUNDLE_ALL_PROVEN_FLAG: all_proven={self.all_proven} contradicts certificates.")

        self.plan_id = validate_safe_text(self.plan_id, field_name="plan_id", allow_empty=True)
        if self.plan_hash:
            self.plan_hash = normalize_sha256(self.plan_hash, field_name="plan_hash")
        self.backend = validate_safe_text(self.backend, field_name="backend", allow_empty=True)
        self.total_elapsed_ms = max(0.0, round(float(self.total_elapsed_ms), 6))

        expected_agg = self.compute_certificate_sha256()
        if self.certificate_sha256:
            provided = normalize_sha256(self.certificate_sha256, field_name="certificate_sha256")
            if not hmac.compare_digest(provided, expected_agg):
                raise ValueError("BUNDLE_CERTIFICATE_DIGEST_MISMATCH: aggregate certificate_sha256 tampered.")
            self.certificate_sha256 = provided
        else:
            self.certificate_sha256 = expected_agg

    def _digest_basis(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "all_proven": self.all_proven,
            "plan_id": self.plan_id,
            "plan_hash": self.plan_hash,
            "backend": self.backend,
            "certificate_digests": {k: self.certificates[k].proof_sha256 for k in sorted(self.certificates.keys())},
        }

    def compute_certificate_sha256(self) -> str:
        """Compute canonical aggregate SHA-256 across all property certificates."""
        return sha256_digest(self._digest_basis())

    def verify_integrity(self) -> bool:
        """Return True iff every certificate and aggregate `certificate_sha256` are intact."""
        if self.schema != FORMAL_BUNDLE_SCHEMA or not self.certificates:
            return False
        if not all(cert.verify_integrity() for cert in self.certificates.values()):
            return False
        if self.all_proven != all(c.status == STATUS_PROVEN for c in self.certificates.values()):
            return False
        if not is_valid_sha256(self.certificate_sha256):
            return False
        return hmac.compare_digest(self.certificate_sha256.lower(), self.compute_certificate_sha256().lower())

    def to_dict(self) -> Dict[str, Any]:
        return redact_secrets_in_value(
            {
                "schema": self.schema,
                "all_proven": self.all_proven,
                "plan_id": self.plan_id,
                "plan_hash": self.plan_hash,
                "backend": self.backend,
                "total_elapsed_ms": self.total_elapsed_ms,
                "certificates": {k: v.to_dict() for k, v in self.certificates.items()},
                "certificate_sha256": self.certificate_sha256,
            }
        )

    def to_canonical_json(self) -> str:
        serialized = canonical_json_dumps(self.to_dict())
        assert_no_raw_secrets(serialized, context=f"FormalVerificationBundle:{self.plan_id}")
        return serialized

    @classmethod
    def from_dict(cls, data: Union["FormalVerificationBundle", Mapping[str, Any]]) -> "FormalVerificationBundle":
        if isinstance(data, FormalVerificationBundle):
            if not data.verify_integrity():
                raise ValueError("BUNDLE_CERTIFICATE_DIGEST_MISMATCH: in-memory bundle tampered.")
            return data
        if not isinstance(data, Mapping):
            raise ValueError("INVALID_FORMAL_VERIFICATION_BUNDLE: expected mapping.")
        required = ("all_proven", "certificates", "certificate_sha256")
        missing = [k for k in required if k not in data]
        if missing:
            raise ValueError(f"MISSING_BUNDLE_FIELDS: {','.join(missing)}")
        return cls(
            all_proven=data["all_proven"],
            certificates=dict(data["certificates"]),
            certificate_sha256=data["certificate_sha256"],
            plan_id=data.get("plan_id", ""),
            plan_hash=data.get("plan_hash", ""),
            backend=data.get("backend", ""),
            total_elapsed_ms=data.get("total_elapsed_ms", 0.0),
            schema=data.get("schema", FORMAL_BUNDLE_SCHEMA),
        )


def verify_certificate_digest(cert_or_dict: Union[SMTProofCertificate, Mapping[str, Any]]) -> bool:
    """Verify an `SMTProofCertificate` or serialized dict without crashing."""
    try:
        return SMTProofCertificate.from_dict(cert_or_dict).verify_integrity()
    except (ValueError, KeyError, TypeError):
        return False


def verify_bundle_digest(bundle_or_dict: Union[FormalVerificationBundle, Mapping[str, Any]]) -> bool:
    """Verify a `FormalVerificationBundle` or serialized dict including all sub-certificates."""
    try:
        return FormalVerificationBundle.from_dict(bundle_or_dict).verify_integrity()
    except (ValueError, KeyError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Shared Plan Normalization, Graph Extraction & Verification Preamble
# ---------------------------------------------------------------------------


@dataclass
class _PreparedContext:
    property_name: str
    backend_name: str
    z3_mod: Optional[Any]
    solver_version: str
    start_ns: int
    plan_dict: Dict[str, Any]
    plan_id: str
    plan_hash: str
    graph: Dict[str, Any]
    tool_map: Dict[str, ToolSpec]
    adapter_map: Dict[str, AdapterSpec]
    raw_adapters_by_id: Dict[str, Mapping[str, Any]]
    error_cert: Optional[SMTProofCertificate] = None

    def make_cert(self, status: str, witness: Any, *, smtlib2_text: str = "") -> SMTProofCertificate:
        elapsed_ms = (time.perf_counter_ns() - self.start_ns) / 1_000_000.0
        smt_hash = sha256_digest(smtlib2_text) if smtlib2_text else ""
        return SMTProofCertificate(
            status=status,
            backend=self.backend_name,
            property_name=self.property_name,
            unsat_core_or_witness=witness,
            elapsed_ms=elapsed_ms,
            plan_id=self.plan_id,
            plan_hash=self.plan_hash,
            solver_version=self.solver_version,
            smtlib2_sha256=smt_hash,
        )


def _z3_eval_int(model: Any, expr: Any) -> int:
    return int(model.evaluate(expr, model_completion=True).as_long())


def _extract_plan_envelope(
    plan: Union[CompositionPlan, Mapping[str, Any]],
) -> Tuple[Dict[str, Any], str, str, Optional[str]]:
    if isinstance(plan, CompositionPlan):
        plan_dict: Dict[str, Any] = {
            "schema": plan.schema,
            "plan_id": plan.plan_id,
            "goal_contract_hash": plan.goal_contract_hash,
            "nodes": [dict(n) if isinstance(n, Mapping) else n for n in (plan.nodes or ())],
            "edges": [dict(e) if isinstance(e, Mapping) else e for e in (plan.edges or ())],
            "input_bindings": dict(plan.input_bindings or {}),
            "tool_artifact_hashes": dict(plan.tool_artifact_hashes or {}),
            "adapter_hashes": dict(plan.adapter_hashes or {}),
            "permission_union": list(plan.permission_union or ()),
            "effects_union": dict(plan.effects_union or {}),
            "expected_outputs": (
                dict(plan.expected_outputs)
                if isinstance(plan.expected_outputs, Mapping)
                else list(plan.expected_outputs or ())
            ),
            "oracle_ref": plan.oracle_ref,
            "verification_plan": dict(plan.verification_plan or {}),
            "estimated_resources": dict(plan.estimated_resources or {}),
            "plan_hash": plan.plan_hash,
            "profile": plan.profile,
            "max_depth": plan.max_depth,
            "security_checks": dict(plan.security_checks) if isinstance(plan.security_checks, Mapping) else None,
        }
    elif isinstance(plan, Mapping):
        plan_dict = dict(plan)
    else:
        return {}, "invalid-plan", "", "INVALID_PLAN_TYPE: expected CompositionPlan or Mapping."

    plan_id = str(plan_dict.get("plan_id") or "unnamed-plan").strip() or "unnamed-plan"
    raw_hash = str(plan_dict.get("plan_hash") or "").strip().lower()
    if is_valid_sha256(raw_hash):
        plan_hash = raw_hash
    else:
        plan_hash = sha256_digest(
            {
                "plan_id": plan_id,
                "nodes": plan_dict.get("nodes") or [],
                "edges": plan_dict.get("edges") or [],
                "input_bindings": plan_dict.get("input_bindings") or {},
            }
        )
    return plan_dict, plan_id, plan_hash, None


def _extract_binding_source_node(val: Any) -> Optional[str]:
    if isinstance(val, str):
        cleaned = val.strip()
        return cleaned.split(".", 1)[0].strip() if "." in cleaned else (cleaned or None)
    if isinstance(val, Mapping):
        for key in ("node_id", "node", "from_node"):
            if key in val:
                return str(val[key]).strip()
    return None


def _build_dependency_graph(plan_dict: Mapping[str, Any]) -> Dict[str, Any]:
    raw_nodes = plan_dict.get("nodes")
    raw_edges = plan_dict.get("edges") or ()
    bindings = plan_dict.get("input_bindings") if isinstance(plan_dict.get("input_bindings"), Mapping) else {}

    node_ids: List[str] = []
    node_map: Dict[str, Dict[str, Any]] = {}
    structural_errors: List[str] = []

    if not isinstance(raw_nodes, (list, tuple)) or not raw_nodes:
        return {
            "node_ids": [],
            "node_map": {},
            "adj": {},
            "preds": {},
            "edge_records": [],
            "structural_errors": ["EMPTY_OR_INVALID_NODES"],
        }

    seen: Set[str] = set()
    for idx, raw_node in enumerate(raw_nodes):
        if not isinstance(raw_node, Mapping):
            structural_errors.append(f"INVALID_NODE_ENTRY:idx={idx}")
            continue
        raw_nid = raw_node.get("node_id")
        if not isinstance(raw_nid, str) or not raw_nid.strip():
            structural_errors.append(f"EMPTY_NODE_ID:idx={idx}")
            continue
        nid = raw_nid.strip()
        if nid in seen:
            structural_errors.append(f"DUPLICATE_NODE_ID:{nid}")
            continue
        seen.add(nid)
        node_ids.append(nid)
        node_map[nid] = dict(raw_node)

    adj: Dict[str, Set[str]] = {nid: set() for nid in node_ids}
    preds: Dict[str, Set[str]] = {nid: set() for nid in node_ids}
    edge_records: List[Dict[str, Any]] = []

    def _register_edge(src: str, dst: str, origin: str, edge_meta: Optional[Mapping[str, Any]] = None) -> None:
        if src not in seen or dst not in seen:
            structural_errors.append(f"UNKNOWN_EDGE_ENDPOINT:{origin}:{src}->{dst}")
            return
        adj[src].add(dst)
        preds[dst].add(src)
        rec = dict(edge_meta or {})
        rec["from_node"] = src
        rec["to_node"] = dst
        rec["_origin"] = origin
        edge_records.append(rec)

    if not isinstance(raw_edges, (list, tuple)):
        structural_errors.append("INVALID_EDGES_TYPE")
    else:
        for edge in raw_edges:
            if not isinstance(edge, Mapping):
                structural_errors.append("INVALID_EDGE_MAPPING")
                continue
            _register_edge(str(edge.get("from_node") or "").strip(), str(edge.get("to_node") or "").strip(), "edge", edge)

    for nid in node_ids:
        inputs_from = node_map[nid].get("inputs_from")
        if isinstance(inputs_from, Mapping):
            for port_name, val in inputs_from.items():
                src_node = _extract_binding_source_node(val)
                if src_node and src_node != "goal" and src_node in seen:
                    meta: Dict[str, Any] = {"input_port": str(port_name)}
                    if isinstance(val, Mapping) and val.get("adapter_id"):
                        meta["adapter_id"] = val["adapter_id"]
                    _register_edge(src_node, nid, "inputs_from", meta)

    for dst_key, src_val in bindings.items():
        key_s = str(dst_key).strip()
        if "." not in key_s or key_s in {"goal_sensitivities", "preconditions", "satisfied_preconditions", "goal_input_adapters"}:
            continue
        dst_nid, dst_port = key_s.split(".", 1)
        dst_nid = dst_nid.strip()
        if dst_nid not in seen:
            continue
        src_node = _extract_binding_source_node(src_val)
        if src_node and src_node != "goal" and src_node in seen:
            meta = {"input_port": dst_port.strip()}
            if isinstance(src_val, Mapping) and src_val.get("adapter_id"):
                meta["adapter_id"] = src_val["adapter_id"]
            _register_edge(src_node, dst_nid, "input_bindings", meta)

    return {
        "node_ids": node_ids,
        "node_map": node_map,
        "adj": adj,
        "preds": preds,
        "edge_records": edge_records,
        "structural_errors": structural_errors,
    }


def _lookup_tool(registry: Optional[Union[ToolRegistry, Mapping[str, ToolSpec]]], tool_id: str) -> Optional[ToolSpec]:
    if registry is None or not tool_id:
        return None
    if isinstance(registry, ToolRegistry):
        try:
            return registry.get(tool_id)
        except ValueError:
            return None
    if isinstance(registry, Mapping):
        spec = registry.get(tool_id)
        if spec is None or isinstance(spec, ToolSpec):
            return spec
        if isinstance(spec, Mapping):
            return ToolSpec.from_dict(dict(spec), from_discovery=False)
    raise ValueError("INVALID_REGISTRY: expected ToolRegistry or mapping of ToolSpec.")


def _collect_adapters(
    plan_dict: Mapping[str, Any],
    adapters: Union[Sequence[Union[AdapterSpec, Mapping[str, Any]]], Mapping[str, Union[AdapterSpec, Mapping[str, Any]]], None],
) -> Tuple[Dict[str, AdapterSpec], Dict[str, Mapping[str, Any]]]:
    parsed: Dict[str, AdapterSpec] = {}
    raw_by_id: Dict[str, Mapping[str, Any]] = {}
    sources: List[Any] = []
    ver_plan = plan_dict.get("verification_plan")
    for src in (ver_plan.get("adapters") if isinstance(ver_plan, Mapping) else None, adapters):
        if not src:
            continue
        sources.extend(src.values() if isinstance(src, Mapping) else src)
    for raw_item in sources:
        if isinstance(raw_item, AdapterSpec):
            parsed[raw_item.adapter_id] = raw_item
            continue
        if isinstance(raw_item, Mapping):
            aid = str(raw_item.get("adapter_id") or "").strip()
            if aid:
                raw_by_id[aid] = raw_item
            try:
                spec = AdapterSpec.from_dict(raw_item)
                parsed[spec.adapter_id] = spec
            except (ValueError, KeyError, TypeError):
                # Keep raw metadata even if AdapterSpec validation rejects untrusted/partial specs
                continue
    return parsed, raw_by_id


def _prepare_context(
    property_name: str,
    plan: Union[CompositionPlan, Mapping[str, Any]],
    *,
    backend: str = "auto",
    security_context: Optional[SecurityContext] = None,
    require_security_context: bool = False,
    registry: Optional[Union[ToolRegistry, Mapping[str, ToolSpec]]] = None,
    adapters: Union[Sequence[Union[AdapterSpec, Mapping[str, Any]]], Mapping[str, Union[AdapterSpec, Mapping[str, Any]]], None] = (),
    allow_structural_counterexample: bool = False,
) -> _PreparedContext:
    start_ns = time.perf_counter_ns()
    backend_name, z3_mod, solver_version = _resolve_backend(backend)
    plan_dict, plan_id, plan_hash, env_err = _extract_plan_envelope(plan)
    ctx = _PreparedContext(
        property_name=property_name,
        backend_name=backend_name,
        z3_mod=z3_mod,
        solver_version=solver_version,
        start_ns=start_ns,
        plan_dict=plan_dict,
        plan_id=plan_id,
        plan_hash=plan_hash,
        graph={},
        tool_map={},
        adapter_map={},
        raw_adapters_by_id={},
    )
    if env_err is not None:
        ctx.error_cert = ctx.make_cert(STATUS_ERROR, {"error": env_err})
        return ctx

    if require_security_context:
        if not isinstance(security_context, SecurityContext):
            ctx.error_cert = ctx.make_cert(STATUS_ERROR, {"error": "INVALID_SECURITY_CONTEXT"})
            return ctx
        try:
            _verify_context_policy_integrity(security_context)
        except PermissionError as exc:
            ctx.error_cert = ctx.make_cert(STATUS_ERROR, {"error": str(exc)})
            return ctx

    graph = _build_dependency_graph(plan_dict)
    ctx.graph = graph
    if graph["structural_errors"]:
        status = STATUS_COUNTEREXAMPLE if (allow_structural_counterexample and graph["node_ids"]) else STATUS_ERROR
        ctx.error_cert = ctx.make_cert(status, {"structural_errors": graph["structural_errors"]})
        return ctx

    ctx.adapter_map, ctx.raw_adapters_by_id = _collect_adapters(plan_dict, adapters)
    for n in graph["node_map"].values():
        tid = str(n.get("tool_id") or "").strip()
        if tid and n.get("kind") != "adapter" and tid not in ctx.tool_map:
            spec = _lookup_tool(registry, tid)
            if spec is not None:
                ctx.tool_map[tid] = spec
    return ctx


def _kahn_topological_order(
    node_ids: Sequence[str],
    adj: Mapping[str, Set[str]],
    preds: Mapping[str, Set[str]],
) -> Tuple[List[str], bool]:
    indegree = {nid: len(preds.get(nid, ())) for nid in node_ids}
    heap = [nid for nid in node_ids if indegree[nid] == 0]
    heapq.heapify(heap)
    order: List[str] = []
    while heap:
        cur = heapq.heappop(heap)
        order.append(cur)
        for nxt in sorted(adj.get(cur, ())):
            indegree[nxt] -= 1
            if indegree[nxt] == 0:
                heapq.heappush(heap, nxt)
    return order, len(order) == len(node_ids)


def _find_deterministic_cycle(node_ids: Sequence[str], adj: Mapping[str, Set[str]]) -> List[str]:
    state: Dict[str, int] = {nid: 0 for nid in node_ids}
    stack: List[str] = []
    pos_in_stack: Dict[str, int] = {}
    for start in sorted(node_ids):
        if state[start] != 0:
            continue
        iter_stack: List[Tuple[str, List[str], int]] = [(start, sorted(adj.get(start, ())), 0)]
        state[start] = 1
        pos_in_stack[start] = len(stack)
        stack.append(start)
        while iter_stack:
            cur, nbrs, idx = iter_stack[-1]
            if idx < len(nbrs):
                nxt = nbrs[idx]
                iter_stack[-1] = (cur, nbrs, idx + 1)
                if nxt not in state:
                    continue
                if state[nxt] == 1:
                    return stack[pos_in_stack[nxt]:] + [nxt]
                if state[nxt] == 0:
                    state[nxt] = 1
                    pos_in_stack[nxt] = len(stack)
                    stack.append(nxt)
                    iter_stack.append((nxt, sorted(adj.get(nxt, ())), 0))
            else:
                iter_stack.pop()
                stack.pop()
                pos_in_stack.pop(cur, None)
                state[cur] = 2
    return []


def _shortest_chain_to_node(
    target: str,
    node_ids: Sequence[str],
    adj: Mapping[str, Set[str]],
    preds: Mapping[str, Set[str]],
) -> List[str]:
    roots = sorted(nid for nid in node_ids if not preds.get(nid)) or [target]
    queue: deque[List[str]] = deque([r] for r in roots)
    seen: Set[str] = set(roots)
    while queue:
        path = queue.popleft()
        cur = path[-1]
        if cur == target:
            return path
        for nxt in sorted(adj.get(cur, ())):
            if nxt not in seen:
                seen.add(nxt)
                queue.append(path + [nxt])
    return [target]


# ---------------------------------------------------------------------------
# Property 1: Acyclicity & Total Order
# ---------------------------------------------------------------------------


def prove_acyclic_and_total_order(
    plan: Union[CompositionPlan, Mapping[str, Any]],
    *,
    backend: str = "auto",
) -> SMTProofCertificate:
    """Prove `plan` contains no directed cycle and synthesize a valid total order."""
    ctx = _prepare_context("acyclic_and_total_order", plan, backend=backend, allow_structural_counterexample=True)
    if ctx.error_cert is not None:
        return ctx.error_cert

    node_ids: List[str] = ctx.graph["node_ids"]
    adj: Mapping[str, Set[str]] = ctx.graph["adj"]
    preds: Mapping[str, Set[str]] = ctx.graph["preds"]
    unique_edges = sorted({(rec["from_node"], rec["to_node"]) for rec in ctx.graph["edge_records"]})

    if ctx.backend_name == BACKEND_Z3 and ctx.z3_mod is not None:
        z3_mod = ctx.z3_mod
        solver = z3_mod.Solver()
        n = len(node_ids)
        ranks = {nid: z3_mod.Int(f"rank_{idx}") for idx, nid in enumerate(node_ids)}
        for idx, nid in enumerate(node_ids):
            solver.assert_and_track(z3_mod.And(ranks[nid] >= 0, ranks[nid] < n), f"domain_{idx}")
        if n > 1:
            solver.assert_and_track(z3_mod.Distinct([ranks[nid] for nid in node_ids]), "distinct_ranks")
        edge_labels: Dict[str, Tuple[str, str]] = {}
        for e_idx, (src, dst) in enumerate(unique_edges):
            lbl = f"edge_{e_idx}_{src}_to_{dst}"
            edge_labels[lbl] = (src, dst)
            solver.assert_and_track(ranks[src] < ranks[dst], lbl)

        smtlib2 = solver.to_smt2()
        verdict = solver.check()
        if verdict == z3_mod.sat:
            model = solver.model()
            rank_cert = {nid: _z3_eval_int(model, ranks[nid]) for nid in node_ids}
            total_order = sorted(node_ids, key=lambda nid: (rank_cert[nid], nid))
            if any(rank_cert[s] >= rank_cert[d] for s, d in unique_edges):
                return ctx.make_cert(STATUS_ERROR, {"error": "MODEL_ORDER_CHECK_FAILED"}, smtlib2_text=smtlib2)
            return ctx.make_cert(
                STATUS_PROVEN,
                {
                    "acyclic": True,
                    "total_order": total_order,
                    "rank_certificate": rank_cert,
                    "node_count": n,
                    "edge_count": len(unique_edges),
                    "smt_verdict": "SAT_STRICT_RANK_EXISTENCE",
                },
                smtlib2_text=smtlib2,
            )
        if verdict == z3_mod.unsat:
            core_labels = sorted(str(c) for c in solver.unsat_core())
            core_adj: Dict[str, Set[str]] = {nid: set() for nid in node_ids}
            for lbl in core_labels:
                if lbl in edge_labels:
                    core_adj[edge_labels[lbl][0]].add(edge_labels[lbl][1])
            cycle = _find_deterministic_cycle(node_ids, core_adj) or _find_deterministic_cycle(node_ids, adj)
            cycle_edges = [{"from_node": cycle[i], "to_node": cycle[i + 1]} for i in range(max(0, len(cycle) - 1))]
            return ctx.make_cert(
                STATUS_COUNTEREXAMPLE,
                {"acyclic": False, "cycle": cycle, "cycle_edges": cycle_edges, "unsat_core": core_labels, "reason": "CYCLE_DETECTED"},
                smtlib2_text=smtlib2,
            )
        return ctx.make_cert(STATUS_ERROR, {"error": f"Z3_UNKNOWN:{solver.reason_unknown()}"}, smtlib2_text=smtlib2)

    order, is_acyclic = _kahn_topological_order(node_ids, adj, preds)
    if is_acyclic:
        return ctx.make_cert(
            STATUS_PROVEN,
            {
                "acyclic": True,
                "total_order": order,
                "rank_certificate": {nid: idx for idx, nid in enumerate(order)},
                "node_count": len(node_ids),
                "edge_count": len(unique_edges),
            },
        )
    cycle = _find_deterministic_cycle(node_ids, adj)
    cycle_edges = [{"from_node": cycle[i], "to_node": cycle[i + 1]} for i in range(max(0, len(cycle) - 1))]
    return ctx.make_cert(
        STATUS_COUNTEREXAMPLE,
        {"acyclic": False, "cycle": cycle, "cycle_edges": cycle_edges, "reason": "CYCLE_DETECTED"},
    )


# ---------------------------------------------------------------------------
# Property 2: Sensitivity Lattice & No Secret Escalation
# ---------------------------------------------------------------------------


def _parse_sensitivity_level(raw: Any, *, field_name: str) -> int:
    if isinstance(raw, int) and not isinstance(raw, bool) and raw in SENSITIVITY_NAMES:
        return raw
    token = str(raw or "").strip().lower()
    if token not in SENSITIVITY_LATTICE:
        raise ValueError(f"INVALID_SENSITIVITY_LEVEL ({field_name}): {raw!r}")
    return SENSITIVITY_LATTICE[token]


def _extract_node_port_sensitivity(node: Mapping[str, Any], tool: Optional[ToolSpec], direction: str) -> Optional[int]:
    plural_key, single_key = f"{direction}_ports", f"{direction}_port"
    for container in (node, tool.semantic_contract if tool is not None else {}):
        if not isinstance(container, Mapping):
            continue
        ports_map = container.get(plural_key)
        if isinstance(ports_map, Mapping):
            for port_obj in ports_map.values():
                if isinstance(port_obj, PortContract):
                    return _parse_sensitivity_level(port_obj.sensitivity, field_name=plural_key)
                if isinstance(port_obj, Mapping) and "sensitivity" in port_obj:
                    return _parse_sensitivity_level(port_obj["sensitivity"], field_name=plural_key)
        raw_single = container.get(single_key)
        if isinstance(raw_single, PortContract):
            return _parse_sensitivity_level(raw_single.sensitivity, field_name=single_key)
        if isinstance(raw_single, Mapping) and "sensitivity" in raw_single:
            return _parse_sensitivity_level(raw_single["sensitivity"], field_name=single_key)

    if tool is not None:
        io_schema = tool.output_schema if direction == "output" else tool.input_schema
        if isinstance(io_schema, Mapping):
            if io_schema.get("sensitivity") is not None:
                return _parse_sensitivity_level(io_schema["sensitivity"], field_name=f"tool_{direction}_schema")
            nested = io_schema.get("port_contract")
            if isinstance(nested, PortContract):
                return _parse_sensitivity_level(nested.sensitivity, field_name="tool_port_contract")
            if isinstance(nested, Mapping) and "sensitivity" in nested:
                return _parse_sensitivity_level(nested["sensitivity"], field_name="tool_port_contract")
        if isinstance(tool.semantic_contract, Mapping):
            for key in (f"{direction}_sensitivity", "sensitivity"):
                if tool.semantic_contract.get(key) is not None:
                    return _parse_sensitivity_level(tool.semantic_contract[key], field_name=key)
    return None


def _is_verified_adapter(adapter: AdapterSpec, plan_dict: Mapping[str, Any], authority: Optional[AttestationAuthority]) -> bool:
    if adapter.trust_status != TrustStatus.VERIFIED or not is_valid_sha256(adapter.verification_corpus_hash):
        return False
    att = adapter.verification_attestation
    if not isinstance(att, Mapping) or not att:
        return False
    norm_att = {**dict(att), "binary_hash": att.get("binary_hash", adapter.adapter_hash), "tool_id": att.get("tool_id", adapter.adapter_id)}
    if not has_valid_verification_attestation(norm_att, adapter.adapter_hash, adapter.adapter_id):
        return False
    adapter_hashes = plan_dict.get("adapter_hashes") if isinstance(plan_dict.get("adapter_hashes"), Mapping) else {}
    if adapter.adapter_id in adapter_hashes:
        if not hmac.compare_digest(str(adapter_hashes[adapter.adapter_id]).strip().lower(), adapter.adapter_hash.lower()):
            return False
    if authority is not None and authority.has_registered_verifiers:
        return authority.verify_adapter_attestation(
            att,
            expected_adapter_id=adapter.adapter_id,
            expected_adapter_hash=adapter.adapter_hash,
            expected_corpus_hash=adapter.verification_corpus_hash,
        )
    return True


def _adapter_declassifier_target(adapter: Optional[AdapterSpec], plan_dict: Mapping[str, Any], authority: Optional[AttestationAuthority]) -> Optional[int]:
    if adapter is None or adapter.lossless or not _is_verified_adapter(adapter, plan_dict, authority):
        return None
    map_text = canonical_json_dumps({"mapping": adapter.mapping, "preconditions": list(adapter.preconditions)}).lower()
    if not any(tok in map_text for tok in _DECLASSIFICATION_HINTS):
        return None
    return _parse_sensitivity_level(adapter.target_port.sensitivity, field_name="adapter_target_sensitivity")


def _node_declassifier_target(
    node: Mapping[str, Any],
    tool: Optional[ToolSpec],
    adapter_map: Mapping[str, AdapterSpec],
    plan_dict: Mapping[str, Any],
    authority: Optional[AttestationAuthority],
) -> Optional[int]:
    nid = str(node.get("node_id") or "").strip()
    tid = str(node.get("tool_id") or "").strip()
    if node.get("kind") == "adapter":
        return _adapter_declassifier_target(adapter_map.get(str(node.get("adapter_id") or tid).strip()), plan_dict, authority)

    decl_flag = bool(
        node.get("declassifier") is True
        or node.get("is_declassifier") is True
        or str(node.get("kind") or "").strip().lower() == "declassifier"
        or str(node.get("role") or "").strip().lower() == "declassifier"
    )
    if not decl_flag or node.get("attested") is False or node.get("verified") is False:
        return None
    if str(node.get("trust_status") or "").strip().upper() in {TrustStatus.DISCOVERED.value, TrustStatus.QUARANTINED.value, TrustStatus.RETIRED.value}:
        return None

    attested_ok = False
    att = node.get("declassifier_attestation") or node.get("verification_attestation")
    tool_hashes = plan_dict.get("tool_artifact_hashes") if isinstance(plan_dict.get("tool_artifact_hashes"), Mapping) else {}
    if isinstance(att, Mapping) and att:
        exp_hash = str(node.get("binary_hash") or tool_hashes.get(tid) or att.get("binary_hash") or "").strip().lower()
        exp_subj = str(att.get("tool_id") or tid or nid).strip()
        if is_valid_sha256(exp_hash) and has_valid_verification_attestation(dict(att), exp_hash, exp_subj):
            attested_ok = True
    if not attested_ok and tool is not None and tool.trust_status == TrustStatus.VERIFIED:
        if has_valid_verification_attestation(tool.verification_attestation, tool.binary_hash, tool.tool_id):
            if authority is None or not authority.has_registered_verifiers or authority.verify_attestation(
                tool.verification_attestation or {}, expected_tool_id=tool.tool_id, expected_binary_hash=tool.binary_hash
            ):
                attested_ok = True
    if not attested_ok:
        return None

    raw_target = node.get("target_sensitivity") or node.get("declassify_to") or node.get("output_sensitivity")
    if raw_target is not None:
        return _parse_sensitivity_level(raw_target, field_name="declassifier_target_sensitivity")
    port_out = _extract_node_port_sensitivity(node, tool, "output")
    return port_out if port_out is not None else SENSITIVITY_LATTICE["public"]


def _collect_sensitivity_model(ctx: _PreparedContext, security_context: SecurityContext, authority: Optional[AttestationAuthority]) -> Dict[str, Any]:
    plan_dict, graph = ctx.plan_dict, ctx.graph
    node_ids, node_map, preds, adj = graph["node_ids"], graph["node_map"], graph["preds"], graph["adj"]
    bindings = plan_dict.get("input_bindings") if isinstance(plan_dict.get("input_bindings"), Mapping) else {}
    goal_sens_raw = bindings.get("goal_sensitivities") if isinstance(bindings.get("goal_sensitivities"), Mapping) else {}
    goal_sens = {str(k): _parse_sensitivity_level(v, field_name=f"goal_sensitivities.{k}") for k, v in goal_sens_raw.items()}

    binding_floors: Dict[str, Tuple[int, Optional[str]]] = {}
    for dst_key, src_val in bindings.items():
        key_s = str(dst_key).strip()
        if "." not in key_s or key_s in {"goal_sensitivities", "preconditions", "satisfied_preconditions", "goal_input_adapters"}:
            continue
        dst_nid = key_s.split(".", 1)[0].strip()
        if dst_nid not in node_map:
            continue
        lvl, src_lbl = None, None
        if isinstance(src_val, str) and src_val in goal_sens:
            lvl, src_lbl = goal_sens[src_val], src_val
        elif isinstance(src_val, Mapping):
            if src_val.get("sensitivity") is not None:
                lvl = _parse_sensitivity_level(src_val["sensitivity"], field_name=f"input_bindings.{key_s}")
                src_lbl = str(src_val.get("source") or f"binding:{key_s}")
            elif isinstance(src_val.get("source"), str) and src_val["source"] in goal_sens:
                lvl, src_lbl = goal_sens[src_val["source"]], str(src_val["source"])
        if lvl is not None and lvl >= binding_floors.get(dst_nid, (0, None))[0]:
            binding_floors[dst_nid] = (lvl, src_lbl)

    node_source_floor: Dict[str, int] = {}
    node_sink_ceiling: Dict[str, Optional[int]] = {}
    node_declass_target: Dict[str, Optional[int]] = {}

    for nid in node_ids:
        n = node_map[nid]
        tool = ctx.tool_map.get(str(n.get("tool_id") or "").strip())
        declass_to = _node_declassifier_target(n, tool, ctx.adapter_map, plan_dict, authority)
        node_declass_target[nid] = declass_to

        raw_general = n.get("sensitivity") or n.get("data_sensitivity")
        raw_out = n.get("output_sensitivity") or n.get("source_sensitivity") or n.get("taint")
        raw_in = n.get("input_sensitivity") or n.get("sink_sensitivity")
        port_out = _extract_node_port_sensitivity(n, tool, "output")
        port_in = _extract_node_port_sensitivity(n, tool, "input")

        src_lvl = max(
            [0]
            + [_parse_sensitivity_level(c, field_name=f"node.{nid}.sensitivity") for c in (raw_out, raw_general) if c is not None]
            + ([port_out] if port_out is not None else [])
        )
        node_source_floor[nid] = declass_to if declass_to is not None else src_lvl

        ceiling: Optional[int] = None
        if raw_in is not None:
            ceiling = _parse_sensitivity_level(raw_in, field_name=f"node.{nid}.input_sensitivity")
        elif port_in is not None:
            ceiling = port_in
        elif raw_general is not None and declass_to is None:
            if len(preds.get(nid, ())) > 0 or bool(n.get("is_sink") or n.get("sink") or n.get("external_sink")) or nid in binding_floors:
                ceiling = _parse_sensitivity_level(raw_general, field_name=f"node.{nid}.sensitivity")
        node_sink_ceiling[nid] = ceiling

    edge_specs: List[Dict[str, Any]] = []
    seen_edges: Set[Tuple[str, str, str]] = set()
    for rec in graph["edge_records"]:
        src, dst, aid = rec["from_node"], rec["to_node"], str(rec.get("adapter_id") or "").strip()
        if (src, dst, aid) in seen_edges:
            continue
        seen_edges.add((src, dst, aid))
        adapter = ctx.adapter_map.get(aid) if aid else None
        declass_to = _adapter_declassifier_target(adapter, plan_dict, authority) if aid else None
        ad_src_ceil, ad_dst_floor = None, None
        if adapter is not None and declass_to is None:
            ad_src_ceil = _parse_sensitivity_level(adapter.source_port.sensitivity, field_name=f"adapter.{aid}.source_port")
            ad_dst_floor = _parse_sensitivity_level(adapter.target_port.sensitivity, field_name=f"adapter.{aid}.target_port")
        edge_specs.append(
            {
                "from_node": src,
                "to_node": dst,
                "adapter_id": aid or None,
                "declassify_to": declass_to,
                "adapter_src_ceiling": ad_src_ceil,
                "adapter_dst_floor": ad_dst_floor,
            }
        )

    goal_sinks: List[Dict[str, Any]] = []
    sink_nodes = [nid for nid in node_ids if len(adj.get(nid, ())) == 0] or list(node_ids)
    expected_outputs = plan_dict.get("expected_outputs")
    if isinstance(expected_outputs, list):
        for idx, item in enumerate(expected_outputs):
            if isinstance(item, Mapping) and item.get("sensitivity") is not None:
                exp_lvl = _parse_sensitivity_level(item["sensitivity"], field_name=f"expected_outputs[{idx}].sensitivity")
                tgt = str(item.get("node_id") or "").strip()
                goal_sinks.append({"label": f"goal_output[{idx}]", "ceiling": exp_lvl, "source_nodes": [tgt] if tgt in node_map else sink_nodes})
    elif isinstance(expected_outputs, Mapping) and expected_outputs.get("sensitivity") is not None:
        exp_lvl = _parse_sensitivity_level(expected_outputs["sensitivity"], field_name="expected_outputs.sensitivity")
        goal_sinks.append({"label": "goal_output", "ceiling": exp_lvl, "source_nodes": sink_nodes})
    if not goal_sinks and security_context.profile == SecurityProfile.GITHUB_PUBLIC:
        goal_sinks.append({"label": "github_public_egress", "ceiling": SENSITIVITY_LATTICE["public"], "source_nodes": sink_nodes})

    return {
        "binding_floors": binding_floors,
        "node_source_floor": node_source_floor,
        "node_sink_ceiling": node_sink_ceiling,
        "node_declass_target": node_declass_target,
        "edge_specs": edge_specs,
        "goal_sinks": goal_sinks,
    }


def _trace_sensitivity_witness(
    *,
    violating_node: str,
    violating_sink_label: str,
    violating_level: int,
    expected_ceiling: int,
    m_in: Mapping[str, int],
    m_out: Mapping[str, int],
    model_info: Mapping[str, Any],
    graph: Mapping[str, Any],
) -> Dict[str, Any]:
    node_ids: Sequence[str] = graph["node_ids"]
    binding_floors = model_info["binding_floors"]
    node_source_floor = model_info["node_source_floor"]
    node_declass_target = model_info["node_declass_target"]
    preds_edges: Dict[str, List[Mapping[str, Any]]] = {nid: [] for nid in node_ids}
    for es in model_info["edge_specs"]:
        preds_edges[es["to_node"]].append(es)

    path: List[str] = [violating_node]
    adapters_on_path: List[str] = []
    cur = violating_node
    visited: Set[str] = {cur}
    origin_source = cur
    origin_level = m_out.get(cur, m_in.get(cur, violating_level))

    for _ in range(len(node_ids) + 1):
        b_lvl, b_src = binding_floors.get(cur, (0, None))
        if cur != violating_node and node_source_floor.get(cur, 0) > expected_ceiling and node_declass_target.get(cur) is None:
            origin_source, origin_level = cur, node_source_floor[cur]
        if b_lvl > expected_ceiling and m_in.get(cur, 0) <= b_lvl:
            origin_source, origin_level = (b_src or cur), b_lvl
            break
        if node_declass_target.get(cur) is not None and cur != violating_node:
            break
        chosen = next(
            (
                es
                for es in sorted(preds_edges.get(cur, ()), key=lambda e: str(e["from_node"]))
                if es.get("declassify_to") is None and es["from_node"] not in visited and m_out.get(es["from_node"], 0) > expected_ceiling
            ),
            None,
        )
        if chosen is None:
            break
        u = str(chosen["from_node"])
        if chosen.get("adapter_id"):
            adapters_on_path.append(str(chosen["adapter_id"]))
        visited.add(u)
        path.append(u)
        cur, origin_source = u, u
        origin_level = m_out.get(u, m_in.get(u, violating_level))

    path.reverse()
    if origin_source != path[0]:
        path = [origin_source] + path
    if violating_sink_label != violating_node:
        path = path + [violating_sink_label]

    return {
        "leak_detected": True,
        "violating_path": path,
        "source_node": origin_source,
        "source_sensitivity": SENSITIVITY_NAMES.get(origin_level, str(origin_level)),
        "sink_node": violating_sink_label,
        "sink_ceiling": SENSITIVITY_NAMES.get(expected_ceiling, str(expected_ceiling)),
        "propagated_sensitivity": SENSITIVITY_NAMES.get(violating_level, str(violating_level)),
        "adapters_on_path": list(reversed(adapters_on_path)),
        "reason": "SECRET_SENSITIVITY_ESCALATION_WITHOUT_ATTESTED_DECLASSIFIER",
    }


def prove_no_secret_escalation(
    plan: Union[CompositionPlan, Mapping[str, Any]],
    security_context: SecurityContext,
    *,
    registry: Optional[Union[ToolRegistry, Mapping[str, ToolSpec]]] = None,
    adapters: Union[Sequence[Union[AdapterSpec, Mapping[str, Any]]], Mapping[str, Union[AdapterSpec, Mapping[str, Any]]], None] = (),
    authority: Optional[AttestationAuthority] = None,
    backend: str = "auto",
) -> SMTProofCertificate:
    """Prove no SECRET/RESTRICTED (or higher) taint reaches a lower-sensitivity sink un-declassified."""
    ctx = _prepare_context(
        "no_secret_escalation",
        plan,
        backend=backend,
        security_context=security_context,
        require_security_context=True,
        registry=registry,
        adapters=adapters,
    )
    if ctx.error_cert is not None:
        return ctx.error_cert

    eff_authority = authority if authority is not None else (registry.authority if isinstance(registry, ToolRegistry) else None)
    try:
        model_info = _collect_sensitivity_model(ctx, security_context, eff_authority)
    except ValueError as exc:
        return ctx.make_cert(STATUS_ERROR, {"error": str(exc)})

    node_ids: List[str] = ctx.graph["node_ids"]
    binding_floors = model_info["binding_floors"]
    node_source_floor = model_info["node_source_floor"]
    node_sink_ceiling = model_info["node_sink_ceiling"]
    node_declass_target = model_info["node_declass_target"]
    edge_specs = model_info["edge_specs"]
    goal_sinks = model_info["goal_sinks"]
    attested_declassifiers = sorted(nid for nid, tgt in node_declass_target.items() if tgt is not None) + sorted(
        str(es["adapter_id"]) for es in edge_specs if es["declassify_to"] is not None and es.get("adapter_id")
    )

    if ctx.backend_name == BACKEND_Z3 and ctx.z3_mod is not None:
        return _prove_sensitivity_z3(ctx, model_info, attested_declassifiers)

    t_in: Dict[str, int] = {nid: binding_floors.get(nid, (0, None))[0] for nid in node_ids}
    t_out: Dict[str, int] = {
        nid: (node_declass_target[nid] if node_declass_target[nid] is not None else max(t_in[nid], node_source_floor[nid]))
        for nid in node_ids
    }
    for _ in range(len(node_ids) + 1):
        changed = False
        for es in edge_specs:
            e_lvl = int(es["declassify_to"]) if es["declassify_to"] is not None else max(t_out[es["from_node"]], int(es["adapter_dst_floor"] or 0))
            dst = es["to_node"]
            if e_lvl > t_in[dst]:
                t_in[dst] = e_lvl
                changed = True
                if node_declass_target[dst] is None:
                    t_out[dst] = max(t_in[dst], node_source_floor[dst])
        if not changed:
            break

    checks: List[Tuple[bool, str, str, int, int]] = []
    for nid in node_ids:
        if node_sink_ceiling[nid] is not None:
            checks.append((t_in[nid] > int(node_sink_ceiling[nid]), nid, nid, t_in[nid], int(node_sink_ceiling[nid])))
    for es in edge_specs:
        if es.get("adapter_src_ceiling") is not None:
            src, ceil = es["from_node"], int(es["adapter_src_ceiling"])
            checks.append((t_out[src] > ceil, src, f"adapter:{es['adapter_id']}", t_out[src], ceil))
    for gs in goal_sinks:
        for sn in gs["source_nodes"]:
            ceil = int(gs["ceiling"])
            checks.append((t_out[sn] > ceil, sn, str(gs["label"]), t_out[sn], ceil))

    for is_bad, v_nid, v_sink_lbl, v_lvl, v_ceil in checks:
        if is_bad:
            return ctx.make_cert(
                STATUS_COUNTEREXAMPLE,
                _trace_sensitivity_witness(
                    violating_node=v_nid,
                    violating_sink_label=v_sink_lbl,
                    violating_level=v_lvl,
                    expected_ceiling=v_ceil,
                    m_in=t_in,
                    m_out=t_out,
                    model_info=model_info,
                    graph=ctx.graph,
                ),
            )
    return ctx.make_cert(
        STATUS_PROVEN,
        {
            "leak_free": True,
            "lattice": ["public", "internal", "secret", "restricted"],
            "attested_declassifiers": attested_declassifiers,
            "checked_sinks": len(checks),
        },
    )


def _prove_sensitivity_z3(
    ctx: _PreparedContext,
    model_info: Mapping[str, Any],
    attested_declassifiers: Sequence[str],
) -> SMTProofCertificate:
    z3_mod = ctx.z3_mod
    node_ids: List[str] = ctx.graph["node_ids"]
    binding_floors = model_info["binding_floors"]
    node_source_floor = model_info["node_source_floor"]
    node_sink_ceiling = model_info["node_sink_ceiling"]
    node_declass_target = model_info["node_declass_target"]
    edge_specs = model_info["edge_specs"]
    goal_sinks = model_info["goal_sinks"]

    order, is_acyclic = _kahn_topological_order(node_ids, ctx.graph["adj"], ctx.graph["preds"])
    solver = z3_mod.Solver()

    incoming_map: Dict[str, List[Mapping[str, Any]]] = {nid: [] for nid in node_ids}
    for es in edge_specs:
        incoming_map[es["to_node"]].append(es)

    def _max_expr(terms: Sequence[Any]) -> Any:
        acc = terms[0]
        for t in terms[1:]:
            acc = z3_mod.If(t > acc, t, acc)
        return acc

    if is_acyclic:
        t_in = {nid: z3_mod.Int(f"taint_in_{idx}") for idx, nid in enumerate(node_ids)}
        t_out = {nid: z3_mod.Int(f"taint_out_{idx}") for idx, nid in enumerate(node_ids)}
        for nid in order:
            solver.assert_and_track(z3_mod.And(t_in[nid] >= 0, t_in[nid] <= 3), f"bounds_in_{nid}")
            solver.assert_and_track(z3_mod.And(t_out[nid] >= 0, t_out[nid] <= 3), f"bounds_out_{nid}")
            in_terms: List[Any] = [z3_mod.IntVal(binding_floors[nid][0] if nid in binding_floors else 0)]
            for es in incoming_map[nid]:
                if es["declassify_to"] is not None:
                    in_terms.append(z3_mod.IntVal(int(es["declassify_to"])))
                else:
                    src_expr = t_out[es["from_node"]]
                    if es.get("adapter_dst_floor") is not None:
                        fl = int(es["adapter_dst_floor"])
                        src_expr = z3_mod.If(src_expr >= fl, src_expr, fl)
                    in_terms.append(src_expr)
            solver.assert_and_track(t_in[nid] == _max_expr(in_terms), f"join_in_{nid}")
            if node_declass_target[nid] is not None:
                solver.assert_and_track(t_out[nid] == int(node_declass_target[nid]), f"node_declass_{nid}")
            else:
                fl_n = int(node_source_floor[nid])
                solver.assert_and_track(t_out[nid] == z3_mod.If(t_in[nid] >= fl_n, t_in[nid], fl_n), f"node_prop_{nid}")
    else:
        in_layer: Dict[str, Any] = {nid: z3_mod.IntVal(binding_floors[nid][0] if nid in binding_floors else 0) for nid in node_ids}
        out_layer: Dict[str, Any] = {
            nid: z3_mod.IntVal(
                node_declass_target[nid] if node_declass_target[nid] is not None else max(binding_floors.get(nid, (0, None))[0], int(node_source_floor[nid]))
            )
            for nid in node_ids
        }
        for step in range(len(node_ids)):
            next_in, next_out = {}, {}
            for idx, nid in enumerate(node_ids):
                vi, vo = z3_mod.Int(f"taint_in_s{step}_{idx}"), z3_mod.Int(f"taint_out_s{step}_{idx}")
                terms = [in_layer[nid]] + [
                    z3_mod.IntVal(int(es["declassify_to"]))
                    if es["declassify_to"] is not None
                    else (
                        z3_mod.If(out_layer[es["from_node"]] >= int(es["adapter_dst_floor"]), out_layer[es["from_node"]], int(es["adapter_dst_floor"]))
                        if es.get("adapter_dst_floor") is not None
                        else out_layer[es["from_node"]]
                    )
                    for es in incoming_map[nid]
                ]
                solver.assert_and_track(vi == _max_expr(terms), f"step_in_{step}_{nid}")
                if node_declass_target[nid] is not None:
                    solver.assert_and_track(vo == int(node_declass_target[nid]), f"step_out_{step}_{nid}")
                else:
                    fl_n = int(node_source_floor[nid])
                    solver.assert_and_track(vo == z3_mod.If(vi >= fl_n, vi, fl_n), f"step_out_{step}_{nid}")
                next_in[nid], next_out[nid] = vi, vo
            in_layer, out_layer = next_in, next_out
        t_in, t_out = in_layer, out_layer

    violation_clauses: List[Tuple[Any, str, str, int]] = []
    for nid in node_ids:
        if node_sink_ceiling[nid] is not None:
            violation_clauses.append((t_in[nid] > int(node_sink_ceiling[nid]), nid, nid, int(node_sink_ceiling[nid])))
    for es in edge_specs:
        if es.get("adapter_src_ceiling") is not None:
            ceil = int(es["adapter_src_ceiling"])
            violation_clauses.append((t_out[es["from_node"]] > ceil, es["from_node"], f"adapter:{es['adapter_id']}", ceil))
    for gs in goal_sinks:
        ceil = int(gs["ceiling"])
        for sn in gs["source_nodes"]:
            violation_clauses.append((t_out[sn] > ceil, sn, str(gs["label"]), ceil))

    solver.assert_and_track(
        z3_mod.Or([c for c, _, _, _ in violation_clauses]) if violation_clauses else z3_mod.BoolVal(False),
        "exists_sensitivity_leak",
    )
    smtlib2 = solver.to_smt2()
    verdict = solver.check()

    if verdict == z3_mod.unsat:
        return ctx.make_cert(
            STATUS_PROVEN,
            {
                "leak_free": True,
                "lattice": ["public", "internal", "secret", "restricted"],
                "unsat_core": sorted(str(c) for c in solver.unsat_core()),
                "attested_declassifiers": list(attested_declassifiers),
                "checked_sinks": len(violation_clauses),
            },
            smtlib2_text=smtlib2,
        )
    if verdict == z3_mod.sat:
        model = solver.model()
        m_in = {nid: _z3_eval_int(model, t_in[nid]) for nid in node_ids}
        m_out = {nid: _z3_eval_int(model, t_out[nid]) for nid in node_ids}
        for clause, v_nid, v_sink_lbl, v_ceil in violation_clauses:
            if z3_mod.is_true(model.evaluate(clause, model_completion=True)):
                witness = _trace_sensitivity_witness(
                    violating_node=v_nid,
                    violating_sink_label=v_sink_lbl,
                    violating_level=m_in[v_nid] if v_sink_lbl == v_nid else m_out[v_nid],
                    expected_ceiling=v_ceil,
                    m_in=m_in,
                    m_out=m_out,
                    model_info=model_info,
                    graph=ctx.graph,
                )
                witness["model_taints"] = {
                    nid: {"in": SENSITIVITY_NAMES.get(m_in[nid], str(m_in[nid])), "out": SENSITIVITY_NAMES.get(m_out[nid], str(m_out[nid]))}
                    for nid in node_ids
                }
                return ctx.make_cert(STATUS_COUNTEREXAMPLE, witness, smtlib2_text=smtlib2)
    return ctx.make_cert(STATUS_ERROR, {"error": f"Z3_UNEXPECTED_STATUS:{verdict}"}, smtlib2_text=smtlib2)


# ---------------------------------------------------------------------------
# Property 3: Permission Monotonicity (BitVector Constraint Verification)
# ---------------------------------------------------------------------------


def _extract_perm_list(container: Any) -> List[str]:
    if not isinstance(container, Mapping):
        return []
    perms: List[str] = []
    for key in ("required_permissions", "permissions", "exec_permissions", "granted_permissions", "delegated_permissions", "escalated_permissions"):
        vals = container.get(key)
        if isinstance(vals, (list, tuple, set)):
            perms.extend(str(v).strip() for v in vals if str(v).strip())
    eff = container.get("effect_contract")
    if isinstance(eff, EffectContract):
        perms.extend(eff.exec_permissions)
    elif isinstance(eff, Mapping) and isinstance(eff.get("exec_permissions"), (list, tuple, set)):
        perms.extend(str(v).strip() for v in eff["exec_permissions"] if str(v).strip())
    return perms


def _collect_permission_universe(ctx: _PreparedContext, security_context: SecurityContext) -> Dict[str, Any]:
    plan_dict, graph = ctx.plan_dict, ctx.graph
    node_ids, node_map = graph["node_ids"], graph["node_map"]

    allowed_perms = {str(p).strip() for p in security_context.allowed_permissions if str(p).strip()}
    if not security_context.network_allowed:
        allowed_perms = {p for p in allowed_perms if not p.lower().startswith(_NETWORK_PERMISSION_PREFIXES)}

    raw_declared = [str(p).strip() for p in (plan_dict.get("permission_union") or ()) if str(p).strip()]
    declared_union = set(raw_declared)
    enforce_declared = len(declared_union) > 0

    node_perms: Dict[str, Set[str]] = {}
    for nid in node_ids:
        n = node_map[nid]
        tid = str(n.get("tool_id") or "").strip()
        tool = ctx.tool_map.get(tid)
        pset = set(_extract_perm_list(n))
        if tool is not None:
            pset.update(str(p).strip() for p in tool.required_permissions if str(p).strip())
            pset.update(_extract_perm_list(tool.semantic_contract))
            pset.update(_extract_perm_list(tool.runtime_requirements))
        if not security_context.network_allowed:
            net_scopes = list(n.get("network_scopes") or ())
            if isinstance(n.get("effect_contract"), Mapping):
                net_scopes.extend(n["effect_contract"].get("network_scopes") or ())
            if any(str(s).strip() for s in net_scopes):
                pset.add("network.egress")
        if n.get("kind") == "adapter":
            aid = str(n.get("adapter_id") or tid).strip()
            pset.update(_extract_perm_list(ctx.raw_adapters_by_id.get(aid)))
            if aid in ctx.adapter_map:
                pset.update(p[5:].strip() for p in ctx.adapter_map[aid].preconditions if p.startswith("perm:"))
        node_perms[nid] = pset

    adapter_edge_perms: Dict[str, Set[str]] = {}
    for rec in graph["edge_records"]:
        aid = str(rec.get("adapter_id") or "").strip()
        if not aid:
            continue
        pset = set(_extract_perm_list(rec)) | set(_extract_perm_list(ctx.raw_adapters_by_id.get(aid)))
        if aid in ctx.adapter_map:
            pset.update(p[5:].strip() for p in ctx.adapter_map[aid].preconditions if p.startswith("perm:"))
        if pset:
            adapter_edge_perms.setdefault(aid, set()).update(pset)
            node_perms[rec["to_node"]].update(pset)

    for aid, raw_ad in ctx.raw_adapters_by_id.items():
        pset = set(_extract_perm_list(raw_ad))
        if pset:
            adapter_edge_perms.setdefault(aid, set()).update(pset)

    universe = sorted(
        allowed_perms | declared_union | {p for ps in node_perms.values() for p in ps} | {p for ps in adapter_edge_perms.values() for p in ps}
    ) or ["__noop__"]
    perm_idx = {p: idx for idx, p in enumerate(universe)}

    def _to_mask(perms: Iterable[str]) -> int:
        mask = 0
        for p in perms:
            if p in perm_idx:
                mask |= 1 << perm_idx[p]
        return mask

    return {
        "universe": universe,
        "width": len(universe),
        "allowed_perms": sorted(allowed_perms),
        "allowed_mask": _to_mask(allowed_perms),
        "declared_mask": _to_mask(declared_union),
        "enforce_declared": enforce_declared,
        "node_perms": {nid: sorted(ps) for nid, ps in node_perms.items()},
        "node_masks": {nid: _to_mask(ps) for nid, ps in node_perms.items()},
        "adapter_perms": {aid: sorted(ps) for aid, ps in adapter_edge_perms.items()},
        "adapter_masks": {aid: _to_mask(ps) for aid, ps in adapter_edge_perms.items()},
    }


def _decode_mask(mask: int, universe: Sequence[str]) -> List[str]:
    return [p for idx, p in enumerate(universe) if (mask >> idx) & 1]


def prove_permission_monotonicity(
    plan: Union[CompositionPlan, Mapping[str, Any]],
    security_context: SecurityContext,
    *,
    registry: Optional[Union[ToolRegistry, Mapping[str, ToolSpec]]] = None,
    adapters: Union[Sequence[Union[AdapterSpec, Mapping[str, Any]]], Mapping[str, Union[AdapterSpec, Mapping[str, Any]]], None] = (),
    backend: str = "auto",
) -> SMTProofCertificate:
    """Prove `security_context.allowed_permissions` & `plan.permission_union` cover all DAG chains."""
    ctx = _prepare_context(
        "permission_monotonicity",
        plan,
        backend=backend,
        security_context=security_context,
        require_security_context=True,
        registry=registry,
        adapters=adapters,
    )
    if ctx.error_cert is not None:
        return ctx.error_cert

    perm_info = _collect_permission_universe(ctx, security_context)
    node_ids: List[str] = ctx.graph["node_ids"]
    adj, preds = ctx.graph["adj"], ctx.graph["preds"]
    order, is_acyclic = _kahn_topological_order(node_ids, adj, preds)
    eval_order = order if is_acyclic else sorted(node_ids)

    universe: List[str] = perm_info["universe"]
    width: int = perm_info["width"]
    allowed_mask: int = perm_info["allowed_mask"]
    declared_mask: int = perm_info["declared_mask"]
    enforce_declared: bool = perm_info["enforce_declared"]
    node_masks: Mapping[str, int] = perm_info["node_masks"]
    adapter_masks: Mapping[str, int] = perm_info["adapter_masks"]

    def _find_first_witness(chain_masks: Mapping[str, int]) -> Optional[Dict[str, Any]]:
        for nid in eval_order:
            own_m, ch_m = node_masks[nid], chain_masks[nid]
            miss_ctx = _decode_mask((own_m | ch_m) & (~allowed_mask), universe)
            miss_plan = _decode_mask((own_m | ch_m) & (~declared_mask), universe) if enforce_declared else []
            if miss_ctx or miss_plan:
                return {
                    "monotonic": False,
                    "offending_node": nid,
                    "offending_chain": _shortest_chain_to_node(nid, node_ids, adj, preds),
                    "missing_permissions": _decode_mask(own_m & (~allowed_mask), universe) or miss_ctx,
                    "undeclared_in_plan_permissions": (_decode_mask(own_m & (~declared_mask), universe) or miss_plan) if enforce_declared else [],
                    "node_required_permissions": perm_info["node_perms"][nid],
                    "allowed_permissions": perm_info["allowed_perms"],
                    "reason": "PRIVILEGE_ESCALATION_DETECTED",
                }
        for aid, amask in sorted(adapter_masks.items()):
            miss_ctx = _decode_mask(amask & (~allowed_mask), universe)
            miss_plan = _decode_mask(amask & (~declared_mask), universe) if enforce_declared else []
            if miss_ctx or miss_plan:
                return {
                    "monotonic": False,
                    "offending_node": f"adapter:{aid}",
                    "offending_chain": [f"adapter:{aid}"],
                    "missing_permissions": miss_ctx,
                    "undeclared_in_plan_permissions": miss_plan,
                    "allowed_permissions": perm_info["allowed_perms"],
                    "reason": "ADAPTER_PRIVILEGE_ESCALATION",
                }
        if enforce_declared:
            excess_plan = _decode_mask(declared_mask & (~allowed_mask), universe)
            if excess_plan:
                return {
                    "monotonic": False,
                    "offending_node": "plan.permission_union",
                    "offending_chain": ["plan.permission_union"],
                    "missing_permissions": excess_plan,
                    "undeclared_in_plan_permissions": [],
                    "allowed_permissions": perm_info["allowed_perms"],
                    "reason": "OVER_PRIVILEGED_PLAN_PERMISSION_UNION",
                }
        return None

    required_union = sorted(
        {p for ps in perm_info["node_perms"].values() for p in ps} | {p for ps in perm_info["adapter_perms"].values() for p in ps}
    )

    if ctx.backend_name == BACKEND_Z3 and ctx.z3_mod is not None:
        z3_mod = ctx.z3_mod
        solver = z3_mod.Solver()
        bv_allowed = z3_mod.BitVecVal(allowed_mask, width)
        bv_declared = z3_mod.BitVecVal(declared_mask, width)
        zero_bv = z3_mod.BitVecVal(0, width)

        chain_bv: Dict[str, Any] = {}
        if is_acyclic:
            for idx, nid in enumerate(eval_order):
                c_var = z3_mod.BitVec(f"chain_bv_{idx}", width)
                rhs = z3_mod.BitVecVal(node_masks[nid], width)
                for p_nid in sorted(preds.get(nid, ())):
                    rhs = rhs | chain_bv[p_nid]
                solver.assert_and_track(c_var == rhs, f"chain_def_{nid}")
                chain_bv[nid] = c_var
        else:
            layer = {nid: z3_mod.BitVecVal(node_masks[nid], width) for nid in node_ids}
            for step in range(len(node_ids)):
                nxt_layer = {}
                for idx, nid in enumerate(node_ids):
                    v = z3_mod.BitVec(f"chain_s{step}_{idx}", width)
                    rhs = layer[nid]
                    for p_nid in sorted(preds.get(nid, ())):
                        rhs = rhs | layer[p_nid]
                    solver.assert_and_track(v == rhs, f"chain_s{step}_{nid}")
                    nxt_layer[nid] = v
                layer = nxt_layer
            chain_bv = layer

        checks: List[Any] = [((chain_bv[nid] & (~bv_allowed)) != zero_bv) for nid in eval_order]
        checks.extend((z3_mod.BitVecVal(am, width) & (~bv_allowed)) != zero_bv for am in adapter_masks.values())
        if enforce_declared:
            checks.extend(((chain_bv[nid] & (~bv_declared)) != zero_bv) for nid in eval_order)
            checks.extend((z3_mod.BitVecVal(am, width) & (~bv_declared)) != zero_bv for am in adapter_masks.values())
            checks.append((bv_declared & (~bv_allowed)) != zero_bv)

        solver.assert_and_track(z3_mod.Or(checks), "exists_permission_escalation")
        smtlib2 = solver.to_smt2()
        verdict = solver.check()
        if verdict == z3_mod.unsat:
            return ctx.make_cert(
                STATUS_PROVEN,
                {
                    "monotonic": True,
                    "bitvector_width": width,
                    "allowed_permissions": perm_info["allowed_perms"],
                    "required_permissions_union": required_union,
                    "unsat_core": sorted(str(c) for c in solver.unsat_core()),
                },
                smtlib2_text=smtlib2,
            )
        if verdict == z3_mod.sat:
            model = solver.model()
            model_masks = {nid: _z3_eval_int(model, chain_bv[nid]) for nid in node_ids}
            witness = _find_first_witness(model_masks)
            if witness is not None:
                return ctx.make_cert(STATUS_COUNTEREXAMPLE, witness, smtlib2_text=smtlib2)
        return ctx.make_cert(STATUS_ERROR, {"error": f"Z3_UNEXPECTED_STATUS:{verdict}"}, smtlib2_text=smtlib2)

    chain_mask: Dict[str, int] = {nid: node_masks[nid] for nid in node_ids}
    for _ in range(len(node_ids) + 1):
        changed = False
        for nid in eval_order:
            new_m = chain_mask[nid]
            for p_nid in preds.get(nid, ()):
                new_m |= chain_mask[p_nid]
            if new_m != chain_mask[nid]:
                chain_mask[nid] = new_m
                changed = True
        if not changed:
            break
    witness = _find_first_witness(chain_mask)
    if witness is not None:
        return ctx.make_cert(STATUS_COUNTEREXAMPLE, witness)
    return ctx.make_cert(
        STATUS_PROVEN,
        {
            "monotonic": True,
            "bitvector_width": width,
            "allowed_permissions": perm_info["allowed_perms"],
            "required_permissions_union": required_union,
        },
    )


# ---------------------------------------------------------------------------
# Property 4: Effect Idempotency & WAL Replay / Retry Multiplicity
# ---------------------------------------------------------------------------


def _extract_idempotency_model(ctx: _PreparedContext) -> Dict[str, Any]:
    plan_dict, graph = ctx.plan_dict, ctx.graph
    node_ids, node_map = graph["node_ids"], graph["node_map"]
    ver_plan = plan_dict.get("verification_plan") if isinstance(plan_dict.get("verification_plan"), Mapping) else {}
    retryable_set = {str(x).strip() for x in (ver_plan.get("retryable_nodes") or ())}
    retry_policies = ver_plan.get("retry_policies") if isinstance(ver_plan.get("retry_policies"), Mapping) else {}
    idem_keys_map = ver_plan.get("idempotency_keys") if isinstance(ver_plan.get("idempotency_keys"), Mapping) else {}
    plan_wal_protected = ver_plan.get("wal_protected") is True or plan_dict.get("wal_protected") is True
    wal_replay_global = bool(
        ver_plan.get("wal_replay") is True
        or ver_plan.get("crash_replay") is True
        or ver_plan.get("allow_crash_replay") is True
        or plan_dict.get("wal_replay") is True
    )
    step_checkpointed = bool(ver_plan.get("step_checkpointing") is True)

    incoming_count: Dict[str, int] = {nid: 0 for nid in node_ids}
    unique_sources: Dict[str, Set[str]] = {nid: set() for nid in node_ids}
    edge_amp: Dict[str, bool] = {nid: False for nid in node_ids}
    for rec in graph["edge_records"]:
        src, dst = rec["from_node"], rec["to_node"]
        if rec.get("_origin") == "edge":
            incoming_count[dst] += 1
        unique_sources[dst].add(src)
        if str(rec.get("cardinality") or "").strip().lower() in {"many", "stream"} or int(rec.get("fan_out", 1) or 1) > 1:
            edge_amp[dst] = True

    node_info: Dict[str, Dict[str, Any]] = {}
    for nid in node_ids:
        n = node_map[nid]
        tool = ctx.tool_map.get(str(n.get("tool_id") or "").strip())
        eff_raw = n.get("effect_contract")
        irreversible = bool(n.get("irreversible", False))
        idempotent_explicit = "idempotent" in n
        idempotent = bool(n.get("idempotent", True))
        if isinstance(eff_raw, EffectContract):
            irreversible, idempotent, idempotent_explicit = irreversible or eff_raw.irreversible, eff_raw.idempotent, True
        elif isinstance(eff_raw, Mapping):
            irreversible = irreversible or bool(eff_raw.get("irreversible", False))
            if "idempotent" in eff_raw:
                idempotent, idempotent_explicit = bool(eff_raw["idempotent"]), True
        elif tool is not None:
            sem_eff = tool.semantic_contract.get("effect_contract") if isinstance(tool.semantic_contract, Mapping) else None
            if isinstance(sem_eff, Mapping):
                irreversible = irreversible or bool(sem_eff.get("irreversible", False))
                if "idempotent" in sem_eff and not idempotent_explicit:
                    idempotent, idempotent_explicit = bool(sem_eff["idempotent"]), True
            for se in tool.side_effects:
                se_low = str(se).strip().lower()
                if se_low == "irreversible":
                    irreversible = True
                elif se_low in {"non_idempotent", "not_idempotent"}:
                    idempotent, idempotent_explicit = False, True

        if irreversible and not idempotent_explicit:
            idempotent = False

        max_retries = max([0] + [int(n[k]) for k in ("max_retries", "retries") if n.get(k) is not None])
        for pol in (retry_policies.get(nid), n.get("retry_policy")):
            if isinstance(pol, Mapping):
                max_retries = max(max_retries, int(pol.get("max_retries", pol.get("retries", 1)) or 1))
        if (bool(n.get("retryable")) or bool(n.get("retry_policy")) or nid in retryable_set or nid in retry_policies) and max_retries <= 0:
            max_retries = 1

        has_barrier = bool(n.get("fan_in_barrier") is True or str(n.get("join_mode") or "").strip().lower() == "barrier")
        fan_in = max(incoming_count[nid], len(unique_sources[nid]))
        fan_in_mult = fan_in if (fan_in > 1 and not has_barrier) else 1
        if edge_amp[nid] or str(n.get("fan_out_mode") or "").strip().lower() in {"per_item", "scatter"}:
            fan_in_mult = max(fan_in_mult, 2)

        node_idem_key = str(n.get("idempotency_key") or idem_keys_map.get(nid) or "").strip()
        wal_protected = (n.get("wal_protected") is not False) and (
            n.get("wal_protected") is True
            or bool(node_idem_key)
            or (plan_wal_protected and bool(ver_plan.get("idempotency_key_prefix")))
        )
        node_info[nid] = {
            "is_idempotent": idempotent and not irreversible,
            "irreversible": irreversible,
            "self_retry_mult": 1 + max_retries,
            "fan_in_mult": fan_in_mult,
            "wal_protected": wal_protected,
            "idempotency_key": node_idem_key,
        }
    return {"nodes": node_info, "wal_replay_global": wal_replay_global, "step_checkpointed": step_checkpointed}


def _build_idempotency_witness(
    offending_node: str,
    eff_mult: int,
    raw_mult: int,
    idem_info: Mapping[str, Any],
    graph: Mapping[str, Any],
) -> Dict[str, Any]:
    nodes_meta = idem_info["nodes"]
    meta = nodes_meta[offending_node]
    causes: List[str] = []
    if meta["self_retry_mult"] > 1:
        causes.append(f"self_retry(attempts={meta['self_retry_mult']})")
    if meta["fan_in_mult"] > 1:
        causes.append(f"fan_in_amplification(factor={meta['fan_in_mult']})")
    if idem_info["wal_replay_global"]:
        causes.append("wal_crash_replay")
    for u in sorted(graph["preds"].get(offending_node, ())):
        if nodes_meta[u]["self_retry_mult"] > 1 and not nodes_meta[u]["wal_protected"]:
            causes.append(f"upstream_unguarded_retry:{u}")
    if not causes:
        causes.append("unguarded_multiplicity_gt_1")
    return {
        "idempotent_safe": False,
        "offending_node": offending_node,
        "execution_trace": _shortest_chain_to_node(offending_node, graph["node_ids"], graph["adj"], graph["preds"]),
        "effective_multiplicity": eff_mult,
        "raw_multiplicity": raw_mult,
        "node_idempotent": meta["is_idempotent"],
        "node_irreversible": meta["irreversible"],
        "wal_protected": meta["wal_protected"],
        "amplification_causes": causes,
        "reason": "NON_IDEMPOTENT_SIDE_EFFECT_UNDER_UNGUARDED_MULTIPLICITY",
    }


def prove_effect_idempotency(
    plan: Union[CompositionPlan, Mapping[str, Any]],
    *,
    registry: Optional[Union[ToolRegistry, Mapping[str, ToolSpec]]] = None,
    backend: str = "auto",
) -> SMTProofCertificate:
    """Prove non-idempotent nodes never exceed multiplicity 1 without WAL checkpointing."""
    ctx = _prepare_context("effect_idempotency", plan, backend=backend, registry=registry)
    if ctx.error_cert is not None:
        return ctx.error_cert

    idem_info = _extract_idempotency_model(ctx)
    node_ids: List[str] = ctx.graph["node_ids"]
    adj, preds = ctx.graph["adj"], ctx.graph["preds"]
    nodes_meta = idem_info["nodes"]
    wal_replay_global = idem_info["wal_replay_global"]
    step_checkpointed = idem_info["step_checkpointed"]
    order, is_acyclic = _kahn_topological_order(node_ids, adj, preds)
    eval_order = order if is_acyclic else sorted(node_ids)
    wal_nodes = sorted(nid for nid, m in nodes_meta.items() if m["wal_protected"])

    if ctx.backend_name == BACKEND_Z3 and ctx.z3_mod is not None:
        z3_mod = ctx.z3_mod
        solver = z3_mod.Solver()
        raw_mult = {nid: z3_mod.Int(f"raw_mult_{idx}") for idx, nid in enumerate(node_ids)}
        eff_mult = {nid: z3_mod.Int(f"eff_mult_{idx}") for idx, nid in enumerate(node_ids)}

        for nid in eval_order:
            meta = nodes_meta[nid]
            base_local = max(meta["self_retry_mult"] * meta["fan_in_mult"], 2 if wal_replay_global else 1)
            factors: List[Any] = [z3_mod.IntVal(base_local)]
            if not step_checkpointed:
                for u in sorted(preds.get(nid, ())):
                    if not nodes_meta[u]["wal_protected"]:
                        factors.append(eff_mult[u] * meta["self_retry_mult"])
            if is_acyclic:
                max_expr = factors[0]
                for f_expr in factors[1:]:
                    max_expr = z3_mod.If(f_expr > max_expr, f_expr, max_expr)
                solver.assert_and_track(raw_mult[nid] == max_expr, f"raw_mult_def_{nid}")
            else:
                for k_idx, f_expr in enumerate(factors):
                    solver.assert_and_track(raw_mult[nid] >= f_expr, f"raw_mult_lb_{nid}_{k_idx}")
                solver.assert_and_track(raw_mult[nid] <= max(16, base_local * 4), f"raw_mult_ub_{nid}")
            if meta["wal_protected"]:
                solver.assert_and_track(eff_mult[nid] == 1, f"wal_dedup_{nid}")
            else:
                solver.assert_and_track(eff_mult[nid] == raw_mult[nid], f"unguarded_exec_{nid}")

        unsafe = [(z3_mod.And(z3_mod.Not(z3_mod.BoolVal(nodes_meta[nid]["is_idempotent"])), eff_mult[nid] > 1), nid) for nid in eval_order]
        solver.assert_and_track(z3_mod.Or([c for c, _ in unsafe]), "exists_non_idempotent_amplification")
        smtlib2 = solver.to_smt2()
        verdict = solver.check()

        if verdict == z3_mod.unsat:
            return ctx.make_cert(
                STATUS_PROVEN,
                {
                    "idempotent_safe": True,
                    "wal_protected_nodes": wal_nodes,
                    "wal_replay_mode": wal_replay_global,
                    "unsat_core": sorted(str(c) for c in solver.unsat_core()),
                },
                smtlib2_text=smtlib2,
            )
        if verdict == z3_mod.sat:
            model = solver.model()
            for clause, nid in unsafe:
                if z3_mod.is_true(model.evaluate(clause, model_completion=True)):
                    witness = _build_idempotency_witness(
                        nid, _z3_eval_int(model, eff_mult[nid]), _z3_eval_int(model, raw_mult[nid]), idem_info, ctx.graph
                    )
                    return ctx.make_cert(STATUS_COUNTEREXAMPLE, witness, smtlib2_text=smtlib2)
        return ctx.make_cert(STATUS_ERROR, {"error": f"Z3_UNEXPECTED_STATUS:{verdict}"}, smtlib2_text=smtlib2)

    raw_m = {
        nid: max(nodes_meta[nid]["self_retry_mult"] * nodes_meta[nid]["fan_in_mult"], 2 if wal_replay_global else 1)
        for nid in eval_order
    }
    eff_m = {nid: (1 if nodes_meta[nid]["wal_protected"] else raw_m[nid]) for nid in eval_order}
    for _ in range(len(node_ids) + 1):
        changed = False
        for nid in eval_order:
            cur = raw_m[nid]
            if not step_checkpointed:
                for u in preds.get(nid, ()):
                    if not nodes_meta[u]["wal_protected"]:
                        cur = max(cur, eff_m[u] * nodes_meta[nid]["self_retry_mult"])
            if cur != raw_m[nid]:
                raw_m[nid] = cur
                eff_m[nid] = 1 if nodes_meta[nid]["wal_protected"] else cur
                changed = True
        if not changed:
            break

    for nid in eval_order:
        if (not nodes_meta[nid]["is_idempotent"]) and eff_m[nid] > 1:
            return ctx.make_cert(STATUS_COUNTEREXAMPLE, _build_idempotency_witness(nid, eff_m[nid], raw_m[nid], idem_info, ctx.graph))
    return ctx.make_cert(STATUS_PROVEN, {"idempotent_safe": True, "wal_protected_nodes": wal_nodes, "wal_replay_mode": wal_replay_global})


# ---------------------------------------------------------------------------
# Unified Formal Verification Bundle Entrypoint
# ---------------------------------------------------------------------------


def verify_plan_formal(
    plan: Union[CompositionPlan, Mapping[str, Any]],
    security_context: SecurityContext,
    *,
    registry: Optional[Union[ToolRegistry, Mapping[str, ToolSpec]]] = None,
    adapters: Union[Sequence[Union[AdapterSpec, Mapping[str, Any]]], Mapping[str, Union[AdapterSpec, Mapping[str, Any]]], None] = (),
    authority: Optional[AttestationAuthority] = None,
    backend: str = "auto",
) -> FormalVerificationBundle:
    """Run all 4 formal SMT/constraint verifiers and return a signed `FormalVerificationBundle`."""
    total_start_ns = time.perf_counter_ns()
    backend_name, _, _ = _resolve_backend(backend)
    _, plan_id, plan_hash, _ = _extract_plan_envelope(plan)

    certs = {
        "acyclic_and_total_order": prove_acyclic_and_total_order(plan, backend=backend_name),
        "no_secret_escalation": prove_no_secret_escalation(
            plan, security_context, registry=registry, adapters=adapters, authority=authority, backend=backend_name
        ),
        "permission_monotonicity": prove_permission_monotonicity(
            plan, security_context, registry=registry, adapters=adapters, backend=backend_name
        ),
        "effect_idempotency": prove_effect_idempotency(plan, registry=registry, backend=backend_name),
    }
    return FormalVerificationBundle(
        all_proven=all(c.status == STATUS_PROVEN for c in certs.values()),
        certificates=certs,
        plan_id=plan_id,
        plan_hash=plan_hash,
        backend=backend_name,
        total_elapsed_ms=(time.perf_counter_ns() - total_start_ns) / 1_000_000.0,
    )


__all__ = [
    "BACKEND_PYTHON",
    "BACKEND_Z3",
    "FORMAL_BUNDLE_SCHEMA",
    "SENSITIVITY_LATTICE",
    "SMT_CERTIFICATE_SCHEMA",
    "STATUS_COUNTEREXAMPLE",
    "STATUS_ERROR",
    "STATUS_PROVEN",
    "FormalVerificationBundle",
    "SMTProofCertificate",
    "is_z3_available",
    "prove_acyclic_and_total_order",
    "prove_effect_idempotency",
    "prove_no_secret_escalation",
    "prove_permission_monotonicity",
    "verify_bundle_digest",
    "verify_certificate_digest",
    "verify_plan_formal",
]
