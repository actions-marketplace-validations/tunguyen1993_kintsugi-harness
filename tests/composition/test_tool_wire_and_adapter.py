"""Comprehensive tests for Working Tool #3 `ToolWire` and `AdapterSynthesizer`."""

from __future__ import annotations

import itertools
import json
import stat
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

try:
    from fixture_attestation import make_fixture_authority, sign_fixture_adapter, sign_fixture_spec
except ImportError:  # pragma: no cover
    from tests.fixture_attestation import make_fixture_authority, sign_fixture_adapter, sign_fixture_spec

from kintsugi.capability.contracts_v2 import (
    AbstainError,
    AdapterSpec,
    PortContract,
)
from kintsugi.capability.schemas import (
    ExecutionStatus,
    SecurityContext,
    SecurityProfile,
    ToolSpec,
    TrustStatus,
    sha256_digest,
)
from kintsugi.composition.adapter_synthesizer import (
    AdapterCatalog,
    AdapterProposalStatus,
    AdapterSynthesizer,
)
from kintsugi.runtime.secure_runner import SecureRunner, compute_callable_sha256
from kintsugi.tools.log_forge import normalize_log_records_python
from kintsugi.tools.tool_wire import (
    DeclassificationGrant,
    LossyConversionError,
    ToolWire,
    ToolWireContractError,
    ToolWireEncodingError,
    ToolWireFormatError,
    ToolWireSensitivityError,
    WireDiagnostic,
    WireFormat,
)

HASH_1 = "sha256:" + "1" * 64
HASH_2 = "sha256:" + "2" * 64


def _make_verified_catalog_adapter(
    adapter_id: str,
    src_port: PortContract,
    dst_port: PortContract,
    *,
    mapping: dict,
    unit_conversion: dict | None = None,
    lossless: bool = True,
    authority=None,
) -> AdapterSpec:
    draft = AdapterSpec(
        adapter_id=adapter_id,
        version="1.0.0",
        source_port=src_port,
        target_port=dst_port,
        mapping=mapping,
        unit_conversion=unit_conversion,
        lossless=lossless,
        verification_corpus_hash=HASH_1,
        trust_status=TrustStatus.DISCOVERED,
    )
    attestation = {
        "verifier_id": "ci-verifier",
        "source": "ci_attestation",
        "adapter_id": adapter_id,
        "adapter_hash": draft.adapter_hash,
        "verification_digest": sha256_digest(
            {"adapter_id": adapter_id, "adapter_hash": draft.adapter_hash, "corpus": HASH_1}
        ),
    }
    spec = AdapterSpec(
        adapter_id=adapter_id,
        version="1.0.0",
        source_port=src_port,
        target_port=dst_port,
        mapping=mapping,
        unit_conversion=unit_conversion,
        lossless=lossless,
        verification_corpus_hash=HASH_1,
        adapter_hash=draft.adapter_hash,
        trust_status=TrustStatus.VERIFIED,
        verification_attestation=attestation,
    )
    return sign_fixture_adapter(authority, spec) if authority is not None else spec


class TestToolWire(unittest.TestCase):
    def setUp(self) -> None:
        self.wire = ToolWire()

    def test_cross_format_roundtrip_and_large_integer_precision(self) -> None:
        p_typed = PortContract(
            schema_ref="typed_event_stream",
            semantic_type="telemetry_event",
            encoding="utf-8",
            unit="none",
            cardinality="many",
            ordering="ordered",
            precision="exact",
        )
        p_jsonl = PortContract(
            schema_ref="jsonl",
            semantic_type="telemetry_event",
            encoding="utf-8",
            unit="none",
            cardinality="many",
            ordering="ordered",
            precision="exact",
        )
        p_csv = PortContract(
            schema_ref="csv",
            semantic_type="telemetry_event",
            encoding="utf-8",
            unit="none",
            cardinality="many",
            ordering="ordered",
            precision="exact",
        )

        # 2^53 + 1, 2^63 - 1, 2^64 - 1, and >128-bit integer MUST never lose precision
        big_53 = (1 << 53) + 1
        big_63 = (1 << 63) - 1
        big_64 = (1 << 64) - 1
        huge_int = 1234567890123456789012345678901234567890
        events = [
            {"seq": 0, "big_id": big_53, "msg": "café ☕"},
            {"seq": 1, "big_id": big_63, "msg": "東京"},
            {"seq": 2, "big_id": big_64, "msg": "ascii"},
            {"seq": 3, "big_id": huge_int, "msg": "arbitrary"},
        ]

        res_jsonl = self.wire.convert(events, source_port=p_typed, target_port=p_jsonl)
        self.assertEqual(res_jsonl.record_count, 4)
        self.assertTrue(res_jsonl.lossless)

        res_csv = self.wire.convert(res_jsonl.output, source_port=p_jsonl, target_port=p_csv)
        res_back = self.wire.convert(
            res_csv.output,
            source_port=p_csv,
            target_port=p_typed,
            field_types={"seq": "int", "big_id": "int"},
        )
        self.assertEqual(len(res_back.output), 4)
        for idx, expected in enumerate(events):
            got = res_back.output[idx]
            self.assertIs(type(got["big_id"]), int)
            self.assertEqual(got["big_id"], expected["big_id"])
            self.assertEqual(got["seq"], expected["seq"])
            self.assertEqual(got["msg"], expected["msg"])

        # Bounded int64 target rejects uint64_max (2^64 - 1) overflow instead of wrapping
        p_int64 = PortContract(
            schema_ref="typed_event_stream",
            semantic_type="telemetry_event",
            encoding="utf-8",
            unit="none",
            cardinality="many",
            ordering="ordered",
            precision="int64",
        )
        res_i64_ok = self.wire.convert(events[:2], source_port=p_typed, target_port=p_int64)
        self.assertEqual(res_i64_ok.output[1]["big_id"], big_63)
        with self.assertRaises(LossyConversionError):
            self.wire.convert([events[2]], source_port=p_typed, target_port=p_int64)

        # ToolSpec build check
        spec = ToolWire.build_tool_spec()
        self.assertEqual(spec.tool_id, "kintsugi.tool_wire")
        self.assertIn("wire.convert", spec.capabilities)

        # Compatibility with LogForge NormalizedLogEvent objects
        log_events = normalize_log_records_python(b'{"ts":"2026-01-01T00:00:00Z","level":"INFO","message":"ok"}\n')
        res_lf = self.wire.convert(log_events, source_port=p_typed, target_port=p_jsonl)
        self.assertEqual(res_lf.record_count, 1)
        self.assertIn('"level":"INFO"', res_lf.output)

    def test_ns_vs_ms_unit_scaling_exact_and_lossy_rejection(self) -> None:
        p_ns = PortContract(
            schema_ref="typed_event_stream",
            semantic_type="latency",
            unit="ns",
            cardinality="many",
            ordering="ordered",
            precision="int64",
        )
        p_ms_int = PortContract(
            schema_ref="typed_event_stream",
            semantic_type="latency",
            unit="ms",
            cardinality="many",
            ordering="ordered",
            precision="int64",
        )
        p_ms_dec = PortContract(
            schema_ref="typed_event_stream",
            semantic_type="latency",
            unit="ms",
            cardinality="many",
            ordering="ordered",
            precision="decimal128",
        )
        p_s_int = PortContract(
            schema_ref="typed_event_stream",
            semantic_type="latency",
            unit="s",
            cardinality="many",
            ordering="ordered",
            precision="int64",
        )

        # 1. Missing unit_conversion MUST fail (ns vs ms never confused)
        with self.assertRaises(LossyConversionError):
            self.wire.convert([{"dur": 1_000_000}], source_port=p_ns, target_port=p_ms_int, unit_fields=["dur"])

        # 2. Wrong conversion factor (confusing us->ms 0.001 with ns->ms 1e-6) MUST fail
        with self.assertRaises(ToolWireContractError):
            self.wire.convert(
                [{"dur": 1_000_000}],
                source_port=p_ns,
                target_port=p_ms_int,
                unit_fields=["dur"],
                unit_conversion={"from_unit": "ns", "to_unit": "ms", "factor": "0.001"},
            )

        # 3. Exact divisible ns -> ms (including negative delta) succeeds with exact int
        res_div = self.wire.convert(
            [{"dur": 1_700_000_000_000_000_000}, {"dur": -2_000_000}],
            source_port=p_ns,
            target_port=p_ms_int,
            unit_fields=["dur"],
            unit_conversion={"from_unit": "ns", "to_unit": "ms", "factor": "0.000001"},
        )
        self.assertTrue(res_div.lossless)
        self.assertEqual(res_div.output[0]["dur"], 1_700_000_000_000)
        self.assertIs(type(res_div.output[0]["dur"]), int)
        self.assertEqual(res_div.output[1]["dur"], -2)

        # 4. Non-divisible ns -> int ms MUST be rejected when lossless=True (default)
        with self.assertRaises(LossyConversionError):
            self.wire.convert(
                [{"dur": 1_700_000_000_123_456_789}],
                source_port=p_ns,
                target_port=p_ms_int,
                unit_fields=["dur"],
                unit_conversion={"from_unit": "ns", "to_unit": "ms", "scale": {"numerator": 1, "denominator": 1_000_000}},
            )

        # 5. Explicit lossy opt-in (allow_lossy=True, lossless=False) truncates AND flags lossless=False
        res_lossy = self.wire.convert(
            [{"dur": 1_700_000_000_123_456_789}],
            source_port=p_ns,
            target_port=p_ms_int,
            unit_fields=["dur"],
            unit_conversion={"from_unit": "ns", "to_unit": "ms", "scale": {"numerator": 1, "denominator": 1_000_000}},
            allow_lossy=True,
            lossless=False,
        )
        self.assertFalse(res_lossy.lossless)
        self.assertEqual(res_lossy.output[0]["dur"], 1_700_000_000_123)

        # 6. Exact Decimal / structured conversion preserves ALL sub-millisecond nanoseconds
        res_dec = self.wire.convert(
            [{"dur": 1_700_000_000_123_456_789}],
            source_port=p_ns,
            target_port=p_ms_dec,
            unit_fields=["dur"],
            unit_conversion={"from_unit": "ns", "to_unit": "ms", "scale": {"numerator": 1, "denominator": 1_000_000}},
            unit_output_mode="decimal",
        )
        self.assertTrue(res_dec.lossless)
        self.assertEqual(res_dec.output[0]["dur"], Decimal("1700000000123.456789"))

        res_struct = self.wire.convert(
            [{"dur": 1_700_000_000_123_456_789}],
            source_port=p_ns,
            target_port=p_ms_dec,
            unit_fields=["dur"],
            unit_conversion={"from_unit": "ns", "to_unit": "ms", "scale": {"numerator": 1, "denominator": 1_000_000}},
            unit_output_mode="structured",
        )
        self.assertEqual(
            res_struct.output[0]["dur"],
            {"value": 1_700_000_000_123, "remainder": 456_789, "unit": "ms", "remainder_unit": "ns"},
        )

        # 7. Exact integer upscaling s -> ns
        res_up = self.wire.convert(
            [{"dur": 1_700_000_000}],
            source_port=p_s_int,
            target_port=p_ns,
            unit_fields=["dur"],
            unit_conversion={"from_unit": "s", "to_unit": "ns", "factor": "1000000000"},
        )
        self.assertEqual(res_up.output[0]["dur"], 1_700_000_000_000_000_000)

        # 8. Raw IEEE-754 float rejected on exact unit conversion
        with self.assertRaises(LossyConversionError):
            self.wire.convert(
                [{"dur": 1.5}],
                source_port=p_s_int,
                target_port=p_ns,
                unit_fields=["dur"],
                unit_conversion={"from_unit": "s", "to_unit": "ns", "factor": "1000000000"},
            )

        # 9. Exact us <-> ms <-> s chain and float64 ceiling overflow check (2^53 + 1)
        p_us = PortContract(schema_ref="typed_event_stream", semantic_type="latency", unit="us", cardinality="many", ordering="ordered")
        res_us_ms = self.wire.convert(
            [{"dur": 250_000}],
            source_port=p_us,
            target_port=p_ms_int,
            unit_fields=["dur"],
            unit_conversion={"from_unit": "us", "to_unit": "ms", "factor": "0.001"},
        )
        self.assertEqual(res_us_ms.output[0]["dur"], 250)

        p_f64 = PortContract(schema_ref="typed_event_stream", semantic_type="latency", unit="ns", cardinality="many", ordering="ordered", precision="float64")
        with self.assertRaises(LossyConversionError):
            self.wire.convert([{"dur": (1 << 53) + 1}], source_port=p_ns, target_port=p_f64)

    def test_utf8_validation_and_malformed_jsonl_csv_rejection(self) -> None:
        p_bytes = PortContract(
            schema_ref="bytes", semantic_type="raw_bytes", encoding="utf-8", cardinality="stream", ordering="ordered"
        )
        p_jsonl = PortContract(
            schema_ref="jsonl", semantic_type="jsonl_events", encoding="utf-8", cardinality="stream", ordering="ordered"
        )
        p_csv = PortContract(
            schema_ref="csv", semantic_type="csv_records", encoding="utf-8", cardinality="stream", ordering="ordered"
        )
        p_typed = PortContract(
            schema_ref="typed_event_stream",
            semantic_type="typed_events",
            encoding="utf-8",
            cardinality="stream",
            ordering="ordered",
        )

        # Multi-byte UTF-8 character split mid-codepoint across byte chunks succeeds
        payload = '{"msg":"café ☕"}\n'.encode("utf-8")
        split_at = payload.index(b"\xc3") + 1  # right inside 2-byte 'é'
        res_split = self.wire.convert(
            [payload[:split_at], payload[split_at:]],
            source_port=p_bytes,
            target_port=p_typed,
        )
        self.assertEqual(res_split.output, [{"msg": "café ☕"}])

        # Invalid UTF-8 bytes rejected
        with self.assertRaises(ToolWireEncodingError):
            self.wire.convert(b'{"msg":"\xff\xfe"}\n', source_port=p_bytes, target_port=p_jsonl)

        # Truncated UTF-8 at EOF rejected
        with self.assertRaises(ToolWireEncodingError):
            self.wire.convert([b'{"msg":"', b"\xe2\x98"], source_port=p_bytes, target_port=p_jsonl)

        # Lone surrogate / Trojan bidi rejected
        with self.assertRaises(ToolWireEncodingError):
            self.wire.convert('{"msg":"bad\u202etext"}\n', source_port=p_jsonl, target_port=p_typed)

        # Malformed JSONL inputs rejected cleanly (never silently dropped)
        for bad_jsonl in (
            '{"a": 1}\n{not_json\n',
            '{"a": 1}\n[1, 2, 3]\n',
            '{"a": 1}\n\n{"a": 2}\n',
            '{"a": NaN}\n',
        ):
            with self.assertRaises(ToolWireFormatError):
                self.wire.convert(bad_jsonl, source_port=p_jsonl, target_port=p_typed)

        # Malformed CSV inputs rejected cleanly
        for bad_csv in (
            "",
            "a,\n1,2\n",
            "a,a\n1,2\n",
            "a,b\n1,2,3\n",
            "a,b\n1\n",
            'a,b\n1,"unclosed\n',
            'a,b\n1,"x"junk\n',
        ):
            with self.assertRaises(ToolWireFormatError):
                self.wire.convert(bad_csv, source_port=p_csv, target_port=p_typed)

        # Non-strict mode captures every rejected record in diagnostics (never silently drops)
        diags: list[WireDiagnostic] = []
        res_diag = self.wire.convert(
            '{"seq":0}\n{corrupt\n{"seq":2}\n',
            source_port=p_jsonl,
            target_port=p_typed,
            strict=False,
            diagnostics=diags,
        )
        self.assertEqual(len(res_diag.output), 2)
        self.assertEqual(res_diag.rejected_count, 1)
        self.assertEqual(len(diags), 1)
        self.assertEqual(diags[0].line_number, 2)
        self.assertEqual(diags[0].code, "MALFORMED_JSONL")

    def test_ordering_preservation_and_sensitivity_declassification(self) -> None:
        p_ordered = PortContract(
            schema_ref="typed_event_stream",
            semantic_type="audit_log",
            cardinality="many",
            ordering="ordered",
            sensitivity="secret",
        )
        p_unordered = PortContract(
            schema_ref="typed_event_stream",
            semantic_type="audit_log",
            cardinality="many",
            ordering="unordered",
            sensitivity="secret",
        )
        p_public_ordered = PortContract(
            schema_ref="jsonl",
            semantic_type="audit_log",
            cardinality="many",
            ordering="ordered",
            sensitivity="public",
        )

        # unordered -> ordered blocked without sort_key
        with self.assertRaises(ToolWireContractError):
            self.wire.convert([{"seq": 0}], source_port=p_unordered, target_port=p_ordered)

        # out-of-order sequence_field rejected
        p_internal = PortContract(
            schema_ref="typed_event_stream",
            semantic_type="audit_log",
            cardinality="many",
            ordering="ordered",
            sensitivity="internal",
        )
        with self.assertRaises(ToolWireContractError):
            self.wire.convert(
                [{"seq": 5}, {"seq": 3}],
                source_port=p_ordered,
                target_port=p_internal,
                sequence_field="seq",
                declassification_grant=DeclassificationGrant(
                    grant_id="g-ord",
                    source_sensitivity="secret",
                    target_sensitivity="internal",
                    authorized_by="security-officer",
                    transform="redact",
                ),
                lossless=False,
            )

        # secret -> public blocked without DeclassificationGrant
        records = [{"seq": 0, "api_token": "tok_secret_value_123", "msg": "ok"}]
        with self.assertRaises(ToolWireSensitivityError):
            self.wire.convert(records, source_port=p_ordered, target_port=p_public_ordered)

        # Self-asserted grant rejected
        with self.assertRaises(ToolWireSensitivityError):
            DeclassificationGrant(
                grant_id="g-self",
                source_sensitivity="secret",
                target_sensitivity="public",
                authorized_by="self",
                transform="redact",
            )

        # Grant with lossless=True rejected
        grant = DeclassificationGrant(
            grant_id="g-pub-01",
            source_sensitivity="secret",
            target_sensitivity="public",
            authorized_by="privacy-gate",
            transform="redact",
            redacted_fields=("api_token",),
        )
        with self.assertRaises(ToolWireSensitivityError):
            self.wire.convert(
                records,
                source_port=p_ordered,
                target_port=p_public_ordered,
                declassification_grant=grant,
                lossless=True,
            )

        # Authorized grant with lossless=False scrubs raw secret and succeeds
        res_ok = self.wire.convert(
            records,
            source_port=p_ordered,
            target_port=p_public_ordered,
            declassification_grant=grant,
            lossless=False,
        )
        self.assertFalse(res_ok.lossless)
        self.assertNotIn("tok_secret_value_123", res_ok.output)
        self.assertIn("[REDACTED]", res_ok.output)

    def test_streaming_generator_o1_ram_and_provenance(self) -> None:
        p_stream = PortContract(
            schema_ref="typed_event_stream",
            semantic_type="telemetry",
            cardinality="stream",
            ordering="ordered",
            streaming=True,
        )
        p_csv_stream = PortContract(
            schema_ref="csv",
            semantic_type="telemetry",
            cardinality="stream",
            ordering="ordered",
            streaming=True,
        )
        p_jsonl_stream = PortContract(
            schema_ref="jsonl",
            semantic_type="telemetry",
            cardinality="stream",
            ordering="ordered",
            streaming=True,
        )

        pulled = {"count": 0}

        def infinite_events():
            i = 0
            while True:
                pulled["count"] += 1
                yield {"seq": i, "val": i * 10}
                i += 1

        # Take only first 5 JSONL items from an infinite generator -> MUST pull at most 5 items!
        ws_jsonl = self.wire.stream(
            infinite_events(),
            source_port=p_stream,
            target_port=p_jsonl_stream,
            include_provenance=True,
        )
        first_five = list(itertools.islice(ws_jsonl, 5))
        self.assertEqual(len(first_five), 5)
        self.assertEqual(pulled["count"], 5)
        self.assertEqual(ws_jsonl.record_count, 5)
        self.assertTrue(ws_jsonl.source_digest.startswith("sha256:"))
        self.assertTrue(ws_jsonl.transform_digest.startswith("sha256:"))
        parsed_last = json.loads(first_five[-1])
        self.assertEqual(parsed_last["seq"], 4)
        self.assertTrue(parsed_last["source_digest"].startswith("sha256:"))
        self.assertTrue(parsed_last["transform_digest"].startswith("sha256:"))

        # CSV stream over infinite generator pulls only 3 source records for header + 3 rows
        pulled["count"] = 0
        ws_csv = self.wire.stream(infinite_events(), source_port=p_stream, target_port=p_csv_stream)
        csv_lines = list(itertools.islice(ws_csv, 4))  # 1 header + 3 rows
        self.assertEqual(len(csv_lines), 4)
        self.assertEqual(csv_lines[0], "seq,val\n")
        self.assertEqual(csv_lines[3], "2,20\n")
        self.assertEqual(pulled["count"], 3)

        # stream_records preserves upstream source_digest across hops
        recs = list(
            self.wire.stream_records(
                first_five,
                source_port=p_jsonl_stream,
                target_port=p_stream,
                preserve_upstream_provenance=True,
            )
        )
        self.assertEqual(len(recs), 5)
        self.assertEqual(recs[-1].source_digest, parsed_last["source_digest"])
        self.assertNotEqual(recs[-1].transform_digest, parsed_last["transform_digest"])


class TestAdapterSynthesizer(unittest.TestCase):
    def test_tier1_catalog_selection_and_tamper_rejection(self) -> None:
        auth = make_fixture_authority()
        with tempfile.TemporaryDirectory() as tmp:
            cat_path = Path(tmp) / "adapter_catalog.json"
            catalog = AdapterCatalog(cat_path, authority=auth)

            src = PortContract(
                schema_ref="typed_event_stream",
                semantic_type="duration",
                unit="ns",
                cardinality="many",
                ordering="ordered",
                precision="decimal128",
            )
            dst = PortContract(
                schema_ref="typed_event_stream",
                semantic_type="duration",
                unit="ms",
                cardinality="many",
                ordering="ordered",
                precision="decimal128",
            )
            verified_spec = _make_verified_catalog_adapter(
                "adapter.catalog.ns_ms",
                src,
                dst,
                mapping={"fields": {"dur_ns": "dur_ms"}, "unit_fields": {"dur_ns": "dur_ms"}, "unit_mode": "decimal"},
                unit_conversion={
                    "from_unit": "ns",
                    "to_unit": "ms",
                    "factor": "0.000001",
                    "scale": {"numerator": 1, "denominator": 1_000_000},
                },
                lossless=True,
                authority=auth,
            )
            catalog.register(verified_spec)
            catalog.save()
            self.assertEqual(stat.S_IMODE(cat_path.stat().st_mode), 0o600)

            reloaded_catalog = AdapterCatalog(cat_path, authority=auth)
            synth = AdapterSynthesizer(catalog=reloaded_catalog, authority=auth)
            res = synth.propose(src, dst)
            self.assertEqual(res.status, AdapterProposalStatus.VERIFIED_CATALOG)
            self.assertEqual(res.tier, 1)
            self.assertEqual(res.llm_calls, 0)
            self.assertIsNotNone(res.callable_adapter)
            out = res.callable_adapter([{"dur_ns": 1_700_000_000_123_456_789}])
            self.assertEqual(out[0]["dur_ms"], Decimal("1700000000123.456789"))

            # Unverified DISCOVERED spec rejected by catalog
            unverified = AdapterSpec(
                adapter_id="adapter.unverified",
                version="1.0.0",
                source_port=src,
                target_port=dst,
                mapping={"fields": {"dur_ns": "dur_ms"}},
                unit_conversion={"from_unit": "ns", "to_unit": "ms", "factor": "0.000001"},
                trust_status=TrustStatus.DISCOVERED,
            )
            with self.assertRaises(AbstainError):
                catalog.register(unverified)

    def test_tier2_synthesis_format_units_projection_and_oracle(self) -> None:
        auth = make_fixture_authority()
        auth.register_verifier("kintsugi.composition_oracle", b"kintsugi-round4-oracle-verifier-key-32b")
        synth = AdapterSynthesizer(authority=auth)

        # 1. bytes -> jsonl synthesis + oracle verification
        p_bytes = PortContract(schema_ref="bytes", semantic_type="raw_bytes", encoding="utf-8", cardinality="many")
        p_jsonl = PortContract(schema_ref="jsonl", semantic_type="jsonl_events", encoding="utf-8", cardinality="many")
        res_bj = synth.propose(p_bytes, p_jsonl)
        self.assertEqual(res_bj.status, AdapterProposalStatus.SYNTHESIZED_VERIFIED)
        self.assertEqual(res_bj.tier, 2)
        self.assertEqual(res_bj.llm_calls, 0)
        self.assertIsNotNone(res_bj.oracle_report)
        self.assertTrue(res_bj.oracle_report.passed)
        self.assertGreaterEqual(res_bj.oracle_report.positive_passed, 2)
        self.assertGreaterEqual(res_bj.oracle_report.negative_passed, 2)
        self.assertEqual(res_bj.adapter_spec.trust_status, TrustStatus.VERIFIED)
        self.assertEqual(res_bj.callable_adapter(b'{"id":9007199254740993}\n'), '{"id":9007199254740993}\n')

        # 2. ns -> ms lossless scaling with decimal representation + SecureRunner callable integration
        p_ns = PortContract(
            schema_ref="typed_event_stream",
            semantic_type="request_latency",
            unit="ns",
            cardinality="many",
            ordering="ordered",
            precision="int64",
        )
        p_ms_dec = PortContract(
            schema_ref="typed_event_stream",
            semantic_type="request_latency",
            unit="ms",
            cardinality="many",
            ordering="ordered",
            precision="decimal128",
        )
        res_unit = synth.propose(
            p_ns,
            p_ms_dec,
            source_schema={"properties": {"dur_ns": {"type": "integer"}}, "required": ["dur_ns"]},
            target_schema={"properties": {"dur_ms": {"type": "decimal"}}, "required": ["dur_ms"]},
        )
        self.assertEqual(res_unit.status, AdapterProposalStatus.SYNTHESIZED_VERIFIED)
        self.assertTrue(res_unit.adapter_spec.lossless)
        self.assertTrue(res_unit.oracle_report.passed)
        self.assertEqual(
            res_unit.callable_adapter([{"dur_ns": 1_700_000_000_123_456_789}]),
            [{"dur_ms": Decimal("1700000000123.456789")}],
        )

        # Register JSON-safe synthesized callable (decimal_string) inside SecureRunner and execute with oracle
        res_unit_str = synth.propose(
            p_ns,
            p_ms_dec,
            source_schema={"properties": {"dur_ns": {"type": "integer"}}, "required": ["dur_ns"]},
            target_schema={"properties": {"dur_ms": {"type": "string"}}, "required": ["dur_ms"]},
            unit_representation="decimal_string",
        )
        self.assertEqual(res_unit_str.status, AdapterProposalStatus.SYNTHESIZED_VERIFIED)
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            ctx = SecurityContext(workspace_root=str(ws), profile=SecurityProfile.LOCAL_RESEARCH)
            runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=auth)
            reg_hash = runner.register_trusted_host_callable(
                "adapter.synth_ns_ms", lambda args: res_unit_str.callable_adapter(args["records"])
            )
            self.assertEqual(compute_callable_sha256(res_unit.callable_adapter), res_unit.callable_hash)
            tool = sign_fixture_spec(
                auth,
                ToolSpec(
                    tool_id="adapter.synth_ns_ms",
                    version="1.0.0",
                    source="builtin",
                    binary_hash=reg_hash,
                    capabilities=["adapter.ns_ms"],
                    trust_status=TrustStatus.VERIFIED,
                    verification_attestation={
                        "verifier_id": "ci-verifier",
                        "source": "ci_attestation",
                        "tool_id": "adapter.synth_ns_ms",
                        "binary_hash": reg_hash,
                        "verification_digest": HASH_2,
                    },
                ),
            )
            rec = runner.run(
                tool,
                {"records": [{"dur_ns": 2_500_000}]},
                ctx,
                oracle=lambda r: r.get("output") == [{"dur_ms": "2.5"}],
            )
            self.assertEqual(rec.status, ExecutionStatus.PASS)

        # 3. ns -> ms divisible-only integer adapter rejects non-divisible input
        p_ms_int = PortContract(
            schema_ref="typed_event_stream",
            semantic_type="request_latency",
            unit="ms",
            cardinality="many",
            ordering="ordered",
            precision="int64",
        )
        res_div = synth.propose(
            p_ns,
            p_ms_int,
            source_schema={"properties": {"dur_ns": {"type": "integer"}}, "required": ["dur_ns"]},
            target_schema={"properties": {"dur_ms": {"type": "integer"}}, "required": ["dur_ms"]},
            require_divisible=True,
        )
        self.assertEqual(res_div.status, AdapterProposalStatus.SYNTHESIZED_VERIFIED)
        self.assertEqual(res_div.callable_adapter([{"dur_ns": 3_000_000}]), [{"dur_ms": 3}])
        with self.assertRaises(LossyConversionError):
            res_div.callable_adapter([{"dur_ns": 3_000_001}])

        # 4. field_rename + nested projection (does not mutate input dict)
        p_one_in = PortContract(schema_ref="json:object", semantic_type="trace_span", unit="ns", cardinality="one")
        p_one_out = PortContract(
            schema_ref="json:object",
            semantic_type="trace_span",
            unit="ms",
            cardinality="one",
            precision="decimal128",
        )
        res_proj = synth.propose(
            p_one_in,
            p_one_out,
            field_map={"meta.trace_id": "trace_id", "metrics.latency_ns": "latency_ms"},
            unit_fields={"metrics.latency_ns": "latency_ms"},
        )
        self.assertEqual(res_proj.status, AdapterProposalStatus.SYNTHESIZED_VERIFIED)
        sample_in = {"meta": {"trace_id": "tr-99"}, "metrics": {"latency_ns": 4_500_000}}
        projected = res_proj.callable_adapter(sample_in)
        self.assertEqual(projected, {"trace_id": "tr-99", "latency_ms": Decimal("4.5")})
        self.assertIn("meta", sample_in)

    def test_tier3_abstention_on_ambiguous_unknown_lossy_and_secret_leak(self) -> None:
        auth = make_fixture_authority()
        auth.register_verifier("kintsugi.composition_oracle", b"kintsugi-round4-oracle-verifier-key-32b")
        synth = AdapterSynthesizer(authority=auth)

        # 1. Ambiguous semantic type -> ABSTAIN + AbstainError
        p_amb = PortContract(schema_ref="json:obj", semantic_type="ambiguous", unit="none")
        p_ok = PortContract(schema_ref="json:obj", semantic_type="latency", unit="none")
        res_amb = synth.propose(p_amb, p_ok)
        self.assertTrue(res_amb.abstained)
        self.assertEqual(res_amb.status, AdapterProposalStatus.ABSTAIN)
        self.assertEqual(res_amb.tier, 3)
        with self.assertRaises(AbstainError):
            synth.synthesize(p_amb, p_ok, raise_on_abstain=True)

        # 2. Incompatible unrelated semantic types -> ABSTAIN
        p_user = PortContract(schema_ref="json:obj", semantic_type="user_account_id", unit="none")
        self.assertTrue(synth.propose(p_user, p_ok).abstained)

        # 3. Unknown target field -> ABSTAIN
        p_evt = PortContract(schema_ref="typed_event_stream", semantic_type="event", unit="none")
        res_unk = synth.propose(
            p_evt,
            p_evt,
            source_schema={"properties": {"ts": {"type": "integer"}}, "required": ["ts"]},
            target_schema={"properties": {"ts": {"type": "integer"}, "region_code": {"type": "string"}}, "required": ["ts", "region_code"]},
        )
        self.assertTrue(res_unk.abstained)
        self.assertIn("UNKNOWN_OR_UNMAPPED_TARGET_FIELD", res_unk.abstain_reason or "")

        # 4. Unprovable lossless ns -> int64 ms without decimal/structured/divisible opt-in -> ABSTAIN
        p_ns_int = PortContract(schema_ref="typed_event_stream", semantic_type="latency", unit="ns", precision="int64")
        p_ms_int = PortContract(schema_ref="typed_event_stream", semantic_type="latency", unit="ms", precision="int64")
        res_unprovable = synth.propose(
            p_ns_int,
            p_ms_int,
            source_schema={"properties": {"dur_ns": {"type": "integer"}}, "required": ["dur_ns"]},
            target_schema={"properties": {"dur_ms": {"type": "integer"}}, "required": ["dur_ms"]},
        )
        self.assertTrue(res_unprovable.abstained)
        self.assertIn("UNPROVABLE_LOSSLESS_UNIT_CONVERSION", res_unprovable.abstain_reason or "")

        # 5. Sensitivity lattice violation secret -> public without grant -> ABSTAIN
        p_sec = PortContract(schema_ref="typed_event_stream", semantic_type="log", sensitivity="secret")
        p_pub = PortContract(schema_ref="jsonl", semantic_type="log", sensitivity="public")
        res_sec = synth.propose(p_sec, p_pub)
        self.assertTrue(res_sec.abstained)
        self.assertIn("SENSITIVITY_LATTICE", res_sec.abstain_reason or "")

        # With authorized DeclassificationGrant -> Tier 2 synthesizes verified redacting adapter
        grant = DeclassificationGrant(
            grant_id="grant-auth-1",
            source_sensitivity="secret",
            target_sensitivity="public",
            authorized_by="security-review-board",
            transform="redact",
            redacted_fields=("api_secret",),
        )
        res_declass = synth.propose(
            p_sec,
            p_pub,
            source_schema={"properties": {"api_secret": {"type": "string"}, "event": {"type": "string"}}, "required": ["api_secret", "event"]},
            target_schema={"properties": {"api_secret": {"type": "string"}, "event": {"type": "string"}}, "required": ["api_secret", "event"]},
            declassification_grant=grant,
        )
        self.assertEqual(res_declass.status, AdapterProposalStatus.SYNTHESIZED_VERIFIED)
        self.assertFalse(res_declass.adapter_spec.lossless)
        redacted_jsonl = res_declass.callable_adapter([{"api_secret": "RAW_SECRET_999", "event": "login"}])
        self.assertNotIn("RAW_SECRET_999", redacted_jsonl)

        # 6. Trust label escalation untrusted -> trusted -> ABSTAIN
        p_untrust = PortContract(schema_ref="json:obj", semantic_type="event", trust_label="untrusted")
        p_trust = PortContract(schema_ref="json:obj", semantic_type="event", trust_label="trusted")
        self.assertTrue(synth.propose(p_untrust, p_trust).abstained)

        # 7. Precision loss float64->float32, decimal128->float64, int64->int32 -> ABSTAIN
        for sp, dp in (("float64", "float32"), ("decimal128", "float64"), ("int64", "int32")):
            self.assertTrue(
                synth.propose(
                    PortContract(schema_ref="json:obj", semantic_type="metric", unit="none", precision=sp),
                    PortContract(schema_ref="json:obj", semantic_type="metric", unit="none", precision=dp),
                ).abstained
            )

        # 8. Ambiguous unit fields (multiple *_ns candidates) and conflicting field_map -> ABSTAIN
        self.assertTrue(
            synth.propose(
                p_ns_int,
                p_ms_int,
                source_schema={"properties": {"created_ns": {"type": "integer"}, "dur_ns": {"type": "integer"}}},
                target_schema={"properties": {"created_ms": {"type": "decimal"}, "dur_ms": {"type": "decimal"}}},
                unit_representation="decimal",
            ).abstained
        )
        self.assertTrue(
            synth.propose(p_evt, p_evt, field_map={"a": "same", "b": "same"}).abstained
        )

        # 9. Unbounded unordered -> ordered stream -> ABSTAIN
        p_unord_stream = PortContract(schema_ref="typed_event_stream", semantic_type="event", cardinality="stream", ordering="unordered")
        p_ord_stream = PortContract(schema_ref="typed_event_stream", semantic_type="event", cardinality="stream", ordering="ordered")
        self.assertTrue(synth.propose(p_unord_stream, p_ord_stream).abstained)

    def test_tier2_additional_formats_structured_units_and_schema_parity(self) -> None:
        auth = make_fixture_authority()
        auth.register_verifier("kintsugi.composition_oracle", b"kintsugi-round4-oracle-verifier-key-32b")
        synth = AdapterSynthesizer(authority=auth)

        # jsonl -> typed_event_stream -> csv synthesis + oracle
        p_jsonl = PortContract(schema_ref="jsonl", semantic_type="jsonl_events", cardinality="many", ordering="ordered")
        p_typed = PortContract(schema_ref="typed_event_stream", semantic_type="typed_events", cardinality="many", ordering="ordered")
        p_csv = PortContract(schema_ref="csv", semantic_type="csv_records", cardinality="many", ordering="ordered")

        res_jt = synth.propose(p_jsonl, p_typed)
        self.assertEqual(res_jt.status, AdapterProposalStatus.SYNTHESIZED_VERIFIED)
        self.assertEqual(res_jt.callable_adapter('{"seq":9007199254740993}\n'), [{"seq": 9007199254740993}])

        res_tc = synth.propose(
            p_typed,
            p_csv,
            source_schema={"properties": {"seq": {"type": "integer"}, "tag": {"type": "string"}}, "required": ["seq", "tag"]},
            target_schema={"properties": {"seq": {"type": "integer"}, "tag": {"type": "string"}}, "required": ["seq", "tag"]},
        )
        self.assertEqual(res_tc.status, AdapterProposalStatus.SYNTHESIZED_VERIFIED)
        self.assertEqual(res_tc.callable_adapter([{"seq": 7, "tag": "ok"}]), "seq,tag\n7,ok\n")

        # Structured lossless ns -> ms representation
        p_ns = PortContract(schema_ref="typed_event_stream", semantic_type="latency", unit="ns", cardinality="many", ordering="ordered")
        p_ms_struct = PortContract(schema_ref="typed_event_stream", semantic_type="latency", unit="ms", cardinality="many", ordering="ordered")
        res_struct = synth.propose(
            p_ns,
            p_ms_struct,
            unit_fields={"dur_ns": "dur_ms"},
            unit_representation="structured",
        )
        self.assertEqual(res_struct.status, AdapterProposalStatus.SYNTHESIZED_VERIFIED)
        self.assertTrue(res_struct.adapter_spec.lossless)
        self.assertEqual(
            res_struct.callable_adapter([{"dur_ns": 1_500_123}]),
            [{"dur_ms": {"value": 1, "remainder": 500_123, "unit": "ms", "remainder_unit": "ns"}}],
        )

        # Verify AdapterSpec emitted by Tier 2 satisfies adapter_spec.v1.schema.json required fields
        schema_path = Path(__file__).resolve().parents[2] / "schemas" / "adapter_spec.v1.schema.json"
        schema_doc = json.loads(schema_path.read_text(encoding="utf-8"))
        spec_dict = res_struct.adapter_spec.to_dict()
        for req_key in schema_doc["required"]:
            self.assertIn(req_key, spec_dict)
        self.assertEqual(set(spec_dict.keys()), set(schema_doc["properties"].keys()))

        # Direct compatibility (Tier 0) when ports match with no custom mapping
        res_direct = synth.propose(p_typed, p_typed)
        self.assertEqual(res_direct.status, AdapterProposalStatus.DIRECT_COMPATIBLE)
        self.assertEqual(res_direct.tier, 0)
        self.assertEqual(res_direct.callable_adapter({"x": 1}), {"x": 1})

        # Tampered catalog JSON on disk rejected cleanly during load
        with tempfile.TemporaryDirectory() as tmp:
            cat_file = Path(tmp) / "tampered_catalog.json"
            cat = AdapterCatalog(cat_file, authority=auth)
            cat.register(res_struct.adapter_spec)
            cat.save()
            raw_doc = json.loads(cat_file.read_text(encoding="utf-8"))
            raw_doc["adapters"][0]["lossless"] = False
            cat_file.write_text(json.dumps(raw_doc), encoding="utf-8")
            with self.assertRaises(ValueError):
                AdapterCatalog(cat_file, authority=auth)


if __name__ == "__main__":
    unittest.main()
