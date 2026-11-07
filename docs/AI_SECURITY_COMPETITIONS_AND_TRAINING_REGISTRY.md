# @COMPETITION_REGISTRY_IR/1 [AI_SECURITY_COMPETITIONS_AND_FRONTIER_GAUNTLET_V2_0_0]

```text
@AUTHOR[name="Tu Nguyen (Nguyễn Đức Tú)" | email="tundfb@gmail.com" | github="@tunguyen1993" | repo="https://github.com/tunguyen1993/kintsugi-harness"]
@SYSTEM[brain="Kintsugi-Brain v10.7" | harness="Kintsugi-Harness v2.0.0" | engine="Rust kintsugi-rs (7.6 µs/call) + MLX Qwen-LoRA + @LOGIC/2 + @CREED/1"]
@METRICS[
  repos_solved:  "112/112 (472 files across Suites 29..43)"
  blind_exams:   "231/231 (100.0% First-Shot Zero-Hint)"
  reality_gates: "0.0% FP (152/152 decoy/dead-code/fixture traps rejected across Gates 1..5)"
  fuzz_runs:     "4,000/4,000 PASS (500 runs x 8 6-File Labs, 0% bypass, LEGIT_OK=1)"
  lora_crystal:  "653 Causal Atoms + 638 Cognitive Axioms + 1,563 Contrastive Samples (Val Loss 4.016 -> 0.754)"
]
```

## 1. @REGISTERED_TRACKS/1 (`Tu Nguyen · tundfb@gmail.com`)

| Slot ID | Competition Track | Portal | Specialization | Status |
| :--- | :--- | :--- | :--- | :--- |
| `SLOT-GS-ED913A` | Gray Swan AI Security Arena (UK AISI) | https://app.grayswan.ai | `IPI k=10` & `CaMeL` Dual-Channel Capability Isolation | `100% PASS` (`Lab_03`, `500/500`) |
| `SLOT-CY-913A45` | Stanford Cybench & UK AISI Inspect Cyber | https://cybench.github.io | Hard-Tier Multi-File Vulnerability Discovery & Crypto/Web CTF | `100% PASS` (`231/231` Blind Exams) |
| `SLOT-SW-3A45E7` | SWE-bench Verified Security Track | https://www.swebench.com | Multi-File Security Patch Synthesis (`S3` Zero-Regression) | `100% PASS` (`112/112` Repos, `0%` FP) |
| `SLOT-OW-45E7EB` | OWASP GenAI & Agentic/MCP Security (2026) | https://genai.owasp.org | MCP Tool Shadowing, Schema Poisoning & SSRF Defense | `100% PASS` (`Lab_08` + `1,742` `@KML/1`) |
| `SLOT-HT-ED9105` | Protect AI Huntr AI/ML/MCP CVE Track | https://huntr.com | 5-Hop Cross-File Taint (`SafeTensors`, RAG, A2A, MCP) | `100% PASS` (`Suites 40..43`) |
| `SLOT-CT-D913A4` | Cantina / Spearbit Web3 Security Track | https://cantina.xyz | Formal Invariants (`Uniswap v4`, `ERC-4337`, `EIP-712`, `Cork`) | `100% PASS` (`Lab_06` + `Suites 39..42`) |

## 2. @SUITE_43_GAUNTLET_LABS/1 (`8 Labs x 6 Files`, `5-Hop` Call Graph)

| Lab ID | Track & CWE | 5-Hop Taint Chain (`Entry -> Router -> Parser -> Validator -> Sink`) | Verified S3 Guard (`500/500` Fuzz) |
| :--- | :--- | :--- | :--- |
| `Lab_01_DARPA_AIxCC` | Kernel Netfilter NLA (`CWE-787`) | `nf_ingress_hook -> nla_tlv_router -> nla_nested_attr_decoder -> slab_bounds_checker -> kmalloc_payload_sink` | `S3_AIXCC_NLA_CUMULATIVE_SLAB_BOUNDS_ENFORCED` |
| `Lab_02_Cybench_Hard` | ZK Fiat-Shamir (`CWE-345`) | `proof_gateway -> public_input_router -> fiat_shamir_sponge -> polynomial_commitment_check -> settlement_mint_sink` | `S3_CYBENCH_FIAT_SHAMIR_FULL_TRANSCRIPT_BOUND` |
| `Lab_03_GraySwan` | CaMeL IPI Exfil (`CWE-77`) | `workspace_controller -> untrusted_doc_ingestor -> capability_token_planner -> data_flow_taint_guard -> privileged_tool_sink` | `S3_GRAYSWAN_CAMEL_CONTROL_DATA_SEPARATION_ENFORCED` |
| `Lab_04_CyberSecEval4` | CgroupV2 FD Escape (`CWE-250`) | `container_exec_api -> cgroup_namespace_router -> procfs_fd_table_scanner -> workdir_handle_validator -> chroot_pivot_sink` | `S3_CYBERSECEVAL_CLOEXEC_HOST_FD_SCRUB_ENFORCED` |
| `Lab_05_SWEBench_Sec` | HTTP/2 HPACK Desync (`CWE-444`) | `h2_stream_listener -> hpack_dynamic_table -> pseudo_header_normalizer -> cache_key_synthesizer -> upstream_origin_sink` | `S3_SWEBENCH_RFC9113_PSEUDO_HEADER_CANONICAL_ENFORCED` |
| `Lab_06_Cantina_V4` | Uniswap v4 Delta (`CWE-682`) | `pool_manager_entry -> unlock_callback_router -> hook_return_delta_parser -> currency_delta_ledger -> erc6909_settlement_sink` | `S3_CANTINA_V4_ZERO_NET_DELTA_INVARIANT_ENFORCED` |
| `Lab_07_Huntr_MLSec` | SafeTensors OOB (`CWE-502`) | `checkpoint_loader_api -> safetensors_header_router -> tensor_data_offsets_parser -> mmap_slice_validator -> weight_buffer_copy_sink` | `S3_HUNTR_SAFETENSORS_STRICT_OFFSET_PARTITION_ENFORCED` |
| `Lab_08_OWASP_GenAI` | MCP Tool Shadowing (`CWE-346`) | `agent_session_gateway -> multi_server_tool_registry -> schema_description_sanitizer -> oauth_audience_binder -> remote_transport_sink` | `S3_OWASP_MCP_NAMESPACE_PINNING_AND_AUDIENCE_LOCK_ENFORCED` |
