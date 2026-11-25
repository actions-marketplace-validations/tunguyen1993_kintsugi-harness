//! Minimal-build (`--no-default-features`) integration suite verifying core scanner,
//! `BoundedRegex`, SHA-256, and compile-time vs runtime ABI feature masks without optional features.

use kintsugi_core::ffi::{
    kintsugi_abi_compiled_features_v1, kintsugi_abi_features_v1, FEAT_AUDIT, FEAT_LOGFORGE,
    FEAT_RULE_IR, FEAT_SARIF, FEAT_SHA256,
};
use kintsugi_core::prelude::*;
use kintsugi_core::{sha256_hex, BoundedRegex};

#[test]
fn minimal_core_scans_hashes_and_reports_exact_compiled_feature_mask() {
    let compiled = kintsugi_abi_compiled_features_v1();
    let runtime = kintsugi_abi_features_v1();
    assert_eq!(compiled & runtime, compiled);
    assert_ne!(compiled & FEAT_SHA256, 0);

    assert_eq!((compiled & FEAT_AUDIT) != 0, cfg!(feature = "audit"));
    assert_eq!((compiled & FEAT_RULE_IR) != 0, cfg!(feature = "rule-ir"));
    assert_eq!((compiled & FEAT_LOGFORGE) != 0, cfg!(feature = "logforge"));
    assert_eq!((compiled & FEAT_SARIF) != 0, cfg!(feature = "sarif"));

    // Powerset-agnostic invariant: each library feature is an independent single bit,
    // and the compiled mask restricted to those bits equals exactly the cfg-derived mask
    // for whichever of the 32 (2^5) configurations this binary was built under.
    let lib_bits = [
        (FEAT_AUDIT, cfg!(feature = "audit"), "audit"),
        (FEAT_RULE_IR, cfg!(feature = "rule-ir"), "rule-ir"),
        (FEAT_LOGFORGE, cfg!(feature = "logforge"), "logforge"),
        (FEAT_SARIF, cfg!(feature = "sarif"), "sarif"),
    ];
    let mut known = FEAT_SHA256;
    let mut expected = FEAT_SHA256;
    for (i, &(bit, enabled, name)) in lib_bits.iter().enumerate() {
        assert_eq!(bit.count_ones(), 1, "feature `{name}` must map to exactly one bit");
        assert_eq!(bit & FEAT_SHA256, 0, "feature `{name}` overlaps FEAT_SHA256");
        for &(other, _, other_name) in &lib_bits[i + 1..] {
            assert_eq!(bit & other, 0, "feature bits `{name}` and `{other_name}` overlap");
        }
        known |= bit;
        if enabled {
            expected |= bit;
        }
        assert_eq!(
            compiled & bit != 0,
            enabled,
            "compiled bit for `{name}` disagrees with cfg!(feature = \"{name}\")"
        );
    }
    assert_eq!(compiled & known, expected, "compiled feature mask mismatch for this powerset cell");
    assert_eq!(runtime & expected, expected, "runtime mask must advertise every compiled feature");

    // `lab-tools = ["audit"]`: enabling lab-tools must force the audit bit on.
    if cfg!(feature = "lab-tools") {
        assert_ne!(compiled & FEAT_AUDIT, 0, "lab-tools must imply audit");
    }

    let hits = scan_text("import subprocess\nsubprocess.run(cmd, shell=True)\n", "a.py", "python", Severity::High, None);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].scar_id, "KS-002");

    let rx = BoundedRegex::compile_strict(r"shell\s*=\s*True").unwrap();
    assert_eq!(rx.try_find_all("subprocess.run(x, shell=True)").unwrap().len(), 1);
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}
