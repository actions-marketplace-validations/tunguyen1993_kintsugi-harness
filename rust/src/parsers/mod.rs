// kintsugi: ignore-file
//! Multi-line & function-scope Python shadow parser and Arm C (`KC-C01`..`KC-C05`) rule evaluators.

pub mod python_shadow;
pub mod python_shadow_rules;

pub use python_shadow_rules::{
    evaluate_arm_c_shadow_rule, scan_arm_c_shadow_text, scan_arm_c_shadow_text_with_options,
};
