//! Structured semantic field extractor for `PreToolUse` JSON payloads (`audit/pre_tool_fields.rs`).
//!
//! Enforces `MAX_PRETOOL_STRINGS = 1_024` and `MAX_PRETOOL_DECODED_BYTES = 8 MiB` fail-closed caps,
//! explicit [`BomPolicy`] isolation, semantic [`FieldRole`] classification, and JSON key Trojan checks.

use std::collections::BTreeMap;

use crate::json_dom::JsonValue;
use crate::unicode_policy::contains_security_unicode_control;

/// Maximum number of decoded string leaves permitted in a single `PreToolUse` JSON payload.
pub const MAX_PRETOOL_STRINGS: usize = 1_024;
/// Maximum cumulative UTF-8 byte volume of decoded strings permitted in a `PreToolUse` payload (`8 MiB`).
pub const MAX_PRETOOL_DECODED_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldRole {
    ShellCommand,
    SourceCode,
    FilePath,
    Metadata,
}

/// Explicit leading `U+FEFF` BOM policy for an extracted field or JSON key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BomPolicy {
    FileStartOnly,
    Forbidden,
}

impl BomPolicy {
    #[inline]
    pub const fn allows_file_start_bom(self) -> bool {
        matches!(self, Self::FileStartOnly)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedField {
    pub field_path: String,
    pub leaf_key: String,
    pub role: FieldRole,
    pub bom_policy: BomPolicy,
    pub text: String,
}

#[inline]
pub fn is_shell_tool_name(tool_name: &str) -> bool {
    matches!(tool_name.trim().to_ascii_lowercase().as_str(), "bash" | "run_command" | "shell" | "exec_command" | "sh" | "zsh" | "terminal")
}

#[inline]
pub fn is_edit_or_patch_tool(tool_name: &str) -> bool {
    matches!(
        tool_name.trim().to_ascii_lowercase().as_str(),
        "edit" | "multiedit" | "edit_file" | "str_replace" | "str_replace_editor"
            | "replace_file_content" | "multi_replace_file_content" | "apply_patch" | "patch"
    )
}

#[inline]
pub fn classify_field_role(leaf_key: &str, shell_tool: bool, in_tool_input: bool) -> FieldRole {
    match leaf_key {
        "command" | "cmd" | "CommandLine" | "bash" | "script" => FieldRole::ShellCommand,
        "content" | "Content" | "new_string" | "Replacement" | "code" | "patch" | "diff" | "Prompt" => FieldRole::SourceCode,
        "file_path" | "Path" | "path" | "target_file" | "cwd" | "workspace_root" | "Cwd" => FieldRole::FilePath,
        "description" | "toolSummary" | "summary" | "old_string" | "Target" | "reason" | "note"
        | "title" | "tool_name" | "tool" | "hook_event_name" | "session_id" | "transcript_path" | "permission_mode" => FieldRole::Metadata,
        _ if !in_tool_input => FieldRole::Metadata,
        _ if shell_tool => FieldRole::ShellCommand,
        _ => FieldRole::SourceCode,
    }
}

/// Heuristic Python detector for untyped `SourceCode` payloads without an explicit `file_path`.
pub fn looks_like_python_code(text: &str) -> bool {
    let trimmed = text.trim_start();
    if trimmed.starts_with("#!/usr/bin/env python") || trimmed.starts_with("#!/usr/bin/python") {
        return true;
    }
    text.lines().any(|ln| {
        let t = ln.trim_start();
        t.starts_with("import ") || t.starts_with("from ") || t.starts_with("def ") || t.starts_with("async def ") || t.starts_with("class ")
    })
}

struct ExtractAcc {
    fields: Vec<ExtractedField>,
    decoded_bytes: usize,
    shell_tool: bool,
    allow_full_file_bom: bool,
}

impl ExtractAcc {
    fn push_str(&mut self, field_path: String, leaf_key: &str, role: FieldRole, bom_policy: BomPolicy, text: &str) -> Result<(), String> {
        if self.fields.len() >= MAX_PRETOOL_STRINGS {
            return Err(format!("PreToolUse string count exceeds MAX_PRETOOL_STRINGS ({MAX_PRETOOL_STRINGS})"));
        }
        self.decoded_bytes = self.decoded_bytes.checked_add(text.len()).ok_or_else(|| "PreToolUse decoded byte count overflow".to_string())?;
        if self.decoded_bytes > MAX_PRETOOL_DECODED_BYTES {
            return Err(format!("PreToolUse decoded bytes exceed MAX_PRETOOL_DECODED_BYTES ({MAX_PRETOOL_DECODED_BYTES})"));
        }
        self.fields.push(ExtractedField { field_path, leaf_key: leaf_key.to_string(), role, bom_policy, text: text.to_string() });
        Ok(())
    }

    fn walk_value(&mut self, val: &JsonValue, path_prefix: &str, leaf_key: &str, in_tool_input: bool, is_direct_field_str: bool) -> Result<(), String> {
        match val {
            JsonValue::Str(s) => {
                let role = classify_field_role(leaf_key, self.shell_tool, in_tool_input);
                let bom_policy = if is_direct_field_str && in_tool_input && self.allow_full_file_bom && matches!(leaf_key, "content" | "Content") {
                    BomPolicy::FileStartOnly
                } else {
                    BomPolicy::Forbidden
                };
                self.push_str(path_prefix.to_string(), leaf_key, role, bom_policy, s)
            }
            JsonValue::Array(arr) => {
                for (idx, item) in arr.iter().enumerate() {
                    self.walk_value(item, &format!("{path_prefix}[{idx}]"), leaf_key, in_tool_input, false)?;
                }
                Ok(())
            }
            JsonValue::Object(map) => {
                for (k, v) in map {
                    if contains_security_unicode_control(k, BomPolicy::Forbidden.allows_file_start_bom()) {
                        return Err("TROJAN_UNICODE_IN_JSON_KEY".to_string());
                    }
                    let sub_path = if path_prefix.is_empty() { k.clone() } else { format!("{path_prefix}.{k}") };
                    self.walk_value(v, &sub_path, k, in_tool_input || matches!(k.as_str(), "tool_input" | "toolCall"), true)?;
                }
                Ok(())
            }
            JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) => Ok(()),
        }
    }
}

/// Extract all string leaves from `root` with semantic [`FieldRole`] and [`BomPolicy`] tags.
pub fn extract_pre_tool_fields(
    root: &BTreeMap<String, JsonValue>,
    ti_obj: Option<&BTreeMap<String, JsonValue>>,
    tool_name: &str,
) -> Result<Vec<ExtractedField>, String> {
    let treat_root_as_input = ti_obj.is_none();
    let has_partial_target = ["old_string", "Target", "patch", "diff"]
        .iter()
        .any(|k| ti_obj.and_then(|o| o.get(*k)).or_else(|| root.get(*k)).is_some());
    let mut acc = ExtractAcc {
        fields: Vec::with_capacity(8),
        decoded_bytes: 0,
        shell_tool: is_shell_tool_name(tool_name),
        allow_full_file_bom: !is_edit_or_patch_tool(tool_name) && !has_partial_target,
    };
    for (k, v) in root {
        if contains_security_unicode_control(k, BomPolicy::Forbidden.allows_file_start_bom()) {
            return Err("TROJAN_UNICODE_IN_JSON_KEY".to_string());
        }
        acc.walk_value(v, k, k, treat_root_as_input || matches!(k.as_str(), "tool_input" | "toolCall"), true)?;
    }
    Ok(acc.fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json_dom::parse_json_value;

    #[test]
    fn classifies_roles_bom_policy_and_enforces_string_count_cap() {
        let dom = parse_json_value(r#"{"tool_name":"Write","tool_input":{"file_path":"a.py","content":"x=1"}}"#).unwrap();
        let root = dom.as_object().unwrap();
        let wf = extract_pre_tool_fields(root, root["tool_input"].as_object(), "Write").unwrap();
        assert_eq!(wf.iter().find(|f| f.leaf_key == "content").unwrap().bom_policy, BomPolicy::FileStartOnly);
        assert_eq!(wf.iter().find(|f| f.leaf_key == "file_path").unwrap().bom_policy, BomPolicy::Forbidden);

        let ed = parse_json_value(r#"{"tool_name":"Edit","tool_input":{"file_path":"a.py","old_string":"x","new_string":"y","content":"z"}}"#).unwrap();
        let er = ed.as_object().unwrap();
        assert!(extract_pre_tool_fields(er, er["tool_input"].as_object(), "Edit").unwrap().iter().all(|f| f.bom_policy == BomPolicy::Forbidden));

        let many = format!("{{\"tool_name\":\"Write\",\"tool_input\":{{\"items\":[{}]}}}}", vec!["\"x\""; MAX_PRETOOL_STRINGS + 2].join(","));
        let mr = parse_json_value(&many).unwrap();
        assert!(extract_pre_tool_fields(mr.as_object().unwrap(), mr.as_object().unwrap()["tool_input"].as_object(), "Write").is_err());
    }
}
