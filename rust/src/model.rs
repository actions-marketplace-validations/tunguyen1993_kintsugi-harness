// kintsugi: ignore-file
//! Core Kintsugi data models (`Severity`, `NativeRule`, `Finding`, `ScanSummary`, `TokenBenchmark`).

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Severity {
    /// Strict case-insensitive parser accepting only canonical severity levels.
    pub fn parse_strict(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_uppercase().as_str() {
            "CRITICAL" => Some(Severity::Critical),
            "HIGH" => Some(Severity::High),
            "MEDIUM" => Some(Severity::Medium),
            "LOW" => Some(Severity::Low),
            _ => None,
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(raw: &str) -> Self {
        Self::parse_strict(raw).unwrap_or(Severity::Low)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
        }
    }

    pub fn short_tag(&self) -> &'static str {
        match self {
            Severity::Critical => "CRIT",
            Severity::High => "HIGH",
            Severity::Medium => "MED",
            Severity::Low => "LOW",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeRule {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub category: &'static str,
    pub kmi_token: &'static str,
    pub languages: &'static [&'static str],
    pub fix_hint: &'static str,
    pub premium_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub scar_id: String,
    pub title: String,
    pub severity: Severity,
    pub category: String,
    pub file_path: String,
    pub line: usize,
    pub column: usize,
    pub snippet: String,
    pub fix_hint: String,
}

impl Finding {
    pub fn from_rule(
        rule: &NativeRule,
        file_path: &str,
        line: usize,
        column: usize,
        snippet: &str,
    ) -> Self {
        Self {
            scar_id: rule.id.to_string(),
            title: rule.title.to_string(),
            severity: rule.severity,
            category: rule.category.to_string(),
            file_path: file_path.to_string(),
            line,
            column,
            snippet: snippet.to_string(),
            fix_hint: rule.fix_hint.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanSummary {
    pub scanned_files: usize,
    pub active_rules: usize,
    pub elapsed_micros: u128,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone)]
pub struct TokenBenchmark {
    pub rules_count: usize,
    pub verbose_tokens: usize,
    pub kmi_tokens: usize,
    pub reduction_pct: f64,
    pub saved_tokens_50_turns: usize,
}
