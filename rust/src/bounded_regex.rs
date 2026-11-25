//! Bounded pure-Rust regex compiler and fail-closed matcher (`re.MULTILINE` semantics) for `RuleIR/1`.
//!
//! Hardened with typed [`RegexError`] taxonomy, zero-`Vec<char>` ASCII `&[u8]` fast-path [`InputView`],
//! `O(1)` incremental line tracking, `MAX_REGEX_NODES = 512`, `MAX_REGEX_RECURSION_DEPTH = 64`,
//! `O(1)`-stack iterative `Seq` and `Atom`-quantifier fast paths, and fail-closed step caps.

use std::cell::Cell;
use std::fmt;

pub const MAX_REGEX_NODES: usize = 512;
pub const MAX_REGEX_RECURSION_DEPTH: usize = 64;
/// Maximum pattern byte length matching Python `RuleIR.validate()` (`len(pat) <= 350`) to bound compile-time AST expansion.
pub const MAX_REGEX_PATTERN_BYTES: usize = 350;
pub const DEFAULT_GLOBAL_MAX_STEPS: usize = 500_000;
pub const DEFAULT_MAX_STEPS_PER_POS: usize = 250_000;

/// Typed fail-closed error taxonomy for [`BoundedRegex`] compilation and execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegexError {
    InvalidPattern(String),
    NodeLimitExceeded,
    RecursionLimitExceeded,
    StepBudgetExhausted,
}

impl fmt::Display for RegexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegexError::InvalidPattern(msg) => write!(f, "Invalid bounded_regex pattern: {msg}"),
            RegexError::NodeLimitExceeded => write!(f, "Regex pattern exceeds MAX_REGEX_NODES ({MAX_REGEX_NODES})"),
            RegexError::RecursionLimitExceeded => {
                write!(f, "Regex nesting/recursion exceeds MAX_REGEX_RECURSION_DEPTH ({MAX_REGEX_RECURSION_DEPTH})")
            }
            RegexError::StepBudgetExhausted => write!(f, "BoundedRegex step budget exhausted (fail-closed)"),
        }
    }
}

impl std::error::Error for RegexError {}

impl From<RegexError> for String {
    fn from(err: RegexError) -> Self { err.to_string() }
}

#[derive(Debug, Clone)]
pub enum RegexNode {
    Seq(Vec<RegexNode>),
    Alt(Vec<RegexNode>),
    Atom(RegexAtom),
    Quant { inner: Box<RegexNode>, min: usize, max: Option<usize>, greedy: bool },
    Group(Box<RegexNode>),
    Lookahead { inner: Box<RegexNode>, positive: bool },
    StartLine,
    EndLine,
    WordBoundary(bool),
}

#[derive(Debug, Clone)]
pub enum RegexAtom {
    Lit(char),
    AnyNonNewline,
    Class { negated: bool, ranges: Vec<(char, char)>, shorthands: Vec<ShorthandClass> },
    Shorthand(ShorthandClass),
}

#[derive(Debug, Clone, Copy)]
pub enum ShorthandClass { Space, NonSpace, Digit, NonDigit, Word, NonWord }

#[inline]
fn is_py_word_char(c: char) -> bool {
    if c.is_ascii() { c.is_ascii_alphanumeric() || c == '_' } else { c.is_alphanumeric() }
}

impl ShorthandClass {
    #[inline]
    pub fn matches(self, c: char) -> bool {
        match self {
            ShorthandClass::Space => c.is_whitespace(),
            ShorthandClass::NonSpace => !c.is_whitespace(),
            ShorthandClass::Digit => c.is_ascii_digit(),
            ShorthandClass::NonDigit => !c.is_ascii_digit(),
            ShorthandClass::Word => is_py_word_char(c),
            ShorthandClass::NonWord => !is_py_word_char(c),
        }
    }
}

impl RegexAtom {
    #[inline]
    pub fn matches(&self, c: char) -> bool {
        match self {
            RegexAtom::Lit(ch) => c == *ch,
            RegexAtom::AnyNonNewline => c != '\n',
            RegexAtom::Shorthand(sc) => sc.matches(c),
            RegexAtom::Class { negated, ranges, shorthands } => {
                let hit = ranges.iter().any(|&(lo, hi)| c >= lo && c <= hi)
                    || shorthands.iter().any(|sc| sc.matches(c));
                if *negated { !hit } else { hit }
            }
        }
    }
}

/// Zero-`Vec<char>` ASCII fast-path view vs indexed UTF-8 scalar view.
enum InputView<'a> {
    Ascii { text: &'a str, bytes: &'a [u8] },
    Utf8 { text: &'a str, chars: Vec<(usize, char)> },
}

impl<'a> InputView<'a> {
    #[inline]
    fn new(text: &'a str) -> Self {
        if text.is_ascii() {
            Self::Ascii { text, bytes: text.as_bytes() }
        } else {
            Self::Utf8 { text, chars: text.char_indices().collect() }
        }
    }

    #[cfg(test)]
    fn new_forced_utf8(text: &'a str) -> Self {
        Self::Utf8 { text, chars: text.char_indices().collect() }
    }

    #[inline]
    fn len(&self) -> usize {
        match self {
            Self::Ascii { bytes, .. } => bytes.len(),
            Self::Utf8 { chars, .. } => chars.len(),
        }
    }

    #[inline]
    fn char_at(&self, idx: usize) -> Option<char> {
        match self {
            Self::Ascii { bytes, .. } => bytes.get(idx).map(|&b| b as char),
            Self::Utf8 { chars, .. } => chars.get(idx).map(|&(_, ch)| ch),
        }
    }

    #[inline]
    fn count_newlines(&self, from: usize, to: usize) -> usize {
        let hi = to.min(self.len());
        if from >= hi { return 0; }
        match self {
            Self::Ascii { bytes, .. } => bytes[from..hi].iter().filter(|&&b| b == b'\n').count(),
            Self::Utf8 { chars, .. } => chars[from..hi].iter().filter(|&&(_, c)| c == '\n').count(),
        }
    }

    #[inline]
    fn slice_capped(&self, start: usize, end: usize, max_chars: usize) -> String {
        let capped_end = end.min(start.saturating_add(max_chars)).min(self.len());
        if start >= capped_end { return String::new(); }
        match self {
            Self::Ascii { text, .. } => text[start..capped_end].to_string(),
            Self::Utf8 { text, chars } => {
                let b_start = chars[start].0;
                let b_end = if capped_end < chars.len() { chars[capped_end].0 } else { text.len() };
                text[b_start..b_end].to_string()
            }
        }
    }
}

pub struct RegexCompiler {
    chars: Vec<char>,
    pos: usize,
    node_count: usize,
    group_depth: usize,
}

impl RegexCompiler {
    pub fn compile_strict(pattern: &str) -> Result<RegexNode, RegexError> {
        let mut comp = Self { chars: pattern.chars().collect(), pos: 0, node_count: 0, group_depth: 0 };
        let node = comp.parse_alt()?;
        if comp.pos != comp.chars.len() {
            return Err(RegexError::InvalidPattern(format!("Unexpected regex char at position {}", comp.pos)));
        }
        Ok(node)
    }

    pub fn compile(pattern: &str) -> Result<RegexNode, String> {
        Self::compile_strict(pattern).map_err(|e| e.to_string())
    }

    #[inline]
    fn alloc(&mut self, node: RegexNode) -> Result<RegexNode, RegexError> {
        self.node_count += 1;
        if self.node_count > MAX_REGEX_NODES { return Err(RegexError::NodeLimitExceeded); }
        Ok(node)
    }

    fn peek(&self) -> Option<char> { self.chars.get(self.pos).copied() }

    fn next(&mut self) -> Option<char> {
        let ch = *self.chars.get(self.pos)?;
        self.pos += 1;
        Some(ch)
    }

    fn parse_alt(&mut self) -> Result<RegexNode, RegexError> {
        let mut branches = vec![self.parse_seq()?];
        while self.peek() == Some('|') {
            self.pos += 1;
            branches.push(self.parse_seq()?);
        }
        if branches.len() == 1 { Ok(branches.remove(0)) } else { self.alloc(RegexNode::Alt(branches)) }
    }

    fn parse_seq(&mut self) -> Result<RegexNode, RegexError> {
        let mut items = Vec::new();
        while let Some(ch) = self.peek() {
            if ch == ')' || ch == '|' { break; }
            let atom = self.parse_piece()?;
            items.push(self.parse_quantifier(atom)?);
        }
        if items.len() == 1 { Ok(items.remove(0)) } else { self.alloc(RegexNode::Seq(items)) }
    }

    fn parse_piece(&mut self) -> Result<RegexNode, RegexError> {
        let ch = self.next().ok_or_else(|| RegexError::InvalidPattern("Unexpected end of regex".to_string()))?;
        match ch {
            '^' => self.alloc(RegexNode::StartLine),
            '$' => self.alloc(RegexNode::EndLine),
            '.' => self.alloc(RegexNode::Atom(RegexAtom::AnyNonNewline)),
            '[' => self.parse_class(),
            '(' => self.parse_group(),
            '\\' => self.parse_escape_node(),
            '*' | '+' | '?' => Err(RegexError::InvalidPattern(format!("Nothing to repeat before '{ch}'"))),
            c => self.alloc(RegexNode::Atom(RegexAtom::Lit(c))),
        }
    }

    fn parse_shorthand(esc: char) -> Option<ShorthandClass> {
        match esc {
            's' => Some(ShorthandClass::Space), 'S' => Some(ShorthandClass::NonSpace),
            'd' => Some(ShorthandClass::Digit), 'D' => Some(ShorthandClass::NonDigit),
            'w' => Some(ShorthandClass::Word), 'W' => Some(ShorthandClass::NonWord),
            _ => None,
        }
    }

    fn unescape_ctrl(esc: char) -> char {
        match esc { 'n' => '\n', 'r' => '\r', 't' => '\t', other => other }
    }

    fn parse_escape_node(&mut self) -> Result<RegexNode, RegexError> {
        let esc = self.next().ok_or_else(|| RegexError::InvalidPattern("Trailing backslash in regex".to_string()))?;
        let node = match esc {
            'b' => RegexNode::WordBoundary(true),
            'B' => RegexNode::WordBoundary(false),
            c => match Self::parse_shorthand(c) {
                Some(sc) => RegexNode::Atom(RegexAtom::Shorthand(sc)),
                None => RegexNode::Atom(RegexAtom::Lit(Self::unescape_ctrl(c))),
            },
        };
        self.alloc(node)
    }

    fn parse_class(&mut self) -> Result<RegexNode, RegexError> {
        let negated = if self.peek() == Some('^') { self.pos += 1; true } else { false };
        let (mut ranges, mut shorthands, mut first, mut last_single) = (Vec::new(), Vec::new(), true, None);
        while let Some(ch) = self.next() {
            if ch == ']' && !first {
                if let Some(prev) = last_single { ranges.push((prev, prev)); }
                return self.alloc(RegexNode::Atom(RegexAtom::Class { negated, ranges, shorthands }));
            }
            first = false;
            if ch == '-' && last_single.is_some() && self.peek().is_some_and(|n| n != ']') {
                let start_ch = last_single.take().unwrap();
                let end_ch = match self.next().unwrap() {
                    '\\' => Self::unescape_ctrl(self.next().ok_or_else(|| RegexError::InvalidPattern("Trailing backslash".to_string()))?),
                    c => c,
                };
                if start_ch > end_ch { return Err(RegexError::InvalidPattern("Bad character range in regex".to_string())); }
                ranges.push((start_ch, end_ch));
                continue;
            }
            if let Some(prev) = last_single.take() { ranges.push((prev, prev)); }
            if ch == '\\' {
                let esc = self.next().ok_or_else(|| RegexError::InvalidPattern("Trailing backslash in character class".to_string()))?;
                if let Some(sc) = Self::parse_shorthand(esc) { shorthands.push(sc); } else { last_single = Some(Self::unescape_ctrl(esc)); }
            } else {
                last_single = Some(ch);
            }
        }
        Err(RegexError::InvalidPattern("Unterminated character class in regex".to_string()))
    }

    fn parse_group(&mut self) -> Result<RegexNode, RegexError> {
        self.group_depth += 1;
        if self.group_depth > MAX_REGEX_RECURSION_DEPTH {
            return Err(RegexError::RecursionLimitExceeded);
        }
        let node = if self.peek() == Some('?') {
            self.pos += 1;
            match self.next() {
                Some(':') => RegexNode::Group(Box::new(self.parse_alt()?)),
                Some('=') => RegexNode::Lookahead { inner: Box::new(self.parse_alt()?), positive: true },
                Some('!') => RegexNode::Lookahead { inner: Box::new(self.parse_alt()?), positive: false },
                other => return Err(RegexError::InvalidPattern(format!("Unsupported regex group syntax '(?{other:?}'"))),
            }
        } else {
            RegexNode::Group(Box::new(self.parse_alt()?))
        };
        if self.next() != Some(')') { return Err(RegexError::InvalidPattern("Unbalanced '(' in regex".to_string())); }
        self.group_depth -= 1;
        self.alloc(node)
    }

    fn parse_digits(&mut self) -> String {
        let mut s = String::new();
        while let Some(c) = self.peek().filter(|c| c.is_ascii_digit()) { s.push(c); self.pos += 1; }
        s
    }

    fn parse_quantifier(&mut self, node: RegexNode) -> Result<RegexNode, RegexError> {
        let (min, max) = match self.peek() {
            Some('*') => { self.pos += 1; (0, None) }
            Some('+') => { self.pos += 1; (1, None) }
            Some('?') => { self.pos += 1; (0, Some(1)) }
            Some('{') => {
                let save = self.pos;
                self.pos += 1;
                let num1 = self.parse_digits();
                if num1.is_empty() { self.pos = save; return Ok(node); }
                let lo = num1.parse::<usize>().map_err(|_| RegexError::InvalidPattern("Bad repeat count".to_string()))?;
                match self.peek() {
                    Some('}') => { self.pos += 1; (lo, Some(lo)) }
                    Some(',') => {
                        self.pos += 1;
                        if self.peek() == Some('}') {
                            self.pos += 1;
                            (lo, None)
                        } else {
                            let num2 = self.parse_digits();
                            if self.next() != Some('}') || num2.is_empty() { self.pos = save; return Ok(node); }
                            let hi = num2.parse::<usize>().map_err(|_| RegexError::InvalidPattern("Bad repeat max".to_string()))?;
                            if hi < lo { return Err(RegexError::InvalidPattern("min repeat > max repeat".to_string())); }
                            (lo, Some(hi))
                        }
                    }
                    _ => { self.pos = save; return Ok(node); }
                }
            }
            _ => return Ok(node),
        };
        let greedy = if self.peek() == Some('?') { self.pos += 1; false } else { true };
        self.alloc(RegexNode::Quant { inner: Box::new(node), min, max, greedy })
    }
}

struct ExecState {
    steps: Cell<usize>,
    max_steps: usize,
    exhausted: Cell<bool>,
    depth_exceeded: Cell<bool>,
}

impl ExecState {
    fn new(max_steps: usize) -> Self {
        Self { steps: Cell::new(0), max_steps, exhausted: Cell::new(false), depth_exceeded: Cell::new(false) }
    }

    #[inline]
    fn tick(&self) -> bool {
        if self.depth_exceeded.get() { return false; }
        let cur = self.steps.get();
        if cur >= self.max_steps { self.exhausted.set(true); return false; }
        self.steps.set(cur + 1);
        true
    }
}

#[derive(Debug, Clone)]
pub struct BoundedRegex {
    pattern: String,
    root: RegexNode,
}

impl BoundedRegex {
    pub fn compile_strict(pattern: &str) -> Result<Self, RegexError> {
        if pattern.is_empty() || pattern.len() > MAX_REGEX_PATTERN_BYTES {
            return Err(RegexError::InvalidPattern("Pattern length must be 1..=350 bytes".to_string()));
        }
        Ok(Self { pattern: pattern.to_string(), root: RegexCompiler::compile_strict(pattern)? })
    }

    pub fn compile(pattern: &str) -> Result<Self, String> {
        Self::compile_strict(pattern).map_err(|e| e.to_string())
    }

    #[inline]
    pub fn as_str(&self) -> &str { &self.pattern }

    pub fn required_anchor_literals(&self) -> Vec<Vec<u8>> { Self::extract_node_literals(&self.root) }

    fn extract_node_literals(node: &RegexNode) -> Vec<Vec<u8>> {
        match node {
            RegexNode::Group(inner) => Self::extract_node_literals(inner),
            RegexNode::Quant { inner, min, .. } if *min >= 1 => Self::extract_node_literals(inner),
            RegexNode::Seq(items) => {
                let (mut best, mut run): (Option<Vec<u8>>, String) = (None, String::new());
                for item in items {
                    if let RegexNode::Atom(RegexAtom::Lit(ch)) = item { run.push(*ch); continue; }
                    if run.len() >= 2 && best.as_ref().map_or(true, |b| run.len() > b.len()) {
                        best = Some(run.as_bytes().to_vec());
                    }
                    run.clear();
                    let sub = Self::extract_node_literals(item);
                    if sub.len() == 1 && sub[0].len() >= 2 && best.as_ref().map_or(true, |b| sub[0].len() > b.len()) {
                        best = Some(sub[0].clone());
                    }
                }
                if run.len() >= 2 && best.as_ref().map_or(true, |b| run.len() > b.len()) {
                    best = Some(run.as_bytes().to_vec());
                }
                best.into_iter().collect()
            }
            RegexNode::Alt(branches) if !branches.is_empty() && branches.len() <= 8 => {
                let mut all = Vec::new();
                for br in branches {
                    let sub = Self::extract_node_literals(br);
                    if sub.is_empty() { return Vec::new(); }
                    all.extend(sub);
                }
                all
            }
            _ => Vec::new(),
        }
    }

    /// Fail-closed regex scan returning [`RegexError`] on per-position cap, global step budget, or depth exhaustion.
    pub fn try_find_all(&self, text: &str) -> Result<Vec<(usize, String)>, RegexError> {
        let mut budget = DEFAULT_GLOBAL_MAX_STEPS;
        self.find_all_with_budget(text, &mut budget)
    }

    /// Fail-closed regex scan sharing `step_budget` across rules/invocations.
    pub fn find_all_with_budget(&self, text: &str, step_budget: &mut usize) -> Result<Vec<(usize, String)>, RegexError> {
        self.scan_view(&InputView::new(text), step_budget)
    }

    fn scan_view(&self, input: &InputView<'_>, budget: &mut usize) -> Result<Vec<(usize, String)>, RegexError> {
        let per_pos_cap = DEFAULT_MAX_STEPS_PER_POS;
        let len = input.len();
        let (mut matches, mut pos, mut line_no) = (Vec::new(), 0usize, 1usize);
        while pos <= len {
            if *budget == 0 { return Err(RegexError::StepBudgetExhausted); }
            let st = ExecState::new((*budget).min(per_pos_cap));
            let mut matched_end: Option<usize> = None;
            Self::match_node(&self.root, input, pos, 0, &st, &mut |end| { matched_end = Some(end); true });
            let used = st.steps.get();
            *budget = budget.saturating_sub(used);
            if st.depth_exceeded.get() { return Err(RegexError::RecursionLimitExceeded); }
            if *budget == 0 || st.exhausted.get() || (used >= per_pos_cap && matched_end.is_none()) {
                return Err(RegexError::StepBudgetExhausted);
            }
            let next_pos = if let Some(end) = matched_end {
                matches.push((line_no, input.slice_capped(pos, end, 120)));
                if end > pos { end } else { pos + 1 }
            } else {
                pos + 1
            };
            line_no += input.count_newlines(pos, next_pos);
            pos = next_pos;
        }
        Ok(matches)
    }

    fn match_node(
        node: &RegexNode,
        input: &InputView<'_>,
        pos: usize,
        depth: usize,
        st: &ExecState,
        cont: &mut dyn FnMut(usize) -> bool,
    ) -> bool {
        if depth > MAX_REGEX_RECURSION_DEPTH { st.depth_exceeded.set(true); return false; }
        if !st.tick() { return false; }
        let len = input.len();
        match node {
            RegexNode::Atom(atom) => input.char_at(pos).is_some_and(|c| atom.matches(c)) && cont(pos + 1),
            RegexNode::StartLine => (pos == 0 || input.char_at(pos - 1) == Some('\n')) && cont(pos),
            RegexNode::EndLine => (pos == len || input.char_at(pos) == Some('\n')) && cont(pos),
            RegexNode::WordBoundary(want) => {
                let left = pos > 0 && input.char_at(pos - 1).is_some_and(is_py_word_char);
                let right = input.char_at(pos).is_some_and(is_py_word_char);
                ((left != right) == *want) && cont(pos)
            }
            RegexNode::Group(inner) => Self::match_node(inner, input, pos, depth + 1, st, cont),
            RegexNode::Lookahead { inner, positive } => {
                let mut hit = false;
                Self::match_node(inner, input, pos, depth + 1, st, &mut |_| { hit = true; true });
                !st.depth_exceeded.get() && !st.exhausted.get() && (hit == *positive) && cont(pos)
            }
            RegexNode::Alt(branches) => {
                for br in branches {
                    if Self::match_node(br, input, pos, depth + 1, st, cont) { return true; }
                    if st.depth_exceeded.get() || st.exhausted.get() { return false; }
                }
                false
            }
            RegexNode::Seq(items) => Self::match_seq(items, 0, input, pos, depth + 1, st, cont),
            RegexNode::Quant { inner, min, max, greedy } => {
                Self::match_quant(inner, *min, *max, *greedy, 0, input, pos, depth + 1, st, cont)
            }
        }
    }

    fn match_seq(
        items: &[RegexNode],
        mut idx: usize,
        input: &InputView<'_>,
        mut pos: usize,
        depth: usize,
        st: &ExecState,
        cont: &mut dyn FnMut(usize) -> bool,
    ) -> bool {
        if depth > MAX_REGEX_RECURSION_DEPTH { st.depth_exceeded.set(true); return false; }
        let len = input.len();
        while idx < items.len() {
            match &items[idx] {
                RegexNode::Atom(atom) => {
                    if !st.tick() || !input.char_at(pos).is_some_and(|c| atom.matches(c)) { return false; }
                    pos += 1;
                }
                RegexNode::StartLine => {
                    if !st.tick() || !(pos == 0 || input.char_at(pos - 1) == Some('\n')) { return false; }
                }
                RegexNode::EndLine => {
                    if !st.tick() || !(pos == len || input.char_at(pos) == Some('\n')) { return false; }
                }
                RegexNode::WordBoundary(want) => {
                    let left = pos > 0 && input.char_at(pos - 1).is_some_and(is_py_word_char);
                    let right = input.char_at(pos).is_some_and(is_py_word_char);
                    if !st.tick() || ((left != right) != *want) { return false; }
                }
                branching => {
                    return Self::match_node(branching, input, pos, depth + 1, st, &mut |next_pos| {
                        Self::match_seq(items, idx + 1, input, next_pos, depth + 1, st, cont)
                    });
                }
            }
            idx += 1;
        }
        cont(pos)
    }

    #[allow(clippy::too_many_arguments)]
    fn match_quant(
        inner: &RegexNode,
        min: usize,
        max: Option<usize>,
        greedy: bool,
        count: usize,
        input: &InputView<'_>,
        pos: usize,
        depth: usize,
        st: &ExecState,
        cont: &mut dyn FnMut(usize) -> bool,
    ) -> bool {
        if depth > MAX_REGEX_RECURSION_DEPTH { st.depth_exceeded.set(true); return false; }
        let len = input.len();
        if count == 0 {
            if let RegexNode::Atom(atom) = inner {
                let cap = max.unwrap_or(len.saturating_sub(pos));
                let mut k = 0usize;
                while k < min {
                    if !st.tick() || !input.char_at(pos + k).is_some_and(|c| atom.matches(c)) { return false; }
                    k += 1;
                }
                if greedy {
                    while k < cap && pos + k < len && st.tick() && input.char_at(pos + k).is_some_and(|c| atom.matches(c)) { k += 1; }
                    return (min..=k).rev().any(|try_k| !st.exhausted.get() && !st.depth_exceeded.get() && cont(pos + try_k));
                }
                loop {
                    if cont(pos + k) { return true; }
                    if k >= cap || !st.tick() || !input.char_at(pos + k).is_some_and(|c| atom.matches(c)) { return false; }
                    k += 1;
                }
            }
        }
        if st.steps.get() >= st.max_steps || st.depth_exceeded.get() {
            if st.steps.get() >= st.max_steps { st.exhausted.set(true); }
            return false;
        }
        if count < min {
            return Self::match_node(inner, input, pos, depth + 1, st, &mut |next_pos| {
                (next_pos != pos || min != 0)
                    && Self::match_quant(inner, min, max, greedy, count + 1, input, next_pos, depth + 1, st, cont)
            });
        }
        if max.is_some_and(|m| count >= m) { return cont(pos); }
        if greedy {
            let matched = Self::match_node(inner, input, pos, depth + 1, st, &mut |next_pos| {
                next_pos != pos && Self::match_quant(inner, min, max, greedy, count + 1, input, next_pos, depth + 1, st, cont)
            });
            matched || (!st.depth_exceeded.get() && !st.exhausted.get() && cont(pos))
        } else {
            cont(pos)
                || Self::match_node(inner, input, pos, depth + 1, st, &mut |next_pos| {
                    next_pos != pos && Self::match_quant(inner, min, max, greedy, count + 1, input, next_pos, depth + 1, st, cont)
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_fast_path_matches_utf8_view_and_error_taxonomy_is_exact() {
        let rx = BoundedRegex::compile_strict(r"^\s*\b(?:eval|exec)\s*\([^)\n]+\)$").unwrap();
        let sample = "ok = 1\n  eval(user_payload)\nsafe_eval(x)\n\texec(cmd_str)\n";
        let (mut b_ascii, mut b_utf8) = (DEFAULT_GLOBAL_MAX_STEPS, DEFAULT_GLOBAL_MAX_STEPS);
        let m_ascii = rx.scan_view(&InputView::new(sample), &mut b_ascii).unwrap();
        let m_utf8 = rx.scan_view(&InputView::new_forced_utf8(sample), &mut b_utf8).unwrap();
        assert_eq!((&m_ascii, b_ascii), (&m_utf8, b_utf8));
        assert_eq!((m_ascii[0].0, m_ascii[1].0), (2, 4));

        let hits = BoundedRegex::compile_strict(r"\beval\([^)]+\)").unwrap().try_find_all("# Tiếng Việt 🚀\neval(dữ_liệu)\n").unwrap();
        assert_eq!(hits, vec![(2, "eval(dữ_liệu)".to_string())]);

        let adv = "a".repeat(48) + "c";
        let neg_la = BoundedRegex::compile_strict("(?!(a+)+b)a+c").unwrap();
        let mut budget = DEFAULT_MAX_STEPS_PER_POS * 4;
        assert_eq!(neg_la.find_all_with_budget(&adv, &mut budget), Err(RegexError::StepBudgetExhausted));

        let deep_pat = format!("{}x{}", "(".repeat(MAX_REGEX_RECURSION_DEPTH + 1), ")".repeat(MAX_REGEX_RECURSION_DEPTH + 1));
        assert_eq!(BoundedRegex::compile_strict(&deep_pat).unwrap_err(), RegexError::RecursionLimitExceeded);
        assert_eq!(BoundedRegex::compile_strict("(?:ab)+").unwrap().try_find_all(&"ab".repeat(72)), Err(RegexError::RecursionLimitExceeded));
        assert_eq!(RegexCompiler::compile_strict(&"a?".repeat(300)).unwrap_err(), RegexError::NodeLimitExceeded);
        assert!(matches!(BoundedRegex::compile_strict("[z-a]"), Err(RegexError::InvalidPattern(_))));
    }
}
