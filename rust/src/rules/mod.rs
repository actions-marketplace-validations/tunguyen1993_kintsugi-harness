// kintsugi: ignore-file
//! Built-in Kintsugi rules, prompt-injection semantics, and fast line/scope matchers.

pub mod builtin;
pub mod matcher;
pub mod prompt_injection;

pub use builtin::*;
pub use matcher::*;
pub use prompt_injection::*;
