// kintsugi: ignore-file
//! Shell command argv policy analyzer and symlink-confined workspace/policy verifier.

pub mod shell;
pub mod workspace;

pub use shell::*;
pub use workspace::*;
