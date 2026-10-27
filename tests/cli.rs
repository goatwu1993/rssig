//! All fixture cases are native Rust tests; no test executable is spawned.
#[path = "cli/cab.rs"]
mod cab;
#[path = "cli/msi.rs"]
mod msi;
#[path = "cli/pe.rs"]
mod pe;
#[path = "cli/powershell.rs"]
mod powershell;
#[path = "cli/support.rs"]
mod support;
