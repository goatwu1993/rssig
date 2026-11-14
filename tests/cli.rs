//! All fixture cases are native Rust tests; no test executable is spawned.
#[path = "cli/appx.rs"]
mod appx;
#[path = "cli/appx_bundle.rs"]
mod appx_bundle;
#[path = "cli/cab.rs"]
mod cab;
#[path = "cli/msi.rs"]
mod msi;
#[path = "cli/msp.rs"]
mod msp;
#[path = "cli/pe.rs"]
mod pe;
#[path = "cli/powershell.rs"]
mod powershell;
#[path = "cli/psxml.rs"]
mod psxml;
#[path = "cli/rdp.rs"]
mod rdp;
#[path = "cli/support.rs"]
mod support;
#[path = "cli/wsh.rs"]
mod wsh;

#[path = "cli/navx.rs"]
mod navx;

#[path = "cli/parse.rs"]
mod parse;

#[path = "cli/text_parsing.rs"]
mod text_parsing;

#[path = "cli/package_parsing.rs"]
mod package_parsing;

#[path = "cli/policy.rs"]
mod policy;

#[path = "cli/budgets.rs"]
mod budgets;

#[path = "cli/host_limits.rs"]
mod host_limits;

#[path = "cli/crl_fetch.rs"]
mod crl_fetch;

#[path = "cli/cms_audit.rs"]
mod cms_audit;

#[path = "cli/signer_selection.rs"]
mod signer_selection;

#[path = "cli/coverage_inventory.rs"]
mod coverage_inventory;
