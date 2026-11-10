//! Verification-only configuration: roots, CRLs, time, and explicit policy.
use super::batch;
use crate::{
    TrustStore, VerifyOptions,
    domain::{FileResult, FileSuccess},
};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(clap::Args)]
pub(super) struct Args {
    #[arg(required = true)]
    files: Vec<PathBuf>,
    /// Verify cryptography and image integrity without claiming certificate trust.
    #[arg(long, conflicts_with_all = ["roots", "no_system_roots", "crl", "no_revocation"])]
    integrity_only: bool,
    /// Additional trusted roots (PEM bundle or DER certificate); repeatable.
    #[arg(long)]
    roots: Vec<PathBuf>,
    #[arg(long)]
    no_system_roots: bool,
    /// Complete, current CRLs (PEM or DER); repeat for every issuer in each chain.
    #[arg(long)]
    crl: Vec<PathBuf>,
    /// Explicitly disable revocation checking (reported in output).
    #[arg(long)]
    no_revocation: bool,
    /// Permit legacy SHA-1 CMS/image digests (not SHA-1 certificate chains).
    #[arg(long)]
    allow_sha1: bool,
    /// Validation time as Unix seconds. Defaults to the current time.
    #[arg(long = "time")]
    at: Option<u64>,
    /// Compatibility flag; verification results are always JSON.
    #[arg(long, hide = true)]
    json: bool,
}

pub(super) fn execute(args: Args) -> Result<(Value, u8)> {
    let Args {
        files,
        integrity_only,
        roots,
        no_system_roots,
        crl,
        no_revocation,
        allow_sha1,
        at,
        json: _,
    } = args;
    ensure!(
        integrity_only || no_revocation || !crl.is_empty(),
        "supply --crl for revocation checks, or explicitly choose --no-revocation / --integrity-only"
    );
    let mut trust = if integrity_only || no_system_roots {
        TrustStore::default()
    } else {
        #[cfg(feature = "system-roots")]
        {
            TrustStore::from_system()?
        }
        #[cfg(not(feature = "system-roots"))]
        anyhow::bail!(
            "system roots are unavailable in this build; use --no-system-roots with --roots, or --integrity-only"
        );
    };
    for path in roots {
        trust
            .add_roots(
                &std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?,
            )
            .with_context(|| format!("loading roots from {}", path.display()))?;
    }
    for path in &crl {
        trust
            .add_crl(&std::fs::read(path).with_context(|| format!("reading {}", path.display()))?)
            .with_context(|| format!("loading CRL from {}", path.display()))?;
    }
    let now = match at {
        Some(at) => at,
        None => SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    };
    let mut options = if integrity_only {
        VerifyOptions::integrity_only(now)
    } else {
        VerifyOptions::trusted_with_revocation(
            &trust,
            now,
            if no_revocation {
                crate::verify::RevocationPolicy::Disabled
            } else {
                crate::verify::RevocationPolicy::Required
            },
        )
    };
    options.allow_sha1 = allow_sha1;
    batch::execute(
        "verify",
        files,
        |path, bytes| crate::verify::verify_detected(bytes, Some(path), &options),
        |file, verification| {
            FileResult::Success(FileSuccess {
                file,
                ok: true,
                verification,
            })
        },
        FileResult::Failure,
    )
}
