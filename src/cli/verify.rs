//! Verification-only configuration: roots, CRLs, time, and explicit policy.
use super::batch;
use anyhow::{Context, Result, ensure};
use rssig_engine::{
    TrustStore, VerifyOptions,
    domain::{FileResult, FileSuccess},
};
use serde_json::Value;
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(clap::Args)]
pub(super) struct Args {
    #[arg(required = true)]
    files: Vec<PathBuf>,
    #[command(flatten)]
    limits: super::limits::Limits,
    /// Verify cryptography and image integrity without claiming certificate trust.
    #[arg(long, conflicts_with_all = ["roots", "no_system_roots", "crl", "no_revocation", "fetch_crls"])]
    integrity_only: bool,
    /// Additional trusted roots (PEM bundle or DER certificate); repeatable.
    #[arg(long)]
    roots: Vec<PathBuf>,
    #[arg(long)]
    no_system_roots: bool,
    /// Complete, current CRLs (PEM bundle or DER); cover every issuer in each chain.
    #[arg(long)]
    crl: Vec<PathBuf>,
    /// Discover and retrieve direct CRLs over bounded public HTTP (opt-in).
    #[arg(long, conflicts_with_all = ["integrity_only", "no_revocation"])]
    fetch_crls: bool,
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

pub(super) fn execute(args: Args, host: super::Host<'_>) -> Result<(Value, u8)> {
    let super::Host {
        crl_source: source,
        logger,
    } = host;
    let Args {
        files,
        limits,
        integrity_only,
        roots,
        no_system_roots,
        crl,
        fetch_crls,
        no_revocation,
        allow_sha1,
        at,
        json: _,
    } = args;
    limits.validate(&files)?;
    super::limits::validate_paths(&roots, 64)?;
    super::limits::validate_paths(&crl, 64)?;
    ensure!(
        roots.len() + crl.len() <= 64,
        "at most 64 root/CRL files are allowed"
    );
    let mut trust_remaining = super::limits::TRUST_TOTAL;
    ensure!(
        integrity_only || no_revocation || !crl.is_empty() || fetch_crls,
        "supply --crl or --fetch-crls for revocation checks, or explicitly choose --no-revocation / --integrity-only"
    );
    let mut trust = if integrity_only || no_system_roots {
        TrustStore::default()
    } else {
        #[cfg(feature = "system-roots")]
        {
            crate::roots::system_roots()?
        }
        #[cfg(not(feature = "system-roots"))]
        anyhow::bail!(
            "system roots are unavailable in this build; use --no-system-roots with --roots, or --integrity-only"
        );
    };
    super::limits::check_trust(&trust)?;
    for path in roots {
        trust
            .add_roots(
                &super::limits::read_trust(&path, &mut trust_remaining)
                    .with_context(|| format!("reading {}", path.display()))?,
            )
            .with_context(|| format!("loading roots from {}", path.display()))?;
        super::limits::check_trust(&trust)?;
    }
    for path in &crl {
        trust
            .add_crl(
                &super::limits::read_trust(path, &mut trust_remaining)
                    .with_context(|| format!("reading {}", path.display()))?,
            )
            .with_context(|| format!("loading CRL from {}", path.display()))?;
        super::limits::check_trust(&trust)?;
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
                rssig_engine::verify::RevocationPolicy::Disabled
            } else {
                rssig_engine::verify::RevocationPolicy::Required
            },
        )
    };
    options.allow_sha1 = allow_sha1;
    let mut http = crate::crl::HttpCrlSource::new();
    let source = source.unwrap_or(&mut http);
    batch::execute(
        "verify",
        files,
        &limits,
        |path, bytes| {
            // Preserve extension hints even when the filename stem is not UTF-8.
            let hint = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| format!("input.{e}"));
            let mut verifier = rssig_engine::verify::Verifier::new(&options);
            if let Some(logger) = logger {
                verifier = verifier.with_logger(logger);
                if logger.enabled(rssig_engine::log::Level::Debug) {
                    logger.log(&rssig_engine::log::Record::new(
                        rssig_engine::log::Level::Debug,
                        rssig_engine::domain::Stage::Input,
                        format_args!("verifying file {path:?} ({} bytes)", bytes.len()),
                    ));
                }
            }
            if fetch_crls {
                // Each verification starts its source's allowances afresh
                // (`CrlSource::begin_verification`): the built-in source's
                // limits bound one file, not the batch.
                verifier.verify_with_crl_source(bytes, hint.as_deref(), source)
            } else {
                verifier.verify_with_hint(bytes, hint.as_deref())
            }
        },
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
