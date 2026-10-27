//! Clap-based, in-process CLI entry point.
use crate::domain::{
    CommandReport, ErrorCode, FileFailure, FileResult, FileSuccess, Stage, VerificationError,
};
use crate::{TrustStore, VerifyOptions, verify};
use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use serde_json::Value;
use std::{
    ffi::OsString,
    io::{self, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Parser)]
#[command(
    version,
    about = "Verify embedded Windows PE/MSI/CAB/PowerShell Authenticode signatures in pure Rust; results are JSON"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Verify {
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
        /// Compatibility flag; JSON is always the output format.
        #[arg(long, hide = true)]
        json: bool,
    },
}

fn execute(command: Command) -> Result<(Value, u8)> {
    let Command::Verify {
        files,
        integrity_only,
        roots,
        no_system_roots,
        crl,
        no_revocation,
        allow_sha1,
        at,
        json: _,
    } = command;
    ensure!(
        integrity_only || no_revocation || !crl.is_empty(),
        "supply --crl for revocation checks, or explicitly choose --no-revocation / --integrity-only"
    );
    let mut trust = if integrity_only || no_system_roots {
        TrustStore::default()
    } else {
        TrustStore::from_system()?
    };
    for path in roots {
        trust.add_roots(
            &std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?,
        )?;
    }
    for path in &crl {
        trust.add_crl(
            &std::fs::read(path).with_context(|| format!("reading {}", path.display()))?,
        )?;
    }
    let now = match at {
        Some(at) => at,
        None => SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    };
    let options = VerifyOptions {
        trust: if integrity_only { None } else { Some(&trust) },
        check_revocation: !no_revocation,
        allow_sha1,
        now,
    };
    let mut success = true;
    let mut output = Vec::new();
    for path in files {
        let result = match std::fs::read(&path) {
            Ok(bytes) => {
                if crate::powershell::has_extension(&path) && !crate::verify::is_binary(&bytes) {
                    crate::verify_powershell(&bytes, &options)
                } else {
                    verify(&bytes, &options)
                }
            }
            Err(error) => Err(VerificationError::new(
                ErrorCode::ReadFailed,
                Stage::Input,
                format!("reading {}: {error}", path.display()),
            )
            .detail("file", &path)
            .detail("io_kind", format!("{:?}", error.kind()))
            .detail("os_error", error.raw_os_error())),
        };
        match result {
            Ok(verification) => output.push(FileResult::Success(FileSuccess {
                file: path,
                ok: true,
                verification,
            })),
            Err(error) => {
                success = false;
                output.push(FileResult::Failure(FileFailure {
                    file: path,
                    ok: false,
                    error,
                }));
            }
        }
    }
    // The first failing input is the primary problem; retain every result,
    // including successful files and subsequent problems, in the extension.
    let problem = output.iter().find_map(|result| match result {
        FileResult::Failure(failure) => Some(failure.error.problem.as_ref().clone()),
        FileResult::Success(_) => None,
    });
    Ok((
        serde_json::to_value(CommandReport {
            problem,
            schema_version: 1,
            command: "verify".into(),
            ok: success,
            results: output,
            error: None,
        })?,
        if success { 0 } else { 1 },
    ))
}
/// Parse argv (including the program name), execute, and write one JSON document.
///
/// All command paths, including help and argument errors, return an exit code
/// instead of exiting the process. Tests and embedders can capture output with
/// any `Write` implementation; no global stdout or working directory is changed.
///
/// ```
/// let mut stdout = Vec::new();
/// let code = rssig::cli::run(["rssig", "--version"], &mut stdout)?;
/// assert_eq!(code, 0);
/// let report: serde_json::Value = serde_json::from_slice(&stdout)?;
/// assert_eq!(report["command"], "version");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn run<I, T, W>(arguments: I, mut stdout: W) -> io::Result<u8>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
    W: Write,
{
    let (value, exit) = dispatch(arguments);
    serde_json::to_writer_pretty(&mut stdout, &value).map_err(io::Error::other)?;
    stdout.write_all(b"\n")?;
    Ok(exit)
}

fn dispatch<I, T>(arguments: I) -> (Value, u8)
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(arguments) {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            return (
                serde_json::to_value(crate::domain::InformationReport {
                    schema_version: 1,
                    command: if error.kind() == clap::error::ErrorKind::DisplayVersion {
                        "version".into()
                    } else {
                        "help".into()
                    },
                    ok: true,
                    text: error.to_string(),
                })
                .expect("information serializes"),
                0,
            );
        }
        Err(error) => {
            return (
                serde_json::to_value(CommandReport::<FileResult>::failure(
                    "arguments",
                    VerificationError::new(
                        ErrorCode::InvalidArguments,
                        Stage::Arguments,
                        error.to_string(),
                    ),
                ))
                .expect("report serializes"),
                2,
            );
        }
    };
    match execute(cli.command) {
        Ok(output) => output,
        Err(error) => (
            serde_json::to_value(CommandReport::<FileResult>::failure(
                "verify",
                VerificationError::from_internal(
                    error,
                    ErrorCode::Configuration,
                    Stage::Configuration,
                ),
            ))
            .expect("report serializes"),
            2,
        ),
    }
}
