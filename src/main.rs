use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use rssig::domain::{
    CommandReport, ErrorCode, FileFailure, FileResult, FileSuccess, Stage, VerificationError,
};
use rssig::{TrustStore, VerifyOptions, verify_pe};
use serde_json::Value;
use std::{
    path::PathBuf,
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

mod testcases;

#[derive(Parser)]
#[command(
    version,
    about = "Verify embedded Windows PE Authenticode signatures in pure Rust; results are JSON"
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
    /// Run a JSON testcase suite against this executable and emit a JSON report.
    Test {
        #[arg(long, default_value = "tests/cases.json")]
        cases: PathBuf,
    },
}

fn run(command: Command) -> Result<(Value, u8)> {
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
    } = command
    else {
        let Command::Test { cases } = command else {
            unreachable!()
        };
        return testcases::run(&cases);
    };
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
            Ok(bytes) => verify_pe(&bytes, &options),
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
    Ok((
        serde_json::to_value(CommandReport {
            schema_version: 1,
            command: "verify".into(),
            ok: success,
            results: output,
            error: None,
        })?,
        if success { 0 } else { 1 },
    ))
}
fn emit(value: &Value, code: u8) -> ExitCode {
    println!(
        "{}",
        serde_json::to_string_pretty(value).expect("JSON value must serialize")
    );
    ExitCode::from(code)
}
fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            return emit(
                &serde_json::to_value(rssig::domain::InformationReport {
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
            return emit(
                &serde_json::to_value(CommandReport::<FileResult> {
                    schema_version: 1,
                    command: "arguments".into(),
                    ok: false,
                    error: Some(VerificationError::new(
                        ErrorCode::InvalidArguments,
                        Stage::Arguments,
                        error.to_string(),
                    )),
                    results: vec![],
                })
                .expect("report serializes"),
                2,
            );
        }
    };
    let name = match &cli.command {
        Command::Verify { .. } => "verify",
        Command::Test { .. } => "test",
    };
    match run(cli.command) {
        Ok((value, code)) => emit(&value, code),
        Err(error) => emit(
            &serde_json::to_value(CommandReport::<FileResult> {
                schema_version: 1,
                command: name.into(),
                ok: false,
                error: Some(VerificationError::from_internal(
                    error,
                    if name == "test" {
                        ErrorCode::InvalidTestSuite
                    } else {
                        ErrorCode::Configuration
                    },
                    if name == "test" {
                        Stage::TestSuite
                    } else {
                        Stage::Configuration
                    },
                )),
                results: vec![],
            })
            .expect("report serializes"),
            2,
        ),
    }
}
