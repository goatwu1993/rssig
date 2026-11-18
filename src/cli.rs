//! Clap-based, in-process CLI entry point and stream/exit-code contract.
mod batch;
mod limits;
mod parse;
mod verify;

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde_json::Value;
use std::{
    ffi::OsString,
    io::{self, Write},
};

#[derive(Parser)]
#[command(
    version,
    about = "Parse PE/CMS metadata or verify embedded Windows PE/MSI/MSP/CAB/NAVX/PowerShell/WSH/MSIX/AppX Authenticode and RDP signatures in pure Rust; results are JSON"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Authenticate embedded signatures with explicit trust and revocation policy.
    Verify(verify::Args),
    /// Inspect untrusted signed PE or standalone DER CMS metadata without verification.
    Parse(parse::Args),
}

/// Collaborators an embedding application injects into the in-process CLI.
/// Everything is optional; [`Host::new`] reproduces [`run_with_writers`].
#[derive(Default)]
#[non_exhaustive]
pub struct Host<'a> {
    /// Replaces the built-in HTTP CRL source. Called only with `--fetch-crls`.
    pub crl_source: Option<&'a mut dyn crate::retrieval::CrlSource>,
    /// Receives verification diagnostics. Nothing is logged without one, and
    /// records never reach stdout or stderr. `parse` does not log.
    pub logger: Option<&'a dyn crate::log::Logger>,
}

impl<'a> Host<'a> {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_crl_source(mut self, source: &'a mut dyn crate::retrieval::CrlSource) -> Self {
        self.crl_source = Some(source);
        self
    }
    pub fn with_logger(mut self, logger: &'a dyn crate::log::Logger) -> Self {
        self.logger = Some(logger);
        self
    }
}

/// The Clap definition behind [`run`], for tests that must agree with the
/// real argument parser (the specification runner checks which options take
/// a file). Hidden and not a stable interface: Clap's types may change.
#[doc(hidden)]
pub fn command() -> clap::Command {
    <Cli as clap::CommandFactory>::command()
}

fn execute(command: Command, host: Host<'_>) -> Result<(Value, u8)> {
    match command {
        Command::Verify(args) => verify::execute(args, host),
        Command::Parse(args) => parse::execute(args),
    }
}

/// Parse argv (including the program name) and capture all CLI output in one sink.
///
/// Parse and verification results are JSON; usage/configuration errors, help, and version
/// are plain text. This convenience API combines stdout and stderr for embedders.
/// Use [`run_with_writers`] to preserve the process stream separation.
/// Neither entry point exits the process or changes the working directory.
///
/// ```
/// let mut output = Vec::new();
/// let code = rssig::cli::run(["rssig", "--version"], &mut output)?;
/// assert_eq!(code, 0);
/// assert!(String::from_utf8(output)?.starts_with("rssig "));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn run<I, T, W>(arguments: I, output: W) -> io::Result<u8>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
    W: Write,
{
    dispatch(arguments, Host::new()).write(output)
}

/// Execute with separate output sinks, without exiting the calling process.
///
/// Parsing and verification emit one JSON document to stdout (exit 0 or 1). Argument and
/// configuration errors emit plain text to stderr (exit 2). Help/version emit
/// plain text to stdout (exit 0). Writer failures are returned to the caller.
pub fn run_with_writers<I, T, O, E>(arguments: I, stdout: O, stderr: E) -> io::Result<u8>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
    O: Write,
    E: Write,
{
    run_with_host(arguments, stdout, stderr, Host::new())
}

/// Execute with injected collaborators: a CRL source, a diagnostic logger, or both.
///
/// The stream and exit-code contract of [`run_with_writers`] is unchanged: log
/// records go only to the supplied logger, never to `stdout` or `stderr`.
pub fn run_with_host<I, T, O, E>(
    arguments: I,
    stdout: O,
    stderr: E,
    host: Host<'_>,
) -> io::Result<u8>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
    O: Write,
    E: Write,
{
    let output = dispatch(arguments, host);
    if matches!(output, Output::Text { stderr: true, .. }) {
        output.write(stderr)
    } else {
        output.write(stdout)
    }
}

/// Execute with an injected CRL source. The source is used only with --fetch-crls;
/// deterministic tests and offline applications can supply bounded artifacts.
pub fn run_with_crl_source<I, T, O, E>(
    arguments: I,
    stdout: O,
    stderr: E,
    source: &mut dyn crate::retrieval::CrlSource,
) -> io::Result<u8>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
    O: Write,
    E: Write,
{
    run_with_host(
        arguments,
        stdout,
        stderr,
        Host::new().with_crl_source(source),
    )
}

enum Output {
    Json(Value, u8),
    Text {
        text: String,
        exit: u8,
        stderr: bool,
    },
}

impl Output {
    fn write(self, mut writer: impl Write) -> io::Result<u8> {
        match self {
            Self::Json(value, exit) => {
                serde_json::to_writer_pretty(&mut writer, &value).map_err(|error| {
                    io::Error::new(error.io_error_kind().unwrap_or(io::ErrorKind::Other), error)
                })?;
                writer.write_all(b"\n")?;
                Ok(exit)
            }
            Self::Text { text, exit, .. } => {
                writer.write_all(text.as_bytes())?;
                Ok(exit)
            }
        }
    }
}

fn dispatch<I, T>(arguments: I, host: Host<'_>) -> Output
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(arguments) {
        Ok(cli) => cli,
        Err(error) => {
            return Output::Text {
                text: error.to_string(),
                exit: if error.use_stderr() { 2 } else { 0 },
                stderr: error.use_stderr(),
            };
        }
    };
    match execute(cli.command, host) {
        Ok((value, exit)) => Output::Json(value, exit),
        Err(error) => Output::Text {
            text: format!("error: {error:#}\n"),
            exit: 2,
            stderr: true,
        },
    }
}
