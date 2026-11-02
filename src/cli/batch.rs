//! Shared file I/O, ordered outcomes, and JSON command envelopes.
//! Operations receive bytes and a filename hint; this layer owns no crypto policy.
use crate::domain::{CommandReport, ErrorCode, FileFailure, Stage, VerificationError};
use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use std::path::{Path, PathBuf};

pub(super) fn execute<T, S: Serialize>(
    command: &str,
    files: Vec<PathBuf>,
    operation: impl Fn(&Path, &[u8]) -> std::result::Result<T, VerificationError>,
    success_report: impl Fn(PathBuf, T) -> S,
    failure_report: impl Fn(FileFailure) -> S,
) -> Result<(Value, u8)> {
    let mut success = true;
    let mut problem = None;
    let mut output = Vec::new();
    for path in files {
        let result = match std::fs::read(&path) {
            Ok(bytes) => operation(&path, &bytes),
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
            Ok(value) => output.push(success_report(path, value)),
            Err(error) => {
                success = false;
                // Retain the first problem while collecting every input's outcome.
                problem.get_or_insert_with(|| error.problem.as_ref().clone());
                output.push(failure_report(FileFailure {
                    file: path,
                    ok: false,
                    error,
                }));
            }
        }
    }
    Ok((
        serde_json::to_value(CommandReport {
            problem,
            schema_version: 1,
            command: command.into(),
            ok: success,
            results: output,
            error: None,
        })?,
        if success { 0 } else { 1 },
    ))
}
