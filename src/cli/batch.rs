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
    limits: &super::limits::Limits,
    operation: impl Fn(&Path, &[u8]) -> std::result::Result<T, VerificationError>,
    success_report: impl Fn(PathBuf, T) -> S,
    failure_report: impl Fn(FileFailure) -> S,
) -> Result<(Value, u8)> {
    let mut success = true;
    let mut problem = None;
    let mut output = Vec::new();
    let mut input_used = 0;
    let mut report_used = 0;
    for path in files {
        let available = limits.max_total_input_bytes - input_used;
        let limit = limits.max_input_bytes.min(available);
        input_used += limit; // Reserve before I/O; failed reads retain their reservation.
        let result = match super::limits::read_file(&path, limit) {
            Ok((bytes, overflow)) => {
                input_used -= limit - bytes.len();
                if overflow {
                    let (resource, cap, used) = if available < limits.max_input_bytes {
                        (
                            "total_input_bytes",
                            limits.max_total_input_bytes,
                            input_used,
                        )
                    } else {
                        ("input_bytes", limits.max_input_bytes, bytes.len())
                    };
                    Err(super::limits::exceeded(resource, cap, used, 1))
                } else {
                    operation(&path, &bytes)
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
        let result = result.and_then(|value| {
            let report = success_report(path.clone(), value);
            let available = limits.max_total_report_bytes - report_used;
            let cap = limits.max_report_bytes.min(available);
            match super::limits::report_size(&report, cap) {
                Ok(size) => {
                    report_used += size;
                    Ok(serde_json::to_value(report).expect("domain report serializes"))
                }
                Err((partial, requested)) => {
                    let (resource, limit, used) = if available < limits.max_report_bytes {
                        (
                            "total_report_bytes",
                            limits.max_total_report_bytes,
                            report_used + partial,
                        )
                    } else {
                        ("report_bytes", limits.max_report_bytes, partial)
                    };
                    Err(super::limits::exceeded(resource, limit, used, requested))
                }
            }
        });
        match result {
            Ok(value) => output.push(value),
            Err(error) => {
                success = false;
                let mut failure = FileFailure {
                    file: path,
                    ok: false,
                    error,
                };
                // Reserve bounded diagnostics independently of successful reports,
                // so every input can still receive an ordered failure result.
                if let Err((used, requested)) = super::limits::report_size(&failure, 64 * 1024) {
                    failure.error =
                        super::limits::exceeded("failure_report_bytes", 64 * 1024, used, requested)
                            .detail("original_code", failure.error.code)
                            .detail("original_stage", failure.error.stage);
                }
                problem.get_or_insert_with(|| failure.error.problem.as_ref().clone());
                output.push(serde_json::to_value(failure_report(failure))?);
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sec03_failure_evidence_is_bounded_too() {
        let limits = super::super::limits::Limits {
            max_input_bytes: 4096,
            max_total_input_bytes: 4096,
            max_report_bytes: 100,
            max_total_report_bytes: 100,
        };
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/good-pe64.exe");
        let (json, code) = execute::<(), _>(
            "verify",
            vec![path],
            &limits,
            |_, _| {
                Err(VerificationError::new(
                    ErrorCode::InvalidSignature,
                    Stage::Cms,
                    "bad signature",
                )
                .detail("large_evidence", "x".repeat(100_000)))
            },
            |_, _| serde_json::json!({"ok": true}),
            |failure| serde_json::to_value(failure).unwrap(),
        )
        .unwrap();
        assert_eq!(code, 1);
        assert!(serde_json::to_vec(&json).unwrap().len() < 4096);
        let error = &json["results"][0]["error"];
        assert_eq!(error["details"]["resource"], "failure_report_bytes");
        assert_eq!(error["details"]["original_code"], "invalid_signature");
    }
}
