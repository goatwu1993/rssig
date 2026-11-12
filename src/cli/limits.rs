//! Host limits apply before parsing and before retaining serialized results.
use crate::domain::{ErrorCode, Stage, VerificationError};
use serde::Serialize;
use std::{
    fs::OpenOptions,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

pub(super) const MAX_FILES: usize = 128;
pub(super) const TRUST_FILE: usize = 8 * 1024 * 1024;
pub(super) const TRUST_TOTAL: usize = 32 * 1024 * 1024;

#[derive(clap::Args)]
pub(super) struct Limits {
    /// Maximum bytes read per input (hard ceiling: 128 MiB).
    #[arg(long, default_value_t = 128 * 1024 * 1024)]
    pub max_input_bytes: usize,
    /// Maximum bytes read across the batch (hard ceiling: 512 MiB).
    #[arg(long, default_value_t = 512 * 1024 * 1024)]
    pub max_total_input_bytes: usize,
    /// Maximum compact JSON bytes per successful result (hard ceiling: 8 MiB).
    #[arg(long, default_value_t = 8 * 1024 * 1024)]
    pub max_report_bytes: usize,
    /// Maximum retained successful-result JSON bytes (hard ceiling: 32 MiB).
    #[arg(long, default_value_t = 32 * 1024 * 1024)]
    pub max_total_report_bytes: usize,
}
impl Limits {
    pub fn validate(&self, files: &[PathBuf]) -> anyhow::Result<()> {
        validate_paths(files, MAX_FILES)?;
        for (name, value, cap) in [
            ("max-input-bytes", self.max_input_bytes, 128 * 1024 * 1024),
            (
                "max-total-input-bytes",
                self.max_total_input_bytes,
                512 * 1024 * 1024,
            ),
            ("max-report-bytes", self.max_report_bytes, 8 * 1024 * 1024),
            (
                "max-total-report-bytes",
                self.max_total_report_bytes,
                32 * 1024 * 1024,
            ),
        ] {
            anyhow::ensure!(
                value > 0 && value <= cap,
                "--{name} must be between 1 and {cap}"
            );
        }
        Ok(())
    }
}
pub(super) fn validate_paths(files: &[PathBuf], count: usize) -> anyhow::Result<()> {
    anyhow::ensure!(
        files.len() <= count,
        "at most {count} file paths are allowed"
    );
    anyhow::ensure!(
        files.iter().all(|p| p.as_os_str().len() <= 4096),
        "file paths must not exceed 4096 bytes"
    );
    Ok(())
}
pub(super) fn exceeded(
    resource: &str,
    limit: usize,
    used: usize,
    requested: usize,
) -> VerificationError {
    VerificationError::new(
        ErrorCode::ResourceLimitExceeded,
        Stage::Input,
        "host resource budget exhausted",
    )
    .detail("resource", resource)
    .detail("limit", limit)
    .detail("used", used)
    .detail("requested", requested)
}

// Read only bounded chunks; neither metadata nor Read::size_hint determines allocation.
pub(super) fn read_stream(mut reader: impl Read, limit: usize) -> io::Result<(Vec<u8>, bool)> {
    let mut result = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let available = (limit - result.len()).min(chunk.len());
        if available == 0 {
            let mut probe = [0];
            match reader.read(&mut probe) {
                Ok(n) => return Ok((result, n != 0)),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        match reader.read(&mut chunk[..available]) {
            Ok(0) => return Ok((result, false)),
            Ok(n) => result.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}
pub(super) fn read_file(path: &Path, limit: usize) -> io::Result<(Vec<u8>, bool)> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "only regular files are supported",
        ));
    }
    read_stream(file, limit)
}

pub(super) fn report_size(value: &impl Serialize, limit: usize) -> Result<usize, (usize, usize)> {
    struct Count {
        used: usize,
        limit: usize,
        requested: usize,
    }
    impl Write for Count {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > self.limit - self.used {
                self.requested = bytes.len();
                return Err(io::Error::other("report limit"));
            }
            self.used += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Count {
        used: 0,
        limit,
        requested: 0,
    };
    serde_json::to_writer(&mut counter, value).map_err(|_| (counter.used, counter.requested))?;
    Ok(counter.used)
}

pub(super) fn read_trust(path: &Path, remaining: &mut usize) -> anyhow::Result<Vec<u8>> {
    let limit = TRUST_FILE.min(*remaining);
    let (bytes, overflow) = read_file(path, limit)?;
    *remaining -= bytes.len();
    anyhow::ensure!(
        !overflow,
        "root/CRL input exceeds host byte budget ({limit} bytes available)"
    );
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sec03_stream_limits_handle_growth_short_reads_and_exact_eof() {
        let (bytes, exceeded) = read_stream(io::repeat(7), 17).unwrap();
        assert_eq!(bytes, vec![7; 17]);
        assert!(exceeded);
        for size in [0, 16, 17, 18] {
            let (bytes, exceeded) = read_stream(io::Cursor::new(vec![3; size]), 17).unwrap();
            assert_eq!(bytes.len(), size.min(17));
            assert_eq!(exceeded, size > 17);
        }
        struct Growing {
            read: usize,
        }
        impl Read for Growing {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                // Content remains available as if the file grew after metadata.
                bytes[0] = 1;
                self.read += 1;
                Ok(1)
            }
        }
        let mut growing = Growing { read: 0 };
        assert!(read_stream(&mut growing, 17).unwrap().1);
        assert_eq!(growing.read, 18);
    }
    #[test]
    fn sec03_report_count_rejects_without_allocating_encoded_output() {
        let error = report_size(&"x".repeat(1000), 20).unwrap_err();
        assert!(error.0 <= 20);
        assert!(error.1 > 20 - error.0);
        assert_eq!(report_size(&"abc", 5).unwrap(), 5);
    }
    #[cfg(unix)]
    #[test]
    fn sec03_nonregular_inputs_are_rejected_before_reading() {
        for path in [
            Path::new("/dev/zero"),
            Path::new(env!("CARGO_MANIFEST_DIR")),
        ] {
            let error = read_file(path, 10).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
    }
    #[test]
    fn sec03_trust_reads_share_the_allowance() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/root.der");
        let mut remaining = std::fs::metadata(&path).unwrap().len() as usize;
        assert!(!read_trust(&path, &mut remaining).unwrap().is_empty());
        assert_eq!(remaining, 0);
        assert!(read_trust(&path, &mut remaining).is_err());
    }
}
