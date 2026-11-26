//! Caller-injected diagnostic logging. The engine has no global logger, writes to
//! no stream, and emits nothing unless a [`Logger`] is supplied.
//!
//! Records are diagnostics for people. They never carry a verdict: only the
//! returned [`VerificationBundle`](crate::VerificationBundle) or
//! [`VerificationError`](crate::VerificationError) states an outcome, and a
//! logger cannot change it. Match error codes and report fields, never messages.
use crate::domain::Stage;
use core::fmt;

/// Severity, ordered so that `level >= Level::Info` filters out debug records.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum Level {
    /// Step-by-step progress through one verification.
    Debug,
    /// Notable events: a verified signer, a CRL request.
    Info,
    /// An explicitly weakened policy, or the failure that ended verification.
    Warn,
}

/// One diagnostic event. `message` is formatted only if the logger reads it.
///
/// Messages are unstable prose and may quote text derived from the untrusted
/// input (certificate subjects, CRL URLs). Such text is Rust-debug-escaped, but
/// a sink must still treat every message as untrusted data.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Record<'a> {
    pub level: Level,
    /// The verification stage that produced the record.
    pub stage: Stage,
    pub message: fmt::Arguments<'a>,
}

impl<'a> Record<'a> {
    /// For an application that reports its own steps (reading a file, say)
    /// through the logger it injects into the engine.
    pub fn new(level: Level, stage: Stage, message: fmt::Arguments<'a>) -> Self {
        Self {
            level,
            stage,
            message,
        }
    }
}

/// A diagnostic sink supplied by the caller.
///
/// `Sync` keeps verification shareable across threads; use atomics or a lock for
/// interior state. Logging is not charged to verification budgets, so a sink
/// bounds its own retention and I/O. Do not panic or block indefinitely in `log`.
pub trait Logger: Sync {
    /// Return `false` to skip records of `level` before they are built.
    fn enabled(&self, level: Level) -> bool {
        let _ = level;
        true
    }
    fn log(&self, record: &Record<'_>);
}

/// The optional sink for one verification, carried beside its work budget.
#[derive(Clone, Copy, Default)]
pub(crate) struct Sink<'a>(pub(crate) Option<&'a dyn Logger>);

impl fmt::Debug for Sink<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.0.is_some() {
            "Sink(Some(..))"
        } else {
            "Sink(None)"
        })
    }
}

impl Sink<'_> {
    pub(crate) fn emit(&self, level: Level, stage: Stage, message: fmt::Arguments<'_>) {
        if let Some(logger) = self.0
            && logger.enabled(level)
        {
            logger.log(&Record {
                level,
                stage,
                message,
            });
        }
    }
    pub(crate) fn debug(&self, stage: Stage, message: fmt::Arguments<'_>) {
        self.emit(Level::Debug, stage, message);
    }
    pub(crate) fn info(&self, stage: Stage, message: fmt::Arguments<'_>) {
        self.emit(Level::Info, stage, message);
    }
    pub(crate) fn warn(&self, stage: Stage, message: fmt::Arguments<'_>) {
        self.emit(Level::Warn, stage, message);
    }
}
