//! The rssig application: the command-line verifier and the default
//! collaborators the engine ([`rssig_engine`], re-exported as [`engine`])
//! leaves to its caller.
//!
//! The engine is pure logic over explicit inputs and policy. This package
//! decides what an application supplies by default:
//!
//! - `cli`: argv, files, the clock, host limits, default policy and the
//!   JSON stream and exit-code contract (feature `cli`);
//! - `crl::HttpCrlSource`: the default `engine::retrieval::CrlSource`,
//!   bounded public HTTP (feature `crl-fetch`);
//! - `roots::system_roots`: the operating system's root store as an
//!   [`engine::TrustStore`] (feature `system-roots`).
//!
//! A library that brings its own roots, CRLs and clock needs only the engine.

/// The engine, re-exported so an embedder of `cli` can name the types its
/// collaborators implement (`CrlSource`, `Logger`) without a second
/// dependency.
pub use rssig_engine as engine;

#[cfg(feature = "cli")]
pub mod cli;
#[cfg(feature = "crl-fetch")]
pub mod crl;
#[cfg(feature = "system-roots")]
pub mod roots;

// The application's own unit tests (`src/crl.rs`, `src/roots.rs`) take the
// same guard as its integration tests (tests/common/crosscheck.rs).
#[cfg(test)]
#[path = "../tests/common/crosscheck.rs"]
mod crosscheck;
