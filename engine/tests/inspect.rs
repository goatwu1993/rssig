//! The engine's public interfaces that the application builds on, without the
//! CLI: unverified inspection reports, the trust store's size accessors, and
//! a caller-built log record. Inspection authenticates nothing.
#![cfg(feature = "verify-core")]
#[path = "common/crosscheck.rs"]
mod crosscheck;
use rssig_engine::{
    TrustStore,
    domain::{ErrorCode, Stage},
    inspect,
    log::{Level, Record},
    parse::Pe,
};

const PE: &[u8] = include_bytes!("../../tests/fixtures/good-pe64.exe");
const CAB: &[u8] = include_bytes!("../../tests/fixtures/good.cab");
const NAVX: &[u8] = include_bytes!("../../tests/fixtures/good.navx");

#[test]
fn inspection_reports_each_format_without_verifying() {
    let cms = Pe::parse(PE).unwrap().signatures().unwrap()[0];
    for (report, format) in [
        (inspect::pe(PE), "pe"),
        (inspect::cms(cms), "cms"),
        (inspect::cab(CAB), "cab"),
        (inspect::navx(NAVX), "navx"),
    ] {
        let report = report.unwrap();
        assert_eq!(report.format, format);
        assert!(!report.verification_performed);
        assert_eq!(report.signatures.len(), 1, "{format}");
    }
    // A tampered image still inspects: nothing is hashed or authenticated.
    let tampered =
        inspect::pe(include_bytes!("../../tests/fixtures/bad-image-digest.exe")).unwrap();
    assert!(!tampered.verification_performed);
    assert_eq!(tampered.signatures.len(), 1);
}

#[test]
fn inspection_rejects_other_formats_and_malformed_cms() {
    for error in [
        inspect::pe(CAB).unwrap_err(),
        inspect::cab(PE).unwrap_err(),
        inspect::navx(CAB).unwrap_err(),
        inspect::cms(PE).unwrap_err(),
    ] {
        assert_ne!(error.code, ErrorCode::InternalError, "{error:?}");
    }
    let error = inspect::cab(include_bytes!(
        "../../tests/fixtures/bad-cab-malformed-cms.cab"
    ))
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::MalformedCms);
    assert_eq!(error.stage, Stage::Cms);
}

/// CAB permits up to seven zero bytes after its CMS object; NAVX permits no
/// trailing data. Inspection applies each container's rule.
#[test]
fn inspection_applies_each_containers_cms_padding_rule() {
    // The committed cabinet ends in zero padding after its CMS object.
    assert_eq!(CAB.last(), Some(&0));
    assert!(inspect::cab(CAB).is_ok());
    let mut nonzero = CAB.to_vec();
    *nonzero.last_mut().unwrap() = 1;
    let error = inspect::cab(&nonzero).unwrap_err();
    assert_eq!(error.code, ErrorCode::MalformedCms);
    assert_eq!(error.stage, Stage::Cms);
    let error = inspect::navx(include_bytes!(
        "../../tests/fixtures/bad-navx-cms-trailing.navx"
    ))
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::MalformedCms);
    assert_eq!(error.stage, Stage::Cms);
}

#[test]
fn a_trust_store_reports_what_it_holds() {
    let root = include_bytes!("../../tests/fixtures/root.der");
    let crl = include_bytes!("../../tests/fixtures/good.crl");
    let mut store = TrustStore::default();
    assert_eq!(
        (store.root_count(), store.crl_count(), store.encoded_len()),
        (0, 0, 0)
    );
    store.add_roots(root).unwrap();
    store.add_crl(crl).unwrap();
    // Exact duplicates are kept once and counted once.
    store.add_roots(root).unwrap();
    store.add_crl(crl).unwrap();
    assert_eq!(store.root_count(), 1);
    assert_eq!(store.crl_count(), 1);
    assert_eq!(store.encoded_len(), root.len() + crl.len());
}

#[test]
fn an_application_builds_its_own_log_record() {
    fn check(record: &Record<'_>) {
        assert_eq!(record.level, Level::Debug);
        assert_eq!(record.stage, Stage::Input);
        assert_eq!(record.message.to_string(), "reading 3 bytes");
    }
    let bytes = 3;
    // Built and used in one statement, as a logger call does: the formatted
    // arguments borrow temporaries.
    check(&Record::new(
        Level::Debug,
        Stage::Input,
        format_args!("reading {bytes} bytes"),
    ));
}

#[cfg(feature = "retrieval")]
#[test]
fn a_retrieval_limit_error_has_the_details_every_limit_reports() {
    let error = rssig_engine::retrieval::limit("crl_http_requests", 16, 16, 1);
    assert_eq!(error.code, ErrorCode::ResourceLimitExceeded);
    assert_eq!(error.stage, Stage::Revocation);
    assert_eq!(error.details["resource"], "crl_http_requests");
    assert_eq!(error.details["limit"], 16);
    assert_eq!(error.details["used"], 16);
    assert_eq!(error.details["requested"], 1);
}
