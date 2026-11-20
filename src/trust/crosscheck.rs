//! Test-only revocation cross-check (SEC-24), compiled only with the
//! `revocation-crosscheck` feature, which only the test targets enable.
//!
//! rssig decides revocation alone. This module re-runs webpki's own
//! revocation check on the accepted path with the CRLs rssig chose, the check
//! rssig ran in production before SEC-24, and panics if the two disagree. It
//! guards the parts webpki can judge independently: serial lookup, the CRL
//! signature under the adapter, scope and expiry of the chosen CRLs. It
//! cannot judge which CRL rssig chose.
//!
//! It never changes a result: the unbudgeted algorithms are used so budgets
//! are not charged, and nothing is logged.
use super::{ChosenCrl, LoadedCrl, same_name_different_keys};
use crate::crypto::ALGORITHMS;
use alloc::vec::Vec;
use core::time::Duration;
use rustls_pki_types::{CertificateDer, UnixTime};

/// Panic unless webpki rejects the accepted path exactly when rssig does.
/// `rejects` is rssig's decision for the path after its per-certificate
/// evaluation accepted every certificate on it.
///
/// webpki judges CRL freshness at `validation_time`, rssig at `now`. They
/// cannot disagree on freshness: a timestamp later than `now` is rejected
/// (`timestamp_in_future`, pinned in `tests/cases.json`), so
/// `validation_time <= now`, and a CRL current at `now` is current at any
/// earlier time.
pub(super) fn confirm(
    leaf: &webpki::EndEntityCert<'_>,
    path: &webpki::VerifiedPath<'_>,
    validation_time: u64,
    eku: &'static [u8],
    chosen: &[ChosenCrl],
    crls: &[LoadedCrl],
    rejects: bool,
) {
    // webpki picks a CRL by issuer name alone. On a self-issued key rollover
    // whose CRLs each name their issuer's key (two issuers of one name with
    // different keys), rssig gives each certificate its own key's CRL; webpki
    // can only check the signer with the signer's CRL. Decided from the CRL
    // data, not from `rejects`, so a wrong rssig verdict cannot hide itself.
    // The pairs come from the helper rssig's own rule uses, so they cannot
    // drift.
    let key_rollover = same_name_different_keys(chosen, crls).next().is_some()
        && same_name_different_keys(chosen, crls)
            .all(|(first, second)| first.names_issuer && second.names_issuer);
    let mut indices: Vec<usize> = if key_rollover {
        chosen.iter().take(1).map(|c| c.index).collect()
    } else {
        chosen.iter().map(|c| c.index).collect()
    };
    indices.sort_unstable();
    indices.dedup();
    let picked: Vec<webpki::CertRevocationList<'_>> = indices
        .iter()
        .filter_map(|&index| crls[index].webpki.clone().ok())
        .map(webpki::CertRevocationList::from)
        .collect();
    // No oracle when webpki cannot use a chosen CRL (a feature rssig may
    // support and webpki does not) or when nothing was chosen.
    if picked.is_empty() || picked.len() != indices.len() {
        return;
    }
    let picked_refs: Vec<_> = picked.iter().collect();
    let Ok(options) = webpki::RevocationOptionsBuilder::new(&picked_refs) else {
        return;
    };
    let options = options
        .with_depth(if key_rollover {
            webpki::RevocationCheckDepth::EndEntity
        } else {
            webpki::RevocationCheckDepth::Chain
        })
        .with_status_policy(webpki::UnknownStatusPolicy::Deny)
        .with_expiration_policy(webpki::ExpirationPolicy::Enforce)
        .build();
    let intermediates: Vec<CertificateDer<'static>> = path
        .intermediate_certificates()
        .map(|c| c.der().clone().into_owned())
        .collect();
    let anchor = [path.anchor().clone()];
    let confirmed = leaf.verify_for_usage(
        ALGORITHMS,
        &anchor,
        &intermediates,
        UnixTime::since_unix_epoch(Duration::from_secs(validation_time)),
        webpki::KeyUsage::required_if_present(eku),
        Some(options),
        None,
    );
    assert!(
        confirmed.is_err() == rejects,
        "SEC-24 revocation cross-check: rssig {} the accepted path, webpki returned {:?}",
        if rejects { "rejects" } else { "accepts" },
        confirmed.err(),
    );
}
