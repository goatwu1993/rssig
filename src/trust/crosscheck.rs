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
use super::{ChosenCrl, LoadedCrl};
use crate::crypto::ALGORITHMS;
use alloc::vec::Vec;
use core::time::Duration;
use rustls_pki_types::{CertificateDer, UnixTime};

/// Panic unless webpki rejects the accepted path exactly when rssig does.
/// `rejects` is rssig's decision for the path after its per-certificate
/// evaluation accepted every certificate on it.
pub(super) fn confirm(
    leaf: &webpki::EndEntityCert<'_>,
    path: &webpki::VerifiedPath<'_>,
    validation_time: u64,
    eku: &'static [u8],
    chosen: &[ChosenCrl],
    crls: &[LoadedCrl],
    rejects: bool,
) {
    // webpki picks a CRL by issuer name alone. When two issuers of one name
    // with different keys each have a CRL naming its key, rssig gives each
    // certificate its own key's CRL; webpki can only check the signer with
    // the signer's CRL. This is the rule the production check used.
    let key_rollover = {
        let mut two_keys = false;
        let mut all_named = true;
        for (position, first) in chosen.iter().enumerate() {
            for second in &chosen[position + 1..] {
                if first.index == second.index
                    || crls[first.index].issuer != crls[second.index].issuer
                {
                    continue;
                }
                all_named &= first.names_issuer && second.names_issuer;
                two_keys |= crls[first.index].authority_key != crls[second.index].authority_key;
            }
        }
        two_keys && all_named
    };
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
