//! SEC-10 CRL applicability: unusable CRLs outside the chain are excluded. A CRL
//! from a chain issuer that is stale or structurally invalid fails closed when it
//! is the only one for the certificate, and is set aside when another CRL of
//! that issuer is usable (the best CRL decides, as in OpenSSL and Bouncy Castle).
//! The cRLSign tests use the SEC-06 chain, whose issuer variants differ only in
//! KeyUsage. The distribution-point tests use SEC-06 signers and one intermediate
//! that list CRL distribution points in several forms, issuer and root CRLs
//! scoped by issuingDistributionPoint, and a root CRL revoking the intermediate.

use super::support::*;

const T: &str = "1800000000";

fn run_with(extra: &str) -> Output {
    run_fixture(
        "good-countersignature.exe",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--crl",
            &format!("fixtures/{extra}"),
            "--time",
            T,
        ],
    )
}

/// The chain issuer's CRL `crl` alone, without `good.crl`.
fn run_alone(crl: &str) -> Output {
    run_fixture(
        "good-countersignature.exe",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            &format!("fixtures/{crl}"),
            "--time",
            T,
        ],
    )
}

#[test]
fn sec10_an_unusable_chain_issuer_crl_is_set_aside_beside_a_usable_one() {
    for extra in [
        "sec10-root-no-next-update.crl",
        "expired.crl",
        "sec10-root-aki-expired.crl",
        "sec10-root-malformed-aki.crl",
        "sec10-root-signed-other-aki-expired.crl",
        "sec10-root-unknown-critical-extension.crl",
        "sec10-root-delta.crl",
        "sec10-root-indirect.crl",
        "sec10-root-entry-critical-extension.crl",
        "sec10-root-delta-expired.crl",
        "sec10-root-idp-user-certs.crl",
        "sec10-root-idp-ca-certs.crl",
        "sec10-root-aki-issuer-serial-expired.crl",
        "sec10-root-idp-named-point.crl",
    ] {
        let output = run_with(extra);
        expect_success(&output);
        assert_eq!(
            output.json["results"][0]["signatures"][0]["trust"]["revocation"]["status"], "good",
            "{extra}"
        );
    }
}

#[test]
fn sec10_unrelated_issuer_crls_are_excluded_whatever_their_fault() {
    for extra in [
        "sec10-unrelated-expired.crl",
        "sec10-unrelated-not-yet-valid.crl",
        "sec10-unrelated-no-next-update.crl",
    ] {
        let output = run_with(extra);
        expect_success(&output);
        assert_eq!(
            output.json["results"][0]["signatures"][0]["trust"]["revocation"]["status"], "good",
            "{extra}"
        );
    }
}

#[test]
fn sec10_chain_issuer_crl_without_next_update_is_a_typed_revocation_failure() {
    let output = run_alone("sec10-root-no-next-update.crl");
    expect_failure(
        &output,
        1,
        "invalid_crl",
        "Invalid CRL",
        Some("revocation"),
        Some("nextUpdate"),
    );
}

#[test]
fn sec10_chain_issuer_stale_crl_still_fails_closed() {
    let output = run_alone("expired.crl");
    expect_failure(
        &output,
        1,
        "crl_expired",
        "CRL expired",
        Some("revocation"),
        None,
    );
    assert_eq!(
        output.json["results"][0]["error"]["details"]["validation_time"],
        1_800_000_000u64
    );
}

#[test]
fn sec10_only_unrelated_crls_leave_revocation_unknown() {
    let output = run_fixture(
        "good-countersignature.exe",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/sec10-unrelated-expired.crl",
            "--time",
            T,
        ],
    );
    expect_failure(
        &output,
        1,
        "revocation_unknown",
        "Revocation status unknown",
        Some("revocation"),
        None,
    );
}

#[test]
fn sec10_crl_naming_another_authority_key_is_excluded() {
    // Same issuer name as the root, but its authorityKeyIdentifier names a
    // different key, so it cannot be the CRL of the chain's issuer.
    expect_success(&run_with("sec10-root-name-other-aki-expired.crl"));
}

#[test]
fn sec10_crl_naming_the_issuer_key_still_fails_closed_when_stale() {
    let output = run_alone("sec10-root-aki-expired.crl");
    expect_failure(
        &output,
        1,
        "crl_expired",
        "CRL expired",
        Some("revocation"),
        None,
    );
}

#[test]
fn sec10_malformed_authority_key_identifier_fails_closed() {
    let output = run_alone("sec10-root-malformed-aki.crl");
    expect_failure(
        &output,
        1,
        "invalid_crl",
        "Invalid CRL",
        Some("revocation"),
        Some("authorityKeyIdentifier"),
    );
}

#[test]
fn sec10_chain_issuer_signature_is_never_excluded_by_a_mismatched_aki() {
    // Signed by the root's own key, so a differing authorityKeyIdentifier
    // cannot make it irrelevant: the stale CRL still fails closed.
    let output = run_alone("sec10-root-signed-other-aki-expired.crl");
    expect_failure(
        &output,
        1,
        "crl_expired",
        "CRL expired",
        Some("revocation"),
        None,
    );
}

#[test]
fn sec10_unrelated_crl_with_malformed_aki_is_excluded() {
    expect_success(&run_with("sec10-unrelated-malformed-aki.crl"));
}

#[test]
fn sec10_unsupported_crl_features_from_a_chain_issuer_are_typed() {
    for (file, reason) in [
        (
            "sec10-root-unknown-critical-extension.crl",
            "unknown_critical_extension",
        ),
        (
            "sec10-root-entry-critical-extension.crl",
            "unknown_critical_extension",
        ),
        (
            "sec10-root-idp-user-certs.crl",
            "issuing_distribution_point",
        ),
        ("sec10-root-idp-ca-certs.crl", "issuing_distribution_point"),
        ("sec10-root-delta.crl", "delta_crl"),
        ("sec10-root-delta-expired.crl", "delta_crl"),
        ("sec10-root-indirect.crl", "indirect_crl"),
    ] {
        let output = run_alone(file);
        expect_failure(
            &output,
            1,
            "invalid_crl",
            "Invalid CRL",
            Some("revocation"),
            None,
        );
        let details = &output.json["results"][0]["error"]["details"];
        assert_eq!(details["reason"], reason, "{file}");
        assert!(details["crl"]["der_hex"].is_string(), "{file}");
    }
}

#[test]
fn sec10_unknown_noncritical_crl_extension_is_ignored() {
    expect_success(&run_with("sec10-root-unknown-noncritical-extension.crl"));
}

fn run_sec06(input: &str) -> Output {
    run_sec06_crls(input, &["sec06-issuer.crl"])
}

#[test]
fn sec10_crl_from_an_issuer_without_crl_sign_is_rejected() {
    let output = run_sec06("sec10-ca-no-crl-sign.exe");
    expect_failure(
        &output,
        1,
        "invalid_key_usage",
        "Invalid key usage",
        Some("revocation"),
        None,
    );
}

#[test]
fn sec10_crl_from_an_issuer_with_crl_sign_is_used() {
    revocation_good(&run_sec06("sec10-ca-crl-sign.exe"));
}

#[test]
fn sec10_path_building_falls_back_to_the_issuer_with_crl_sign() {
    let fallback = run_sec06("sec10-ca-crl-sign-fallback.exe");
    let usable = run_sec06("sec10-ca-crl-sign.exe");
    expect_success(&fallback);
    let chain =
        |output: &Output| output.json["results"][0]["signatures"][0]["trust"]["chain"].clone();
    assert_eq!(chain(&fallback), chain(&usable));
}

#[test]
fn sec10_aki_without_key_identifier_is_matched_by_issuer_name() {
    // authorityCertIssuer/serial alone cannot exclude a CRL: the stale CRL
    // from the chain issuer's name still fails closed.
    let output = run_alone("sec10-root-aki-issuer-serial-expired.crl");
    expect_failure(
        &output,
        1,
        "crl_expired",
        "CRL expired",
        Some("revocation"),
        None,
    );
}

#[test]
fn sec10_named_distribution_point_crl_without_matching_certificate_point_fails_closed() {
    // The signer lists no CRL distribution points, so a CRL scoped to a named
    // point may be a partition that does not cover it.
    let output = run_alone("sec10-root-idp-named-point.crl");
    expect_failure(
        &output,
        1,
        "invalid_crl",
        "Invalid CRL",
        Some("revocation"),
        None,
    );
    let details = &output.json["results"][0]["error"]["details"];
    assert_eq!(details["reason"], "distribution_point_scope");
}

fn run_sec06_root(root: &str) -> Output {
    run_sec06_with(root, "good-sec06-basic.exe", &["sec06-issuer.crl"])
}

#[test]
fn sec10_crl_from_a_root_without_crl_sign_is_used() {
    // Configured anchors are keys: their KeyUsage does not restrict CRL signing.
    revocation_good(&run_sec06_root("sec10-root-no-crl-sign.der"));
}

#[test]
fn sec10_revocation_in_any_applicable_crl_wins_regardless_of_order() {
    for crls in [["good.crl", "revoked.crl"], ["revoked.crl", "good.crl"]] {
        let output = run_fixture(
            "good-countersignature.exe",
            &[
                "verify",
                "--no-system-roots",
                "--roots",
                "fixtures/root.der",
                "--crl",
                &format!("fixtures/{}", crls[0]),
                "--crl",
                &format!("fixtures/{}", crls[1]),
                "--time",
                T,
            ],
        );
        expect_failure(
            &output,
            1,
            "certificate_revoked",
            "Certificate revoked",
            Some("revocation"),
            None,
        );
    }
}

/// Verify a SEC-06 chain input with the root CRL and these issuer CRLs, in order.
fn run_sec06_crls(input: &str, crls: &[&str]) -> Output {
    run_sec06_with("sec06-root.der", input, crls)
}

fn run_sec06_with(root: &str, input: &str, crls: &[&str]) -> Output {
    let crls: Vec<&str> = ["sec06-root.crl"]
        .into_iter()
        .chain(crls.iter().copied())
        .collect();
    run_sec06_exact(root, input, &crls)
}

/// Verify a SEC-06 chain input with exactly these CRLs, in order.
fn run_sec06_exact(root: &str, input: &str, crls: &[&str]) -> Output {
    let mut args = vec![
        "verify".to_string(),
        "--no-system-roots".into(),
        "--roots".into(),
        format!("fixtures/{root}"),
        "--time".into(),
        T.into(),
    ];
    for crl in crls {
        args.extend(["--crl".into(), format!("fixtures/{crl}")]);
    }
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    run_fixture(input, &args)
}

/// The signer that lists distribution point A.
fn run_crl_dp(crls: &[&str]) -> Output {
    run_sec06_crls("sec10-leaf-crl-dp.exe", crls)
}

fn revocation_failure(output: &Output, code: &str, title: &str) {
    expect_failure(output, 1, code, title, Some("revocation"), None);
}

fn revocation_good(output: &Output) {
    expect_success(output);
    let trust = &output.json["results"][0]["signatures"][0]["trust"];
    assert_eq!(trust["revocation"]["status"], "good");
    assert_eq!(trust["chain"].as_array().unwrap().len(), 3);
}

#[test]
fn sec10_crl_scoped_to_the_listed_distribution_point_is_authoritative() {
    revocation_good(&run_crl_dp(&["sec10-issuer-idp-match.crl"]));
    revocation_failure(
        &run_crl_dp(&["sec10-issuer-idp-match-revoked.crl"]),
        "certificate_revoked",
        "Certificate revoked",
    );
}

#[test]
fn sec10_crl_scoped_to_another_distribution_point_leaves_status_unknown() {
    // The second URI differs from the listed point only in letter case.
    for crl in ["sec10-issuer-idp-other.crl", "sec10-issuer-idp-case.crl"] {
        unknown(&run_crl_dp(&[crl]));
    }
}

#[test]
fn sec10_listing_by_a_non_authoritative_partition_alone_leaves_status_unknown() {
    // A listed serial counts only on a path where every certificate has an
    // authoritative CRL. A partition that is not authoritative for the signer
    // is not enough evidence on its own to call it revoked.
    unknown(&run_crl_dp(&["sec10-issuer-idp-other-revoked.crl"]));
}

#[test]
fn sec10_matching_partition_is_selected_whatever_the_crl_order() {
    let first = run_crl_dp(&["sec10-issuer-idp-other.crl", "sec10-issuer-idp-match.crl"]);
    let last = run_crl_dp(&["sec10-issuer-idp-match.crl", "sec10-issuer-idp-other.crl"]);
    revocation_good(&first);
    revocation_good(&last);
}

#[test]
fn sec10_revocation_in_another_partition_of_the_issuer_still_rejects() {
    // On a path whose certificates all have an authoritative CRL, a serial
    // listed by another applicable CRL of the same issuer name also rejects.
    for crls in [
        [
            "sec10-issuer-idp-match.crl",
            "sec10-issuer-idp-other-revoked.crl",
        ],
        [
            "sec10-issuer-idp-other-revoked.crl",
            "sec10-issuer-idp-match.crl",
        ],
    ] {
        revocation_failure(
            &run_crl_dp(&crls),
            "certificate_revoked",
            "Certificate revoked",
        );
    }
}

#[test]
fn sec10_full_crl_covers_a_certificate_that_lists_a_distribution_point() {
    revocation_good(&run_crl_dp(&["sec06-issuer.crl"]));
    // The full CRL is authoritative even next to a non-matching partition.
    revocation_good(&run_crl_dp(&[
        "sec10-issuer-idp-other.crl",
        "sec06-issuer.crl",
    ]));
}

#[test]
fn sec10_partition_crl_is_rejected_for_a_signer_listing_no_distribution_point() {
    // The same matching-partition CRL, but the base SEC-06 leaf lists no point.
    let output = run_sec06_crls("good-sec06-basic.exe", &["sec10-issuer-idp-match.crl"]);
    revocation_failure(&output, "invalid_crl", "Invalid CRL");
    assert_eq!(
        output.json["results"][0]["error"]["details"]["reason"],
        "distribution_point_scope"
    );
}

fn unknown(output: &Output) {
    revocation_failure(output, "revocation_unknown", "Revocation status unknown");
}

#[test]
fn sec10_scope_flag_with_a_named_point_restricts_the_signer_role() {
    // Both CRLs name the signer's listed point; only the role scope differs.
    revocation_good(&run_crl_dp(&["sec10-issuer-idp-match-user.crl"]));
    unknown(&run_crl_dp(&["sec10-issuer-idp-match-ca.crl"]));
}

#[test]
fn sec10_scope_flag_with_a_named_point_restricts_the_issuer_role() {
    // The intermediate lists a point; the root CRLs name it with a role scope.
    let run = |root_crl: &str| {
        run_sec06_exact(
            "sec06-root.der",
            "sec10-ca-crl-dp.exe",
            &[root_crl, "sec06-issuer.crl"],
        )
    };
    revocation_good(&run("sec10-sec06-root-idp-ca.crl"));
    unknown(&run("sec10-sec06-root-idp-user.crl"));
}

#[test]
fn sec10_any_matching_uri_among_several_names_or_points_is_authoritative() {
    // The CRL's second name is the signer's listed point.
    revocation_good(&run_crl_dp(&["sec10-issuer-idp-two-names.crl"]));
    // The CRL names the second name of the signer's second point.
    let multi = "sec10-leaf-crl-dp-multi.exe";
    revocation_good(&run_sec06_crls(
        multi,
        &["sec10-issuer-idp-second-point.crl"],
    ));
    // A point the multi-point signer does not list.
    unknown(&run_sec06_crls(multi, &["sec10-issuer-idp-match.crl"]));
}

#[test]
fn sec10_non_uri_and_issuer_relative_names_never_match() {
    // The same dNSName on both sides is not compared.
    unknown(&run_sec06_crls(
        "sec10-leaf-crl-dp-dns.exe",
        &["sec10-issuer-idp-dns.crl"],
    ));
    // The CRL names the directoryName that the signer's issuer-relative name
    // expands to; relative names are not expanded.
    let relative = "sec10-leaf-crl-dp-relative.exe";
    unknown(&run_sec06_crls(
        relative,
        &["sec10-issuer-idp-relative-expanded.crl"],
    ));
}

#[test]
fn sec10_crl_scoped_by_an_issuer_relative_name_is_rejected() {
    let reason = |output: &Output| {
        revocation_failure(output, "invalid_crl", "Invalid CRL");
        output.json["results"][0]["error"]["details"]["reason"].clone()
    };
    let crl = ["sec10-issuer-idp-relative.crl"];
    // Unsupported form when every covered certificate lists a point.
    assert_eq!(
        reason(&run_sec06_crls("sec10-leaf-crl-dp-relative.exe", &crl)),
        "issuing_distribution_point"
    );
    // The scope rule is checked first for a signer that lists no point.
    assert_eq!(
        reason(&run_sec06_crls("good-sec06-basic.exe", &crl)),
        "distribution_point_scope"
    );
}

#[test]
fn sec10_certificate_point_with_reasons_or_crl_issuer_never_matches() {
    // Each signer lists the URI that the partition CRL names.
    for signer in [
        "sec10-leaf-crl-dp-reasons.exe",
        "sec10-leaf-crl-dp-crl-issuer.exe",
    ] {
        unknown(&run_sec06_crls(signer, &["sec10-issuer-idp-match.crl"]));
    }
}

#[test]
fn sec10_full_crl_covers_every_distribution_point_form() {
    for signer in [
        "sec10-leaf-crl-dp-multi.exe",
        "sec10-leaf-crl-dp-dns.exe",
        "sec10-leaf-crl-dp-relative.exe",
        "sec10-leaf-crl-dp-reasons.exe",
        "sec10-leaf-crl-dp-crl-issuer.exe",
    ] {
        revocation_good(&run_sec06_crls(signer, &["sec06-issuer.crl"]));
    }
}

#[test]
fn sec10_revoked_intermediate_is_rejected_whatever_the_crl_order() {
    let revoked = "sec10-sec06-root-revoked-issuer.crl";
    for crls in [
        vec![revoked, "sec06-issuer.crl"],
        vec!["sec06-issuer.crl", revoked],
        vec!["sec06-root.crl", revoked, "sec06-issuer.crl"],
        vec![revoked, "sec06-root.crl", "sec06-issuer.crl"],
    ] {
        let output = run_sec06_exact("sec06-root.der", "good-sec06-basic.exe", &crls);
        revocation_failure(&output, "certificate_revoked", "Certificate revoked");
    }
}

/// Two candidate paths: the cross certificate under the other root, which
/// that root's CRL revokes, and the issuer under the root. Without the root's
/// CRL the revocation decides, as without retrieval nothing can complete the
/// second path, and the second path's gap is named for a CRL source; with
/// that CRL, the second path verifies.
#[test]
fn sec10_a_revoked_path_names_what_another_path_still_lacks() {
    let run = |extra: &[&str]| {
        let mut args = vec![
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/sec06-root.der",
            "--roots",
            "fixtures/sec06-other-root.der",
            "--time",
            T,
            "--crl",
            "fixtures/sec06-issuer.crl",
            "--crl",
            "fixtures/sec10-sec06-other-root-revoked-cross.crl",
        ];
        args.extend_from_slice(extra);
        run_fixture("good-sec06-cross-first.exe", &args)
    };
    let output = run(&[]);
    revocation_failure(&output, "certificate_revoked", "Certificate revoked");
    let details = &output.json["results"][0]["error"]["details"];
    let missing = details["certificates_without_crl"].as_array().unwrap();
    assert_eq!(missing.len(), 1);
    assert_eq!(missing[0]["subject"]["display"], "CN=SEC-06 issuer");
    revocation_good(&run(&["--crl", "fixtures/sec06-root.crl"]));
}

/// The other path's cross certificate lacks keyCertSign, so a CRL for it could
/// not make it verify: the revocation on the first path decides, whether or
/// not the other path has a CRL.
#[test]
fn sec10_a_revoked_path_decides_when_the_other_path_fails_key_usage() {
    let run = |extra: &[&str]| {
        let mut args = vec![
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/sec06-root.der",
            "--roots",
            "fixtures/sec06-other-root.der",
            "--time",
            T,
            "--crl",
            "fixtures/sec06-issuer.crl",
            "--crl",
            "fixtures/sec10-sec06-root-revoked-issuer.crl",
        ];
        args.extend_from_slice(extra);
        run_fixture("sec10-sec06-cross-no-cert-sign.exe", &args)
    };
    for extra in [&[][..], &["--crl", "fixtures/sec06-other-root.crl"]] {
        let output = run(extra);
        revocation_failure(&output, "certificate_revoked", "Certificate revoked");
        assert!(
            output.json["results"][0]["error"]["details"]
                .get("certificates_without_crl")
                .is_none()
        );
    }
}

/// The issuer under the root has only an unusable root CRL (scoped to a
/// point it does not list); the cross path fails keyCertSign and lacks a
/// CRL. Only the path that could verify decides: its CRL failure is
/// reported, not an unknown status naming the blocked path's certificate.
#[test]
fn sec10_an_unknown_status_ignores_a_path_failing_key_usage() {
    let output = run_fixture(
        "sec10-sec06-cross-no-cert-sign.exe",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/sec06-root.der",
            "--roots",
            "fixtures/sec06-other-root.der",
            "--time",
            T,
            "--crl",
            "fixtures/sec06-issuer.crl",
            "--crl",
            "fixtures/sec10-sec06-root-idp-ca.crl",
        ],
    );
    revocation_failure(&output, "invalid_crl", "Invalid CRL");
    assert_eq!(
        output.json["results"][0]["error"]["details"]["reason"],
        "distribution_point_scope"
    );
}

/// `good.crl`: thisUpdate and nextUpdate in seconds.
const CRL_THIS_UPDATE: u64 = 1_799_999_900;
const CRL_NEXT_UPDATE: u64 = 1_800_001_000;

/// An untimestamped signer, so the validation time is the pinned `--time`.
fn run_at(time: u64) -> Output {
    run_fixture(
        "good-pe64.exe",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            &time.to_string(),
        ],
    )
}

fn fresh_at(time: u64) {
    let output = run_at(time);
    expect_success(&output);
    let signature = &output.json["results"][0]["signatures"][0];
    assert!(signature["timestamp"].is_null());
    assert_eq!(signature["trust"]["validation_time"], time);
    assert_eq!(signature["trust"]["revocation"]["status"], "good");
}

fn stale_at(time: u64, code: &str, title: &str) {
    let output = run_at(time);
    revocation_failure(&output, code, title);
    let details = &output.json["results"][0]["error"]["details"];
    assert_eq!(details["validation_time"], time);
    assert_eq!(details["crl"]["this_update"], CRL_THIS_UPDATE);
    assert_eq!(details["crl"]["next_update"], CRL_NEXT_UPDATE);
}

#[test]
fn sec10_crl_this_update_is_an_inclusive_lower_bound() {
    stale_at(
        CRL_THIS_UPDATE - 1,
        "crl_not_yet_valid",
        "CRL not yet valid",
    );
    fresh_at(CRL_THIS_UPDATE);
}

#[test]
fn sec10_crl_next_update_is_an_exclusive_upper_bound() {
    fresh_at(CRL_NEXT_UPDATE - 1);
    stale_at(CRL_NEXT_UPDATE, "crl_expired", "CRL expired");
}

#[test]
fn sec10_a_revocation_in_a_stale_crl_does_not_count_beside_a_fresh_one() {
    // The fresh CRL decides and does not list the signer. The expired one
    // does, but a listing counts only from a current CRL, as in OpenSSL and
    // Bouncy Castle: it may be a hold that was since released.
    let output = run_with("sec10-root-expired-revoked.crl");
    expect_success(&output);
    assert_eq!(
        output.json["results"][0]["signatures"][0]["trust"]["revocation"]["status"],
        "good"
    );
    // Alone, the stale CRL is not usable evidence: expired, not revoked.
    let output = run_alone("sec10-root-expired-revoked.crl");
    revocation_failure(&output, "crl_expired", "CRL expired");
}

#[test]
fn sec10_an_expired_partition_for_another_point_does_not_decide_the_signer() {
    // Not authoritative for the signer, so its age is irrelevant: the status
    // is unknown and the signer is named, not crl_expired.
    let output = run_crl_dp(&["sec06-root.crl", "sec10-issuer-idp-other-expired.crl"]);
    revocation_failure(&output, "revocation_unknown", "Revocation status unknown");
    let missing = &output.json["results"][0]["error"]["details"]["certificates_without_crl"];
    assert_eq!(missing.as_array().unwrap().len(), 1);
    assert_eq!(
        missing[0]["sha256"],
        "53af4ab427625a14a3f148cb35f101dd2c79725123085d301dec3df57dc419a1"
    );
}

#[test]
fn sec10_a_listing_in_an_authenticated_crl_counts_even_with_a_malformed_aki() {
    // The root signed it, so its listing of the signer counts beside good.crl,
    // although its authorityKeyIdentifier cannot be decoded.
    let output = run_with("sec10-root-malformed-aki-revoked.crl");
    revocation_failure(&output, "certificate_revoked", "Certificate revoked");
}
