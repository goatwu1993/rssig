//! CRL-T001 CRL applicability: unusable CRLs outside the chain are excluded. A CRL
//! from a chain issuer that is stale or structurally invalid fails closed when it
//! is the only one for the certificate, and is set aside when another CRL of
//! that issuer is usable (the best CRL decides, as in OpenSSL and Bouncy Castle).
//! The cRLSign tests use the PATH-T001 chain, whose issuer variants differ only in
//! KeyUsage. The distribution-point tests use PATH-T001 signers and one intermediate
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
fn crl_an_unusable_chain_issuer_crl_is_set_aside_beside_a_usable_one() {
    for extra in [
        "crl-root-no-next-update.crl",
        "expired.crl",
        "crl-root-aki-expired.crl",
        "crl-root-malformed-aki.crl",
        "crl-root-signed-other-aki-expired.crl",
        "crl-root-unknown-critical-extension.crl",
        "crl-root-delta.crl",
        "crl-root-indirect.crl",
        "crl-root-entry-critical-extension.crl",
        "crl-root-delta-expired.crl",
        "crl-root-idp-user-certs.crl",
        "crl-root-idp-ca-certs.crl",
        "crl-root-aki-issuer-serial-expired.crl",
        "crl-root-idp-named-point.crl",
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
fn crl_unrelated_issuer_crls_are_excluded_whatever_their_fault() {
    for extra in [
        "crl-unrelated-expired.crl",
        "crl-unrelated-not-yet-valid.crl",
        "crl-unrelated-no-next-update.crl",
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
fn crl_chain_issuer_crl_without_next_update_is_a_typed_revocation_failure() {
    let output = run_alone("crl-root-no-next-update.crl");
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
fn crl_chain_issuer_stale_crl_still_fails_closed() {
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
fn crl_only_unrelated_crls_leave_revocation_unknown() {
    let output = run_fixture(
        "good-countersignature.exe",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/crl-unrelated-expired.crl",
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
fn crl_naming_another_authority_key_is_excluded() {
    // Same issuer name as the root, but its authorityKeyIdentifier names a
    // different key, so it cannot be the CRL of the chain's issuer.
    expect_success(&run_with("crl-root-name-other-aki-expired.crl"));
}

#[test]
fn crl_naming_the_issuer_key_still_fails_closed_when_stale() {
    let output = run_alone("crl-root-aki-expired.crl");
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
fn crl_malformed_authority_key_identifier_fails_closed() {
    let output = run_alone("crl-root-malformed-aki.crl");
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
fn crl_chain_issuer_signature_is_never_excluded_by_a_mismatched_aki() {
    // Signed by the root's own key, so a differing authorityKeyIdentifier
    // cannot make it irrelevant: the stale CRL still fails closed.
    let output = run_alone("crl-root-signed-other-aki-expired.crl");
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
fn crl_unrelated_crl_with_malformed_aki_is_excluded() {
    expect_success(&run_with("crl-unrelated-malformed-aki.crl"));
}

#[test]
fn crl_unsupported_crl_features_from_a_chain_issuer_are_typed() {
    for (file, reason) in [
        (
            "crl-root-unknown-critical-extension.crl",
            "unknown_critical_extension",
        ),
        (
            "crl-root-entry-critical-extension.crl",
            "unknown_critical_extension",
        ),
        ("crl-root-idp-user-certs.crl", "issuing_distribution_point"),
        ("crl-root-idp-ca-certs.crl", "issuing_distribution_point"),
        ("crl-root-delta.crl", "delta_crl"),
        ("crl-root-delta-expired.crl", "delta_crl"),
        ("crl-root-indirect.crl", "indirect_crl"),
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
fn crl_unknown_noncritical_crl_extension_is_ignored() {
    expect_success(&run_with("crl-root-unknown-noncritical-extension.crl"));
}

fn run_path(input: &str) -> Output {
    run_path_crls(input, &["path-issuer.crl"])
}

#[test]
fn crl_from_an_issuer_without_crl_sign_is_rejected() {
    let output = run_path("crl-ca-no-crl-sign.exe");
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
fn crl_from_an_issuer_with_crl_sign_is_used() {
    revocation_good(&run_path("crl-ca-crl-sign.exe"));
}

#[test]
fn crl_path_building_falls_back_to_the_issuer_with_crl_sign() {
    let fallback = run_path("crl-ca-crl-sign-fallback.exe");
    let usable = run_path("crl-ca-crl-sign.exe");
    expect_success(&fallback);
    let chain =
        |output: &Output| output.json["results"][0]["signatures"][0]["trust"]["chain"].clone();
    assert_eq!(chain(&fallback), chain(&usable));
}

#[test]
fn crl_aki_without_key_identifier_is_matched_by_issuer_name() {
    // authorityCertIssuer/serial alone cannot exclude a CRL: the stale CRL
    // from the chain issuer's name still fails closed.
    let output = run_alone("crl-root-aki-issuer-serial-expired.crl");
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
fn crl_named_distribution_point_crl_without_matching_certificate_point_fails_closed() {
    // The signer lists no CRL distribution points, so a CRL scoped to a named
    // point may be a partition that does not cover it.
    let output = run_alone("crl-root-idp-named-point.crl");
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

fn run_path_root(root: &str) -> Output {
    run_path_with(root, "good-path-basic.exe", &["path-issuer.crl"])
}

#[test]
fn crl_from_a_root_without_crl_sign_is_used() {
    // Configured anchors are keys: their KeyUsage does not restrict CRL signing.
    revocation_good(&run_path_root("crl-root-no-crl-sign.der"));
}

#[test]
fn crl_revocation_in_any_applicable_crl_wins_regardless_of_order() {
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

/// Verify a PATH-T001 chain input with the root CRL and these issuer CRLs, in order.
fn run_path_crls(input: &str, crls: &[&str]) -> Output {
    run_path_with("path-root.der", input, crls)
}

fn run_path_with(root: &str, input: &str, crls: &[&str]) -> Output {
    let crls: Vec<&str> = ["path-root.crl"]
        .into_iter()
        .chain(crls.iter().copied())
        .collect();
    run_path_exact(root, input, &crls)
}

/// Verify a PATH-T001 chain input with exactly these CRLs, in order.
fn run_path_exact(root: &str, input: &str, crls: &[&str]) -> Output {
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
    run_path_crls("crl-leaf-crl-dp.exe", crls)
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
fn crl_scoped_to_the_listed_distribution_point_is_authoritative() {
    revocation_good(&run_crl_dp(&["crl-issuer-idp-match.crl"]));
    revocation_failure(
        &run_crl_dp(&["crl-issuer-idp-match-revoked.crl"]),
        "certificate_revoked",
        "Certificate revoked",
    );
}

#[test]
fn crl_scoped_to_another_distribution_point_leaves_status_unknown() {
    // The second URI differs from the listed point only in letter case.
    for crl in ["crl-issuer-idp-other.crl", "crl-issuer-idp-case.crl"] {
        unknown(&run_crl_dp(&[crl]));
    }
}

#[test]
fn crl_listing_by_a_non_authoritative_partition_alone_leaves_status_unknown() {
    // A listed serial counts only on a path where every certificate has an
    // authoritative CRL. A partition that is not authoritative for the signer
    // is not enough evidence on its own to call it revoked.
    unknown(&run_crl_dp(&["crl-issuer-idp-other-revoked.crl"]));
}

#[test]
fn crl_matching_partition_is_selected_whatever_the_crl_order() {
    let first = run_crl_dp(&["crl-issuer-idp-other.crl", "crl-issuer-idp-match.crl"]);
    let last = run_crl_dp(&["crl-issuer-idp-match.crl", "crl-issuer-idp-other.crl"]);
    revocation_good(&first);
    revocation_good(&last);
}

#[test]
fn crl_revocation_in_another_partition_of_the_issuer_does_not_count() {
    // The signer's own partition decides and does not list it. A partition
    // for another point does not cover the signer, so its entries are not
    // read, whatever the `--crl` order: OpenSSL gives such a CRL no scope
    // score and Bouncy Castle's processCRLB2 rejects it.
    for crls in [
        [
            "crl-issuer-idp-match.crl",
            "crl-issuer-idp-other-revoked.crl",
        ],
        [
            "crl-issuer-idp-other-revoked.crl",
            "crl-issuer-idp-match.crl",
        ],
    ] {
        revocation_good(&run_crl_dp(&crls));
    }
}

#[test]
fn crl_full_crl_covers_a_certificate_that_lists_a_distribution_point() {
    revocation_good(&run_crl_dp(&["path-issuer.crl"]));
    // The full CRL is authoritative even next to a non-matching partition.
    revocation_good(&run_crl_dp(&[
        "crl-issuer-idp-other.crl",
        "path-issuer.crl",
    ]));
}

#[test]
fn crl_partition_crl_is_rejected_for_a_signer_listing_no_distribution_point() {
    // The same matching-partition CRL, but the base PATH-T001 leaf lists no point.
    let output = run_path_crls("good-path-basic.exe", &["crl-issuer-idp-match.crl"]);
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
fn crl_scope_flag_with_a_named_point_restricts_the_signer_role() {
    // Both CRLs name the signer's listed point; only the role scope differs.
    revocation_good(&run_crl_dp(&["crl-issuer-idp-match-user.crl"]));
    unknown(&run_crl_dp(&["crl-issuer-idp-match-ca.crl"]));
}

#[test]
fn crl_scope_flag_with_a_named_point_restricts_the_issuer_role() {
    // The intermediate lists a point; the root CRLs name it with a role scope.
    let run = |root_crl: &str| {
        run_path_exact(
            "path-root.der",
            "crl-ca-crl-dp.exe",
            &[root_crl, "path-issuer.crl"],
        )
    };
    revocation_good(&run("crl-path-root-idp-ca.crl"));
    unknown(&run("crl-path-root-idp-user.crl"));
}

#[test]
fn crl_any_matching_uri_among_several_names_or_points_is_authoritative() {
    // The CRL's second name is the signer's listed point.
    revocation_good(&run_crl_dp(&["crl-issuer-idp-two-names.crl"]));
    // The CRL names the second name of the signer's second point.
    let multi = "crl-leaf-crl-dp-multi.exe";
    revocation_good(&run_path_crls(multi, &["crl-issuer-idp-second-point.crl"]));
    // A point the multi-point signer does not list.
    unknown(&run_path_crls(multi, &["crl-issuer-idp-match.crl"]));
}

#[test]
fn crl_non_uri_and_issuer_relative_names_never_match() {
    // The same dNSName on both sides is not compared.
    unknown(&run_path_crls(
        "crl-leaf-crl-dp-dns.exe",
        &["crl-issuer-idp-dns.crl"],
    ));
    // The CRL names the directoryName that the signer's issuer-relative name
    // expands to; relative names are not expanded.
    let relative = "crl-leaf-crl-dp-relative.exe";
    unknown(&run_path_crls(
        relative,
        &["crl-issuer-idp-relative-expanded.crl"],
    ));
}

#[test]
fn crl_scoped_by_an_issuer_relative_name_is_rejected() {
    let reason = |output: &Output| {
        revocation_failure(output, "invalid_crl", "Invalid CRL");
        output.json["results"][0]["error"]["details"]["reason"].clone()
    };
    let crl = ["crl-issuer-idp-relative.crl"];
    // Unsupported form when every covered certificate lists a point.
    assert_eq!(
        reason(&run_path_crls("crl-leaf-crl-dp-relative.exe", &crl)),
        "issuing_distribution_point"
    );
    // The scope rule is checked first for a signer that lists no point.
    assert_eq!(
        reason(&run_path_crls("good-path-basic.exe", &crl)),
        "distribution_point_scope"
    );
}

#[test]
fn crl_certificate_point_with_reasons_or_crl_issuer_never_matches() {
    // Each signer lists the URI that the partition CRL names.
    for signer in [
        "crl-leaf-crl-dp-reasons.exe",
        "crl-leaf-crl-dp-crl-issuer.exe",
    ] {
        unknown(&run_path_crls(signer, &["crl-issuer-idp-match.crl"]));
    }
}

#[test]
fn crl_full_crl_covers_every_distribution_point_form() {
    for signer in [
        "crl-leaf-crl-dp-multi.exe",
        "crl-leaf-crl-dp-dns.exe",
        "crl-leaf-crl-dp-relative.exe",
        "crl-leaf-crl-dp-reasons.exe",
        "crl-leaf-crl-dp-crl-issuer.exe",
    ] {
        revocation_good(&run_path_crls(signer, &["path-issuer.crl"]));
    }
}

#[test]
fn crl_revoked_intermediate_is_rejected_whatever_the_crl_order() {
    let revoked = "crl-path-root-revoked-issuer.crl";
    for crls in [
        vec![revoked, "path-issuer.crl"],
        vec!["path-issuer.crl", revoked],
        vec!["path-root.crl", revoked, "path-issuer.crl"],
        vec![revoked, "path-root.crl", "path-issuer.crl"],
    ] {
        let output = run_path_exact("path-root.der", "good-path-basic.exe", &crls);
        revocation_failure(&output, "certificate_revoked", "Certificate revoked");
    }
}

/// Two candidate paths: the cross certificate under the other root, which
/// that root's CRL revokes, and the issuer under the root. Without the root's
/// CRL the revocation decides, as without retrieval nothing can complete the
/// second path, and the second path's gap is named for a CRL source; with
/// that CRL, the second path verifies.
#[test]
fn crl_a_revoked_path_names_what_another_path_still_lacks() {
    let run = |extra: &[&str]| {
        let mut args = vec![
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/path-root.der",
            "--roots",
            "fixtures/path-other-root.der",
            "--time",
            T,
            "--crl",
            "fixtures/path-issuer.crl",
            "--crl",
            "fixtures/crl-path-other-root-revoked-cross.crl",
        ];
        args.extend_from_slice(extra);
        run_fixture("good-path-cross-first.exe", &args)
    };
    let output = run(&[]);
    revocation_failure(&output, "certificate_revoked", "Certificate revoked");
    let details = &output.json["results"][0]["error"]["details"];
    let missing = details["certificates_without_crl"].as_array().unwrap();
    assert_eq!(missing.len(), 1);
    assert_eq!(missing[0]["subject"]["display"], "CN=SEC-06 issuer");
    revocation_good(&run(&["--crl", "fixtures/path-root.crl"]));
}

/// The other path's cross certificate lacks keyCertSign, so a CRL for it could
/// not make it verify: the revocation on the first path decides, whether or
/// not the other path has a CRL.
#[test]
fn crl_a_revoked_path_decides_when_the_other_path_fails_key_usage() {
    let run = |extra: &[&str]| {
        let mut args = vec![
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/path-root.der",
            "--roots",
            "fixtures/path-other-root.der",
            "--time",
            T,
            "--crl",
            "fixtures/path-issuer.crl",
            "--crl",
            "fixtures/crl-path-root-revoked-issuer.crl",
        ];
        args.extend_from_slice(extra);
        run_fixture("crl-path-cross-no-cert-sign.exe", &args)
    };
    for extra in [&[][..], &["--crl", "fixtures/path-other-root.crl"]] {
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
fn crl_an_unknown_status_ignores_a_path_failing_key_usage() {
    let output = run_fixture(
        "crl-path-cross-no-cert-sign.exe",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/path-root.der",
            "--roots",
            "fixtures/path-other-root.der",
            "--time",
            T,
            "--crl",
            "fixtures/path-issuer.crl",
            "--crl",
            "fixtures/crl-path-root-idp-ca.crl",
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
fn crl_this_update_is_an_inclusive_lower_bound() {
    stale_at(
        CRL_THIS_UPDATE - 1,
        "crl_not_yet_valid",
        "CRL not yet valid",
    );
    fresh_at(CRL_THIS_UPDATE);
}

#[test]
fn crl_next_update_is_an_exclusive_upper_bound() {
    fresh_at(CRL_NEXT_UPDATE - 1);
    stale_at(CRL_NEXT_UPDATE, "crl_expired", "CRL expired");
}

#[test]
fn crl_a_revocation_in_a_stale_crl_does_not_count_beside_a_fresh_one() {
    // The fresh CRL decides and does not list the signer. The expired one
    // does, but a listing counts only from a current CRL, as in OpenSSL and
    // Bouncy Castle: it may be a hold that was since released.
    let output = run_with("crl-root-expired-revoked.crl");
    expect_success(&output);
    assert_eq!(
        output.json["results"][0]["signatures"][0]["trust"]["revocation"]["status"],
        "good"
    );
    // Alone, the stale CRL is not usable evidence: expired, not revoked.
    let output = run_alone("crl-root-expired-revoked.crl");
    revocation_failure(&output, "crl_expired", "CRL expired");
}

#[test]
fn crl_a_revocation_in_a_superseded_crl_does_not_count_beside_a_newer_one() {
    // Both CRLs are within their validity, but good.crl is newer and does
    // not list the signer: the newest usable CRL decides, as OpenSSL prefers
    // the latest lastUpdate, so the older listing may be a released hold.
    let output = run_with("crl-root-superseded-revoked.crl");
    expect_success(&output);
    assert_eq!(
        output.json["results"][0]["signatures"][0]["trust"]["revocation"]["status"],
        "good"
    );
    // Alone it is the newest usable CRL, and its listing revokes.
    let output = run_alone("crl-root-superseded-revoked.crl");
    revocation_failure(&output, "certificate_revoked", "Certificate revoked");
}

#[test]
fn crl_a_revocation_in_a_role_partition_without_a_point_counts() {
    // A user-certificate partition with no distribution point name is in
    // scope for the signer in OpenSSL (`crl_crldp_check`) and Bouncy Castle
    // (processCRLB2), so its listing counts beside the full good.crl.
    let output = run_with("crl-root-idp-user-certs-revoked.crl");
    revocation_failure(&output, "certificate_revoked", "Certificate revoked");
    // Alone it cannot decide here: webpki does not support the form.
    let output = run_alone("crl-root-idp-user-certs-revoked.crl");
    revocation_failure(&output, "invalid_crl", "Invalid CRL");
}

#[test]
fn crl_an_expired_partition_for_another_point_does_not_decide_the_signer() {
    // Not authoritative for the signer, so its age is irrelevant: the status
    // is unknown and the signer is named, not crl_expired.
    let output = run_crl_dp(&["path-root.crl", "crl-issuer-idp-other-expired.crl"]);
    revocation_failure(&output, "revocation_unknown", "Revocation status unknown");
    let missing = &output.json["results"][0]["error"]["details"]["certificates_without_crl"];
    assert_eq!(missing.as_array().unwrap().len(), 1);
    assert_eq!(
        missing[0]["sha256"],
        "53af4ab427625a14a3f148cb35f101dd2c79725123085d301dec3df57dc419a1"
    );
}

#[test]
fn crl_a_listing_in_an_authenticated_crl_counts_even_with_a_malformed_aki() {
    // The root signed it, so its listing of the signer counts beside good.crl,
    // although its authorityKeyIdentifier cannot be decoded.
    let output = run_with("crl-root-malformed-aki-revoked.crl");
    revocation_failure(&output, "certificate_revoked", "Certificate revoked");
}

/// CRL-T004: a self-issued key rollover. The chain verifies without
/// revocation. With CRLs that carry no authorityKeyIdentifier nothing tells
/// the two same-name issuers' CRLs apart: OpenSSL and BoringSSL reject (CRL
/// signature failure), Bouncy Castle accepts, and rssig rejects (fails
/// closed) in either `--crl` order. With CRLs that each name their issuer's
/// key all three accept, and so does rssig.
#[test]
fn a_self_issued_rollover_path_needs_key_identified_crls() {
    let run = |extra: &[&str]| {
        let mut args = vec![
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/path-root.der",
            "--time",
            T,
        ];
        args.extend_from_slice(extra);
        run_fixture("good-path-self-issued-rollover.exe", &args)
    };
    expect_success(&run(&["--no-revocation"]));
    for crls in [
        ["fixtures/path-root.crl", "fixtures/path-rollover.crl"],
        ["fixtures/path-rollover.crl", "fixtures/path-root.crl"],
    ] {
        let output = run(&["--crl", crls[0], "--crl", crls[1]]);
        assert_eq!(output.exit_code, 1);
        let error = &output.json["results"][0]["error"];
        assert_eq!(error["code"], "certificate_chain_invalid");
        assert_eq!(error["details"]["reason"], "ambiguous_issuer_keys");
    }
    for crls in [
        [
            "fixtures/path-root-akid.crl",
            "fixtures/path-rollover-akid.crl",
        ],
        [
            "fixtures/path-rollover-akid.crl",
            "fixtures/path-root-akid.crl",
        ],
    ] {
        let output = run(&["--crl", crls[0], "--crl", crls[1]]);
        expect_success(&output);
        let signature = &output.json["results"][0]["signatures"][0];
        assert_eq!(signature["revocation_checked"], true);
        assert_eq!(signature["chain_trusted"], true);
    }
    // The rollover certificate itself is still checked: revoked by the root
    // key's CRL, it rejects the path.
    let output = run(&[
        "--crl",
        "fixtures/path-root-akid-revoked-rollover.crl",
        "--crl",
        "fixtures/path-rollover-akid.crl",
    ]);
    revocation_failure(&output, "certificate_revoked", "Certificate revoked");
}

/// CRL-T001: two configured roots with one key and name may carry different
/// subjectKeyIdentifiers. A CRL signed by another key that names one of them
/// is forged for that anchor, whichever root is listed first; naming an
/// identifier no configured root carries, it is another issuer's CRL and is
/// set aside without a failure.
#[test]
fn crl_a_same_key_roots_identifier_makes_a_crl_forged_not_set_aside() {
    let run = |roots: &[&str]| {
        let mut args = vec!["verify", "--no-system-roots"];
        for root in roots {
            args.extend(["--roots", root]);
        }
        args.extend([
            "--time",
            T,
            "--crl",
            "fixtures/crl-root-forged-other-ski.crl",
        ]);
        run_fixture("good-countersignature.exe", &args)
    };
    let alone = run(&["fixtures/root.der"]);
    assert_eq!(
        alone.json["results"][0]["error"]["code"],
        "revocation_unknown"
    );
    assert!(
        alone.json["results"][0]["error"]["details"]
            .get("unusable_crl")
            .is_none()
    );
    for roots in [
        ["fixtures/root.der", "fixtures/crl-root-other-ski.der"],
        ["fixtures/crl-root-other-ski.der", "fixtures/root.der"],
    ] {
        let output = run(&roots);
        let error = &output.json["results"][0]["error"];
        assert_eq!(error["code"], "revocation_unknown");
        assert_eq!(
            error["details"]["unusable_crl"]["code"],
            "invalid_crl_signature"
        );
    }
}

/// PR #64: a root CRL without nextUpdate that lists the signer revokes alone,
/// as in OpenSSL, BoringSSL and Bouncy Castle, unless a newer complete CRL of
/// the root leaves the signer out; an older one does not clear it. Run on
/// `good-pe64.exe`, which has no timestamp, so the signer is checked first.
#[test]
fn crl_a_crl_without_next_update_revokes_unless_a_newer_crl_clears_it() {
    let run = |crls: &[&str]| {
        let mut args = vec![
            "verify".to_owned(),
            "--no-system-roots".to_owned(),
            "--roots".to_owned(),
            "fixtures/root.der".to_owned(),
            "--time".to_owned(),
            T.to_owned(),
        ];
        for crl in crls {
            args.extend(["--crl".to_owned(), format!("fixtures/{crl}")]);
        }
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        run_fixture("good-pe64.exe", &args)
    };
    let alone = run(&["crl-root-no-next-update-revoked.crl"]);
    assert_eq!(alone.exit_code, 1);
    assert_eq!(
        alone.json["results"][0]["error"]["code"],
        "certificate_revoked"
    );
    let older = run(&[
        "crl-root-no-next-update-revoked.crl",
        "crl-root-no-next-update.crl",
    ]);
    assert_eq!(
        older.json["results"][0]["error"]["code"],
        "certificate_revoked"
    );
    let cleared = run(&[
        "crl-root-no-next-update-revoked.crl",
        "crl-root-no-next-update-newer.crl",
    ]);
    assert_eq!(cleared.exit_code, 1);
    let error = &cleared.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_crl");
    assert_eq!(error["details"]["reason"], "missing_next_update");
}

/// CRL-T004, CRL-041: a CRL whose issuer is the root's name in another string
/// type, case or spacing is matched by RFC 5280 section 7.1 and authenticated
/// by its signature, so the root's status is good.
#[test]
fn crl_an_issuer_name_matches_by_rfc_5280_comparison() {
    for crl in [
        "fixtures/crl-root-issuer-printable.crl",
        "fixtures/crl-root-issuer-case-space.crl",
        "fixtures/crl-root-issuer-bmp.crl",
        "fixtures/crl-root-issuer-teletex.crl",
        "fixtures/crl-root-issuer-visible.crl",
    ] {
        let output = run_fixture(
            "good-countersignature.exe",
            &[
                "verify",
                "--no-system-roots",
                "--roots",
                "fixtures/root.der",
                "--time",
                T,
                "--crl",
                crl,
            ],
        );
        assert_eq!(output.json["ok"], true, "{crl}");
        let revocation = &output.json["results"][0]["signatures"][0]["trust"]["revocation"];
        assert_eq!(revocation["status"], "good", "{crl}");
        assert_eq!(revocation["method"], "crl", "{crl}");
    }
}

/// CRL-041: a BMPString issuer is compared by its text, so one letter
/// different is another name and no CRL applies.
#[test]
fn crl_a_bmp_string_issuer_with_other_text_does_not_match() {
    let output = run_alone("crl-root-issuer-bmp-other-text.crl");
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "revocation_unknown");
    assert_eq!(error["stage"], "revocation");
}

/// CRL-T004, CRL-042: an issuer certificate with no subjectKeyIdentifier, or one
/// that does not parse, cannot disprove a CRL's key, so a CRL signed by
/// another key that names one is forged, where a root with an identifier sets
/// it aside.
#[test]
fn crl_an_issuer_without_a_usable_key_identifier_cannot_disprove_another_keys_crl() {
    for root in [
        "fixtures/crl-root-no-ski.der",
        "fixtures/crl-root-malformed-ski.der",
    ] {
        let output = run_fixture(
            "good-countersignature.exe",
            &[
                "verify",
                "--no-system-roots",
                "--roots",
                root,
                "--time",
                T,
                "--crl",
                "fixtures/crl-root-forged-other-ski.crl",
            ],
        );
        let error = &output.json["results"][0]["error"];
        assert_eq!(error["code"], "revocation_unknown", "{root}");
        assert_eq!(error["stage"], "revocation", "{root}");
        assert_eq!(
            error["details"]["unusable_crl"]["code"], "invalid_crl_signature",
            "{root}"
        );
    }
}

/// CRL-T004, CRL-043 and CRL-044: a CRL signed by another key whose authorityKeyIdentifier
/// names another serial or issuer than the root's is another certificate's CRL
/// and is set aside, not forged; one the root signed verifies whatever its
/// authorityKeyIdentifier names.
#[test]
fn crl_naming_another_certificate_by_issuer_and_serial_is_set_aside_when_it_fails() {
    for crl in [
        "crl-root-forged-aki-other-serial.crl",
        "crl-root-forged-aki-other-issuer.crl",
    ] {
        let output = run_alone(crl);
        let error = &output.json["results"][0]["error"];
        assert_eq!(error["code"], "revocation_unknown", "{crl}");
        assert_eq!(error["stage"], "revocation", "{crl}");
        assert!(error["details"].get("unusable_crl").is_none(), "{crl}");
    }
    let signed = run_alone("crl-root-signed-aki-other-serial.crl");
    assert_eq!(signed.json["ok"], true);
    assert_eq!(
        signed.json["results"][0]["signatures"][0]["trust"]["revocation"]["status"],
        "good"
    );
}

/// CRL-T004, CRL-041: a CRL whose issuer equals the root's name only under RFC
/// 5280 comparison (another case) and that fails under the root's key is
/// another CA's and is set aside, not forged, so it cannot block retrieval
/// (CRL-018) or name a forged CRL in the result.
#[test]
fn crl_a_failed_crl_matching_only_by_name_comparison_is_set_aside() {
    let output = run_alone("crl-root-forged-issuer-case.crl");
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "revocation_unknown");
    assert_eq!(error["stage"], "revocation");
    assert!(error["details"].get("unusable_crl").is_none());
    // One whose authorityKeyIdentifier names the root's own key claims the
    // root, so it stays forged whatever its spelling.
    let claiming = run_alone("crl-root-forged-issuer-case-naming-root-key.crl");
    assert_eq!(
        claiming.json["results"][0]["error"]["code"],
        "invalid_crl_signature"
    );
    // So does one naming a key that a root without a subjectKeyIdentifier
    // cannot disprove (CRL-042).
    let undisprovable = run_fixture(
        "good-countersignature.exe",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/crl-root-no-ski.der",
            "--time",
            T,
            "--crl",
            "fixtures/crl-root-forged-issuer-case-naming-root-key.crl",
        ],
    );
    assert_eq!(
        undisprovable.json["results"][0]["error"]["code"],
        "invalid_crl_signature"
    );
}

/// CRL-T004, CRL-008: a rollover CRL that spells its issuer as a PrintableString
/// cannot escape the rule for issuers of one name with different keys whose
/// CRLs name no key, in either order of the CRLs.
#[test]
fn crl_a_differently_encoded_rollover_crl_is_still_ambiguous() {
    for crls in [
        [
            "fixtures/path-root.crl",
            "fixtures/path-rollover-printable.crl",
        ],
        [
            "fixtures/path-rollover-printable.crl",
            "fixtures/path-root.crl",
        ],
    ] {
        let output = run_fixture(
            "good-path-self-issued-rollover.exe",
            &[
                "verify",
                "--no-system-roots",
                "--roots",
                "fixtures/path-root.der",
                "--time",
                T,
                "--crl",
                crls[0],
                "--crl",
                crls[1],
            ],
        );
        let error = &output.json["results"][0]["error"];
        assert_eq!(error["code"], "certificate_chain_invalid", "{crls:?}");
        assert_eq!(
            error["details"]["reason"], "ambiguous_issuer_keys",
            "{crls:?}"
        );
    }
}
