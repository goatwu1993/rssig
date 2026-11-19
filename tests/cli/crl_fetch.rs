use super::support::*;
#[test]
fn crl_fetch_rejects_private_destinations_and_checks_integrity_first() {
    // A denied private destination is no evidence: the status is unknown and
    // the denial is recorded. A bad image fails before any discovery.
    for (file, code, denied) in [
        ("bad-crl-private-url.exe", "revocation_unknown", true),
        (
            "bad-crl-discovery-image.exe",
            "image_digest_mismatch",
            false,
        ),
    ] {
        let out = run_fixture(
            file,
            &[
                "verify",
                "--no-system-roots",
                "--roots",
                "fixtures/root.der",
                "--time",
                "1800000000",
                "--fetch-crls",
            ],
        );
        assert_eq!(out.exit_code, 1);
        let error = &out.json["results"][0]["error"];
        assert_eq!(error["code"], code);
        let failures = &error["details"]["crl_retrieval"]["failures"];
        if denied {
            assert_eq!(failures[0]["code"], "crl_fetch_denied");
        } else {
            assert!(failures.is_null());
        }
    }
}

#[test]
fn crl_fetch_injected_bytes_are_authenticated_and_reported() {
    struct Source {
        bytes: Vec<u8>,
        calls: usize,
    }
    impl rssig::retrieval::CrlSource for Source {
        fn crls(
            &mut self,
            request: &rssig::retrieval::CrlRequest<'_>,
        ) -> Result<rssig::retrieval::CrlResponse, rssig::retrieval::CrlSourceError> {
            Ok(rssig::retrieval::fetch_each(request, |url, _max_bytes| {
                assert_eq!(url, "http://crl.example.invalid/test.crl");
                self.calls += 1;
                Ok(rssig::retrieval::SourcedCrl::new(self.bytes.clone()))
            }))
        }
    }
    for (crl, expected) in [
        ("good.crl", None),
        ("revoked.crl", Some("certificate_revoked")),
        ("forged.crl", Some("invalid_crl_signature")),
        ("expired.crl", Some("crl_expired")),
    ] {
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let input = base.join("good-crl-discovery.exe");
        let root = base.join("root.der");
        let mut source = Source {
            bytes: std::fs::read(base.join(crl)).unwrap(),
            calls: 0,
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = rssig::cli::run_with_crl_source(
            [
                "rssig",
                "verify",
                "--no-system-roots",
                "--roots",
                root.to_str().unwrap(),
                "--time",
                "1800000000",
                "--fetch-crls",
                input.to_str().unwrap(),
            ],
            &mut out,
            &mut err,
            &mut source,
        )
        .unwrap();
        assert!(err.is_empty());
        assert_eq!(source.calls, 1);
        let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
        if let Some(expected) = expected {
            assert_eq!(code, 1);
            assert_eq!(json["results"][0]["error"]["code"], expected);
        } else {
            assert_eq!(code, 0);
            assert_eq!(
                json["results"][0]["signatures"][0]["revocation_checked"],
                true
            );
            assert_eq!(
                json["results"][0]["crl_retrieval"]["artifacts"][0]["url"],
                "http://crl.example.invalid/test.crl"
            );
        }
    }
}

#[test]
fn supplied_crls_and_offline_mode_do_not_call_the_provider() {
    struct NoCalls;
    impl rssig::retrieval::CrlSource for NoCalls {
        fn crls(
            &mut self,
            request: &rssig::retrieval::CrlRequest<'_>,
        ) -> Result<rssig::retrieval::CrlResponse, rssig::retrieval::CrlSourceError> {
            Ok(rssig::retrieval::fetch_each(request, |_url, _max_bytes| {
                panic!("supplied CRL or offline mode must not call the provider");
            }))
        }
    }
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let root = base.join("root.der");
    let input = base.join("good-crl-discovery.exe");
    for (fetch, crl, expected) in [
        (false, "good.crl", 0),
        (true, "good.crl", 0),
        (true, "expired.crl", 1),
    ] {
        let crl = base.join(crl);
        let mut args = vec![
            "rssig",
            "verify",
            "--no-system-roots",
            "--roots",
            root.to_str().unwrap(),
            "--crl",
            crl.to_str().unwrap(),
            "--time",
            "1800000000",
        ];
        if fetch {
            args.push("--fetch-crls");
        }
        args.push(input.to_str().unwrap());
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(
            rssig::cli::run_with_crl_source(args, &mut out, &mut err, &mut NoCalls).unwrap(),
            expected
        );
        assert!(err.is_empty());
        let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let result = &report["results"][0];
        if expected == 0 {
            assert_eq!(result["signatures"][0]["revocation_checked"], true);
            if fetch {
                assert_eq!(result["crl_retrieval"]["artifacts"], serde_json::json!([]));
            } else {
                assert!(result.get("crl_retrieval").is_none());
            }
        } else {
            assert_eq!(result["error"]["code"], "crl_expired");
            assert_eq!(result["error"]["stage"], "revocation");
        }
    }
}

#[test]
fn sec07_fetched_bundles_enforce_retained_crl_limit() {
    struct Source {
        bytes: Vec<u8>,
        calls: usize,
    }
    impl rssig::retrieval::CrlSource for Source {
        fn crls(
            &mut self,
            request: &rssig::retrieval::CrlRequest<'_>,
        ) -> Result<rssig::retrieval::CrlResponse, rssig::retrieval::CrlSourceError> {
            Ok(rssig::retrieval::fetch_each(request, |_url, _max_bytes| {
                self.calls += 1;
                Ok(rssig::retrieval::SourcedCrl::new(self.bytes.clone()))
            }))
        }
    }
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for (count, supplied) in [(64, false), (65, false), (64, true)] {
        let mut source = Source {
            bytes: std::fs::read(base.join(format!("sec07-fetch-{count}-crls.pem"))).unwrap(),
            calls: 0,
        };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let root = base.join("root.der");
        let input = base.join("good-crl-discovery.exe");
        let local = base.join("good-intermediate.crl");
        let mut args = vec![
            "rssig",
            "verify",
            "--no-system-roots",
            "--roots",
            root.to_str().unwrap(),
            "--time",
            "1800000000",
            "--fetch-crls",
            input.to_str().unwrap(),
        ];
        if supplied {
            args.extend(["--crl", local.to_str().unwrap()]);
        }
        let code = rssig::cli::run_with_crl_source(args, &mut out, &mut err, &mut source).unwrap();
        assert!(err.is_empty());
        assert_eq!(source.calls, 1);
        let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let result = &json["results"][0];
        assert_eq!(
            code,
            u8::from(count + usize::from(supplied) > 64),
            "{count} CRLs must respect the artifact limit"
        );
        if count == 64 && !supplied {
            assert_eq!(result["signatures"][0]["revocation_checked"], true);
            let crls = result["signatures"][0]["trust"]["revocation"]["crls"]
                .as_array()
                .unwrap();
            assert_eq!(crls.len(), 64);
            let unique: std::collections::HashSet<_> =
                crls.iter().map(|c| c["sha256"].as_str().unwrap()).collect();
            assert_eq!(unique.len(), 64);
        } else {
            assert!(result.get("signatures").is_none());
            assert_eq!(result["error"]["code"], "resource_limit_exceeded");
            assert_eq!(result["error"]["stage"], "revocation");
            let details = &result["error"]["details"];
            assert_eq!(details["resource"], "retrieval_crl_artifacts");
            assert_eq!(details["limit"], 64);
            assert_eq!(details["used"], usize::from(supplied));
            assert_eq!(details["requested"], count);
            assert_eq!(
                details["crl_retrieval"]["artifacts"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
        }
    }
}

/// SEC-10: a supplied CRL suppresses retrieval only when it would be
/// authoritative for the certificate, not merely because it has the issuer's
/// name. Each row is (input, supplied CRLs, fetched response, requested URLs,
/// expected error code).
#[test]
fn sec10_fetch_coverage_uses_the_verification_authority_rule() {
    struct Source {
        response: Option<Vec<u8>>,
        requests: Vec<String>,
    }
    impl rssig::retrieval::CrlSource for Source {
        fn crls(
            &mut self,
            request: &rssig::retrieval::CrlRequest<'_>,
        ) -> Result<rssig::retrieval::CrlResponse, rssig::retrieval::CrlSourceError> {
            Ok(rssig::retrieval::fetch_each(request, |url, _max_bytes| {
                self.requests.push(url.into());
                Ok(rssig::retrieval::SourcedCrl::new(
                    self.response.clone().expect("unexpected provider call"),
                ))
            }))
        }
    }
    const LEAF: &str = "sec10-leaf-crl-dp.exe";
    const CA: &str = "sec10-ca-crl-dp.exe";
    const NO_POINT: &str = "good-sec06-basic.exe";
    const LEAF_POINT: &str = "http://crl.invalid/sec10-a.crl";
    const CA_POINT: &str = "http://crl.invalid/sec10-issuer.crl";
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let root = base.join("sec06-root.der");
    type Row = (
        &'static str,
        [&'static str; 2],
        Option<&'static str>,
        &'static [&'static str],
        Option<&'static str>,
    );
    #[rustfmt::skip]
    let rows: [Row; 13] = [
        // Another partition's CRL has the issuer's name but is not authoritative.
        (LEAF, ["sec06-root.crl", "sec10-issuer-idp-other.crl"], Some("sec10-issuer-idp-match.crl"), &[LEAF_POINT], None),
        (LEAF, ["sec06-root.crl", "sec10-issuer-idp-other.crl"], Some("sec10-issuer-idp-match-revoked.crl"), &[LEAF_POINT], Some("certificate_revoked")),
        // The fetched bytes are held to the same rule: still no authoritative CRL.
        (LEAF, ["sec06-root.crl", "sec10-issuer-idp-other.crl"], Some("sec10-issuer-idp-other.crl"), &[LEAF_POINT], Some("revocation_unknown")),
        // Role flags: a CA-only CRL does not cover the signer, nor a user-only CRL an issuer.
        (LEAF, ["sec06-root.crl", "sec10-issuer-idp-match-ca.crl"], Some("sec10-issuer-idp-match.crl"), &[LEAF_POINT], None),
        (CA, ["sec10-sec06-root-idp-user.crl", "sec06-issuer.crl"], Some("sec10-sec06-root-idp-ca.crl"), &[CA_POINT], None),
        // Authoritative supplied CRLs still suppress retrieval.
        (LEAF, ["sec06-root.crl", "sec10-issuer-idp-match.crl"], None, &[], None),
        (LEAF, ["sec06-root.crl", "sec10-issuer-idp-match-user.crl"], None, &[], None),
        (LEAF, ["sec06-root.crl", "sec06-issuer.crl"], None, &[], None),
        (CA, ["sec10-sec06-root-idp-ca.crl", "sec06-issuer.crl"], None, &[], None),
        // A signer listing no point has nothing to fetch: the partition is reported, not skipped.
        (NO_POINT, ["sec06-root.crl", "sec10-issuer-idp-match.crl"], None, &[], Some("invalid_crl")),
        // A listed point that discovery does not support is not fetched. Verification
        // decides, as without --fetch-crls; the point is listed in the report's failures.
        ("sec10-leaf-crl-dp-reasons.exe", ["sec06-root.crl", "sec10-issuer-idp-match.crl"], None, &[], Some("revocation_unknown")),
        ("sec10-leaf-crl-dp-crl-issuer.exe", ["sec06-root.crl", "sec10-issuer-idp-match.crl"], None, &[], Some("revocation_unknown")),
        ("sec10-leaf-crl-dp-dns.exe", ["sec06-root.crl", "sec10-issuer-idp-dns.crl"], None, &[], Some("revocation_unknown")),
    ];
    for (input, supplied, response, requests, error) in rows {
        let label = format!("{input} with {supplied:?}");
        let input = base.join(input);
        let supplied = supplied.map(|crl| base.join(crl));
        let mut source = Source {
            response: response.map(|crl| std::fs::read(base.join(crl)).unwrap()),
            requests: Vec::new(),
        };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = rssig::cli::run_with_crl_source(
            [
                "rssig",
                "verify",
                "--no-system-roots",
                "--roots",
                root.to_str().unwrap(),
                "--time",
                "1800000000",
                "--fetch-crls",
                "--crl",
                supplied[0].to_str().unwrap(),
                "--crl",
                supplied[1].to_str().unwrap(),
                input.to_str().unwrap(),
            ],
            &mut out,
            &mut err,
            &mut source,
        )
        .unwrap();
        assert!(err.is_empty(), "{label}");
        assert_eq!(source.requests, requests, "{label}");
        let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let result = &report["results"][0];
        if let Some(error) = error {
            assert_eq!(code, 1, "{label}");
            assert_eq!(result["error"]["code"], error, "{label}");
            assert_eq!(result["error"]["stage"], "revocation", "{label}");
            let artifacts = result["error"]["details"]["crl_retrieval"]["artifacts"]
                .as_array()
                .unwrap();
            assert_eq!(artifacts.len(), requests.len(), "{label}");
            for (artifact, request) in artifacts.iter().zip(requests) {
                assert_eq!(artifact["url"], *request, "{label}");
            }
        } else {
            assert_eq!(code, 0, "{label}: {result}");
            assert_eq!(
                result["signatures"][0]["revocation_checked"], true,
                "{label}"
            );
            assert_eq!(
                result["crl_retrieval"]["artifacts"]
                    .as_array()
                    .unwrap()
                    .len(),
                requests.len(),
                "{label}"
            );
        }
    }
}

/// SEC-10: retrieval follows the verifier's result. Each row is (input, root,
/// supplied CRLs, responses by URL, requested URLs in order, expected error
/// code and `details.reason`). A URL without a response fails the request.
#[test]
fn sec10_fetch_follows_the_verification_result() {
    struct Source {
        responses: Vec<(&'static str, Vec<u8>)>,
        requests: Vec<String>,
    }
    impl rssig::retrieval::CrlSource for Source {
        fn crls(
            &mut self,
            request: &rssig::retrieval::CrlRequest<'_>,
        ) -> Result<rssig::retrieval::CrlResponse, rssig::retrieval::CrlSourceError> {
            Ok(rssig::retrieval::fetch_each(request, |url, _max_bytes| {
                self.requests.push(url.into());
                let (_, bytes) = self
                    .responses
                    .iter()
                    .find(|(known, _)| *known == url)
                    .ok_or_else(|| {
                        rssig::retrieval::CrlSourceError::new(
                            rssig::domain::CrlSourceErrorKind::Failed,
                            "no response for this URL",
                        )
                    })?;
                Ok(rssig::retrieval::SourcedCrl::new(bytes.clone()))
            }))
        }
    }
    const EXAMPLE_POINT: &str = "http://crl.example.invalid/test.crl";
    const LEAF_POINT: &str = "http://crl.invalid/sec10-a.crl";
    const CA_POINT: &str = "http://crl.invalid/sec10-issuer.crl";
    type Row = (
        &'static str,
        &'static str,
        &'static [&'static str],
        &'static [(&'static str, &'static str)],
        &'static [&'static str],
        Option<(&'static str, &'static str)>,
    );
    #[rustfmt::skip]
    let rows: [Row; 7] = [
        // A CRL with the issuer's name from another key is excluded by verification,
        // so it does not stand in for the listed point.
        ("good-crl-discovery.exe", "root.der", &["sec10-root-name-other-aki-expired.crl"], &[(EXAMPLE_POINT, "good.crl")], &[EXAMPLE_POINT], None),
        // A supplied CRL that verification rejects is reported as it is offline; the
        // provider is not asked, although it could answer.
        ("good-sec06-basic.exe", "sec06-root.der", &["sec06-root.crl", "sec10-issuer-idp-match-ca.crl"], &[], &[], Some(("invalid_crl", "distribution_point_scope"))),
        ("sec10-leaf-crl-dp.exe", "sec06-root.der", &["sec06-root.crl", "sec10-issuer-idp-relative.crl"], &[(LEAF_POINT, "sec10-issuer-idp-match.crl")], &[], Some(("invalid_crl", "issuing_distribution_point"))),
        // Both selected certificates list a point. The verifier reports only the
        // issuer as lacking a CRL, so only its point is requested.
        ("sec10-chain-crl-dp.exe", "sec06-root.der", &["sec06-issuer.crl"], &[(CA_POINT, "sec06-root.crl")], &[CA_POINT], None),
        // A partition that is not authoritative for the signer, and no root CRL: both
        // certificates lack a CRL and are asked about in path order, in one round.
        ("sec10-chain-crl-dp.exe", "sec06-root.der", &["sec10-issuer-idp-other.crl"], &[(CA_POINT, "sec06-root.crl"), (LEAF_POINT, "sec10-issuer-idp-match.crl")], &[LEAF_POINT, CA_POINT], None),
        // The signer is covered and its issuer is not (a user-only root partition):
        // only the issuer is asked about; the signer's point is never requested.
        ("sec10-chain-crl-dp.exe", "sec06-root.der", &["sec06-issuer.crl", "sec10-sec06-root-idp-user.crl"], &[(CA_POINT, "sec06-root.crl")], &[CA_POINT], None),
        // A reason-partitioned point beside a plain one: the plain URI is still requested,
        // and the partitioned point is listed in the report's failures.
        ("sec10-leaf-crl-dp-mixed.exe", "sec06-root.der", &["sec06-root.crl", "sec10-issuer-idp-other.crl"], &[(LEAF_POINT, "sec10-issuer-idp-match.crl")], &[LEAF_POINT], None),
    ];
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let path = |name: &str| base.join(name).to_str().unwrap().to_owned();
    for (input, root, supplied, responses, requests, error) in rows {
        let label = format!("{input} with {supplied:?}");
        let mut args = vec![
            "rssig".to_owned(),
            "verify".to_owned(),
            "--no-system-roots".to_owned(),
            "--roots".to_owned(),
            path(root),
            "--time".to_owned(),
            "1800000000".to_owned(),
            "--fetch-crls".to_owned(),
        ];
        for crl in supplied {
            args.extend(["--crl".to_owned(), path(crl)]);
        }
        args.push(path(input));
        let mut source = Source {
            responses: responses
                .iter()
                .map(|(url, file)| (*url, std::fs::read(base.join(file)).unwrap()))
                .collect(),
            requests: Vec::new(),
        };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = rssig::cli::run_with_crl_source(args, &mut out, &mut err, &mut source).unwrap();
        assert!(err.is_empty(), "{label}");
        assert_eq!(source.requests, requests, "{label}");
        let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let result = &report["results"][0];
        if let Some((error, reason)) = error {
            assert_eq!(code, 1, "{label}");
            assert_eq!(result["error"]["code"], error, "{label}");
            assert_eq!(result["error"]["stage"], "revocation", "{label}");
            assert_eq!(result["error"]["details"]["reason"], reason, "{label}");
            assert_eq!(
                result["error"]["details"]["crl_retrieval"]["artifacts"],
                serde_json::json!([]),
                "{label}"
            );
        } else {
            assert_eq!(code, 0, "{label}: {result}");
            let revocation = &result["signatures"][0]["trust"]["revocation"];
            assert_eq!(revocation["status"], "good", "{label}");
            // Only answered requests become artifacts.
            let answered: Vec<_> = requests
                .iter()
                .filter(|url| responses.iter().any(|(known, _)| known == *url))
                .collect();
            let artifacts = result["crl_retrieval"]["artifacts"].as_array().unwrap();
            assert_eq!(artifacts.len(), answered.len(), "{label}");
            // Each artifact names the chain certificate it was asked for: the
            // issuer's point for the issuer, any other for the signer.
            let chain = &result["signatures"][0]["trust"]["chain"];
            for (artifact, request) in artifacts.iter().zip(&answered) {
                assert_eq!(artifact["url"], **request, "{label}");
                let depth = usize::from(**request == CA_POINT);
                assert_eq!(
                    artifact["certificate_sha256"], chain[depth]["sha256"],
                    "{label}"
                );
            }
            // Every unanswered request, and the mixed signer's partitioned point, is a
            // reported failure.
            let failures = result["crl_retrieval"]["failures"]
                .as_array()
                .map_or(0, Vec::len);
            let partitioned = usize::from(input == "sec10-leaf-crl-dp-mixed.exe");
            assert_eq!(
                failures,
                requests.len() - answered.len() + partitioned,
                "{label}"
            );
            // Supplied CRLs stay loaded beside the fetched ones.
            assert_eq!(
                revocation["crls"].as_array().unwrap().len(),
                supplied.len() + answered.len(),
                "{label}"
            );
        }
    }
}

/// SEC-10: only the certificate the verifier reports as lacking a CRL is asked
/// about. The signer is covered by a supplied CRL and is never asked; the
/// issuer's point fails, so the status stays unknown with that failure.
#[test]
fn sec10_fetch_asks_only_the_certificate_without_a_crl() {
    struct Unreachable(Vec<String>);
    impl rssig::retrieval::CrlSource for Unreachable {
        fn crls(
            &mut self,
            request: &rssig::retrieval::CrlRequest<'_>,
        ) -> Result<rssig::retrieval::CrlResponse, rssig::retrieval::CrlSourceError> {
            Ok(rssig::retrieval::fetch_each(request, |url, _max_bytes| {
                self.0.push(url.into());
                Err(rssig::retrieval::CrlSourceError::new(
                    rssig::domain::CrlSourceErrorKind::Failed,
                    "unreachable",
                ))
            }))
        }
    }
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let path = |name: &str| base.join(name).to_str().unwrap().to_owned();
    let args = [
        "rssig".to_owned(),
        "verify".to_owned(),
        "--no-system-roots".to_owned(),
        "--roots".to_owned(),
        path("sec06-root.der"),
        "--time".to_owned(),
        "1800000000".to_owned(),
        "--crl".to_owned(),
        path("sec06-issuer.crl"),
        "--fetch-crls".to_owned(),
        path("sec10-chain-crl-dp.exe"),
    ];
    let mut source = Unreachable(Vec::new());
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = rssig::cli::run_with_crl_source(args, &mut out, &mut err, &mut source).unwrap();
    assert!(err.is_empty());
    assert_eq!(code, 1);
    assert_eq!(source.0, ["http://crl.invalid/sec10-issuer.crl"]);
    let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let error = &report["results"][0]["error"];
    assert_eq!(error["code"], "revocation_unknown");
    let failures = error["details"]["crl_retrieval"]["failures"]
        .as_array()
        .unwrap();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0]["url"], "http://crl.invalid/sec10-issuer.crl");
    assert_eq!(failures[0]["code"], "crl_fetch_failed");
    // The failure names the certificate it was for: the issuer, the one
    // certificate the verifier reported without a CRL.
    let issuer = "8dc7731929354e18379fa5f78b071548885ed9f2bb12aded834dddfb44815fbb";
    assert_eq!(failures[0]["certificate_sha256"], issuer);
    assert_eq!(
        error["details"]["certificates_without_crl"][0]["sha256"],
        issuer
    );
}

/// SEC-10: a response that is not a CRL, and a failed request, are no evidence;
/// another listed point of the same certificate still supplies its CRL.
#[test]
fn sec10_fetch_bad_response_is_no_evidence_beside_another_point() {
    struct Source(Vec<String>);
    impl rssig::retrieval::CrlSource for Source {
        fn crls(
            &mut self,
            request: &rssig::retrieval::CrlRequest<'_>,
        ) -> Result<rssig::retrieval::CrlResponse, rssig::retrieval::CrlSourceError> {
            Ok(rssig::retrieval::fetch_each(request, |url, _max_bytes| {
                self.0.push(url.into());
                let file = match url {
                    "http://crl.invalid/sec10-c.crl" => "sec06-root.der", // a certificate
                    "http://crl.invalid/sec10-e.crl" => "sec10-issuer-idp-second-point.crl",
                    _ => {
                        return Err(rssig::retrieval::CrlSourceError::new(
                            rssig::domain::CrlSourceErrorKind::Failed,
                            "unreachable",
                        ));
                    }
                };
                let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
                Ok(rssig::retrieval::SourcedCrl::new(
                    std::fs::read(base.join(file)).unwrap(),
                ))
            }))
        }
    }
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let path = |name: &str| base.join(name).to_str().unwrap().to_owned();
    let args = [
        "rssig".to_owned(),
        "verify".to_owned(),
        "--no-system-roots".to_owned(),
        "--roots".to_owned(),
        path("sec06-root.der"),
        "--time".to_owned(),
        "1800000000".to_owned(),
        "--crl".to_owned(),
        path("sec06-root.crl"),
        "--fetch-crls".to_owned(),
        path("sec10-leaf-crl-dp-multi.exe"),
    ];
    let mut source = Source(Vec::new());
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = rssig::cli::run_with_crl_source(args, &mut out, &mut err, &mut source).unwrap();
    assert!(err.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let result = &report["results"][0];
    assert_eq!(code, 0, "{result}");
    assert_eq!(
        source.0,
        [
            "http://crl.invalid/sec10-c.crl",
            "http://crl.invalid/sec10-d.crl",
            "http://crl.invalid/sec10-e.crl"
        ]
    );
    let failures = result["crl_retrieval"]["failures"].as_array().unwrap();
    assert_eq!(failures.len(), 2);
    assert_eq!(failures[0]["url"], "http://crl.invalid/sec10-d.crl");
    assert_eq!(failures[0]["source_error"], "failed");
    let bad = &failures[1];
    assert_eq!(bad["url"], "http://crl.invalid/sec10-c.crl");
    assert_eq!(bad["code"], "invalid_crl");
    assert_eq!(bad["stage"], "revocation");
    assert_eq!(bad["title"], "Invalid CRL");
    assert!(
        bad["type"]
            .as_str()
            .unwrap()
            .ends_with("problems.md#invalid_crl")
    );
    assert_eq!(
        result["signatures"][0]["trust"]["revocation"]["status"],
        "good"
    );
}

/// SEC-10: one candidate path is revoked by a supplied CRL and the other only
/// lacks its root's CRL. Retrieval asks about exactly that path's issuer, by
/// certificate and issuer name (it lists no point), and the path verifies.
#[test]
fn sec10_fetch_completes_the_path_without_a_crl_beside_a_revoked_path() {
    struct ByCertificate {
        crl: Vec<u8>,
        asked: Vec<(Vec<u8>, Vec<u8>, usize)>,
    }
    impl rssig::retrieval::CrlSource for ByCertificate {
        fn crls(
            &mut self,
            request: &rssig::retrieval::CrlRequest<'_>,
        ) -> Result<rssig::retrieval::CrlResponse, rssig::retrieval::CrlSourceError> {
            self.asked.push((
                request.certificate.to_vec(),
                request.issuer.to_vec(),
                request.distribution_points.len(),
            ));
            Ok(rssig::retrieval::CrlResponse::new()
                .with_crl(rssig::retrieval::SourcedCrl::new(self.crl.clone())))
        }
    }
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let path = |name: &str| base.join(name).to_str().unwrap().to_owned();
    let read = |name: &str| std::fs::read(base.join(name)).unwrap();
    let args = [
        "rssig".to_owned(),
        "verify".to_owned(),
        "--no-system-roots".to_owned(),
        "--roots".to_owned(),
        path("sec06-root.der"),
        "--roots".to_owned(),
        path("sec06-other-root.der"),
        "--time".to_owned(),
        "1800000000".to_owned(),
        "--crl".to_owned(),
        path("sec06-issuer.crl"),
        "--crl".to_owned(),
        path("sec10-sec06-other-root-revoked-cross.crl"),
        "--fetch-crls".to_owned(),
        path("good-sec06-cross-first.exe"),
    ];
    let mut source = ByCertificate {
        crl: read("sec06-root.crl"),
        asked: Vec::new(),
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = rssig::cli::run_with_crl_source(args, &mut out, &mut err, &mut source).unwrap();
    assert!(err.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(code, 0, "{report}");
    // Asked once, about the issuer under the root, never about the revoked
    // cross certificate or a covered one.
    assert_eq!(source.asked.len(), 1);
    let (certificate, issuer, points) = &source.asked[0];
    assert_eq!(certificate, &read("sec06-issuer.der"));
    assert_eq!(*points, 0);
    // The issuer name is the root's subject, as the root's CRL names it.
    let root_crl = read("sec06-root.crl");
    assert!(
        root_crl
            .windows(issuer.len())
            .any(|w| w == issuer.as_slice()),
        "the request's issuer name is the root CRL's issuer"
    );
    let result = &report["results"][0];
    assert_eq!(
        result["signatures"][0]["trust"]["revocation"]["status"],
        "good"
    );
    let artifacts = result["crl_retrieval"]["artifacts"].as_array().unwrap();
    assert_eq!(artifacts.len(), 1);
    assert_eq!(
        artifacts[0]["certificate_sha256"],
        "d04249adc82c33d5cc0b2de207defa23a91114277340d310e10c34d6a95d54ea"
    );
}

/// SEC-10: one path is revoked and the other only lacks its root's CRL. The
/// source aborts before that path could be completed, so the result says that
/// retrieval was cut short, keeping the revocation and the gap it names.
#[test]
fn sec10_fetch_abort_beside_a_revoked_path_is_reported() {
    struct Aborts(usize);
    impl rssig::retrieval::CrlSource for Aborts {
        fn crls(
            &mut self,
            _: &rssig::retrieval::CrlRequest<'_>,
        ) -> Result<rssig::retrieval::CrlResponse, rssig::retrieval::CrlSourceError> {
            self.0 += 1;
            Err(rssig::retrieval::CrlSourceError::new(
                rssig::domain::CrlSourceErrorKind::Abort,
                "deadline",
            ))
        }
    }
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let path = |name: &str| base.join(name).to_str().unwrap().to_owned();
    let args = [
        "rssig".to_owned(),
        "verify".to_owned(),
        "--no-system-roots".to_owned(),
        "--roots".to_owned(),
        path("sec06-root.der"),
        "--roots".to_owned(),
        path("sec06-other-root.der"),
        "--time".to_owned(),
        "1800000000".to_owned(),
        "--crl".to_owned(),
        path("sec06-issuer.crl"),
        "--crl".to_owned(),
        path("sec10-sec06-other-root-revoked-cross.crl"),
        "--fetch-crls".to_owned(),
        path("good-sec06-cross-first.exe"),
    ];
    let mut source = Aborts(0);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = rssig::cli::run_with_crl_source(args, &mut out, &mut err, &mut source).unwrap();
    assert!(err.is_empty());
    assert_eq!(code, 1);
    assert_eq!(source.0, 1);
    let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let error = &report["results"][0]["error"];
    assert_eq!(error["code"], "crl_fetch_aborted", "{error}");
    let details = &error["details"];
    assert!(details["certificate_revoked"].is_string(), "{details}");
    assert_eq!(
        details["certificates_without_crl"][0]["sha256"],
        "d04249adc82c33d5cc0b2de207defa23a91114277340d310e10c34d6a95d54ea"
    );
    assert_eq!(
        details["crl_retrieval"]["failures"][0]["source_error"],
        "abort"
    );
}

/// SEC-10: the only path's intermediate lacks keyCertSign and its root CRL.
/// No CRL could make that path verify, so nothing is named for retrieval and
/// the source is never asked: retrieval reports the path policy failure, as
/// verification without revocation finds it.
#[test]
fn sec10_fetch_never_asks_about_a_path_failing_key_usage() {
    struct Counts(usize);
    impl rssig::retrieval::CrlSource for Counts {
        fn crls(
            &mut self,
            _: &rssig::retrieval::CrlRequest<'_>,
        ) -> Result<rssig::retrieval::CrlResponse, rssig::retrieval::CrlSourceError> {
            self.0 += 1;
            Ok(rssig::retrieval::CrlResponse::new())
        }
    }
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let path = |name: &str| base.join(name).to_str().unwrap().to_owned();
    let args = |fetch: bool| {
        let mut args = vec![
            "rssig".to_owned(),
            "verify".to_owned(),
            "--no-system-roots".to_owned(),
            "--roots".to_owned(),
            path("sec06-root.der"),
            "--time".to_owned(),
            "1800000000".to_owned(),
            "--crl".to_owned(),
            path("sec06-issuer.crl"),
        ];
        if fetch {
            args.push("--fetch-crls".to_owned());
        }
        args.push(path("bad-sec06-ca-ku.exe"));
        args
    };
    // Offline: revocation is reported first, as on main, naming nothing.
    let (mut out, mut err) = (Vec::new(), Vec::new());
    assert_eq!(
        rssig::cli::run_with_writers(args(false), &mut out, &mut err).unwrap(),
        1
    );
    let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let error = &report["results"][0]["error"];
    assert_eq!(error["code"], "revocation_unknown");
    assert!(error["details"].get("certificates_without_crl").is_none());
    // With retrieval: no request, and the path policy failure decides.
    let mut source = Counts(0);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code =
        rssig::cli::run_with_crl_source(args(true), &mut out, &mut err, &mut source).unwrap();
    assert_eq!(code, 1);
    assert_eq!(source.0, 0);
    let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(report["results"][0]["error"]["code"], "invalid_key_usage");
}
