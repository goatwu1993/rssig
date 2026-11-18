use super::support::*;
#[test]
fn crl_fetch_rejects_private_destinations_and_checks_integrity_first() {
    for (file, code) in [
        ("bad-crl-private-url.exe", "crl_fetch_denied"),
        ("bad-crl-discovery-image.exe", "image_digest_mismatch"),
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
        assert_eq!(out.json["results"][0]["error"]["code"], code);
    }
}

#[test]
fn crl_fetch_injected_bytes_are_authenticated_and_reported() {
    struct Source {
        bytes: Vec<u8>,
        calls: usize,
    }
    impl rssig::retrieval::CrlSource for Source {
        fn fetch(
            &mut self,
            url: &str,
            _: usize,
        ) -> Result<rssig::retrieval::FetchedCrl, rssig::VerificationError> {
            assert_eq!(url, "http://crl.example.invalid/test.crl");
            self.calls += 1;
            Ok(rssig::retrieval::FetchedCrl {
                bytes: self.bytes.clone(),
                final_url: url.into(),
            })
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
        fn fetch(
            &mut self,
            _: &str,
            _: usize,
        ) -> Result<rssig::retrieval::FetchedCrl, rssig::VerificationError> {
            panic!("supplied CRL or offline mode must not call the provider");
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
        fn fetch(
            &mut self,
            url: &str,
            _: usize,
        ) -> Result<rssig::retrieval::FetchedCrl, rssig::VerificationError> {
            self.calls += 1;
            Ok(rssig::retrieval::FetchedCrl {
                bytes: self.bytes.clone(),
                final_url: url.into(),
            })
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
        fn fetch(
            &mut self,
            url: &str,
            _: usize,
        ) -> Result<rssig::retrieval::FetchedCrl, rssig::VerificationError> {
            self.requests.push(url.into());
            Ok(rssig::retrieval::FetchedCrl {
                bytes: self.response.clone().expect("unexpected provider call"),
                final_url: url.into(),
            })
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
        // A listed point that discovery does not support is denied, not fetched: without
        // --fetch-crls the same inputs are revocation_unknown.
        ("sec10-leaf-crl-dp-reasons.exe", ["sec06-root.crl", "sec10-issuer-idp-match.crl"], None, &[], Some("crl_fetch_denied")),
        ("sec10-leaf-crl-dp-crl-issuer.exe", ["sec06-root.crl", "sec10-issuer-idp-match.crl"], None, &[], Some("crl_fetch_denied")),
        ("sec10-leaf-crl-dp-dns.exe", ["sec06-root.crl", "sec10-issuer-idp-dns.crl"], None, &[], Some("crl_fetch_denied")),
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
        fn fetch(
            &mut self,
            url: &str,
            _: usize,
        ) -> Result<rssig::retrieval::FetchedCrl, rssig::VerificationError> {
            self.requests.push(url.into());
            let (_, bytes) = self
                .responses
                .iter()
                .find(|(known, _)| *known == url)
                .ok_or_else(|| {
                    rssig::VerificationError::new(
                        rssig::domain::ErrorCode::CrlFetchFailed,
                        rssig::domain::Stage::Revocation,
                        "no response for this URL",
                    )
                })?;
            Ok(rssig::retrieval::FetchedCrl {
                bytes: bytes.clone(),
                final_url: url.into(),
            })
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
    let rows: [Row; 5] = [
        // A CRL with the issuer's name from another key is excluded by verification,
        // so it does not stand in for the listed point.
        ("good-crl-discovery.exe", "root.der", &["sec10-root-name-other-aki-expired.crl"], &[(EXAMPLE_POINT, "good.crl")], &[EXAMPLE_POINT], None),
        // A supplied CRL that verification rejects is reported as it is offline; the
        // provider is not asked, although it could answer.
        ("good-sec06-basic.exe", "sec06-root.der", &["sec06-root.crl", "sec10-issuer-idp-match-ca.crl"], &[], &[], Some(("invalid_crl", "distribution_point_scope"))),
        ("sec10-leaf-crl-dp.exe", "sec06-root.der", &["sec06-root.crl", "sec10-issuer-idp-relative.crl"], &[(LEAF_POINT, "sec10-issuer-idp-match.crl")], &[], Some(("invalid_crl", "issuing_distribution_point"))),
        // Both selected certificates list a point. Only the issuer has no supplied CRL
        // naming its issuer, so only its point is requested: the signer's point has no
        // response here and a request for it would fail the run.
        ("sec10-chain-crl-dp.exe", "sec06-root.der", &["sec06-issuer.crl"], &[(CA_POINT, "sec06-root.crl")], &[CA_POINT], None),
        // A name-matching CRL that is not authoritative for the signer: its point is
        // requested second, after the certainly missing one did not settle the status.
        ("sec10-chain-crl-dp.exe", "sec06-root.der", &["sec10-issuer-idp-other.crl"], &[(CA_POINT, "sec06-root.crl"), (LEAF_POINT, "sec10-issuer-idp-match.crl")], &[CA_POINT, LEAF_POINT], None),
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
            let artifacts = result["crl_retrieval"]["artifacts"].as_array().unwrap();
            assert_eq!(artifacts.len(), requests.len(), "{label}");
            for (artifact, request) in artifacts.iter().zip(requests) {
                assert_eq!(artifact["url"], *request, "{label}");
            }
            // Supplied CRLs stay loaded beside the fetched ones.
            assert_eq!(
                revocation["crls"].as_array().unwrap().len(),
                supplied.len() + requests.len(),
                "{label}"
            );
        }
    }
}
