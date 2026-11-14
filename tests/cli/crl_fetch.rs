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
