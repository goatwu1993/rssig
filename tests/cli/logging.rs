//! A logger injected into the in-process CLI never alters streams or results.
use rssig::{
    cli::{self, Host},
    domain::Stage,
    log::{Level, Logger, Record},
};
use std::{path::Path, sync::Mutex};

#[derive(Default)]
struct Capture(Mutex<Vec<(Level, Stage, String)>>);
impl Logger for Capture {
    fn log(&self, record: &Record<'_>) {
        self.0
            .lock()
            .unwrap()
            .push((record.level, record.stage, record.message.to_string()));
    }
}
impl Capture {
    fn has(&self, level: Level, stage: Stage, fragment: &str) -> bool {
        self.0
            .lock()
            .unwrap()
            .iter()
            .any(|(l, s, message)| *l == level && *s == stage && message.contains(fragment))
    }
}

fn fixture(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
        .to_str()
        .unwrap()
        .into()
}

#[test]
fn cli_logger_leaves_streams_and_exit_codes_unchanged() {
    for (file, exit) in [("good-pe64.exe", 0), ("bad-image-digest.exe", 1)] {
        let input = fixture(file);
        let args = [
            "rssig",
            "verify",
            "--integrity-only",
            "--time",
            "1800000000",
            &input,
        ];
        let (mut plain, mut plain_err) = (Vec::new(), Vec::new());
        assert_eq!(
            cli::run_with_writers(args, &mut plain, &mut plain_err).unwrap(),
            exit
        );
        let capture = Capture::default();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = cli::run_with_host(args, &mut out, &mut err, Host::new().with_logger(&capture))
            .unwrap();
        assert_eq!(code, exit);
        assert_eq!(out, plain);
        assert!(err.is_empty() && plain_err.is_empty());
        serde_json::from_slice::<serde_json::Value>(&out).expect("exactly one JSON document");
        assert!(capture.has(Level::Debug, Stage::Input, file));
        assert!(capture.has(Level::Warn, Stage::Configuration, "integrity-only"));
        assert_eq!(
            capture.has(Level::Info, Stage::Cms, "signer verified"),
            exit == 0
        );
    }
}

#[test]
fn cli_logger_is_not_used_for_argument_errors_or_parse() {
    struct Never;
    impl Logger for Never {
        fn log(&self, record: &Record<'_>) {
            panic!("unexpected record: {}", record.message);
        }
    }
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = cli::run_with_host(
        ["rssig", "verify"],
        &mut out,
        &mut err,
        Host::new().with_logger(&Never),
    )
    .unwrap();
    assert_eq!(code, 2);
    assert!(out.is_empty() && !err.is_empty());

    let input = fixture("good-pe64.exe");
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = cli::run_with_host(
        ["rssig", "parse", &input],
        &mut out,
        &mut err,
        Host::new().with_logger(&Never),
    )
    .unwrap();
    assert_eq!(code, 0);
    assert!(err.is_empty());
}

#[test]
fn cli_logger_and_crl_source_combine_and_log_each_request() {
    struct Source(Vec<u8>);
    impl rssig::retrieval::CrlSource for Source {
        fn fetch(
            &mut self,
            url: &str,
            _: usize,
        ) -> Result<rssig::retrieval::FetchedCrl, rssig::retrieval::FetchError> {
            Ok(rssig::retrieval::FetchedCrl {
                bytes: self.0.clone(),
                final_url: url.into(),
            })
        }
    }
    let (input, root) = (fixture("good-crl-discovery.exe"), fixture("root.der"));
    let args = [
        "rssig",
        "verify",
        "--no-system-roots",
        "--roots",
        &root,
        "--time",
        "1800000000",
        "--fetch-crls",
        &input,
    ];
    for (crl, exit) in [("good.crl", 0), ("revoked.crl", 1)] {
        let bytes = std::fs::read(fixture(crl)).unwrap();
        let (mut plain, mut plain_err) = (Vec::new(), Vec::new());
        cli::run_with_crl_source(args, &mut plain, &mut plain_err, &mut Source(bytes.clone()))
            .unwrap();
        let capture = Capture::default();
        let mut source = Source(bytes);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = cli::run_with_host(
            args,
            &mut out,
            &mut err,
            Host::new()
                .with_crl_source(&mut source)
                .with_logger(&capture),
        )
        .unwrap();
        assert_eq!(code, exit);
        assert_eq!(out, plain);
        assert!(err.is_empty());
        assert!(capture.has(
            Level::Info,
            Stage::Revocation,
            "http://crl.example.invalid/test.crl"
        ));
        assert!(capture.has(Level::Debug, Stage::Revocation, "not yet authenticated"));
        assert_eq!(
            capture.has(Level::Warn, Stage::Revocation, "verification failed"),
            exit == 1
        );
    }
}
