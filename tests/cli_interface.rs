use rssig::cli;
use serde_json::Value;

#[test]
fn missing_files_are_plain_usage_errors() {
    let case: Value =
        serde_json::from_str(include_str!("fixtures/cli-missing-files.json")).unwrap();
    let argv: Vec<_> = case["argv"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = cli::run_with_writers(argv, &mut stdout, &mut stderr).unwrap();
    assert_eq!(exit, case["exit_code"].as_u64().unwrap() as u8);
    assert_eq!(
        String::from_utf8(stdout).unwrap(),
        case["stdout"].as_str().unwrap()
    );
    assert!(serde_json::from_slice::<Value>(&stderr).is_err());
    let text = String::from_utf8(stderr).unwrap();
    for fragment in case["stderr_contains"].as_array().unwrap() {
        assert!(text.contains(fragment.as_str().unwrap()));
    }
}

#[test]
fn invalid_arguments_are_captured_without_exiting_the_test_process() {
    let (exit, stdout, stderr) = invoke_raw(&["rssig".into(), "verify".into()]);
    assert_eq!(exit, 2);
    assert!(stdout.is_empty());
    assert!(stderr.starts_with("error:"));
    assert!(stderr.contains("<FILES>..."));
}

#[test]
fn help_is_plain_text_on_stdout() {
    let (exit, stdout, stderr) = invoke_raw(&["rssig".into(), "--help".into()]);
    assert_eq!(exit, 0);
    assert!(stderr.is_empty());
    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("verify"));
    assert!(serde_json::from_str::<Value>(&stdout).is_err());
}

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn invoke(arguments: &[std::ffi::OsString]) -> (u8, Value) {
    let (code, stdout, stderr) = invoke_raw(arguments);
    assert!(stderr.is_empty());
    (code, serde_json::from_str(&stdout).unwrap())
}

fn invoke_raw(arguments: &[std::ffi::OsString]) -> (u8, String, String) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = cli::run_with_writers(arguments, &mut stdout, &mut stderr).unwrap();
    (
        code,
        String::from_utf8(stdout).unwrap(),
        String::from_utf8(stderr).unwrap(),
    )
}

#[test]
fn multiple_inputs_preserve_successes_and_each_problem_in_input_order() {
    let args = vec![
        "rssig".into(),
        "verify".into(),
        "--integrity-only".into(),
        "--time".into(),
        "1800000000".into(),
        fixture("good-pe64.exe").into_os_string(),
        fixture("bad-image-digest.exe").into_os_string(),
        fixture("not-pe.bin").into_os_string(),
    ];
    let (code, json) = invoke(&args);
    assert_eq!(code, 1);
    assert_eq!(json["results"].as_array().unwrap().len(), 3);
    assert_eq!(json["results"][0]["ok"], true);
    assert_eq!(json["results"][1]["error"]["code"], "image_digest_mismatch");
    assert_eq!(json["results"][2]["error"]["code"], "invalid_pe");
    assert_eq!(json["type"], json["results"][1]["error"]["type"]);
}

#[test]
fn version_is_plain_text_on_stdout() {
    let (code, stdout, stderr) = invoke_raw(&["rssig".into(), "--version".into()]);
    assert_eq!(code, 0);
    assert!(stderr.is_empty());
    assert_eq!(stdout, format!("rssig {}\n", env!("CARGO_PKG_VERSION")));
}

#[test]
fn unknown_subcommands_are_argument_problems() {
    let (code, stdout, stderr) = invoke_raw(&["rssig".into(), "does-not-exist".into()]);
    assert_eq!(code, 2);
    assert!(stdout.is_empty());
    assert!(stderr.contains("unrecognized subcommand"));
    assert!(stderr.contains("'does-not-exist'"));
}

#[test]
fn old_test_runner_is_no_longer_a_product_command() {
    let (code, stdout, stderr) = invoke_raw(&["rssig".into(), "test".into()]);
    assert_eq!(code, 2);
    assert!(stdout.is_empty());
    assert!(stderr.contains("unrecognized subcommand"));
    assert!(stderr.contains("'test'"));
}

#[test]
fn integrity_only_conflicts_with_trust_policy_flags() {
    let (code, stdout, stderr) = invoke_raw(&[
        "rssig".into(),
        "verify".into(),
        "--integrity-only".into(),
        "--no-system-roots".into(),
        fixture("good-pe64.exe").into_os_string(),
    ]);
    assert_eq!(code, 2);
    assert!(stdout.is_empty());
    assert!(stderr.contains("cannot be used with"));
}

fn configuration_problem(flag: &str, file: &str) {
    let mut args: Vec<std::ffi::OsString> = [
        "rssig",
        "verify",
        "--no-system-roots",
        "--no-revocation",
        "--time",
        "1800000000",
    ]
    .into_iter()
    .map(Into::into)
    .collect();
    args.extend([
        flag.into(),
        fixture(file).into_os_string(),
        fixture("good-pe64.exe").into_os_string(),
    ]);
    let (code, stdout, stderr) = invoke_raw(&args);
    assert_eq!(code, 2);
    assert!(stdout.is_empty());
    assert!(stderr.starts_with("error:"));
    assert!(stderr.contains(file));
    assert!(serde_json::from_str::<Value>(&stderr).is_err());
}

#[test]
fn missing_roots_are_configuration_problems() {
    configuration_problem("--roots", "missing-root.der");
}
#[test]
fn malformed_roots_are_configuration_problems() {
    configuration_problem("--roots", "not-pe.bin");
}
#[test]
fn missing_crls_are_configuration_problems() {
    configuration_problem("--crl", "missing.crl");
}
#[test]
fn malformed_crls_are_configuration_problems() {
    configuration_problem("--crl", "not-pe.bin");
}

#[test]
fn verification_without_time_uses_the_clock_without_affecting_unsigned_errors() {
    // Unsigned input makes this assertion independent of the wall clock.
    let (code, json) = invoke(&[
        "rssig".into(),
        "verify".into(),
        "--integrity-only".into(),
        fixture("unsigned.exe").into_os_string(),
    ]);
    assert_eq!(code, 1);
    assert_eq!(json["results"][0]["error"]["code"], "unsigned");
}

#[test]
fn writer_failures_are_returned_without_panicking() {
    struct Closed;
    impl std::io::Write for Closed {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "sink closed",
            ))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let error = cli::run(["rssig", "--help"], Closed).unwrap_err();
    assert!(error.to_string().contains("sink closed"));
    let mut stdout = Vec::new();
    let error = cli::run_with_writers(["rssig", "verify"], &mut stdout, Closed).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    assert!(stdout.is_empty());
    let mut stderr = Vec::new();
    let args = [
        "rssig".into(),
        "verify".into(),
        "--integrity-only".into(),
        "--time".into(),
        "1800000000".into(),
        fixture("unsigned.exe").into_os_string(),
    ];
    let error = cli::run_with_writers(args, Closed, &mut stderr).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    assert!(stderr.is_empty());
}

#[test]
fn single_writer_entry_point_captures_plain_command_diagnostics() {
    let mut output = Vec::new();
    assert_eq!(cli::run(["rssig", "verify"], &mut output).unwrap(), 2);
    assert!(String::from_utf8(output).unwrap().starts_with("error:"));
}
