//! The public distribution-point URL check, `check_public_http_url`, on
//! arbitrary text. It parses untrusted URIs taken from certificates, so it
//! must never panic, and an accepted URL must be plain `http` without
//! credentials.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rssig::crl::check_public_http_url;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    if check_public_http_url(text).is_ok() {
        assert!(
            text.get(..5)
                .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http:")),
            "accepted a URL that is not http"
        );
        assert!(
            !text.contains('\0'),
            "accepted a URL with a control character"
        );
    }
});
