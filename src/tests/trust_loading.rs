//! SEC-07 explicit maintenance only: PEM wrapping and narrow loading mutations.
use std::path::Path;

pub(super) fn write(dir: &Path) {
    let root = std::fs::read(dir.join("root.der")).unwrap();
    let crl = std::fs::read(dir.join("good.crl")).unwrap();
    let forged = std::fs::read(dir.join("forged.crl")).unwrap();
    let pem = |label, bytes: &[u8]| {
        ::der::pem::encode_string(label, ::der::pem::LineEnding::LF, bytes)
            .unwrap()
            .into_bytes()
    };
    let root_pem = pem("CERTIFICATE", &root);
    let crl_pem = pem("X509 CRL", &crl);
    let mut unsupported = root.clone();
    let at = unsupported
        .windows(5)
        .position(|w| w == [0xa0, 3, 2, 1, 2])
        .unwrap();
    unsupported[at + 4] = 1;
    let bad_root = pem("CERTIFICATE", &[0x30, 0]);
    let bad_crl = pem("X509 CRL", &[0x30, 0]);
    let write = |name, bytes| std::fs::write(dir.join(name), bytes).unwrap();
    write("sec07-root-unsupported.der", unsupported.clone());
    write("sec07-roots-good.pem", root_pem.clone());
    write(
        "sec07-roots-duplicate.pem",
        [root_pem.as_slice(), &root_pem].concat(),
    );
    write(
        "sec07-roots-unsupported.pem",
        [root_pem.as_slice(), &pem("CERTIFICATE", &unsupported)].concat(),
    );
    write(
        "sec07-roots-invalid.pem",
        [root_pem.as_slice(), &bad_root].concat(),
    );
    write(
        "sec07-roots-invalid-first.pem",
        [bad_root.as_slice(), &root_pem].concat(),
    );
    write(
        "sec07-roots-trailing.pem",
        [root_pem.as_slice(), b"!"].concat(),
    );
    write(
        "sec07-roots-truncated.pem",
        [root_pem.as_slice(), &root_pem[..root_pem.len() - 28]].concat(),
    );
    write(
        "sec07-roots-whitespace.pem",
        [b" \t\r\n".as_slice(), &root_pem, b" \t\r\n"].concat(),
    );
    write("sec07-crls-good.pem", crl_pem.clone());
    write(
        "sec07-crls-duplicate.pem",
        [crl_pem.as_slice(), &crl_pem].concat(),
    );
    write(
        "sec07-crls-invalid.pem",
        [crl_pem.as_slice(), &bad_crl].concat(),
    );
    write(
        "sec07-crls-invalid-first.pem",
        [bad_crl.as_slice(), &crl_pem].concat(),
    );
    write(
        "sec07-crls-trailing.pem",
        [crl_pem.as_slice(), b"!"].concat(),
    );
    write("sec07-crls-forged.pem", pem("X509 CRL", &forged));
    write("sec07-empty.pem", Vec::new());
}
