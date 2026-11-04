//! Runs against the same parser with or without the verification/CLI features.
use rssig::parse::{ErrorKind, Pe, PeTrait, SignedData};

const GOOD: &[u8] = include_bytes!("fixtures/good-pe64.exe");

#[test]
fn parser_errors_are_independent_of_verification() {
    for (bytes, kind) in [
        (
            include_bytes!("fixtures/bad-truncated.exe").as_slice(),
            ErrorKind::InvalidPe,
        ),
        (
            include_bytes!("fixtures/bad-pe-header-offset.exe").as_slice(),
            ErrorKind::InvalidPe,
        ),
        (
            include_bytes!("fixtures/unsigned.exe").as_slice(),
            ErrorKind::Unsigned,
        ),
    ] {
        let error = Pe::parse(bytes).unwrap_err();
        assert_eq!(error.kind(), kind);
        let _: &dyn core::error::Error = &error;
        assert!(!error.to_string().is_empty());
    }
    let pe = Pe::parse(include_bytes!("fixtures/bad-certificate-payload.exe")).unwrap();
    assert_eq!(
        pe.signatures().unwrap_err().kind(),
        ErrorKind::InvalidCertificateTable
    );
    assert_eq!(
        SignedData::parse(include_bytes!("fixtures/parse-truncated-cms.der"))
            .unwrap_err()
            .kind(),
        ErrorKind::MalformedCms,
    );
}

#[test]
fn borrowed_pe_chunks_preserve_the_authenticode_digest() {
    use sha2::{Digest, Sha256};
    for (bytes, expected) in [
        (
            GOOD,
            "dea5b51087a941e1757bc435b116fc1a7dfc9c8343bf4cb27b7fc9431a9dd30f",
        ),
        (
            include_bytes!("fixtures/bad-image-digest.exe").as_slice(),
            "821ba3d28e9ea20b53901de76a090d109e9dced8426ca75f2f844543b59cd243",
        ),
    ] {
        let pe = Pe::parse(bytes).unwrap();
        let mut hash = Sha256::new();
        for chunk in pe.authenticode_chunks() {
            assert!(chunk.as_ptr() >= bytes.as_ptr());
            assert!(chunk.as_ptr_range().end <= bytes.as_ptr_range().end);
            hash.update(chunk);
        }
        assert_eq!(format!("{:x}", hash.finalize()), expected);
    }
}

#[test]
fn cms_inspection_borrows_signer_encodings_without_allocating_on_access() {
    let pe = Pe::parse(GOOD).unwrap();
    let bytes = pe.signatures().unwrap()[0];
    let cms = SignedData::parse(bytes).unwrap();
    let signers: &[&[u8]] = cms.signer_infos();
    assert_eq!(signers.len(), 1);
    assert_eq!(signers.as_ptr(), cms.signer_infos().as_ptr());
    assert!(signers[0].as_ptr() >= bytes.as_ptr());
    assert!(signers[0].as_ptr_range().end <= bytes.as_ptr_range().end);
    assert_eq!(cms.certificate_choices().len(), 2);
    assert_eq!(cms.content_type().to_string(), "1.3.6.1.4.1.311.2.1.4");
}

#[test]
fn generic_pe_trait_digest_matches_existing_authenticode_chunks() {
    use sha2::{Digest, Sha256};
    let pe = Pe::parse(GOOD).unwrap();
    let mut generic = Sha256::new();
    rssig::parse::authenticode_digest(&pe, &mut generic).unwrap();
    let mut chunks = Sha256::new();
    for chunk in pe.authenticode_chunks() {
        chunks.update(chunk);
    }
    assert_eq!(generic.finalize(), chunks.finalize());
    assert_eq!(pe.offsets().unwrap().after_header, 512);
    assert_eq!(pe.num_sections(), 1);
    assert_eq!(pe.section_data_range(1).unwrap(), 512..1024);
    assert_eq!(pe.certificate_table_range().unwrap(), Some(1024..2176));
}

#[test]
fn generic_pe_trait_hashes_gaps_and_overlay_but_excludes_certificate_table() {
    use sha2::{Digest, Sha256};
    struct ExternalPe<'a>(&'a [u8]);
    impl rssig::parse::PeTrait for ExternalPe<'_> {
        fn data(&self) -> &[u8] {
            self.0
        }
        fn num_sections(&self) -> usize {
            1
        }
        fn section_data_range(
            &self,
            index: usize,
        ) -> Result<std::ops::Range<usize>, rssig::parse::PeOffsetError> {
            if index == 1 {
                Ok(28..30)
            } else {
                Err(rssig::parse::PeOffsetError)
            }
        }
        fn certificate_table_range(
            &self,
        ) -> Result<Option<std::ops::Range<usize>>, rssig::parse::PeOffsetError> {
            Ok(Some(36..40))
        }
        fn offsets(&self) -> Result<rssig::parse::PeOffsets, rssig::parse::PeOffsetError> {
            Ok(rssig::parse::PeOffsets {
                check_sum: 4,
                after_check_sum: 8,
                security_data_dir: 12,
                after_security_data_dir: 20,
                after_header: 24,
            })
        }
    }
    let bytes: Vec<u8> = (0..40).collect();
    let mut actual = Sha256::new();
    rssig::parse::authenticode_digest(&ExternalPe(&bytes), &mut actual).unwrap();
    let mut expected = Sha256::new();
    for range in [0..4, 8..12, 20..24, 28..30, 26..36] {
        expected.update(&bytes[range]);
    }
    assert_eq!(actual.finalize(), expected.finalize());
}
