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
            Ok(Some(32..40))
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
    for range in [0..4, 8..12, 20..32] {
        expected.update(&bytes[range]);
    }
    assert_eq!(actual.finalize(), expected.finalize());
}

#[test]
fn generic_pe_digest_matches_committed_gap_overlay_fixture() {
    use sha2::{Digest, Sha256};
    let pe = Pe::parse(include_bytes!("fixtures/bad-pe-gap-overlay-digest.exe")).unwrap();
    let mut hash = Sha256::new();
    rssig::parse::authenticode_digest(&pe, &mut hash).unwrap();
    assert_eq!(
        format!("{:x}", hash.finalize()),
        "52dcc6b7526e7ebf531f9493ebba135f41eba0639a9cad7c7518fb6e2f5fc21d"
    );
}

#[derive(Clone)]
struct ExternalLayout {
    count: Option<usize>,
    offsets: rssig::parse::PeOffsets,
    sections: Vec<std::ops::Range<usize>>,
    certificate: Option<std::ops::Range<usize>>,
}

impl Default for ExternalLayout {
    fn default() -> Self {
        Self {
            count: None,
            offsets: rssig::parse::PeOffsets {
                check_sum: 4,
                after_check_sum: 8,
                security_data_dir: 12,
                after_security_data_dir: 20,
                after_header: 24,
            },
            sections: vec![24..28, 28..32],
            certificate: Some(32..40),
        }
    }
}

impl PeTrait for ExternalLayout {
    fn data(&self) -> &[u8] {
        b"0123456789012345678901234567890123456789"
    }
    fn offsets(&self) -> Result<rssig::parse::PeOffsets, rssig::parse::PeOffsetError> {
        Ok(self.offsets.clone())
    }
    fn num_sections(&self) -> usize {
        self.count.unwrap_or(self.sections.len())
    }
    fn section_data_range(
        &self,
        index: usize,
    ) -> Result<std::ops::Range<usize>, rssig::parse::PeOffsetError> {
        self.sections
            .get(index.checked_sub(1).ok_or(rssig::parse::PeOffsetError)?)
            .cloned()
            .ok_or(rssig::parse::PeOffsetError)
    }
    fn certificate_table_range(
        &self,
    ) -> Result<Option<std::ops::Range<usize>>, rssig::parse::PeOffsetError> {
        Ok(self.certificate.clone())
    }
}

#[derive(Default)]
struct RecordingSink(Vec<u8>);
impl digest::Update for RecordingSink {
    fn update(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }
}

#[test]
#[allow(clippy::single_range_in_vec_init)] // Each element is a section range, not its bytes.
fn generic_pe_rejects_invalid_layout_without_updating_sink() {
    let base = ExternalLayout::default();
    let mut invalid = Vec::new();
    for certificate in [
        40..48,
        24..32,
        16..40,
        32..32,
        33..40,
        32..39,
        std::ops::Range { start: 40, end: 32 },
        usize::MAX - 7..usize::MAX,
    ] {
        invalid.push(ExternalLayout {
            certificate: Some(certificate),
            ..base.clone()
        });
    }
    for sections in [
        vec![20..24],
        vec![24..29, 28..32],
        vec![24..26, 28..32],
        vec![24..40],
        vec![24..41],
        vec![std::ops::Range { start: 28, end: 24 }],
    ] {
        invalid.push(ExternalLayout {
            sections,
            ..base.clone()
        });
    }
    for count in [3, u16::MAX as usize + 1, usize::MAX] {
        invalid.push(ExternalLayout {
            count: Some(count),
            ..base.clone()
        });
    }
    for field in 0..7 {
        let mut view = base.clone();
        match field {
            0 => view.offsets.after_check_sum = 7,
            1 => view.offsets.after_security_data_dir = 19,
            2 => {
                view.offsets.security_data_dir = 6;
                view.offsets.after_security_data_dir = 14;
            }
            3 => view.offsets.after_header = 19,
            4 => view.offsets.after_header = 41,
            5 => view.offsets.check_sum = usize::MAX,
            _ => view.offsets.security_data_dir = usize::MAX,
        }
        invalid.push(view);
    }
    for (i, view) in invalid.iter().enumerate() {
        let mut sink = RecordingSink(b"prefix".to_vec());
        assert_eq!(
            rssig::parse::authenticode_digest(view, &mut sink),
            Err(rssig::parse::PeOffsetError),
            "layout {i}"
        );
        assert_eq!(sink.0, b"prefix", "layout {i} partially updated sink");
    }
}

#[test]
fn generic_pe_supports_unsigned_and_reordered_sections() {
    for certificate in [Some(32..40), None] {
        let end = certificate.as_ref().map_or(40, |r| r.start);
        let view = ExternalLayout {
            sections: vec![28..32, 24..28, 0..0],
            certificate,
            ..ExternalLayout::default()
        };
        let mut sink = RecordingSink::default();
        rssig::parse::authenticode_digest(&view, &mut sink).unwrap();
        let bytes = view.data();
        assert_eq!(
            sink.0,
            [&bytes[..4], &bytes[8..12], &bytes[20..end]].concat()
        );
    }
}

#[test]
fn generic_pe_hashes_sectionless_images() {
    for certificate in [Some(32..40), None] {
        let end = certificate.as_ref().map_or(40, |r| r.start);
        let view = ExternalLayout {
            sections: Vec::new(),
            certificate,
            ..ExternalLayout::default()
        };
        let mut sink = RecordingSink::default();
        rssig::parse::authenticode_digest(&view, &mut sink).unwrap();
        let bytes = view.data();
        assert_eq!(
            sink.0,
            [&bytes[..4], &bytes[8..12], &bytes[20..end]].concat()
        );
    }
}
