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

#[test]
fn cab_and_navx_borrow_container_signature_and_digest_bytes() {
    use rssig::parse::{Cab, Navx};
    use sha2::{Digest, Sha256};
    fn borrowed(input: &[u8], slice: &[u8]) {
        assert!(slice.as_ptr() >= input.as_ptr());
        assert!(slice.as_ptr_range().end <= input.as_ptr_range().end);
    }
    for bytes in [
        include_bytes!("fixtures/good.cab").as_slice(),
        include_bytes!("fixtures/cab-independent-jsign.cab").as_slice(),
        include_bytes!("fixtures/bad-cab-digest.cab").as_slice(),
        include_bytes!("fixtures/bad-cab-framing-and-digest.cab").as_slice(),
    ] {
        let cab = Cab::parse(bytes).unwrap();
        let end = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        assert_eq!(cab.as_bytes().as_ptr(), bytes.as_ptr());
        assert_eq!(cab.signature(), &bytes[end..]);
        borrowed(bytes, cab.signature());
        let mut digest = Sha256::new();
        for chunk in cab.authenticode_chunks() {
            borrowed(bytes, chunk);
            digest.update(chunk);
        }
        // Independent recipe, including the synthetic four zero bytes.
        let expected = [&bytes[..4], &bytes[8..34], &[0; 4], &bytes[60..end]].concat();
        assert_eq!(digest.finalize(), Sha256::digest(expected));
    }
    for bytes in [
        include_bytes!("fixtures/good.navx").as_slice(),
        include_bytes!("fixtures/navx-independent-jsign.navx").as_slice(),
        include_bytes!("fixtures/bad-navx-digest.navx").as_slice(),
        include_bytes!("fixtures/bad-navx-framing-and-digest.navx").as_slice(),
    ] {
        let navx = Navx::parse(bytes).unwrap();
        let end = 40 + u32::from_le_bytes(bytes[28..32].try_into().unwrap()) as usize;
        assert_eq!(navx.as_bytes().as_ptr(), bytes.as_ptr());
        assert_eq!(navx.signature(), &bytes[end + 4..bytes.len() - 8]);
        borrowed(bytes, navx.signature());
        let [chunk] = navx.authenticode_chunks();
        borrowed(bytes, chunk);
        assert_eq!(chunk, &bytes[..end]);
    }
}

#[test]
fn cab_and_navx_have_typed_structural_errors_without_verification() {
    use rssig::parse::{Cab, Navx};
    for (error, kind) in [
        (
            Cab::parse(include_bytes!("fixtures/bad-cab-offset.cab")).unwrap_err(),
            ErrorKind::InvalidCab,
        ),
        (
            Cab::parse(include_bytes!("fixtures/unsigned.cab")).unwrap_err(),
            ErrorKind::UnsignedCab,
        ),
        (
            Cab::parse(include_bytes!("fixtures/unsigned-cab-no-reserve.cab")).unwrap_err(),
            ErrorKind::UnsignedCab,
        ),
        (
            Navx::parse(include_bytes!("fixtures/bad-navx-offset.navx")).unwrap_err(),
            ErrorKind::InvalidNavx,
        ),
        (
            Navx::parse(include_bytes!("fixtures/unsigned.navx")).unwrap_err(),
            ErrorKind::UnsignedNavx,
        ),
    ] {
        assert_eq!(error.kind(), kind);
        let error: &dyn core::error::Error = &error;
        assert!(error.source().is_some());
        assert!(!error.to_string().is_empty());
    }
    // CMS interpretation remains separate from bounded container extraction.
    assert!(Cab::parse(include_bytes!("fixtures/bad-cab-malformed-cms.cab")).is_ok());
    assert!(Navx::parse(include_bytes!("fixtures/bad-navx-malformed-cms.navx")).is_ok());
}

#[test]
fn cab_and_navx_truncations_and_extreme_fields_fail_without_panics() {
    use rssig::parse::{Cab, Navx};
    let cab = include_bytes!("fixtures/good.cab");
    let navx = include_bytes!("fixtures/good.navx");
    for end in 0..cab.len() {
        assert!(Cab::parse(&cab[..end]).is_err(), "CAB prefix {end}");
    }
    for end in 0..navx.len() {
        assert!(Navx::parse(&navx[..end]).is_err(), "NAVX prefix {end}");
    }
    for at in [8, 16, 44, 48, 60, 68, 72] {
        let mut bytes = cab.to_vec();
        bytes[at..at + 4].fill(255);
        assert_eq!(
            Cab::parse(&bytes).unwrap_err().kind(),
            ErrorKind::InvalidCab
        );
    }
    for at in [26, 28, 34, 36, 64, 76, 90, 92] {
        let mut bytes = cab.to_vec();
        bytes[at..at + 2].fill(255);
        assert_eq!(
            Cab::parse(&bytes).unwrap_err().kind(),
            ErrorKind::InvalidCab
        );
    }
    let mut bytes = navx.to_vec();
    bytes[28..32].fill(255);
    assert_eq!(
        Navx::parse(&bytes).unwrap_err().kind(),
        ErrorKind::InvalidNavx
    );
}

#[test]
fn structured_cms_views_preserve_borrowed_unknown_values() {
    use rssig::parse::{SignerIdentifier, SignerInfo};
    let bytes = include_bytes!("fixtures/parse-signer-views.der");
    let cms = SignedData::parse(bytes).unwrap();
    let content = cms.content().unwrap();
    assert_eq!(content.tag(), 4);
    assert_eq!(content.value(), b"hello");
    assert_eq!(content.as_der(), cms.content_der().unwrap());
    for (i, raw) in cms.signer_infos().iter().enumerate() {
        let signer = SignerInfo::parse(raw).unwrap();
        assert_eq!(signer.as_der().as_ptr(), raw.as_ptr());
        assert_eq!(
            signer.digest_algorithm().oid().to_string(),
            "2.16.840.1.101.3.4.2.1"
        );
        assert_eq!(signer.signature_algorithm().oid().to_string(), "1.2.3.5");
        assert_eq!(
            signer.signature_algorithm().parameters_der(),
            Some(b"\x30\x00".as_slice())
        );
        assert_eq!(signer.signature(), b"sig");
        match signer.identifier() {
            SignerIdentifier::IssuerAndSerialNumber {
                issuer_der,
                serial_number_der,
            } => {
                assert_eq!(i, 0);
                assert_eq!(issuer_der, b"\x30\x00");
                assert_eq!(serial_number_der, b"\x02\x01\x01");
            }
            SignerIdentifier::SubjectKeyIdentifier(value) => {
                assert_eq!(i, 1);
                assert_eq!(value, b"key-id");
            }
        }
        let signed = signer.signed_attributes().unwrap();
        assert_eq!(signed.attributes()[0].oid().to_string(), "1.2.3.4");
        assert_eq!(signed.attributes()[0].values()[0].value(), b"opaque");
        let unsigned = signer.unsigned_attributes().unwrap();
        assert_eq!(unsigned.attributes()[0].values().len(), 2);
        for attr in signed.attributes().iter().chain(unsigned.attributes()) {
            for value in attr.values() {
                assert!(value.as_der().as_ptr() >= bytes.as_ptr());
                assert!(value.as_der().as_ptr_range().end <= bytes.as_ptr_range().end);
            }
        }
    }
    let bad = SignedData::parse(include_bytes!(
        "fixtures/parse-signer-bad-signature-tag.der"
    ))
    .unwrap();
    assert_eq!(
        SignerInfo::parse(bad.signer_infos()[0]).unwrap_err().kind(),
        ErrorKind::MalformedCms
    );
}

#[test]
fn structured_signer_bounds_and_attribute_rules_are_explicit() {
    use rssig::parse::{AlgorithmIdentifier, Attributes, SignerInfo};
    let cms = SignedData::parse(include_bytes!("fixtures/parse-signer-views.der")).unwrap();
    let raw = cms.signer_infos()[0];
    for end in 0..raw.len() {
        assert!(SignerInfo::parse(&raw[..end]).is_err(), "prefix {end}");
    }
    let signer = SignerInfo::parse(raw).unwrap();
    let attr = signer.signed_attributes().unwrap().attributes()[0].as_der();
    let wrap = |tag: u8, body: &[u8]| {
        let mut v = vec![tag, body.len() as u8];
        v.extend(body);
        v
    };
    let duplicate = wrap(0xa0, &[attr, attr].concat());
    assert!(
        Attributes::parse(&duplicate)
            .unwrap_err()
            .to_string()
            .contains("duplicate")
    );
    let mut empty_value = attr.to_vec();
    empty_value.truncate(7);
    empty_value[1] = 7;
    empty_value.extend([0x31, 0]);
    assert!(Attributes::parse(&wrap(0xa0, &empty_value)).is_err());
    let mut other = attr.to_vec();
    other[6] = 8;
    assert!(Attributes::parse(&wrap(0xa0, &[&other[..], attr].concat())).is_err());
    assert!(Attributes::parse(&wrap(0xa1, &[&other[..], attr].concat())).is_ok());
    assert!(Attributes::parse(&wrap(0x31, attr)).is_err());
    assert!(AlgorithmIdentifier::parse(b"\x30\x00").is_err());
    assert!(AlgorithmIdentifier::parse(b"\x30\x03\x06\x01\x80").is_err());
    assert!(AlgorithmIdentifier::parse(b"\x30\x07\x06\x03\x2a\x03\x05\x30\x00").is_ok());
}

#[test]
fn structured_signers_inspect_existing_authenticode_without_authentication() {
    use rssig::parse::SignerInfo;
    for bytes in [
        GOOD,
        include_bytes!("fixtures/bad-cms-signature.exe").as_slice(),
        include_bytes!("fixtures/unsupported-digest-algorithm.exe").as_slice(),
        include_bytes!("fixtures/good-rfc3161.exe").as_slice(),
        include_bytes!("fixtures/good-nested.exe").as_slice(),
    ] {
        let pe = Pe::parse(bytes).unwrap();
        let cms = SignedData::parse(pe.signatures().unwrap()[0]).unwrap();
        for raw in cms.signer_infos() {
            let signer = SignerInfo::parse(raw).unwrap();
            assert!(!signer.signature().is_empty());
            assert_eq!(signer.version_der(), b"\x02\x01\x01");
        }
    }
}

#[test]
fn signer_identity_versions_and_optional_attributes_are_structural_only() {
    use rssig::parse::SignerInfo;
    let cms = SignedData::parse(include_bytes!("fixtures/parse-signer-views.der")).unwrap();
    let signer = SignerInfo::parse(cms.signer_infos()[0]).unwrap();
    let make = |version: &[u8], sid: &[u8]| {
        let body = [
            version,
            sid,
            signer.digest_algorithm().as_der(),
            signer.signature_algorithm().as_der(),
            b"\x04\x03sig",
        ]
        .concat();
        let mut bytes = vec![0x30, body.len() as u8];
        bytes.extend(body);
        bytes
    };
    let bare = make(b"\x02\x01\x01", signer.identifier_der());
    let parsed = SignerInfo::parse(&bare).unwrap();
    assert!(parsed.signed_attributes().is_none());
    assert!(parsed.unsigned_attributes().is_none());
    assert!(SignerInfo::parse(&make(b"\x02\x01\xff", signer.identifier_der())).is_err());
    assert!(SignerInfo::parse(&make(b"\x05\x00", signer.identifier_der())).is_err());
    assert!(SignerInfo::parse(&make(b"\x02\x01\x01", b"\x81\x01x")).is_err());
    let future_version = make(b"\x02\x01\x7f", signer.identifier_der());
    assert_eq!(
        SignerInfo::parse(&future_version).unwrap().version_der(),
        b"\x02\x01\x7f"
    );
}
