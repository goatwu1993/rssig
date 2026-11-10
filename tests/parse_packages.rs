//! Structural adapters consume committed, inert packages without verification.
#[cfg(any(feature = "verify", feature = "msi"))]
mod msi {
    use rssig::parse::{ErrorKind, Msi};
    use sha2::{Digest, Sha256};

    #[test]
    fn metadata_and_content_are_independent_of_the_embedded_extended_digest() {
        let bytes = include_bytes!("fixtures/msi-good-pe64.msi");
        let mut package = Msi::parse(bytes).unwrap();
        assert_eq!(package.as_bytes().as_ptr(), bytes.as_ptr());
        let mut metadata = Sha256::new();
        package.update_metadata(&mut metadata).unwrap();
        let metadata = metadata.finalize();
        assert_eq!(package.extended_digest(), Some(&metadata[..]));
        let mut first = Sha256::new();
        first.update(metadata);
        package.update_content(&mut first).unwrap();
        let mut second = Sha256::new();
        second.update(metadata);
        package.update_content(&mut second).unwrap();
        assert_eq!(first.finalize(), second.finalize());
        // Empty extended evidence stays present; parsing makes no digest claim.
        let bad = Msi::parse(include_bytes!("fixtures/msi-bad-empty-extended.msi")).unwrap();
        assert_eq!(bad.extended_digest(), Some([].as_slice()));
        assert!(!bad.signature().is_empty());
        assert_eq!(
            Msi::parse(b"bad").err().unwrap().kind(),
            ErrorKind::InvalidMsi
        );
        assert_eq!(
            Msi::parse(include_bytes!("fixtures/msi-unsigned.msi"))
                .err()
                .unwrap()
                .kind(),
            ErrorKind::UnsignedMsi
        );
    }
}

#[cfg(any(feature = "verify", feature = "appx"))]
mod appx {
    use rssig::parse::{Appx, ErrorKind};
    use sha2::{Digest, Sha256};

    #[test]
    fn digest_inputs_and_metadata_have_no_verification_state() {
        let bytes = include_bytes!("fixtures/good.msix");
        let package = Appx::parse(bytes).unwrap();
        assert_eq!(package.as_bytes().as_ptr(), bytes.as_ptr());
        assert!(!package.is_bundle());
        assert_eq!(
            package.identity().unwrap().publisher,
            "CN=rssig test publisher"
        );
        let first = package.digest_inputs().unwrap();
        let second = package.digest_inputs().unwrap();
        assert_eq!(
            first.iter().map(|c| c.tag).collect::<Vec<_>>(),
            ["AXPC", "AXCD", "AXCT", "AXBM"]
        );
        assert_eq!(first[0].bytes.as_ptr(), bytes.as_ptr());
        for (a, b) in first.iter().zip(second.iter()) {
            assert_eq!(a.bytes, b.bytes);
            assert_eq!(Sha256::digest(&a.bytes), Sha256::digest(&b.bytes));
        }
        // A structurally readable identity does not establish publisher binding.
        Appx::parse(include_bytes!("fixtures/bad-appx-publisher.msix"))
            .unwrap()
            .identity()
            .unwrap();
        assert_eq!(
            Appx::parse(b"bad").err().unwrap().kind(),
            ErrorKind::InvalidAppx
        );
    }

    #[test]
    fn archive_parts_and_block_maps_can_be_inspected_without_authentication() {
        use rssig::parse::BlockMap;
        for bytes in [
            include_bytes!("fixtures/good.msix").as_slice(),
            include_bytes!("fixtures/good-appx-deflate.msix").as_slice(),
            include_bytes!("fixtures/good-appx-zip64.msix").as_slice(),
            include_bytes!("fixtures/appx-independent-signtool.msix").as_slice(),
        ] {
            let package = Appx::parse(bytes).unwrap();
            let xml = package.block_map_bytes().unwrap();
            let map = BlockMap::parse(&xml).unwrap();
            assert_eq!(
                map.hash_method().unwrap(),
                "http://www.w3.org/2001/04/xmlenc#sha256"
            );
            for file in map.files() {
                let name = file.name().unwrap().replace('\\', "/");
                let part = package.parts().find(|part| part.name() == name).unwrap();
                assert_eq!(file.size().unwrap(), part.uncompressed_size());
                assert_eq!(file.local_header_size().unwrap(), part.local_header_size());
                let start = part.offset() + part.local_header_size();
                assert_eq!(part.compressed_bytes().as_ptr(), bytes[start..].as_ptr());
                let content = part.read(64 * 1024 * 1024).unwrap();
                let blocks = file.blocks().unwrap();
                assert_eq!(blocks.len(), content.len().div_ceil(65536));
                let mut sizes = Vec::new();
                for (block, chunk) in blocks.iter().zip(content.chunks(65536)) {
                    assert_eq!(block.hash().unwrap(), Sha256::digest(chunk).to_vec());
                    if let Some(size) = block.compressed_size().unwrap() {
                        sizes.push(size);
                    }
                }
                if part.compression_method() == 8 {
                    part.check_compressed_blocks(&sizes).unwrap();
                    assert!(part.check_compressed_blocks(&[]).is_err());
                }
                if !content.is_empty() {
                    assert_eq!(
                        part.read(content.len() - 1).unwrap_err().kind(),
                        ErrorKind::InvalidAppx
                    );
                }
            }
        }
        let package =
            Appx::parse(include_bytes!("fixtures/bad-appx-block-algorithm.msix")).unwrap();
        let bytes = package.block_map_bytes().unwrap();
        let map = BlockMap::parse(&bytes).unwrap();
        assert_ne!(
            map.hash_method().unwrap(),
            "http://www.w3.org/2001/04/xmlenc#sha256"
        );
        // The XML adapter rejects DTDs rather than fetching or expanding entities.
        let package = Appx::parse(include_bytes!("fixtures/bad-appx-dtd.msix")).unwrap();
        let xml = package.block_map_bytes().unwrap();
        assert_eq!(
            BlockMap::parse(&xml).err().unwrap().kind(),
            ErrorKind::InvalidAppx
        );
    }

    #[test]
    fn archive_errors_remain_typed_and_reject_truncated_inputs() {
        let bytes = include_bytes!("fixtures/good.msix");
        for end in [0, 3, 4, 22, 29, bytes.len() - 1] {
            assert_eq!(
                Appx::parse(&bytes[..end]).err().unwrap().kind(),
                ErrorKind::InvalidAppx
            );
        }
        let mut unsupported = bytes.to_vec();
        let footer = bytes.len() - 22;
        let cd = u32::from_le_bytes(bytes[footer + 16..footer + 20].try_into().unwrap()) as usize;
        unsupported[cd + 10..cd + 12].copy_from_slice(&9u16.to_le_bytes());
        assert_eq!(
            Appx::parse(&unsupported).err().unwrap().kind(),
            ErrorKind::UnsupportedAppx
        );
        let bundle = Appx::parse(include_bytes!(
            "fixtures/bad-appxbundle-child-unsigned.msixbundle"
        ))
        .unwrap();
        let packages = bundle.bundle_packages().unwrap();
        assert!(packages.iter().any(|p| {
            Appx::parse(p.bytes)
                .err()
                .is_some_and(|e| e.kind() == ErrorKind::UnsignedAppx)
        }));
    }

    #[test]
    fn bundle_entries_borrow_the_exact_embedded_package() {
        let bytes = include_bytes!("fixtures/good.msixbundle");
        let bundle = Appx::parse(bytes).unwrap();
        assert!(bundle.is_bundle());
        let packages = bundle.bundle_packages().unwrap();
        assert!(!packages.is_empty());
        for package in packages {
            assert_eq!(package.bytes.as_ptr(), bytes[package.offset..].as_ptr());
            assert_eq!(package.bytes.len(), package.size);
            let child = Appx::parse(package.bytes).unwrap();
            assert!(!child.is_bundle());
            child.identity().unwrap();
        }
    }
}

#[cfg(feature = "verify")]
mod verification {
    use rssig::{
        TrustStore, VerifyOptions,
        parse::{Appx, Msi},
        verify_parsed_appx, verify_parsed_msi,
    };
    use serde_json::to_value;

    #[test]
    fn parsed_msi_can_be_reused_across_integrity_and_trusted_policies() {
        let mut roots = TrustStore::default();
        roots
            .add_roots(include_bytes!("fixtures/root.der"))
            .unwrap();
        roots.add_crl(include_bytes!("fixtures/good.crl")).unwrap();
        for bytes in [
            include_bytes!("fixtures/msi-good-pe64.msi").as_slice(),
            include_bytes!("fixtures/msi-good-legacy.msi").as_slice(),
            include_bytes!("fixtures/msi-good-v4.msi").as_slice(),
            include_bytes!("fixtures/msi-good-sha384.msi").as_slice(),
            include_bytes!("fixtures/msi-good-sha512.msi").as_slice(),
            include_bytes!("fixtures/msp-good.msp").as_slice(),
        ] {
            let mut package = Msi::parse(bytes).unwrap();
            let signature = package.signature().to_vec();
            for trust in [None, Some(&roots), None] {
                let options = VerifyOptions {
                    trust,
                    check_revocation: true,
                    allow_sha1: false,
                    now: 1_800_000_000,
                };
                let actual = verify_parsed_msi(&mut package, &options).unwrap();
                assert_eq!(
                    to_value(actual).unwrap(),
                    to_value(rssig::verify_msi(bytes, &options).unwrap()).unwrap()
                );
            }
            assert_eq!(package.signature(), signature);
        }
    }

    #[test]
    fn parsed_appx_is_reusable_and_byte_verifier_outputs_are_identical() {
        let mut roots = TrustStore::default();
        roots
            .add_roots(include_bytes!("fixtures/root.der"))
            .unwrap();
        roots.add_crl(include_bytes!("fixtures/good.crl")).unwrap();
        for bytes in [
            include_bytes!("fixtures/good.msix").as_slice(),
            include_bytes!("fixtures/good.msixbundle").as_slice(),
            include_bytes!("fixtures/good-appx-catalog.msix").as_slice(),
            include_bytes!("fixtures/good-appx-sha384.msix").as_slice(),
            include_bytes!("fixtures/good-appx-sha512.msix").as_slice(),
            include_bytes!("fixtures/good-appxbundle-sha384.msixbundle").as_slice(),
            include_bytes!("fixtures/good-appxbundle-sha512.msixbundle").as_slice(),
            include_bytes!("fixtures/good-appx-deflate.msix").as_slice(),
            include_bytes!("fixtures/good-appx-zip64.msix").as_slice(),
        ] {
            let package = Appx::parse(bytes).unwrap();
            let inputs = package.digest_inputs().unwrap();
            for trust in [None, Some(&roots), None] {
                let options = VerifyOptions {
                    trust,
                    check_revocation: true,
                    allow_sha1: false,
                    now: 1_800_000_000,
                };
                let actual = verify_parsed_appx(&package, &options).unwrap();
                assert_eq!(
                    to_value(actual).unwrap(),
                    to_value(rssig::verify_appx(bytes, &options).unwrap()).unwrap()
                );
            }
            for (before, after) in inputs.iter().zip(package.digest_inputs().unwrap()) {
                assert_eq!(before.tag, after.tag);
                assert_eq!(before.bytes, after.bytes);
            }
        }
    }

    #[test]
    fn independent_package_hashing_is_reusable_without_trust_claims() {
        let options = VerifyOptions {
            trust: None,
            check_revocation: false,
            allow_sha1: false,
            now: 1_800_000_000,
        };
        for bytes in [
            include_bytes!("fixtures/msi-independent-jsign.msi").as_slice(),
            include_bytes!("fixtures/msp-independent-jsign.msp").as_slice(),
        ] {
            let mut parsed = Msi::parse(bytes).unwrap();
            let expected = to_value(rssig::verify_msi(bytes, &options).unwrap()).unwrap();
            for _ in 0..2 {
                let result = verify_parsed_msi(&mut parsed, &options).unwrap();
                assert!(!result.signatures[0].chain_trusted);
                assert_eq!(to_value(result).unwrap(), expected);
            }
        }
    }

    #[test]
    fn parsed_bad_evidence_is_rejected_on_every_verification() {
        let options = VerifyOptions {
            trust: None,
            check_revocation: false,
            allow_sha1: false,
            now: 1_800_000_000,
        };
        for bytes in [
            include_bytes!("fixtures/msi-bad-empty-extended.msi").as_slice(),
            include_bytes!("fixtures/msi-bad-extended-digest.msi").as_slice(),
            include_bytes!("fixtures/msi-bad-legacy-stream.msi").as_slice(),
        ] {
            let mut package = Msi::parse(bytes).unwrap();
            let expected = to_value(rssig::verify_msi(bytes, &options).unwrap_err()).unwrap();
            for _ in 0..2 {
                assert_eq!(
                    to_value(verify_parsed_msi(&mut package, &options).unwrap_err()).unwrap(),
                    expected
                );
            }
        }
        for bytes in [
            include_bytes!("fixtures/bad-appx-payload.msix").as_slice(),
            include_bytes!("fixtures/bad-appx-block-hash.msix").as_slice(),
            include_bytes!("fixtures/bad-appx-publisher.msix").as_slice(),
            include_bytes!("fixtures/bad-appxbundle-name.msixbundle").as_slice(),
            include_bytes!("fixtures/bad-appxbundle-different-signer.msixbundle").as_slice(),
        ] {
            let package = Appx::parse(bytes).unwrap();
            let expected = to_value(rssig::verify_appx(bytes, &options).unwrap_err()).unwrap();
            for _ in 0..2 {
                assert_eq!(
                    to_value(verify_parsed_appx(&package, &options).unwrap_err()).unwrap(),
                    expected
                );
            }
        }
    }
}
