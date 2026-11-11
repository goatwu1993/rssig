//! Per-verification consumable work limits. Never reset for siblings or children.
use crate::{der, domain::*};
use anyhow::Result;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[derive(Debug)]
pub(crate) struct Counter {
    name: &'static str,
    limit: usize,
    used: AtomicUsize,
    exhausted: AtomicBool,
}
impl Counter {
    const fn new(name: &'static str, limit: usize) -> Self {
        Self {
            name,
            limit,
            used: AtomicUsize::new(0),
            exhausted: AtomicBool::new(false),
        }
    }
    pub(crate) fn charge(&self, requested: usize) -> Result<()> {
        let mut used = self.used.load(Ordering::Relaxed);
        loop {
            let Some(next) = used
                .checked_add(requested)
                .filter(|next| *next <= self.limit)
            else {
                self.exhausted.store(true, Ordering::Relaxed);
                return Err(self.error(used, requested).into());
            };
            match self
                .used
                .compare_exchange_weak(used, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return Ok(()),
                Err(current) => used = current,
            }
        }
    }

    fn error(&self, used: usize, requested: usize) -> VerificationError {
        VerificationError::new(
            ErrorCode::ResourceLimitExceeded,
            Stage::Cms,
            "verification work budget exhausted",
        )
        .detail("resource", self.name)
        .detail("limit", self.limit)
        .detail("used", used)
        .detail("requested", requested)
    }
    pub(crate) fn check(&self) -> Result<()> {
        if self.exhausted.load(Ordering::Relaxed) {
            return Err(self.error(self.used.load(Ordering::Relaxed), 1).into());
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct Budget {
    pub(crate) cms_objects: Counter,
    pub(crate) certificate_entries: Counter,
    pub(crate) cms_bytes: Counter,
    pub(crate) certificates: Counter,
    pub(crate) signers: Counter,
    pub(crate) reports: Counter,
    pub(crate) report_certificates: Counter,
    pub(crate) decoded_bytes: Counter,
    pub(crate) hash_bytes: Counter,
    pub(crate) containers: Counter,
    pub(crate) path_work: Counter,
    pub(crate) crypto: Counter,
}
impl Default for Budget {
    fn default() -> Self {
        Self {
            certificate_entries: Counter::new("certificate_entries", 64),
            cms_objects: Counter::new("cms_objects", 64),
            cms_bytes: Counter::new("cms_bytes", 64 * 1024 * 1024),
            certificates: Counter::new("certificates", 256),
            signers: Counter::new("signers", 128),
            reports: Counter::new("reports", 64),
            report_certificates: Counter::new("report_certificates", 4096),
            decoded_bytes: Counter::new("decoded_bytes", 512 * 1024 * 1024),
            hash_bytes: Counter::new("hash_bytes", 1024 * 1024 * 1024),
            containers: Counter::new("containers", 64),
            path_work: Counter::new("path_work", 64 * 200_000),
            crypto: Counter::new("crypto_operations", 1024),
        }
    }
}
impl Budget {
    pub(crate) fn depth(&self, depth: usize) -> Result<()> {
        if depth > 8 {
            return Err(VerificationError::new(
                ErrorCode::MalformedCms,
                Stage::Cms,
                "too many nested signatures",
            )
            .detail("resource", "nesting")
            .detail("limit", 8)
            .detail("used", depth - 1)
            .detail("requested", 1)
            .into());
        }
        Ok(())
    }
    pub(crate) fn container(&self, bytes: &[u8]) -> Result<()> {
        self.containers.charge(1)?;
        // Reserve whole-text decoding and adapter copies before parsing. Host reads
        // and caller-owned input memory are a separate boundary (SEC-03).
        for _ in 0..4 {
            self.decoded_bytes.charge(bytes.len())?;
        }
        Ok(())
    }
    pub(crate) fn cms(&self, bytes: &[u8]) -> Result<()> {
        self.cms_objects.charge(1)?;
        self.cms_bytes.charge(bytes.len())?;
        self.decoded_bytes.charge(bytes.len())?;
        // Shallow framing only: do not eagerly inspect unsigned nested objects,
        // which would change first-failure precedence. Charge each certificate
        // choice before the structural parser allocates its decoded X.509 value.
        let outer = der::fields(der::one(bytes, 0x30)?, 2)?;
        let fields = der::one(outer[1].expect(0xa0)?.body, 0x30)?.children()?;
        if let Some(certificates) = fields.get(3).filter(|n| n.tag == 0xa0) {
            let mut rest = certificates.body;
            while !rest.is_empty() {
                self.certificates.charge(1)?;
                der::take(&mut rest)?;
            }
        }
        Ok(())
    }
    pub(crate) fn signer(&self) -> Result<()> {
        self.signers.charge(1)
    }
    pub(crate) fn report(&self, certificates: usize) -> Result<()> {
        self.reports.charge(1)?;
        self.report_certificates.charge(certificates)
    }
    pub(crate) fn certificate_bytes(&self, certificates: &[x509_cert::Certificate]) -> Result<()> {
        use ::der::Encode;
        for cert in certificates {
            let length = usize::try_from(cert.encoded_len().map_err(crate::compat_error)?)
                .map_err(crate::compat_error)?;
            // Reserve DER hex plus decoded names/extensions/report copies.
            for _ in 0..8 {
                self.hash_bytes.charge(length)?;
                self.decoded_bytes.charge(length)?;
            }
        }
        Ok(())
    }
    #[cfg(feature = "appx")]
    pub(crate) fn appx(&self, bytes: &[u8]) -> Result<()> {
        // ZIP metadata is bounded independently. Reserve all expanded entry bytes
        // before any decompression, including repeated footprint/block-map reads.
        let zip = crate::parse::appx::zip::Zip::parse(bytes)?;
        for entry in &zip.entries {
            for _ in 0..4 {
                self.decoded_bytes.charge(entry.size)?;
            }
        }
        Ok(())
    }
    #[cfg(feature = "appx")]
    pub(crate) fn appx_hash(&self, bytes: &[u8]) -> Result<()> {
        let zip = crate::parse::appx::zip::Zip::parse(bytes)?;
        for entry in &zip.entries {
            for _ in 0..4 {
                self.hash_bytes.charge(entry.size)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        format::Format,
        verify::{VerifyOptions, verify_inner_budget},
    };
    use alloc::string::ToString;

    #[test]
    fn sec02_counters_reject_overflow_and_preserve_consumed_units() {
        let counter = Counter::new("test", 2);
        counter.charge(2).unwrap();
        let error = counter.charge(usize::MAX).unwrap_err();
        let error = error.downcast_ref::<VerificationError>().unwrap();
        assert_eq!(error.code, ErrorCode::ResourceLimitExceeded);
        assert_eq!(error.details["used"], 2);
        assert_eq!(error.details["requested"], usize::MAX);
        assert_eq!(counter.used.load(Ordering::Relaxed), 2);
    }

    fn fails(bytes: &[u8], format: Format, budget: &Budget, resource: &str) {
        let error = verify_inner_budget(
            bytes,
            &VerifyOptions::integrity_only(1800000000),
            format,
            budget,
        )
        .unwrap_err();
        let error = VerificationError::from_internal(error, ErrorCode::InternalError, Stage::Cms);
        assert_eq!(error.code, ErrorCode::ResourceLimitExceeded, "{error:?}");
        assert_eq!(error.details["resource"], resource);
    }

    #[test]
    fn sec02_each_allowance_is_checked_before_work() {
        let pe = include_bytes!("../../tests/fixtures/good-pe64.exe");
        for resource in [
            "decoded_bytes",
            "certificates",
            "cms_bytes",
            "hash_bytes",
            "signers",
            "reports",
            "report_certificates",
            "crypto_operations",
        ] {
            let mut budget = Budget::default();
            let counter = Counter::new(resource, 0);
            match resource {
                "decoded_bytes" => budget.decoded_bytes = counter,
                "certificates" => budget.certificates = counter,
                "cms_bytes" => budget.cms_bytes = counter,
                "hash_bytes" => budget.hash_bytes = counter,
                "signers" => budget.signers = counter,
                "reports" => budget.reports = counter,
                "report_certificates" => budget.report_certificates = counter,
                _ => budget.crypto = counter,
            }
            fails(pe, Format::Pe, &budget, resource);
        }
    }

    #[test]
    fn sec02_nested_and_timestamp_objects_share_allowances() {
        let nested = include_bytes!("../../tests/fixtures/good-nested.exe");
        let budget = Budget {
            cms_objects: Counter::new("cms_objects", 1),
            ..Budget::default()
        };
        fails(nested, Format::Pe, &budget, "cms_objects");
        for bytes in [
            include_bytes!("../../tests/fixtures/good-rfc3161.exe").as_slice(),
            include_bytes!("../../tests/fixtures/good-countersignature.exe").as_slice(),
        ] {
            let budget = Budget {
                crypto: Counter::new("crypto_operations", 1),
                ..Budget::default()
            };
            fails(bytes, Format::Pe, &budget, "crypto_operations");
            assert_eq!(budget.crypto.used.load(Ordering::Relaxed), 1);
        }
        let budget = Budget {
            cms_objects: Counter::new("cms_objects", 1),
            ..Budget::default()
        };
        fails(
            include_bytes!("../../tests/fixtures/good-rdp-rfc3161.rdp"),
            Format::Rdp,
            &budget,
            "cms_objects",
        );
    }

    #[test]
    fn sec02_depth_is_checked_before_decoding_malformed_child() {
        let budget = Budget::default();
        budget.depth(8).unwrap();
        let error = budget.depth(9).unwrap_err();
        assert!(error.to_string().contains("too many nested signatures"));
        assert_eq!(budget.cms_objects.used.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn sec02_path_search_reservation_is_shared() {
        let mut store = crate::TrustStore::default();
        store
            .add_roots(include_bytes!("../../tests/fixtures/root.der"))
            .unwrap();
        let budget = Budget {
            path_work: Counter::new("path_work", 200_000),
            ..Budget::default()
        };
        let options = VerifyOptions::trusted_with_revocation(
            &store,
            1800000000,
            crate::verify::RevocationPolicy::Disabled,
        );
        let bytes = include_bytes!("../../tests/fixtures/good-pe64.exe");
        verify_inner_budget(bytes, &options, Format::Pe, &budget).unwrap();
        let error = verify_inner_budget(bytes, &options, Format::Pe, &budget).unwrap_err();
        let error = error.downcast_ref::<VerificationError>().unwrap();
        assert_eq!(error.details["resource"], "path_work");
    }

    #[test]
    fn sec02_chain_crypto_exhaustion_keeps_typed_error() {
        let mut store = crate::TrustStore::default();
        store
            .add_roots(include_bytes!("../../tests/fixtures/root.der"))
            .unwrap();
        let options = VerifyOptions::trusted_with_revocation(
            &store,
            1800000000,
            crate::verify::RevocationPolicy::Disabled,
        );
        let budget = Budget {
            crypto: Counter::new("crypto_operations", 1),
            ..Budget::default()
        };
        let error = verify_inner_budget(
            include_bytes!("../../tests/fixtures/good-pe64.exe"),
            &options,
            Format::Pe,
            &budget,
        )
        .unwrap_err();
        let error = VerificationError::from_internal(
            error,
            ErrorCode::InternalError,
            Stage::CertificateChain,
        );
        assert_eq!(error.code, ErrorCode::ResourceLimitExceeded);
        assert_eq!(error.details["resource"], "crypto_operations");
        assert_eq!(error.details["used"], 1);
        assert!(budget.crypto.check().is_err());
    }

    #[cfg(feature = "appx")]
    #[test]
    fn sec02_bundle_children_do_not_get_fresh_budgets() {
        let budget = Budget {
            containers: Counter::new("containers", 1),
            ..Budget::default()
        };
        fails(
            include_bytes!("../../tests/fixtures/good.msixbundle"),
            Format::Appx,
            &budget,
            "containers",
        );
        let budget = Budget {
            reports: Counter::new("reports", 1),
            ..Budget::default()
        };
        fails(
            include_bytes!("../../tests/fixtures/good.msixbundle"),
            Format::Appx,
            &budget,
            "reports",
        );
    }

    #[test]
    fn sec02_bounded_table_collection_stops_before_allocating_more_entries() {
        let bytes = include_bytes!("../../tests/fixtures/sec02-entries-65.exe");
        let pe = crate::parse::Pe::parse(bytes).unwrap();
        let budget = Budget::default();
        assert!(
            pe.certificates_bounded(|| budget.certificate_entries.charge(1))
                .is_err()
        );
        assert_eq!(budget.certificate_entries.used.load(Ordering::Relaxed), 64);
        // Ordinary parsing retains its separate structural contract.
        assert_eq!(pe.signatures().unwrap().len(), 65);
    }
}
