# CRL decisions

Numbered decisions behind rssig's CRL and revocation behavior. The entry
format, Status values and how cases name an entry are defined in
[Decision indexes](decisions.md). The history and review discussion is in
[SEC-10](tasks/sec-10-crl-applicability.md) and
[SEC-24](tasks/sec-24-single-revocation-authority.md).

## Order

Entries are numbered from most to least important, by what breaks if the rule
is wrong, in four tiers; within a tier, Decided entries come before Observed
ones. The Area column gives the subject.

1. **Fail-open and privacy:** a broken rule could accept a revoked or
   unproven certificate, or send requests for an input that cannot verify.
2. **Availability:** a broken rule would reject a valid file or change what
   fetching can complete.
3. **Result diagnostics:** the error code, stage or details a consumer
   matches; both outcomes reject.
4. **Retrieval diagnostics:** which requests a source receives and how
   retrieval is reported.

A new entry takes the next free number, whatever its tier; the order above
holds for the entries numbered when it was set.

## Index

| ID | Decision | Area | Status | Pins |
|---|---|---|---|---|
| [CRL-001](#crl-001-a-crl-that-does-not-apply-is-excluded) | A CRL that does not apply is excluded | Scope | Decided | acceptance |
| [CRL-002](#crl-002-a-crl-without-nextupdate-is-not-evidence-of-good-status) | A CRL without nextUpdate is not evidence of good status | Choosing CRLs | Decided | acceptance |
| [CRL-003](#crl-003-a-listing-in-a-crl-whose-signature-cannot-be-verified-never-counts) | A listing in a CRL whose signature cannot be verified never counts | Choosing CRLs | Decided | acceptance |
| [CRL-004](#crl-004-a-crl-without-nextupdate-counts-for-a-listing-beside-an-older-crl) | A CRL without nextUpdate counts for a listing beside an older CRL | Choosing CRLs | Decided | acceptance |
| [CRL-005](#crl-005-a-listing-in-a-current-crl-with-a-malformed-aki-counts-beside-a-usable-crl) | A listing in a current CRL with a malformed AKI counts beside a usable CRL | Choosing CRLs | Decided | acceptance |
| [CRL-006](#crl-006-a-role-only-partition-counts-for-its-role) | A role-only partition counts for its role | Scope | Decided | acceptance |
| [CRL-007](#crl-007-on-a-key-rollover-path-each-certificate-uses-its-own-keys-crl) | On a key-rollover path each certificate uses its own key's CRL | Issuer keys | Decided | acceptance |
| [CRL-008](#crl-008-a-rollover-path-with-crls-that-name-no-key-is-rejected) | A rollover path with CRLs that name no key is rejected | Issuer keys | Decided | acceptance |
| [CRL-009](#crl-009-a-point-scoped-crl-for-a-certificate-that-lists-no-points-is-rejected) | A point-scoped CRL for a certificate that lists no points is rejected | Scope | Decided | acceptance |
| [CRL-010](#crl-010-a-listings-scope-needs-a-positive-match) | A listing's scope needs a positive match | Scope | Decided | acceptance |
| [CRL-011](#crl-011-nothing-is-fetched-for-an-input-that-cannot-verify) | Nothing is fetched for an input that cannot verify | Retrieval | Decided | acceptance |
| [CRL-012](#crl-012-the-best-usable-crl-decides) | The best usable CRL decides | Choosing CRLs | Decided | acceptance |
| [CRL-013](#crl-013-a-revocation-in-a-crl-that-does-not-cover-the-certificate-does-not-count) | A revocation in a CRL that does not cover the certificate does not count | Scope | Decided | acceptance |
| [CRL-014](#crl-014-a-full-crl-is-in-scope-for-any-certificate) | A full CRL is in scope for any certificate | Scope | Decided | acceptance |
| [CRL-015](#crl-015-a-crl-issuer-needs-crlsign-except-a-configured-root) | A CRL issuer needs cRLSign, except a configured root | Issuer keys | Decided | acceptance |
| [CRL-016](#crl-016-a-listing-counts-only-from-a-current-crl-and-the-newest-decides) | A listing counts only from a current CRL, and the newest decides | Choosing CRLs | Decided | acceptance |
| [CRL-017](#crl-017-a-path-that-verifies-with-its-crls-is-accepted-whatever-another-path-does) | A path that verifies with its CRLs is accepted whatever another path does | Paths and usages | Decided | acceptance |
| [CRL-018](#crl-018-a-crl-with-a-bad-signature-is-not-refreshed) | A CRL with a bad signature is not refreshed | Retrieval | Decided | acceptance |
| [CRL-019](#crl-019-an-expired-supplied-crl-is-refreshed) | An expired supplied CRL is refreshed | Retrieval | Decided | acceptance |
| [CRL-020](#crl-020-a-supplied-crl-the-references-would-look-past-is-refreshed) | A supplied CRL the references would look past is refreshed | Retrieval | Decided | acceptance |
| [CRL-021](#crl-021-a-crl-without-nextupdate-but-with-another-defect-is-replaced) | A CRL without nextUpdate but with another defect is replaced | Retrieval | Decided | acceptance |
| [CRL-022](#crl-022-a-point-scoped-crl-for-a-certificate-that-lists-no-points-is-replaced-by-certificate) | A point-scoped CRL for a certificate that lists no points is replaced by certificate | Retrieval | Decided | acceptance |
| [CRL-023](#crl-023-a-source-completes-another-path-beside-a-revoked-one) | A source completes another path beside a revoked one | Paths and usages | Decided | acceptance |
| [CRL-024](#crl-024-an-rdp-signer-lacking-only-a-crl-under-one-usage-verifies-once-the-crl-is-present) | An RDP signer lacking only a CRL under one usage verifies once the CRL is present | Paths and usages | Decided | acceptance |
| [CRL-025](#crl-025-the-source-decides-transport-the-core-screens-hygiene-only) | The source decides transport; the core screens hygiene only | Retrieval | Decided | acceptance |
| [CRL-026](#crl-026-one-certificates-distribution-points-never-end-the-run) | One certificate's distribution points never end the run | Retrieval | Decided | acceptance |
| [CRL-027](#crl-027-a-role-only-partition-alone-is-unsupported) | A role-only partition alone is unsupported | Scope | Observed | acceptance |
| [CRL-028](#crl-028-missing-evidence-is-revocation_unknown-a-source-has-four-outcome-kinds) | Missing evidence is `revocation_unknown`; a source has four outcome kinds | Retrieval | Decided | diagnostics |
| [CRL-029](#crl-029-which-error-a-rejected-chain-reports) | Which error a rejected chain reports | Paths and usages | Decided | diagnostics |
| [CRL-030](#crl-030-a-crl-without-nextupdate-alone-revokes-unless-a-newer-crl-clears-it) | A CRL without nextUpdate alone revokes, unless a newer CRL clears it | Choosing CRLs | Decided | diagnostics |
| [CRL-031](#crl-031-a-definite-result-keeps-its-code-with---fetch-crls) | A definite result keeps its code with `--fetch-crls` | Retrieval | Decided | diagnostics |
| [CRL-032](#crl-032-a-revoked-rdp-usage-is-reported-over-another-usages-failure) | A revoked RDP usage is reported over another usage's failure | Paths and usages | Decided | diagnostics |
| [CRL-033](#crl-033-an-rdp-signer-lacking-only-a-crl-under-one-usage-reports-the-missing-crl) | An RDP signer lacking only a CRL under one usage reports the missing CRL | Paths and usages | Decided | diagnostics |
| [CRL-034](#crl-034-a-partition-for-another-point-is-no-evidence) | A partition for another point is no evidence | Scope | Decided | diagnostics |
| [CRL-035](#crl-035-a-revocation-names-another-paths-refreshable-certificates) | A revocation names another path's refreshable certificates | Paths and usages | Decided | diagnostics |
| [CRL-036](#crl-036-a-path-a-source-could-complete-is-reported-over-a-stuck-path) | A path a source could complete is reported over a stuck path | Paths and usages | Decided | diagnostics |
| [CRL-037](#crl-037-retrieval-asks-per-certificate-only-about-what-lacks-a-crl) | Retrieval asks per certificate, only about what lacks a CRL | Retrieval | Decided | diagnostics |
| [CRL-038](#crl-038-a-source-answering-by-certificate-leaves-no-per-point-failures) | A source answering by certificate leaves no per-point failures | Retrieval | Decided | diagnostics |
| [CRL-039](#crl-039-a-missing-nextupdate-blocks-retrieval-only-as-a-crls-sole-defect) | A missing nextUpdate blocks retrieval only as a CRL's sole defect | Retrieval | Decided | diagnostics |
| [CRL-040](#crl-040-an-abort-before-an-expired-crl-is-refreshed-is-marked) | An abort before an expired CRL is refreshed is marked | Retrieval | Decided | diagnostics |
| [CRL-041](#crl-041-without-an-answer-a-replaceable-crls-error-stands-and-names-the-certificate) | Without an answer, a replaceable CRL's error stands and names the certificate | Retrieval | Decided | diagnostics |
| [CRL-042](#crl-042-the-built-in-source-refuses-what-it-does-not-fetch) | The built-in source refuses what it does not fetch | Retrieval | Decided | diagnostics |
| [CRL-043](#crl-043-a-uri-that-is-not-an-absolute-url-is-never-offered-to-a-source) | A URI that is not an absolute URL is never offered to a source | Retrieval | Decided | diagnostics |
| [CRL-044](#crl-044-fetch-limits-bound-one-verification) | Fetch limits bound one verification | Retrieval | Decided | diagnostics |
| [CRL-045](#crl-045-a-crl-naming-a-same-key-roots-identifier-is-forged-not-set-aside) | A CRL naming a same-key root's identifier is forged, not set aside | Issuer keys | Observed | diagnostics |

## Tier 1: fail-open and privacy

Acceptance pins whose breakage could accept a revoked or unproven certificate, or send requests for an input that cannot verify.

### CRL-001: A CRL that does not apply is excluded

A CRL that does not apply to the chain is excluded whatever its fault. When no supplied CRL applies, the result is `revocation_unknown`, returned before path building; unknown status is never good. Among CRLs that do apply, CRL-012 decides which one counts.

- **Status:** Decided
- **Decided by:** written argument (fail closed), PR #44, #45, #46
- **Pins:** acceptance
- **Sources:**
  - AGENTS.md, "Fail closed".
- **Note:** no case names this entry yet.

### CRL-002: A CRL without nextUpdate is not evidence of good status

Without a listing, a chain issuer's CRL that lacks nextUpdate is `invalid_crl` (`missing_next_update`). RFC 5280 section 5.1.2.5 requires nextUpdate, and a CRL that never expires cannot show that the status is still current.

- **Status:** Decided
- **Decided by:** written argument (stricter than the references, which would accept it)
- **Pins:** acceptance
- **Sources:**
  - RFC 5280 section 5.1.2.5.

### CRL-003: A listing in a CRL whose signature cannot be verified never counts

A CRL with a bad or unsupported signature is `invalid_crl` (`unsupported_signature_algorithm`) or `invalid_crl_signature`, and its entries are never read. It is set aside when another CRL is usable.

- **Status:** Decided
- **Decided by:** references agree (OpenSSL, Bouncy Castle)
- **Pins:** acceptance
- **Sources:**
  - OpenSSL `crypto/x509/x509_vfy.c` `check_crl` fails the CRL before `cert_crl` reads entries.
  - Bouncy Castle `RFC3280CertPathUtilities` processCRLG skips it before processCRLJ reads entries.

### CRL-004: A CRL without nextUpdate counts for a listing beside an older CRL

A correctly signed, in-scope CRL without nextUpdate claims no expiry, so it is current: its listing revokes beside an older usable CRL.

- **Status:** Decided
- **Decided by:** references agree (OpenSSL, BoringSSL, Bouncy Castle); corrected after review of PR #60, where the earlier rule failed open
- **Pins:** acceptance
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:1555-1587 (ossl_x509_check_crl_time): a CRL without nextUpdate is never expired, so a current CRL whose entries are read.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/PKIXCRLUtil.java:42-45: a CRL with a null nextUpdate is kept ("nextUpdate == null || nextUpdate.after(validityDate)") and its entries are read.
  - BoringSSL crypto/x509/x509_vfy.cc:414: the nextUpdate comparison runs only if the field is present.
  - All three agree; the earlier rule in this task, that a CRL without nextUpdate is never current, followed none of them and failed open for a listed certificate.

### CRL-005: A listing in a current CRL with a malformed AKI counts beside a usable CRL

A correctly signed CRL of the issuer that lists the certificate revokes even if its authorityKeyIdentifier is malformed, when it is at least as new as the usable CRL beside it. Alone it is `invalid_crl`. A malformed identifier does not make the issuer's statement less authentic.

- **Status:** Decided
- **Decided by:** owner, PR #60 (the references disagree; closest to OpenSSL; fails closed)
- **Pins:** acceptance
- **Sources:**
  - OpenSSL crypto/x509/x_crl.c:265-269 (crl_cb): a malformed AKI leaves crl->akid NULL and sets EXFLAG_INVALID, which crypto/x509/x509_vfy.c never reads for a CRL; crypto/x509/v3_purp.c:1353 (X509_check_akid) treats a NULL akid as a match, so get_crl_sk (x509_vfy.c:1603-1633) can select the CRL and cert_crl (x509_vfy.c:2344) reports the listing: revoked if that CRL has the later lastUpdate, or an equal one and comes first; otherwise good.
  - Bouncy Castle pkix/src/main/java/org/bouncycastle/pkix/jcajce/RFC3280CertPathUtilities.java:255-280 (processCRLF, used by X509RevocationChecker): the CRL's AKI is not read; revoked or good by CRL iteration order.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/RFC3280CertPathUtilities.java:379-393 (processCRLF): AuthorityKeyIdentifier.getInstance throws an uncaught IllegalArgumentException, or the result is good if the well-formed CRL is iterated first; never revoked.
  - BoringSSL crypto/x509/x_crl.cc:157-161 (crl_cb): returns 0, so the CRL fails to parse and is never used; never revoked.

### CRL-006: A role-only partition counts for its role

An issuingDistributionPoint with only onlyContainsUserCerts or onlyContainsCACerts that admits the certificate is in scope, so its listing revokes beside a full CRL.

- **Status:** Decided
- **Decided by:** references agree (OpenSSL, Bouncy Castle)
- **Pins:** acceptance
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:2154-2157 and :2195-2197 (crl_crldp_check): role flags are checked first, and an issuingDistributionPoint with no distpoint is in scope for a certificate of that role.
  - Bouncy Castle core PKIXCRLValidator.java:151-158, 218-220 (processCRLB2): names are compared only when the IDP has one; the onlyContains flags then admit or reject by role.

### CRL-007: On a key-rollover path each certificate uses its own key's CRL

A self-issued rollover path (two issuers of one name, different keys) verifies without revocation. With CRLs whose authorityKeyIdentifier names their key, each certificate gets its own key's CRL in either order, and a revoked rollover certificate is rejected.

- **Status:** Decided
- **Decided by:** references agree (OpenSSL, BoringSSL, Bouncy Castle; OpenSSL 3.0.13 run as a maintenance step), SEC-16
- **Pins:** acceptance
- **Sources:**
  - RFC 5280 section 6.1: self-issued certificates (same subject and issuer name, different keys) are valid on a path and support key rollover.
  - OpenSSL crypto/x509/x509_vfy.c:755 and :802 (self-issued intermediates are accepted). Run with OpenSSL 3.0.13, `openssl verify -attime 1800000000` without CRL checks: OK.
  - OpenSSL crypto/x509/x509_vfy.c:1869-1889 (get_crl_score, crl_akid_check) and crypto/x509/v3_purp.c:1353 (X509_check_akid): a CRL whose authorityKeyIdentifier names the issuer's key outscores a same-name CRL that names another key, so each certificate gets its own key's CRL. Run with OpenSSL 3.0.13, `openssl verify -crl_check_all -attime 1800000000`, either CRL order: OK.
  - BoringSSL crypto/x509/x509_vfy.cc:490-515 (crl_akid_check) and :665-693 (get_crl_sk): the same scoring.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/RFC3280CertPathUtilities.java:379-390 (processCRLF selects the signing key by the CRL's authority key identifier) and :1716-1721 (checkCRL skips a CRL that does not verify and continues).
  - webpki 0.103.16: check_crls takes the first authoritative CRL by issuer name and IDP only, so it cannot confirm two issuers of one name; rssig's own per-key evaluation decides for such a path.
  - RFC 5280 section 6.3.3: a certificate listed on a current CRL of its issuer is revoked.
  - OpenSSL crypto/x509/x509_vfy.c (check_cert_crl, cert_crl) and Bouncy Castle RFC3280CertPathUtilities.checkCRL: every certificate on the path is checked against its own issuer key's CRL, the rollover certificate included.

### CRL-008: A rollover path with CRLs that name no key is rejected

With same-name CRLs that carry no authorityKeyIdentifier, the path is `certificate_chain_invalid` (`ambiguous_issuer_keys`) in either order.

- **Status:** Decided
- **Decided by:** owner, PR #60 (the references differ; BoringSSL is the tiebreaker and rejects, failing closed)
- **Pins:** acceptance
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:1869-1881 (get_crl_score), :1614-1627 (get_crl_sk keeps one best CRL for a name) and :2318-2320 (check_crl has no fallback after a signature failure); crypto/x509/v3_purp.c:1353-1354 (a CRL without an authorityKeyIdentifier matches any key). Run with OpenSSL 3.0.13, `openssl verify -crl_check_all -attime 1800000000`: 'CRL signature failure' at depth 0 or 1 depending on CRL order. Rejects.
  - BoringSSL crypto/x509/x509_vfy.cc:490-515, :665-693 and :755-760: the same logic. Rejects.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/RFC3280CertPathUtilities.java:1716-1721 (checkCRL skips a CRL that does not verify and tries the next). Accepts.
  - webpki 0.103.16: check_crls takes the first authoritative CRL by issuer name and IDP only, then verifies it under the certificate's issuer key. Rejects.
  - The references differ; the owner chose the tiebreaker (PR #60): the third reference, BoringSSL, rejects, and rejecting fails closed.

### CRL-009: A point-scoped CRL for a certificate that lists no points is rejected

A CRL that names a distribution point (including a CA-only one) is `invalid_crl` (`distribution_point_scope`) for a certificate that lists no cRLDistributionPoints; it is not set aside. With a full CRL of the issuer present, the full CRL is used.

- **Status:** Decided
- **Decided by:** references agree (OpenSSL, Bouncy Castle); PR #48, confirmed in PR #60, where setting it aside was declined
- **Pins:** acceptance
- **Sources:**
  - OpenSSL crypto/x509/x_crl.c:358-361 sets IDP_ONLYCA; OpenSSL crypto/x509/x509_vfy.c:2154-2157 (crl_crldp_check) returns 0 for an end entity, and :2295 (check_crl) fails with X509_V_ERR_DIFFERENT_CRL_SCOPE.
  - Bouncy Castle core PKIXCRLValidator.java:151-158 (checkDistributionPointName): the CRL is rejected with a distribution point name mismatch; RFC3280CertPathUtilities.java:1716-1729 reports the last such exception when no CRL is valid.

### CRL-010: A listing's scope needs a positive match

A named partition's listing counts only on a positive match with a fullName URI the certificate lists; an issuer-relative or non-URI name is no match. A certificate whose own cRLDistributionPoints cannot be read fails closed: the partition is not set aside and its listing counts.

- **Status:** Decided
- **Decided by:** references agree (OpenSSL `crl_crldp_check`, Bouncy Castle processCRLB2); refined after review of PR #60
- **Pins:** acceptance
- **Sources:**
  - OpenSSL `crl_crldp_check`; Bouncy Castle processCRLB2.
- **Note:** no spec case (no committed certificate has an undecodable extension).
- **Unit tests:** `a_listing_counts_only_on_a_positive_scope_match`, `unreadable_certificate_points_never_discard_a_partition` in `src/trust.rs`.

### CRL-011: Nothing is fetched for an input that cannot verify

Before the first request the whole input is verified once without revocation, so an untrusted chain, an invalid nested signature, later signer or bundle member is the result and no source is asked.

- **Status:** Decided
- **Decided by:** OpenSSL followed for an untrusted chain; written argument (privacy) for the rest of the input
- **Pins:** acceptance
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:266-284 (verify_chain): build_chain, which requires a trust anchor, runs before check_revocation (:276), so no CRL is looked up for a chain that does not reach a trusted root.
  - Verifying the whole input (nested signatures, later signers, bundle members) before any request has no reference equivalent; it is a written privacy argument in docs/crl-retrieval.md: an input that cannot verify must not cause network requests.

## Tier 2: availability

Acceptance pins whose breakage would reject a valid file or change what fetching can complete.

### CRL-012: The best usable CRL decides

An unusable CRL of the issuer is set aside when another CRL of that issuer is usable; alone, it keeps its own exact error. Revocation is evaluated per certificate on each candidate path.

- **Status:** Decided
- **Decided by:** owner, PR #60 (one-time exception to the pinned-expectation rule: the earlier failures beside `good.crl` became verifications)
- **Pins:** acceptance
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:1592-1633 (get_crl_sk) and :1801-1861 (get_crl_score): CRLs of the issuer are scored (CRL_SCORE_TIME, CRL_SCORE_SCOPE, CRL_SCORE_NOCRITICAL) and the best one is used; :2257-2320 (check_crl) reports the best CRL's own defect when no better one exists.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/RFC3280CertPathUtilities.java:1586-1721 (checkCRL): a CRL that fails a check is skipped (lastException, :1718) and the next is tried; its error is thrown only when no CRL was valid (:1721).
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/RFC3280CertPathUtilities.java:1716-1718 (checkCRL): a CRL that fails a check is skipped (lastException) and the next CRL is tried.
  - OpenSSL crypto/x509/x509_vfy.c:1603-1633 (get_crl_sk): candidate CRLs are scored and the best is used.

### CRL-013: A revocation in a CRL that does not cover the certificate does not count

A partition for another point or role, or a CRL whose issuingDistributionPoint does not decode, is never read for the certificate's entries.

- **Status:** Decided
- **Decided by:** owner, PR #60 (chose to follow the libraries; the earlier `-revoked` cases now verify)
- **Pins:** acceptance
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:2146-2198 (crl_crldp_check) and :1847-1853 (get_crl_score): a CRL whose issuingDistributionPoint does not match the certificate gets no CRL_SCORE_SCOPE and is not selected over a CRL that covers it.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/RFC3280CertPathUtilities.java:1678 (processCRLB2) with core PKIXCRLValidator.java:151-158 (checkDistributionPointName): a distribution point mismatch rejects the CRL before processCRLJ (:1703) reads entries.

### CRL-014: A full CRL is in scope for any certificate

A CRL without an issuingDistributionPoint covers every certificate of its issuer, whatever points the certificate lists.

- **Status:** Decided
- **Decided by:** references agree (OpenSSL, Bouncy Castle)
- **Pins:** acceptance
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:2146-2200 (crl_crldp_check): a CRL without an issuingDistributionPoint is in scope for any certificate, whatever points the certificate lists.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/RFC3280CertPathUtilities.java:105-195 (processCRLB2): distribution point names are compared only when the CRL has an issuingDistributionPoint.

### CRL-015: A CRL issuer needs cRLSign, except a configured root

A configured root whose KeyUsage lacks cRLSign still issues usable CRLs. An intermediate without cRLSign does not (`invalid_key_usage`).

- **Status:** Decided
- **Decided by:** written argument, PR #48
- **Pins:** acceptance
- **Sources:**
  - webpki 0.103 does not track anchor KeyUsage; a configured anchor is a trusted key, not a certificate to be policed (the general anchor rule is PATH-011).
  - RFC 5280 section 4.2.1.3: a CRL issuer's KeyUsage, when present, must include cRLSign.

### CRL-016: A listing counts only from a current CRL, and the newest decides

A revocation in an expired CRL beside a fresh CRL that omits the serial does not count; alone, the expired CRL is `crl_expired`. Among usable CRLs the newest lastUpdate decides, so a listing in an older, still-valid CRL does not count beside a newer one, and alone it revokes.

- **Status:** Decided
- **Decided by:** owner (delegated the call), PR #60; OpenSSL and Bouncy Castle agree
- **Pins:** acceptance
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:1603-1633 (get_crl_sk): one best CRL is selected, the newer lastUpdate winning a tie; :2344 (cert_crl) reads entries from that CRL only.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/PKIXCRLUtil.java:42-49 (findCRLs): CRLs whose nextUpdate is not after the validation date are dropped before any entry is read.

### CRL-017: A path that verifies with its CRLs is accepted whatever another path does

- **Status:** Decided
- **Decided by:** Bouncy Castle followed (OpenSSL builds one chain and has no equivalent)
- **Pins:** acceptance
- **Sources:**
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/PKIXCertPathBuilderSpi.java:135-270 (build): every candidate issuer is tried and a path that validates is returned; a failed candidate only sets certPathException (:268).
  - OpenSSL crypto/x509/x509_vfy.c:3925 (build_chain) builds one chain and :1444-1537 (check_cert_crl) checks that chain only; it has no second path to fall back on, so Bouncy Castle is followed.

### CRL-018: A CRL with a bad signature is not refreshed

A supplied CRL with a bad signature is `invalid_crl_signature` and nothing is requested, even if the source holds a good CRL. Likewise an issuer without cRLSign is not asked about: a fetched CRL has the same issuer.

- **Status:** Decided
- **Decided by:** owner, PR #64 (SEC-23): BoringSSL decides (OpenSSL and BoringSSL report without a second lookup; Bouncy Castle fetches)
- **Pins:** acceptance
- **Sources:**
  - OpenSSL 3.3 crypto/x509/x509_vfy.c:1564-1590 (get_crl_delta) consults lookup_crls when the best supplied CRL scores below CRL_SCORE_VALID (:33-42: no unhandled critical extension, time and scope; get_crl_score :1283-1340); the signature is not scored and its failure is reported at :1664 without another lookup.
  - BoringSSL crypto/x509/x509_vfy.cc:697-708 (get_crl) looks CRLs up in the store on the same condition.
  - Bouncy Castle pkix/src/main/java/org/bouncycastle/pkix/jcajce/X509RevocationChecker.java:797-863 turns any checkCRL failure but a revocation into 'no valid CRL found', and :468-487 then fetches from the certificate's distribution points when fetching is enabled.

### CRL-019: An expired supplied CRL is refreshed

With a source, an expired supplied CRL is refreshed from the certificate's points and the fetched CRL decides.

- **Status:** Decided
- **Decided by:** owner (delegated the call), PR #60; Bouncy Castle followed (OpenSSL does not fetch)
- **Pins:** acceptance
- **Sources:**
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/PKIXCRLUtil.java:42-49 drops CRLs past nextUpdate; CertPathValidatorUtilities.java:571-630 and pkix X509RevocationChecker.java:477-492 then fetch from the certificate's distribution points when fetching is enabled.
  - OpenSSL crypto/x509/x509_vfy.c:2223-2231 (get_crl_delta): CRLs come from ctx->crls and the store lookup only; the verifier does not fetch.

### CRL-020: A supplied CRL the references would look past is refreshed

A not-yet-valid CRL, an unusable issuingDistributionPoint, an unknown critical extension, a delta, indirect or reasons-partitioned CRL, or a malformed CRL is replaceable: a source is asked, and a fetched CRL that passes the same checks decides. A malformed CRL does not stop the search for another, alone or beside an expired one.

- **Status:** Decided
- **Decided by:** owner, PR #64 (SEC-23): follow OpenSSL and Bouncy Castle where they agree, BoringSSL where they differ; replaces the Observed rule that only an expired CRL is refreshed; for a malformed CRL the three references agree
- **Pins:** acceptance
- **Sources:**
  - OpenSSL 3.3 crypto/x509/x509_vfy.c:1564-1590 (get_crl_delta) consults lookup_crls when the best supplied CRL scores below CRL_SCORE_VALID (:33-42: no unhandled critical extension, time and scope; get_crl_score :1283-1340); the signature is not scored and its failure is reported at :1664 without another lookup.
  - BoringSSL crypto/x509/x509_vfy.cc:697-708 (get_crl) looks CRLs up in the store on the same condition.
  - Bouncy Castle pkix/src/main/java/org/bouncycastle/pkix/jcajce/X509RevocationChecker.java:797-863 turns any checkCRL failure but a revocation into 'no valid CRL found', and :468-487 then fetches from the certificate's distribution points when fetching is enabled.
  - BoringSSL crypto/x509/x_crl.cc:122-160 (ASN1_OP_D2I_POST): a CRL with an unsupported version, or a malformed issuingDistributionPoint or authorityKeyIdentifier, fails to decode and never joins the CRLs consulted, so the store is looked up as if it were absent.
  - OpenSSL 3.3 crypto/x509/x_crl.c:196-220 marks such a CRL EXFLAG_INVALID, which crypto/x509/x509_vfy.c never tests for a CRL; an invalid issuingDistributionPoint scores 0 (:1292) and the store lookup still runs when no CRL scores valid (:1576-1588).

### CRL-021: A CRL without nextUpdate but with another defect is replaced

A CRL's other defects decide exactly as they would with nextUpdate present, so a replaceable defect is replaced by a source's CRL.

- **Status:** Decided
- **Decided by:** owner, PR #64 (SEC-23); to the references a missing nextUpdate is no defect
- **Pins:** acceptance
- **Sources:**
  - OpenSSL 3.3 crypto/x509/x509_vfy.c:1576-1588 (get_crl_delta): a CRL without the scope score is not valid, so lookup_crls consults the store, which here answers by certificate.
  - BoringSSL crypto/x509/x509_vfy.cc:697-708 (get_crl): a CRL scored below valid, here without the scope score, is followed by a store lookup by issuer name.
  - OpenSSL 3.3 crypto/x509/x509_vfy.c:1112 (ossl_x509_check_crl_time) and BoringSSL crypto/x509/x509_vfy.cc:414 check nextUpdate only when present, so the missing nextUpdate is no defect to them and the scope miss decides, as for the same CRL with nextUpdate.
  - Bouncy Castle pkix/src/main/java/org/bouncycastle/pkix/jcajce/X509RevocationChecker.java:797-863 turns the scope failure into 'no valid CRL found' and :468-487 then fetches.

### CRL-022: A point-scoped CRL for a certificate that lists no points is replaced by certificate

The certificate is asked about by certificate and issuer, and a full CRL from the source decides. A source that answers only by URL has nothing to fetch, so `invalid_crl` stands (CRL-009).

- **Status:** Decided
- **Decided by:** owner, PR #64 (SEC-23)
- **Pins:** acceptance
- **Sources:**
  - OpenSSL 3.3 crypto/x509/x_crl.c:358-361 sets IDP_ONLYCA; OpenSSL crypto/x509/x509_vfy.c:2154-2157 (crl_crldp_check) returns 0 for an end entity, and :2295 (check_crl) fails with X509_V_ERR_DIFFERENT_CRL_SCOPE.
  - Bouncy Castle core PKIXCRLValidator.java:151-158 (checkDistributionPointName): the CRL is rejected with a distribution point name mismatch; RFC3280CertPathUtilities.java:1716-1729 reports the last such exception when no CRL is valid.
  - OpenSSL 3.3 crypto/x509/x509_vfy.c:1576-1588 (get_crl_delta): a CRL without the scope score is not valid, so lookup_crls consults the store, which here answers by certificate.
  - BoringSSL crypto/x509/x509_vfy.cc:697-708 (get_crl): a CRL scored below valid, here without the scope score, is followed by a store lookup by issuer name.

### CRL-023: A source completes another path beside a revoked one

With `--fetch-crls`, the path named under CRL-035 is refreshed and the file verifies through it.

- **Status:** Decided
- **Decided by:** Bouncy Castle followed, under the owner's delegated call to refresh CRLs, PR #60 and PR #64
- **Pins:** acceptance
- **Sources:**
  - OpenSSL 3.3 crypto/x509/x509_vfy.c:1564-1590 (get_crl_delta) consults lookup_crls when the best supplied CRL scores below CRL_SCORE_VALID (:33-42: no unhandled critical extension, time and scope; get_crl_score :1283-1340); the signature is not scored and its failure is reported at :1664 without another lookup.
  - BoringSSL crypto/x509/x509_vfy.cc:697-708 (get_crl) looks CRLs up in the store on the same condition.
  - Bouncy Castle pkix/src/main/java/org/bouncycastle/pkix/jcajce/X509RevocationChecker.java:797-863 turns any checkCRL failure but a revocation into 'no valid CRL found', and :468-487 then fetches from the certificate's distribution points when fetching is enabled.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/PKIXCertPathBuilderSpi.java:135-270 (build): every candidate path is tried and one that validates is accepted, whatever another path's revocation.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/PKIXCRLUtil.java:42-45 drops a CRL past nextUpdate, and with CRL distribution point fetching enabled (CertPathValidatorUtilities.java:571) a fresh CRL is fetched from the certificate's points.
  - OpenSSL builds one chain (crypto/x509/x509_vfy.c:3925 build_chain) and does not fetch, so it has no equivalent; the owner's delegated call to refresh expired CRLs follows Bouncy Castle (crl-019-stale-local-refreshed-by-provider).

### CRL-024: An RDP signer lacking only a CRL under one usage verifies once the CRL is present

When one usage fails its path (`invalid_eku`) and another lacks only a CRL, supplying or fetching that CRL verifies the file.

- **Status:** Decided
- **Decided by:** written argument (no reference has multi-EKU acceptance; `docs/rdp.md`)
- **Pins:** acceptance
- **Sources:**
  - No reference library has an equivalent: accepting an RDP signer under any one of several EKUs is an rssig RDP rule (docs/rdp.md). Written argument: the signer is acceptable under serverAuth and only lacks a CRL, so the missing CRL, which a source can supply, is the result rather than the other EKU's path failure.
  - On main, retrieval ran after a preliminary pass without revocation, which succeeded through serverAuth, so the CRL was fetched and the file verified; the fetch case restores that.

### CRL-025: The source decides transport; the core screens hygiene only

The verification core passes every listed URI to an injected source after hygiene screening; the source decides what to fetch.

- **Status:** Decided
- **Decided by:** owner, PR #60 (none of the references screens addresses in its verification core)
- **Pins:** acceptance
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:2228: the verifier only calls lookup_crls; apps/lib/apps.c:2833 and :2905-2907 (get_dp_url, crls_http_cb): the scheme rule (http only) lives in the application callback.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/CrlCache.java:136-141 and :185-188: the fetch helper applies an optional scheme allow-list (unrestricted by default) and opens the URL.
  - BoringSSL crypto/x509/x509_vfy.cc:697-704 (get_crl): never fetches.

### CRL-026: One certificate's distribution points never end the run

An over-long URI is skipped, and URIs past the first 16 are recorded as one `crl_urls` failure. Per-verification limits stay engine limits.

- **Status:** Decided
- **Decided by:** references agree (neither OpenSSL nor Bouncy Castle has such a limit; both skip a failing point)
- **Pins:** acceptance
- **Sources:**
  - OpenSSL and Bouncy Castle have no per-certificate point limit and skip a point that fails.
- **Unit test:** `a_certificate_over_the_url_limits_is_skipped_point_by_point`.

### CRL-027: A role-only partition alone is unsupported

Alone, a role-only partition is `invalid_crl`, because webpki cannot use that form.

- **Status:** Observed
- **Decided by:** —
- **Pins:** acceptance

## Tier 3: result diagnostics

Diagnostics pins on the error code, stage or details a consumer matches; both outcomes reject.

### CRL-028: Missing evidence is `revocation_unknown`; a source has four outcome kinds

However a CRL could not be obtained, the code is `revocation_unknown`, with the cause (denied, failed, abort, unknown) in `crl_retrieval.failures`.

- **Status:** Decided
- **Decided by:** owner, PR #60 design (the single code matches the references; the four kinds have no equivalent)
- **Pins:** diagnostics
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:1489 and :1527 (check_cert_crl): however a CRL could not be obtained, the result is the single X509_V_ERR_UNABLE_TO_GET_CRL.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/CertPathValidatorUtilities.java:1340: a single "No CRLs found for issuer" error, with lookup diagnostics appended to its message.
  - The four source kinds (denied, failed, abort, unknown) have no reference equivalent; they are the owner's design in PR #60, described in docs/crl-retrieval.md.

### CRL-029: Which error a rejected chain reports

A revocation is definite evidence and is reported over another path's failure; only a path that passes every other check and lacks CRLs can be completed, so its gap is named. With `--fetch-crls`, an unknown status that names nothing is followed by a check without revocation, which reports the path's own failure. Both results reject.

- **Status:** Decided
- **Decided by:** written argument (`docs/crl-retrieval.md`); the `--fetch-crls` part changed at the owner's request in review of PR #60
- **Pins:** diagnostics
- **Sources:**
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/PKIXCertPathBuilderSpi.java:135-270 (build): every candidate issuer is tried and a path that validates is returned; a failed candidate only sets certPathException (:268).
  - OpenSSL crypto/x509/x509_vfy.c:3925 (build_chain) builds one chain and :1444-1537 (check_cert_crl) checks that chain only; it has no second path to fall back on, so Bouncy Castle is followed.
  - No reference reports which of several rejected paths decides; the order is the written argument in docs/crl-retrieval.md (only a path that passes every other check and lacks CRLs can be completed).

### CRL-030: A CRL without nextUpdate alone revokes, unless a newer CRL clears it

Alone, such a listing is `certificate_revoked` if webpki would admit the CRL apart from the missing nextUpdate (judged on a byte-identical re-encoding with a stand-in nextUpdate). A newer current, complete, direct CRL that leaves the certificate out clears the listing; an older one does not. A removeFromCRL entry releases the listing. Both outcomes reject; only the code is pinned. On a timestamped file the timestamp authority's chain is checked first, so the same CRL alone is `invalid_crl` there.

- **Status:** Decided
- **Decided by:** owner, PR #64 (SEC-23): references checked at the owner's request; BoringSSL breaks the tie on clearing; OpenSSL and Bouncy Castle agree on removeFromCRL
- **Pins:** diagnostics
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:1555-1587 (ossl_x509_check_crl_time): a CRL without nextUpdate is never expired, so a current CRL whose entries are read.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/PKIXCRLUtil.java:42-45: a CRL with a null nextUpdate is kept ("nextUpdate == null || nextUpdate.after(validityDate)") and its entries are read.
  - BoringSSL crypto/x509/x509_vfy.cc:414: the nextUpdate comparison runs only if the field is present.
  - All three agree; the earlier rule in this task, that a CRL without nextUpdate is never current, followed none of them and failed open for a listed certificate.
  - OpenSSL 3.3 crypto/x509/x509_vfy.c:1112 (ossl_x509_check_crl_time): nextUpdate is checked only when present, so the CRL is current and its entry revokes (X509_V_ERR_CERT_REVOKED).
  - BoringSSL crypto/x509/x509_vfy.cc:414 (check_crl_time): the same; the CRL is used and the listed certificate is revoked.
  - Bouncy Castle pkix/src/main/java/org/bouncycastle/pkix/jcajce/PKIXCRLUtil.java findCRLs keeps a CRL whose nextUpdate is null, so its entry revokes.
  - OpenSSL 3.3 crypto/x509/x509_vfy.c:1134-1186 (get_crl_sk): among equally scored CRLs only the newest lastUpdate is kept (:1150-1164), so an older CRL's listing is not read once a newer valid CRL leaves the certificate out.
  - BoringSSL crypto/x509/x509_vfy.cc:666-691 (get_crl_sk): the same newest-CRL choice (:675-685).
  - Bouncy Castle pkix/src/main/java/org/bouncycastle/pkix/jcajce/RFC3280CertPathUtilities.java:708 walks its CRL set in no fixed order and stops at the first listing or once all reasons are covered, so it may revoke from the older CRL: it differs from OpenSSL, and BoringSSL decides (newest CRL decides).
  - removeFromCRL releases the entry in OpenSSL 3.3 crypto/x509/x509_vfy.c:1686-1689 (cert_crl) and Bouncy Castle RFC3280CertPathUtilities.java:794 (step k); BoringSSL crypto/x509/x509_vfy.cc:768-790 (cert_crl) revokes on any entry, so OpenSSL and Bouncy Castle, which agree, are followed.
- **Unit tests:** `a_crl_without_next_update_revokes_only_under_webpki_rules`, `a_crl_without_next_update_is_judged_by_its_other_defects`, `only_a_usable_covering_crl_clears_a_listing_without_next_update`, `a_crl_without_next_update_for_another_point_is_set_aside_if_admitted`, `a_crl_that_does_not_reencode_to_its_bytes_is_not_judged`.

### CRL-031: A definite result keeps its code with `--fetch-crls`

A definite revocation or CRL failure is the result, as without fetching, and is not followed by a check of the rest of the input. Both results reject. An unknown status is the exception, described in CRL-029.

- **Status:** Decided
- **Decided by:** written argument
- **Pins:** diagnostics
- **Sources:**
  - Without --fetch-crls, a chain whose paths all fail the path checks reports revocation first, as on main (crl-029-cross-unusable-crl-decides-beside-path-failing-key-usage); with --fetch-crls a definite CRL failure or revocation keeps that code. Only an unknown status, which is no evidence, is replaced by the path failure with fetching (crl-029-fetch-path-failing-key-usage-asks-nothing).
  - Only an unknown status that names nothing is followed by a check without revocation (crl-029-fetch-path-failing-key-usage-asks-nothing): it is no evidence, while these are.
  - Diagnostics only: both results reject.

### CRL-032: A revoked RDP usage is reported over another usage's failure

The revocation is reported and names the certificates another usage only lacks a CRL for. Both reject.

- **Status:** Decided
- **Decided by:** written argument
- **Pins:** diagnostics
- **Sources:**
  - No reference library has an equivalent: accepting an RDP signer under any one of several EKUs is an rssig RDP rule (docs/rdp.md).
  - Written argument, as for candidate paths (crl-029-cross-revoked-path-beside-path-failing-key-usage-is-revoked): a revocation is definite evidence and is reported over another usage's path failure (here invalid_eku for codeSigning). Both reject.
- **Unit test:** `a_revoked_usage_is_reported_and_names_another_usages_gaps`.

### CRL-033: An RDP signer lacking only a CRL under one usage reports the missing CRL

Without the CRL, the result is the missing CRL (`revocation_unknown`), not the other usage's `invalid_eku`, because a source can supply it.

- **Status:** Decided
- **Decided by:** written argument (no reference has multi-EKU acceptance; `docs/rdp.md`)
- **Pins:** diagnostics
- **Sources:**
  - No reference library has an equivalent: accepting an RDP signer under any one of several EKUs is an rssig RDP rule (docs/rdp.md). Written argument: the signer is acceptable under serverAuth and only lacks a CRL, so the missing CRL, which a source can supply, is the result rather than the other EKU's path failure.
  - On main, retrieval ran after a preliminary pass without revocation, which succeeded through serverAuth, so the CRL was fetched and the file verified; the fetch case restores that.

### CRL-034: A partition for another point is no evidence

The certificate is without a CRL, so the status is `revocation_unknown` and retrieval fetches its own point.

- **Status:** Decided
- **Decided by:** references agree (OpenSSL, Bouncy Castle)
- **Pins:** diagnostics
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:2146-2198 (crl_crldp_check) and :1847-1853 (get_crl_score): a CRL whose issuingDistributionPoint does not match the certificate gets no CRL_SCORE_SCOPE and is not selected over a CRL that covers it.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/RFC3280CertPathUtilities.java:1678 (processCRLB2) with core PKIXCRLValidator.java:151-158 (checkDistributionPointName): a distribution point mismatch rejects the CRL before processCRLJ (:1703) reads entries.

### CRL-035: A revocation names another path's refreshable certificates

A revocation on one candidate path names, in `details.certificates_with_expired_crl` or `details.certificates_with_replaceable_crl`, the certificates of another viable path whose only CRLs a source could refresh. Paths with a CRL no refresh can fix are not named.

- **Status:** Decided
- **Decided by:** Bouncy Castle followed, under the owner's delegated call to refresh CRLs, PR #60 and PR #64
- **Pins:** diagnostics
- **Sources:**
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/PKIXCertPathBuilderSpi.java:135-270 (build): every candidate path is tried and one that validates is accepted, whatever another path's revocation.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/PKIXCRLUtil.java:42-45 drops a CRL past nextUpdate, and with CRL distribution point fetching enabled (CertPathValidatorUtilities.java:571) a fresh CRL is fetched from the certificate's points.
  - OpenSSL builds one chain (crypto/x509/x509_vfy.c:3925 build_chain) and does not fetch, so it has no equivalent; the owner's delegated call to refresh expired CRLs follows Bouncy Castle (crl-019-stale-local-refreshed-by-provider).
  - OpenSSL 3.3 crypto/x509/x509_vfy.c:1564-1590 (get_crl_delta) consults lookup_crls when the best supplied CRL scores below CRL_SCORE_VALID (:33-42: no unhandled critical extension, time and scope; get_crl_score :1283-1340); the signature is not scored and its failure is reported at :1664 without another lookup.
  - BoringSSL crypto/x509/x509_vfy.cc:697-708 (get_crl) looks CRLs up in the store on the same condition.
  - Bouncy Castle pkix/src/main/java/org/bouncycastle/pkix/jcajce/X509RevocationChecker.java:797-863 turns any checkCRL failure but a revocation into 'no valid CRL found', and :468-487 then fetches from the certificate's distribution points when fetching is enabled.
- **Unit test:** `a_revocation_names_only_paths_a_source_could_complete`.

### CRL-036: A path a source could complete is reported over a stuck path

When no path is revoked, a viable path that only lacks, or has expired or replaceable, CRLs is reported ahead of a path whose CRL no refresh can fix; when every path is stuck, the most specific failure decides. Acceptance with `--fetch-crls` follows from CRL-023.

- **Status:** Decided
- **Decided by:** written argument (`docs/crl-retrieval.md`)
- **Pins:** diagnostics
- **Sources:**
  - Written argument in `docs/crl-retrieval.md`.
- **Unit test:** `a_path_a_source_could_complete_is_reported_over_a_stuck_paths_failure`.

## Tier 4: retrieval diagnostics

Diagnostics pins on which requests a source receives and how retrieval is reported.

### CRL-037: Retrieval asks per certificate, only about what lacks a CRL

Which requests are made; the verification result is the same either way.

- **Status:** Decided
- **Decided by:** references agree (OpenSSL, Bouncy Castle)
- **Pins:** diagnostics
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:2206-2254 (get_crl_delta; lookup_crls at :2228) called from :1444-1537 (check_cert_crl): CRLs are looked up for the certificate being checked, by its issuer name, and only when the context holds none for it.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/RFC3280CertPathUtilities.java:1754-1880 (checkCRLs): CRLs are looked up per certificate, per distribution point.

### CRL-038: A source answering by certificate leaves no per-point failures

Only a body that loads as a CRL of the certificate's issuer counts. When that answer settles the status, no per-point failure is recorded; when it does not, the listed points the source left unused are recorded as not used, so no listed point disappears from the report.

- **Status:** Decided
- **Decided by:** owner (delegated the call), PR #60; written argument for unused points
- **Pins:** diagnostics
- **Sources:**
  - OpenSSL crypto/x509/x509_lu.c:978-990 (X509_STORE_CTX_get1_crls): CRLs are looked up by issuer name, with no per-distribution-point outcome.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/CertPathValidatorUtilities.java:1100-1124 (getCompleteCRLs): the selector matches the issuer only.
  - OpenSSL crypto/x509/x509_lu.c:978-990 (X509_STORE_CTX_get1_crls) and Bouncy Castle CertPathValidatorUtilities.java:1100-1124 (getCompleteCRLs): CRLs are looked up by issuer, with no per-distribution-point outcome, so an answer by certificate leaves no per-point failure when it settles the status.
  - Written argument for the other case: when that answer does not settle the status, the report must still account for every listed point (docs/crl-retrieval.md: no listed point disappears from the report), so the points the source did not use are recorded as not used.

### CRL-039: A missing nextUpdate blocks retrieval only as a CRL's sole defect

A CRL whose only defect is a missing nextUpdate is `invalid_crl` (`missing_next_update`) and is not asked about; with another defect, that defect is reported and is replaceable.

- **Status:** Decided
- **Decided by:** owner, PR #64 (SEC-23)
- **Pins:** diagnostics
- **Sources:**
  - OpenSSL 3.3 crypto/x509/x509_vfy.c:1564-1590 (get_crl_delta) consults lookup_crls when the best supplied CRL scores below CRL_SCORE_VALID (:33-42: no unhandled critical extension, time and scope; get_crl_score :1283-1340); the signature is not scored and its failure is reported at :1664 without another lookup.
  - BoringSSL crypto/x509/x509_vfy.cc:697-708 (get_crl) looks CRLs up in the store on the same condition.
  - Bouncy Castle pkix/src/main/java/org/bouncycastle/pkix/jcajce/X509RevocationChecker.java:797-863 turns any checkCRL failure but a revocation into 'no valid CRL found', and :468-487 then fetches from the certificate's distribution points when fetching is enabled.
  - OpenSSL 3.3 crypto/x509/x509_vfy.c:1112 (ossl_x509_check_crl_time) and BoringSSL crypto/x509/x509_vfy.cc:414 (check_crl_time) check nextUpdate only when present, so a CRL without it is time-valid, scores valid and no store lookup follows.
  - Bouncy Castle pkix/src/main/java/org/bouncycastle/pkix/jcajce/PKIXCRLUtil.java findCRLs keeps a CRL whose nextUpdate is null, so it is used and nothing is fetched for it.
  - OpenSSL 3.3 crypto/x509/x509_vfy.c:1576-1588 (get_crl_delta): a CRL without the scope score is not valid, so lookup_crls consults the store, which here answers by certificate.
  - BoringSSL crypto/x509/x509_vfy.cc:697-708 (get_crl): a CRL scored below valid, here without the scope score, is followed by a store lookup by issuer name.
  - OpenSSL 3.3 crypto/x509/x509_vfy.c:1112 (ossl_x509_check_crl_time) and BoringSSL crypto/x509/x509_vfy.cc:414 check nextUpdate only when present, so the missing nextUpdate is no defect to them and the scope miss decides, as for the same CRL with nextUpdate.
  - Bouncy Castle pkix/src/main/java/org/bouncycastle/pkix/jcajce/X509RevocationChecker.java:797-863 turns the scope failure into 'no valid CRL found' and :468-487 then fetches.

### CRL-040: An abort before an expired CRL is refreshed is marked

Without an answer `crl_expired` stands, marked `retrieval_aborted` when the source aborted.

- **Status:** Decided
- **Decided by:** owner (delegated the call), PR #60
- **Pins:** diagnostics
- **Sources:**
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/PKIXCRLUtil.java:42-49 drops CRLs past nextUpdate; CertPathValidatorUtilities.java:571-630 and pkix X509RevocationChecker.java:477-492 then fetch from the certificate's distribution points when fetching is enabled.
  - OpenSSL crypto/x509/x509_vfy.c:2223-2231 (get_crl_delta): CRLs come from ctx->crls and the store lookup only; the verifier does not fetch.

### CRL-041: Without an answer, a replaceable CRL's error stands and names the certificate

This includes a malformed CRL. The certificate is named in `certificates_with_replaceable_crl` on the error that stands, and the error is marked `retrieval_aborted` when the source aborted.

- **Status:** Decided
- **Decided by:** owner, PR #64 (SEC-23)
- **Pins:** diagnostics
- **Sources:**
  - OpenSSL 3.3 crypto/x509/x509_vfy.c:1564-1590 (get_crl_delta) consults lookup_crls when the best supplied CRL scores below CRL_SCORE_VALID (:33-42: no unhandled critical extension, time and scope; get_crl_score :1283-1340); the signature is not scored and its failure is reported at :1664 without another lookup.
  - BoringSSL crypto/x509/x509_vfy.cc:697-708 (get_crl) looks CRLs up in the store on the same condition.
  - Bouncy Castle pkix/src/main/java/org/bouncycastle/pkix/jcajce/X509RevocationChecker.java:797-863 turns any checkCRL failure but a revocation into 'no valid CRL found', and :468-487 then fetches from the certificate's distribution points when fetching is enabled.
  - BoringSSL crypto/x509/x_crl.cc:122-160 (ASN1_OP_D2I_POST): a CRL with an unsupported version, or a malformed issuingDistributionPoint or authorityKeyIdentifier, fails to decode and never joins the CRLs consulted, so the store is looked up as if it were absent.
  - OpenSSL 3.3 crypto/x509/x_crl.c:196-220 marks such a CRL EXFLAG_INVALID, which crypto/x509/x509_vfy.c never tests for a CRL; an invalid issuingDistributionPoint scores 0 (:1292) and the store lookup still runs when no CRL scores valid (:1576-1588).

### CRL-042: The built-in source refuses what it does not fetch

The built-in `HttpCrlSource` is stricter than the references (public addresses, `http` only, no redirects, size and time bounds) and reports a refused URL as denied; `retrieval::check_public_http_url` gives a custom source the same check.

- **Status:** Decided
- **Decided by:** owner, PR #60
- **Pins:** diagnostics
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:2228: the verifier only calls lookup_crls; apps/lib/apps.c:2833 and :2905-2907 (get_dp_url, crls_http_cb): the scheme rule (http only) lives in the application callback.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/CrlCache.java:136-141 and :185-188: the fetch helper applies an optional scheme allow-list (unrestricted by default) and opens the URL.
  - BoringSSL crypto/x509/x509_vfy.cc:697-704 (get_crl): never fetches.

### CRL-043: A URI that is not an absolute URL is never offered to a source

It is recorded as `crl_fetch_denied` with its own message and no `url`.

- **Status:** Decided
- **Decided by:** references agree (OpenSSL, Bouncy Castle)
- **Pins:** diagnostics
- **Sources:**
  - OpenSSL `apps/lib/apps.c:2833`: `get_dp_url` returns only `http://`.
  - Bouncy Castle `CrlCache.java:185`: `toURL()` fails on a relative URI.
- **Unit test:** `a_uri_that_is_not_an_absolute_url_is_withheld_with_its_own_reason`.

### CRL-044: Fetch limits bound one verification

The engine renews a source's allowances for each verification (`CrlSource::begin_verification`). A DNS timeout still closes the built-in source for the invocation, keeping at most one unfinished resolver thread.

- **Status:** Decided
- **Decided by:** references agree (neither OpenSSL nor Bouncy Castle lets one validation exhaust the next)
- **Pins:** diagnostics
- **Sources:**
  - OpenSSL `apps/lib/apps.c:2866-2867`, `apps/verify.c:220-232`: per-fetch limits, nothing accumulated.
  - Bouncy Castle `CrlCache.java:41-46`: per-connection timeouts, process-wide cache.
- **Unit test:** `a_new_verification_restores_a_sources_allowances_but_a_dns_timeout_closes_it_for_good`.

### CRL-045: A CRL naming a same-key root's identifier is forged, not set aside

Two configured roots with one key and name may carry different subjectKeyIdentifiers. A CRL signed by another key that names any of them is `invalid_crl_signature`; one naming an identifier no configured root carries is another issuer's and is set aside. Both reject; the libraries have no equivalent for two same-key anchors.

- **Status:** Observed
- **Decided by:** —
- **Pins:** diagnostics

## Candidate rules

Unnumbered. `tests/decision-claims.json` assigns these cases here until they name an entry.

- `attach`: cases that pin an existing CRL entry but do not name it yet: the remaining SEC-10 audit cases and every format's revocation, CRL-freshness and forged-CRL cases.
