# CRL decisions

Numbered decisions behind rssig's CRL and revocation behavior. The entry
format, Status values and how cases name an entry are defined in
[Decision indexes](decisions.md). The history and review discussion is in
[CRL-T001](tasks/crl-t001.md) and
[CRL-T011](tasks/crl-t011.md).

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
| [CRL-021](#crl-021-a-point-scoped-crl-for-a-certificate-that-lists-no-points-is-replaced-by-certificate) | A point-scoped CRL for a certificate that lists no points is replaced by certificate | Retrieval | Decided | acceptance |
| [CRL-022](#crl-022-a-source-completes-another-path-beside-a-revoked-one) | A source completes another path beside a revoked one | Paths and usages | Decided | acceptance |
| [CRL-023](#crl-023-the-source-decides-transport-the-core-screens-hygiene-only) | The source decides transport; the core screens hygiene only | Retrieval | Decided | acceptance |
| [CRL-024](#crl-024-one-certificates-distribution-points-never-end-the-run) | One certificate's distribution points never end the run | Retrieval | Decided | acceptance |
| [CRL-025](#crl-025-a-role-only-partition-alone-is-unsupported) | A role-only partition alone is unsupported | Scope | Observed | acceptance |
| [CRL-026](#crl-026-missing-evidence-is-revocation_unknown-a-source-has-four-outcome-kinds) | Missing evidence is `revocation_unknown`; a source has four outcome kinds | Retrieval | Decided | diagnostics |
| [CRL-027](#crl-027-which-error-a-rejected-chain-reports) | Which error a rejected chain reports | Paths and usages | Decided | diagnostics |
| [CRL-028](#crl-028-a-crl-without-nextupdate-alone-revokes-unless-a-newer-crl-clears-it) | A CRL without nextUpdate alone revokes, unless a newer CRL clears it | Choosing CRLs | Decided | diagnostics |
| [CRL-029](#crl-029-a-definite-result-keeps-its-code-with---fetch-crls) | A definite result keeps its code with `--fetch-crls` | Retrieval | Decided | diagnostics |
| [CRL-030](#crl-030-a-partition-for-another-point-is-no-evidence) | A partition for another point is no evidence | Scope | Decided | diagnostics |
| [CRL-031](#crl-031-a-revocation-names-another-paths-refreshable-certificates) | A revocation names another path's refreshable certificates | Paths and usages | Decided | diagnostics |
| [CRL-032](#crl-032-a-path-a-source-could-complete-is-reported-over-a-stuck-path) | A path a source could complete is reported over a stuck path | Paths and usages | Decided | diagnostics |
| [CRL-033](#crl-033-retrieval-asks-per-certificate-only-about-what-lacks-a-crl) | Retrieval asks per certificate, only about what lacks a CRL | Retrieval | Decided | diagnostics |
| [CRL-034](#crl-034-a-source-answering-by-certificate-leaves-no-per-point-failures) | A source answering by certificate leaves no per-point failures | Retrieval | Decided | diagnostics |
| [CRL-035](#crl-035-a-missing-nextupdate-blocks-retrieval-only-as-a-crls-sole-defect) | A missing nextUpdate blocks retrieval only as a CRL's sole defect | Retrieval | Decided | diagnostics |
| [CRL-036](#crl-036-without-an-answer-an-expired-or-replaceable-crls-error-stands) | Without an answer, an expired or replaceable CRL's error stands | Retrieval | Decided | diagnostics |
| [CRL-037](#crl-037-the-built-in-source-refuses-what-it-does-not-fetch) | The built-in source refuses what it does not fetch | Retrieval | Decided | diagnostics |
| [CRL-038](#crl-038-a-uri-that-is-not-an-absolute-url-is-never-offered-to-a-source) | A URI that is not an absolute URL is never offered to a source | Retrieval | Decided | diagnostics |
| [CRL-039](#crl-039-fetch-limits-bound-one-verification) | Fetch limits bound one verification | Retrieval | Decided | diagnostics |
| [CRL-040](#crl-040-a-crl-naming-a-same-key-roots-identifier-is-forged-not-set-aside) | A CRL naming a same-key root's identifier is forged, not set aside | Issuer keys | Observed | diagnostics |
| [CRL-041](#crl-041-a-crls-issuer-name-matches-by-rfc-5280-name-comparison) | A CRL's issuer name matches by RFC 5280 name comparison | Issuer keys | Decided | acceptance |
| [CRL-042](#crl-042-an-issuer-without-a-usable-key-identifier-cannot-disprove-another-keys-crl) | An issuer without a usable key identifier cannot disprove another key's CRL | Issuer keys | Decided | diagnostics |
| [CRL-043](#crl-043-a-crl-naming-another-certificate-by-issuer-and-serial-is-set-aside-when-its-signature-fails) | A CRL naming another certificate by issuer and serial is set aside when its signature fails | Issuer keys | Decided | diagnostics |
| [CRL-044](#crl-044-a-crl-that-verifies-is-used-whatever-its-authoritykeyidentifier-names-by-issuer-and-serial) | A CRL that verifies is used whatever its authorityKeyIdentifier names by issuer and serial | Issuer keys | Decided | acceptance |
| [CRL-045](#crl-045-a-retrieved-crl-over-the-size-cap-is-never-evidence) | A retrieved CRL over the size cap is never evidence | Retrieval | Observed | acceptance |
| [CRL-046](#crl-046-a-retrieved-crl-over-the-size-cap-is-reported-with-the-cap-it-hit) | A retrieved CRL over the size cap is reported with the cap it hit | Retrieval | Observed | diagnostics |
| [CRL-047](#crl-047-an-aborted-source-stops-retrieval-and-is-reported-as-crl_fetch_aborted) | An aborted source stops retrieval and is reported as `crl_fetch_aborted` | Retrieval | Decided | diagnostics |
| [CRL-048](#crl-048-a-crl-from-a-source-is-evidence-only-when-verification-authenticates-it) | A CRL from a source is evidence only when verification authenticates it | Retrieval | Decided | acceptance |
| [CRL-049](#crl-049-retrieval-failures-are-reported-in-a-fixed-order) | Retrieval failures are reported in a fixed order | Retrieval | Observed | diagnostics |
| [CRL-050](#crl-050-each-request-carries-every-point-the-certificate-lists-whatever-was-asked-before) | Each request carries every point the certificate lists, whatever was asked before | Retrieval | Observed | acceptance |
| [CRL-051](#crl-051-each-certificate-records-what-its-own-request-yielded-reuse-is-the-sources) | Each certificate records what its own request yielded; reuse is the source's | Retrieval | Observed | diagnostics |

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

Without a listing, a chain issuer's CRL that lacks nextUpdate is `invalid_crl` (`missing_next_update`). RFC 5280 section 5.1.2.5 requires nextUpdate, and a CRL that never expires cannot show that the status is still current. Its listing still counts, beside an older CRL (CRL-004) or alone (CRL-028), so the rule fails closed.

- **Status:** Decided
- **Decided by:** written argument (stricter than the references, which would accept it)
- **Pins:** acceptance
- **Sources:**
  - RFC 5280 section 5.1.2.5.

### CRL-003: A listing in a CRL whose signature cannot be verified never counts

A CRL with a bad or unsupported signature is `invalid_crl` (`unsupported_signature_algorithm`) or `invalid_crl_signature`, and its entries are never read. It is set aside beside a usable CRL (CRL-012).

- **Status:** Decided
- **Decided by:** references agree (OpenSSL, Bouncy Castle)
- **Pins:** acceptance
- **Sources:**
  - OpenSSL `crypto/x509/x509_vfy.c` `check_crl` fails the CRL before `cert_crl` reads entries.
  - Bouncy Castle `RFC3280CertPathUtilities` processCRLG skips it before processCRLJ reads entries.

### CRL-004: A CRL without nextUpdate counts for a listing beside an older CRL

A correctly signed, in-scope CRL without nextUpdate claims no expiry, so it is current: its listing revokes beside an older usable CRL. This is the other side of CRL-002: a listing counts but an absence never clears, so a missing nextUpdate can only make a status look worse.

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
- **Decided by:** references agree (OpenSSL, BoringSSL, Bouncy Castle; OpenSSL 3.0.13 run as a maintenance step), CRL-T004
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
- **Note:** no spec case: since PATH-013 (PR #97) a path certificate whose cRLDistributionPoints does not decode fails the path before revocation is checked, so this rule, and the `certificate_distribution_points` reason, stay as a guard the unit tests pin.
- **Unit tests:** `a_listing_counts_only_on_a_positive_scope_match`, `unreadable_certificate_points_never_discard_a_partition` in `engine/src/trust.rs`.

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

A candidate path that passes every check, with its CRLs, is accepted whatever another candidate path does or lacks. For an RDP signer each usage is a candidate path: when one usage fails its path (`invalid_eku`) and another lacks only a CRL, supplying or fetching that CRL verifies the file.

- **Status:** Decided
- **Decided by:** Bouncy Castle followed (OpenSSL builds one chain and has no equivalent); for RDP usages, written argument (no reference has multi-EKU acceptance; `docs/rdp.md`)
- **Pins:** acceptance
- **Sources:**
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/PKIXCertPathBuilderSpi.java:135-270 (build): every candidate issuer is tried and a path that validates is returned; a failed candidate only sets certPathException (:268).
  - OpenSSL crypto/x509/x509_vfy.c:3925 (build_chain) builds one chain and :1444-1537 (check_cert_crl) checks that chain only; it has no second path to fall back on, so Bouncy Castle is followed.
  - No reference library has an equivalent: accepting an RDP signer under any one of several EKUs is an rssig RDP rule (docs/rdp.md). Written argument: the signer is acceptable under serverAuth and only lacks a CRL, so the missing CRL, which a source can supply, is the result rather than the other EKU's path failure.
  - On main, retrieval ran after a preliminary pass without revocation, which succeeded through serverAuth, so the CRL was fetched and the file verified; the fetch case restores that.

### CRL-018: A CRL with a bad signature is not refreshed

A supplied CRL with a bad signature is `invalid_crl_signature` and nothing is requested, even if the source holds a good CRL. Likewise an issuer without cRLSign (CRL-015) is not asked about: a fetched CRL has the same issuer.

- **Status:** Decided
- **Decided by:** owner, PR #64: BoringSSL decides (OpenSSL and BoringSSL report without a second lookup; Bouncy Castle fetches)
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

A not-yet-valid CRL, an unusable issuingDistributionPoint, an unknown critical extension, a delta, indirect or reasons-partitioned CRL, or a malformed CRL is replaceable: a source is asked, and a fetched CRL that passes the same checks decides. A malformed CRL does not stop the search for another, alone or beside an expired one. A CRL without nextUpdate that has another defect is no different: its other defects decide exactly as they would with nextUpdate present, so a replaceable defect is replaced by a source's CRL (to the references a missing nextUpdate is no defect).

- **Status:** Decided
- **Decided by:** owner, PR #64: follow OpenSSL and Bouncy Castle where they agree, BoringSSL where they differ; replaces the Observed rule that only an expired CRL is refreshed; for a malformed CRL the three references agree
- **Pins:** acceptance
- **Sources:**
  - OpenSSL 3.3 crypto/x509/x509_vfy.c:1564-1590 (get_crl_delta) consults lookup_crls when the best supplied CRL scores below CRL_SCORE_VALID (:33-42: no unhandled critical extension, time and scope; get_crl_score :1283-1340); the signature is not scored and its failure is reported at :1664 without another lookup.
  - BoringSSL crypto/x509/x509_vfy.cc:697-708 (get_crl) looks CRLs up in the store on the same condition.
  - Bouncy Castle pkix/src/main/java/org/bouncycastle/pkix/jcajce/X509RevocationChecker.java:797-863 turns any checkCRL failure but a revocation into 'no valid CRL found', and :468-487 then fetches from the certificate's distribution points when fetching is enabled.
  - BoringSSL crypto/x509/x_crl.cc:122-160 (ASN1_OP_D2I_POST): a CRL with an unsupported version, or a malformed issuingDistributionPoint or authorityKeyIdentifier, fails to decode and never joins the CRLs consulted, so the store is looked up as if it were absent.
  - OpenSSL 3.3 crypto/x509/x509_vfy.c:1576-1588 (get_crl_delta): a CRL without the scope score is not valid, so lookup_crls consults the store, which here answers by certificate.
  - OpenSSL 3.3 crypto/x509/x509_vfy.c:1112 (check_crl_time) and BoringSSL crypto/x509/x509_vfy.cc:414 check nextUpdate only when present, so a missing nextUpdate is no defect to them and the scope miss decides, as for the same CRL with nextUpdate.
  - Bouncy Castle pkix/src/main/java/org/bouncycastle/pkix/jcajce/X509RevocationChecker.java:797-863 turns the scope failure into 'no valid CRL found' and :468-487 then fetches.
  - OpenSSL 3.3 crypto/x509/x_crl.c:196-220 marks such a CRL EXFLAG_INVALID, which crypto/x509/x509_vfy.c never tests for a CRL; an invalid issuingDistributionPoint scores 0 (:1292) and the store lookup still runs when no CRL scores valid (:1576-1588).

### CRL-021: A point-scoped CRL for a certificate that lists no points is replaced by certificate

The certificate is asked about by certificate and issuer, and a full CRL from the source decides. A source that answers only by URL has nothing to fetch, so `invalid_crl` stands (CRL-009).

- **Status:** Decided
- **Decided by:** owner, PR #64
- **Pins:** acceptance
- **Sources:**
  - OpenSSL 3.3 crypto/x509/x_crl.c:358-361 sets IDP_ONLYCA; OpenSSL crypto/x509/x509_vfy.c:2154-2157 (crl_crldp_check) returns 0 for an end entity, and :2295 (check_crl) fails with X509_V_ERR_DIFFERENT_CRL_SCOPE.
  - Bouncy Castle core PKIXCRLValidator.java:151-158 (checkDistributionPointName): the CRL is rejected with a distribution point name mismatch; RFC3280CertPathUtilities.java:1716-1729 reports the last such exception when no CRL is valid.
  - OpenSSL 3.3 crypto/x509/x509_vfy.c:1576-1588 (get_crl_delta): a CRL without the scope score is not valid, so lookup_crls consults the store, which here answers by certificate.
  - BoringSSL crypto/x509/x509_vfy.cc:697-708 (get_crl): a CRL scored below valid, here without the scope score, is followed by a store lookup by issuer name.

### CRL-022: A source completes another path beside a revoked one

With `--fetch-crls`, the path named under CRL-031 is refreshed and the file verifies through it.

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

### CRL-023: The source decides transport; the core screens hygiene only

The verification core passes every listed URI to an injected source after hygiene screening; the source decides what to fetch.

- **Status:** Decided
- **Decided by:** owner, PR #60 (none of the references screens addresses in its verification core)
- **Pins:** acceptance
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:2228: the verifier only calls lookup_crls; apps/lib/apps.c:2833 and :2905-2907 (get_dp_url, crls_http_cb): the scheme rule (http only) lives in the application callback.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/CrlCache.java:136-141 and :185-188: the fetch helper applies an optional scheme allow-list (unrestricted by default) and opens the URL.
  - BoringSSL crypto/x509/x509_vfy.cc:697-704 (get_crl): never fetches.

### CRL-024: One certificate's distribution points never end the run

An over-long URI is skipped; every other listed URI is offered to the source, however many, and the source decides how many it tries. The report keeps at most 16 failure entries about points and 16 about none per certificate (a source's first abort is always kept) and counts the rest in one `resource_limit_exceeded` entry each (`details.resource` `crl_failure_entries`, `details.omitted`). The engine's own retrieval limits do not end the run either: a certificate reached with the retained-byte cap full is not asked and its points are recorded as not tried (CRL-039), and a response past the entry bound or a body past the retained-CRL cap is recorded and not used (LIMIT-T004); only the LIMIT-T002 work budget ends it. A source's request and URL totals are the source's (CRL-039).

- **Status:** Decided
- **Decided by:** references agree (neither OpenSSL nor Bouncy Castle has such a limit; both skip a failing point); the offered-point cap was removed by CRL-T040 (PR #92), owner approval to be recorded there; a full retained-byte store leaves a certificate unasked instead of ending the run since CRL-T041; owner, PR #95 (approved); since LIMIT-T004 the supplied bytes checked up front, the response entries and the retained CRL count are recorded and the run goes on with the evidence gathered; it can accept an input the run used to end on (a library store over the byte cap; a body refused for the CRL count beside an older CRL that loaded); owner, PR #100 (approved 2026-11-27)
- **Pins:** acceptance
- **Sources:**
  - OpenSSL and Bouncy Castle have no per-certificate point limit and skip a point that fails.
- **Unit tests:** `a_certificate_over_the_url_limits_is_skipped_point_by_point`, `the_report_bounds_failure_entries_per_certificate_not_the_points_offered`.

### CRL-025: A role-only partition alone is unsupported

Alone, a role-only partition is `invalid_crl`, because webpki cannot use that form.

- **Status:** Observed
- **Decided by:** —
- **Pins:** acceptance

## Tier 3: result diagnostics

Diagnostics pins on the error code, stage or details a consumer matches; both outcomes reject.

### CRL-026: Missing evidence is `revocation_unknown`; a source has four outcome kinds

However a CRL could not be obtained, the code is `revocation_unknown`, with the cause (denied, failed, abort, unknown) in `crl_retrieval.failures`, unless an aborted source left a certificate without a CRL unasked or cut its request short (CRL-047). When no supplied CRL applies at all, CRL-001 returns it before path building.

- **Status:** Decided
- **Decided by:** owner, PR #60 design (the single code matches the references; the four kinds have no equivalent); owner, PR #84 (approved): an abort is excepted, as CRL-047 decides
- **Pins:** diagnostics
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:1489 and :1527 (check_cert_crl): however a CRL could not be obtained, the result is the single X509_V_ERR_UNABLE_TO_GET_CRL.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/CertPathValidatorUtilities.java:1340: a single "No CRLs found for issuer" error, with lookup diagnostics appended to its message.
  - The four source kinds (denied, failed, abort, unknown) have no reference equivalent; they are the owner's design in PR #60, described in docs/crl-retrieval.md.

### CRL-027: Which error a rejected chain reports

A revocation is definite evidence and is reported over another path's failure; only a path that passes every other check and lacks CRLs can be completed, so its gap is named. With `--fetch-crls`, an unknown status that names nothing is followed by a check without revocation, which reports the path's own failure. Both results reject. A lifetime-signing validity failure on another path is the exception: it outranks a revocation (TIME-011). For an RDP signer each usage is a candidate path: a revoked usage is reported over another usage's failure and names the certificates another usage only lacks a CRL for; when one usage fails its path (`invalid_eku`) and another only lacks a CRL, the missing CRL (`revocation_unknown`) is the result, because a source can supply it.

- **Status:** Decided
- **Decided by:** written argument (`docs/crl-retrieval.md`); the `--fetch-crls` part changed at the owner's request in review of PR #60; for RDP usages, written argument (no reference has multi-EKU acceptance; `docs/rdp.md`)
- **Pins:** diagnostics
- **Sources:**
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/PKIXCertPathBuilderSpi.java:135-270 (build): every candidate issuer is tried and a path that validates is returned; a failed candidate only sets certPathException (:268).
  - OpenSSL crypto/x509/x509_vfy.c:3925 (build_chain) builds one chain and :1444-1537 (check_cert_crl) checks that chain only; it has no second path to fall back on, so Bouncy Castle is followed.
  - No reference reports which of several rejected paths decides; the order is the written argument in docs/crl-retrieval.md (only a path that passes every other check and lacks CRLs can be completed).
  - No reference library has an equivalent: accepting an RDP signer under any one of several EKUs is an rssig RDP rule (docs/rdp.md). Written argument: the signer is acceptable under serverAuth and only lacks a CRL, so the missing CRL, which a source can supply, is the result rather than the other EKU's path failure.
  - Written argument, as for candidate paths (crl-027-cross-revoked-path-beside-path-failing-key-usage-is-revoked): a revocation is definite evidence and is reported over another usage's path failure (here invalid_eku for codeSigning). Both reject.
- **Unit tests:** `a_revoked_usage_is_reported_and_names_another_usages_gaps`.

### CRL-028: A CRL without nextUpdate alone revokes, unless a newer CRL clears it

Alone, such a listing is `certificate_revoked` if webpki would admit the CRL apart from the missing nextUpdate (judged on a byte-identical re-encoding with a stand-in nextUpdate). A newer current, complete, direct CRL that leaves the certificate out clears the listing; an older one does not. A removeFromCRL entry releases the listing. Both outcomes reject; only the code is pinned. On a timestamped file the timestamp authority's chain is checked first, so the same CRL alone is `invalid_crl` there.

- **Status:** Decided
- **Decided by:** owner, PR #64: references checked at the owner's request; BoringSSL breaks the tie on clearing; OpenSSL and Bouncy Castle agree on removeFromCRL
- **Pins:** diagnostics
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:1555-1587 (ossl_x509_check_crl_time): a CRL without nextUpdate is never expired, so a current CRL whose entries are read.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/PKIXCRLUtil.java:42-45: a CRL with a null nextUpdate is kept ("nextUpdate == null || nextUpdate.after(validityDate)") and its entries are read.
  - BoringSSL crypto/x509/x509_vfy.cc:414: the nextUpdate comparison runs only if the field is present.
  - All three agree; the earlier rule in this task, that a CRL without nextUpdate is never current, followed none of them and failed open for a listed certificate.
  - OpenSSL 3.3 crypto/x509/x509_vfy.c:1112 (check_crl_time): nextUpdate is checked only when present, so the CRL is current and its entry revokes (X509_V_ERR_CERT_REVOKED).
  - BoringSSL crypto/x509/x509_vfy.cc:414 (check_crl_time): the same; the CRL is used and the listed certificate is revoked.
  - Bouncy Castle pkix/src/main/java/org/bouncycastle/pkix/jcajce/PKIXCRLUtil.java findCRLs keeps a CRL whose nextUpdate is null, so its entry revokes.
  - OpenSSL 3.3 crypto/x509/x509_vfy.c:1134-1186 (get_crl_sk): among equally scored CRLs only the newest lastUpdate is kept (:1150-1164), so an older CRL's listing is not read once a newer valid CRL leaves the certificate out.
  - BoringSSL crypto/x509/x509_vfy.cc:666-691 (get_crl_sk): the same newest-CRL choice (:675-685).
  - Bouncy Castle pkix/src/main/java/org/bouncycastle/pkix/jcajce/RFC3280CertPathUtilities.java:708 walks its CRL set in no fixed order and stops at the first listing or once all reasons are covered, so it may revoke from the older CRL: it differs from OpenSSL, and BoringSSL decides (newest CRL decides).
  - removeFromCRL releases the entry in OpenSSL 3.3 crypto/x509/x509_vfy.c:1686-1689 (cert_crl) and Bouncy Castle RFC3280CertPathUtilities.java:794 (step k); BoringSSL crypto/x509/x509_vfy.cc:768-790 (cert_crl) revokes on any entry, so OpenSSL and Bouncy Castle, which agree, are followed.
- **Unit tests:** `a_crl_without_next_update_revokes_only_under_webpki_rules`, `a_crl_without_next_update_is_judged_by_its_other_defects`, `only_a_usable_covering_crl_clears_a_listing_without_next_update`, `a_crl_without_next_update_for_another_point_is_set_aside_if_admitted`, `a_crl_that_does_not_reencode_to_its_bytes_is_not_judged`.

### CRL-029: A definite result keeps its code with `--fetch-crls`

A definite revocation or CRL failure is the result, as without fetching, and is not followed by a check of the rest of the input. Both results reject. An unknown status is the exception, described in CRL-027.

- **Status:** Decided
- **Decided by:** written argument
- **Pins:** diagnostics
- **Sources:**
  - Without --fetch-crls, a chain whose paths all fail the path checks reports revocation first, as on main (crl-027-cross-unusable-crl-decides-beside-path-failing-key-usage); with --fetch-crls a definite CRL failure or revocation keeps that code. Only an unknown status, which is no evidence, is replaced by the path failure with fetching (crl-027-fetch-path-failing-key-usage-asks-nothing).
  - Only an unknown status that names nothing is followed by a check without revocation (crl-027-fetch-path-failing-key-usage-asks-nothing): it is no evidence, while these are.
  - Diagnostics only: both results reject.

### CRL-030: A partition for another point is no evidence

The certificate is without a CRL, so the status is `revocation_unknown` and retrieval fetches its own point.

- **Status:** Decided
- **Decided by:** references agree (OpenSSL, Bouncy Castle)
- **Pins:** diagnostics
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:2146-2198 (crl_crldp_check) and :1847-1853 (get_crl_score): a CRL whose issuingDistributionPoint does not match the certificate gets no CRL_SCORE_SCOPE and is not selected over a CRL that covers it.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/RFC3280CertPathUtilities.java:1678 (processCRLB2) with core PKIXCRLValidator.java:151-158 (checkDistributionPointName): a distribution point mismatch rejects the CRL before processCRLJ (:1703) reads entries.

### CRL-031: A revocation names another path's refreshable certificates

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

### CRL-032: A path a source could complete is reported over a stuck path

When no path is revoked, a viable path that only lacks, or has expired or replaceable, CRLs is reported ahead of a path whose CRL no refresh can fix; when every path is stuck, the most specific failure decides. Acceptance with `--fetch-crls` follows from CRL-022.

- **Status:** Decided
- **Decided by:** written argument (`docs/crl-retrieval.md`)
- **Pins:** diagnostics
- **Sources:**
  - Written argument in `docs/crl-retrieval.md`.
- **Unit test:** `a_path_a_source_could_complete_is_reported_over_a_stuck_paths_failure`.

## Tier 4: retrieval diagnostics

Diagnostics pins on which requests a source receives and how retrieval is reported.

### CRL-033: Retrieval asks per certificate, only about what lacks a CRL

Which requests are made. Each certificate the verifier reports without a usable CRL is asked about once in a verification, and no other certificate is. The engine reuses no earlier answer: a certificate whose issuer name, authority key and CA role, or whose points, another certificate's request already carried is still asked (what the request carries is CRL-050's). Answering a repeat without new work is the source's, as any reuse is the lookup callback's in OpenSSL; the built-in source's is CRL-051's.

- **Status:** Decided
- **Decided by:** references agree (OpenSSL, Bouncy Castle); the engine's issuer skip (a certificate with no new point, whose issuer, authority key and role were already asked about, was not asked) was removed by CRL-T041, leaving any reuse to the source (the built-in one reuses per-URL outcomes only, CRL-051); owner, PR #95 (approved)
- **Pins:** diagnostics
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:2206-2254 (get_crl_delta; lookup_crls at :2228) called from :1444-1537 (check_cert_crl): CRLs are looked up for the certificate being checked, by its issuer name, and only when the context holds none for it. The verifier keeps no record of earlier lookups: it calls the lookup for each certificate. Any reuse is the store's (CRLs a lookup method such as `by_dir` loaded stay in the `X509_STORE` the application owns) or the lookup callback's.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/RFC3280CertPathUtilities.java:1754-1880 (checkCRLs): CRLs are looked up per certificate, per distribution point.
- **Unit tests:** `a_source_is_asked_about_each_certificate_at_most_once_in_a_verification` and `every_certificate_is_asked_whatever_its_issuer_role_or_authority_key` in `engine/src/retrieval.rs`.
- **Note:** Asking about more certificates cannot weaken a result: a CRL a source returns counts only when verification authenticates it (CRL-048). A source without a cache gets one more call per certificate of an issuer already asked about, bounded by the certificates the verification budget allows; the built-in source does not count a call that fetches nothing (CRL-039).

### CRL-034: A source answering by certificate leaves no per-point failures

Only a body that loads as a CRL of the certificate's issuer counts as an answer by certificate; whether it is evidence is CRL-048's. When that answer settles the status, no per-point failure is recorded; when it does not, the listed points the source left unused are recorded as not used, so no listed point disappears from the report.

- **Status:** Decided
- **Decided by:** owner (delegated the call), PR #60; written argument for unused points; owner, PR #84 (approved): whether an answer is evidence moved to CRL-048
- **Pins:** diagnostics
- **Sources:**
  - OpenSSL crypto/x509/x509_lu.c:978-990 (X509_STORE_CTX_get1_crls): CRLs are looked up by issuer name, with no per-distribution-point outcome.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/CertPathValidatorUtilities.java:1100-1124 (getCompleteCRLs): the selector matches the issuer only.
  - OpenSSL crypto/x509/x509_lu.c:978-990 (X509_STORE_CTX_get1_crls) and Bouncy Castle CertPathValidatorUtilities.java:1100-1124 (getCompleteCRLs): CRLs are looked up by issuer, with no per-distribution-point outcome, so an answer by certificate leaves no per-point failure when it settles the status.
  - Written argument for the other case: when that answer does not settle the status, the report must still account for every listed point (docs/crl-retrieval.md: no listed point disappears from the report), so the points the source did not use are recorded as not used.

### CRL-035: A missing nextUpdate blocks retrieval only as a CRL's sole defect

A CRL whose only defect is a missing nextUpdate is not asked about: it is `invalid_crl` (`missing_next_update`, CRL-002) and no request follows. With another defect, that defect is reported and the CRL is replaceable (CRL-020).

- **Status:** Decided
- **Decided by:** owner, PR #64
- **Pins:** diagnostics
- **Sources:**
  - OpenSSL 3.3 crypto/x509/x509_vfy.c:1112 (check_crl_time) and BoringSSL crypto/x509/x509_vfy.cc:414 (check_crl_time) check nextUpdate only when present, so a CRL without it is time-valid, scores valid and no store lookup follows.
  - Bouncy Castle pkix/src/main/java/org/bouncycastle/pkix/jcajce/PKIXCRLUtil.java findCRLs keeps a CRL whose nextUpdate is null, so it is used and nothing is fetched for it.
  - What else makes a CRL replaceable is CRL-020's sources.

### CRL-036: Without an answer, an expired or replaceable CRL's error stands

Without an answer from the source, the CRL's own error stands. An expired CRL stays `crl_expired`. For a replaceable CRL (CRL-020, including a malformed one) the error stands and the certificate is named in `certificates_with_replaceable_crl`. Either error is marked `retrieval_aborted` after an abort, under the condition CRL-047 decides.

- **Status:** Decided
- **Decided by:** owner (delegated the call), PR #60 for an expired CRL; owner, PR #64 for a replaceable one; owner, PR #84 (approved): the mark's condition is CRL-047's
- **Pins:** diagnostics
- **Sources:**
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/PKIXCRLUtil.java:42-49 drops CRLs past nextUpdate; CertPathValidatorUtilities.java:571-630 and pkix X509RevocationChecker.java:477-492 then fetch from the certificate's distribution points when fetching is enabled.
  - OpenSSL crypto/x509/x509_vfy.c:2223-2231 (get_crl_delta): CRLs come from ctx->crls and the store lookup only; the verifier does not fetch.
  - A replaceable CRL is CRL-020's: the same references decide what is replaceable.

### CRL-037: The built-in source refuses what it does not fetch

The built-in `HttpCrlSource` is stricter than the references (public addresses, `http` only, no redirects, size and time bounds) and reports a refused URL as denied; `rssig::crl::check_public_http_url` gives a custom source the same check.

- **Status:** Decided
- **Decided by:** owner, PR #60
- **Pins:** diagnostics
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:2228: the verifier only calls lookup_crls; apps/lib/apps.c:2833 and :2905-2907 (get_dp_url, crls_http_cb): the scheme rule (http only) lives in the application callback.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/CrlCache.java:136-141 and :185-188: the fetch helper applies an optional scheme allow-list (unrestricted by default) and opens the URL.
  - BoringSSL crypto/x509/x509_vfy.cc:697-704 (get_crl): never fetches.

### CRL-038: A URI that is not an absolute URL is never offered to a source

It is recorded as `crl_fetch_denied` with its own message and no `url`.

- **Status:** Decided
- **Decided by:** references agree (OpenSSL, Bouncy Castle)
- **Pins:** diagnostics
- **Sources:**
  - OpenSSL `apps/lib/apps.c:2833`: `get_dp_url` returns only `http://`.
  - Bouncy Castle `CrlCache.java:185`: `toURL()` fails on a relative URI.
- **Unit test:** `a_uri_that_is_not_an_absolute_url_is_withheld_with_its_own_reason`.

### CRL-039: Fetch limits bound one verification

The engine renews a source's allowances for each verification (`CrlSource::begin_verification`). A DNS timeout still closes the built-in source for the invocation, keeping at most one unfinished resolver thread.

The engine keeps no total of requests to a source, and none of the distinct URIs it passes on: how often a source may be asked, and for how many URLs, in one verification is the source's decision, as the fetch limits are the application's in OpenSSL and the fetch helper's in Bouncy Castle. The built-in `HttpCrlSource` caps its requests at 64 per verification (`MAX_SOURCE_REQUESTS`, a call counted at the first point it fetches, even one its policy then refuses; a call with no point, or whose points are all answered from the verification's memory, is not counted) and its distinct URLs at 64 (`MAX_SOURCE_URLS`), and answers the first point it would fetch past either with an `Abort` carrying `details.resource` (`crl_requests` or `crl_source_urls`) with `limit`, `used` and `requested`; it fetches at most 16 points of a certificate per request (`MAX_POINTS_PER_REQUEST`), counting only points it does not answer from the verification's memory, and reports the others as `Denied` with `details.resource` `crl_request_points` and `requested` the request's distinct points it reached and would have fetched (not answered from memory), spending neither allowance; it returns at most 64 bodies in one response, the engine's `MAX_RESPONSE_ENTRIES`, and reports the points past them as `Denied` with `details.resource` `crl_response_entries`, so answers from memory cannot make the engine refuse the response; a custom source owns its own counts. The code is the kind's, `crl_fetch_aborted`, not `resource_limit_exceeded`: a source error takes its code from its kind. A cap now ends retrieval as CRL-047 describes (`revocation_unknown` or `crl_fetch_aborted`, never an acceptance), where the engine's `resource_limit_exceeded` once ended the run with no verdict.

The engine still enforces what bounds its own work and what no source can be trusted to bound, because the points and CRLs are the input's, not the source's: each body (8 MiB) and the bytes its store retains (32 MiB of roots and CRLs held after exact-DER deduplication, so a body that does not load, or repeats a CRL already held, adds nothing; before CRL-T041 the bytes of every body were counted; a certificate reached with none of it left is not asked, and its points are recorded as not tried with `retrieval_trust_bytes`, where the run used to end; supplied roots and CRLs over it leave every certificate unasked the same way, where the run used to end before the first verification), CRL bodies in one response (64), bodies and failures together (64 beside one per point offered), the CRLs retained (64), and the LIMIT-T002 work budget. Only the work budget ends the run; a response past either entry bound is not used and each point it was offered is recorded with `crl_response_entries`, and a body past the retained CRLs is not loaded and is recorded with `retrieval_crl_artifacts`; once the store holds 64 CRLs, a certificate is not asked and its points are recorded as not tried with that resource (LIMIT-T004). Requests to a source are bounded only indirectly: each certificate is asked about at most once, and the budget bounds the certificates (256 decoded, 4,096 report slots). The engine sets no time limit, so a source that fetches over a network must set its own.

- **Status:** Decided
- **Decided by:** references agree (neither OpenSSL nor Bouncy Castle lets one validation exhaust the next); owner, the pull request of CRL-T039 (the engine stops counting source requests); since CRL-T041 a call that fetches nothing is not counted, the request-cap abort answers the first point a call would fetch instead of failing the whole call, kept bodies are returned again up to `MAX_REPLAY_BYTES`, the retained-byte cap counts what the store holds, and a full store leaves a certificate unasked instead of ending the run; owner, PR #95 (approved); since LIMIT-T004 supplied evidence over the byte cap, a response past the entry bound and a body past the retained CRLs are recorded and the run goes on; this can accept an input the run used to end on; owner, PR #100 (approved 2026-11-27)
- **Pins:** diagnostics
- **Sources:**
  - OpenSSL `apps/lib/apps.c:2866-2867`, `apps/verify.c:220-232`: per-fetch limits, nothing accumulated. `crypto/x509/x509_vfy.c:2228`: the verifier only calls `lookup_crls`; limits live in the application callback.
  - Bouncy Castle `CrlCache.java:41-46`: per-connection timeouts, process-wide cache; its limits are in the fetch helper, not the path validator.
- **Unit tests:** `a_new_verification_restores_a_sources_allowances_but_a_dns_timeout_closes_it_for_good` and `the_built_in_source_aborts_after_its_request_cap_until_a_new_verification` in `src/crl.rs`; `a_source_with_no_cap_is_not_stopped_by_the_engine_on_request_or_url_count` and `re_offered_points_are_not_stopped_by_the_engine_on_request_count` in `engine/src/retrieval.rs`; `the_built_in_source_aborts_past_its_distinct_url_cap_until_a_new_verification` and `a_call_with_nothing_new_to_fetch_is_not_charged_and_repeats_the_earlier_answer` in `src/crl.rs`; `the_retained_bytes_count_what_the_store_holds_and_every_body_is_work` in `engine/src/retrieval.rs`.
- **Note:** Before CRL-T039 the engine stopped the run at 64 requests (`crl_requests`) or 64 distinct URIs (`crl_source_urls`) with `resource_limit_exceeded` for any source. No case pinned that result.

### CRL-040: A CRL naming a same-key root's identifier is forged, not set aside

Two configured roots with one key and name may carry different subjectKeyIdentifiers. A CRL signed by another key that names any of them is `invalid_crl_signature`; one naming an identifier no configured root carries is another issuer's and is set aside. Both reject; the libraries have no equivalent for two same-key anchors.

- **Status:** Observed
- **Decided by:** —
- **Pins:** diagnostics

### CRL-041: A CRL's issuer name matches by RFC 5280 name comparison

A CRL is a candidate for a certificate when its issuer name matches the certificate's issuer name as RFC 5280 section 7.1 compares names: the same attribute types in the same RDNs and order, and string values equal after lower-casing (each character's Unicode lowercase mapping, not the full RFC 3454 case folding, so `ß` and `ss` differ) and white-space compression, whether encoded as PrintableString, UTF8String, BMPString (UTF-16BE), TeletexString (read as Latin-1), VisibleString or IA5String. A CRL whose issuer spells the name in another of these string types, case or spacing is matched, and is authenticated like any other by its signature under the path's issuer key. Any other string type, and a malformed value (a BMPString of odd length or with a surrogate unit, a VisibleString with a byte outside 0x20 to 0x7e, a PrintableString outside its character set), compares by exact bytes. rssig applies none of RFC 4518's Unicode normalization (NFKC), map-to-nothing or prohibited-character steps, so it is stricter than the RFC there: such a CRL is not matched and the certificate's status is unknown.

- **Status:** Decided
- **Decided by:** owner, PR #79 and #82
- **Pins:** acceptance
- **Sources:**
  - RFC 5280 section 7.1 ([rfc/rfc5280.txt](rfc/rfc5280.txt)): "Conforming implementations MUST use the LDAP StringPrep profile (including insignificant space handling), as specified in [RFC4518], as the basis for comparison of distinguished name attributes encoded in either PrintableString or UTF8String."
  - RFC 5280 section 7.1: "Conforming implementations MUST support UTF8String and PrintableString." and "Implementations may encounter certificates and CRLs with names encoded using TeletexString, BMPString, or UniversalString, but support for these is OPTIONAL." RFC 4518 section 2.1 ([rfc/rfc4518.txt](rfc/rfc4518.txt)): "UniversalString, UTF8String, and bmpString [X.680] values need not be transcoded as they are Unicode-based strings" and "As there is no standard for mapping TeletexString values to Unicode, the mapping is left a local matter."
  - String types, OpenSSL 3.3 (7f736187): `crypto/x509/x_name.c:386-391` canonicalizes UTF8, BMP, Universal, Printable, T61, IA5 and Visible strings; `crypto/asn1/a_strex.c:299-319` reads a T61String as one byte per character and a BMPString as two, and `crypto/asn1/a_mbstr.c:215-240` (`traverse_string`) takes a one-byte string's bytes as code points, which is Latin-1. Bouncy Castle (bb81bfa7) `IETFUtils.java:472-476` and `564-601` compare the text `getString` returns, which is Latin-1 for `ASN1T61String.java:95-98` and UTF-16 units for `ASN1BMPString.java:100-113`, rejecting an odd length. Both references agree on BMPString, TeletexString and VisibleString as text, which rssig follows, except for a surrogate unit in a BMPString: OpenSSL (`a_utf8.c:114-115`, `UTF8_putc`) rejects it, so its canonical form fails, while Bouncy Castle keeps the UTF-16 units and would match a valid pair to the same text in a UTF8String; X.680's BMPString has no surrogates, so rssig takes OpenSSL's reading and compares such a value by exact bytes, though the JSON report (`engine/src/report.rs`) still shows a valid pair as text; RFC 4518 leaves the TeletexString mapping local, and a real T.61 string is not always Latin-1.
  - Not followed: neither reference applies NFKC, map-to-nothing or the prohibited-character check (OpenSSL `x_name.c:414-460` copies every non-ASCII byte as it is; Bouncy Castle `canonicalize` only lower-cases and strips spaces). rssig leaves them out too: they need Unicode tables, a new dependency of the verifier core (`icu_normalizer` is in the tree only through `url` for `--fetch-crls`), and a name they would have matched stays unmatched, which fails closed. NumericString compares by exact bytes: OpenSSL copies it as it is, where Bouncy Castle reads it as text, so the references disagree and rssig takes the stricter reading. UniversalString is not supported at all: `der` 0.7 has no tag for it, so a name that carries one does not decode.
  - OpenSSL 3.3 (7f736187) `crypto/x509/x509_cmp.c:253-285` (`X509_NAME_cmp` compares the canonical encoding) and `crypto/x509/x_name.c:300-308` (UTF-8, lower case, white space collapsed); BoringSSL (289645a4) `crypto/x509/x509_cmp.cc:117-143` and `x_name.cc:45-100`; Bouncy Castle (bb81bfa7) `X500Name.java:265-290` (`equals`, then the style's `areEqual`). All three match names canonically, but OpenSSL (`x_name.c:414-460`) and BoringSSL lower-case and collapse spaces only for ASCII and copy any other byte as it is, while RFC 5280 and Bouncy Castle fold Unicode text. rssig follows the RFC, so a name that differs only in the case of a non-ASCII letter (`Zoë` and `ZOË`) matches in rssig and Bouncy Castle but not in OpenSSL or BoringSSL.
- **Unit tests:** `names_match_as_rfc_5280_compares_them` and `a_prepared_name_compares_alike_every_time` in `engine/src/trust/names.rs`.
- **Note:** A name is read literally, so UTF-8 bytes in a TeletexString (a common CA mistake) read as Latin-1 text that matches nothing, and a supplementary character cannot be written in a BMPString (UCS-2 has none, and a surrogate unit is malformed): such a CRL is not matched, which fails closed. A TeletexString read as Latin-1 departs from real T.61, which differs from Latin-1 in a few code points and writes accents as combining escapes, so a Teletex issuer can match a name its CA did not mean; the references do the same, RFC 4518 leaves the mapping local, and the match only selects a candidate CRL, which its signature then authenticates. Before this entry rssig compared exact DER, so such a CRL was ignored and the certificate was `revocation_unknown`; webpki still requires a certificate's issuer to equal its issuer's subject byte for byte when it builds the path. CRL-008's rule for issuers of one name with different keys compares the names of the issuers on the path as webpki built it (exact bytes), not the CRLs' issuer fields, so a CRL cannot escape that rule by spelling its issuer differently (`crl-008-self-issued-rollover-with-a-differently-encoded-crl-is-rejected`); two issuers whose names differ only in case are two to it, as to webpki, where OpenSSL would treat them as one. Retrieval also uses exact bytes: a fetched CRL counts as an issuer's answer only when its issuer is the certificate's issuer byte for byte, since one equal only under this comparison may be another CA's, which verification sets aside. CRL-T035 tracks the first and CRL-T034 the second. A CRL whose issuer equals the certificate's only under this comparison, whose authorityKeyIdentifier does not claim the issuer (by its key identifier or by its certificate's issuer and serial), and that fails under the issuer's key or cannot be verified, is another CA's and is set aside, as one naming another key is, not forged or unsupported; one that claims the issuer, including by a key identifier the issuer cannot disprove (CRL-042), is judged like an exactly named CRL (`crl-041-forged-crl-naming-the-issuers-key-stays-forged`). A set-aside one neither names a forged CRL in the result nor stops retrieval (CRL-018), as before this entry, when it was ignored (`crl-041-forged-crl-matching-only-by-comparison-is-set-aside`).

### CRL-042: An issuer without a usable key identifier cannot disprove another key's CRL

A CRL whose issuer is spelled as the certificate's issuer and that is signed by another key is set aside as another issuer's only when its authorityKeyIdentifier names a key identifier and the issuer's certificate carries a parseable subjectKeyIdentifier that differs, or names another certificate (CRL-043); one spelled differently is CRL-041's. An issuer certificate with no subjectKeyIdentifier, or a configured root whose subjectKeyIdentifier does not parse (in a path certificate it fails the path, PATH-013), cannot disprove the match: the CRL is forged (`invalid_crl_signature`). Both outcomes reject.

- **Status:** Decided
- **Decided by:** owner, PR #79; narrowed to configured roots with PATH-013, PR #97
- **Pins:** diagnostics
- **Sources:**
  - OpenSSL 3.3 (7f736187) `crypto/x509/v3_purp.c:1007` (`X509_check_akid` compares key identifiers only when the issuer has one, so the check passes) and `crypto/x509/x509_vfy.c:1676` (a signature that then fails is `CRL_SIGNATURE_FAILURE`); BoringSSL (289645a4) `v3_purp.cc:453-460`, `x509_vfy.cc:491-499`. Both agree with rssig.
  - Bouncy Castle (bb81bfa7) `RFC3280CertPathUtilities.java:382-391` narrows candidate certificates by subjectKeyIdentifier and skips a CRL that fails to verify, then tries the next: it differs.
  - A subjectKeyIdentifier that does not parse: OpenSSL (`v3_purp.c:550-552`) and BoringSSL (`v3_purp.cc:371-375`) mark the certificate invalid, which fails the path. So does rssig for a path certificate (PATH-013), so only a configured root, which is a key (PATH-011), reads as having none here.
- **Unit tests:** `only_a_differing_key_identifier_sets_a_failed_crl_aside` in `engine/src/trust.rs`.
- **Note:** The owner kept rssig's rule, which OpenSSL and BoringSSL share: a CRL that cannot be shown to be another key's and fails its signature is forged, the fail-closed reading. Bouncy Castle's skip-and-try-the-next is looser.

### CRL-043: A CRL naming another certificate by issuer and serial is set aside when its signature fails

An authorityKeyIdentifier with authorityCertIssuer and authorityCertSerialNumber names the CRL signer's certificate. A CRL whose signature fails under the path's issuer key and whose authorityKeyIdentifier names no key identifier but another certificate (an issuer name, compared as in CRL-041, together with a serial that are not those of the issuer's certificate or of any configured root with the same key, name and constraints) is another certificate's CRL and is set aside, as one naming another key identifier is. RFC 5280 requires the two fields together, so an extension with only one names no certificate and is not judged; nor is one whose authorityCertIssuer holds no directoryName (only a URI or DNS name, say), which rssig cannot compare with a certificate's issuer. Such a CRL stays forged. A CRL that verifies is CRL-044's.

- **Status:** Decided
- **Decided by:** owner, PR #79
- **Pins:** diagnostics
- **Sources:**
  - RFC 5280 sections 4.2.1.1 and 5.2.1 ([rfc/rfc5280.txt](rfc/rfc5280.txt)): the extension "provides a means of identifying the public key corresponding to the private key used to sign a CRL", "based on either the key identifier ... or the issuer name and serial number", and "Conforming CRL issuers MUST use the key identifier method". It identifies a key, and one key can be certified more than once, so another serial alone does not show another key.
  - OpenSSL 3.3 (7f736187) `v3_purp.c:1009-1032` compares the serial and the issuer name and returns `AKID_ISSUER_SERIAL_MISMATCH`, which excludes the CRL before its signature is read (`x509_vfy.c:1322-1326`); BoringSSL (289645a4) `v3_purp.cc:464-482`, `x509_vfy.cc:653-656`. They exclude a CRL that would verify; rssig does not.
  - Bouncy Castle (bb81bfa7) `RFC3280CertPathUtilities.java:382-386` reads only the key identifier.
- **Note:** Before this entry a CRL that failed under the issuer's key and named another serial or issuer was forged, and the result was `invalid_crl_signature`; now it is set aside and the certificate's status is unknown unless another CRL decides. Both reject. The owner kept the signature as the authority rather than follow OpenSSL and BoringSSL, which would drop a CRL that verifies; and kept no diagnostic for a CRL set aside this way, as none is left for one naming another key identifier.

### CRL-044: A CRL that verifies is used whatever its authorityKeyIdentifier names by issuer and serial

A CRL whose signature verifies under the path's issuer key is authenticated by that signature, and is used even when its authorityKeyIdentifier names another certificate by issuer and serial. OpenSSL and BoringSSL exclude such a CRL before reading its signature, which would reject a valid file.

- **Status:** Decided
- **Decided by:** owner, PR #79
- **Pins:** acceptance
- **Sources:**
  - RFC 5280 sections 4.2.1.1 and 5.2.1 ([rfc/rfc5280.txt](rfc/rfc5280.txt)): the extension identifies the public key that signed the CRL, by key identifier or by the issuer name and serial of a certificate for it; one key can be certified more than once, so another certificate named is not another key.
  - OpenSSL 3.3 (7f736187) `v3_purp.c:1009-1032` and `x509_vfy.c:1322-1326`, BoringSSL (289645a4) `v3_purp.cc:464-482` and `x509_vfy.cc:653-656`: excluded on a mismatch; Bouncy Castle (bb81bfa7) `RFC3280CertPathUtilities.java:382-386` reads only the key identifier and uses it.
- **Note:** The owner chose the signature as the authority over OpenSSL and BoringSSL's exclusion.

### CRL-045: A retrieved CRL over the size cap is never evidence

A body a source returns that is over 8 MiB, or that takes the response past the request's allowance, is not decoded or loaded. It is no answer for the certificate, so the result rests on the other evidence (CRL-026 when there is none). It does not count against the bodies after it, so a good body that follows in the same response still answers. How it is reported is CRL-046.

- **Status:** Observed
- **Decided by:** —
- **Pins:** acceptance
- **Sources:**
  - OpenSSL 3.3 (7f736187) caps a downloaded CRL at 32 MiB: `include/openssl/http.h:39` (`OSSL_HTTP_DEFAULT_MAX_CRL_LEN`), applied at `crypto/x509/x_all.c:102`, and a longer response fails at `crypto/http/http_client.c:507-512` (`HTTP_R_MAX_RESP_LEN_EXCEEDED`), so no CRL is obtained.
  - Bouncy Castle (bb81bfa7) `CrlCache.java:185-192` sets connect and read timeouts and parses the whole stream (`generateCRLs`), with no size limit.
  - The references differ. rssig's number, observed and not yet decided: a fetched CRL may be as large as a supplied one, 8 MiB ([host-limits.md](host-limits.md), "Each root/CRL source file"), and the 32 MiB a verification may take in all is [crl-retrieval.md](crl-retrieval.md)'s limits table. Either way an over-cap body is never evidence, which fails closed.
- **Unit tests:** `an_oversized_body_does_not_count_against_the_bodies_after_it` and `fetch_each_tries_the_next_point_after_an_over_allowance_body` in `engine/src/retrieval.rs`.
- **Note:** A source fetching by URL (`fetch_each`) is held to both caps by its unit test, since a case cannot give the built-in source a real response.

### CRL-046: A retrieved CRL over the size cap is reported with the cap it hit

A body skipped under CRL-045 is reported in `crl_retrieval.failures` as `resource_limit_exceeded`, with `resource` `crl_response_bytes`, the cap it hit (`limit`), its own size (`requested`) and `used`: 0 for the 8 MiB a body may have, and the bytes the response had already taken for the request's allowance. When the body names no URL (offered by certificate or issuer), the listed point it was meant to answer is recorded as `crl_fetch_failed`, the source having returned nothing usable for it (CRL-026), unless the bodies the response had accepted in all, before or after it, spent the request's whole allowance, when the point is recorded as not tried for that reason (`resource_limit_exceeded`, `points_left_when_the_byte_allowance_is_spent_are_not_tried` in `engine/src/retrieval.rs`). The rest of the response can change that, by the entries that decide it: a failure naming no URL answers the point (CRL-026), an abort leaves it not tried (CRL-047), and another body answering by certificate leaves it unused (CRL-034); the over-cap body itself, never loaded, is no answer by certificate. The same holds without an over-cap body: when the bodies a response had accepted spent the request's whole allowance, each point it left unanswered is recorded as not tried; short of it, the point is CRL-026's (`crl-046-a-spent-byte-allowance-leaves-the-point-not-tried` and `crl-046-a-byte-short-of-the-allowance-leaves-the-point-failed`, on an input listing one point; several points left, `points_left_when_the_byte_allowance_is_spent_are_not_tried` in `engine/src/retrieval.rs`). A body naming its point answers that point, so no second failure is recorded for it (`an_oversized_body_naming_its_point_is_its_only_failure` in `engine/src/retrieval.rs`). The built-in URL source passes on only the first over-cap body of a request; it reports each later one itself as a `failed` source error with the same `resource`, `limit` and `requested`, which the report records as `crl_fetch_failed` (`fetch_each_tries_the_next_point_after_an_over_allowance_body` in `engine/src/retrieval.rs`).

- **Status:** Observed
- **Decided by:** —
- **Pins:** diagnostics
- **Sources:**
  - [crl-retrieval.md](crl-retrieval.md): the limits table, and no listed point disappears from the report (CRL-034's written argument).
- **Unit tests:** `an_over_allowance_body_reports_the_cap_it_hit`, `an_oversized_body_naming_its_point_is_its_only_failure` and `points_left_when_the_byte_allowance_is_spent_are_not_tried` in `engine/src/retrieval.rs`; the named test `crl_fetch_by_certificate_a_body_over_the_size_cap_is_rejected_and_leaves_the_point_unanswered` in `tests/cli/crl_fetch.rs`.

### CRL-047: An aborted source stops retrieval and is reported as `crl_fetch_aborted`

A source that reports `abort` (its budget spent, a deadline passed, or cancelled), as a failure or for the whole request, is asked nothing more in this verification. In the request it cut short, a point the abort itself answers carries it (`source_error` `abort`). An abort naming no URL marks every other point left as not tried (`points_not_tried_after_an_abort_stay_in_the_report`, `points_left_after_an_abort_among_url_less_failures_are_not_tried`); one naming a point leaves the others to the response's other failures (`an_abort_naming_one_point_does_not_relabel_the_others`), and only those still unanswered are not tried; a certificate after it is never asked, so its points are not recorded (`abort_stops_every_further_request`). When that left a certificate still without a CRL unasked, or cut its request short, the result is `crl_fetch_aborted` instead of `revocation_unknown`, with the verifier's message kept in the `revocation_unknown` detail and the same `crl_retrieval.failures`. An abort after every such certificate was asked, none of them in the request it cut short, leaves CRL-026's `revocation_unknown`. A definite result keeps its code (CRL-029), and is marked `retrieval_aborted` (CRL-036) only when the abort cut retrieval short in the same way for a certificate the result names.

- **Status:** Decided
- **Decided by:** owner (delegated the call), PR #84
- **Pins:** diagnostics
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:1489 and :1527 (check_cert_crl) and Bouncy Castle CertPathValidatorUtilities.java:1340 report a single error however a CRL could not be obtained (CRL-026); neither has a source that can give up, so this departs from both.
  - Written argument: an aborted source left evidence unasked, so a caller may retry, where `revocation_unknown` says the evidence was sought and is missing. Both reject, so the difference is diagnostics only. [crl-retrieval.md](crl-retrieval.md) describes the result.
- **Unit tests:** `the_first_of_two_aborts_without_a_url_answers_the_points`, `the_result_tells_an_aborted_source_from_missing_evidence`, `abort_stops_every_further_request` and `points_not_tried_after_an_abort_stay_in_the_report` in `engine/src/retrieval.rs`; the abort rows of the named test `crl_fetch_by_certificate_failures_are_serialized_for_the_listed_point` in `tests/cli/crl_fetch.rs`; the named test `crl_fetch_an_abort_beside_a_revoking_crl_leaves_the_result_unmarked` in `tests/cli/crl_fetch.rs`.

### CRL-048: A CRL from a source is evidence only when verification authenticates it

A source is never trusted: where a CRL came from adds nothing to it. Whatever a source returns, by URL or by certificate, is judged exactly as a supplied CRL is, by the entries that decide a supplied CRL (CRL-001 and CRL-003 among them), and earns no standing from being returned. This entry pins only that point; the rules it defers to keep their own entries.

- **Status:** Decided
- **Decided by:** owner (delegated the call), PR #84; references agree
- **Pins:** acceptance
- **Sources:**
  - OpenSSL `crypto/x509/x509_vfy.c` `check_crl` verifies every CRL that `get_crl` or `lookup_crls` returned before `cert_crl` reads its entries; Bouncy Castle `RFC3280CertPathUtilities` processCRLG verifies every CRL its stores returned before processCRLJ. Neither trusts where a CRL came from.
  - [crl-retrieval.md](crl-retrieval.md): "A source never returns a trust verdict."
- **Unit tests:** the named test `crl_fetch_by_certificate_a_body_that_is_not_a_crl_leaves_the_point_unanswered` in `tests/cli/crl_fetch.rs`. A source's CRLs join the supplied ones before verification, so no branch trusts them apart and no unit test isolates one.
- **Note:** This entry overlaps CRL-001 and CRL-003 by design, as the owner decided in PR #84: it pins that a source adds no standing, and they keep deciding what a CRL must satisfy.
- **Note:** Whether a returned body counts as the source's answer by certificate (CRL-034) only decides what is asked and reported next. Removing that rule changes no verification result (checked by changing the engine: every case and named test still passed, and only CRL-034's unit test `only_a_real_crl_without_a_url_answers_by_certificate` failed), because the entries this one defers to decide acceptance.

### CRL-049: Retrieval failures are reported in a fixed order

`crl_retrieval.failures` lists the points that yielded no evidence grouped by the certificate they were asked for, in request order. Within a request: points refused before asking, the source's own failures in response order, bodies rejected on load, then the points it did not answer (after an abort, the points not tried). The first failure naming no URL is held while a listed point is still unanswered, since it may answer those points: it comes after the bodies rejected on load, recorded for each point left or, when it answers none, as it is. A whole-request error naming a listed point is recorded for every other point, in listed order, then for that one; naming no listed point (a URL outside the request counts as none), for every point in listed order, or once, without a URL, when the request lists none. Last, for a failed retrieval, come the points a source answering by certificate left unused, in the order those certificates were asked about.

- **Status:** Observed
- **Decided by:** —
- **Pins:** diagnostics
- **Sources:**
  - Written argument: the references report one error and keep no list of failed points, so they have no order to follow. The report follows what happened, so a reader can replay retrieval from it without sorting: a certificate's points in the order it was asked about; within a request, what was refused before asking, then what the source said in the order it said it, then what loading its bodies showed, then what was left. A failure naming no URL is the one exception because its meaning is not known when it arrives: whether it answers the points left depends on the bodies, so it is placed where that is known. A whole-request error names one point at most; the others come first, in listed order, so the point it names is last and its own entry ends the request. The same order is documented on `CrlRetrievalReport::failures` (`engine/src/domain.rs`).
- **Unit tests:** `a_whole_request_error_naming_a_foreign_url_is_not_attributed_to_the_certificate`, `a_whole_request_error_records_the_point_it_names_last`, `the_first_failure_without_a_url_comes_after_the_bodies_rejected_on_load` and `a_failure_without_a_url_is_recorded_as_it_is_when_every_point_was_named` in `engine/src/retrieval.rs`; the named tests `crl_fetch_by_certificate_a_body_that_is_not_a_crl_leaves_the_point_unanswered` and `crl_fetch_by_certificate_a_body_over_the_size_cap_is_rejected_and_leaves_the_point_unanswered` in `tests/cli/crl_fetch.rs`.

### CRL-050: Each request carries every point the certificate lists, whatever was asked before

Within CRL-033's choice of certificates, the request for a certificate carries every point it lists (each once, compared after normalization; however many, CRL-024), including a point another certificate's request carried, whether the source used it, left it unused (CRL-034) or failed it, and whatever issuer, authority key or role was asked about before. CRLs are per issuer, so another issuer's answer is not this certificate's, and fetching can still complete its path.

- **Status:** Observed
- **Decided by:** —
- **Pins:** acceptance
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:2206-2254 (get_crl_delta; lookup_crls at :2228), called from :1444-1537 (check_cert_crl): CRLs are looked up for each certificate being checked, by its issuer name.
  - Bouncy Castle (bb81bfa7) pkix/src/main/java/org/bouncycastle/pkix/jcajce/X509RevocationChecker.java:486-487 and :596-669 (downloadCRLs): each certificate's own listed points are read and their CRLs selected by that certificate's issuer, so a point two certificates list is consulted for each.
  - Written argument: the engine judges evidence; remembering what a point yielded is a cache of fetches, which is the source's by OpenSSL's boundary (CRL-033). Leaving a point out because another certificate's request carried it would leave this certificate `revocation_unknown` whenever the source could still answer it.
- **Unit tests:** `every_certificate_of_one_issuer_is_offered_to_the_source_with_its_points`, `points_unused_by_an_answer_by_certificate_are_offered_again` and `uris_are_deduplicated_per_certificate_and_screened_for_hygiene` in `engine/src/retrieval.rs`.
- **Note:** Before CRL-T041 a point a source had used (by a body or a failure) was not offered again, and a certificate with no point left whose issuer, authority key and role were already asked about was not asked; this entry then pinned only that a certificate of an issuer not yet asked about was asked.

### CRL-051: Each certificate records what its own request yielded; reuse is the source's

A point's outcome is recorded under each certificate from what the source answered in that certificate's own request; the engine replays no earlier outcome. A source that answers a repeated point from its own memory reports it again, and it is recorded again, so each certificate's report accounts for every point it lists. A point a source answering by certificate left unused is reported as not used for the certificate it was left for (CRL-034). The built-in `HttpCrlSource` keeps each URL's outcome (compared after normalization) for one verification, except an abort: a repeat returns the same body or failure without an HTTP request or a distinct-URL slot, and a call carrying nothing new is not counted (CRL-039). A repeated body is listed as an artifact for each certificate it was returned for, and decoded, hashed and charged to the work budget each time: the engine remembers no body, so what a repeat costs is the source's to bound. The store holds its CRL once, so it adds nothing to the retained bytes (CRL-039). The built-in source returns at most 16 MiB of kept bodies again per verification (`MAX_REPLAY_BYTES`) and reports a point past that as `Denied` with `details.resource` `crl_replay_bytes`, which with its 32 MiB of network bytes keeps the bodies the engine processes within 48 MiB, inside the decode budget (512 MiB, a body charged eight times); sharing bodies is CRL-T046. A replay counts against its request's byte allowance like any body (the built-in source refuses one over the room left as a fetch would, without copying it), so near the 32 MiB cap one can be refused as `crl_response_bytes` though the store holds it (`a_replayed_body_counts_against_the_requests_allowance`): the allowance is one rule for the engine and every source. The source keeps no abort; a size failure under a request's allowance smaller than the per-body cap (`crl_response_bytes`) is kept with that allowance, so a request with no more room gets it again, reporting its own room, and one with more fetches again. Where the failures sit in the report is CRL-049's.

- **Status:** Observed
- **Decided by:** —
- **Pins:** diagnostics
- **Sources:**
  - Bouncy Castle (bb81bfa7) pkix/src/main/java/org/bouncycastle/pkix/jcajce/CrlCache.java:43-44, :53-61 and :110: the CRLs fetched from a point are cached by URI, in the fetch helper rather than the path validator, and served to a later certificate listing it, without fetching again. A fetch that fails throws before :110 and is not cached, so Bouncy Castle tries the point again for the next certificate; the built-in source does not.
  - OpenSSL crypto/x509/x509_lu.c:978-990 (X509_STORE_CTX_get1_crls): CRLs are looked up by issuer name with no per-point outcome, so OpenSSL has nothing to compare with the per-point report. Reuse is the store's and its lookup method's, never the verifier's; the command-line tool's download callback (apps/lib/apps.c:2905-2907, crls_http_cb, as CRL-037 cites) fetches for the current certificate on each call and keeps nothing, so it fetches a point two certificates list twice. The built-in source departs from that, as Bouncy Castle's cache does.
  - Written argument: each fetch costs the built-in source a request, which only the source bounds (CRL-039), and a point that just failed is fetched again only to fail the same way within one verification; the outcome is the point's, whichever certificate listed it, so it is returned for each. Not retrying can only turn a good result into `revocation_unknown` (fail closed), never the reverse; a custom source decides its own reuse.
- **Unit tests:** `a_point_one_certificates_answer_left_unused_is_reported_as_not_used`, `a_failure_under_an_unhygienic_spelling_is_recorded_for_each_certificate_without_its_url` and `the_retained_bytes_count_what_the_store_holds_and_every_body_is_work` in `engine/src/retrieval.rs`; `a_call_with_nothing_new_to_fetch_is_not_charged_and_repeats_the_earlier_answer` in `src/crl.rs`.
- **Note:** Before CRL-T041 the engine kept each point's outcome (`Retrieval::asked`), left a used point out of later requests and recorded its failure again itself.

## Candidate rules

Unnumbered. `tests/decision-claims.json` assigns these cases here until they name an entry.

- `attach`: cases that pin an existing CRL entry but do not name it yet: the remaining CRL-T001 audit cases and every format's revocation, CRL-freshness and forged-CRL cases.
