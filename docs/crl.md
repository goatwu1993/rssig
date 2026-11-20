# CRL decisions

Numbered index of the decisions behind rssig's CRL and revocation behavior.
Each entry states the rule once, whether it is **Decided** or **Observed**,
whether it pins **acceptance** (verifies or rejects) or only **diagnostics**
(which code, detail or request), its sources, and the cases that pin it.

The rules for pinned expectations are in
[AGENTS.md](../AGENTS.md#pinned-expectations). The history and review
discussion behind these entries is in
[SEC-10](tasks/sec-10-crl-applicability.md) and
[SEC-24](tasks/sec-24-single-revocation-authority.md); this file does not
repeat it.

## How IDs work

- An ID is `CRL-` and a three-digit number. It is never reused or
  renumbered. A dropped decision stays here, marked **Retired**, with one line
  saying why.
- A Decided entry's rule changes only with the repository owner's approval,
  recorded in the PR; the ID stays the same and git history keeps the earlier
  text.
- Reference line numbers are for OpenSSL 3a3f1356 (3.3 where an entry says
  so), bc-java e03fee0b, relic 02c54d58, BoringSSL `main` (commit not
  captured) and webpki 0.103.16, unless the entry says otherwise.
- **Migration status:** cases in `tests/cases.json` still carry their own
  `decision` blocks with `reason` pointing at the SEC-10 document. The case
  lists below were generated from those blocks; a case appears under exactly
  one ID. Entries marked "no spec case" are pinned by unit or named tests
  only.

## Index

| ID | Decision | Basis | Pins |
|---|---|---|---|
| [CRL-001](#crl-001-the-best-usable-crl-decides) | The best usable CRL decides | Decided | acceptance |
| [CRL-002](#crl-002-a-listing-counts-only-from-a-current-crl-and-the-newest-decides) | A listing counts only from a current CRL, and the newest decides | Decided | acceptance |
| [CRL-003](#crl-003-a-crl-without-nextupdate-is-current-for-a-listing) | A CRL without nextUpdate is current for a listing | Decided | acceptance, diagnostics |
| [CRL-004](#crl-004-a-crl-without-nextupdate-is-not-evidence-of-good-status) | A CRL without nextUpdate is not evidence of good status | Decided | acceptance |
| [CRL-005](#crl-005-a-listing-in-a-current-crl-with-a-malformed-aki-counts-beside-a-usable-crl) | A listing in a current CRL with a malformed AKI counts beside a usable CRL | Decided | acceptance |
| [CRL-006](#crl-006-a-listing-in-a-crl-whose-signature-cannot-be-verified-never-counts) | A listing in a CRL whose signature cannot be verified never counts | Decided | acceptance |
| [CRL-007](#crl-007-a-crl-that-does-not-apply-is-excluded-one-that-applies-must-be-usable) | A CRL that does not apply is excluded; one that applies must be usable | Decided | acceptance |
| [CRL-008](#crl-008-a-full-crl-is-in-scope-for-any-certificate) | A full CRL is in scope for any certificate | Decided | acceptance |
| [CRL-009](#crl-009-a-revocation-in-a-crl-that-does-not-cover-the-certificate-does-not-count) | A revocation in a CRL that does not cover the certificate does not count | Decided | acceptance |
| [CRL-010](#crl-010-a-partition-for-another-point-is-no-evidence) | A partition for another point is no evidence | Decided | diagnostics |
| [CRL-011](#crl-011-a-role-only-partition-counts-for-its-role) | A role-only partition counts for its role | Decided, Observed | acceptance |
| [CRL-012](#crl-012-a-point-scoped-crl-for-a-certificate-that-lists-no-points-is-rejected) | A point-scoped CRL for a certificate that lists no points is rejected | Decided | acceptance |
| [CRL-013](#crl-013-a-listings-scope-needs-a-positive-match) | A listing's scope needs a positive match | Decided | acceptance |
| [CRL-014](#crl-014-configured-anchors-are-keys) | Configured anchors are keys | Decided | acceptance |
| [CRL-015](#crl-015-on-a-key-rollover-path-each-certificate-uses-its-own-keys-crl) | On a key-rollover path each certificate uses its own key's CRL | Decided | acceptance |
| [CRL-016](#crl-016-a-rollover-path-with-crls-that-name-no-key-is-rejected) | A rollover path with CRLs that name no key is rejected | Decided | acceptance |
| [CRL-017](#crl-017-a-crl-naming-a-same-key-roots-identifier-is-forged-not-set-aside) | A CRL naming a same-key root's identifier is forged, not set aside | Observed | diagnostics |
| [CRL-018](#crl-018-a-path-that-verifies-with-its-crls-is-accepted-whatever-another-path-does) | A path that verifies with its CRLs is accepted whatever another path does | Decided | acceptance |
| [CRL-019](#crl-019-which-error-a-rejected-chain-reports) | Which error a rejected chain reports | Decided | diagnostics |
| [CRL-020](#crl-020-a-revocation-names-another-paths-refreshable-certificates) | A revocation names another path's refreshable certificates | Decided | acceptance, diagnostics |
| [CRL-021](#crl-021-a-path-a-source-could-complete-is-reported-over-a-stuck-path) | A path a source could complete is reported over a stuck path | Decided | acceptance, diagnostics |
| [CRL-022](#crl-022-lifetime-signing-validity-outranks-revocation-on-another-path) | Lifetime-signing validity outranks revocation on another path | Decided | diagnostics |
| [CRL-023](#crl-023-an-rdp-signer-lacking-only-a-crl-under-one-usage-reports-the-missing-crl) | An RDP signer lacking only a CRL under one usage reports the missing CRL | Decided | acceptance, diagnostics |
| [CRL-024](#crl-024-a-revoked-rdp-usage-is-reported-over-another-usages-failure) | A revoked RDP usage is reported over another usage's failure | Decided | diagnostics |
| [CRL-025](#crl-025-nothing-is-fetched-for-an-input-that-cannot-verify) | Nothing is fetched for an input that cannot verify | Decided | acceptance |
| [CRL-026](#crl-026-a-definite-result-keeps-its-code-with---fetch-crls) | A definite result keeps its code with `--fetch-crls` | Decided | diagnostics |
| [CRL-027](#crl-027-retrieval-asks-per-certificate-only-about-what-lacks-a-crl) | Retrieval asks per certificate, only about what lacks a CRL | Decided | diagnostics |
| [CRL-028](#crl-028-missing-evidence-is-revocation_unknown-a-source-has-four-outcome-kinds) | Missing evidence is `revocation_unknown`; a source has four outcome kinds | Decided | diagnostics |
| [CRL-029](#crl-029-a-source-answering-by-certificate-leaves-no-per-point-failures) | A source answering by certificate leaves no per-point failures | Decided | diagnostics |
| [CRL-030](#crl-030-an-expired-supplied-crl-is-refreshed) | An expired supplied CRL is refreshed | Decided | acceptance, diagnostics |
| [CRL-031](#crl-031-a-supplied-crl-the-references-would-look-past-is-refreshed) | A supplied CRL the references would look past is refreshed | Decided | acceptance, diagnostics |
| [CRL-032](#crl-032-a-crl-with-a-bad-signature-is-not-refreshed) | A CRL with a bad signature is not refreshed | Decided | acceptance |
| [CRL-033](#crl-033-a-malformed-crl-is-replaceable) | A malformed CRL is replaceable | Decided | acceptance, diagnostics |
| [CRL-034](#crl-034-a-missing-nextupdate-blocks-retrieval-only-as-a-crls-sole-defect) | A missing nextUpdate blocks retrieval only as a CRL's sole defect | Decided | acceptance, diagnostics |
| [CRL-035](#crl-035-a-point-scoped-crl-for-a-certificate-that-lists-no-points-is-replaced-by-certificate) | A point-scoped CRL for a certificate that lists no points is replaced by certificate | Decided | acceptance |
| [CRL-036](#crl-036-the-source-decides-transport-the-core-screens-hygiene-only) | The source decides transport; the core screens hygiene only | Decided | acceptance, diagnostics |
| [CRL-037](#crl-037-fetch-limits-bound-one-verification) | Fetch limits bound one verification | Decided | diagnostics |
| [CRL-038](#crl-038-one-certificates-distribution-points-never-end-the-run) | One certificate's distribution points never end the run | Decided | acceptance |
| [CRL-039](#crl-039-a-uri-that-is-not-an-absolute-url-is-never-offered-to-a-source) | A URI that is not an absolute URL is never offered to a source | Decided | diagnostics |

## Choosing among CRLs

### CRL-001: The best usable CRL decides

An unusable CRL of the issuer is set aside when another CRL of that issuer is
usable; alone, it keeps its own exact error. Revocation is evaluated per
certificate on each candidate path.

- **Basis:** Decided, acceptance. Owner-approved one-time exception to the
  pinned-expectation rule (PR #60): the earlier failures beside `good.crl`
  became verifications; each failure is still pinned with the bad CRL alone.
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:1592-1633 (get_crl_sk) and :1801-1861 (get_crl_score): CRLs of the issuer are scored (CRL_SCORE_TIME, CRL_SCORE_SCOPE, CRL_SCORE_NOCRITICAL) and the best one is used; :2257-2320 (check_crl) reports the best CRL's own defect when no better one exists.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/RFC3280CertPathUtilities.java:1586-1721 (checkCRL): a CRL that fails a check is skipped (lastException, :1718) and the next is tried; its error is thrown only when no CRL was valid (:1721).
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/RFC3280CertPathUtilities.java:1716-1718 (checkCRL): a CRL that fails a check is skipped (lastException) and the next CRL is tried.
  - OpenSSL crypto/x509/x509_vfy.c:1603-1633 (get_crl_sk): candidate CRLs are scored and the best is used.
- **Cases:** `sec10-root-crl-no-next-update` (acceptance), `sec10-root-expired-crl-still-rejected` (acceptance), `sec10-root-aki-crl-still-rejected` (acceptance), `sec10-root-crl-malformed-aki` (acceptance), `sec10-root-signed-other-aki-crl-still-rejected` (acceptance), `sec10-root-unknown-critical-extension-crl-unsupported` (acceptance), `sec10-root-delta-crl-unsupported` (acceptance), `sec10-root-indirect-crl-unsupported` (acceptance), `sec10-root-entry-critical-extension-crl-unsupported` (acceptance), `sec10-root-delta-expired-crl-reports-feature` (acceptance), `sec10-root-idp-user-certs-crl-unsupported` (acceptance), `sec10-root-idp-ca-certs-crl-unsupported` (acceptance), `sec10-root-aki-issuer-serial-crl-name-matched` (acceptance), `sec10-root-idp-named-point-crl-rejected` (acceptance), `sec10-root-crl-no-next-update-beside-good-crl` (acceptance), `sec10-root-expired-crl-still-rejected-beside-good-crl` (acceptance), `sec10-root-aki-crl-still-rejected-beside-good-crl` (acceptance), `sec10-root-crl-malformed-aki-beside-good-crl` (acceptance), `sec10-root-signed-other-aki-crl-still-rejected-beside-good-crl` (acceptance), `sec10-root-unknown-critical-extension-crl-unsupported-beside-good-crl` (acceptance), `sec10-root-delta-crl-unsupported-beside-good-crl` (acceptance), `sec10-root-indirect-crl-unsupported-beside-good-crl` (acceptance), `sec10-root-entry-critical-extension-crl-unsupported-beside-good-crl` (acceptance), `sec10-root-delta-expired-crl-reports-feature-beside-good-crl` (acceptance), `sec10-root-idp-user-certs-crl-unsupported-beside-good-crl` (acceptance), `sec10-root-idp-ca-certs-crl-unsupported-beside-good-crl` (acceptance), `sec10-root-aki-issuer-serial-crl-name-matched-beside-good-crl` (acceptance), `sec10-root-idp-named-point-crl-rejected-beside-good-crl` (acceptance).

### CRL-002: A listing counts only from a current CRL, and the newest decides

A revocation in an expired CRL beside a fresh CRL that omits the serial does
not count; alone, the expired CRL is `crl_expired`. Among usable CRLs the
newest lastUpdate decides, so a listing in an older, still-valid CRL does not
count beside a newer one, and alone it revokes.

- **Basis:** Decided, acceptance (owner delegated the call, PR #60).
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:1603-1633 (get_crl_sk): one best CRL is selected, the newer lastUpdate winning a tie; :2344 (cert_crl) reads entries from that CRL only.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/PKIXCRLUtil.java:42-49 (findCRLs): CRLs whose nextUpdate is not after the validation date are dropped before any entry is read.
- **Cases:** `sec10-stale-crl-revocation-beside-fresh-crl-is-ignored` (acceptance), `sec10-stale-crl-revocation-alone-is-expired` (acceptance), `sec10-superseded-crl-revocation-beside-newer-crl-is-ignored` (acceptance), `sec10-superseded-crl-revocation-alone-revokes` (acceptance).

### CRL-003: A CRL without nextUpdate is current for a listing

A correctly signed, in-scope CRL without nextUpdate that lists the certificate
revokes, beside an older CRL and alone (`certificate_revoked`). Alone it
revokes only if webpki would admit it apart from the missing nextUpdate (judged
on a byte-identical re-encoding with a stand-in nextUpdate). A newer current,
complete, direct CRL that leaves the certificate out clears the listing; an
older one does not. A removeFromCRL entry releases the listing.

- **Basis:** Decided. Acceptance beside an older CRL (corrected after review:
  the earlier rule failed open); diagnostics alone (both results reject).
  OpenSSL, BoringSSL and Bouncy Castle agree on currency; on clearing,
  BoringSSL breaks the OpenSSL / Bouncy Castle tie (newest CRL decides); on
  removeFromCRL, OpenSSL and Bouncy Castle agree and are followed.
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
- **Cases:** `sec10-no-next-update-crl-revocation-beside-older-crl-revokes` (acceptance), `sec10-no-next-update-crl-revocation-alone-is-invalid` (diagnostics), `sec10-no-next-update-crl-revocation-alone-revokes` (diagnostics), `sec10-no-next-update-crl-revocation-cleared-by-newer-crl` (diagnostics), `sec10-no-next-update-crl-revocation-beside-older-clearing-crl-revokes` (diagnostics).
- **Unit tests:** `a_crl_without_next_update_revokes_only_under_webpki_rules`,
  `a_crl_without_next_update_is_judged_by_its_other_defects`,
  `only_a_usable_covering_crl_clears_a_listing_without_next_update`,
  `a_crl_without_next_update_for_another_point_is_set_aside_if_admitted`,
  `a_crl_that_does_not_reencode_to_its_bytes_is_not_judged`.

### CRL-004: A CRL without nextUpdate is not evidence of good status

Without a listing, a chain issuer's CRL that lacks nextUpdate is `invalid_crl`
(`missing_next_update`). This is stricter than the references, which would
accept it: RFC 5280 section 5.1.2.5 requires nextUpdate, and a CRL that never
expires cannot show that the status is still current.

- **Basis:** Decided, acceptance (rssig's stricter rule, kept on purpose).
- **Sources:** RFC 5280 section 5.1.2.5; written argument above.
- **Cases:** pinned by `sec10-root-crl-no-next-update`, listed under CRL-001
  because its `decision` block carries CRL-001's sources.

### CRL-005: A listing in a current CRL with a malformed AKI counts beside a usable CRL

A correctly signed CRL of the issuer that lists the certificate revokes even
if its authorityKeyIdentifier is malformed, when it is at least as new as the
usable CRL beside it. Alone it is `invalid_crl`. A malformed identifier does
not make the issuer's statement less authentic, and counting it fails closed.

- **Basis:** Decided by the owner, acceptance (PR #60). The references
  disagree; rssig is closest to OpenSSL.
- **Sources:**
  - OpenSSL crypto/x509/x_crl.c:265-269 (crl_cb): a malformed AKI leaves crl->akid NULL and sets EXFLAG_INVALID, which crypto/x509/x509_vfy.c never reads for a CRL; crypto/x509/v3_purp.c:1353 (X509_check_akid) treats a NULL akid as a match, so get_crl_sk (x509_vfy.c:1603-1633) can select the CRL and cert_crl (x509_vfy.c:2344) reports the listing: revoked if that CRL has the later lastUpdate, or an equal one and comes first; otherwise good.
  - Bouncy Castle pkix/src/main/java/org/bouncycastle/pkix/jcajce/RFC3280CertPathUtilities.java:255-280 (processCRLF, used by X509RevocationChecker): the CRL's AKI is not read; revoked or good by CRL iteration order.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/RFC3280CertPathUtilities.java:379-393 (processCRLF): AuthorityKeyIdentifier.getInstance throws an uncaught IllegalArgumentException, or the result is good if the well-formed CRL is iterated first; never revoked.
  - BoringSSL crypto/x509/x_crl.cc:157-161 (crl_cb): returns 0, so the CRL fails to parse and is never used; never revoked.
  - relic lib/pkcs7/verify.go:177: Go's x509.VerifyOptions, no CRL checking.
- **Cases:** `sec10-malformed-aki-crl-revocation-beside-good-crl-revokes` (acceptance).

### CRL-006: A listing in a CRL whose signature cannot be verified never counts

A CRL with a bad or unsupported signature is `invalid_crl`
(`unsupported_signature_algorithm`) or `invalid_crl_signature`, and its
entries are never read. It is set aside when another CRL is usable.

- **Basis:** Decided, acceptance.
- **Sources:** OpenSSL `crypto/x509/x509_vfy.c` (`check_crl` fails the CRL
  before `cert_crl` reads entries); Bouncy Castle
  `RFC3280CertPathUtilities` (processCRLG skips it before processCRLJ).
- **Cases:** no spec case carries this decision.

## Scope and applicability

### CRL-007: A CRL that does not apply is excluded; one that applies must be usable

A CRL that does not apply to the chain is excluded whatever its fault; an
applicable CRL that cannot be used fails closed. When no supplied CRL applies,
the result is `revocation_unknown`, returned before path building.
Unsupported features are reported before freshness.

- **Basis:** Decided, acceptance (PR #44, #45, #46).
- **Sources:** written fail-closed argument (AGENTS.md, "Fail closed").
- **Cases:** no spec case carries a `decision` block for this; the behavior is
  pinned by the `sec10-unrelated-*-excluded`,
  `sec10-only-unrelated-crl-is-unknown` and
  `sec10-root-delta-expired-crl-reports-feature` cases (Observed).

### CRL-008: A full CRL is in scope for any certificate

A CRL without an issuingDistributionPoint covers every certificate of its
issuer, whatever points the certificate lists.

- **Basis:** Decided, acceptance.
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:2146-2200 (crl_crldp_check): a CRL without an issuingDistributionPoint is in scope for any certificate, whatever points the certificate lists.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/RFC3280CertPathUtilities.java:105-195 (processCRLB2): distribution point names are compared only when the CRL has an issuingDistributionPoint.
- **Cases:** `sec10-chain-crl-dp-full-crls` (acceptance), `sec10-leaf-crl-dp-mixed-full-crl` (acceptance), `sec10-leaf-crl-dp-https-full-crl` (acceptance).

### CRL-009: A revocation in a CRL that does not cover the certificate does not count

A partition for another point or role, or a CRL whose issuingDistributionPoint
does not decode, is never read for the certificate's entries.

- **Basis:** Decided, acceptance (owner chose to follow the libraries, PR #60;
  the earlier `-revoked` cases now verify).
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:2146-2198 (crl_crldp_check) and :1847-1853 (get_crl_score): a CRL whose issuingDistributionPoint does not match the certificate gets no CRL_SCORE_SCOPE and is not selected over a CRL that covers it.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/RFC3280CertPathUtilities.java:1678 (processCRLB2) with core PKIXCRLValidator.java:151-158 (checkDistributionPointName): a distribution point mismatch rejects the CRL before processCRLJ (:1703) reads entries.
- **Cases:** `sec10-crl-dp-other-partition-revocation-is-ignored` (acceptance), `sec10-crl-dp-other-partition-revocation-is-ignored-first` (acceptance).

### CRL-010: A partition for another point is no evidence

The certificate is without a CRL, so the status is `revocation_unknown` and
retrieval fetches its own point.

- **Basis:** Decided, diagnostics.
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:2146-2198 (crl_crldp_check) and :1847-1853 (get_crl_score): a CRL whose issuingDistributionPoint does not match the certificate gets no CRL_SCORE_SCOPE and is not selected over a CRL that covers it.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/RFC3280CertPathUtilities.java:1678 (processCRLB2) with core PKIXCRLValidator.java:151-158 (checkDistributionPointName): a distribution point mismatch rejects the CRL before processCRLJ (:1703) reads entries.
- **Cases:** `sec10-crl-dp-other-idp-unknown` (diagnostics), `sec10-expired-partition-for-another-point-leaves-status-unknown` (diagnostics), `sec10-fetch-expired-partition-for-another-point-still-fetches` (diagnostics).

### CRL-011: A role-only partition counts for its role

An issuingDistributionPoint with only onlyContainsUserCerts or
onlyContainsCACerts that admits the certificate is in scope, so its listing
revokes beside a full CRL. Alone it is still `invalid_crl`, because webpki
cannot use that form.

- **Basis:** Decided, acceptance (beside a full CRL); **Observed**, acceptance
  (alone).
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:2154-2157 and :2195-2197 (crl_crldp_check): role flags are checked first, and an issuingDistributionPoint with no distpoint is in scope for a certificate of that role.
  - Bouncy Castle core PKIXCRLValidator.java:151-158, 218-220 (processCRLB2): names are compared only when the IDP has one; the onlyContains flags then admit or reject by role.
- **Cases:** `sec10-role-partition-crl-revocation-beside-full-crl-revokes` (acceptance), `sec10-role-partition-crl-revocation-alone-is-unsupported` (acceptance, Observed).

### CRL-012: A point-scoped CRL for a certificate that lists no points is rejected

A CRL that names a distribution point (including a CA-only one) is
`invalid_crl` (`distribution_point_scope`) for a certificate that lists no
cRLDistributionPoints; it is not set aside. With a full CRL of the issuer
present, the full CRL is used. Setting such a CRL aside instead was declined
after review.

- **Basis:** Decided, acceptance (PR #48; confirmed against the references
  in PR #60).
- **Sources:**
  - OpenSSL crypto/x509/x_crl.c:358-361 sets IDP_ONLYCA; OpenSSL crypto/x509/x509_vfy.c:2154-2157 (crl_crldp_check) returns 0 for an end entity, and :2295 (check_crl) fails with X509_V_ERR_DIFFERENT_CRL_SCOPE.
  - Bouncy Castle core PKIXCRLValidator.java:151-158 (checkDistributionPointName): the CRL is rejected with a distribution point name mismatch; RFC3280CertPathUtilities.java:1716-1729 reports the last such exception when no CRL is valid.
- **Cases:** `sec10-fetch-no-listed-point-role-excluded-scope-rejected` (acceptance).

### CRL-013: A listing's scope needs a positive match

A named partition's listing counts only on a positive match with a fullName
URI the certificate lists; an issuer-relative or non-URI name is no match. A
certificate whose own cRLDistributionPoints cannot be read fails closed: the
partition is not set aside and its listing counts.

- **Basis:** Decided, acceptance (refined after review of PR #60).
- **Sources:** OpenSSL `crl_crldp_check`; Bouncy Castle processCRLB2.
- **Cases:** no spec case (no committed certificate has an undecodable
  extension). Unit tests `a_listing_counts_only_on_a_positive_scope_match`,
  `unreadable_certificate_points_never_discard_a_partition` in `src/trust.rs`.

## Issuers and keys

### CRL-014: Configured anchors are keys

A configured root whose KeyUsage lacks cRLSign still issues usable CRLs. An
intermediate without cRLSign does not (`invalid_key_usage`).

- **Basis:** Decided, acceptance (PR #48).
- **Sources:** webpki 0.103 does not track anchor KeyUsage; written argument
  that a configured anchor is a trusted key, not a certificate to be policed.
- **Cases:** no spec case carries this decision; pinned by
  `sec10-root-no-crl-sign-accepted` (Observed).

### CRL-015: On a key-rollover path each certificate uses its own key's CRL

A self-issued rollover path (two issuers of one name, different keys) verifies
without revocation. With CRLs whose authorityKeyIdentifier names their key, each
certificate gets its own key's CRL in either order, and a revoked rollover
certificate is rejected.

- **Basis:** Decided, acceptance (SEC-16; OpenSSL, BoringSSL and Bouncy
  Castle agree; OpenSSL 3.0.13 run as a maintenance step).
- **Sources:**
  - RFC 5280 section 6.1: self-issued certificates (same subject and issuer name, different keys) are valid on a path and support key rollover.
  - OpenSSL crypto/x509/x509_vfy.c:755 and :802 (self-issued intermediates are accepted). Run with OpenSSL 3.0.13, `openssl verify -attime 1800000000` without CRL checks: OK.
  - OpenSSL crypto/x509/x509_vfy.c:1869-1889 (get_crl_score, crl_akid_check) and crypto/x509/v3_purp.c:1353 (X509_check_akid): a CRL whose authorityKeyIdentifier names the issuer's key outscores a same-name CRL that names another key, so each certificate gets its own key's CRL. Run with OpenSSL 3.0.13, `openssl verify -crl_check_all -attime 1800000000`, either CRL order: OK.
  - BoringSSL crypto/x509/x509_vfy.cc:490-515 (crl_akid_check) and :665-693 (get_crl_sk): the same scoring.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/RFC3280CertPathUtilities.java:379-390 (processCRLF selects the signing key by the CRL's authority key identifier) and :1716-1721 (checkCRL skips a CRL that does not verify and continues).
  - webpki 0.103.16: check_crls takes the first authoritative CRL by issuer name and IDP only, so it cannot confirm two issuers of one name; rssig's own per-key evaluation decides for such a path.
  - RFC 5280 section 6.3.3: a certificate listed on a current CRL of its issuer is revoked.
  - OpenSSL crypto/x509/x509_vfy.c (check_cert_crl, cert_crl) and Bouncy Castle RFC3280CertPathUtilities.checkCRL: every certificate on the path is checked against its own issuer key's CRL, the rollover certificate included.
- **Cases:** `sec16-self-issued-rollover-without-revocation-verifies` (acceptance), `sec16-self-issued-rollover-with-key-identified-crls-verifies` (acceptance), `sec16-self-issued-rollover-with-key-identified-crls-verifies-reversed` (acceptance), `sec16-self-issued-rollover-revoked-by-key-identified-crl-is-rejected` (acceptance).

### CRL-016: A rollover path with CRLs that name no key is rejected

With same-name CRLs that carry no authorityKeyIdentifier, the path is
`certificate_chain_invalid` (`ambiguous_issuer_keys`) in either order.

- **Basis:** Decided, acceptance. The references differ; the owner chose
  BoringSSL as the tiebreaker (PR #60), which rejects and fails closed.
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:1869-1881 (get_crl_score), :1614-1627 (get_crl_sk keeps one best CRL for a name) and :2318-2320 (check_crl has no fallback after a signature failure); crypto/x509/v3_purp.c:1353-1354 (a CRL without an authorityKeyIdentifier matches any key). Run with OpenSSL 3.0.13, `openssl verify -crl_check_all -attime 1800000000`: 'CRL signature failure' at depth 0 or 1 depending on CRL order. Rejects.
  - BoringSSL crypto/x509/x509_vfy.cc:490-515, :665-693 and :755-760: the same logic. Rejects.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/RFC3280CertPathUtilities.java:1716-1721 (checkCRL skips a CRL that does not verify and tries the next). Accepts.
  - webpki 0.103.16: check_crls takes the first authoritative CRL by issuer name and IDP only, then verifies it under the certificate's issuer key. Rejects.
  - The references differ; the owner chose the tiebreaker (PR #60): the third reference, BoringSSL, rejects, and rejecting fails closed.
- **Cases:** `sec16-self-issued-rollover-with-both-crls-is-rejected` (acceptance).

### CRL-017: A CRL naming a same-key root's identifier is forged, not set aside

Two configured roots with one key and name may carry different
subjectKeyIdentifiers. A CRL signed by another key that names any of them is
`invalid_crl_signature`; one naming an identifier no configured root carries
is another issuer's and is set aside.

- **Basis:** **Observed**, diagnostics only (both reject; the libraries have
  no equivalent for two same-key anchors).
- **Sources:** none; written argument in SEC-10.
- **Cases:** `sec10-forged-crl-naming-another-key-is-set-aside` (diagnostics, Observed), `sec10-forged-crl-naming-a-same-key-roots-identifier-is-forged` (diagnostics, Observed).

## Candidate paths and usages

### CRL-018: A path that verifies with its CRLs is accepted whatever another path does

- **Basis:** Decided, acceptance. Bouncy Castle tries every candidate path;
  OpenSSL builds one chain and has no equivalent, so Bouncy Castle is
  followed.
- **Sources:**
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/PKIXCertPathBuilderSpi.java:135-270 (build): every candidate issuer is tried and a path that validates is returned; a failed candidate only sets certPathException (:268).
  - OpenSSL crypto/x509/x509_vfy.c:3925 (build_chain) builds one chain and :1444-1537 (check_cert_crl) checks that chain only; it has no second path to fall back on, so Bouncy Castle is followed.
- **Cases:** `sec10-cross-revoked-path-beside-covered-path-verifies` (acceptance), `sec10-fetch-completes-the-path-without-a-crl-beside-a-revoked-path` (acceptance), `sec10-fetch-completes-the-path-beside-an-expired-path` (acceptance).

### CRL-019: Which error a rejected chain reports

A revocation is definite evidence and is reported over another path's failure;
only a path that passes every other check and lacks CRLs can be completed, so
its gap is named. With `--fetch-crls`, an unknown status that names nothing is
followed by a check without revocation, which reports the path's own failure.

- **Basis:** Decided, diagnostics (written argument in
  `docs/crl-retrieval.md`; both results reject).
- **Sources:**
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/PKIXCertPathBuilderSpi.java:135-270 (build): every candidate issuer is tried and a path that validates is returned; a failed candidate only sets certPathException (:268).
  - OpenSSL crypto/x509/x509_vfy.c:3925 (build_chain) builds one chain and :1444-1537 (check_cert_crl) checks that chain only; it has no second path to fall back on, so Bouncy Castle is followed.
  - No reference reports which of several rejected paths decides; the order is the written argument in docs/crl-retrieval.md (only a path that passes every other check and lacks CRLs can be completed).
- **Cases:** `sec10-cross-revoked-path-beside-path-without-crl-names-it` (diagnostics), `sec10-fetch-revocation-stands-when-the-other-path-stays-without-crl` (diagnostics), `sec10-cross-revoked-path-beside-path-failing-key-usage-is-revoked` (diagnostics), `sec10-cross-unusable-crl-decides-beside-path-failing-key-usage` (diagnostics), `sec10-cross-expired-path-beside-path-without-crl-names-the-gap` (diagnostics), `sec10-fetch-path-failing-key-usage-asks-nothing` (diagnostics).

### CRL-020: A revocation names another path's refreshable certificates

A revocation on one candidate path names, in
`details.certificates_with_expired_crl` or
`details.certificates_with_replaceable_crl`, the certificates of another viable
path whose only CRLs a source could refresh, and `--fetch-crls` then verifies
through that path. Paths with a CRL no refresh can fix are not named.

- **Basis:** Decided. Diagnostics offline, acceptance with `--fetch-crls`
  (follows Bouncy Castle; OpenSSL has no equivalent).
- **Sources:**
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/PKIXCertPathBuilderSpi.java:135-270 (build): every candidate path is tried and one that validates is accepted, whatever another path's revocation.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/PKIXCRLUtil.java:42-45 drops a CRL past nextUpdate, and with CRL distribution point fetching enabled (CertPathValidatorUtilities.java:571) a fresh CRL is fetched from the certificate's points.
  - OpenSSL builds one chain (crypto/x509/x509_vfy.c:3925 build_chain) and does not fetch, so it has no equivalent; the owner's delegated call to refresh expired CRLs follows Bouncy Castle (crl-stale-local-refreshed-by-provider).
  - OpenSSL 3.3 crypto/x509/x509_vfy.c:1564-1590 (get_crl_delta) consults lookup_crls when the best supplied CRL scores below CRL_SCORE_VALID (:33-42: no unhandled critical extension, time and scope; get_crl_score :1283-1340); the signature is not scored and its failure is reported at :1664 without another lookup.
  - BoringSSL crypto/x509/x509_vfy.cc:697-708 (get_crl) looks CRLs up in the store on the same condition.
  - Bouncy Castle pkix/src/main/java/org/bouncycastle/pkix/jcajce/X509RevocationChecker.java:797-863 turns any checkCRL failure but a revocation into 'no valid CRL found', and :468-487 then fetches from the certificate's distribution points when fetching is enabled.
- **Cases:** `sec10-cross-revoked-path-beside-path-with-expired-crl-names-it` (diagnostics), `sec10-cross-revoked-path-beside-path-with-not-yet-valid-crl-names-it` (diagnostics), `sec10-fetch-replaces-the-path-with-a-not-yet-valid-crl-beside-a-revoked-path` (acceptance), `sec10-fetch-refreshes-the-path-with-an-expired-crl-beside-a-revoked-path` (acceptance).
- **Unit test:** `a_revocation_names_only_paths_a_source_could_complete`.

### CRL-021: A path a source could complete is reported over a stuck path

When no path is revoked, a viable path that only lacks, or has expired or
replaceable, CRLs is reported ahead of a path whose CRL no refresh can fix.

- **Basis:** Decided, diagnostics offline and acceptance with `--fetch-crls`.
- **Sources:** written argument in `docs/crl-retrieval.md`.
- **Cases:** no spec case. Unit test
  `a_path_a_source_could_complete_is_reported_over_a_stuck_paths_failure`.

### CRL-022: Lifetime-signing validity outranks revocation on another path

Across candidate paths, a CA issued after the lifetime signing time on one path
outranks a revocation on another; both reject.

- **Basis:** Decided by choice, diagnostics only. The libraries disagree and
  neither has lifetime signing; the SEC-14 precedence is kept.
- **Sources:** OpenSSL builds one chain and checks revocation before
  validity; Bouncy Castle tries every path and checks validity before
  revocation per certificate.
- **Cases:** pinned by `sec09-lifetime-rollover-revoked-issuer`, which has no
  `decision` block yet.

### CRL-023: An RDP signer lacking only a CRL under one usage reports the missing CRL

When one usage fails its path (`invalid_eku`) and another lacks only a CRL, the
missing CRL is the result, and `--fetch-crls` verifies the file.

- **Basis:** Decided by written argument. Acceptance (with CRLs or fetching),
  diagnostics (without them). No reference has an equivalent: multi-EKU
  acceptance is rssig's RDP policy (`docs/rdp.md`).
- **Sources:**
  - No reference library has an equivalent: accepting an RDP signer under any one of several EKUs is rssig's RDP policy (docs/rdp.md). Written argument: the signer is acceptable under serverAuth and only lacks a CRL, so the missing CRL, which a source can supply, is the result rather than the other EKU's path failure.
  - On main, retrieval ran after a preliminary pass without revocation, which succeeded through serverAuth, so the CRL was fetched and the file verified; the fetch case restores that.
- **Cases:** `rdp-eku-retry-ca-with-crls-verifies` (acceptance), `rdp-eku-retry-ca-fetches-the-missing-crl` (acceptance), `rdp-eku-retry-ca-missing-crl-is-unknown` (diagnostics).

### CRL-024: A revoked RDP usage is reported over another usage's failure

The revocation is reported and names the certificates another usage only lacks
a CRL for.

- **Basis:** Decided by written argument, diagnostics (both reject).
- **Sources:**
  - No reference library has an equivalent: accepting an RDP signer under any one of several EKUs is rssig's RDP policy (docs/rdp.md).
  - Written argument, as for candidate paths (sec10-cross-revoked-path-beside-path-failing-key-usage-is-revoked): a revocation is definite evidence and is reported over another usage's path failure (here invalid_eku for codeSigning). Both reject.
- **Cases:** `rdp-eku-retry-ca-revoked-usage-is-revoked` (diagnostics).
- **Unit test:** `a_revoked_usage_is_reported_and_names_another_usages_gaps`.

## Retrieval (`--fetch-crls` and `CrlSource`)

### CRL-025: Nothing is fetched for an input that cannot verify

Retrieval happens only when verification with the supplied CRLs is
`revocation_unknown` or names a refreshable CRL. Before the first request the
whole input is verified once without revocation, so an untrusted chain, an
invalid nested signature, later signer or bundle member is the result and no
source is asked.

- **Basis:** Decided, acceptance and privacy.
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:266-284 (verify_chain): build_chain, which requires a trust anchor, runs before check_revocation (:276), so no CRL is looked up for a chain that does not reach a trusted root.
  - Verifying the whole input (nested signatures, later signers, bundle members) before any request has no reference equivalent; it is a written privacy argument in docs/crl-retrieval.md: an input that cannot verify must not cause network requests.
- **Cases:** `crl-fetch-untrusted-chain-requests-nothing` (acceptance), `crl-fetch-invalid-nested-signature-requests-nothing` (acceptance).

### CRL-026: A definite result keeps its code with `--fetch-crls`

A definite revocation or CRL failure is the result, as without fetching, and
is not followed by a check of the rest of the input. Only an unknown status,
which is no evidence, is replaced by the path's own failure.

- **Basis:** Decided, diagnostics (both results reject).
- **Sources:**
  - Without --fetch-crls, a chain whose paths all fail path policy reports revocation first, as on main (sec10-cross-unusable-crl-decides-beside-path-failing-key-usage); with --fetch-crls a definite CRL failure or revocation keeps that code. Only an unknown status, which is no evidence, is replaced by the path failure with fetching (sec10-fetch-path-failing-key-usage-asks-nothing).
  - Only an unknown status that names nothing is followed by a check without revocation (sec10-fetch-path-failing-key-usage-asks-nothing): it is no evidence, while these are.
  - Diagnostics only: both results reject.
- **Cases:** `sec10-fetch-path-failing-key-usage-with-unusable-crl-keeps-the-crl-failure` (diagnostics), `sec10-fetch-path-failing-key-usage-with-revoked-issuer-is-revoked` (diagnostics).

### CRL-027: Retrieval asks per certificate, only about what lacks a CRL

- **Basis:** Decided, diagnostics (which requests are made; the result is the
  same either way).
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:2206-2254 (get_crl_delta; lookup_crls at :2228) called from :1444-1537 (check_cert_crl): CRLs are looked up for the certificate being checked, by its issuer name, and only when the context holds none for it.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/RFC3280CertPathUtilities.java:1754-1880 (checkCRLs): CRLs are looked up per certificate, per distribution point.
- **Cases:** `sec10-fetch-excluded-name-match-fetches-listed-point` (diagnostics), `sec10-fetch-covered-signer-point-not-requested` (diagnostics), `sec10-fetch-asks-each-certificate-without-crl` (diagnostics), `sec10-fetch-covered-signer-is-not-asked` (diagnostics), `sec10-fetch-mixed-point-requests-plain-uri` (diagnostics), `sec10-fetch-asks-only-the-uncovered-certificate` (diagnostics), `sec10-fetch-bad-response-is-no-evidence-beside-another-point` (diagnostics).

### CRL-028: Missing evidence is `revocation_unknown`; a source has four outcome kinds

However a CRL could not be obtained, the code is `revocation_unknown`, with the
cause (denied, failed, abort, unknown) in `crl_retrieval.failures`.

- **Basis:** Decided by the owner (PR #60 design), diagnostics. The single
  code matches the references; the four kinds have no equivalent.
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:1489 and :1527 (check_cert_crl): however a CRL could not be obtained, the result is the single X509_V_ERR_UNABLE_TO_GET_CRL.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/CertPathValidatorUtilities.java:1340: a single "No CRLs found for issuer" error, with lookup diagnostics appended to its message.
  - The four source kinds (denied, failed, abort, unknown) have no reference equivalent; they are the owner's design in PR #60, described in docs/crl-retrieval.md.
- **Cases:** `crl-fetch-private` (diagnostics), `crl-fetch-injected-unavailable` (diagnostics), `sec10-fetch-reasons-point-denied` (diagnostics), `sec10-fetch-crl-issuer-point-denied` (diagnostics), `sec10-fetch-dns-name-point-denied` (diagnostics), `crl-fetch-source-denied-is-no-evidence` (diagnostics), `crl-fetch-source-failed-is-no-evidence` (diagnostics), `crl-fetch-source-unknown-is-no-evidence` (diagnostics), `crl-fetch-source-abort-is-reported` (diagnostics), `sec10-fetch-source-abort-stops-requests` (diagnostics).

### CRL-029: A source answering by certificate leaves no per-point failures

Only a body that loads as a CRL of the certificate's issuer counts. When that
answer settles the status, no per-point failure is recorded; when it does not,
the listed points the source left unused are recorded as not used, so no
listed point disappears from the report.

- **Basis:** Decided, diagnostics (owner delegated the call; the second half
  is a written argument).
- **Sources:**
  - OpenSSL crypto/x509/x509_lu.c:978-990 (X509_STORE_CTX_get1_crls): CRLs are looked up by issuer name, with no per-distribution-point outcome.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/CertPathValidatorUtilities.java:1100-1124 (getCompleteCRLs): the selector matches the issuer only.
  - OpenSSL crypto/x509/x509_lu.c:978-990 (X509_STORE_CTX_get1_crls) and Bouncy Castle CertPathValidatorUtilities.java:1100-1124 (getCompleteCRLs): CRLs are looked up by issuer, with no per-distribution-point outcome, so an answer by certificate leaves no per-point failure when it settles the status.
  - Written argument for the other case: when that answer does not settle the status, the report must still account for every listed point (docs/crl-retrieval.md: no listed point disappears from the report), so the points the source did not use are recorded as not used.
- **Cases:** `sec10-fetch-by-certificate-answer-requests-no-listed-point` (diagnostics), `sec10-fetch-by-certificate-unusable-answer-records-unused-points` (diagnostics).

### CRL-030: An expired supplied CRL is refreshed

With a source, an expired supplied CRL is refreshed from the certificate's
points; without an answer `crl_expired` stands, marked `retrieval_aborted` when
the source aborted.

- **Basis:** Decided, acceptance (owner delegated the call, PR #60; follows
  Bouncy Castle, OpenSSL does not fetch).
- **Sources:**
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/PKIXCRLUtil.java:42-49 drops CRLs past nextUpdate; CertPathValidatorUtilities.java:571-630 and pkix X509RevocationChecker.java:477-492 then fetch from the certificate's distribution points when fetching is enabled.
  - OpenSSL crypto/x509/x509_vfy.c:2223-2231 (get_crl_delta): CRLs come from ctx->crls and the store lookup only; the verifier does not fetch.
- **Cases:** `crl-stale-local-asks-provider` (acceptance), `crl-stale-local-refreshed-by-provider` (acceptance), `crl-stale-local-source-abort-is-marked` (diagnostics).

### CRL-031: A supplied CRL the references would look past is refreshed

A not-yet-valid CRL, an unusable issuingDistributionPoint, an unknown critical
extension, a delta, indirect or reasons-partitioned CRL is replaceable: the
certificate is named in `certificates_with_replaceable_crl` and a source is
asked. Without an answer the original error stands, marked `retrieval_aborted`
when the source aborted.

- **Basis:** Decided by the owner after PR #60 (SEC-23): follow OpenSSL and
  Bouncy Castle where they agree, BoringSSL where they differ. Replaces the
  Observed rule that only an expired CRL is refreshed.
- **Sources:**
  - OpenSSL 3.3 crypto/x509/x509_vfy.c:1564-1590 (get_crl_delta) consults lookup_crls when the best supplied CRL scores below CRL_SCORE_VALID (:33-42: no unhandled critical extension, time and scope; get_crl_score :1283-1340); the signature is not scored and its failure is reported at :1664 without another lookup.
  - BoringSSL crypto/x509/x509_vfy.cc:697-708 (get_crl) looks CRLs up in the store on the same condition.
  - Bouncy Castle pkix/src/main/java/org/bouncycastle/pkix/jcajce/X509RevocationChecker.java:797-863 turns any checkCRL failure but a revocation into 'no valid CRL found', and :468-487 then fetches from the certificate's distribution points when fetching is enabled.
- **Cases:** `crl-not-yet-valid-local-refreshed-by-provider` (acceptance), `crl-unknown-critical-extension-local-refreshed-by-provider` (acceptance), `sec10-fetch-completes-missing-and-not-yet-valid-crl` (acceptance), `sec10-fetch-unusable-scope-supplied-crl-refreshed` (acceptance), `crl-not-yet-valid-local-asks-provider` (diagnostics), `crl-not-yet-valid-local-source-abort-is-marked` (diagnostics), `crl-unknown-critical-extension-local-source-abort-is-marked` (diagnostics), `sec10-chain-unknown-names-missing-and-not-yet-valid-crl` (diagnostics), `sec10-fetch-unusable-scope-supplied-crl-stands-without-answer` (diagnostics).

### CRL-032: A CRL with a bad signature is not refreshed

A supplied CRL with a bad signature is `invalid_crl_signature` and nothing is
requested, even if the source holds a good CRL. Likewise an issuer without
cRLSign is not asked about: a fetched CRL has the same issuer.

- **Basis:** Decided, acceptance (BoringSSL decides: OpenSSL and BoringSSL
  report without a second lookup; Bouncy Castle fetches).
- **Sources:**
  - OpenSSL 3.3 crypto/x509/x509_vfy.c:1564-1590 (get_crl_delta) consults lookup_crls when the best supplied CRL scores below CRL_SCORE_VALID (:33-42: no unhandled critical extension, time and scope; get_crl_score :1283-1340); the signature is not scored and its failure is reported at :1664 without another lookup.
  - BoringSSL crypto/x509/x509_vfy.cc:697-708 (get_crl) looks CRLs up in the store on the same condition.
  - Bouncy Castle pkix/src/main/java/org/bouncycastle/pkix/jcajce/X509RevocationChecker.java:797-863 turns any checkCRL failure but a revocation into 'no valid CRL found', and :468-487 then fetches from the certificate's distribution points when fetching is enabled.
- **Cases:** `crl-forged-local-asks-nothing` (acceptance).

### CRL-033: A malformed CRL is replaceable

A malformed CRL does not stop the search for another, alone or beside an
expired one; without an answer its failure stands and names the certificate.

- **Basis:** Decided, acceptance (the three references agree).
- **Sources:**
  - OpenSSL 3.3 crypto/x509/x509_vfy.c:1564-1590 (get_crl_delta) consults lookup_crls when the best supplied CRL scores below CRL_SCORE_VALID (:33-42: no unhandled critical extension, time and scope; get_crl_score :1283-1340); the signature is not scored and its failure is reported at :1664 without another lookup.
  - BoringSSL crypto/x509/x509_vfy.cc:697-708 (get_crl) looks CRLs up in the store on the same condition.
  - Bouncy Castle pkix/src/main/java/org/bouncycastle/pkix/jcajce/X509RevocationChecker.java:797-863 turns any checkCRL failure but a revocation into 'no valid CRL found', and :468-487 then fetches from the certificate's distribution points when fetching is enabled.
  - BoringSSL crypto/x509/x_crl.cc:122-160 (ASN1_OP_D2I_POST): a CRL with an unsupported version, or a malformed issuingDistributionPoint or authorityKeyIdentifier, fails to decode and never joins the CRLs consulted, so the store is looked up as if it were absent.
  - OpenSSL 3.3 crypto/x509/x_crl.c:196-220 marks such a CRL EXFLAG_INVALID, which crypto/x509/x509_vfy.c never tests for a CRL; an invalid issuingDistributionPoint scores 0 (:1292) and the store lookup still runs when no CRL scores valid (:1576-1588).
- **Cases:** `crl-malformed-aki-local-refreshed-by-provider` (acceptance), `crl-malformed-aki-beside-expired-local-refreshed-by-provider` (acceptance), `crl-malformed-aki-beside-expired-local-asks-provider` (diagnostics).

### CRL-034: A missing nextUpdate blocks retrieval only as a CRL's sole defect

A CRL whose only defect is a missing nextUpdate is `invalid_crl`
(`missing_next_update`) and is not asked about. Any other defect decides
exactly as it would with nextUpdate present.

- **Basis:** Decided. Acceptance and diagnostics as listed per case.
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
- **Cases:** `crl-no-next-update-local-asks-nothing` (diagnostics), `sec10-no-next-update-point-scope-crl-is-replaceable` (diagnostics), `sec10-fetch-no-next-update-point-scope-crl-replaced-by-certificate` (acceptance).

### CRL-035: A point-scoped CRL for a certificate that lists no points is replaced by certificate

The certificate is asked about by certificate and issuer, and a full CRL from
the source decides. A source that answers only by URL has nothing to fetch,
so `invalid_crl` stands (CRL-012).

- **Basis:** Decided, acceptance.
- **Sources:**
  - OpenSSL 3.3 crypto/x509/x_crl.c:358-361 sets IDP_ONLYCA; OpenSSL crypto/x509/x509_vfy.c:2154-2157 (crl_crldp_check) returns 0 for an end entity, and :2295 (check_crl) fails with X509_V_ERR_DIFFERENT_CRL_SCOPE.
  - Bouncy Castle core PKIXCRLValidator.java:151-158 (checkDistributionPointName): the CRL is rejected with a distribution point name mismatch; RFC3280CertPathUtilities.java:1716-1729 reports the last such exception when no CRL is valid.
  - OpenSSL 3.3 crypto/x509/x509_vfy.c:1576-1588 (get_crl_delta): a CRL without the scope score is not valid, so lookup_crls consults the store, which here answers by certificate.
  - BoringSSL crypto/x509/x509_vfy.cc:697-708 (get_crl): a CRL scored below valid, here without the scope score, is followed by a store lookup by issuer name.
- **Cases:** `sec10-fetch-no-listed-point-scope-crl-replaced-by-certificate` (acceptance).

### CRL-036: The source decides transport; the core screens hygiene only

The verification core passes every listed URI to the source after hygiene
screening; the source decides what to fetch. The built-in `HttpCrlSource` is
stricter than the references (public addresses, `http` only, no redirects,
size and time bounds), and `retrieval::check_public_http_url` gives a custom
source the same check.

- **Basis:** Decided by the owner. Acceptance for the injected source,
  diagnostics for the built-in refusal.
- **Sources:**
  - OpenSSL crypto/x509/x509_vfy.c:2228: the verifier only calls lookup_crls; apps/lib/apps.c:2833 and :2905-2907 (get_dp_url, crls_http_cb): the scheme rule (http only) lives in the application callback.
  - Bouncy Castle prov/src/main/java/org/bouncycastle/jce/provider/CrlCache.java:136-141 and :185-188: the fetch helper applies an optional scheme allow-list (unrestricted by default) and opens the URL.
  - BoringSSL crypto/x509/x509_vfy.cc:697-704 (get_crl): never fetches.
- **Cases:** `sec10-fetch-source-is-asked-for-any-scheme` (acceptance), `sec10-fetch-builtin-source-denies-https` (diagnostics).

### CRL-037: Fetch limits bound one verification

The engine renews a source's allowances for each verification
(`CrlSource::begin_verification`). A DNS timeout still closes the built-in
source for the invocation, keeping at most one unfinished resolver thread.

- **Basis:** Decided, diagnostics and availability.
- **Sources:** OpenSSL `apps/lib/apps.c:2866-2867`, `apps/verify.c:220-232`
  (per-fetch limits, nothing accumulated); Bouncy Castle `CrlCache.java:41-46`
  (per-connection timeouts, process-wide cache).
- **Cases:** no spec case. Unit test
  `a_new_verification_restores_a_sources_allowances_but_a_dns_timeout_closes_it_for_good`.

### CRL-038: One certificate's distribution points never end the run

An over-long URI is skipped, and URIs past the first 16 are recorded as one
`crl_urls` failure. Per-verification limits stay engine limits.

- **Basis:** Decided, acceptance.
- **Sources:** neither OpenSSL nor Bouncy Castle has such a limit; both skip a
  point that fails.
- **Cases:** no spec case. Unit test
  `a_certificate_over_the_url_limits_is_skipped_point_by_point`.

### CRL-039: A URI that is not an absolute URL is never offered to a source

It is recorded as `crl_fetch_denied` with its own message and no `url`.

- **Basis:** Decided, diagnostics.
- **Sources:** OpenSSL `apps/lib/apps.c:2833` (`get_dp_url` returns only
  `http://`); Bouncy Castle `CrlCache.java:185` (`toURL()` fails on a relative
  URI).
- **Cases:** no spec case. Unit test
  `a_uri_that_is_not_an_absolute_url_is_withheld_with_its_own_reason`.
