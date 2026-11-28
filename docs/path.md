# Certificate-path decisions

Numbered decisions behind rssig's certificate-path rules. The entry format is
defined in [Decision indexes](decisions.md); the explanation of the profile,
webpki's role and its limits is in
[certificate paths](certificate-paths.md), and the history in
PATH-T001 ([done](tasks/done.md), PR #40). Path rules for CRL issuers are CRL
entries ([CRL decisions](crl.md)); time rules are [time decisions](time.md).

## Order

Entries are numbered from most to least important, in the tiers used by
[CRL decisions](crl.md#order); within a tier, Decided entries come before
Observed ones. A new entry takes the next free number.

1. **Fail-open:** a broken rule could accept a path that should not be
   trusted.
2. **Availability:** a broken rule would reject a valid path or report the
   wrong chain for one.
3. **Result diagnostics:** which chain or anchor is reported.

## Index

| ID | Decision | Status | Pins |
|---|---|---|---|
| [PATH-001](#path-001-trust-comes-only-from-a-configured-root) | Trust comes only from a configured root | Decided | acceptance |
| [PATH-002](#path-002-an-issuer-is-identified-by-its-key-not-its-name) | An issuer is identified by its key, not its name | Decided | acceptance |
| [PATH-003](#path-003-intermediates-must-be-cas-and-a-ca-cannot-sign) | Intermediates must be CAs, and a CA cannot sign | Decided | acceptance |
| [PATH-004](#path-004-path-length-constraints-are-enforced) | Path length constraints are enforced | Decided | acceptance |
| [PATH-005](#path-005-dns-name-constraints-apply-at-intermediates-and-anchors) | DNS name constraints apply at intermediates and anchors | Decided | acceptance |
| [PATH-006](#path-006-unknown-critical-extensions-are-rejected) | Unknown critical extensions are rejected | Decided | acceptance |
| [PATH-007](#path-007-an-authenticode-signer-needs-the-code-signing-eku-explicitly) | An Authenticode signer needs the code-signing EKU explicitly | Decided | acceptance |
| [PATH-008](#path-008-a-present-keyusage-must-allow-the-certificates-role) | A present KeyUsage must allow the certificate's role | Decided | acceptance |
| [PATH-009](#path-009-a-rejected-candidate-issuer-does-not-stop-path-building) | A rejected candidate issuer does not stop path building | Decided | acceptance |
| [PATH-010](#path-010-cross-signed-paths-lead-to-the-configured-root) | Cross-signed paths lead to the configured root | Decided | acceptance |
| [PATH-011](#path-011-configured-anchors-are-keys) | Configured anchors are keys | Decided | acceptance |
| [PATH-012](#path-012-the-reported-anchor-is-the-one-whose-constraints-accepted-the-path) | The reported anchor is the one whose constraints accepted the path | Decided | diagnostics |
| [PATH-013](#path-013-a-path-certificate-whose-extension-does-not-decode-fails-the-path) | A path certificate whose extension does not decode fails the path | Decided | acceptance |
| [PATH-014](#path-014-a-path-certificate-that-repeats-an-extension-fails-the-path) | A path certificate that repeats an extension fails the path | Observed | acceptance |
| [PATH-015](#path-015-a-certificate-report-marks-an-extension-it-cannot-decode) | A certificate report marks an extension it cannot decode | Observed | diagnostics |

## Tier 1: fail-open

### PATH-001: Trust comes only from a configured root

An embedded root or cross-signature does not establish trust, and a
cryptographically valid cycle (A→B→A) terminates with `untrusted_root` in
either order.

- **Status:** Decided
- **Decided by:** written argument (AGENTS.md, "Architecture and
  constraints": trust anchors come only from the configured root store)
- **Pins:** acceptance
- **Sources:**
  - RFC 5280 section 6.1: a path starts at a trust anchor the relying party
    chose; embedded certificates are untrusted candidates.

### PATH-002: An issuer is identified by its key, not its name

A matching issuer DN alone does not establish issuer identity: with only a
wrong-key issuer of the same name the path is `certificate_chain_invalid`,
and with both, the signature-valid issuer is chosen in either order.

- **Status:** Decided
- **Decided by:** written argument
- **Pins:** acceptance
- **Sources:**
  - RFC 5280 section 6.1.3 (a)(1): each certificate's signature is verified
    with the working public key.

### PATH-003: Intermediates must be CAs, and a CA cannot sign

An intermediate needs BasicConstraints with cA=true (a missing extension or
cA=false is `certificate_chain_invalid`); a CA certificate cannot act as the
signing leaf; a leaf may omit BasicConstraints.

- **Status:** Decided
- **Decided by:** written argument, PR #40 (PATH-T001); enforced by webpki
- **Pins:** acceptance
- **Sources:**
  - RFC 5280 sections 4.2.1.9 and 6.1.4 (k).

### PATH-004: Path length constraints are enforced

pathLenConstraint 0 allows an issuing CA directly above the leaf; an upper CA
with one subordinate CA needs at least 1.

- **Status:** Decided
- **Decided by:** written argument, PR #40 (PATH-T001); enforced by webpki
- **Pins:** acceptance
- **Sources:**
  - RFC 5280 sections 4.2.1.9 and 6.1.4 (l), (m).

### PATH-005: DNS name constraints apply at intermediates and anchors

A DNS SAN within a permitted subtree is accepted; one outside it, or within
an excluded subtree, is `certificate_chain_invalid`. A configured anchor's
name constraints are applied too. A publisher CN is not a DNS identity.

- **Status:** Decided
- **Decided by:** written argument, PR #40 (PATH-T001); enforced by webpki
- **Pins:** acceptance
- **Sources:**
  - RFC 5280 section 4.2.1.10.
  - webpki `subject_name/mod.rs` for the supported name forms; see
    [certificate paths](certificate-paths.md#applicable-profile-and-boundaries).

### PATH-006: Unknown critical extensions are rejected

An unfamiliar extension is ignored when noncritical, preserving the
certificate DER, and rejected when critical on the leaf or an intermediate.

- **Status:** Decided
- **Decided by:** written argument, PR #40 (PATH-T001); enforced by webpki
- **Pins:** acceptance
- **Sources:**
  - RFC 5280 section 4.2: a certificate with an unrecognized critical
    extension must be rejected.

### PATH-007: An Authenticode signer needs the code-signing EKU explicitly

For every Authenticode format (PE, MSI and the others that share its
verifier), the signing leaf must list the code-signing EKU (`invalid_eku` at
`certificate`); an intermediate EKU, when present, must permit it
(`invalid_eku` at `certificate_chain`); an intermediate without EKU is
unrestricted. RDP signers follow RDP's own EKU rule (codeSigning, serverAuth
or Remote Desktop signing; see [RDP](rdp.md)), which a future `RDP-` entry
will state; TSA certificates follow TSA-003.

- **Status:** Decided
- **Decided by:** written choice, PR #40 (PATH-T001)
- **Pins:** acceptance
- **Sources:**
  - webpki `KeyUsage::required_if_present` propagates the leaf's required
    usage through intermediates.
  - Written argument: an Authenticode signer must be a code-signing
    certificate; no Windows equivalence is claimed.

### PATH-008: A present KeyUsage must allow the certificate's role

A present leaf KeyUsage needs digitalSignature and a present intermediate
KeyUsage needs keyCertSign (`invalid_key_usage`); an absent KeyUsage is
unrestricted. rssig checks both itself, because webpki's TLS-oriented checks
do not.

- **Status:** Decided
- **Decided by:** written argument, PR #40 (PATH-T001)
- **Pins:** acceptance
- **Sources:**
  - RFC 5280 section 4.2.1.3.

### PATH-013: A path certificate whose extension does not decode fails the path

An extension that rssig or webpki decodes (basicConstraints, keyUsage,
extKeyUsage, subjectAltName, nameConstraints, cRLDistributionPoints,
subjectKeyIdentifier or authorityKeyIdentifier) whose value does not decode as
that extension, critical or not, fails the path when it is in the signing leaf
or an intermediate. A value decodes as DER of the extension's ASN.1 type,
string contents included, so an IA5String (a dNSName, rfc822Name or URI) with
a byte above 0x7F does not decode.

- The signer is on every path, so it fails before any path is built (after
  the check for a configured root): `certificate_chain_invalid` at
  `certificate_chain`, with `details.reason` `malformed_extension`,
  `details.extension` its OID and `details.certificate_sha256` the signer.
- An intermediate rejects each candidate path through it, and path building
  goes on (PATH-009). rssig rejects the path in its path callback, which
  webpki calls only for a path it has linked by signature to a configured
  root, so the error names the intermediate (with the same `reason`,
  `extension` and `certificate_sha256`) only when it is what kept such a path
  from being accepted, and no other candidate path failed for a reason webpki
  ranks higher (it reports the most specific failure); a path that reaches no
  root stays `untrusted_root`. The rejection is logged at debug level either
  way.
  webpki itself rejects, before the callback, an intermediate whose
  basicConstraints, extKeyUsage or nameConstraints does not decode, and one
  whose subjectAltName or cRLDistributionPoints is not a SEQUENCE at all (it
  keeps those two only as a SEQUENCE): that failure is
  `certificate_chain_invalid` at `certificate_chain` with webpki's message
  (`BadDer`) and no `details.reason`.
- A path through such an intermediate is rejected before its revocation and
  other path checks are judged, as OpenSSL's `verify_chain` runs
  `check_extensions` before `check_revocation` (`x509_vfy.c`): a revoked
  malformed intermediate is reported as the malformed extension.
- As in every chain error, `details.certificate` is the signer's report.
  The signer's own failure is judged before any usage, so it has no
  `required_eku`, `lifetime_signing` or `signing_time` detail.
- When one candidate lacks keyCertSign and another is rejected for a
  malformed extension, the malformed extension is reported: webpki ranks the
  callback's rejection above the unknown issuer a missing keyCertSign is
  reported through (PATH-T007 tracks that shared flag).
- The rule holds for a timestamp signer's chain too, with the same code and
  stage, and with `details.certificate_sha256` and `details.certificate`
  naming the TSA certificate. For an RFC 3161 token it is judged before
  TSA-003, so a TSA extKeyUsage that does not decode is
  `malformed_extension`, not `invalid_eku` at `timestamp`
  (`path-013-bad-tsa-malformed-eku`). A countersignature's TSA certificate
  goes through the same `TrustStore::verify`, which checks the signer's
  extensions before its usage (`engine/src/trust.rs`), so the order is the
  same there; no case pins it yet (PATH-T020). It holds for an RDP signer too, which
  is checked for a configured root first
  (`path-013-bad-rdp-leaf-malformed-eku-empty-store`).
- A certificate that also repeats an extension is reported for the repeat
  (PATH-014).
- Integrity-only verification builds no path, so the rule does not apply
  there, as OpenSSL checks no extension without path verification: a signer
  whose basicConstraints, keyUsage, extKeyUsage or subjectKeyIdentifier does
  not decode verifies, and so does a signature that embeds such a
  certificate.
- The rule judges a path, not a report. Every embedded certificate is
  reported, with or without a path, and the report decodes basicConstraints,
  keyUsage and extKeyUsage. One it cannot decode never fails the signature:
  the report marks it (PATH-015). So a signature whose path goes around a
  candidate with a malformed basicConstraints verifies and reports that
  candidate.
- A configured root is a key (PATH-011): its extensions are not judged, and
  one whose subjectKeyIdentifier does not decode still reads as having none
  (CRL-042). One exception stands, by history and not by this rule: a path
  that ends at a root whose basicConstraints, keyUsage or extKeyUsage does
  not decode fails as it did when that root's report could not be built
  (a root that repeats one of them is refused when the roots are loaded, by
  webpki): `certificate_chain_invalid` at `certificate_chain` for a
  signer, with a message that names the extension and no details. Whether it should
  verify is the owner's to decide (PATH-T016).

- **Status:** Decided
- **Decided by:** owner, PR #97 (PATH-T002); the report and integrity-only
  rule by the owner's answer of 2026-11-27, "follow OpenSSL", applied in
  PR #108 (PATH-T010)
- **Pins:** acceptance
- **Sources:**
  - OpenSSL 3.3 (7f736187) decodes a certificate's extensions only when it
    validates a path (`crypto/x509/v3_purp.c`,
    `ossl_x509v3_cache_extensions`, reached from `x509_vfy.c` and
    `X509_check_purpose`), not when it parses one (`crypto/x509/x_x509.c`),
    and with chain verification off (`CMS_NO_SIGNER_CERT_VERIFY` in
    `crypto/cms/cms_smime.c`) it checks none: the reason a report and an
    integrity-only verification do not fail on one.
  - OpenSSL 3.3 (7f736187) `crypto/x509/v3_purp.c:401-587`
    (`ossl_x509v3_cache_extensions` marks the certificate `EXFLAG_INVALID`
    when basicConstraints (454), keyUsage (490), extKeyUsage (534),
    subjectKeyIdentifier (552), authorityKeyIdentifier (556), subjectAltName
    (571), nameConstraints (574) or cRLDistributionPoints (577-579) is present
    and does not decode), `v3_purp.c:961-973` (`ossl_x509_likely_issued` fails
    when either certificate is invalid, so neither the leaf nor a CA can be
    linked to an issuer) and `crypto/x509/x509_vfy.c:545-561`
    (`X509_check_ca` is 0 for an invalid CA: `X509_V_ERR_INVALID_CA`).
    BoringSSL (289645a4) `crypto/x509/v3_purp.cc:255-419` does the same for
    the same eight (307, 323, 371, 377, 382, 396, 401, 404) and
    `v3_purp.cc:429-438` (`X509_check_issued`). Both agree with rssig on
    which extensions are judged; their decoders are more lenient in what
    decodes (below).
  - Bouncy Castle (bb81bfa7) rejects basicConstraints and keyUsage when it
    builds the certificate (`X509CertificateObject.java:311-356`),
    subjectAltName and nameConstraints in path validation
    (`RFC3280CertPathUtilities.java:1015-1022`, `1505-1512`) and
    cRLDistributionPoints when it checks revocation (`1765-1773`). Its
    validator does not read extKeyUsage (left to the caller),
    subjectKeyIdentifier or authorityKeyIdentifier: it differs for those
    three, where rssig takes OpenSSL's and BoringSSL's stricter reading.
  - webpki 0.103.16 `cert.rs` (`remember_cert_extension`) requires a
    SEQUENCE for each extension it keeps except keyUsage and decodes
    basicConstraints and extKeyUsage on every certificate and nameConstraints
    on a CA (`verify_cert.rs`, `check_issuer_independent_properties`); it
    does not decode subjectKeyIdentifier or authorityKeyIdentifier, nor
    subjectAltName or cRLDistributionPoints past their outer SEQUENCE
    without name constraints or its own revocation check, which rssig does
    not use.
  - Not followed: OpenSSL decodes an IA5String without checking its
    characters (`crypto/asn1/tasn_dec.c:930-977`, `asn1_ex_c2i` copies the
    bytes), so it accepts a subjectAltName or cRLDistributionPoints name
    holding a byte above 0x7F. rssig's decoder (`der` 0.7, `Ia5StringRef`)
    rejects it: X.680 defines IA5String as the 7-bit IA5 set, so the value is
    malformed, and rssig takes the fail-closed reading.
  - Not followed: rssig decodes each value with `x509-cert` 0.2 as strict
    DER, as RFC 5280 section 4.1 requires of a certificate; OpenSSL's d2i
    also accepts some BER (a BOOLEAN TRUE other than 0xFF, a non-minimal
    INTEGER). And `x509-cert`'s DirectoryString has no BMPString or
    UniversalString, so an ediPartyName in a subjectAltName,
    authorityKeyIdentifier or cRLDistributionPoints that uses one does not
    decode, where OpenSSL accepts it; nor does an authorityKeyIdentifier whose
    authorityCertSerialNumber is longer than `x509-cert`'s 20-octet serial
    bound allows. `x509-cert`'s GeneralName has no x400Address [3] choice,
    so a subjectAltName, nameConstraints, authorityKeyIdentifier or
    cRLDistributionPoints name that is one does not decode, where OpenSSL
    reads it (`GEN_X400`); PATH-T012 tracks reading it. Such a certificate
    fails the path in rssig and not in OpenSSL; the non-ASCII IA5String case
    and the unit test
    `only_the_extensions_rssig_or_webpki_decode_are_judged` pin this class.
  - Not followed: OpenSSL also marks a malformed proxyCertInfo, Netscape
    certificate type or RFC 3779 extension invalid, and an empty keyUsage.
    rssig decodes none of them, so they are unfamiliar extensions (PATH-006);
    a keyUsage without bits decodes and is judged by PATH-008.
- **Note:** Before this entry a malformed basicConstraints, keyUsage or
  extKeyUsage already failed the path from either certificate, and a
  nameConstraints from an intermediate, with a message from the decoder and no
  `details.reason`; the others, and nameConstraints in the leaf, read as
  absent and the path stood. The configured root is exempt as every anchor
  rule is (PATH-011); OpenSSL also judges a root it finds in its store.

### PATH-014: A path certificate that repeats an extension fails the path

A signing leaf or an intermediate that carries two extensions with the same
OID fails the path, whatever the extension (one rssig decodes or an
unfamiliar one), critical or not, and whether or not the two values are
equal. It is judged where PATH-013 is, and reported the same way:

- The signer fails before any path is built (after the check for a
  configured root): `certificate_chain_invalid` at `certificate_chain`, with
  `details.reason` `repeated_extension`, `details.extension` the repeated OID
  and `details.certificate_sha256` the signer, and `details.certificate` its
  report.
- An intermediate rejects each candidate path through it in the path
  callback, and path building goes on (PATH-009); it is named, with the same
  details, under the conditions PATH-013 gives for an intermediate. webpki
  itself rejects, before the callback, an intermediate that repeats an
  extension it keeps (basicConstraints, keyUsage, extKeyUsage,
  subjectAltName, nameConstraints or cRLDistributionPoints): that failure is
  `certificate_chain_invalid` at `certificate_chain` with webpki's message
  (`ExtensionValueInvalid`) and no `details.reason`. Such a candidate is
  passed over when a path through another one is accepted (PATH-009). What
  is reported when none is, for a certificate on no path too, is not this
  entry's: see the candidate rule `unparsed-candidate` and PATH-T019.
- The rule holds for a timestamp signer and an RDP signer too, with the same
  code, stage, `details.reason` and `details.extension`; an RDP signer is
  checked for a configured root first too
  (`path-014-bad-rdp-leaf-repeated-eku-empty-store`).
- A certificate with both defects is reported for the repeat: the first
  extension whose OID an earlier one carries, also when the value that does
  not decode sits before it.
- Integrity-only verification builds no path, so the rule does not apply
  there: a signer that repeats an extension verifies, as does a signature
  that embeds such a certificate.
  The owner's answer for PATH-013 (2026-11-27, applied in PR #108) covers
  the repeat: before it, one that repeated its basicConstraints, keyUsage or
  extKeyUsage failed with `invalid_certificate`, as its report could not be
  built. The report now marks the repeat (PATH-015).
- A configured root is a key (PATH-011) and is not judged.

- **Status:** Observed
- **Decided by:** —
- **Pins:** acceptance
- **Sources:**
  - RFC 5280 section 4.2: "A certificate MUST NOT include more than one
    instance of a particular extension."
  - Bouncy Castle (bb81bfa7)
    `core/src/main/java/org/bouncycastle/asn1/x509/Extensions.java:131-136`
    refuses to build the extensions of any certificate that repeats an OID
    ("repeated extension found"), unless the property
    `org.bouncycastle.x509.ignore_repeated_extensions` is set. rssig agrees
    with it for every extension.
  - OpenSSL 3.3 (7f736187) `crypto/x509/v3_lib.c:186-199` (`X509V3_get_d2i`
    returns NULL with `*crit = -2` for an extension found more than once) and
    `crypto/x509/v3_purp.c:401-587` (`ossl_x509v3_cache_extensions` marks the
    certificate `EXFLAG_INVALID` for that result, for the eight extensions
    PATH-013 names). BoringSSL (289645a4) `crypto/x509/v3_lib.cc:228-241` and
    `v3_purp.cc:255-419` do the same. Both agree with rssig for those eight.
  - Not followed: OpenSSL and BoringSSL look for a repeat only of the
    extensions they cache, so a certificate that repeats another extension
    (authorityInfoAccess, an unfamiliar OID) verifies there. rssig rejects it, as RFC 5280 and Bouncy Castle do: a relying
    party that read either instance could disagree with one that read the
    other, and no CA has a reason to issue such a certificate.
  - webpki 0.103.16 `x509.rs` (`set_extension_once`) rejects a repeat of an
    extension it keeps with `ExtensionValueInvalid`, and ignores a repeat of
    any other.
- **Note:** Before this entry a repeated subjectKeyIdentifier,
  authorityKeyIdentifier or unfamiliar extension passed (the first instance
  was read), and a repeat of an extension webpki keeps already failed the
  path with its message. Found in PR #97 (PATH-T013).

## Tier 2: availability

### PATH-009: A rejected candidate issuer does not stop path building

An otherwise valid CA missing keyCertSign does not prevent selection of an
acceptable alternative with the same subject and key, in either order.

- **Status:** Decided
- **Decided by:** written argument, PR #40 (PATH-T001)
- **Pins:** acceptance
- **Sources:**
  - Written argument: a valid embedded issuer must not be lost because
    another candidate was tried first (as TIME-008 for signing time).

### PATH-010: Cross-signed paths lead to the configured root

Among cross-signatures, the one leading to the configured root is chosen,
including when another appears first; changing the configured root changes
the selected chain. Adding an anchored variant to a cycle yields the direct
trusted path in either order. The first acceptable path is reported; no
shortest, newest or strongest preference is promised.

- **Status:** Decided
- **Decided by:** written argument, PR #40 (PATH-T001)
- **Pins:** acceptance
- **Sources:**
  - RFC 5280 section 6.1 (any path to a chosen trust anchor is acceptable).

### PATH-011: Configured anchors are keys

Only subject, public key and name constraints are taken from a configured
root. Its expiry, self-signature, BasicConstraints, path length, KeyUsage and
EKU are not checked as path rules, at the validation time or at a lifetime
signing time, so a lifetime path through a root re-issued after the signing
time is accepted.

- **Status:** Decided
- **Decided by:** written choice, PR #40 (PATH-T001), and kept as a decision for
  lifetime signing in the PR #43 review (TIME-T002). CRL-015 applies the same
  rule to CRL signing
- **Pins:** acceptance
- **Sources:**
  - webpki `anchor_from_trusted_cert`: an anchor is subject, key and name
    constraints.
  - RFC 5280 section 6.1.1 (d): trust anchor information is a name and key,
    optionally with constraints.
- **Note:** the cases pin the rule at the validation time only; no case pins
  a root re-issued after a lifetime signing time (PATH-T008).

## Tier 3: result diagnostics

### PATH-012: The reported anchor is the one whose constraints accepted the path

When configured roots share a subject and key, `trust.chain` reports the one
whose name constraints accepted the path.

- **Status:** Decided
- **Decided by:** review fix, PR #40 (the first run reported a root whose
  constraints had rejected the leaf)
- **Pins:** diagnostics
- **Sources:**
  - Written argument: the report must name the anchor webpki actually used.

### PATH-015: A certificate report marks an extension it cannot decode

A certificate report (the signer, each embedded certificate, each chain
certificate, a `parse` certificate choice, a certificate in an error's
details) decodes basicConstraints, keyUsage and extKeyUsage. For one that is
present and does not decode, or is repeated, the report is still built:

- its field (`basic_constraints`, `key_usage`, `extended_key_usage`) is
  null, as for an absent extension;
- `undecoded_extensions` lists `{"oid", "reason"}` for it, basicConstraints
  first, then keyUsage, then extKeyUsage. The reason is
  `malformed_extension` or `repeated_extension`, the names of
  `details.reason` in PATH-013 and PATH-014; a repeat is reported as one
  whether or not an instance is also malformed, and neither instance is
  decoded;
- every instance stays in `extensions` as DER;
- `undecoded_extensions` is left out when it is empty.

The field names only those three extensions, because they are the ones the
report decodes: it says what the report could not show and is no verdict on
the certificate. A repeat or a malformed value of another extension shows
only in `extensions`. Whether the certificate may be on a path is PATH-013's
and PATH-014's.

- **Status:** Observed
- **Decided by:** —
- **Pins:** diagnostics
- **Sources:**
  - The owner's answer for PATH-013 (2026-11-27): a report must not fail on
    an extension that does not decode, and marks it. The field's name, shape
    and order are the agent's choice in PR #108 (PATH-T010).
  - Written argument: a null field alone would read as an absent extension,
    and a consumer that trusts `key_usage: null` to mean "unrestricted" must
    be able to tell the two apart without decoding `extensions` itself.

## Candidate rules

Unnumbered. `tests/decision-claims.json` assigns these cases here until they name an entry.

- `attach`: cases that pin an existing PATH entry but do not name it yet: every format's untrusted-root case, verification against an empty trust store (PATH-001) and RDP's key-usage case.
- `unparsed-candidate`: an embedded certificate that webpki cannot parse, on no accepted path, where the result would otherwise be `untrusted_root`. webpki 0.103.16 parses each candidate (`Cert::from_der`) before it compares its subject (`verify_cert.rs:120-124`, `build_chain_inner`) and keeps that error, which outranks `UnknownIssuer` (`error.rs`, `rank`), so it is reported instead, even for a certificate on no path. PATH-T019 decides which is right, and needs an entry.
- `certificate-signature`: a certificate whose signature does not verify under its correct issuer's key breaks the path (`certificate_chain_invalid`); this needs a new entry. It differs from PATH-002, where the issuer is a same-name certificate with the wrong key.
