# PATH-T023 docs: Evaluate certval as the path and CMS layer

Task detail for **PATH-T023** in [TODO.md](../../TODO.md). This evaluates
whether rssig should use the pure-Rust `certval` crate (RFC 5280 path
building and validation) and its sibling `certval-cms` instead of
rustls-webpki =0.103.16 and rssig's own CMS code (engine/src/cms.rs), or
alongside them. It is an evaluation only: no package depends on either crate,
and nothing in `Cargo.toml` or `Cargo.lock` changed. The decision it leads to
is the owner's ([the question](#owner-question)), tracked as PATH-T024.

**Recommendation: stay on webpki.** certval is a careful RFC 5280 validator
with typed per-path results, and in places it is closer to RFC 5280 than
webpki (policy processing, name comparison). But measured on rssig's own
fixtures it **accepts 21 cases that rssig rejects**, 20 of them pinned by
Decided or Observed acceptance entries. It is built on a newer RustCrypto
generation than the engine (der 0.8, x509-cert 0.3, rsa 0.10), and its first
published release is a month old and still a release candidate. certval-cms
cannot parse an Authenticode signature at all. Adopting certval would replace
one set of adapter workarounds (the sentinel error, error ranking) with a
validator rssig would have to compose from certval's parts and maintain. A
wrapper around certval is not enough, because certval also rejects cases rssig accepts
(3 in the closest mode, 4 across all modes). Adopting it would also leave every PATH- and CRL- acceptance entry to be proved
again.

## What was read

Both crates were downloaded from crates.io into an empty scratch directory
on 2026-11-28 and read as data. Every `file:line` below is in that copy.

| Crate | Version | `.crate` SHA-256 | VCS commit (`.cargo_vcs_info.json`) |
|---|---|---|---|
| certval | 0.2.0-rc.4 (2026-11-18) | `7bec397c6deb5ebc13d05b628e1690ccd01b90ee480bae4630dc73600f0865c8` | `7fb74fd4d1a175642813738023c8bf77f3f292da` (path `certval` in carl-wallace/rust-pki) |
| certval-cms | 0.1.0-rc.2 (2026-11-15) | `62288a2ed332626656688e02490022c99dd393fc7f9062fd78f550567b86546d` | `9faf362d200fe5c8ca960dab87347c1008566962` (carl-wallace/certval-cms) |

`certval-cms` exists. Its README describes it as building, decrypting,
signing and verifying EnvelopedData, AuthEnvelopedData and SignedData, with
the certificate vetting done by certval (`src/vetting.rs:1-7`).

## 1. Fit with rssig's constraints

**Dependency graph.** A scratch crate depending on
`certval = { version = "=0.2.0-rc.4", default-features = false, features = ["revocation", "rsa", "sha1_sig"] }`
resolves 68 crates for `cargo tree -e normal,build` (deduplicated). None of
them is ring, aws-lc, OpenSSL, reqwest, tokio, hyper or rustls. The default
features are a different matter: `default = ["remote", "webpki"]`
(`Cargo.toml.orig`, `[features]`) resolves 224 crates, among them
`aws-lc-rs 1.19.0`, `aws-lc-sys 0.47.0`, `reqwest 0.13.5`, `tokio 1.54.1`,
`openssl-probe 0.2.2` and `rustls-webpki 0.103.17`. Those features are
forbidden by AGENTS.md, so certval would have to be taken with
`default-features = false`, and the dependency review would have to keep it
that way.

**A second RustCrypto generation.** certval is built on the generation after
the engine's:

| | engine today (`Cargo.lock`) | certval 0.2.0-rc.4 |
|---|---|---|
| der / spki / const-oid | 0.7.10 / 0.7.3 / 0.9.6 | 0.8.3 / 0.8.1 / 0.10.3 |
| x509-cert | 0.2.5 | 0.3.1 |
| rsa / p256 / p384 | 0.9.10 / 0.13.2 / 0.13.1 | 0.10.0 / 0.14.0 / 0.14.0 |
| sha1 / sha2 / digest / signature | 0.10.7 / 0.10.9 / 0.10.7 / 2.2.0 | 0.11.0 / 0.11.2 / 0.11.3 / 3.0.0 |
| cms | (none) | `=0.3.0-rc.2` (exact pin) |

Taking certval without moving the engine would build two copies of every
primitive and two ASN.1 stacks, with no type shared between them: a
`x509_cert::Certificate` from one is not the other's. Moving the engine
first is a migration of its own (every parser, cms.rs, report.rs and
domain.rs). certval also pins two release candidates exactly
(`cms = "=0.3.0-rc.2"`, `x509-ocsp = "=0.3.0-rc.1"`, `Cargo.toml.orig`), so
rssig could not take a fixed `cms` without a new certval. It adds
`ciborium`, `cidr`, `spin`, `readonly`, `subtle-encoding`, `log` and the
proc-macro crate `pkiprocmacros` as unconditional dependencies.

**no_std.** certval declares `#![cfg_attr(not(feature = "std"), no_std)]`
(`src/lib.rs:8`) and its README claims full path validation without `std`.
I could not build it for `thumbv7em-none-eabi` (installing the target was
not allowed in this session), so the no_std claim is **unverified**. The
engine's verify-core build would need that check before any adoption
(docs/testing.md).

**Injected roots, time and CRLs.** All three are possible without files or
network:

- Roots: `TaSource::new()` plus `CertVector::push` and `initialize()`
  (`src/source/ta_source.rs:234,310`); a root may also be an RFC 5914
  TrustAnchorInfo (`src/validator/pdv_trust_anchor.rs:83-192`).
- Embedded certificates: `CertSource::new()`, `push`, `initialize` and
  `find_all_partial_paths` (`src/source/cert_source.rs:647,691,1215`).
- CRLs: `MemoryCrlSource::add` (`src/source/memory_crl_source.rs:89`), or
  rssig's own implementation of certval's `CrlSource` trait
  (`src/environment/pki_environment_traits.rs:486-494`). Fetching exists
  only under `remote`.
- **Time is a trap.** An unset time of interest means "disabled" without
  `std` (`src/util/time_of_interest.rs:45-48`), and then every validity
  check is skipped (`src/validator/path_validator.rs:417-420`). With `std`
  the default is the system clock (`src/util/time_of_interest.rs:154,169-171`).
  rssig would have to set it on every call, and a test would have to show
  that it does.

**Settings are an untyped map.** `CertificationPathSettings` is keyed by
strings (`PS_* = "ps..."`, `src/validator/path_settings.rs:230-480`) with
generated getters and setters (`:487-1001`). It is not a typed
`VerifyOptions`. A misspelt or unset key silently takes the default, and
several defaults are fail-open for rssig (no time; EKU unchecked across the
path, `PS_EXTENDED_KEY_USAGE_PATH` false, `:837`).

**Other constraints.** `#![forbid(unsafe_code)]` (`src/lib.rs:3`). No
`anyhow`; errors are certval's own `Error` and `PathValidationStatus`
(`src/util/error.rs:13-101`), which rssig would map at its boundary.

## 2. Path validation

**RFC 5280 coverage.** `validate_path_rfc5280` (`src/validator/path_validator.rs:72-140`)
runs, in order: validity, excluded keys, trust-anchor membership,
RFC 5937 trust-anchor constraints, key sizes, signature algorithms,
basicConstraints and path length, names, certificate policies (graph-based,
RFC 9618), key usage, EKU, critical extensions, then signatures. That is
more than webpki offers. Certificate policies are processed at all, and names
are compared case- and whitespace-insensitively after a byte comparison
(`src/util/pdv_utilities.rs:1062-1101`), which is relevant to CRL-T035. Where
it departs from rssig's profile:

- **The target's basicConstraints is not checked.** Only intermediates are
  (`path_validator.rs:168`), so a leaf with `cA=TRUE` is accepted as a code
  signer, against PATH-003.
- **The target's EKU may be absent.** A target without extKeyUsage satisfies
  any configured EKU (`path_validator.rs:889-893`), against PATH-007. Across
  the path, EKU is checked only when `PS_EXTENDED_KEY_USAGE_PATH` is set, and
  then the trust anchor's own EKU starts the intersection
  (`path_validator.rs:821`), against PATH-011.
- **An intermediate without keyUsage is rejected,** described as "a
  deliberate fail-closed choice" (`path_validator.rs:757-766`), where PATH-008
  accepts it.
- **An extension that does not decode is read as absent.** `parse_extensions`
  discards the decode error (`src/validator/pdv_certificate.rs:119-139`).
  `check_critical_extensions` refuses an undecodable extension only when its
  OID was "processed" for the path (`path_validator.rs:940-941`).
  subjectKeyIdentifier, authorityKeyIdentifier and cRLDistributionPoints
  never are, and subjectAltName only under name constraints
  (`path_validator.rs:614`). That is looser than PATH-013.
- **A repeated extension fails only when it is critical**
  (`path_validator.rs:957-959`). That is looser than PATH-014.
- **Trust-anchor constraints are all or nothing.** With
  `PS_ENFORCE_TRUST_ANCHOR_CONSTRAINTS` the caller must also call
  `enforce_trust_anchor_constraints` (`path_validator.rs:995-1141`;
  `validate_path_rfc5280` does not). That applies the root's name constraints
  (PATH-005) and also its keyUsage and path length (`:1138-1141`), which
  PATH-011 says are not judged. Without it, the root's name constraints are
  ignored. The anchor's validity is checked by default
  (`PS_ENFORCE_TRUST_ANCHOR_VALIDITY`, `path_settings.rs:740`; check at
  `path_validator.rs:444`). rssig's root-is-a-key rule (PATH-011) can be had
  only by building a TrustAnchorInfo from the root's name, key and name
  constraints in rssig's own code.

**Failure reporting.** A failed path returns one typed
`PathValidationStatus` (for example `InvalidKeyUsage`, `EncodingError`,
`UnprocessedCriticalExtension`, `NameConstraintsViolation`), and the results
carry a failure index (`set_failure_index`, trust anchor = 0). It is typed
and per candidate path. That would remove rssig's sentinel error and its
dependence on webpki's ranking (PATH-T011, PATH-T019, PATH-T007), because
rssig would rank the per-path results itself. The status is coarse, though:
`InvalidKeyUsage` stands for both a keyUsage and an EKU failure
(`path_validator.rs:764-775` for keyUsage, `:860-862,908` for EKU), and a malformed basicConstraints
or keyUsage surfaces as `MissingBasicConstraints` or `InvalidKeyUsage`, not
as an encoding error. rssig's `invalid_eku` versus `invalid_key_usage` and its
`malformed_extension` reason would need rssig's own checks.

**Candidate paths.** The caller asks for every path
(`PkiEnvironment::get_paths_for_target`, `src/environment/pki_environment.rs:901-922`)
and validates each, choosing the order and the result to report. That is
what certval-cms does (`src/vetting.rs:168-172,194-200,280-292`). Issuers are found
by authorityKeyIdentifier first and by name second
(`cert_source.rs:1743-1756,1866-1880`), compatible with PATH-002.

**Bounds.** Path length is capped at 15 non-self-issued certificates
(`PS_MAX_PATH_LENGTH_CONSTRAINT`, `path_settings.rs:292`), and the partial-path
builder recurses at most 13 passes (`cert_source.rs:1705`). Name-constraint
matching has a work budget (`path_validator.rs:510,625`), and policy
processing has a node pool (`ProcessingLimitExceeded`,
`src/validator/policy_utilities.rs:65`). There is **no caller-controlled
budget for path building**: `find_all_partial_paths` is "a slow recursive
builder intended for offline use" (`cert_source.rs:1213-1214`). It verifies
a signature for each certificate against each candidate issuer on every pass
(`cert_source.rs:1593,1658`), with no count limit, so its work grows with the
square of the embedded certificates. certval-cms bounds its own preparation
separately (8 intermediates, 64 candidates; `src/vetting.rs:255,260`). The
existing verification budget (LIMIT-T002, done) counts webpki's search
reservations and would not see this builder. It would have to be extended to
charge certval's signature checks, which is new work.

## 3. Revocation

certval checks CRLs and OCSP responses it is given (`check_revocation_local`,
`src/revocation/check_revocation.rs:308-420`). Its README says delta CRLs,
`onlySomeReasons` partitions, indirect CRLs and CRLs signed by any key other
than the certificate's issuer key are unsupported and fail closed
(README, "Not Supported"). Its answer is a status per certificate, not the
evidence rssig records (which CRL was chosen, why another was set aside).
Measured differences:

- With two current CRLs of the same issuer, the same thisUpdate and
  CRLNumber, one listing the issuer, certval took the first it was given:
  `crl-revoked-issuer-after-good-root-crl` verifies, while the same two CRLs
  in the other order revoke. rssig revokes in both orders (claimed in
  `tests/decision-claims.json`, no entry yet).
- On the self-issued rollover path, certval accepts what CRL-008 rejects as
  ambiguous issuer keys (two cases).
- certval requires cRLSign on a configured root that signs a CRL. CRL-015
  exempts a configured root, so `crl-015-root-no-crl-sign-accepted` fails
  in certval with `RevocationStatusNotDetermined`.

**Retrieval.** rssig's split (docs/crl-retrieval.md, CRL-023, CRL-039), in
which the engine judges evidence and the application's `HttpCrlSource`
fetches, has no counterpart in certval's own fetching (`remote`, reqwest,
`PS_CRL_TIMEOUT` and friends in `path_settings.rs:292-470`). That fetching
is unusable here in any case. rssig could keep `Retrieval` and `CrlSource`
and hand certval only verified bytes, but then certval would decide
revocation, and each of the 30 CRL- acceptance entries (listed in section 7)
would have to be proved again against it. If rssig instead kept
deciding revocation itself, certval would only build paths and webpki's
callback role would simply move to a loop over certval's paths.

## 4. CMS: certval-cms

The entry point is `CmsEnvironment::verify_signed_data(content_info, detached, settings, policy)`
(`src/verify.rs:393-399`). **It cannot verify an Authenticode signature.**
eContent is decoded as an OCTET STRING (`src/verify.rs:126-148`), and
Authenticode's SpcIndirectDataContent is a SEQUENCE (engine/src/cms.rs:80-86).
Measured: for `good-path-basic.exe` and `good-pe32.exe`, `verify_signed_data`
returns `Asn1(TagUnexpected { expected: OCTET STRING, actual: SEQUENCE })`.
Beyond that, compared with docs/cms.md:

- **Looser than rssig on 8 of the 13 CMS acceptance entries:**
  - The signed attributes are re-encoded as parsed under BER rather than
    taken as the signer's DER (`src/verify.rs:123,324`; CMS-008).
  - The digestAlgorithms set is not consulted (`src/verify.rs:133`; CMS-007).
  - The first matching certificate is the signer (`src/verify.rs:267`), with
    and no ambiguity check (CMS-004).
  - A subjectKeyIdentifier signer and signer certificates from outside the
    message are accepted (`src/verify.rs:270-274`; CMS-003).
  - Only content-type, message-digest and signing-certificate-v2 are checked
    for single values (`src/verify.rs:173-196`; CMS-009).
  - A SignerInfo without signed attributes verifies for id-data
    (`src/verify.rs:326-333`; CMS-006).
  - Algorithm parameters are not checked (CMS-002).
  - BER input and SignedData versions are not limited (CMS-010).
  - Possibly CMS-011 as well. const-oid 0.10 is reported to accept a padded
    arc in an unknown attribute's OID; not checked here (compare PATH-T015).
- **Missing entirely:** unsigned attributes are never read, so there are no
  countersignatures, RFC 3161 tokens or nested signatures (CMS-013, and the
  TSA- index). There are no format bindings (page hashes, SIP digests).
- **Diagnostics missing:** there is no ambiguity error with the number of
  matching certificates (CMS-014). Most CMS defects are `InvalidInput(String)`,
  and a digest mismatch is `Crypto(String)` (`src/error.rs:136-158`; CMS-015).
- **Vetting** (certval path validation of the signer) runs only when settings
  are passed (`src/verify.rs:348-353`). It then requires only
  digitalSignature or nonRepudiation (`src/vetting.rs:74-77`).
- **Dependencies:** `getrandom` with `sys_rng` is unconditional
  (`Cargo.toml.orig`; used at `src/software.rs:34,59-60`, `src/content.rs:101`,
  `src/decrypt.rs:273`), an OS call in the engine. The encryption and KEM
  crates (aes, aes-gcm, aes-kw, ml-kem, hkdf, ...) come in even for
  verification.
- **No tests in the package** (`include` lists only `src`, README, CHANGELOG
  and licences); its dev-dependencies show that upstream tests call the
  `openssl` command.

certval-cms is not an option for rssig. Its CMS layer would have to be
rssig's own in any case, as it is today.

## 5. Health

- **Releases.** certval's first published release is 0.2.0-rc.1 of
  2026-10-29; rc.2, rc.3 and rc.4 followed by 2026-11-18. The CHANGELOG says
  0.1.0 to 0.1.4 (2022-2023) "were used internally and never published"
  (`CHANGELOG.md:5-7,48-50`). certval-cms rc.1 and rc.2 date from 2026-11-12
  and 2026-11-15. crates.io counts 3,652 and 690 downloads.
- **Maintainers.** The crates.io owners of both are the accounts
  `carl-wallace` and `agalustyan`. Both are dual-licensed `Apache-2.0 OR MIT`,
  compatible with rssig's Apache-2.0. The MSRV is 1.89.
- **Tests.** The README says CI runs NIST PKITS (sections 4.1-4.14 and 4.16,
  in 17 algorithm editions) and x509-limbo at `554528a`: 9,747 of 9,802 cases
  pass, and all 55 mismatches are certificates the corpus rejects and certval
  accepts. 3 of those are `crl::` cases where certval relies on a CRL that
  breaks the CRL profile (README, "Security Warning"). The test data is not
  in the package (`Cargo.toml.orig`, `include`), so this is the authors'
  claim, not something I checked. The README also says the code "has never
  been independently audited".
- **Fuzzing.** The package and README mention none; whether the repository
  fuzzes is not determined.
- **Advisories.** I could not query the RustSec advisory database (the
  GitHub API answered 403 in this session); **not determined**.
- **Unsafe.** `forbid(unsafe_code)` in certval (`src/lib.rs:3`). certval-cms
  has no `unsafe` in `src` but does not forbid it.

## 6. Measured comparison

**Method.** A scratch binary, outside the repository, ran over a copy of
`tests/fixtures`. For each case it:

1. extracts the PKCS#7 from the PE certificate table;
2. takes the SignerInfo's issuerAndSerialNumber certificate as the target and
   the other embedded certificates as candidates (`CertSource`), with the
   case's `--roots` as trust anchors (`TaSource`);
3. calls `find_all_partial_paths` and `get_paths_for_target`;
4. runs `validate_path_rfc5280` (and `check_revocation_local` with the case's
   `--crl` files in a `MemoryCrlSource`) on each path, accepting on the
   first that passes.

This is how certval-cms vets a signer (`src/vetting.rs:168-200`). Settings:
time of interest 1800000000, `PS_EXTENDED_KEY_USAGE = [1.3.6.1.5.5.7.3.3]`,
and every AIA, CRL DP and OCSP fetch off. Five modes:

- `path`: EKU across the path on, revocation off;
- `path-noeku`: as `path`, with EKU across the path off;
- `path-prof`: as `path`, with trust-anchor validity off and trust-anchor
  constraints enforced, the closest settings to PATH-005 and PATH-011;
- `rev` and `rev-prof`: `path` and `path-prof` with revocation on.

**Coverage.** These are all 107 `tests/cases.json` cases whose input is a
`*path*.exe` fixture verified with `--roots`: the whole PATH-001 to PATH-014
set (PATH-015 pins a report's diagnostics and is not measured here), the PATH-T001 corpus, the PATH-013 malformed-extension and PATH-014
repeated-extension fixtures, and the CRL cases built on the path fixtures.
106 of them ran with revocation (one case is `--no-revocation`). Not
compared:

- `--integrity-only` and `parse` cases (no path is built);
- in the path modes, the 18 cases whose expected failure is at the revocation
  stage, and the 2 CRL-008 cases (`certificate_chain_invalid`,
  `ambiguous_issuer_keys`), which only a revocation run can decide (20);
- in the revocation modes, `--fetch-crls` cases, since certval cannot use
  rssig's source (11).

Whole-signature behavior (CMS, timestamps, page hashes) is not compared;
this is path validation alone.

**Results** (agree / certval accepts where rssig rejects / certval rejects
where rssig accepts / not compared):

| Mode | Agree | Accepts, rssig rejects | Rejects, rssig accepts | Not compared |
|---|---|---|---|---|
| `path` | 64 | 20 | 3 | 20 |
| `path-noeku` | 64 | 21 | 2 | 20 |
| `path-prof` | 66 | **19** | 2 | 20 |
| `rev` | 69 | 22 | 4 | 11 |
| `rev-prof` | 71 | **21** | 3 | 11 |

**Every case certval accepts and rssig rejects** (`rev-prof`, the closest
settings). The PATH- rows hold in every mode. The last three rows are
measured only in the revocation modes; the path modes leave them out:

| Case | Entry (status) | rssig `code` (`details.reason`) | Why certval accepts |
|---|---|---|---|
| `path-003-bad-leaf-ca` | PATH-003 (Decided) | `certificate_chain_invalid` | target basicConstraints unchecked |
| `path-007-bad-leaf-no-eku` | PATH-007 (Decided) | `invalid_eku` | target without EKU passes |
| `path-013-bad-leaf-malformed-san` | PATH-013 (Decided) | `certificate_chain_invalid` (`malformed_extension`) | SAN not processed without name constraints |
| `path-013-bad-leaf-malformed-ski` | PATH-013 | `certificate_chain_invalid` (`malformed_extension`) | SKI never processed |
| `path-013-bad-leaf-malformed-aki` | PATH-013 | `certificate_chain_invalid` (`malformed_extension`) | AKI never processed |
| `path-013-bad-leaf-malformed-crldp` | PATH-013 | `certificate_chain_invalid` (`malformed_extension`) | CRL DP not processed in validation |
| `path-013-bad-leaf-san-non-ascii` | PATH-013 | `certificate_chain_invalid` (`malformed_extension`) | as SAN |
| `path-013-bad-ca-malformed-san` | PATH-013 | `certificate_chain_invalid` (`malformed_extension`) | as SAN |
| `path-013-bad-ca-san-not-a-sequence` | PATH-013 | `certificate_chain_invalid` | as SAN |
| `path-013-bad-ca-malformed-ski` | PATH-013 | `certificate_chain_invalid` (`malformed_extension`) | as SKI |
| `path-013-bad-ca-malformed-aki` | PATH-013 | `certificate_chain_invalid` (`malformed_extension`) | as AKI |
| `path-013-bad-ca-malformed-crldp` | PATH-013 | `certificate_chain_invalid` (`malformed_extension`) | as CRL DP |
| `path-014-bad-leaf-repeated-ski` | PATH-014 (Observed) | `certificate_chain_invalid` (`repeated_extension`) | non-critical repeat ignored |
| `path-014-bad-leaf-repeated-unfamiliar` | PATH-014 | `certificate_chain_invalid` (`repeated_extension`) | as above |
| `path-014-bad-leaf-repeated-and-malformed-reports-the-repeat` | PATH-014 | `certificate_chain_invalid` (`repeated_extension`) | as above |
| `path-014-bad-ca-repeated-ski` | PATH-014 | `certificate_chain_invalid` (`repeated_extension`) | as above |
| `path-014-bad-ca-repeated-san` | PATH-014 | `certificate_chain_invalid` | as above |
| `path-014-bad-ca-repeated-and-malformed-reports-the-repeat` | PATH-014 | `certificate_chain_invalid` (`repeated_extension`) | as above |
| `crl-revoked-issuer-after-good-root-crl` | claimed, no entry | `certificate_revoked` | first of two equal CRLs decides |
| `crl-008-self-issued-rollover-with-both-crls-is-rejected` | CRL-008 (Decided) | `certificate_chain_invalid` (`ambiguous_issuer_keys`) | no ambiguity rule |
| `crl-008-self-issued-rollover-with-a-differently-encoded-crl-is-rejected` | CRL-008 | `certificate_chain_invalid` (`ambiguous_issuer_keys`) | as above |

Mode-dependent accepts:

- `path-005-bad-root-name` (PATH-005, root name constraints) is accepted
  unless trust-anchor constraints are enforced.
- `path-007-bad-ca-eku` (PATH-007) is accepted with EKU across the path off.
- `path-013-bad-ca-malformed-ski-revoked-reports-the-extension` is accepted
  when revocation is off, and rejected as revoked when it is on.

Cases certval rejects and rssig accepts:

- `path-008-good-ca-no-ku` (PATH-008): `InvalidKeyUsage`, every mode.
- `path-011-good-root-profile` (PATH-011): the root's `serverAuth` EKU starts
  the path intersection, or under `-prof` the root's keyUsage fails
  `enforce_trust_anchor_constraints`. It passes only in `path-noeku`, which
  gives up PATH-007 for CAs.
- `path-011-good-root-expired` (PATH-011): `InvalidNotAfterDate` at the
  anchor, unless trust-anchor validity is off.
- `crl-015-root-no-crl-sign-accepted` (CRL-015): `RevocationStatusNotDetermined`.

No setting combination reproduces PATH-005, PATH-007 and PATH-011 together.

Where certval and rssig agree on a rejection, the reason often differs:

- `path-013-bad-ca-malformed-bc` and `path-013-bad-ca-malformed-ku` fail as
  `MissingBasicConstraints` and `InvalidKeyUsage`, because the malformed
  extension reads as absent.
- `path-004-bad-pathlen` finds no path at all (`NoPathsFound`), rather than
  `InvalidPathLength`.
- The leaf's malformed basicConstraints, keyUsage, EKU and nameConstraints
  fail as `EncodingError`.

The harness is in the appendix; it ran in under a second for all 533 runs.

## 7. Migration cost if adopted

- **engine/src/trust.rs** (3,870 lines, 150 `webpki` references): replaced,
  not edited.
  - Out: the path callback, the MALFORMED_INTERMEDIATE sentinel (`:1288`),
    `path_error` (`:916`), `search_limit` (`:2072`) and the webpki CRL glue
    (`webpki_revocation_error`, `crl_rejection_reason`, `:2305,2500`).
  - In: a loop over certval's paths and a validator of rssig's own.
    `validate_path_rfc5280` cannot be used as it is. A layer around it can
    only add rejections, and it rejects up to four cases rssig accepts
    (section 6). rssig would compose its own order of certval's public
    checks (`check_validity`, `check_basic_constraints`, `check_names`,
    `check_certificate_policies_graph`, `check_extended_key_usage`,
    `check_critical_extensions`, `verify_signatures`;
    `path_validator.rs:154-1215`, `policy_graph.rs:40`). Then it needs:
    - rssig's own check in place of `check_key_usage`, which rejects a
      keyUsage-less CA (PATH-008);
    - the root handed over as a TrustAnchorInfo carrying only name, key and
      name constraints, so no validity, keyUsage or EKU of the root is
      judged (PATH-011), with TA constraints enforced so that its name
      constraints apply (PATH-005);
    - added rejections for what certval accepts:
      - the target's basicConstraints (PATH-003);
      - the target's EKU (PATH-007);
      - every extension decoding (PATH-013);
      - no repeated extension (PATH-014);
    - the LIMIT-T002 budget extended to certval's path builder.
    The alternative is a fork of certval, or patches upstream.
  - rssig's own CRL evaluation (`evaluate_crls`, `:1540`) must stay.
    certval's revocation rejects CRL-015's configured root without cRLSign
    and accepts what CRL-008 rejects (section 3).
- **engine/src/rdp.rs**: the usage search and its webpki-version audit
  (`:218,284-311,916-935`, LIMIT-T007) are re-argued against certval.
- **The rest of the trust module:**
  - engine/src/trust/crosscheck.rs (30 `webpki` references) is the
    revocation-crosscheck feature (CRL-T011), which re-runs webpki's
    revocation; it is dropped or rewritten against certval.
  - engine/src/trust/error.rs and engine/src/trust/loading.rs (3 and 2
    references) map webpki errors and load anchors through webpki.
  - engine/src/crypto.rs is the RustCrypto adapter for webpki's signature
    traits; it would be redone for certval's verification callbacks.
- **engine/src/retrieval.rs**: 3 `webpki` references in comments and tests
  (`:766,1372,3740`); little changes structurally.
- **Tests that name webpki:**
  - engine/src/tests/certificate_paths.rs (8) and
    engine/src/tests/crl_applicability.rs (4);
  - tests/cli/certificate_paths.rs (14), tests/cli/trust_loading.rs and
    tests/cli/crl_applicability.rs;
  - 16 mentions in tests/fixtures/manifest.json provenance.
- **CMS** (engine/src/cms.rs): unchanged; certval-cms cannot replace it.
- **Everything else:** a move of the whole engine to der 0.8 / x509-cert 0.3
  (or two stacks side by side), the fuzz targets and `fuzz/Cargo.lock`, and
  the dependency review of both packages.
- **Tasks it would close or make moot:** PATH-T011, PATH-T019 and PATH-T007
  (ranking becomes rssig's own), CRL-T035 in part (certval's name comparison),
  and the PATH-006 hardening in PATH-T022. That task was in progress in
  another PR and not yet on `main` when this was written; it was opened
  because webpki 0.103.17 is reported to accept a critical SCT-list
  extension, which this evaluation did not check.
- **Tasks it would create:**
  - the validator of rssig's own above;
  - a no_std build check;
  - the budget extension;
  - the stack migration;
  - a re-proof of the 13 PATH- acceptance entries (PATH-001 to PATH-011,
    PATH-013, PATH-014) and of the 30 CRL- acceptance entries (CRL-001 to
    CRL-025, CRL-041, CRL-044, CRL-045, CRL-048, CRL-050), since each is
    judged per built path;
  - an update of the 42 lines in docs/path.md, docs/crl.md and
    docs/certificate-paths.md that name webpki (5 of them cite 0.103.16).
- **Risk:** high. 28 measured cases that rssig's own composition must get
  right: the 21 accepts and 3 rejects of the closest mode, plus 3 accepts
  and 1 reject that depend on settings. That is on a validator that is a month into its public life and a
  release candidate. The fixtures measure only what rssig has thought to
  pin.

## What would change the recommendation

- certval reaches a final 0.2.0 or later, fixes the target basicConstraints
  and EKU-absent acceptances, or refuses an undecodable or repeated extension
  of any type. rssig's own composition would then shrink to PATH-008,
  PATH-011 and the CRL rules.
- The engine moves to der 0.8 / x509-cert 0.3 for other reasons, which
  removes the two-stack cost.
- webpki keeps moving in ways that loosen rssig's acceptance (PATH-T022 is
  the first such report, for 0.103.17), so that wrapping it costs more than
  composing a validator from certval.
- rssig needs certificate-policy processing, which certval has and webpki
  lacks.

None holds today. PATH-T005 (AIA) does not change this either: certval's
AIA chasing is part of `remote`, which is unusable here, so rssig's
retrieval boundary would carry it in either case.

## Owner question

### Question 1: Should certval replace webpki as rssig's path validator?

Entry or task: PATH-T024 (Open, owner decision). It touches 43 acceptance
entries: PATH-001 to PATH-011, PATH-013 and PATH-014, and the 30 CRL-
acceptance entries listed in section 7, mostly Decided. Cases: the 28 named in section 6 (21 accepts
and 3 rejects under `rev-prof`, plus 3 mode-dependent accepts and
`path-011-good-root-expired`).

**Today:** rssig builds paths with rustls-webpki =0.103.16 through a
RustCrypto adapter, decides revocation itself in webpki's path callback, and
enforces PATH-013/014 and its own EKU and key-usage rules around webpki.

**References:** OpenSSL and Bouncy Castle, which decide path questions
(docs/decisions.md), say nothing about which Rust library to use; this rests
on the measurement above. certval is neither a reference nor citable as
evidence (AGENTS.md).

**Options**

A. **Stay on webpki** (recommended). Record this evaluation and revisit
   under the conditions above.
   - Pros: no acceptance change; no second RustCrypto generation; keeps the
     audited workarounds and their tests.
   - Cons: the sentinel error and webpki's ranking stay (PATH-T011,
     PATH-T019, PATH-T007), and so do the re-audits on each webpki update.
   - Now: nothing changes; 0 cases, 0 entries, 0 code.
   - Later: fully reversible; the evaluation can be rerun against a newer
     certval with the appendix harness.

B. **Replace webpki with a validator rssig composes from certval's parts.**
   **Fails open where rssig's composition misses a rule:** certval alone
   accepts 21 cases rssig rejects.
   Use certval's path builder and its public checks, but not
   `validate_path_rfc5280` as it is. rssig:
   - replaces its keyUsage check (PATH-008);
   - hands the root over as name, key and name constraints only (PATH-005,
     PATH-011);
   - adds the rejections certval lacks (PATH-003, 007, 013, 014);
   - keeps its own CRL evaluation (CRL-008, CRL-015);
   - adds a path budget.

   A wrapper alone cannot do this: it could not undo the cases certval
   rejects and rssig accepts (3 under `rev-prof`, 4 across modes). The other route is a fork or upstream patches.
   - Pros: typed per-path results that rssig ranks itself; policy
     processing; RFC 5280 name comparison; no dependence on webpki's Web PKI
     choices.
   - Cons: **fails open wherever rssig's composition misses a rule**. Measured,
     28 cases depend on it; unmeasured ones are unknown. It needs the der 0.8
     migration or two stacks, and depends on a release-candidate crate a
     month into its public life.
   - Now:
     - trust.rs (~3,900 lines), trust/crosscheck.rs and the crypto adapter
       rewritten;
     - rdp.rs re-argued;
     - 43 acceptance entries re-proved (13 PATH-, 30 CRL-);
     - all 107 cases re-verified;
     - a no_std check.
   - Later: hard to reverse once the entries cite certval behavior.

C. **Add certval as a test-only cross-check**, like
   `revocation-crosscheck`: run certval beside webpki in tests and fail on
   any unlisted disagreement.
   - Pros: a second Rust opinion on every path fixture, with no product
     change.
   - Cons: certval disagrees by design on 21+ cases, so the allowlist is
     large; it adds a second RustCrypto generation to the dev graph; and the
     evidence for a disputed result stays OpenSSL and Bouncy Castle anyway.
   - Now: a dev-dependency, a test module and an allowlist of the section 6
     disagreements.
   - Later: easy to remove.

**Recommendation:** A. B trades two known, tested webpki workarounds for a
validator rssig assembles itself. That validator has one replaced check, a
reshaped anchor, four added rejections and rssig's CRL rules, all over a
pre-release crate, and acceptance is at risk wherever one is missed.
C costs more than the opinion is worth while the references are OpenSSL and
Bouncy Castle. It would change to B if certval closes the target and
extension gaps above and the engine moves to der 0.8 for its own reasons.

**Reply with:** "1 A".

## Appendix: the harness

`Cargo.toml` dependencies:
`certval = { version = "=0.2.0-rc.4", default-features = false, features = ["revocation", "rsa", "sha1_sig"] }`,
`cms = "=0.3.0-rc.2"`, `der = "0.8.3"` (alloc, derive, oid),
`x509-cert = "0.3.0"` (pem), `const-oid = "0.10.2"`. It reads one line per
case: id, input, roots, CRLs and mode, taken from `tests/cases.json`.

<details>
<summary>src/main.rs (core)</summary>

```rust
fn run(fx: &Path, input: &str, roots: &str, crls: &str, mode: &str) -> std::result::Result<String, String> {
    let p7 = pe_pkcs7(&fs::read(fx.join(input)).map_err(|e| e.to_string())?)?; // security directory, WIN_CERTIFICATE body
    let ci = ContentInfo::from_der(&p7).map_err(|e| format!("contentinfo: {e}"))?;
    let sd: SignedData = ci.content.decode_as().map_err(|e| format!("signeddata: {e}"))?;
    let certs: Vec<Certificate> = /* CertificateChoices::Certificate entries of sd.certificates */;
    let SignerIdentifier::IssuerAndSerialNumber(ias) = &sd.signer_infos.0.iter().next().ok_or("no signer")?.sid else { return Err("ski sid".into()) };
    let leaf_idx = certs.iter().position(|c| c.tbs_certificate().issuer() == &ias.issuer
        && c.tbs_certificate().serial_number() == &ias.serial_number).ok_or("signer cert not found")?;

    let mut cps = CertificationPathSettings::new();
    cps.set_time_of_interest(TimeOfInterest::from_unix_secs(1_800_000_000).unwrap());
    cps.set_extended_key_usage(vec!["1.3.6.1.5.5.7.3.3".to_string()]);
    cps.set_extended_key_usage_path(!mode.contains("noeku"));
    if mode.contains("prof") {
        cps.set_enforce_trust_anchor_validity(false);
        cps.set_enforce_trust_anchor_constraints(true);
    }
    let with_rev = mode.contains("rev");
    cps.set_check_revocation_status(with_rev);
    cps.set_check_ocsp_from_aia(false);
    cps.set_check_crldp_http(false);
    cps.set_retrieve_from_aia_sia_http(false);

    let mut env = PkiEnvironment::new();
    env.populate_5280_pki_environment();
    let mut tas = TaSource::new();
    for each root certificate (DER, or each certificate of a PEM file) { tas.push(CertFile { filename, bytes }); }
    tas.initialize()?;
    env.add_trust_anchor_source(Box::new(tas));
    let mut cs = CertSource::new();
    for each embedded certificate other than the signer { cs.push(CertFile { filename, bytes }); }
    cs.initialize(&cps)?;
    cs.find_all_partial_paths(&env, &cps);
    env.add_certificate_source(Box::new(cs));
    if with_rev {
        let mcs = MemoryCrlSource::new();
        for each --crl file { mcs.add(&bytes); }
        env.add_crl_source(Box::new(mcs));
    }

    let mut target = PDVCertificate::try_from(certs[leaf_idx].to_der().unwrap().as_slice())?;
    target.parse_extensions(EXTS_OF_INTEREST);
    let mut paths = vec![];
    if let Err(e) = env.get_paths_for_target(&target, &mut paths, 0, cps.get_time_of_interest()) {
        return Ok(format!("REJECT\tget_paths: {e:?}"));
    }
    if paths.is_empty() { return Ok("REJECT\tNoPathsFound (0 paths)".into()); }
    let mut errs = vec![];
    for p in &paths {
        let mut r = CertificationPathResults::new();
        let pcps = if mode.contains("prof") {
            match enforce_trust_anchor_constraints(&cps, &p.trust_anchor) {
                Ok(c) => c,
                Err(e) => { errs.push(format!("ta-constraints {e:?}")); continue; }
            }
        } else { cps.clone() };
        match validate_path_rfc5280(&env, &pcps, p, &mut r)
            .and_then(|()| check_revocation_local(&env, &pcps, p, &mut r)) {
            Ok(()) => return Ok(format!("ACCEPT\tpaths={}", paths.len())),
            Err(e) => errs.push(format!("{e:?} at index {:?}", r.get_failure_index())),
        }
    }
    Ok(format!("REJECT\tpaths={} [{}]", paths.len(), errs.join(", ")))
}
```

</details>
