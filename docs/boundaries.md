# Current boundaries

What rssig verifies today and what it does not. Format details and limits are
in each format's document under `docs/`.

Embedded PE32/PE32+, MSI/MSP CFB v3/v4, and standard-reserve single-volume CAB signatures, SHA-256/384/512, RSA PKCS#1 v1.5 (2048+ bits),
ECDSA P-256/SHA-256 and P-384/SHA-384, nested signatures, page hashes, RFC 3161,
and PKCS#9 countersignatures are supported. SHA-1 image/CMS/timestamp digests
require `--allow-sha1`; SHA-1 certificate/CRL chains are not supported.
MSI package/extended metadata hashes and limits are documented in `docs/msi.md`.
MSP patches use the same MSI SIP, `verify_msi` entry point, error codes, and
`msi_authenticode` JSON format. Verification needs no original MSI; patch
applicability, database semantics, and Windows patch authorization are not checked.
CAB layouts and limits are documented in `docs/cab.md`.
PowerShell hash-comment signatures for `.ps1`, `.psm1`, and `.psd1`, including strict
UTF-8 and BOM-marked UTF-16LE/BE, are supported; see `docs/powershell.md` for limits.
PowerShell XML-comment `.ps1xml` signatures support BOM-less ASCII and BOM-marked
UTF-8/UTF-16LE/BE; see `docs/powershell-xml.md`. They use the same SIP identity and
shared verification engine as hash-comment scripts, not XMLDSig.
Windows Script Host `.vbs`/`.vbe`/`.js`/`.jse` and single-job `.wsf` signatures are supported;
see `docs/wsh.md` for strict encoding/block limits and opaque encoded-text handling.
RDP detached CMS over selected settings is supported; `rdp` JSON reports signed and
unsigned settings explicitly. See `docs/rdp.md` for canonicalization and trust limits.
MSIX/AppX package and bundle embedded signatures, package components, block maps,
Publisher binding, and embedded package verification are supported; see `docs/appx.md`
for ZIP/compression and bundle limits. Flat/external, stub, and nested bundles are
unsupported. Embedded CodeIntegrity catalogs are package-hashed but not independently
signature-verified; JSON must report this explicitly.
`verify` detects formats; `verify_pe`, `verify_msi`, `verify_cab`, `verify_navx`, `verify_powershell`, `verify_powershell_xml`, `verify_rdp`, `verify_appx`, and `verify_wsh` select formats explicitly (WSH detects its comment style).

CRLs are supplied as local PEM/DER files, checked for signature, authority,
freshness, and revocation across the chain. A CRL's issuer matches a
certificate's by RFC 5280 name comparison limited to string type (UTF8String,
PrintableString, BMPString, TeletexString read as Latin-1, VisibleString,
IA5String), lower case and white space
([CRL-041](crl.md#crl-041-a-crls-issuer-name-matches-by-rfc-5280-name-comparison)).
A TeletexString is read as Latin-1, which is not always what T.61 means. Any
other string type (NumericString, say) compares by exact bytes, and Unicode
normalization and the other RFC 4518 steps are not applied on purpose, so rssig
matches fewer names than RFC 5280 section 7.1 requires: a CRL whose issuer
differs from the certificate's only that way is not matched, and the status is
`revocation_unknown`. A name with a UniversalString does not decode (PATH-T006).
A leaf or intermediate whose basicConstraints, keyUsage, extKeyUsage,
subjectAltName, nameConstraints, cRLDistributionPoints, subjectKeyIdentifier or
authorityKeyIdentifier does not decode fails the path
([PATH-013](path.md#path-013-a-path-certificate-whose-extension-does-not-decode-fails-the-path));
other extensions are not decoded, so a malformed one is unfamiliar (PATH-006).
A leaf, intermediate, timestamp signer or RDP signer that carries any
extension more than once fails the path too
([PATH-014](path.md#path-014-a-path-certificate-that-repeats-an-extension-fails-the-path)).
An embedded certificate webpki cannot parse, such as one that repeats its
subjectAltName, on no path or on a path to a root that is not configured,
turns what would be `untrusted_root` into webpki's parse error
(`ExtensionValueInvalid` for that repeat); how it ranks against rssig's
other failures is open (PATH-T019, PATH-T011).
A configured root's extensions are not judged (PATH-011).
Both rules judge a path only: integrity-only verification and `parse` build
none, and a certificate report marks a basicConstraints, keyUsage or
extKeyUsage it cannot decode in `undecoded_extensions` instead of failing.

Opt-in bounded HTTP CRL fetching is available through `--fetch-crls` and an injected
`CrlSource`; see `docs/crl-retrieval.md`. The engine keeps no total of requests to
a source (CRL-039): the built-in source caps its own at 64 requests and 64 distinct URLs per
verification, keeps each URL's outcome for the verification and answers a repeat
from it without counting, up to 16 MiB of bodies returned again (CRL-051), and fetches at most 16 points of a certificate
per request, counting only points it has not answered before, denying the rest. The engine asks every
certificate that lacks a CRL with every point it lists, and reuses no answer
(CRL-033). A custom source owns its counts. The engine offers a source
every listed URI and keeps 16 failure entries per certificate in its report
(CRL-024). The engine's own retrieval limits are recorded and the run goes on
(LIMIT-T004): once the store retains 32 MiB of roots and CRLs, or 64 CRLs,
supplied ones included, no further certificate is asked, so `--fetch-crls`
with 64 supplied CRLs fetches nothing. AIA fetching, HTTPS retrieval, OCSP,
catalog signatures, delta/indirect CRLs, RSA-PSS, arbitrary PE section layouts,
Windows-specific trust lists, and Windows policy parity are not implemented.
A PE certificate table may hold only revision 2.0 PKCS#7 WIN_CERTIFICATE
entries; for now a legacy revision 1.0 entry or another certificate type is
rejected, although Microsoft's PE Format page allows any type and legacy
revision 1.0, pending PE-T004.
Nonzero data after the signature inside an entry is rejected, as Windows does
only with the opt-in `EnableCertPaddingCheck`
([PE-004](pe-decisions.md#pe-004-every-win_certificate-is-a-revision-20-pkcs7-entry-holding-one-der-object-and-zero-padding),
PE-T004).
Revocation of a timestamped signer is handled conservatively: an entry on a
current CRL rejects it even if its revocation date is after the signing time.
Signers with the lifetime-signing EKU are validated at the validation time, not
the timestamp; see `docs/validation-time.md`.

The verifier is the `rssig-engine` package and reads no files, clock, network or
OS root store; the `rssig` application supplies those defaults (the CLI, OS
roots, `HttpCrlSource`). See `docs/architecture.md`.

Diagnostic logging is opt-in through an injected `rssig_engine::log::Logger` (`verify::Verifier`,
`rssig::cli::Host`); see `docs/logging.md`. There is no global logger, the binary injects none,
and a logger must never change a result or write to stdout/stderr.

NAVX embedded signatures use the shared verification engine; see `docs/navx.md` for envelope, SIP, hashing, and interoperability limits.
