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
freshness, and revocation across the chain. Opt-in bounded HTTP CRL fetching is available through `--fetch-crls` and an injected
`CrlSource`; see `docs/crl-retrieval.md`. AIA fetching, HTTPS retrieval, OCSP,
catalog signatures, delta/indirect CRLs, RSA-PSS, arbitrary PE section layouts,
Windows-specific trust lists, and Windows policy parity are not implemented.
A PE certificate table may hold only revision 2.0 PKCS#7 WIN_CERTIFICATE
entries; a legacy revision 1.0 entry or another certificate type is rejected,
not skipped as Windows documents, and nonzero data after the signature inside
an entry is rejected, as Windows does only with the opt-in
`EnableCertPaddingCheck` ([PE-004](pe-decisions.md), FORMAT-07).
Revocation of a timestamped signer is handled conservatively: an entry on a
current CRL rejects it even if its revocation date is after the signing time.
Signers with the lifetime-signing EKU are validated at the validation time, not
the timestamp; see `docs/validation-time.md`.

Diagnostic logging is opt-in through an injected `rssig::log::Logger` (`verify::Verifier`,
`cli::Host`); see `docs/logging.md`. There is no global logger, the binary injects none,
and a logger must never change a result or write to stdout/stderr.

NAVX embedded signatures use the shared verification engine; see `docs/navx.md` for envelope, SIP, hashing, and interoperability limits.
