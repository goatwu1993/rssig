# PE format decisions

Numbered decisions that answer one question: **how is a PE file parsed and
hashed for signing?** The image digest and its exclusions, page hashes, the
certificate table and its WIN_CERTIFICATE entries, the supported header and
section layouts, and when an image counts as unsigned. The entry format is
defined in [Decision indexes](decisions.md); what each format key covers is in
[Format indexes](decisions.md#format-indexes).

## Scope

PE images: image hash, page hashes, checksum, certificate table.

## Boundaries

- A rule that is the same in every format stays in its subject index (`CMS-`,
  `ALG-`, `TSA-`, `TIME-`, `CRL-`, `PATH-`, `POLICY-`); this index links to it.
  The SignerInfo signature over the image digest is CMS-001, nested
  signatures CMS-013, SHA-1 page hashes `ALG-`, timestamp controls TSA-007.
- What `parse` reports about a PE is `INSPECT-`; a PE inside an MSI or a
  bundle is that format's index.
- Supported layouts are not Windows policy parity:
  [boundaries.md](boundaries.md) lists what is not implemented, such as
  arbitrary section layouts.

## Sources

- [boundaries.md](boundaries.md)
- Microsoft, *Windows Authenticode Portable Executable Signature Format*,
  version 1.0, March 21, 2008 ([Authenticode PE](https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx)): "Extracting and
  Verifying PKCS #7" and "Calculating the PE Image Hash". Its licence forbids
  reproduction, so no copy is committed.
- Microsoft, [PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) (updated 2026-09-10):
  "The Attribute Certificate Table (Image Only)", "Other Contents of the
  File" and "Appendix A: Calculating Authenticode PE Image Hash".
- Windows-format references, as AGENTS.md describes: osslsigncode 2.16
  (04c9aa7e) `pe.c`, jsign 7.6 (cf5d2ce)
  `jsign-core/src/main/java/net/jsign/pe/PEFile.java`, relic 02c54d58
  `lib/authenticode/pedigest.go` and `peverify.go`.

## Order

Entries are numbered from most to least important, in the tiers used by
[CRL decisions](crl.md#order); within a tier, Decided entries come before
Observed ones. A new entry takes the next free number.

1. **Fail-open:** a broken rule could accept an image whose bytes the
   signature does not cover, or a layout outside the supported profile.
2. **Availability:** a broken rule would reject a well-formed signed image.
3. **Result diagnostics:** the error code or stage a consumer matches; both
   outcomes reject.

## Index

| ID | Decision | Status | Pins |
|---|---|---|---|
| [PE-001](#pe-001-the-image-digest-covers-every-byte-but-the-checksum-the-certificate-table-entry-and-the-certificate-table) | The image digest covers every byte but the checksum, the certificate-table entry and the certificate table | Decided | acceptance |
| [PE-002](#pe-002-signed-page-hashes-must-match-every-page) | Signed page hashes must match every page | Decided | acceptance |
| [PE-003](#pe-003-the-certificate-table-ends-the-file-after-the-headers-on-an-8-byte-boundary) | The certificate table ends the file, after the headers, on an 8-byte boundary | Observed | acceptance |
| [PE-004](#pe-004-every-win_certificate-is-a-revision-20-pkcs7-entry-holding-one-der-object-and-zero-padding) | Every WIN_CERTIFICATE is a revision 2.0 PKCS#7 entry holding one DER object and zero padding | Observed | acceptance |
| [PE-005](#pe-005-only-bounded-pe32-and-pe32-headers-with-contiguous-sections-are-supported) | Only bounded PE32 and PE32+ headers with contiguous sections are supported | Observed | acceptance |
| [PE-006](#pe-006-signed-pe32-and-pe32-images-verify) | Signed PE32 and PE32+ images verify | Decided | acceptance |
| [PE-007](#pe-007-an-empty-certificate-table-entry-means-unsigned) | An empty certificate-table entry means unsigned | Decided | diagnostics |

## Tier 1: fail-open

### PE-001: The image digest covers every byte but the checksum, the certificate-table entry and the certificate table

The image digest is computed over the file in order, from offset 0 to the
start of the certificate table, leaving out only the four-byte optional-header
CheckSum, the eight-byte certificate-table data-directory entry and the
certificate table itself. Bytes between the headers and the first section, and
after the last section before the certificate table, are covered. It must
equal the digest in SpcIndirectDataContent; otherwise the result is
`image_digest_mismatch` at `image_digest`, with the expected and computed
digests in `details`. A changed CheckSum alone still verifies.

- **Status:** Decided
- **Decided by:** references agree (osslsigncode, jsign and relic), PR #76
- **Pins:** acceptance
- **Sources:**
  - osslsigncode `pe.c:775-829` (`pe_digest_calc_bio`): hashes from 0 to the
    certificate table, skipping CheckSum and the directory entry.
  - jsign `PEFile.java:397-434` (`computeDigest`): the same three exclusions.
  - relic `pedigest.go:48-109` (`DigestPE`): headers without the two fields,
    the gap before the first section, the sections, then the trailer up to the
    certificate table (`readTrailer`, `pedigest.go:330-348`).
  - Microsoft Authenticode PE, "Calculating the PE Image Hash", steps 3-14:
    the headers to SizeOfHeaders without CheckSum and the Certificate Table
    entry, the sections sorted by PointerToRawData, then the extra data after
    them less the certificate table. For the contiguous layouts of PE-005 that
    is the same byte sequence. The steps count from SizeOfHeaders and do not
    describe a gap before the first section; the three references and rssig
    hash it.
- **Unit tests:** `checksum_is_excluded_but_section_data_is_not` and
  `validates_page_hashes_and_image_integrity` in `src/tests.rs`;
  `borrowed_pe_chunks_preserve_the_authenticode_digest` in
  `tests/parse_core.rs`.
- **Note:** Microsoft's [PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#process-for-generating-the-authenticode-pe-image-hash)
  Appendix A says that the area past the last section "is not hashed". That
  contradicts step 14 of the Authenticode PE document and all three
  references, which hash data between the last section and the certificate
  table; rssig follows the Authenticode PE document.

### PE-002: Signed page hashes must match every page

When the signed SpcPeImageData carries page hashes, rssig recomputes them and
they must match exactly: the first entry hashes the headers without the two
excluded fields, zero-padded to a page less their 12 bytes; each section is
hashed page by page from its file offset, the last page zero-padded; a final
entry gives the end offset with a zero digest. The page size is 8192 for
Itanium and Alpha machines and 4096 otherwise. A mismatch is
`page_hash_mismatch` at `page_hashes`. An image without page hashes is checked
by PE-001 alone.

- **Status:** Decided
- **Decided by:** references agree (osslsigncode and relic; jsign does not
  verify page hashes), PR #76
- **Pins:** acceptance
- **Sources:**
  - osslsigncode `pe.c:1005-1308` (`pe_page_hash_calc`) and `pe.c:1318`
    (`pe_verify_page_hash`).
  - relic `pedigest.go:121-193` (`setupDigester`, `addPageHash`: the header
    page short by the removed bytes, the trailing null digest) and
    `pedigest.go:236-242` (page size by machine); `peverify.go:137-139`
    rejects a page-hash mismatch.
  - Microsoft documents no page-hash layout: the Authenticode PE document
    says the structure in serializedData "is outside the scope of this
    paper". The [PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#other-contents-of-the-file) page gives the
    page size: "4 K for Intel x86 and for MIPS, and 8 K for Itanium".
- **Unit tests:** `validates_page_hashes_and_image_integrity` in
  `src/tests.rs`.
- **Note:** SHA-1 page hashes need `--allow-sha1`; that is an `ALG-` rule.

### PE-003: The certificate table ends the file, after the headers, on an 8-byte boundary

The certificate-table entry must point at an 8-byte-aligned table, of a size
that is a multiple of 8, that starts at or after SizeOfHeaders and ends exactly
at the end of the file. A byte after the table, or a range outside the file,
is `invalid_pe` at `pe`: bytes after the table would be covered by neither the
image digest nor the signature.

- **Status:** Observed
- **Decided by:** —
- **Pins:** acceptance
- **Sources:**
  - relic `pedigest.go:330-348` (`readTrailer`) rejects "trailing garbage
    after existing certificate".
  - osslsigncode `pe.c:575-588` ignores a signature that does not end the
    file or overlaps the headers, so the image verifies as unsigned.
  - jsign `PEFile.java:424-425` hashes bytes after the table instead.
  - Microsoft [PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#other-contents-of-the-file): "attribute
    certificate and debug information must be placed at the very end of an
    image file"; [the attribute certificate table](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-attribute-certificate-table-image-only)
    is "composed of a set of contiguous, quadword-aligned attribute
    certificate entries", with zero padding before it. Step 14 of the
    Authenticode PE hash also assumes the table ends the file.
  - Microsoft and two of the three references support the rule; jsign
    differs, so this entry stays Observed until the owner decides.

### PE-004: Every WIN_CERTIFICATE is a revision 2.0 PKCS#7 entry holding one DER object and zero padding

Each WIN_CERTIFICATE in the table must have a length of at least 8 that fits
the table, revision 0x0200 and type WIN_CERT_TYPE_PKCS_SIGNED_DATA, and hold
one DER object followed only by zero bytes; entries are padded with zeros to
8 bytes, and the table must not be empty. Anything else is
`invalid_certificate_table` at `certificate_table`.

- **Status:** Observed
- **Decided by:** —
- **Pins:** acceptance
- **Sources:**
  - osslsigncode `pe.c:609-631` (`pe_pkcs7_get_file`) uses the first
    revision 2.0 PKCS#7 entry and skips others.
  - relic `peverify.go:86-103` checks each entry's length and alignment but
    not its revision or type.
  - Microsoft [PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-attribute-certificate-table-image-only):
    entries are walked by dwLength rounded up to 8 until the sum equals the
    table size, otherwise "either the attribute certificate table or the Size
    field is corrupted"; bCertificate is padded with zeros to a quadword.
    Entries "can contain any certificate type", and revision 0x0100 is
    "supported only for purposes of verifying legacy Authenticode signatures".
  - The references differ in what they skip. rssig is stricter than
    Microsoft: it rejects a revision 1.0 entry and an entry of another type
    instead of skipping it.

### PE-005: Only bounded PE32 and PE32+ headers with contiguous sections are supported

A PE must start with `MZ`, have `e_lfanew` of at least 64 pointing at
`PE\0\0` inside the file, a complete COFF header, an optional header with
magic 0x10b or 0x20b that holds the certificate-table directory entry
(NumberOfRvaAndSizes at least 5), and a SizeOfHeaders that covers the section
table and lies inside the file. Non-empty sections, sorted by file offset,
must not overlap the headers and must follow each other without gaps (a gap is
allowed only before the first), ending at or before the certificate table.
Anything else is `invalid_pe` at `pe`, without claiming how Windows would hash
it.

- **Status:** Observed
- **Decided by:** —
- **Pins:** acceptance
- **Sources:**
  - relic `pedigest.go:48-109` (`DigestPE`) and `pedigest.go:294-328` (`readSections`)
    accept the same contiguous layout and reject a section that does not
    begin where the previous one ended.
  - osslsigncode `pe.c:523-600` (`pe_ctx_get`) checks the magic,
    SizeOfHeaders and NumberOfRvaAndSizes.
  - [boundaries.md](boundaries.md): arbitrary PE section layouts are not
    implemented.
  - Microsoft Authenticode PE, step 10, sorts the sections by
    PointerToRawData; it does not say how a gap or an overlap between them is
    hashed, so rssig rejects both rather than guess.

## Tier 2: availability

### PE-006: Signed PE32 and PE32+ images verify

A PE32 or PE32+ image in the layout of PE-005, with a matching image digest
and, where present, matching page hashes, verifies, subject to the CMS, path,
time and revocation rules of the other indexes.

- **Status:** Decided
- **Decided by:** references agree (osslsigncode, jsign and relic), PR #76
- **Pins:** acceptance
- **Sources:**
  - All three accept both optional-header magics: osslsigncode
    `pe.c:550-561`, jsign `PEFile.java:186-188` (`getFormat`) and relic
    `pedigest.go:252-281`.

## Tier 3: result diagnostics

### PE-007: An empty certificate-table entry means unsigned

An image whose certificate-table entry has a zero offset or a zero size is
`unsigned` (stage `pe`), not `invalid_pe`, once its headers parse.

- **Status:** Decided
- **Decided by:** references agree (osslsigncode, jsign and relic), PR #76
- **Pins:** diagnostics
- **Sources:**
  - osslsigncode `pe.c:575-581`: an entry with either field zero is no
    signature.
  - jsign `PEFile.java:418` (`certificateTable.exists()`) and relic
    `pedigest.go:331` (`certSize == 0`).
