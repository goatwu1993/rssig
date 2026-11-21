# PE format decisions

Numbered decisions that answer one question: **how is a PE file parsed and
hashed for signing?** The image digest and its exclusions, page hashes, the
certificate table and its WIN_CERTIFICATE entries, the supported header and
section layouts, and when an image counts as unsigned. The entry format is
defined in [Decision indexes](decisions.md); what each format key covers is in
[Format indexes](decisions.md#format-indexes).

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
  version 1.0, March 21, 2008
  ([Authenticode PE](https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx)):
  "Extracting and Verifying PKCS #7" and "Calculating the PE Image Hash". Its
  licence forbids reproduction, so no copy is committed.
- Microsoft,
  [PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
  (updated 2026-09-10): "The Attribute Certificate Table (Image Only)",
  "Other Contents of the File" and "Appendix A: Calculating Authenticode PE
  Image Hash".
- Microsoft page-hash documentation, with the page's last-updated date:
  [SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool)
  (2026-11-20),
  [SignerSignEx2](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signersignex2)
  (2021-01-07),
  [event 6281](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6281)
  (2026-04-27), and Raymond Chen,
  [What are the page sizes used by Windows on various processors?](https://devblogs.microsoft.com/oldnewthing/20210510-00/?p=105200)
  (2021-05-10).
- Microsoft Security Bulletin
  [MS12-024](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-024)
  (WinVerifyTrust strict PE verification; v1.1, 2012-07-31) and Security
  Advisory
  [2915720](https://learn.microsoft.com/en-us/security-updates/securityadvisories/2014/2915720)
  (the opt-in `EnableCertPaddingCheck`; v1.4, 2014-07-29), with Security
  Bulletin
  [MS13-098](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-098)
  (v1.6, 2014-07-29).
- Windows-format references, as AGENTS.md describes: osslsigncode 2.16
  (04c9aa7e) `pe.c`, jsign 7.6 (cf5d2ce)
  `jsign-core/src/main/java/net/jsign/pe/PEFile.java` and `DataDirectory.java`,
  relic 02c54d58 `lib/authenticode/pedigest.go` and `peverify.go`.
- Tiebreakers where those three disagree (AGENTS.md):
  [signify](https://github.com/ralphje/signify) v0.9.3 (60fa494) and
  [AuthHashCalc](https://github.com/hfiref0x/AuthHashCalc) (69ffce7), for the
  PE-002 page size.

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
| [PE-003](#pe-003-the-certificate-table-ends-the-file-after-the-headers-on-an-8-byte-boundary) | The certificate table ends the file, after the headers, on an 8-byte boundary | Decided | acceptance |
| [PE-004](#pe-004-every-win_certificate-is-a-revision-20-pkcs7-entry-holding-one-der-object-and-zero-padding) | Every WIN_CERTIFICATE is a revision 2.0 PKCS#7 entry holding one DER object and zero padding | Observed | acceptance |
| [PE-005](#pe-005-only-bounded-pe32-and-pe32-headers-with-contiguous-sections-are-supported) | Only bounded PE32 and PE32+ headers with contiguous sections are supported | Observed | acceptance |
| [PE-006](#pe-006-signed-pe32-and-pe32-images-verify) | Signed PE32 and PE32+ images verify | Decided | acceptance |
| [PE-007](#pe-007-a-zero-size-certificate-table-entry-means-unsigned) | A zero-size certificate-table entry means unsigned | Decided | diagnostics |

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
  - Microsoft Authenticode PE (v1.0, 2008-03-21), "Calculating the PE Image
    Hash": step 4 "Skip over the checksum, which is a 4-byte field"; step 7
    "Exclude the Certificate Table entry from the calculation and hash
    everything from the end of the Certificate Table entry to the end of image
    header"; step 10 "sort the section headers in ascending order according to
    the disk-file offset of the sections"; step 14 "If FILE_SIZE is greater than
    SUM_OF_BYTES_HASHED, the file contains extra data that must be added to the
    hash", of length "(File Size) – ((Size of AttributeCertificateTable) +
    SUM_OF_BYTES_HASHED)". For the contiguous layouts of PE-005 that is the same
    byte sequence, except a gap before the first section: the steps count from
    SizeOfHeaders (step 8) and do not describe one, while the three references
    and rssig hash it.
- **Unit tests:** `checksum_is_excluded_but_section_data_is_not` and
  `validates_page_hashes_and_image_integrity` in `src/tests.rs`;
  `borrowed_pe_chunks_preserve_the_authenticode_digest` in
  `tests/parse_core.rs`.
- **Note:** Microsoft's Authenticode PE document states the exclusions and the
  section order (steps 3-13), which the references follow. Its documents
  conflict on data after the last section and are silent on a gap before the
  first section, which only the references hash, so the references decide
  those two. Microsoft's
  [PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#process-for-generating-the-authenticode-pe-image-hash)
  Appendix A says that the area past the last section "is not hashed". That
  contradicts step 14 of the Authenticode PE document and all three
  references, which hash data between the last section and the certificate
  table. rssig follows the three references: they match step 14 there, and
  go beyond the Authenticode PE document in hashing a gap before the first
  section, which it does not describe.

### PE-002: Signed page hashes must match every page

When the signed SpcPeImageData carries page hashes, rssig recomputes them and
they must match exactly: the first entry hashes the headers without the two
excluded fields, zero-padded to a page less their 12 bytes; each section, in
file-offset order, is hashed page by page from its file offset, the last page
zero-padded; a final entry gives the end offset with a zero digest. The page
size is 8192 for Itanium and Alpha machines and 4096 otherwise; the committed
fixtures cover only 4096 (machine 0x8664), and no case yet pins 8192
(FORMAT-01). A mismatch is `page_hash_mismatch` at `page_hashes`. Headers larger
than one page cannot be page-hashed and are rejected, currently with the
untagged fallback `invalid_certificate` at `certificate`; no case pins that
error yet, and FORMAT-01 tags it before adding one. An image without page hashes
is checked by PE-001 alone.

- **Status:** Decided
- **Decided by:** owner, PR #76
- **Pins:** acceptance
- **Sources:**
  - relic `pedigest.go:121-193` (`setupDigester`, `addPageHash`: the header
    page short by the removed bytes, the trailing null digest) and
    `pedigest.go:236-242` (page size by machine); `peverify.go:139-141`
    rejects a page-hash mismatch.
  - osslsigncode `pe.c:1005-1308` (`pe_page_hash_calc`) builds the same
    entries, which `pe_verify_page_hash` (`pe.c:1318`) compares: the header
    page without CheckSum and the Certificate Table entry, zero-padded to the
    page size less those 12 bytes (`pe.c:1145-1180`, rejecting headers larger
    than a page at `pe.c:1166`), each section page by page, and a final entry
    with the end offset and a zero digest (`pe.c:1290-1303`). It differs in
    taking the page size from the optional header's SectionAlignment
    (`pe.c:1052-1056`, rejecting 0) and in walking the sections in table order
    (`pe.c:1196`), so it would reject the committed page-hash fixtures, whose
    SectionAlignment is 0.
  - jsign does not verify page hashes; it only declares the ASN.1
    `SpcSerializedObject` that carries them.
  - [signify](https://github.com/ralphje/signify) (Python, v0.9.3,
    60fa494): `signify/authenticode/signed_file/pe.py:280-293` (`page_size`:
    8192 for Itanium, 4096 otherwise) and `pe.py:358-376`
    (`verify_additional_hashes` rejects a page-hash mismatch);
    `signify/authenticode/indirect_data.py:194-216` reads entries of a
    4-byte offset and a digest, the last with a zero digest. Its commit
    25e7046 (v0.9.2, issue #58) replaced a SectionAlignment page size,
    osslsigncode's method, because it reported page-hash errors on a real
    signed binary, now a test sample.
  - [AuthHashCalc](https://github.com/hfiref0x/AuthHashCalc) (69ffce7):
    `Source/hash.cpp:342-394` (`CalculateFirstPageHash`) computes the WDAC
    header page hash, zero-padded to the page size less the skipped bytes,
    with the host's memory page size (`GetSystemInfo`, `Source/main.cpp:697`),
    not a header field.
  - Microsoft documents no page-hash layout: the Authenticode PE document
    says the structure in serializedData "is outside the scope of this
    paper", and the
    [SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool),
    [SignerSignEx2](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signersignex2)
    and
    [event 6281](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6281)
    pages cover only creating and checking page hashes. SignTool: `/ph` "If
    supported, generates page hashes for executable files" and, when
    verifying, "Print and verify page hash values". SignerSignEx2:
    `SPC_INC_PE_PAGE_HASHES_FLAG` "Include page hashes when creating SIP
    indirect data for the PE file", and the default "is to exclude page hashes
    when creating SIP indirect data for PE files". Event 6281: "Code Integrity
    determined that the page hashes of an image file aren't valid".
  - No Microsoft document names the page-hash page size. Raymond Chen,
    [What are the page sizes used by Windows on various processors?](https://devblogs.microsoft.com/oldnewthing/20210510-00/?p=105200)
    (The Old New Thing, 2021-05-10): 8KB for Alpha AXP, Alpha AXP 64 and
    Itanium, 4KB for x86-32, x86-64, SH-4, MIPS, PowerPC, ARM and ARM64: the
    Windows page size per processor, which is the machine-type mapping above.
    The
    [PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#other-contents-of-the-file)
    page gives the same architecture page sizes ("4 K for Intel x86 and for
    MIPS, and 8 K for Itanium"), as the values SectionAlignment is compared
    with.
- **Unit tests:** `validates_page_hashes_and_image_integrity` in
  `src/tests.rs`.
- **Note:** SHA-1 page hashes need `--allow-sha1`; that is an `ALG-` rule. The
  owner decided the machine-type page size: Microsoft's page sizes per
  processor, relic and signify agree, AuthHashCalc agrees that the size is not
  a header field, and osslsigncode differs. signify maps only Itanium to 8192;
  the Alpha sizes follow Microsoft and relic. rssig sorts sections by file
  offset; relic walks them in table order and requires each to start where
  the previous one ended, so for the layouts relic accepts the order is the
  same. rssig also accepts a section table out of file order, which relic
  rejects.

### PE-003: The certificate table ends the file, after the headers, on an 8-byte boundary

A certificate-table entry with a nonzero size (a zero size is PE-007) must point
at an 8-byte-aligned table, of a size that is a multiple of 8, that starts at or
after SizeOfHeaders and ends exactly at the end of the file. A zero offset is
reported as `unsigned` today, before these bounds; that is not decided (see the
PE-007 Note). A byte after the table, or a range outside the file, is
`invalid_pe` at `pe`: bytes after the table would be covered by neither the
image digest nor the signature.

- **Status:** Decided
- **Decided by:** owner, PR #76
- **Pins:** acceptance
- **Sources:**
  - relic `pedigest.go:330-348` (`readTrailer`) rejects "trailing garbage
    after existing certificate".
  - osslsigncode `pe.c:575-589` ignores a signature that does not end the
    file, or that overlaps the PE header up to the end of the Certificate
    Table field, so the image verifies as unsigned.
  - jsign `PEFile.java:424-425` hashes bytes after the table, but rejects a
    table that extends past the end of the file (`DataDirectory.java:57-69`,
    called at `PEFile.java:419`).
  - Microsoft
    [PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-data-directories-image-only):
    the Certificate Table entry's "first field ..., which is normally an RVA,
    is a file pointer instead", so the offset and range are file positions.
  - Microsoft Authenticode PE (v1.0, 2008-03-21), step 14: the extra data is
    "(File Size) – ((Size of AttributeCertificateTable) +
    SUM_OF_BYTES_HASHED)", which assumes the table ends the file.
  - Microsoft Security Bulletin
    [MS12-024](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-024)
    (KB2653956), FAQ "I have applied this update and now my software's
    digital signature is invalid": "PE files will also be considered
    \"unsigned\" if additional content is appended to the file after the
    signature has been applied." Windows rejects such a file too, reporting
    it unsigned where rssig reports `invalid_pe`.
  - Microsoft
    [PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-attribute-certificate-table-image-only):
    the table is "composed of a set of contiguous, quadword-aligned attribute
    certificate entries. Zero padding is inserted between the original end of
    the file and the beginning of the attribute certificate table to achieve
    this alignment", and the table size "includes the padding": the start and
    size are multiples of 8.
  - Microsoft
    [PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#other-contents-of-the-file)
    differs: "attribute certificate and debug information must be placed at
    the very end of an image file, with the attribute certificate table
    immediately preceding the debug section", which allows debug data after
    the table. MS12-024 treats appended content as unsigned.
- **Note:** The PE Format page and jsign allow data after the table;
  MS12-024, the Authenticode PE hash, relic and osslsigncode do not. The owner
  decided, with the full PE Format text, to reject it: bytes after the table are
  covered by neither the image digest nor the signature, so rejecting fails
  closed. The lower bound, at or after SizeOfHeaders, is rssig's own:
  osslsigncode checks only the PE header up to the Certificate Table field, and
  relic requires the table after the last section, which PE-005 also requires
  whenever the image has sections. The committed cases pin data after the table
  and a range past the end of the file; no case yet pins an unaligned table or
  one overlapping the headers (FORMAT-01).

### PE-004: Every WIN_CERTIFICATE is a revision 2.0 PKCS#7 entry holding one DER object and zero padding

Each WIN_CERTIFICATE in the table must have a length of at least 8 that fits the
table, revision 0x0200 and type WIN_CERT_TYPE_PKCS_SIGNED_DATA, and zero bytes
between its end and the next 8-byte boundary. Its payload may hold only zero
bytes after its DER object. A breach of any of these is
`invalid_certificate_table` at `certificate_table`. In verification, a payload
that does not start with a DER object is a CMS envelope defect, `malformed_cms`
at `cms` (CMS-015), not this rule; `parse` and `Pe::signatures()` report it as
`invalid_certificate_table`, which FORMAT-07 may align. More than 64 entries
exceed the entry budget, which is `resource_limit_exceeded` (`LIMIT-`), not this
rule.

- **Status:** Observed
- **Decided by:** —
- **Pins:** acceptance
- **Sources:**
  - osslsigncode `pe.c:609-631` (`pe_pkcs7_get_file`) uses the first
    revision 2.0 PKCS#7 entry and skips others.
  - jsign `PEFile.java:360-373` (`getCertificateTable`) reads only the first
    entry of a non-EFI file.
  - jsign also skips an entry that is not revision 2.0 PKCS#7
    (`PEFile.java:327-330`, `CertificateTableEntry.java:63-65`).
  - relic `peverify.go:86-107` checks each entry's length, rounds it up to 8
    and parses every entry as PKCS#7, failing on any other; it checks neither
    the revision and type nor the bytes between dwLength and the 8-byte
    boundary. Its parser rejects nonzero bytes after the PKCS#7 object inside
    dwLength ("trailing garbage after PKCS#7 structure",
    `lib/pkcs7/marshal.go:31-35`, called at `peverify.go:147`), as rssig does.
  - Microsoft
    [PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-attribute-certificate-table-image-only):
    entries are walked by dwLength rounded up to 8 until the sum equals the
    table size, otherwise "either the attribute certificate table or the Size
    field is corrupted"; bCertificate is padded with zeros to a quadword.
    Entries "can contain any certificate type", and revision 0x0100 is
    "supported only for purposes of verifying legacy Authenticode signatures".
  - Microsoft Security Advisory
    [2915720](https://learn.microsoft.com/en-us/security-updates/securityadvisories/2014/2915720):
    with the opt-in `EnableCertPaddingCheck`, Windows "will no longer allow
    extraneous information in the WIN_CERTIFICATE structure, and Windows will
    no longer recognize non-compliant binaries as signed". It is not the
    default: Microsoft "no longer plans to enforce the stricter verification
    behavior as a default requirement" (MS13-098, revised July 29, 2014).
- **Note:** rssig is stricter than Windows' default. Like relic and Windows with
  `EnableCertPaddingCheck`, it rejects nonzero bytes after the DER object; and
  it rejects a revision 1.0 entry and an entry of another type, which
  osslsigncode and jsign skip and the PE Format page allows. This departs from
  what Microsoft documents on purpose: rssig verifies only revision 2.0 PKCS#7
  signatures, and an entry it cannot verify, or bytes it cannot attribute to the
  signature, would otherwise ride along unchecked, so it fails closed. FORMAT-07
  in `TODO.md` decides whether to keep that. The committed case pins only the
  nonzero bytes after the DER object, the part relic and Windows with
  `EnableCertPaddingCheck` also reject; it does not pin the revision 1.0 and
  other-type rejection FORMAT-07 may reverse. No case yet pins the entry
  framing (a length below 8 or past the table, a truncated entry, nonzero
  padding between entries); FORMAT-01 adds it.

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
  - Microsoft
    [PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#signature-image-only):
    the file offset at 0x3c points to the 4-byte signature "PE\0\0"; the
    optional-header magic is "0x10B" for a normal executable and "0x20B" for
    PE32+, and "it is important to validate the optional header magic number";
    NumberOfRvaAndSizes "should also be used to ensure that no probe for a
    particular data directory entry goes beyond the optional header", and the
    Certificate Table is the fifth directory (offset 128/144); SizeOfHeaders
    is "The combined size of an MS-DOS stub, PE header, and section headers".
    The page does not name the `MZ` signature or a minimum `e_lfanew`; those
    checks, and the bound of 64, are rssig's own.
  - relic `pedigest.go:48-109` (`DigestPE`) and `pedigest.go:294-328`
    (`readSections`) accept a similar contiguous layout and reject a section
    that does not begin where the previous one ended. It differs: it lowers
    SizeOfHeaders to a first section that starts inside the headers
    (`pedigest.go:314-317`), rounds every section but the last up to
    FileAlignment (`pedigest.go:318-321`) and walks sections in table order.
  - osslsigncode `pe.c:523-600` (`pe_ctx_get`) checks the `e_lfanew` bound
    (`pe.c:537-545`), the PE signature (`pe.c:546-549`), the magic
    (`pe.c:554-562`) and NumberOfRvaAndSizes (`pe.c:567-571`).
  - Microsoft Authenticode PE (v1.0, 2008-03-21), step 10: "sort the section
    headers in ascending order according to the disk-file offset of the
    sections". It does not say how a gap or an overlap between them is hashed,
    so rssig rejects both rather than guess.
  - [boundaries.md](boundaries.md): arbitrary PE section layouts are not
    implemented.
- **Note:** rssig departs from Microsoft by not checking FileAlignment: the
  [PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers)
  page says PointerToRawData and SizeOfRawData "must be a multiple of
  FileAlignment" for executable images. The image digest covers every byte
  either way, so an unaligned section admits no unsigned bytes; FORMAT-01
  decides whether to enforce it. The committed cases pin a missing `MZ`, a
  truncated optional header and an out-of-range `e_lfanew`. No case yet pins a
  truncated COFF header, an unsupported magic, NumberOfRvaAndSizes below 5, a
  bad SizeOfHeaders, a section gap or overlap, or a section running into the
  certificate table; FORMAT-01 in `TODO.md` adds that layout evidence.

## Tier 2: availability

### PE-006: Signed PE32 and PE32+ images verify

A PE32 or PE32+ image in the layout of PE-005, with a matching image digest
and, where present, matching page hashes, verifies, subject to the CMS, path,
time and revocation rules of the other indexes.

- **Status:** Decided
- **Decided by:** references agree (osslsigncode, jsign and relic), PR #76
- **Pins:** acceptance
- **Sources:**
  - Microsoft
    [PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-standard-fields-image-only):
    "0x10B, which identifies it as a normal executable file" and "0x20B
    identifies it as a PE32+ executable"; the Authenticode PE document's hash
    steps name no difference between them.
  - All three references accept both optional-header magics: osslsigncode
    `pe.c:554-562`, jsign `PEFile.java:186-188` (`getFormat`) and relic
    `pedigest.go:252-281`.
- **Note:** Microsoft defines both image types but does not say that signed ones
  verify, so the references decide. Both committed images are synthetic and use
  machine 0x8664 (AMD64); `good-pe32.exe` pairs the PE32 magic with it. No case
  yet verifies a PE32 image for i386 (0x14C) (FORMAT-01).

## Tier 3: result diagnostics

### PE-007: A zero-size certificate-table entry means unsigned

An image whose certificate-table entry has a zero size is `unsigned` at
`pe`, not `invalid_pe`, once its headers parse; its section layout is not
checked.

- **Status:** Decided
- **Decided by:** references agree (osslsigncode, jsign and relic), PR #76
- **Pins:** diagnostics
- **Sources:**
  - osslsigncode `pe.c:575-581`: an entry with either field zero is no
    signature.
  - jsign `DataDirectory.java:47-49` (`exists()`: offset and size both
    nonzero), used by `getCertificateTable` (`PEFile.java:364`).
  - Microsoft documents no rule for an empty certificate-table entry.
  - relic `peverify.go:49-50` returns `NotSignedError` when the size is 0.
- **Note:** Only the zero size is decided, where all three references agree.
  Today rssig also reports `unsigned` for a zero offset with a nonzero size,
  before the bounds of PE-003, as osslsigncode and jsign do; relic reads the
  table at offset 0 and fails to parse it instead. Both reject, the references
  differ on the diagnostic, and no case pins it, so that part is not decided
  here (FORMAT-01). The committed case pins an entry with both fields zero.
