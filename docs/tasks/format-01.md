# FORMAT-01: Extend PE layout evidence before broadening support.

Task detail for **FORMAT-01** in [TODO.md](../../TODO.md), which keeps the ID,
title and checkbox.

Cover multiple certificate entries, reordered sections, padding, overlays,
PE32/PE32+, page sizes and page hashes. Document deliberately rejected
gaps/overlaps and certificate placement. Evaluate unsigned-PE inspection
separately, with an explicit API/CLI contract and unchanged unsigned rejection
in verification.

## PE rules no case pins yet

Add a fixture and case for each, per the TDD workflow in AGENTS.md:

- [PE-002](../pe-decisions.md#pe-002-signed-page-hashes-must-match-every-page):
  8192-byte page hashes for Itanium (0x200) and Alpha (0x184, 0x284); headers
  larger than a page with page hashes, after tagging that error, which now
  falls back to `invalid_certificate` at `certificate`.
- [PE-003](../pe-decisions.md#pe-003-the-certificate-table-ends-the-file-after-the-headers-on-an-8-byte-boundary):
  an unaligned certificate table; one overlapping the headers.
- [PE-004](../pe-decisions.md#pe-004-every-win_certificate-is-a-revision-20-pkcs7-entry-holding-one-der-object-and-zero-padding):
  a WIN_CERTIFICATE length below 8 or past the table; a truncated entry;
  nonzero padding between entries; a table of two valid revision 2.0 entries.
- [PE-005](../pe-decisions.md#pe-005-only-bounded-pe32-and-pe32-headers-with-contiguous-sections-are-supported):
  a truncated COFF header; an unsupported optional-header magic;
  NumberOfRvaAndSizes below 5; a bad SizeOfHeaders; a section gap or overlap;
  a section running into the certificate table.
- [PE-006](../pe-decisions.md#pe-006-signed-pe32-and-pe32-images-verify): a
  PE32 image for i386 (0x14C); the committed images use machine 0x8664.
- [PE-007](../pe-decisions.md#pe-007-a-zero-size-certificate-table-entry-means-unsigned):
  a zero offset with a nonzero size, and decide its diagnostic: osslsigncode
  and jsign report no signature, relic a parse failure, and `unsigned` can hide
  a corrupt directory entry, so `invalid_pe` may be the better result.

## Decisions

- Which code and stage the page-hash header-size failure reports. It is an
  untagged error that falls back to `invalid_certificate` at `certificate`,
  which misleads a consumer; tag it (for example `invalid_pe` at `page_hashes`)
  and pin it with the PE-002 case above.
- Whether to enforce FileAlignment on section offsets and sizes, which
  Microsoft's PE Format page requires and PE-005 does not check.
