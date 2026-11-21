# TEST-30: Remove duplicate and overlapping decisions

Found by an audit of all 94 numbered entries (45 CRL-, 14 TIME-, 12 PATH-,
7 TSA-, 16 CMS-) after PR #72. Nothing is changed yet. Merging, moving or
renumbering entries is a reindex ([AGENTS.md](../../AGENTS.md#pinned-expectations),
rule 8): one owner-approved PR that renames cases and fixtures and records the
old-to-new mapping in the [reindex history](../decisions.md#reindex-history).
Compare each candidate with every index before merging (rule 7).

The audit read the rule statements of the CRL-, TIME- and CMS- entries. PATH-
and TSA-005 to TSA-007 were judged from titles, so read them first. Attached
cases were not re-checked.

## Likely duplicates (merge)

- CRL-002, CRL-021 and CRL-039: a CRL without nextUpdate is `invalid_crl`
  (`missing_next_update`) as its only defect and replaceable with another
  defect. CRL-039 restates the first two.
- CRL-020 and CRL-021: CRL-021 is a special case of CRL-020.
- CRL-040 and CRL-041: both say that without an answer the error stands and is
  marked `retrieval_aborted`.
- CRL-003 and CRL-012: "set aside when another CRL is usable" is in both.
- TIME-002 and TIME-004: one check (notBefore at or before the signing time,
  `certificate_not_yet_valid`), split by lifetime EKU; TIME-003 already covers
  the non-lifetime case.

## Instances of a general rule (fold in, or cross-reference)

- CRL-024, CRL-032, CRL-033 are the RDP "usage" versions of CRL-023, CRL-029,
  CRL-036.
- Error precedence is split: CRL-029, CRL-031, CRL-036 and TIME-010 to
  TIME-013. CRL-031 is the other half of CRL-029's `--fetch-crls` clause.
- TIME-009 and PATH-009: a rejected candidate issuer does not stop path
  building.
- CRL-018's second sentence repeats CRL-015 (cRLSign).
- CRL-001 and CRL-028 both state `revocation_unknown`.
- "Inclusive at whole seconds" appears in TIME-002, TIME-006 and TIME-007.
- CMS: CMS-010 and CMS-014 (version 1); CMS-001 and CMS-008 (exact signed
  bytes); CMS-010 and CMS-016 (error codes); the last sentence of CMS-004
  repeats PATH-001; CMS-012 and TSA-002 split CertificateChoices; TSA-002 and
  CMS-001 are one check with different codes and stages (link them).

## Possible conflicts (state the exception)

- CRL-029 says a revocation is reported over another path's failure; TIME-012
  says a lifetime-signing validity failure outranks a revocation on another
  path. State TIME-012 as the exception in CRL-029 (the precedence belongs in
  `TIME-`, per [which index](../decisions.md#which-index)).
- CRL-002 says a CRL without nextUpdate cannot show status is current;
  CRL-004 says it is current, so its listing counts. It is a fail-closed
  asymmetry (a listing counts, an absence never clears); say so in both.

## Format defects (documentation only, no owner approval needed)

- CRL-017 and TIME-007 have no rule statement.
- Seven format skeletons repeat the same candidate rules (`hash`, `structure`,
  `unsigned`, `support`, "timestamp controls are TSA-007"); decide where the
  shared wording lives before numbering them (TEST-18 and its siblings).

## Not duplicates

The acceptance/diagnostics pairs CMS-004 and CMS-015, CRL-009 and CRL-022,
CRL-013 and CRL-034, and PATH-011 and CRL-015.
