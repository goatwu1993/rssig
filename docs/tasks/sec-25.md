# SEC-25: Narrow CMS-009 to the attributes RFC 5652 limits

[CMS-009](../cms.md#cms-009-an-attribute-oid-appears-at-most-once-in-a-signerinfo)
rejects every duplicated attribute OID. RFC 5652
([copy](../rfc/rfc5652.txt)) and the references support less.

## Decision

Decided by the owner, who delegated the call in PR #72. The countersignature
row is the owner's own decision. Implementation is this task's own PR.

| Attribute | Behavior | Reason |
|---|---|---|
| contentType, messageDigest, signingTime repeated, or without exactly one value | Rejected, `invalid_signature` at `cms` (unchanged) | RFC 5652 sections 11.1 to 11.3; OpenSSL and Bouncy Castle both enforce it |
| Any attribute with an empty value SET | Rejected (unchanged) | RFC 5652 section 11.4 and X.501 require a value |
| Countersignature attribute repeated | Passes the CMS layer; the file is rejected by TSA-004, `invalid_timestamp` at `timestamp` | RFC 5652 section 11.4 allows repeats; "at most one timestamp" is TSA-004's rule |
| RFC 3161 timestamp attribute repeated (either OID) | Same as countersignature | No RFC forbids it; every timestamp-count failure then has one code |
| Nested-signature attribute (SpcNestedSignature) repeated | Rejected, `invalid_signature` at `cms` (unchanged), as a written choice | rssig acts on this attribute, so a repeat would make "which signatures exist" ambiguous; several values in one attribute remain the supported form |
| Any other OID repeated, signed or unsigned | Accepted | rssig keeps these opaque and never acts on them; no RFC or reference rejects them |

No file with more than one timestamp starts to verify. The only new
acceptance is a repeated opaque attribute.

## Work

- Keep structural checks (order, empty value SET, OID encoding) in
  `Attributes::from_node` (`src/parse/signer.rs`); move the single-instance
  check to verification, limited to the attributes above. The library's
  `Attributes::parse` then accepts repeated OIDs.
- Move `cms-009-duplicate-rfc` and `cms-009-duplicate-counter` back to
  TSA-004 with the new expected code and stage, and record it in the reindex
  history. `src/verify/timestamp.rs` already rejects both.
- Add fixtures and cases for CMS-009: a repeated contentType (bad), a
  repeated nested-signature attribute (bad) and a repeated unknown unsigned
  attribute (good), each paired with its good or bad counterpart.
- Amend CMS-009 and TSA-004; both are Decided, so the PR cites this decision.
- Follow the TDD workflow in AGENTS.md.
