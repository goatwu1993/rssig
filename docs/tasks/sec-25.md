# SEC-25: Narrow CMS-009 to the attributes RFC 5652 limits

[CMS-009](../cms.md#cms-009-an-attribute-oid-appears-at-most-once-in-a-signerinfo)
rejects every duplicated attribute OID. The references support less.

| Attribute | RFC 5652 | OpenSSL and Bouncy Castle | Correct behavior |
|---|---|---|---|
| contentType, messageDigest, signingTime (signed) | at most one, one value (sections 11.1 to 11.3) | both reject a repeat | reject (unchanged) |
| countersignature (unsigned) | may repeat (section 11.4) | Bouncy Castle accepts several | accept at the CMS layer |
| any other OID | no limit | neither rejects | owner to decide: accept, or keep rejecting as a written choice |
| empty value SET | one or more values (section 11.4) | both reject where they check | reject (unchanged) |

## Decided by the owner

Rejecting a repeated countersignature attribute is wrong.

## Proposed (owner to confirm in this task's PR)

- Allow a repeated countersignature OID in unsigned attributes; decide the
  "any other OID" row.
- A signer with more than one timestamp stays rejected, by TSA-004
  (`invalid_timestamp` at `timestamp`; `src/verify/timestamp.rs:114-118`
  already enforces it).
- Move `cms-009-duplicate-counter` back to TSA-004 with its new expected
  code, record the move in the reindex history, and amend CMS-009 and
  TSA-004. Both are Decided, so the PR records the owner's approval.
- The library's `Attributes::parse` accepts the same input afterwards.
- The change is in `Attributes::from_node` in `src/parse/signer.rs`; follow
  the TDD workflow in AGENTS.md.
