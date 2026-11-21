# SEC-25: Narrow CMS-009 to the attributes RFC 5652 limits

[CMS-009](../cms.md#cms-009-an-attribute-oid-appears-at-most-once-in-a-signerinfo)
rejects every duplicated attribute OID. RFC 5652
([copy](../rfc/rfc5652.txt)) and the references support less.

## Decision

Decided by the owner, who delegated the call in PR #72. The countersignature
row is the owner's own decision. Implementation is this task's own PR.

| Attribute | Behavior | Reason |
|---|---|---|
| contentType, messageDigest, signingTime repeated, or without exactly one value | Rejected, `invalid_signature` at `cms` (unchanged) | References agree [1] |
| Any attribute with an empty value SET | Rejected (unchanged) | References agree for the attributes they check; written choice for the rest [2] |
| Countersignature attribute repeated | Passes the CMS layer; the file is rejected by TSA-004, `invalid_timestamp` at `timestamp` | RFC and Bouncy Castle allow repeats; "at most one timestamp" is TSA-004's rule [3] |
| RFC 3161 timestamp attribute repeated (either OID) | Same as countersignature | No RFC forbids it; every timestamp-count failure then has one code [4] |
| Nested-signature attribute (SpcNestedSignature) repeated | Rejected, `invalid_signature` at `cms` (unchanged), as a written choice | The format references disagree on what a repeat means [5] |
| Any other OID repeated, signed or unsigned | Accepted | No RFC or reference rejects them, and rssig never acts on them [6] |

## Sources

RFC copies are in [docs/rfc](../rfc/README.md). Line numbers are for OpenSSL
3a3f1356, bc-java e03fee0b, osslsigncode 2.16 (04c9aa7e) and jsign 7.6
(cf5d2ce).

1. RFC 5652 sections 11.1, 11.2 and 11.3: each attribute "MUST have a single
   attribute value", and the SignedAttributes "MUST NOT include multiple
   instances" of it. OpenSSL `crypto/cms/cms_att.c:44-46` (`CMS_ATTR_F_ONLY_ONE`,
   `CMS_ATTR_F_ONE_ATTR_VALUE`) checked at `:213-232` and `:254-273`. Bouncy
   Castle `cms/SignerInformation.java:678-715`
   (`getSingleValuedSignedAttribute`).
2. RFC 5652 sections 11.1 to 11.3 forbid zero values for those attributes and
   section 11.4 requires "one or more" for a countersignature. OpenSSL
   `crypto/cms/cms_att.c:231-232` (`count == 0`) and Bouncy Castle
   `cms/SignerInformation.java:305-312` reject it for the attributes they
   check. RFC 5652 section 5.3 defines `attrValues SET OF AttributeValue`
   with no minimum, so rejecting an empty SET on any other attribute is a
   written choice: an attribute without a value states nothing.
3. RFC 5652 section 11.4: "The UnsignedAttributes in a signerInfo may include
   multiple instances of the countersignature attribute." Bouncy Castle
   `cms/SignerInformation.java:293-300` reads every instance. OpenSSL
   `crypto/cms/cms_att.c:47` lists countersignature without
   `CMS_ATTR_F_ONLY_ONE`. TSA-004 in [tsa.md](../tsa.md);
   `src/verify/timestamp.rs:114-118`.
4. RFC 3161 Appendix A defines the timestamp attribute and sets no limit on
   instances. RFC 5126 section 6.1.1: "Several instances of this attribute
   may occur with an electronic signature, from different TSAs." Neither
   OpenSSL nor Bouncy Castle lists it among single-instance attributes
   (`crypto/cms/cms_att.c:39-53`). TSA-004; `src/verify/timestamp.rs:22-28`.
5. No RFC covers SpcNestedSignature (Microsoft, OID 1.3.6.1.4.1.311.2.4.1).
   osslsigncode `osslsigncode.c:3387-3411` collects nested signatures from
   every instance of the attribute; jsign `SignatureUtils.java:100-105` reads
   only the first instance (`getUnsignedAttribute`). Because rssig acts on
   this attribute and the references disagree, a repeat stays rejected;
   several values in one attribute remain the supported form.
6. RFC 5652 section 5.3: `SignedAttributes` and `UnsignedAttributes` are
   `SET SIZE (1..MAX) OF Attribute` with no uniqueness rule. OpenSSL
   (`crypto/cms/cms_att.c:39-53`) and Bouncy Castle
   (`cms/SignerInformation.java:678-715`) restrict only the listed
   attributes.

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
