# Aggregate verification budgets (SEC-02)

Every public verification call creates one consumable budget. All PE certificate
entries, CMS signers, nested signatures, RFC 3161 tokens, PKCS#9 countersigners,
RDP signers, and embedded AppX bundle children share it. Parsed-container entry
points use the same limits. Each CLI input receives its own budget. Limits are
fixed engine policy; there is no implicit bypass in integrity-only mode.

| Resource (`details.resource`) | Allowance per verification |
| --- | --- |
| `certificate_entries` | 64 PE WIN_CERTIFICATE entries, checked before collecting each slice |
| `cms_objects` | 64 SignedData envelopes, including RFC 3161 tokens |
| `cms_bytes` | 64 MiB of submitted CMS DER and countersigner DER, including repeated/nested bytes |
| `certificates` | 256 CertificateChoices decoded across envelopes, including inherited timestamp candidate copies |
| `signers` | 128 signer verifications, including timestamp signers |
| `reports` | 64 signature and timestamp reports across the complete bundle tree |
| `report_certificates` | 4,096 certificate metadata/candidate slots reserved across reports and chain invocations |
| `decoded_bytes` | 512 MiB of conservatively reserved decoding/copy work |
| `hash_bytes` | 1 GiB of conservatively reserved digest input work |
| `containers` | 64 containers, including the outer bundle and all verified children |
| `path_work` | 12,800,000 reserved webpki path-building calls (64 complete search allowances) |
| `crypto_operations` | 1,024 CMS, timestamp, certificate and CRL signature primitive attempts |
| `nesting` | Nested Authenticode depth eight (outer signature has depth zero) |

These are work allowances, not measured peak heap usage or promises that every
combination below each individual limit succeeds. Reservations are deliberately
conservative, consumed before work, and never refunded. Four times each container's
stored bytes reserves text decoding and adapter copies. ZIP metadata is checked
before decompression; four times every entry's expanded size is reserved before
package parsing and again before each CMS integrity pass. Certificate metadata
reserves eight times DER length before repeated decoding/report construction;
opaque certificate metadata copies are charged separately. Candidate CA decoding
in webpki path callbacks also consumes the shared byte allowance before parsing. Container integrity
passes reserve four times stored input length, plus four times expanded ZIP entry
lengths. CMS content and SignerInfo bytes are additionally charged for each signer;
webpki's adapter charges actual signed message bytes before each primitive.
Certificate/root/CRL metadata hashing reserves the same eightfold DER allowance.
The final file SHA-256 is charged too. This bounds repeated work without treating
these reservations as an exact allocation or instruction counter.

webpki 0.103.16 has independent limits of 100 signature checks, 200,000 path-build
calls, 250,000 name-constraint comparisons and six subordinate CAs per invocation.
Its public API cannot accept a shared search counter. rssig reserves its full
200,000-call allowance before each invocation, including RDP EKU retries. Thus
at most 64 such searches (and 16,000,000 name-constraint comparisons) can occur.
A dependency update must re-audit those constants. A per-request RustCrypto
adapter charges each actual certificate/CRL signature attempt against the same
crypto counter as CMS. An exhausted adapter records that fact and returns the
typed budget error after webpki returns, even if webpki translates it into an
ordinary signature/path failure or finds another path. Each counter retains the
first rejected charge’s original usage and requested amount, so later callbacks
cannot alter the structured exhaustion evidence.

Existing local structural caps remain in force: DER children are bounded, CMS
has at most 64 SignerInfos per envelope, opaque certificate DER recursion is
bounded, MSI storage depth is 64 with 100,000 entries and aggregate stream lengths
bounded by input, ZIP has 4,096 entries with 64 MiB per entry and 256 MiB total,
and AppX XML has 8 MiB and 100,000-node limits. Script/RDP encoding, signature,
setting and XML limits are documented in their format guides. CMS inspection
has its own shared `InspectionBudget`; it does not establish verification.
See also the [structural audit](parser-bounds.md).

New exhaustion failures use `resource_limit_exceeded` at stage `cms`, with
a string `resource` and integer `limit`, `used`, and `requested` details.
Depth exhaustion retains the existing `malformed_cms` code/message and now carries
the same details. An exhausted input returns a failure, without partial signature
or bundle reports. The CLI still emits exactly one JSON document and processes
other inputs independently. Certificate-table framing/collection is bounded
before CMS verification; within a CMS object nested children are visited only
after their parent signer verifies. Malformed deep children are never decoded
past the depth limit.

Evidence includes committed 64/65-signer and 65-entry fixtures made by repeating
valid existing signed DER, plus depth-eight/depth-nine malformed-child fixtures.
The 63-signers-plus-two case was observed returning success with 65 reports before
the fix. Named CLI tests assert successful boundaries, typed serialized failures
and absence of partial reports. Focused unit tests exercise overflow, each work
counter, inherited timestamp/nested/RDP budgets, bundle sharing, and crypto/path
exhaustion. An inert multi-EKU RDP fixture also covers a failed first EKU
followed by budget exhaustion on a retry: exhaustion propagates immediately with
its original typed resource details. Ordinary EKU failures still retain the first
policy error. Existing failure expectations remain unchanged.

CLI file/root/CRL reads, batch/report buffering, and nonregular/changing inputs
are covered by [SEC-03 host limits](host-limits.md). Library callers own their
input and returned report memory. This is not a wall-clock deadline,
fuzzing audit, Windows policy equivalence, or independent interoperability proof.
