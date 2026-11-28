# Aggregate verification budgets (LIMIT-T002)

Every public verification call creates one consumable budget. All PE certificate
entries, CMS signers, nested signatures, RFC 3161 tokens, PKCS#9 countersigners,
RDP signers, and embedded AppX bundle children share it. Parsed-container entry
points use the same limits. Each CLI input receives its own budget. Limits are
fixed engine limits; there is no implicit bypass in integrity-only mode.

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
exhaustion. An RDP fixture whose CA admits serverAuth only covers a failed first
EKU followed by budget exhaustion on a retry: exhaustion propagates immediately
with its original typed resource details
(`rdp_eku_retry_propagates_later_budget_exhaustion`). Ordinary EKU failures are
ranked as [CRL-027](crl.md#crl-027-which-error-a-rejected-chain-reports) pins: a
revocation first, with the other usages' CRL gaps merged into it, then a
failure a CRL could complete, then the first. Existing failure expectations
remain unchanged.

An RDP usage is retried only when another usage could change its failure
(LIMIT-T007), since each retry reserves a whole search. Two failures cannot
change:

- **A failure of the signer alone**, found before any path is built: a KeyUsage
  without digitalSignature, or a lifetime signer issued after its signing time.
  Neither reads the usage, which for RDP is never timeStamping and is always in
  the signer's own list. The failure returned must be that one too
  (`invalid_key_usage` at `certificate`, or lifetime signing's
  `certificate_not_yet_valid`), so a usage-dependent check placed ahead of them
  keeps the search going. (A signer extension that does not decode is rejected
  before any usage is tried, by PATH-013.)
- **Any failure when no embedded certificate other than the signer that can be
  on its path carries an extKeyUsage.** webpki 0.103.16 judges the requested usage
  only in a certificate on a candidate path that carries one
  (`KeyUsage::required_if_present`), the signer lists every usage tried, and a
  configured anchor keeps no extensions. An embedded certificate can be on a
  path only when its subject is the signer's issuer or another such
  certificate's; a timestamp authority's certificate beside the signer's
  usually is not, and counts only if its subject is on that chain. With none of those carrying an extKeyUsage, every usage builds the same
  candidate paths, and rssig's path callback never reads the usage, so each
  fails the same way and names only another `required_eku`
  (`without_a_steering_certificate_every_usage_has_the_same_result`,
  `only_a_certificate_that_can_be_on_the_path_steers_it`, which also fails when
  the webpki version or the path checks' fields change). Which certificates
  can be on a path is found at most once, after the first failure the signer
  alone does not explain and only while another usage is left to try, in time
  linear in the embedded certificates; the names it re-encodes are charged to
  `decoded_bytes`.

In both, every usage not tried would fail as the first did, so the CRL-027
ranking over the usages tried returns the same failure: the first, with its own
CRL gaps. Otherwise (an embedded CA that can be on the path carries an
extKeyUsage, which may admit one usage and not another) every usage is still
tried. Stopping never accepts more: at worst it reports the first usage's
failure. The budget effect is pinned by
`rdp_stops_after_a_path_failure_no_other_eku_can_change` (one reservation, and
the same `untrusted_root` with a single search left) and
`rdp_stops_after_a_signer_failure_no_other_eku_can_change`; before LIMIT-T007 a
file whose first usage failed this way, verified with a single search left,
reported `resource_limit_exceeded` for the retry instead.

CLI file/root/CRL reads, batch/report buffering, and nonregular/changing inputs
are covered by [LIMIT-T003 host limits](host-limits.md). Library callers own their
input and returned report memory. This is not a wall-clock deadline,
fuzzing audit, Windows policy equivalence, or independent interoperability proof.
