# Certificate-path decisions

Numbered decisions behind rssig's certificate-path policy. The entry format is
defined in [Decision indexes](decisions.md); the explanation of the profile,
webpki's role and its limits is in
[certificate-path policy](certificate-path-policy.md), and the history in
SEC-06 ([done](tasks/done.md), PR #40). Path rules for CRL issuers are CRL
entries ([CRL decisions](crl.md)); time rules are [time decisions](time.md).

## Order

Entries are numbered from most to least important, in the tiers used by
[CRL decisions](crl.md#order); within a tier, Decided entries come before
Observed ones. A new entry takes the next free number.

1. **Fail-open:** a broken rule could accept a path that should not be
   trusted.
2. **Availability:** a broken rule would reject a valid path or report the
   wrong chain for one.
3. **Result diagnostics:** which chain or anchor is reported.

## Index

| ID | Decision | Status | Pins |
|---|---|---|---|
| [PATH-001](#path-001-trust-comes-only-from-a-configured-root) | Trust comes only from a configured root | Decided | acceptance |
| [PATH-002](#path-002-an-issuer-is-identified-by-its-key-not-its-name) | An issuer is identified by its key, not its name | Decided | acceptance |
| [PATH-003](#path-003-intermediates-must-be-cas-and-a-ca-cannot-sign) | Intermediates must be CAs, and a CA cannot sign | Decided | acceptance |
| [PATH-004](#path-004-path-length-constraints-are-enforced) | Path length constraints are enforced | Decided | acceptance |
| [PATH-005](#path-005-dns-name-constraints-apply-at-intermediates-and-anchors) | DNS name constraints apply at intermediates and anchors | Decided | acceptance |
| [PATH-006](#path-006-unknown-critical-extensions-are-rejected) | Unknown critical extensions are rejected | Decided | acceptance |
| [PATH-007](#path-007-an-authenticode-signer-needs-the-code-signing-eku-explicitly) | An Authenticode signer needs the code-signing EKU explicitly | Decided | acceptance |
| [PATH-008](#path-008-a-present-keyusage-must-allow-the-certificates-role) | A present KeyUsage must allow the certificate's role | Decided | acceptance |
| [PATH-009](#path-009-a-rejected-candidate-issuer-does-not-stop-path-building) | A rejected candidate issuer does not stop path building | Decided | acceptance |
| [PATH-010](#path-010-cross-signed-paths-lead-to-the-configured-root) | Cross-signed paths lead to the configured root | Decided | acceptance |
| [PATH-011](#path-011-configured-anchors-are-keys) | Configured anchors are keys | Decided | acceptance |
| [PATH-012](#path-012-the-reported-anchor-is-the-one-whose-constraints-accepted-the-path) | The reported anchor is the one whose constraints accepted the path | Decided | diagnostics |

## Tier 1: fail-open

### PATH-001: Trust comes only from a configured root

An embedded root or cross-signature does not establish trust, and a
cryptographically valid cycle (A→B→A) terminates with `untrusted_root` in
either order.

- **Status:** Decided
- **Decided by:** written argument (AGENTS.md, "Architecture and
  constraints": trust anchors come only from the configured root store)
- **Pins:** acceptance
- **Sources:**
  - RFC 5280 section 6.1: a path starts at a trust anchor the relying party
    chose; embedded certificates are untrusted candidates.

### PATH-002: An issuer is identified by its key, not its name

A matching issuer DN alone does not establish issuer identity: with only a
wrong-key issuer of the same name the path is `certificate_chain_invalid`,
and with both, the signature-valid issuer is chosen in either order.

- **Status:** Decided
- **Decided by:** written argument
- **Pins:** acceptance
- **Sources:**
  - RFC 5280 section 6.1.3 (a)(1): each certificate's signature is verified
    with the working public key.

### PATH-003: Intermediates must be CAs, and a CA cannot sign

An intermediate needs BasicConstraints with cA=true (a missing extension or
cA=false is `certificate_chain_invalid`); a CA certificate cannot act as the
signing leaf; a leaf may omit BasicConstraints.

- **Status:** Decided
- **Decided by:** written argument, PR #40 (SEC-06); enforced by webpki
- **Pins:** acceptance
- **Sources:**
  - RFC 5280 sections 4.2.1.9 and 6.1.4 (k).

### PATH-004: Path length constraints are enforced

pathLenConstraint 0 allows an issuing CA directly above the leaf; an upper CA
with one subordinate CA needs at least 1.

- **Status:** Decided
- **Decided by:** written argument, PR #40 (SEC-06); enforced by webpki
- **Pins:** acceptance
- **Sources:**
  - RFC 5280 sections 4.2.1.9 and 6.1.4 (l), (m).

### PATH-005: DNS name constraints apply at intermediates and anchors

A DNS SAN within a permitted subtree is accepted; one outside it, or within
an excluded subtree, is `certificate_chain_invalid`. A configured anchor's
name constraints are applied too. A publisher CN is not a DNS identity.

- **Status:** Decided
- **Decided by:** written argument, PR #40 (SEC-06); enforced by webpki
- **Pins:** acceptance
- **Sources:**
  - RFC 5280 section 4.2.1.10.
  - webpki `subject_name/mod.rs` for the supported name forms; see
    [certificate-path policy](certificate-path-policy.md#applicable-profile-and-boundaries).

### PATH-006: Unknown critical extensions are rejected

An unfamiliar extension is ignored when noncritical, preserving the
certificate DER, and rejected when critical on the leaf or an intermediate.

- **Status:** Decided
- **Decided by:** written argument, PR #40 (SEC-06); enforced by webpki
- **Pins:** acceptance
- **Sources:**
  - RFC 5280 section 4.2: a certificate with an unrecognized critical
    extension must be rejected.

### PATH-007: An Authenticode signer needs the code-signing EKU explicitly

For every Authenticode format (PE, MSI and the others that share its
verifier), the signing leaf must list the code-signing EKU (`invalid_eku` at
`certificate`); an intermediate EKU, when present, must permit it
(`invalid_eku` at `certificate_chain`); an intermediate without EKU is
unrestricted. RDP signers follow RDP's own EKU policy (codeSigning, serverAuth
or Remote Desktop signing; see [RDP](rdp.md)), which a future `RDP-` entry
will state; TSA certificates follow TSA-003.

- **Status:** Decided
- **Decided by:** written choice, PR #40 (SEC-06)
- **Pins:** acceptance
- **Sources:**
  - webpki `KeyUsage::required_if_present` propagates the leaf's required
    usage through intermediates.
  - Written argument: an Authenticode signer must be a code-signing
    certificate; no Windows equivalence is claimed.

### PATH-008: A present KeyUsage must allow the certificate's role

A present leaf KeyUsage needs digitalSignature and a present intermediate
KeyUsage needs keyCertSign (`invalid_key_usage`); an absent KeyUsage is
unrestricted. rssig checks both itself, because webpki's TLS-oriented checks
do not.

- **Status:** Decided
- **Decided by:** written argument, PR #40 (SEC-06)
- **Pins:** acceptance
- **Sources:**
  - RFC 5280 section 4.2.1.3.

## Tier 2: availability

### PATH-009: A rejected candidate issuer does not stop path building

An otherwise valid CA missing keyCertSign does not prevent selection of an
acceptable alternative with the same subject and key, in either order.

- **Status:** Decided
- **Decided by:** written argument, PR #40 (SEC-06)
- **Pins:** acceptance
- **Sources:**
  - Written argument: a valid embedded issuer must not be lost because
    another candidate was tried first (as TIME-009 for signing time).

### PATH-010: Cross-signed paths lead to the configured root

Among cross-signatures, the one leading to the configured root is chosen,
including when another appears first; changing the configured root changes
the selected chain. Adding an anchored variant to a cycle yields the direct
trusted path in either order. The first acceptable path is reported; no
shortest, newest or strongest preference is promised.

- **Status:** Decided
- **Decided by:** written argument, PR #40 (SEC-06)
- **Pins:** acceptance
- **Sources:**
  - RFC 5280 section 6.1 (any path to a chosen trust anchor is acceptable).

### PATH-011: Configured anchors are keys

Only subject, public key and name constraints are taken from a configured
root. Its expiry, self-signature, BasicConstraints, path length, KeyUsage and
EKU are not checked as path policy, at the validation time or at a lifetime
signing time, so a lifetime path through a root re-issued after the signing
time is accepted.

- **Status:** Decided
- **Decided by:** written choice, PR #40 (SEC-06), and kept as policy for
  lifetime signing in the PR #43 review (SEC-14). CRL-015 applies the same
  rule to CRL signing
- **Pins:** acceptance
- **Sources:**
  - webpki `anchor_from_trusted_cert`: an anchor is subject, key and name
    constraints.
  - RFC 5280 section 6.1.1 (d): trust anchor information is a name and key,
    optionally with constraints.
- **Note:** the cases pin the rule at the validation time only; no case pins
  a root re-issued after a lifetime signing time.

## Tier 3: result diagnostics

### PATH-012: The reported anchor is the one whose constraints accepted the path

When configured roots share a subject and key, `trust.chain` reports the one
whose name constraints accepted the path.

- **Status:** Decided
- **Decided by:** review fix, PR #40 (the first run reported a root whose
  constraints had rejected the leaf)
- **Pins:** diagnostics
- **Sources:**
  - Written argument: the report must name the anchor webpki actually used.

## Candidate rules

Unnumbered. `tests/decision-claims.json` assigns these cases here until they name an entry.

- `attach`: cases that pin an existing PATH entry but do not name it yet: every format's untrusted-root case and RDP's key-usage case.
- `certificate-signature`: a certificate whose issuer's signature does not verify breaks the path (`certificate_chain_invalid`); this needs a new entry.
