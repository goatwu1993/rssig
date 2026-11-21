# SEC-12: Decide multi-signature and bundle failure semantics

Today every nested signature must verify
([CMS-013](../cms.md#cms-013-a-nested-signature-is-verified-like-the-primary-one),
Observed). No RFC defines nested Authenticode signatures, and OpenSSL and
Bouncy Castle ignore the unsigned attribute that carries them, so the
all-required rule is rssig's own. osslsigncode 2.16 (a Windows-format
reference) verifies every signature and succeeds when any one is valid
(`osslsigncode.c:3319-3346`).

## Proposed behavior (owner to confirm in this task's PR)

- **Fixed rule (stays in CMS-013):** each nested signature is checked with
  the same CMS, signer, timestamp, path and revocation rules as the primary.
- **Policy (new `POLICY-` entry):** which signatures must verify.
  - Default: all. Fails closed; this is today's behavior.
  - Opt-in: any one valid signature is enough, for dual-signed files (for
    example a SHA-1 primary with a SHA-256 nested signature) and for a valid
    file with an appended bad nested signature.
  - No primary-only mode unless the owner asks for one.
- **Report:** every signature's outcome and the selected mode appear in the
  JSON in every mode.

## Also in scope

Primary/nested ordering, first-failure precedence, and bundle/child identity
and signer binding. Test a valid first signature followed by a bad one and
the reverse. Later parsing failures must not mask earlier cryptographic
failures during refactoring.
