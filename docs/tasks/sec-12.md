# SEC-12: Decide multi-signature and bundle failure semantics

Today every nested signature must verify
([CMS-013](../cms.md#cms-013-a-nested-signature-is-verified-like-the-primary-one),
Observed). No RFC defines nested Authenticode signatures, and OpenSSL and
Bouncy Castle ignore the unsigned attribute that carries them, so the
all-required rule is rssig's own. osslsigncode 2.16 (a Windows-format
reference) verifies every signature and succeeds when any one is valid
(`osslsigncode.c:3319-3346`).

## Decision

Decided by the owner, who delegated the call in PR #72. Implementation is
this task's own PR, after SEC-25.

- **Fixed rule (CMS-013, becomes Decided):** each nested signature is checked
  with the same CMS, signer, timestamp, path and revocation rules as the
  primary, under the same verification mode and options.
- **Policy (new `POLICY-` entry):** which signatures must verify.
  `--signatures all|any` on the CLI and a matching `VerifyOptions` field.
  - `all` is the default and is today's behavior: every signature must
    verify, and the first failure, primary first and then nested signatures
    in file order, is the file's error.
  - `any`: the file verifies when at least one signature, primary or nested,
    verifies completely. A signature that fails for any reason of its own,
    including a malformed nested CMS, a weak algorithm or an untrusted path,
    counts as failed, not as fatal.
  - There is no primary-only mode.
- **Always fatal, in both modes:** a primary envelope that cannot be parsed
  (nested signatures live inside it), a container or format error, and
  `resource_limit_exceeded`.
- **Report:** the JSON names the selected policy and lists every signature
  with its own outcome in both modes. When `any` fails, the file's error is
  the primary signature's.
- **Not alternatives:** bundle members and timestamps. Every member of an
  MSIX/AppX bundle must verify under either policy, each member applying the
  policy to its own signatures; timestamp count stays TSA-004.

`any` is safe to offer because each signature still passes every check on
its own; an attacker cannot add a passing signature without a trusted
code-signing certificate.

## Work

- Fixtures and cases under both policies: a good primary with a bad nested
  signature, the reverse, both bad, and a dual-signed file with a SHA-1
  primary and a SHA-256 nested signature.
- Pin primary/nested ordering, first-failure precedence, and bundle/child
  identity and signer binding. Later parsing failures must not mask earlier
  cryptographic failures.
- Update the JSON schema, `docs/boundaries.md` and the library documentation;
  add the policy to the glossary's list of policies.
