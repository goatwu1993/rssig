# POLICY-T001 feat: Add the signature policy and pin multi-signature semantics

Today every nested signature must verify
([CMS-013](../cms.md#cms-013-a-nested-signature-is-verified-like-the-primary-one),
Observed). The all-required rule is rssig's own:

- No RFC defines nested Authenticode signatures. RFC 5652 section 5.3
  ([copy](../rfc/rfc5652.txt)) only says unsigned attributes are not signed
  by the signer; SpcNestedSignature (OID 1.3.6.1.4.1.311.2.4.1) is
  Microsoft's.
- OpenSSL 3a3f1356 and Bouncy Castle e03fee0b have no equivalent: neither
  knows the attribute (`crypto/cms/cms_att.c:39-53` lists the attributes
  OpenSSL interprets; Bouncy Castle `cms/SignerInformation.java` reads only
  countersignatures from unsigned attributes, `:293-300`), so their
  verification covers the primary SignerInfo only.
- The Windows-format references differ. osslsigncode 2.16 (04c9aa7e)
  collects every nested signature (`osslsigncode.c:3387-3411`), verifies
  each, and succeeds when any one is valid (`osslsigncode.c:3319-3346`,
  "success if at least one valid signature is found"). jsign 7.6 (cf5d2ce)
  lists them (`SignatureUtils.java:91-112`) and has no released verifier.

## Windows behavior, from Microsoft's documentation

Read from the MicrosoftDocs sources on GitHub (`win32` at bc82a65f,
`sdk-api` at 656e9656); nothing was run on Windows, and no Windows policy
equivalence is claimed.

- SignTool `verify` has three modes
  (`desktop-src/SecCrypto/signtool.md`, "Verify command options"): `/all`
  "Verifies all signatures in a file with multiple signatures"; `/ds Index`
  "Verifies the signature at a certain position"; and `/ms` "Uses multiple
  verification semantics. This behavior is the default of a WinVerifyTrust
  call."
- `WINTRUST_SIGNATURE_SETTINGS`
  (`sdk-api-src/content/wintrust/ns-wintrust-wintrust_signature_settings.md`):
  `WSS_VERIFY_SPECIFIC` with `dwIndex` verifies one chosen signature;
  `cSecondarySigs` counts the secondary signatures; `dwVerifiedSigIndex` is
  "The index used for verification. This member is set on return from
  Wintrust"; `pCryptoPolicy` is "the policy that a signature must pass to be
  considered valid."

So Windows does not require every signature by default: verifying all is the
opt-in `/all`, and a `WinVerifyTrust` call reports the single signature index
it used. The documentation does not define "multiple verification
semantics"; that it means "the first signature that passes" is an inference
from `dwVerifiedSigIndex` and `pCryptoPolicy`, not a quoted statement.

How the policy relates: `all` corresponds to SignTool `/all`; `any` is the
closest to the documented `WinVerifyTrust` default; a verify-one-index mode
(`/ds`) is not adopted. rssig's default stays `all`, which is stricter than
the Windows default, because rssig fails closed unless the caller opts out.

## Decision

Decided by the owner, who delegated the call in PR #72. Implementation is
this task's own PR.

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

- Revisit [CMS-009](../cms.md#cms-009-single-instance-attributes-occur-at-most-once-in-a-signerinfo)'s
  rejection of a repeated nested-signature attribute together with the policy.
  It is a written choice: osslsigncode accepts every instance while jsign reads
  only the first, so `any` mode may want to accept them.

- Fixtures and cases under both policies: a good primary with a bad nested
  signature, the reverse, both bad, and a dual-signed file with a SHA-1
  primary and a SHA-256 nested signature.
- Pin primary/nested ordering, first-failure precedence, and bundle/child
  identity and signer binding. Later parsing failures must not mask earlier
  cryptographic failures.
- Update the JSON schema, `docs/boundaries.md` and the library documentation;
  add the policy to the glossary's list of policies.
