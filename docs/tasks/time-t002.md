# TIME-T002 docs: Give each kept lifetime-signing review decision a decision entry

Task detail for **TIME-T002** in [TODO.md](../../TODO.md), which keeps the ID,
title and checkbox.

Recorded from the PR #43 reviews; none permits an invalid signature to verify.
The task is to check each decision below against the `TIME-` and `PATH-`
indexes ([which index](../decisions.md#which-index)) and add the entries that
are missing.

## Kept as decisions

Each changes only with a new decision and paired fixtures.

- Trust anchors: configured anchors remain keys. Their validity is not checked
  at the validation time or at a lifetime signing time, so a lifetime path
  through a root re-issued after the signing time is accepted.
- Error precedence: the leaf lifetime notBefore check runs before path
  building (like webpki's leaf validity check), so it precedes
  untrusted_root/unknown-issuer and unknown revocation status of the signer
  path. Store-wide CRL freshness errors are still reported first, by the TSA
  check. A rejected issuer issued after signing ranks as a webpki validity
  error, so it can hide a revoked or wrongly signed issuer on another
  candidate path (pinned by `time-011-lifetime-rollover-revoked-issuer`); the
  signature is still rejected. Equal-rank failures report the first
  encountered.
- CRL/revocation: revocation is evaluated only at the validation time, and a
  revocation failure on a path is reported before the signing-time check of
  that path. Historical (signing-time) revocation status is not modeled.
- Diagnostics: `details.certificate` names the chain certificate that failed
  the signing-time or fractional-expiry check (an intermediate when it is the
  cause), matching the existing fractional-expiry convention, not always the
  signer leaf. Errors from webpki's own validity checks instead name the leaf
  in `details.certificate` while `not_before`/`not_after` belong to the
  certificate that failed, lifetime or not. This includes a lifetime
  intermediate issued after a timestamp that equals the validation time.
- Unsigned timestamps: the signing-time check (and the non-lifetime
  timestamp-before-notBefore rejection) is a consistency check. Removing the
  unsigned timestamp leaves an untimestamped signature validated at the
  validation time only.
- KeyUsage precedence (pre-existing, PATH-T001): the keyCertSign rejection flag
  is shared across candidate paths, so once any candidate lacked keyCertSign a
  final unknown-issuer failure from another path is reported as
  invalid_key_usage. Fails closed; a per-path reason needs separate work.
- Schema: `TrustReport.lifetime_signing` defaults to `false` when reading
  reports written before TIME-T001, so an older report cannot distinguish "not
  lifetime-signed" from "not evaluated". `validation_time` shows which time
  was used; `Option<bool>` would be a schema change.
- Error details: on "not valid at the signing time", `validation_time` is the
  validation time (when the certificate may be valid) and `signing_time` is
  the instant that failed, unlike other validity errors where
  `validation_time` is the failing instant. CRL presence/freshness errors for
  a lifetime signer carry no `lifetime_signing` detail; per-chain revocation
  evidence is CRL-T001 and CRL-T002. Both are schema decisions.

## Follow-ups

The open follow-ups from the same reviews are separate tasks in
[TODO.md](../../TODO.md), independent of each other: TIME-T005 (fractional
expiry during path building), TIME-T006 (the `certificate_report_error`
fallback), TIME-T007 (lifetime fixtures for MSI, CAB, script and AppX),
LIMIT-T007 (the repeated RDP path search) and TSA-T004 (shared timestamp
token builders).
