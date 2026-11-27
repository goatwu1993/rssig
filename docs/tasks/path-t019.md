# PATH-T019 fix: Decide whether an embedded certificate webpki cannot parse is blamed when no path is found

Task detail for **PATH-T019** in [TODO.md](../../TODO.md), which keeps the ID,
title and checkbox. From the PR #107 review (PATH-T014).

webpki 0.103.16 parses each embedded candidate before it compares the
candidate's subject with the issuer sought (`verify_cert.rs:120-124`,
`build_chain_inner`), and keeps the parse error if no path is accepted.
`ExtensionValueInvalid` ranks 30 and `UnknownIssuer` 0 (`error.rs`, `rank`).
So an embedded certificate on no path that repeats an extension webpki keeps
(subjectAltName, nameConstraints, cRLDistributionPoints) changes the result:

- **Untrusted root.** It becomes `certificate_chain_invalid` with webpki's
  message, though the certificate is on no path. Pinned, and claimed under
  the PATH candidate rule `unparsed-candidate`:
  `path-bad-unrelated-repeated-issuer-fails-in-webpki` and
  `path-bad-ca-repeated-san-first-under-another-root`. PATH-013's callback
  rejection of a malformed intermediate on no path is not blamed
  (`path-013-bad-unrelated-malformed-issuer-is-not-blamed`).
- **A CA lacking keyCertSign (PATH-008).** The path callback rejects it with
  `UnknownIssuer` and sets `invalid_ca_usage`. `path_error` (`engine/src/trust.rs`)
  reports `invalid_key_usage` only while webpki's error is `UnknownIssuer`, so
  such an off-path certificate hides the key-usage diagnosis too. No case
  pins this yet; add one (a PE embedding the issuer without keyCertSign and
  an unrelated CA that repeats its subjectAltName).
- **Other failures.** How the parse error ranks against rssig's revocation,
  expiry and usage results is not pinned.
- **Other parse errors.** A certificate webpki cannot parse for another
  reason gives another error (`UnsupportedCriticalExtension`, `BadDer`,
  `MalformedExtensions`), some ranked higher; how webpki ranks these against
  each other and the path callback is PATH-T011's, which this task must
  agree with.
- **Other extensions.** Only a repeated subjectAltName is pinned; a repeated
  nameConstraints or cRLDistributionPoints off the path is expected to act
  the same, by the same webpki code, but has no case.

Decide whether an off-path certificate is blamed at all (for example, set
aside a parse failure of a candidate whose subject does not match, as the
path callback cannot), then give the result a decision entry and move the
claimed cases to it, renamed with that entry's prefix.

Left from the PR #107 review, to do with this task:

- The claimed cases tell the result apart only by webpki's error name in the
  message (`ExtensionValueInvalid`), as does `path-014-bad-ca-repeated-san`;
  pin a stable serialized field once the result is decided.
- `tests/fixtures/manifest.json` labels `bad-path-unrelated-repeated-issuer.exe`
  and `good-path-ca-repeated-san-first.exe` "PATH-014"; relabel the off-path
  outcome with the new entry.
- The manifest entry of `bad-path-unrelated-malformed-issuer.exe` lists keys
  `[40..45; 32]`, but its generator also uses 47 and 48.
- The stranger and dangling certificates are built twice in
  `engine/src/tests/certificate_paths.rs` (PATH-013 and here); share a helper
  so the two fixtures stay comparable, and add a control without the defect
  pinned as `untrusted_root`.
