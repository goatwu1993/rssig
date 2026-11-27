# PATH-T016 fix: Decide whether a path may end at a configured root whose basicConstraints, keyUsage or extKeyUsage does not decode

Task detail for **PATH-T016** in [TODO.md](../../TODO.md), which keeps the ID,
title and checkbox. It needs the owner's answer (`owner-question` skill)
before any change: either answer changes what rssig accepts or rejects.

A configured root is a key
([PATH-011](../path.md#path-011-configured-anchors-are-keys)), and
[PATH-013](../path.md#path-013-a-path-certificate-whose-extension-does-not-decode-fails-the-path)
says its extensions are not judged. That holds for five of the eight
extensions PATH-013 names: a root whose subjectKeyIdentifier does not decode
verifies (CRL-042). It does not hold for basicConstraints, keyUsage and
extKeyUsage. Before PATH-T010 the report of such a root could not be built, so
a path that ended at it failed with `certificate_chain_invalid` and a decoder
message. PATH-T010 made the report mark the extension, and kept that failure
on purpose (`TrustStore::chain_report`, pinned by the unit test
`a_path_to_a_root_whose_reported_extension_does_not_decode_still_fails`),
because accepting it was not asked.

The choices:

- **Accept it**, as PATH-011 and PATH-013 read today and as the other five
  extensions behave: remove the check in `chain_report`; the root appears in
  `trust.chain` with `undecoded_extensions`.
- **Keep rejecting those three**, and say so in PATH-011 or PATH-013.
- **Judge all eight in a root**, as OpenSSL does for a root it finds in its
  store (`ossl_x509v3_cache_extensions` marks it `EXFLAG_INVALID`; PATH-013,
  Note). This rejects the malformed-subjectKeyIdentifier root that verifies
  today and changes Decided PATH-011.

Today only the first configured root that matches the accepted anchor (same
subject, key and name constraints) is reported and so judged: with a clean
root and a malformed copy of it, the result depends on which was loaded
first. The answer should say whether any or every matching root counts.

Its message names the first undecoded extension in report order
(basicConstraints, keyUsage, extKeyUsage), where the old decoder message was
for the first to fail in the order extKeyUsage, keyUsage, basicConstraints.

The kept rejection is deliberately not in `tests/cases.json` yet: it is a
leftover awaiting this answer, pinned only by that unit test, and a case
would present it as a rule. Whichever is chosen, add a root fixture and cases. A root that repeats
basicConstraints, keyUsage or extKeyUsage
([PATH-014](../path.md#path-014-a-path-certificate-that-repeats-an-extension-fails-the-path))
never reaches this check: webpki refuses it when the roots are loaded, which
the same unit test pins.
