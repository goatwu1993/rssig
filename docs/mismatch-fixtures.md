# Negative verification fixtures

These deterministic, test-only artifacts isolate binding, signature, and trust failures.
Every PE listed below retains the correct Authenticode image hash. The tests also
check signature math for attribute faults and valid outer signatures for nested
and timestamp faults. Never execute these synthetic PE containers.

| Bad artifact | Paired good artifact | Intended fault |
| --- | --- | --- |
| `bad-cms-content-digest.exe` | `good-pe64.exe` | Correctly signed attributes contain the digest of different CMS content; PE image digest remains correct. |
| `bad-cms-content-type.exe` | `good-pe64.exe` | Correctly signed contentType attribute declares TSTInfo while encapsulated content is SpcIndirectDataContent. |
| `bad-signer-issuer.exe` | `good-pe64.exe` | SignerInfo names an unrelated issuer; serial and signed attributes remain unchanged. |
| `bad-signer-serial.exe` | `good-pe64.exe` | SignerInfo names serial 99 instead of the embedded signer certificate serial 2; issuer is unchanged. |
| `bad-cms-digest-set.exe` | `good-pe64.exe` | SignedData digestAlgorithms declares SHA384 while SignerInfo and the content digest use SHA256. |
| `bad-signature-digest-algorithm.exe` | `good-pe64.exe` | Signature algorithm declares ECDSA-with-SHA384 while SignerInfo digestAlgorithm is SHA256. |
| `bad-signature-key-algorithm.exe` | `good-pe64.exe` | Signature algorithm declares RSA while the embedded signer certificate contains an EC public key. |
| `bad-signer-public-key.exe` | `good-pe64.exe` | Root-signed signer certificate contains a different valid P256 public key; CMS is signed by the original key. |
| `bad-countersignature-digest.exe` | `good-countersignature.exe` | Correctly signed PKCS9 countersignature attributes bind to different parent signature bytes. |
| `bad-timestamp-signature.exe` | `good-rfc3161.exe` | Only the RFC3161 token signer signature is corrupted; parent CMS signature and timestamp imprint remain valid. |
| `bad-countersignature-signature.exe` | `good-countersignature.exe` | Only the PKCS9 countersignature signature is corrupted; parent CMS signature and countersignature content digest remain valid. |
| `bad-nested-signature.exe` | `good-nested.exe` | Only the nested CMS signature is corrupted; outer CMS signature and both PE image digests remain valid. |
| `bad-certificate-not-yet-valid.exe` | `good-pe64.exe` | Root-signed leaf certificate notBefore is NOW+1; CMS signature and image digest are valid. |
| `bad-certificate-expired.exe` | `good-pe64.exe` | Root-signed leaf certificate notAfter is NOW-1; CMS signature and image digest are valid. |
| `bad-signer-eku.exe` | `good-pe64.exe` | Root-signed leaf has serverAuth instead of codeSigning EKU; CMS signature remains valid. |
| `bad-signer-key-usage.exe` | `good-pe64.exe` | Root-signed leaf permits keyEncipherment but lacks digitalSignature; CMS signature remains valid. |
| `bad-certificate-signature.exe` | `good-pe64.exe` | Only the leaf certificate ECDSA signature is corrupted; the PE image and CMS signature are valid. |
| `bad-intermediate-signature.exe` | `good-intermediate.exe` | Only the intermediate certificate ECDSA signature is corrupted; leaf certificate signature and CMS signature remain valid. |
| `bad-crl-not-yet-valid.crl` | `good.crl` | Correctly root-signed CRL has thisUpdate NOW+1 while nextUpdate remains NOW+1000. Expected crl_not_yet_valid. |

Each native Rust test in [tests/cli](../tests/cli) pins its exit code, error
code, stage, and Problem Details type. Runs use a fixed validation time and
explicit local roots/CRLs, or explicit integrity-only mode.

`good-intermediate.crl` and `good.crl` provide a passing control with full
revocation coverage for `good-intermediate.exe`. Existing image, CMS signature,
page-hash, and RFC 3161 imprint mismatch fixtures remain in the suite.

Run the complete CLI suite with:

```sh
cargo test --locked
```

Fixture hashes, sizes, provenance, and good/bad pairing are recorded in
[the manifest](../tests/fixtures/manifest.json). Ordinary tests read committed
artifacts; only the explicit ignored maintenance command regenerates them.
