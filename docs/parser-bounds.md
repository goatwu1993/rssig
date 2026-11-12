# Parser bounds audit (SEC-01)

This audit covers local structural arithmetic and allocation bounds on 32-bit and
64-bit targets. It does not establish exhaustive input safety. Aggregate verification work is covered by [SEC-02 budgets](verification-budgets.md).
CLI file reads and retained reports use [SEC-03 host limits](host-limits.md).
Fuzzing remains TEST-02.

| Boundary | Bounds and evidence |
| --- | --- |
| PE | Header ranges checked before additions; section ends and certificate sizes use checked addition. Maximum e_lfanew fixture and truncated-prefix tests retained. |
| DER/CMS | Length-of-length limited to four bytes; checked header/body addition; bounded child counts, opaque recursion, and signer counts. Added rejection of forbidden end-of-contents tags, with a one-byte NULL-parameter mutation. Unknown valid algorithm parameters still remain opaque. |
| CAB | Folder/file counts are u16; table bounds precede allocation and traversal. Block sizes are bounded by remaining cabinet bytes; unpacked totals use u64. Field readers now avoid offset-plus-width overflow, including direct usize::MAX unit tests. |
| NAVX | Checked header-plus-payload size, minimum wrapper length, exact back-pointer and marker validation. Existing truncation/maximum-size tests retained. |
| MSI/MSP | Strict CFB dependency reader, sector alignment, bounded storage depth/entry counts, stream length bounded by input, checked aggregate stream lengths before reading. Mutation coverage includes CFB v3/v4 and MSP. Dependency internals are not independently proven by this audit. |
| ZIP/AppX | Checked slices and u64-to-usize conversions; central-directory equality and count bounds precede allocation. Per-entry/total byte caps bound decompression buffers; exact stream consumption and CRC checked. Existing overlap/ZIP64/truncation tests retained. |
| PowerShell/XML | Strict text decoding, even UTF-16 byte counts, ordered marker ranges, bounded signature text before base64 allocation. Whole-file decoding is proportional to caller input; host input caps remain SEC-03. |
| WSH | Input/signature limits, checked marker ordering and UTF-16 position conversion; XML node budget and DTD prohibition. Existing encoding, truncation, and resource-limit cases retained. |
| RDP | Input/property budgets precede signature decoding; wrapper length compared by subtraction after a minimum-header check. Existing scope/encoding and maximum-count cases retained. |
| AppX XML | Footprint byte and XML node limits; bounded block sizes and checked accumulation. Existing namespace, identity, block-map, and bundle cases retained. |

`tests/parser_bounds.rs` verifies known-good committed artifacts, then exercises
short header prefixes and zero/maximum DWORD mutations through explicit public
format entry points. Mutated fields may be intentionally unauthenticated, so the
mutation property is absence of panic and serializable typed failures, not blanket
rejection. Specific malformed structures retain exact fixture/spec assertions.
No fixture is executed, installed, or rewritten by these tests.

The CMS regression was observed succeeding before the fix, and the direct CAB
maximum-offset test was observed panicking before the fix. Both now reject their
inputs. The CMS pair preserves all bytes except one algorithm-parameter tag;
this tests structural rejection rather than claiming a cryptographic failure.

Validation runs on the host plus the bare-metal parser compile target. Compilation
on a 32-bit target does not execute the mutation corpus there; 32-bit runtime
coverage remains TEST-04. Linux runtime validation is delegated to CI.
