# CLI host limits (SEC-03)

`verify` and `parse` bound host reads before handing bytes to format parsers.
The verification core keeps its separate [aggregate work budgets](verification-budgets.md).

| Resource | Default and hard ceiling | Lowering the limit |
| --- | --- | --- |
| Input bytes per file | 128 MiB | `--max-input-bytes N` |
| Input bytes per batch | 512 MiB | `--max-total-input-bytes N` |
| Compact JSON per successful file result | 8 MiB | `--max-report-bytes N` |
| Retained successful-result JSON per batch | 32 MiB | `--max-total-report-bytes N` |
| Input paths | 128 | Fixed |
| Each path | 4,096 native path bytes | Fixed |
| Each root/CRL source file | 8 MiB | Fixed |
| Root/CRL source files combined | 32 MiB, at most 64 paths | Fixed |
| Loaded trust artifacts | 32 MiB DER, at most 4,096 roots and 64 CRLs | Fixed |
| Each failure result | 64 KiB compact JSON | Fixed diagnostic reserve |

The four options accept positive decimal byte counts up to their hard ceilings.
A count/path/option violation is a configuration error: plain stderr, exit 2,
and no JSON on stdout. Root/CRL loading failures use the same configuration
contract. Input-read and report-limit failures are per-file JSON failures (exit 1).

On macOS/Linux, files open with `O_NONBLOCK`; the opened descriptor must identify
a regular file before any read. This rejects directories, devices, sockets, and
FIFOs without waiting for FIFO writers. Symlinks resolving to regular files are
accepted. Checking the opened descriptor prevents a path replacement between
an earlier metadata check and open from bypassing the type check. The optional
CLI-only `libc` dependency supplies the platform flag constant; no libc function
or native cryptographic operation is called.

Reads use an 8 KiB scratch buffer and stop at the remaining allowance. A one-byte
probe distinguishes exact EOF from excess data. File length metadata never
controls the allocation or replaces the streaming check, so growth after open
cannot bypass the cap. The probe is additional bounded overhead: at most one byte
per attempted file. Successful reads consume their actual payload bytes. An I/O
failure conservatively consumes the complete reservation for that attempt,
because its partial contents are discarded. Later files receive their own ordered
outcomes even if the batch allowance is exhausted. Truncation produces the actual
bytes read, which the normal format verifier must accept or reject.

Root and CRL source reads share an allowance before decoding. Loaded-artifact
count and DER byte limits are checked after native root enumeration and after
each explicit load. Native enumeration returns an OS-owned collection through
`rustls-native-certs`; these checks bound what the CLI accepts, not the platform
adapter's internal transient allocations. No CRL/AIA downloading is introduced.

Before retaining a successful result, a bounded counting writer serializes it
without allocating an encoded JSON buffer. Only admitted results are converted
to JSON values. Each failure has a separate 64 KiB reserve so a small or exhausted
success budget cannot prevent reporting a failure. Oversized failure evidence is
replaced with a resource-limit error preserving `original_code` and
`original_stage`. At most 128 such failure results plus one copied root problem
can be retained. The complete command is still emitted as exactly one JSON
document, and first-failure/ordered-result semantics are preserved.

Limits measure compact serialized result bytes; pretty-print whitespace, the
command envelope, JSON object overhead and transient domain objects are not
included in that byte counter. Input/parser/verification limits bound transient
work independently. This is a bound on input and retained report growth, not an
exact peak-RSS guarantee or a wall-clock deadline. The final JSON conversion may
briefly hold both bounded result collections. Library callers supplying byte
slices retain ownership of their own input/report memory.

Per-file exhaustion uses `resource_limit_exceeded` at stage `input`, with
`resource`, `limit`, `used`, and `requested` details. Resource names are
`input_bytes`, `total_input_bytes`, `report_bytes`, `total_report_bytes`, and
`failure_report_bytes`. For report counting, `used` is the successfully counted
prefix (including prior reports for the batch limit), and `requested` is the
next rejected serialization chunk. The failure is not a partial success verdict.

Portable cases reuse the committed valid PE fixture with lowered limits; the
manifest records those cases. Named CLI tests cover ordered batch failures,
report limits, and configuration errors. Host-specific tests use a disposable
sparse oversized root file and reject directories and `/dev/zero`. Stream unit
tests cover exact EOF, excess data, short reads, and continued growth independently
of filesystem metadata. A separate test bounds oversized error evidence.
