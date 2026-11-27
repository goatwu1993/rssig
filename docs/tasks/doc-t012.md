# DOC-T012 docs: Hold the 1.0 gate for decisions (owner decision)

Task detail for **DOC-T012** in [TODO.md](../../TODO.md), which keeps the ID,
title and checkbox. From PR #101.

Before 1.0.0 the [pre-1.0 flow](../../AGENTS.md#pre-10-flow) lets an agent
decide most things and tell the owner. The gate closes that:

1. Review every Observed entry in every index: make it Decided, change it, or
   keep it Observed on purpose.
2. Review every call listed as "decided without asking" in a merged PR's
   description.
3. Replace the "Pre-1.0 flow" section of AGENTS.md with the flow for 1.0 and
   later.

The gate also settles what the review of PR #101 found unclear in
[docs/decisions.md](../decisions.md#entry-format), with the owner's answers of
2026-11-27 (in the Claude conversation) as the starting point:

- Where OpenSSL and Bouncy Castle differ, an entry stays Observed until the
  owner decides; a written choice does not settle it.
- A Windows-format rule is settled by the references only when osslsigncode,
  jsign and relic all have it and agree; a tiebreaker decides what rssig does
  but leaves the entry Observed.
- "Decided by" holds one listed value; audit entries that use others (for
  example `review fix, PR #43`) or join several.
- BoringSSL is cited as `main` with no commit; pin one.
