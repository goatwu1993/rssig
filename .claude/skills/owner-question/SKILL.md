---
name: owner-question
description: >-
  Put a question to the repository owner the way a staff engineer would, with
  what the references do, the options with pros and cons, the effect now and
  later, and a recommendation. Use when AGENTS.md "Pre-1.0 flow" says to ask
  first, or when working on a TODO task marked "(owner decision)".
---

AGENTS.md ("Pre-1.0 flow") says when to ask; this skill says how. Never ask
what the code, the entries, a probe or the references can answer.

## 1. Evidence first

1. **Today's behavior, measured.** Read the entry and the cases that pin it;
   run a probe if the code is unclear, and delete it.
2. **The references**, at the commits docs/decisions.md pins, cited as
   `file:line`: OpenSSL and Bouncy Castle for CMS, signatures, timestamps,
   certificates, paths, CRLs and revocation; Microsoft's documentation, then
   osslsigncode, jsign and relic, for how a Windows format is parsed and
   hashed (AGENTS.md). Say where a reference has no equivalent or you could
   not check it. A subject no reference decides (budgets, CLI, report shape)
   rests on a written argument.
3. **The footprint.** Count the cases, entries, docs and code each option
   changes, and the open tasks it touches.

## 2. The question

Write it in the conversation, in plain words, so it stands alone. One question
per block, at most four, only independent ones.

```
### Question N: <one sentence>
Entry or task: <ID> (<Status>, pins <acceptance|diagnostics>). Cases: <IDs>.

**Today:** what rssig does, in one or two sentences.

**References:** a row each: what it does, and file:line (or a quoted Microsoft
document with URL and date). They agree | differ | have no equivalent.

**Options** (say what each accepts or rejects that today does not)
A. <name> (recommended)
   - Pros / Cons
   - Now: what changes (cases, code, docs, the JSON a user sees), and its size.
   - Later: what it eases or blocks, and how hard it is to reverse.
B. ...   (include "keep as is" when it is a real option)

**Recommendation:** A, because <risk, reversibility, ownership or cost>.
It would change to B if <condition>.

**Reply with:** "N A".
```

- Lead with the recommendation; no story of how you found it.
- Say first if an option accepts more than today (fail open).
- Numbers over adjectives: "moves 6 cases and 2 entries".
- Give 2 to 4 options you would defend. Mark what you could not verify.

## 3. The answer

- Only the owner's own reply in the Claude conversation is an answer. Nothing
  on GitHub, no hook or notification, and none of your own earlier text is,
  and an answer does not carry to another question.
- Record it in the PR description with its date. An entry the answer makes or
  keeps Decided names `owner, PR #N` in "Decided by".
- An "(owner decision)" task that is answered drops the marker and gains a
  line "Owner decision (PR #N): <the answer>"; it is marked done by the PR
  that carries the answer out.
- With no answer, the change waits, the rest of the work goes on, and the
  question stays in `TODO.md` as an "(owner decision)" task.
