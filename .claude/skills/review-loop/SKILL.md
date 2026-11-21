---
name: review-loop
description: Run /code-review on the current PR or diff, fix every valid finding, track valid findings that don't belong in this PR, and repeat until a round finds nothing valid.
disable-model-invocation: true
---

Review and fix in rounds, in this same turn, with no timer or wakeup.

Each round:

1. Run /code-review on the current PR or diff.
2. Judge every finding on its merits against the code and the cited sources.
   A finding repeated from an earlier round is judged once; do not re-argue it.
3. Valid and belongs in this PR: fix it.
4. Valid but not in this PR's scope: make sure it is tracked as a task
   (`TODO.md`, with detail in `docs/tasks/<id>.md` when it needs more than a
   few lines), not just mentioned. AGENTS.md: a task is the scope of one PR.
5. Invalid: say why in one line.
6. Run the checks AGENTS.md lists, commit as the PR requires, and push.

Stop when a round has no new valid finding. Then report what was fixed, what
is tracked and where, and what was judged invalid and why.
