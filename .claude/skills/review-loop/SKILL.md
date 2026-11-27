---
name: review-loop
description: >-
  Run /code-review on the current PR or diff, fix every valid finding, track
  valid findings that don't belong in this PR, and repeat until a round finds
  nothing valid. Use on your own, without being asked, once a PR's commit is
  pushed and before it merges; also when asked to review a PR or diff.
---

Review and fix in rounds, in this same turn, with no timer or wakeup. Start
it yourself: a PR is not ready to merge until a run has finished
(pr-maintenance, "Merge"). The ten rounds below count per PR, not per
run: starting it again does not reset them.

Each round:

1. Run /code-review on the current PR or diff.
2. Judge every finding on its merits against the code and the cited sources.
   A finding repeated from an earlier round is judged once; do not re-argue it.
3. Valid and belongs in this PR: fix it.
4. Valid but not in this PR's scope: make sure it is tracked as a task
   (`TODO.md`, with detail in `docs/tasks/<id>.md` when it needs more than a
   few lines), not just mentioned. AGENTS.md: a task is the scope of one PR.
5. Invalid: say why in one line. If the reason is that the case cannot
   happen, is already covered or is unreachable, name the test that fails when
   that stops being true (AGENTS.md, "Review findings"). With no such test the
   finding is valid but unguarded: fix it (step 3) or track it (step 4). A
   finding that is wrong on the facts, such as one that reviewed the wrong
   diff, needs no test; say what it misread.
6. Run the checks AGENTS.md lists, commit as the PR requires, and push.

Stop when a round has no new valid finding, or after ten rounds (AGENTS.md,
"Pre-1.0 flow"): after the tenth, fix only a new finding marked important,
and track or drop the rest with a reason. Then report what was fixed, what
is tracked and where, and what was judged invalid, why, and which test guards
each reason.
