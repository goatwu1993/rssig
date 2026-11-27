---
name: pr-maintenance
description: >-
  Keep a pull request as exactly one commit with a current title and
  description, rebased on main, and merge it by squash with a written message.
  Use whenever you commit to, push, rebase, describe or merge a PR branch.
---

AGENTS.md ("Pre-1.0 flow", "Pull request titles") sets the rules; this skill
is how to keep them.

## One commit

- A PR is one task and one commit, always. Fold every later change (a review
  fix, a rebase, a regenerated fixture) into it with `git commit --amend`;
  work that does not belong in it is another task with its own PR.
- Before every push, `git rev-list --count origin/main..HEAD` prints `1`. If
  it does not, `git reset --soft origin/main` and commit once.
- The commit message is the merge message: the PR title as subject, a body
  that says what changed and why, the entries and cases by ID, the follow-up
  tasks, and the attribution lines the session gives. Rewrite it whenever the
  change it describes changes.

## Branch

- Work only on the PR's own branch. Rebase on the latest main, never merge it
  in (`git fetch origin main && git rebase origin/main`), then run the checks
  again.
- Push with `git push --force-with-lease origin <branch>`. If the lease is
  refused, fetch and look before anything else; never plain `--force`, and
  never drop a commit you did not write without the owner's word.
- Run the checks AGENTS.md lists before each push; say which could not run.

## Title and description

- Update them in the same step as every push. The description says what
  changed, the entries and cases, the owner's answers with their dates, what
  was **decided without asking** and why, the follow-up tasks, and the checks.
  It does not narrate review rounds.

## Merge

- Merge when AGENTS.md "Pre-1.0 flow" allows: one commit on the latest main,
  checks green (the fuzz job may still be running), review finished, and no
  ask-first change unanswered. Review is finished when `/review-loop` has
  run on the pushed commit and stopped; start it yourself after the first
  push, without waiting to be asked.
- Squash, with the head you checked pinned (`expectedHeadSha`), the PR title
  as subject and the commit body as body; never GitHub's default message.
- Then tell the owner in the conversation: the merge commit, the checks
  passed or ignored, what was decided without asking, and the follow-ups.
