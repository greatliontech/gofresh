# Two REQ blocks fail the one-normative-keyword compile rule

**Lands: user decision on the requirement split (spec-amend channel).**

`stipulator check` refuses the corpus at compile:

- `REQ-closure-shared-dynamic-state` (docs/specs/closure.md:216) — two
  normative keyword occurrences, want exactly one.
- `REQ-vouch-discharge` (docs/specs/purity.md:107) — same.

Both blocks predate the finding (landed in 62b6345 and 103bcc6); the
one-keyword compile policy is stipulator's current rule, so the pair is
a cross-repo integration break, not a recent spec edit. Consequence:
corpus compilation fails, so stipulator executes zero witnesses
repo-wide — every requirement, not just these two, is unverified until
the blocks are reshaped.

The fix is a normative spec edit — splitting each block into two
single-MUST requirements (each with its own binding), or restating one
clause non-normatively — and requirement identity/binding migration
rides the split. Spec wins by default; the split shape is the user's
call.
