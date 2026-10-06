# Four CI workflows differing only in two integers

The chunk-107 ci.yaml is near-identical across gofresh, gomutant,
stipulator, and pew — the per-repo variation is the measured budget
pair (-timeout, timeout-minutes), the package pattern (stipulator's
workspace needs the module-path form), and stipulator's hygiene
step. The rc-resolution logic — the part that carries the loudness
contract — exists in four copies and must be fixed four times. An
org-level reusable workflow (`workflow_call` in a
greatliontech/.github repo, inputs test-timeout/job-timeout/
packages) would single-source it; the org already centralizes
greatliontech/semrel@main, so the convention exists.

Lands: cross-tool train chunk 325 (the trigger fired at gofresh 48bbe3a — the race/records/workflow_run gate is the CI-contract change every copy must carry, and gomutant 323 and stipulator 321 were about to copy it by hand; one org-level reusable workflow the four repos call with their inputs, the gate's toolchain pinned to a listed one with a next-stable early-warning leg; opens with the user's confirmation of the org repo's creation; audit 316).