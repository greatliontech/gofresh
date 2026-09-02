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

Lands: user decision (creating the org-level repo is an
outward-facing act).
