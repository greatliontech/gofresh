# startup-effect imprecision refuses 99.5% of cerebro's subjects

With the subject-tier walls down (the harness failure/logging channel,
TB dispatch, causal diagnostics, test-main dispatch closure —
observation-rta@7..@10), a full sweep of the cerebro repro (9d0fe5a2,
2,119 test subjects across 57 packages) still proves only 10 subjects
(0.5%) observable. The binding constraint moved to the startup tier:
package-initializer flow is classified with argument-insensitive
symbol rules, so nearly every package refuses wholesale before any
subject-tier precision matters. The measured histogram:

- 1,096  startup: reaches fmt.Fprintf (formatted output) — an init
  formatting into a local bytes.Buffer or strings.Builder is pure
  value computation; the classification is writer-insensitive.
-   505  startup: unaudited math/big.NewInt — arbitrary-precision
  construction is bit-deterministic; math/big is excluded from the
  audited-pure set only by the blanket math-family precedent, whose
  recorded rationale (CPU-dispatched result variance) does not apply.
-   149+27+8+2  startup: unaudited time.Date / time.AddDate /
  time.Time methods / time.Format — fixed-argument calendar
  construction reads no clock; the time exclusion's rationale (ambient
  clock and entropy) covers Now, not Date arithmetic.
-    58  startup: unaudited internal/poll.init$1 — a standard-library
  init CLOSURE flagged as an unaudited operation: the fallback exempts
  the name "init" but not synthetic init$N closures, though std
  initialization rides the toolchain guard by the same argument.
-    54+5+12+1  startup: os mutation/read effects — real ambient init
  effects; correctly blocking, population honest.
-     8+8+7  package scan: net/url.Parse, time.Time, path/filepath.Ext
  — maximal-tier unaudited selectors with pure-computation shapes.
-     5+4  subject tier: unresolved dispatch — the residue the landed
  chunks did not admit; correctly conservative.

Scope for the pass: writer-sensitive classification of the fmt.Fprint
family (pure when the writer's provenance is a local pure sink),
audited-set membership diagnoses for math/big and fixed-argument time
construction (each needs its own no-testlog-invisible-input audit and
rides a strategy bump), the std init-closure exemption, and re-running
this sweep as the acceptance measurement. The methodology and full histogram live in the
plan's close-out commit (git log --all --grep "observability-precision
plan closes").

Lands: the next gofresh plan — this is its charter.
