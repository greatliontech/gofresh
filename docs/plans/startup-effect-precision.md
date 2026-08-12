# Startup-effect precision

The gofresh follow-on plan chartered by the retired
docs/issues/startup-effect-precision.md: with the subject-tier walls
down, the binding constraint on the field corpus moved to the startup
tier - argument-insensitive symbol rules refuse nearly every package
before subject-tier precision matters. Full histogram and methodology:
git log --all --grep "startup-effect-precision plan charters". Each
chunk is one commit through the full adversarial loop; audited-set
changes each carry their own source audit and strategy bump. WIP = 1.

- [x] 0a. TestMain rides the observed window - the user TestMain flow
      (already tracked as its own reachability slice) classifies under
      the observed subject walk, not the startup tier: the test log
      installs in the generated test-main init, which runs after every
      dependency init and before TestMain, so TestMain's reads are
      bracketed observation inputs while package inits stay genuinely
      pre-bracket (driver: gomutant rapid-oracle records never serve).
- [x] 0b. flag-registration startup audit - standard flag registration
      (flag.Bool/String/Var family) from a package init is a
      process-local registry mutation; the usage-printing reaches
      inside the flag package are help-path only (own audit; same
      driver - the real rapid library registers its flags in init).
- [x] 0c. property-driver dispatch closure - a computed prop-callback
      call inside a recognized property driver (rapid.Check/MakeCheck
      shapes) whose operand is a locally closed func literal does not
      open the subject world (the test-main dispatch-closure precedent;
      same driver).
- [ ] 0b2. custom-FlagSet-scoped sink precision - 0b's sink judgment
      poisons on any untraceable registration, including registrations
      on a locally-owned FlagSet parsed only from explicit arguments,
      where the command-line channel needs a Parse that is already
      independently blocked; scoping the poison to registrations whose
      FlagSet (or the default set) can carry os.Args requires Parse-
      argument provenance. Same-package subjects were scan-blocked
      before 0b; a dependency's registration in a function no walk
      reached was not visible to dependents pre-0b and can newly
      poison them - that widening is the fail-closed price of 0b's
      admission, and this chunk is where it narrows.
- [ ] 0d. benchmark-loop package-scan audit - testing.Loop in the
      maximal package scan blocks every subject in a benchmark-bearing
      package; startup masking hid it until the test-main flow moved
      into the observed window (surfaced by 0a's harnessroot fixture).
      Decide the class: harness pacing protocol like m.Run (admit) or
      genuine runtime configuration (keep, with the refusal naming the
      benchmark) - own audit.
- [ ] 1. writer-sensitive fmt.Fprint startup classification - an init
      formatting into a provably-local pure sink is value computation
      (the sink-keying precedent extended to the startup tier;
      ~1,096 refusals in the charter histogram).
- [ ] 2. math/big joins the audited-pure set - arbitrary-precision
      construction is bit-deterministic; the math-family exclusion's
      CPU-dispatch rationale does not apply (own audit; ~505).
- [ ] 3. fixed-argument time construction audited - Date/AddDate/
      Format arithmetic reads no clock; the time exclusion's rationale
      covers Now (own audit; ~186).
- [ ] 4. std init-closure exemption - synthetic init$N closures ride
      the toolchain guard exactly as named init does (~58).
- [ ] 5. maximal-tier pure-shape selector audits - net/url.Parse,
      time.Time, path/filepath.Ext (the audited-symbol precedent;
      ~23).
- [ ] 6. func-value self-capture closes - a receiver-stored func value
      whose literal captures mutable-reach state is itself mutable
      reach (gofresh docs/issues/func-value-self-capture.md).
- [ ] 7. dotless module paths classified standard (gofresh
      docs/issues/dotless-module-paths-classified-standard.md).
- [ ] 8. one dispatch-site classifier (gofresh
      docs/issues/one-dispatch-site-classifier.md).
- [ ] 9. runtimeinput producer facade (gofresh
      docs/issues/runtimeinput-producer-facade.md).
- [ ] 10. enumeration targets tightened (gofresh
      docs/issues/enumeration-targets-over-approximated.md).
- [ ] 11. acceptance: re-run the charter sweep on the pinned field
      repro (requires a machine with the workload checked out) and
      record the observable-subject fraction against the 0.5%
      baseline.
