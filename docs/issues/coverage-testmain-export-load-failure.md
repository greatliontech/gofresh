# Covered test-main export loading constructs an invalid generated-source path

Lands: tooling-redesign 7.8; selected-toolchain repair precedes covered-proof acceptance.

## Reproduction and consequence

A controlled Linux/amd64 run with `go1.27.2-dst.15` and Gofresh v0.117.6
builds and executes one unasserted `TestEnv` that reads `INPUT_VALUE=stable`
and compares it with a pure helper. Both the ordinary and `GOFLAGS=-cover`
executions exit zero, complete the original harness and record precisely that
environment read. The ordinary result has supported observation evidence and
checks valid. The covered result remains identity-only and checks unverifiable;
its native proof reports an unavailable program load, not an analyzed unsupported
effect. Purity was absent in both cases.

Under the recorded compilation environment, this independent listing reproduces
the covered failure (with `GOWORK=off`, `GOENV=off`, `GOPACKAGESDRIVER=off`,
`GOMAXPROCS=2`, and private build caches):

```sh
GOFLAGS=-cover go list -e -json -compiled=true -test=true -export=true \
  -deps=true -find=false -buildvcs=false -pgo=off -- example.com/coverageproof
```

The command exits zero because of `-e`, but the synthetic test-main package has
an error resembling:

```text
cover: open $WORK/b150//tmp/.../fixture-cache/fb/...-d.cover.go: no such file or directory
```

The cached generated test-main file exists and registers exactly `TestEnv`.
This is not the vanished disposable-export case. `cmd/go/internal/list/list.go`
constructs test packages without coverage configuration and replaces generated
test-main source with an absolute cache filename, then requests build-style
coverage preparation. `cmd/go/internal/load/pkg.go` selects the synthetic main;
`cmd/go/internal/work/exec.go` treats that absolute filename as package-relative
when naming coverage inputs and outputs.

## Required repair and acceptance

Repair selected-toolchain test-main coverage loading and generated absolute-path
handling in a distinct toolchain change set, preserving the actual covered
selection. Do not strip coverage from analysis without establishing equivalence
to the producing program. Reconcile any changed toolchain content/admission
identities before consumer adoption.

Preserve successful ordinary execution separately from reusable authority.
Loader errors must continue to refuse proof; no implicit purity or historical
support may replace unavailable analysis. Exercise both uncovered and covered
positive controls after repair, including external tests and coverage-selected
dependencies. A successful listing alone is not proof-method acceptance: inspect
the native proof and outcome support under the repaired selection.

The demonstrated loss is unasserted observation-based reuse for this covered
environment-reading fixture on the identified toolchain. It establishes neither
a blanket coverage exclusion nor an unsound-valid verdict. Temporary evidence is
at `/tmp/opencode/coverage-proof-diagnostic-20261015`; the controlled source,
environments, accounts, fingerprints and loader output were retained there.
