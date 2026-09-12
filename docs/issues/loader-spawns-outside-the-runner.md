# The package loader's `go list` children spawn outside the runner's hook

The go-command policy (`gotool.Runner`) gives a consumer one spawn hook
(`Prepare`) for the `go` commands gofresh spawns itself. The package
loader — `explain.go`, `closure/viewload.go`, `closure/maximal.go`,
`closure/internal/program/program.go` — loads through
`x/tools/go/packages`, whose `Config` carries `Env` and `Dir` but no
spawn hook: its `go list` children run under the policy's environment
and directory, outside any consumer-owned process boundary. A consumer
that sets its children's process group through `Prepare` (stipulator's
owned-processes clause enumerates every Go child by spawn mechanism)
owns the runner's children only; a cancellation sweeping the group
leaves the loader's children to the kernel's default.

The loader's children carry the policy's environment today only
because every site passes a non-nil `Config.Env` (`x/tools` sets
`CleanEnv: cfg.Env != nil`; `EnvForPackages` always appends the driver
pin, so no slice built from it is nil). A future site passing a nil
slice would silently hand the child `os.Environ()` — the fail-open
REQ-fresh-coherent-view's explicit-environment rule forbids. The one
seam holds three things: the environment (pin `cfg.Env != nil` there),
the directory, and the process boundary.

Closing shapes for the boundary, to be decided at the seam: an upstream
spawn hook on `x/tools`'s loader (a `GOPACKAGESDRIVER` that is the
runner is foreclosed as the spec stands — REQ-fresh-coherent-view
refuses every external driver, and `EnvForPackages` pins it off), or
the loader's children stated as the policy's declared exclusion in the
substrate paragraph and in each consumer's boundary clause.

Lands: cross-tool train chunk 241 (the one typed-load seam — the site
the loader's spawn is confined to).
