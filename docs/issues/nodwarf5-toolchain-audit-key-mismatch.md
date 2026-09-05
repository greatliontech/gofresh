# Audited nodwarf5 toolchains do not match their reported identity

Lands: cross-tool train chunk 119

The system Go toolchain reports `go1.27.0-X:nodwarf5` through both
`go version` and `go env GOVERSION`, with `GOEXPERIMENT=nodwarf5`.
`closure/toolchainaudit.go` instead lists `go1.27.0 X:nodwarf5` in both
the release and build-selection tables. Its `binaryExperiment` parser
also splits on the space-prefixed ` X:` spelling only.

The documented nodwarf5 audit therefore does not admit the actual
toolchain it describes. Fixing only the release key leaves the selection
key and baked-experiment parser inconsistent. The same spelling appears
in the Go 1.27.1 entries.

At revision `e037686`, this existing canary fails on the system toolchain:

```sh
go test ./closure -run '^TestAuditedToolchainCoversRunningToolchain$' -count=1
```

Its error reports that `go1.27.0-X:nodwarf5` is not listed. The consumer
VMM, whose module requires Go 1.27.0, passes its ordinary and race test
suites, but Stipulator built with gofresh v0.92.0 refuses standard-library
observation admissions for all 460 executed witnesses. The audit notice
names the same release mismatch. This does not establish the cause of
every individual downstream coverage violation.

The repair must make release lookup, selection lookup, and experiment
parsing agree with the actual audited toolchain identity, without
erasing experiment distinctions or admitting an unwalked toolchain.
Exercise the real hyphenated identity for default and race selections,
explicit and inherited experiment values, and negative unlisted-release,
experiment, and build-tag cases. Consumer binaries must adopt the fixed
gofresh release before their witness gates can benefit.
