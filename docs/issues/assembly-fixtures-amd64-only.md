# The fixture corpus's assembly rows are amd64

Lands: docs/plans/tooling-redesign.md 9.3.

closure/fixtures/asminvoke, genericpostrta and opaqueasm carry amd64
assembly (`.s` files with no other arch's body), so `go build ./...`
over this module fails on every other GOARCH ("missing function body")
while every production package builds on all of them — consumers
import no fixture. The gate's cross-platform vet loop therefore checks
platforms on the runner's amd64 and does not establish another architecture's
fixture coverage. The active plan owns the disposition when a non-amd64 gate
or supported consumer workload is actually selected: provide equivalent
architecture-specific bodies or explicitly scope the fixtures and their
readers. Preserve the assembly-refusal cases; a skipped fixture is not evidence
for that architecture. No new non-amd64 capability is commissioned by this doc.
