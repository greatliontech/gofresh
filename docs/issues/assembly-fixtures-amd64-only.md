# The fixture corpus's assembly rows are amd64

Lands: a gate runner or a consumer report on another architecture

closure/fixtures/asminvoke, genericpostrta and opaqueasm carry amd64
assembly (`.s` files with no other arch's body), so `go build ./...`
over this module fails on every other GOARCH ("missing function body")
while every production package builds on all of them — consumers
import no fixture. The gate's cross-platform vet loop therefore checks
platforms on the runner's amd64 and never an architecture; the rows
gain a second arch's body, or `//go:build amd64` on the package with
the closure pins that read it skipping elsewhere, when a runner or a
consumer builds this module's tests on another architecture.
