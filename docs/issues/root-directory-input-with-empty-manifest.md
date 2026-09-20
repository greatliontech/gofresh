# A runtime-input classification names `/` for every subject while the input list is empty

Lands: cross-tool train chunk 259

Field report (greatliontech/pb, gofresh v0.102.0 through gomutant
v0.57.11-0.20260919151557-ee9616fd4b7b, and v0.99.0 before it): a
campaign over `internal/archive.ExtractZip` and `writeMember` (a
union over 486 subjects) leaves every one of the record's 243
evidence subjects — the target's and every oracle's — with
`runtimeReason: "external directory input: /"` and
`runtimeInputs: ""`, so the record is runtime-unverifiable and stays
machine-local. A syscall trace of the same tests (`strace -f`, every
syscall, the extraction tests selected) touches no path named `/`;
the tests' scratch is a declared namespace under
`internal/archive/testdata/scratch`, gitignored, and the tree is
clean.

The classifier (`runtimeinput.classifyPath`, the "external directory
input" arm after `relUnder` fails and `classifyProbe` finds a
directory) is being handed the literal `/` for subjects whose input
manifest is empty — an origin the record does not carry, so the
consumer cannot say which observation, environment form, or default
produced it. Expected: a runtime input names the observation that
produced it, and an empty manifest classifies as no input, never as
the filesystem root.
