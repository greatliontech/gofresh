# CLI version discovery is inconsistent across the tools

Lands: docs/plans/tooling-redesign.md 5.1v, immediately after the oracle
admission repair and before the next native-boundary correction.

Gomutant exposes both `gomutant version` and `gomutant --version` through
`internal/cmd/version.go` and the root command's version field. Pew's
`cmd/pew/main.go` command tree and Stipulator's command tree expose neither.
An actor reporting a failure should not need to know Go's external binary
inspection command or inspect source to identify the installed tool.

Provide a discoverable `version` command and `--version` on all three executable
tools. Settle their small output contract in the owning specifications and
guidance before implementation. The ordinary answer identifies the tool and its
build version; detailed or structured output has an explicit field-report use
rather than expanding the default response without a reader.

Use the running binary's embedded facts: release/module version or development
identity, available VCS revision and modified state, compiler version, and the
linked Gofresh version or replacement status. Do not infer these from cwd, git
HEAD, a network query, the currently selected `go`, or another installed copy.
Missing metadata is explicitly unknown, never a fabricated clean release.
Keep a source build's dirty state visible even when another version field is
available. Existing server implementation identities use their own running
binary's facts, so a server outliving a CLI upgrade remains distinguishable.

The query works with no repository, a malformed project, and no git or go on
PATH. It loads no policy or source, measures nothing and writes no tool state.
Help names it. Preserve Gomutant's useful document-version capability account
while distinguishing format compatibility from executable identity. Gofresh is
a library: consumers report their linked version; this does not commission a
new library CLI or new server transport.

Pin release, development, dirty, missing-VCS and dependency-replacement cases,
plus actual CLI output and invalid arguments. Record clean installed identities
after the release; package version and source revision are not interchangeable.
