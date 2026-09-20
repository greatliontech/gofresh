# CanonicalDir's doc claims a walk EvalSymlinks does not perform

`gotool.CanonicalDir`'s doc says `..` is "applied to the resolved
prefix — never a lexical clean of the spelling first", contrasting
Windows where `..` is normalized lexically. Measured on Linux (Go
1.27): with `deep -> real/sub`, `filepath.EvalSymlinks("<base>/deep/..")`
answers `<base>` — the link's parent — exactly as a lexical clean
before resolution does; `CanonicalDir` is `EvalSymlinks` over the
absolute spelling, so the two coordinates agree on that shape and the
documented divergence is not one. pew's bump (253) built a `link/..`
witness on the doc's claim and had to delete it. Either the doc names
what EvalSymlinks does (every symbolic link followed; `..` after a
link element folds onto the link's parent, as the shell's `cd ..`
does not), or the function walks elements itself as described.

Lands: cross-tool train chunk 259
