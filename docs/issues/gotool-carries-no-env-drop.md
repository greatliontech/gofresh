# The env policy has a setter and no drop

`gotool.SetEnv` is the policy's one setter. A consumer that DENIES a
variable — stipulator's normalization drops a declared denial's key
before pinning the curated environment (its `dropEnv`, the last env
helper it keeps after the gotool fold at chunk 272) — has no policy
form for the drop and spells its own over `gotool.EqualEnvKey`. A
`gotool.UnsetEnv(env, key)` beside the setter would make the drop the
policy's too, so a consumer never re-spells the key rule.

Lands: cross-tool train chunk 240 (the policy stated as a requirement,
with its forms enumerated).
