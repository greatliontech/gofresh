# Assembly capture close-event refusal

Lands: tooling-redesign 5.1w.2b.3b.2a.2.2.2.2.14r, immediately after the
startup-word transfer and before process-entry contract design.

## Observed failure and authority

A stock Go 1.27.1 `TestNarrowReferenceSelectedRuntime` run refused assembly
capture before source checking with:

```text
assembly capture: protected input namespace mutated (name "importcfg", mask 0x8)
```

The event is `IN_CLOSE_WRITE`. A later unchanged run passed. The original log
does not identify the action, watched path or validation phase; no surviving
process/event trace attributes that instance to a writer. This is an attributed
fail-closed observation, not proof that the captured bytes changed.

## Confirmed false refusal and historical attribution

The Go driver writes a package action's importcfg before launching its tool.
Concurrent forks can retain a close-on-exec reference to an already-written
writable descriptor. Closing the final retained reference after a watch is
installed can emit a close event without a write during the protected interval.
The watcher currently refuses such events unconditionally. A deterministic
retained-writable-descriptor test reproduced the refusal with unchanged bytes,
path resolution and full file metadata. This confirms an adjacent availability
defect, but does not attribute the earlier selected-toolchain failure.

Retain the deciding regression and actual write, truncate,
rename and mutation-and-restore adversaries. Attribute future failures with
action/tool, resolved watched path and pre-execution versus closing-validation
phase while preserving the underlying error.

The repair follows the supported input-use/mutation contract in
[implementation verification](../specs/implementation-verification.md), including
observation loss and intervening mutations. Omit close-only notifications from
the subscription, while retaining all mutation/loss notifications, pre/post
drains and endpoint validation. A successful rerun cannot waive a reported
mutation. A native-AIO probe demonstrated a write without a mutation event until
close; universal write detection therefore cannot justify this repair. The
existing caller-owned exclusion of unobserved mutation-and-restore remains
required and must explicitly describe this notification residual. The prior
close-event guard did not cover a writer remaining open through validation.
