# The ledger's non-Go compiled member arm may be unreachable

The compartment ledger's identity walk (closure/internal/testvariant
ComputeIdentity) and REQ-closure-test-variant-compartment describe a
member that is neither a compiled Go file nor embedded data — a non-Go
compiled input, an assembly or C file — with its whole content as its
header. The listing splits only `.go` files by the `_test` suffix, so
an assembly file beside a test-only package lands in the base package
and is never a compartment member; whether any test-only non-Go
compiled input is constructible under the listing (an external test
package cannot carry one either) is unsettled, and if none is, the arm
and its prose describe no reachable member.

Lands: cross-tool train chunk 189
