# The entropy class refuses every witness whose closure reaches a TLS handshake — 828 of tugboat's 1098 subjects, none of which observes the entropy

Filed from tugboat (2026-09-30, embedder-surface chunk 5's closing
`stipulator check`), uncommitted for the gofresh agent's triage.

Observed: the witnessed summary's largest uncacheable reason is
`post-run validation: reaches crypto/rand.Read (entropy)` — 828 of
1098 subjects on the race invocation, up from 567 at chunk 11's close
and 155 at chunk 6's. The rise tracks the transport test meshes:
chunk 5 added a mutual-TLS fixture (transporttest.TLSMesh: a test CA
and one leaf per node, ecdsa.GenerateKey + x509.CreateCertificate
over crypto/rand.Reader, and tls.Config values whose handshakes read
entropy through crypto/tls) reachable from both providers' meshes.
Injecting the fixture (built only by TLS-mode tests, a nil field
otherwise) did not move the count: the reach is judged over the call
graph, where the mesh's methods and the providers' production TLS
paths (tcptransport's tls.Client/tls.Server, grpc's credentials) stay
reachable from every attach.

Why it is a model question and not a tugboat discharge: the closure
spec classifies crypto/rand's Read as the entropy class — "an
external system call named as such (an input no guard pins and no
bracket records, never observable)" — and REQ-closure-refusal-channels
names the only discharges: restructuring the subject away from the
reach, or purity responsibility on the subject (`//gofresh:pure` on
its declaration, or the accepted policy's blanket assertion for the
invocation whole). A networked subject cannot be restructured away
from a TLS handshake's nonce; a directive on 828 test declarations
is the per-subject spelling of a fact about crypto/tls, not about any
subject; a blanket policy assertion masks real external dependence
everywhere else. Every one of the 828 consumes entropy it never
observes: a handshake nonce or an ephemeral key changes no outcome
the witness records, and the guards that would stale the result on
a real change (closure hash, toolchain, build) all still hold.

Need (need-level): an admission for entropy consumed but never
observed — the reach classified by what the subject can observe of
it, not by the syscall's existence. Candidates the spec's own shape
suggests: a per-reached-package admission (crypto/tls's handshake
entropy, like the filepath and flag rows the classification table
already admits by audit), or an observability rule at the reach
(entropy that feeds only a value the subject's bracket never records
— a nonce sent on the wire, a key held in a tls.Conn — is not an
input to the outcome). Which is gofresh's to derive; tugboat records
the count as a serving cost, not a verdict, until then.

Lands: cross-tool train chunk 202 (the dynamic-state tier's home — a
design input recorded on its plan entry at 281.1).
