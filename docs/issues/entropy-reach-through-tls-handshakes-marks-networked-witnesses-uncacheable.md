# TLS entropy reach: a precision report, not authority to reuse outcomes

Reported by tugboat on 2026-09-30 from its embedder-surface closing
`stipulator check`.

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

The report's claim that none of these subjects observes the entropy is not
established by those counts. A nonce absent from a recorded manifest can still
affect protocol behavior, errors or liveness; network nondeterminism is a
separate obligation. The entropy classification remains conservative under
REQ-fresh-sound, REQ-fresh-authority-account and the admitted outcome rules.
A successful handshake or unchanged source/build guards do not establish
irrelevance of the draw to a consumer-owned test outcome.

Reduce the reported reach into exact executed and conservatively enumerated
paths. Any refinement needs a sound subject/result-model argument and deciding
counterexamples, preserving network and liveness refusals where unsupported.
Do not add a TLS-wide purity grant or silently broaden caller assertions.
The active plan owns deriving that argument; no product decision is needed
to keep unknown effects refused while the proof is absent.

Lands: docs/plans/tooling-redesign.md 7.8.
