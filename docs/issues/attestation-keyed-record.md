# Attestation-keyed discharge record

Two execution-model attestations now mean two option fields, two
factScope markers, two evidence fields (SingleSubjectDischarges,
PackageProcessDischarges), two observationFacts maps, two pairing
checks, and two entries in View.Sibling's fact copy. The Sibling copy
omission that reached a consumer e2e before any gofresh test
(the packageProcessDischarges carry, fixed with the whole-fingerprint
sibling-equality pin) is the demonstrated cost of the per-field
plumbing. A third execution model would make the collapse mandatory:
one attestation-keyed record (mode → discharges) threaded once, with
the evidence encoding keeping the two existing field names for
consumers.

Lands: user decision (an evidence-shape change touches consumers'
persisted records; gomutant and pew pin gofresh versions).
