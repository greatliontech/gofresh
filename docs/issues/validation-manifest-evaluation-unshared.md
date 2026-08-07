# Producer validation evaluates manifests per subject, twice

compareAttachedObservations evaluates each subject's attached manifest
independently and validateObserved calls it twice, so a validation
over N subjects sharing one encoded manifest performs 2N evaluations
where the check path now performs 2 - the same amplification class
the check-window sharing collapsed, on the producer path. Cost-only.

Lands: when the producer validation path is next changed, or when a
field measurement shows validation-time digesting as a standing cost.
