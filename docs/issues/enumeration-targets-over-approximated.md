# Enumeration-closed dispatch inherits RTA's whole-mask candidate set

A subject-closed dispatch operand pins its value set exactly — the
enumerated caller arguments, or local constructions — but the site's
recorded target set is RTA's over-approximation: every address-taken
function of matching signature under the subject's mask. Init-flow
closures are address-taken under every mask, so an initializer closure
whose signature matches a subject's dispatch enters that subject's
provenance, and the anonymous-parent content rule then pulls the whole
package initializer's content into the subject's scan — a spurious
refusal class (the initializer's unrelated references widen the
subject), never a false valid. Restricting a subject-closed site's
targets to the closed-value walk's pinned set would remove it; the walk
already collects exactly that set for enumerated arguments.

Lands: the next gofresh plan, with the startup-effect precision family
— or earlier if a field corpus measurably loses enumeration closures to
init-flow signature collisions.
