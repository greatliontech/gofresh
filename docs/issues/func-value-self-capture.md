# Constructor-installed closures launder receiver writes

A func value stored in receiver state by a constructor whose closure
captures the receiver (`t.c.f = func() { t.n++ }`) reads as reach-free
under the carrier rules - Signature hands out no writable reach - so a
method binding the holding field (`x := r.c; x.f()`) proves
receiver-read-only, yet calling the field mutates receiver state the
served verdict assumed stable. The method-VALUE half of this class
(`x := r.M; x()`) is closed - every consume position in both use-shape
engines refuses a method-value bind of a rooted receiver - and carrier
registrations of capturing values refuse under the environment-free
registration audit; what remains is the field-installed closure on a
non-carrier receiver, whose install site the receiver engine does not
audit. Discharging it needs closure-capture awareness at the receiver
engine's field reads (a func-valued field whose installs the declaring
package cannot prove environment-free is mutable reach), or a
fail-closed Signature reclassification there.

Lands: startup-effect-precision plan chunk 6.
