# The closed-value walk and its target collector are two arm ladders over one shape

`closure/freshpath.go` answers two questions over one set of SSA
shapes: whether an operand closes (`closedDynamicValueUncached`, the
walk every dispatch judgment consults) and which functions a closed
operand can hold (`collectDynamicTargets`, the narrowing's collector),
and the cell judgment beneath them is likewise two referrer walks
(`cellReferrersClosed` and `collectCellStores`). The ladders must
agree arm for arm, and the safety direction is asymmetric: an arm
added to the closing ladder alone is safe (no set, the enumeration's
targets stand), an arm added to the collecting ladder alone admits a
function the walk never closed. Nothing states or enforces the pairing.

The collapse: one ladder returning both answers — closed, and the
functions held — with the cell walk likewise one, so an arm exists in
one place and the asymmetry is unrepresentable; or, short of that, a
table-driven pairing test over the shape corpus asserting the collector
names a set exactly when the walk closes through function-naming shapes.

Lands: with docs/issues/dispatch-admissions-one-predicate.md's collapse
(the one predicate consumes both answers), or with the next arm added
to either ladder.
