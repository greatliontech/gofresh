# The closed-value walk and its target collector are two arm ladders over one shape

`closure/freshpath.go` answers two questions over one set of SSA
shapes: whether an operand closes (`closedDynamicValueUncached`, the
walk every dispatch judgment consults) and which functions a closed
operand can hold (`collectDynamicTargets`, the narrowing's collector),
and the cell judgment beneath them is likewise two referrer walks
(`cellReferrersClosed` and `collectCellStores`). The ladders must
agree on the shapes they jointly support. `closedDynamicTargets` first calls
`subjectClosedDynamicValue` and returns no narrowed set if it fails; adding
a collector arm alone therefore does not admit an unclosed value. A closing
arm without a collector arm keeps the conservative enumeration. The residual
is duplicated traversal and precision maintenance, not demonstrated unsafe
admission.

The collapse: one ladder returning both answers — closed, and the
functions held — with the cell walk likewise one, so an arm exists in
one place with the closure prerequisite explicit; or, short of that, a
table-driven pairing test over the shape corpus asserting the collector
names a set exactly when the walk closes through function-naming shapes.

Lands: docs/plans/tooling-redesign.md 7.8.
