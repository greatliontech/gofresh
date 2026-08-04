# Two purity bars are over-conservative: caller-supplied dynamic and fmt taint

The same cerebro measurement (2026-08-04) shows the two largest
classifier-side uncacheable classes after the bracket misses: 647 witnesses
refused as "subject accepts caller-supplied dynamic" — table-driven and
property-style tests whose subjects take closures or rapid generators, a shape
the corpus uses pervasively and deliberately — and 308 refused as "reaches fmt
(potential external dependence)", which taints any fmt formatting path
regardless of sink, though the overwhelming use is error/message construction
into memory. Neither bar distinguishes the benign shape from the one it exists
to catch (genuinely external effects; dynamism that smuggles unobserved
inputs).

The refinement: (a) caller-supplied dynamic narrows to subjects whose dynamic
argument ESCAPES the observed call graph — a closure fully analyzed within the
generation's own view is not dynamism; (b) fmt's taint keys on the sink
(os.Stdout/files/network) rather than the package — pure formatting into
strings and errors classifies standard. Together they cover ~955 cerebro
witnesses (40% of the uncacheable mass beyond the bracket item).

Lands: with the bracket-declared-static-inputs item — the same measurement,
the classifier half.
