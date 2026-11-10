package dynstate

import (
	"strings"

	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

// CarrierLinkGraph builds the symmetric adjacency map of init-flow carrier
// storage links across allFacts.
func CarrierLinkGraph(allFacts map[string][]Fact, malformed func(Fact)) map[string]map[string]bool {
	linkAdj := map[string]map[string]bool{}
	for _, facts := range allFacts {
		for _, fact := range facts {
			for _, link := range fact.CarrierLinks {
				if !link.Valid() {
					if malformed != nil {
						malformed(fact)
					}
					continue
				}
				if linkAdj[link.From] == nil {
					linkAdj[link.From] = map[string]bool{}
				}
				if linkAdj[link.To] == nil {
					linkAdj[link.To] = map[string]bool{}
				}
				linkAdj[link.From][link.To] = true
				linkAdj[link.To][link.From] = true
			}
		}
	}
	return linkAdj
}

// BlockedExportedSeams resolves which exported mutating seam functions across
// allFacts are reachable from non-sequential function uses (go statements,
// .Parallel-bearing scopes including cross-package .Parallel helpers,
// init/method/var-initializer calls, or escaped function values) across
// call edges, returning varKey -> blocked exported seam functions.
func BlockedExportedSeams(allFacts map[string][]Fact, malformed func(Fact)) map[string]map[syntaxutil.FuncKey]bool {
	blocked := map[string]map[syntaxutil.FuncKey]bool{}
	recordBlocked := func(key string, fn syntaxutil.FuncKey) {
		if blocked[key] == nil {
			blocked[key] = map[syntaxutil.FuncKey]bool{}
		}
		blocked[key][fn] = true
	}
	hasMalformed := false
	var exportedSeams []syntaxutil.ExportedSeam
	parallelReached := map[syntaxutil.FuncKey]bool{}
	nonSeqReached := map[syntaxutil.FuncKey]bool{}
	seqAdj := map[syntaxutil.FuncKey]map[syntaxutil.FuncKey]bool{}
	revSeqAdj := map[syntaxutil.FuncKey]map[syntaxutil.FuncKey]bool{}
	revParAdj := map[syntaxutil.FuncKey]map[syntaxutil.FuncKey]bool{}
	addRevPar := func(caller, callee syntaxutil.FuncKey) {
		if revParAdj[callee] == nil {
			revParAdj[callee] = map[syntaxutil.FuncKey]bool{}
		}
		revParAdj[callee][caller] = true
	}
	for _, facts := range allFacts {
		for _, fact := range facts {
			for _, es := range fact.ExportedSeams {
				if !es.Valid() {
					hasMalformed = true
					if malformed != nil {
						malformed(fact)
					}
					continue
				}
				exportedSeams = append(exportedSeams, es)
			}
			for _, fn := range fact.NonSeqFuncUses {
				if !fn.Valid() {
					hasMalformed = true
					if malformed != nil {
						malformed(fact)
					}
					continue
				}
				nonSeqReached[fn] = true
			}
			for _, edge := range fact.SeqFuncEdges {
				if !edge.Valid() {
					hasMalformed = true
					if malformed != nil {
						malformed(fact)
					}
					continue
				}
				if seqAdj[edge.Func] == nil {
					seqAdj[edge.Func] = map[syntaxutil.FuncKey]bool{}
				}
				seqAdj[edge.Func][edge.Callee] = true
				if revSeqAdj[edge.Callee] == nil {
					revSeqAdj[edge.Callee] = map[syntaxutil.FuncKey]bool{}
				}
				revSeqAdj[edge.Callee][edge.Func] = true
				addRevPar(edge.Func, edge.Callee)
			}
			for _, fn := range fact.ParallelFuncs {
				if !fn.Valid() {
					hasMalformed = true
					if malformed != nil {
						malformed(fact)
					}
					continue
				}
				parallelReached[fn] = true
			}
			for _, edge := range fact.ParallelEdges {
				if !edge.Valid() {
					hasMalformed = true
					if malformed != nil {
						malformed(fact)
					}
					continue
				}
				addRevPar(edge.Func, edge.Callee)
			}
		}
	}
	if hasMalformed {
		for _, facts := range allFacts {
			for _, fact := range facts {
				for _, es := range fact.ExportedSeams {
					if syntaxutil.ValidFactKey(es.Key) {
						recordBlocked(es.Key, syntaxutil.FuncKey{})
					}
				}
			}
		}
		return blocked
	}
	if len(exportedSeams) == 0 {
		return blocked
	}

	if len(parallelReached) > 0 && len(revParAdj) > 0 {
		syntaxutil.PropagateBFS(parallelReached, revParAdj)
	}
	for fn := range parallelReached {
		if fn.Pkg != "*" && !strings.Contains(fn.Name, "#") {
			nonSeqReached[fn] = true
		}
	}
	if len(nonSeqReached) > 0 && len(seqAdj) > 0 {
		syntaxutil.PropagateBFS(nonSeqReached, seqAdj)
	}
	for _, es := range exportedSeams {
		if nonSeqReached[es.Func] || (es.RunnerOnly && len(revSeqAdj[es.Func]) > 0) {
			recordBlocked(es.Key, es.Func)
		}
	}
	return blocked
}
