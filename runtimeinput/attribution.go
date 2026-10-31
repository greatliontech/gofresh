package runtimeinput

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/greatliontech/gofresh/internal/render"
)

// attributionSeparator divides a refusal's clause from its attribution
// (REQ-inputs-refusal-attribution). A refused path, a logged name, or a
// working directory may itself contain the separator, so the split is
// never "the last separator": RefusalClause is the one implementation
// a consumer reads.
const attributionSeparator = " — "

// attributionOps is the one vocabulary of harness operations an
// attribution names — the observation's attribution field carries
// none for an operation outside it (fail-closed), and the
// per-operation round-trip pin is what holds the parser and the
// builder's three labels together (a switch cannot range): a consumer
// that pastes a field's attribution after a clause's separator meets
// the split it recognises.
var attributionOps = []string{"open", "stat", "chdir"}

// movedBracketClause heads the observation-bracket refusal's reason,
// the one reason whose attribution is a bracketed member list.
const movedBracketClause = "observation bracket moved"

// bracketAttributionLabels are the member-list parts a moved-bracket
// attribution is made of (bracketMoveAttribution): each part one label
// and its capped list, the parts joined by "; " inside one bracket pair.
var bracketAttributionLabels = []string{"added: ", "removed: ", "recently touched: "}

// RefusalClause is the clause of a refusal reason — the text a consumer
// keys on (an exemption record, a disposition table), before the
// attribution a resolved-target reason carries, a moved-bracket reason
// carries, or a consumer pastes after it
// (REQ-inputs-refusal-attribution). The attribution is the one
// well-formed suffix: from a separator, an operation and its quoted
// name and quoted directory, or `recorded path`, its quoted spelling,
// and its quoted target, running exactly to the reason's end; or, for
// the moved-bracket reason alone, from " [" the bracketed member list
// — a quoted string cannot carry an unescaped quote, so no separator
// inside a quoted name or directory, or inside the refused path of an
// attributed reason (the fake never runs to the end), parses that way.
// A reason with no such suffix is its own clause; the one residual of
// the text channel is an UNATTRIBUTED reason whose refused path itself
// ends in the attribution's shape — a path deliberately named with a
// quote — whose clause is then the truncated one (recorded, accepted:
// REQ-inputs-refusal-attribution).
func RefusalClause(reason string) string {
	clause, _ := splitAttribution(reason)
	return clause
}

// RefusalAttribution is the attribution of a refusal reason — the one
// well-formed suffix after the separator, without it — or "" for a
// reason carrying none: the complement of RefusalClause over the same
// split, so a consumer recording the attribution beside the clause
// reads the one implementation; the text channel's one residual (an
// unattributed reason whose refused path ends in the attribution's
// shape) yields that fake tail, as its clause is the truncated one
// (REQ-inputs-refusal-attribution).
func RefusalAttribution(reason string) string {
	_, attribution := splitAttribution(reason)
	return attribution
}

// splitAttribution is the one split RefusalClause and
// RefusalAttribution read: the clause before the first separator whose
// suffix is exactly one well-formed attribution, and that suffix.
func splitAttribution(reason string) (clause, attribution string) {
	if clause, attribution, ok := splitBracketAttribution(reason); ok {
		return clause, attribution
	}
	for i := strings.Index(reason, attributionSeparator); i >= 0; {
		if suffix := reason[i+len(attributionSeparator):]; attributionWellFormed(suffix) {
			return reason[:i], suffix
		}
		next := strings.Index(reason[i+1:], attributionSeparator)
		if next < 0 {
			break
		}
		i += 1 + next
	}
	return reason, ""
}

// attributionWellFormed reports whether s is exactly one attribution:
// `<op> <quoted> in <quoted>` for open, stat, and chdir, or
// `recorded path <quoted> resolves to <quoted> outside the tree`.
func attributionWellFormed(s string) bool {
	if _, _, _, ok := parseOperationAttribution(s); ok {
		return true
	}
	if rest, ok := strings.CutPrefix(s, "recorded path "); ok {
		return quotedThen(rest, " resolves to ", " outside the tree")
	}
	return false
}

// bracketAttributionWellFormed reports whether s is exactly one
// moved-bracket attribution: `[<part>(; <part>)*]` running to the end,
// every part beginning with one of the labels.
func bracketAttributionWellFormed(s string) bool {
	inner, ok := strings.CutPrefix(s, "[")
	if !ok {
		return false
	}
	inner, ok = strings.CutSuffix(inner, "]")
	if !ok {
		return false
	}
	for _, part := range bracketAttributionParts(inner) {
		labelled := false
		for _, label := range bracketAttributionLabels {
			if strings.HasPrefix(part, label) {
				labelled = true
			}
		}
		if !labelled {
			return false
		}
	}
	return true
}

// bracketAttributionParts splits a member list's inner text at its
// part separators outside quoted members: a member carrying the list's
// framing travels quoted (memberListName), so a "; " inside
// a quoted name is the name's, never a separator.
func bracketAttributionParts(inner string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(inner); {
		switch {
		case inner[i] == '"':
			quoted, err := strconv.QuotedPrefix(inner[i:])
			if err != nil {
				i++
				continue
			}
			i += len(quoted)
		case strings.HasPrefix(inner[i:], "; "):
			parts = append(parts, inner[start:i])
			i += 2
			start = i
		default:
			i++
		}
	}
	return append(parts, inner[start:])
}

// splitBracketAttribution is the split for the moved-bracket reason:
// the clause is the root — a quoted root (memberListName quoted it:
// its own name carries the list's framing) consumed whole as one Go
// quoted string, a bare root up to the first " [" whose suffix is one
// well-formed member list — and the attribution the list without its
// brackets (REQ-inputs-refusal-attribution). A root quote the arm
// cannot parse as a Go quoted string falls through to the bare scan,
// the member arm's own tolerance of a stray quote; a bare root composed
// before roots were quoted that BEGINS with a valid quoted literal
// followed by more name is refused whole — recorded, since falling
// through there would let a quoted root followed by a malformed list
// mis-split.
func splitBracketAttribution(reason string) (clause, attribution string, ok bool) {
	if !strings.HasPrefix(reason, movedBracketClause) {
		return reason, "", false
	}
	// A quoted root (its own name carries the list's framing) is one
	// Go quoted string after the clause's prefix: the split consumes it
	// whole and reads the list after it, never a " [" inside it.
	if rest, found := strings.CutPrefix(reason, movedBracketClause+": \""); found {
		if root, list, quoted := quotedPrefixThen("\""+rest, " "); quoted {
			if bracketAttributionWellFormed(list) {
				return movedBracketClause + ": " + root, list[1 : len(list)-1], true
			}
			return reason, "", false
		} else if _, _, quotedRootOnly := quotedPrefixThen("\""+rest, ""); quotedRootOnly {
			return reason, "", false
		}
	}
	for i := strings.Index(reason, " ["); i >= 0; {
		if suffix := reason[i+1:]; bracketAttributionWellFormed(suffix) {
			return reason[:i], suffix[1 : len(suffix)-1], true
		}
		next := strings.Index(reason[i+1:], " [")
		if next < 0 {
			break
		}
		i += 1 + next
	}
	return reason, "", false
}

// quotedPrefixThen parses one Go quoted string at the start of s followed by
// prefix, returning the quoted literal and the remainder after prefix.
func quotedPrefixThen(s, prefix string) (quoted, rest string, ok bool) {
	q, err := strconv.QuotedPrefix(s)
	if err != nil {
		return "", "", false
	}
	rest, ok = strings.CutPrefix(s[len(q):], prefix)
	if !ok {
		return "", "", false
	}
	return q, rest, true
}

// quotedThen reports whether s is a quoted string, then mid, then a
// quoted string, then exactly tail.
func quotedThen(s, mid, tail string) bool {
	_, rest, ok := quotedPrefixThen(s, mid)
	if !ok {
		return false
	}
	_, after, ok := quotedPrefixThen(rest, tail)
	return ok && after == ""
}

// operationAttribution is a classification refusal's attribution
// (REQ-inputs-refusal-attribution): the harness operation, its logged
// name, and the working directory the name resolved in — the
// process's own directory, so the producing package process is named
// for every operation, absolute names included — both quoted, so a
// non-UTF-8 or control-bearing name or directory leaves the
// attribution valid UTF-8; the directory is the observation's tracked
// one (lexical after a traversal chdir). An operation outside the
// vocabulary attributes nothing. The form rides the observation's
// attribution field alone; the reason keeps its clause.
func operationAttribution(op, name, cwd string) string {
	if !slices.Contains(attributionOps, op) {
		return ""
	}
	return op + " " + strconv.Quote(name) + " in " + strconv.Quote(cwd)
}

// resolvedTargetAttribution is a resolved-target refusal's attribution
// — the recorded path's quoted spelling and its quoted target — the
// one shape beside the operation's the split recognises; the hashing
// pass carries it in the reason itself, as state.
func resolvedTargetAttribution(spelling, target string) string {
	return "recorded path " + strconv.Quote(spelling) + " resolves to " + strconv.Quote(target) + " outside the tree"
}

// noteAttribution keeps each clause's first attribution, in log order.
func noteAttribution(attributions map[string]string, clause, attribution string) {
	if _, noted := attributions[clause]; !noted {
		attributions[clause] = attribution
	}
}

// bracketMoveAttribution names WHAT moved inside a refused root, best
// effort: members added or removed since capture by set difference,
// and — when membership held, so a content edit moved the digest — the
// most recently modified members by refusal-time stat. A moved bracket
// refusal without the file is unactionable when the writer is another
// process in a parallel suite; the name is the lead the investigation
// starts from. Attribution is advisory text on an already-decided
// refusal: stat errors just drop the entry.
func bracketMoveAttribution(moduleDir string, captured, now bracketRoot) string {
	var added, removed []string
	for rel := range now.members {
		if !captured.members[rel] {
			added = append(added, rel)
		}
	}
	for rel := range captured.members {
		if !now.members[rel] {
			removed = append(removed, rel)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	var parts []string
	if len(added) > 0 {
		parts = append(parts, "added: "+render.CappedList(memberListNames(added)))
	}
	if len(removed) > 0 {
		parts = append(parts, "removed: "+render.CappedList(memberListNames(removed)))
	}
	if len(parts) == 0 {
		p, err := materializePath(moduleDir, captured.id)
		if err == nil {
			type touched struct {
				rel string
				mod time.Time
			}
			var recent []touched
			for rel := range now.members {
				// A directory's mtime moves whenever any direct child
				// changes — the root and nested directories alike are
				// pure noise as leads; the recency list names files.
				if info, err := os.Stat(filepath.Join(p, filepath.FromSlash(rel))); err == nil && !info.IsDir() {
					recent = append(recent, touched{rel: rel, mod: info.ModTime()})
				}
			}
			sort.SliceStable(recent, func(i, j int) bool {
				if !recent[i].mod.Equal(recent[j].mod) {
					return recent[i].mod.After(recent[j].mod)
				}
				return recent[i].rel < recent[j].rel
			})
			var names []string
			for _, t := range recent {
				names = append(names, memberListName(t.rel)+" ("+t.mod.UTC().Format(time.RFC3339Nano)+")")
			}
			if len(names) > 0 {
				parts = append(parts, "recently touched: "+render.CappedList(names))
			}
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " [" + strings.Join(parts, "; ") + "]"
}

// representableReasonName renders one member name safely for a
// manifest reason: names are unconstrained filesystem bytes, and a
// reason carrying framing bytes or invalid UTF-8 would fail manifest
// validation — turning an attributable refusal into a hard error, the
// wrong direction for advisory text — so an unrepresentable name
// travels quoted. This is the reason-safety rule; memberListName is
// the list-framing rule — two predicates by design, never one.
func representableReasonName(name string) string {
	if utf8.ValidString(name) && !strings.ContainsAny(name, "\x00\r\n") {
		return name
	}
	return strconv.Quote(name)
}

// MovedBracketClause is the clause of the refusal a moved observation
// bracket raises for the root named by its display path (a
// module-relative slash path, or an absolute host path's own clean
// spelling): the root travels under the members' quoting rule
// (memberListName) — a root whose own name carries the list's framing
// is a Go quoted string, which splitBracketAttribution's quoted-root
// arm consumes whole, so the split never reads a root's segment as the
// list — and a plain root travels bare. A consumer keying records on
// the clause (RefusalClause) re-keys a stored clause through
// CanonicalMovedBracketClause, never through this composer over the
// stored root text — a quoted key would be quoted again
// (REQ-inputs-refusal-attribution).
func MovedBracketClause(root string) string {
	return movedBracketClause + ": " + memberListName(root)
}

// CanonicalMovedBracketClause is the re-key a consumer applies to a
// stored moved-bracket clause composed before roots were quoted: a
// clause whose root text parses whole as a Go quoted literal of a name
// this spelling quotes is already canonical and comes back unchanged
// (the rule is idempotent); any other root text is composed afresh,
// so a bare root carrying the list's framing re-keys to its quoted
// spelling and a plain root stays. A clause not of the moved-bracket
// form comes back unchanged. The one shape the text cannot resolve —
// a bare root whose own name is a valid Go quoted literal of a
// framing-bearing name — reads as canonical and is not re-keyed, so
// its exemption stops matching the quoted spelling the producer now
// emits: recorded, the text channel's residual class.
func CanonicalMovedBracketClause(clause string) string {
	root, found := strings.CutPrefix(clause, movedBracketClause+": ")
	if !found {
		return clause
	}
	if name, err := strconv.Unquote(root); err == nil && memberListName(name) == root {
		return clause
	}
	return MovedBracketClause(root)
}

// memberListName renders one member of a moved-bracket attribution's
// list: a representable name travels bare unless it carries the list's
// own framing — a part separator "; ", a bracket, or a quote, which
// would pair with a later quoted member's — so an unquoted member
// never contains a byte the split reads, and every quoted one is a Go
// quoted string the split consumes whole
// (REQ-inputs-refusal-attribution). The moved-bracket root travels
// under this rule too; representableReasonName is the separate
// reason-safety rule.
func memberListName(name string) string {
	if !utf8.ValidString(name) || strings.ContainsAny(name, "\x00\r\n[]\"") || strings.Contains(name, "; ") {
		return strconv.Quote(name)
	}
	return name
}

func memberListNames(names []string) []string {
	out := make([]string, len(names))
	for i, name := range names {
		out[i] = memberListName(name)
	}
	return out
}
