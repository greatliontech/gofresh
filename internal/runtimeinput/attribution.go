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
// (REQ-inputs-refusal-attribution).
const attributionSeparator = " — "

// attributionOps is the one vocabulary of harness operations an
// attribution names — the observation's attribution field carries
// none for an operation outside it (fail-closed).
var attributionOps = []string{"open", "stat", "chdir"}

// movedBracketClause heads the observation-bracket refusal's reason,
// the one reason whose attribution is a bracketed member list.
const movedBracketClause = "observation bracket moved"

// bracketAttributionLabels are the member-list parts a moved-bracket
// attribution is made of (bracketMoveAttribution): each part one label
// and its capped list, the parts joined by "; " inside one bracket pair.
var bracketAttributionLabels = []string{"added: ", "removed: ", "recently touched: "}

func refusalClause(reason string) string {
	clause, _ := splitAttribution(reason)
	return clause
}

func refusalAttribution(reason string) string {
	_, attribution := splitAttribution(reason)
	return attribution
}

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

func attributionWellFormed(s string) bool {
	if _, _, _, ok := parseOperationAttribution(s); ok {
		return true
	}
	if rest, ok := strings.CutPrefix(s, "recorded path "); ok {
		return quotedThen(rest, " resolves to ", " outside the tree")
	}
	return false
}

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

func splitBracketAttribution(reason string) (clause, attribution string, ok bool) {
	if !strings.HasPrefix(reason, movedBracketClause) {
		return reason, "", false
	}
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

func movedBracketClauseForRoot(root string) string {
	return movedBracketClause + ": " + memberListName(root)
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
