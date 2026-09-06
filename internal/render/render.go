// Package render holds the presentation helpers refusal and diagnostic
// texts share: bounded lists that stay actionable without becoming a
// wall of paths.
package render

import (
	"fmt"
	"strings"
)

// ListCap is the number of names a bounded list shows before folding
// the remainder into a count — enough to act on, never a wall.
const ListCap = 3

// CappedList joins names, showing at most ListCap of them and naming
// how many more there are.
func CappedList(names []string) string {
	if len(names) <= ListCap {
		return strings.Join(names, ", ")
	}
	return strings.Join(names[:ListCap], ", ") + fmt.Sprintf(", and %d more", len(names)-ListCap)
}
