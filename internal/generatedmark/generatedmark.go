// Package generatedmark is the one reading of the toolchain's
// generated-file marker: the `// Code generated … DO NOT EDIT.` line
// go/build defines, which gofresh reads for its audited-generator
// discharges and folds into a member's canonical form.
package generatedmark

import (
	"regexp"
	"strings"
)

// marker is go/build's rule over the line's trimmed text — trimmed, so
// a trailing space cannot split gofresh's readers from its fold.
var marker = regexp.MustCompile(`^// Code generated .* DO NOT EDIT\.$`)

// IsMarker reports whether one comment line is the generated-file
// marker.
func IsMarker(line string) bool {
	return marker.MatchString(strings.TrimSpace(line))
}
