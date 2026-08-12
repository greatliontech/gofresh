package flagregdep

import (
	_ "github.com/greatliontech/gofresh/closure/fixtures/flagregescape"
)

// A dependency's untraceable registration sink blocks this package's
// subjects too: the poison covers every subject sharing the test
// binary, not just the registering package's own.
func Prod() int { return 7 }
