package closure

import (
	prog "github.com/greatliontech/gofresh/closure/internal/program"
)

// program aliases the internal loader's type so every analysis site keeps
// its package-local name.
type program = prog.Program
