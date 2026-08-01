package closure

import (
	"context"

	prog "github.com/greatliontech/gofresh/closure/internal/program"
)

// program aliases the internal loader's type so every analysis site keeps
// its package-local name.
type program = prog.Program

func loadEnv(ctx context.Context, dir string, env, buildFlags []string, pkgPath string) (*program, error) {
	return prog.Load(ctx, dir, env, buildFlags, pkgPath)
}
