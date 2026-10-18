//go:build !linux || android

package assemblycapture

import (
	"context"
	"fmt"
)

// Acquire refuses when this platform has no supported protected tool boundary.
func Acquire(ctx context.Context, s *Selection, instance string, limits Limits) (*Packet, error) {
	if ctx != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return nil, fmt.Errorf("assembly capture: protected current-action acquisition requires Linux")
}
