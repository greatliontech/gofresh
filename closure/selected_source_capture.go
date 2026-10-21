package closure

import (
	"context"
	"slices"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/closure/internal/listing"
)

// selectedSourceCapture owns caller metadata before any caller context callback.
// The selected AST, SSA, types and loader package objects remain immutable owner
// inputs. Capture and subsequent binding share one cumulative source allowance.
type selectedSourceCapture struct {
	source      computationSource
	limits      selectedSourceLimits
	work, bytes int
}

func (c *selectedSourceCapture) charge(n int) error {
	if n < 0 || c.work >= c.limits.work || n > c.limits.bytes-c.bytes {
		return regionError("selected source capture budget exhausted")
	}
	c.work++
	c.bytes += n
	return nil
}

// strings captures metadata and supplementary selection lists, such as linker
// flags, under the same allowance and before callbacks can mutate their backing.
func (c *selectedSourceCapture) strings(in []string) ([]string, error) {
	if len(in) > (c.limits.bytes-c.bytes)/8 {
		return nil, regionError("selected metadata container budget exhausted")
	}
	if err := c.charge(len(in) * 8); err != nil {
		return nil, err
	}
	for _, s := range in {
		if err := c.charge(len(s)); err != nil {
			return nil, err
		}
	}
	return slices.Clone(in), nil
}

// Capture every metadata container, including dependencies not interpreted by
// this source-only relation. An inventory supplies no approval of native inputs.
// Checks precede allocation; capture itself never calls a caller's Context.
func captureSelectedSource(source computationSource, limits selectedSourceLimits) (*selectedSourceCapture, error) {
	if limits.work <= 0 || limits.depth <= 0 || limits.bytes <= 0 || len(source.metas) > limits.work || len(source.metas) > limits.bytes/8 {
		return nil, regionError("invalid selected source capture budget")
	}
	c := &selectedSourceCapture{source: source, limits: limits}
	if err := c.charge(len(source.metas) * 8); err != nil {
		return nil, err
	}
	c.source.metas = slices.Clone(source.metas)
	var module func(*listing.Module, int) (*listing.Module, error)
	module = func(in *listing.Module, depth int) (*listing.Module, error) {
		if in == nil {
			return nil, nil
		}
		if depth >= limits.depth {
			return nil, regionError("selected module capture depth exhausted")
		}
		for _, s := range []string{in.Path, in.Version, in.Dir} {
			if err := c.charge(len(s)); err != nil {
				return nil, err
			}
		}
		out := *in
		var err error
		out.Replace, err = module(in.Replace, depth+1)
		return &out, err
	}
	for i := range c.source.metas {
		p := &c.source.metas[i]
		for _, s := range []string{p.ImportPath, p.Name, p.Dir, p.ForTest} {
			if err := c.charge(len(s)); err != nil {
				return nil, err
			}
		}
		for _, list := range []*[]string{&p.GoFiles, &p.CgoFiles, &p.CgoCFLAGS, &p.CgoCPPFLAGS, &p.CgoCXXFLAGS, &p.CgoFFLAGS, &p.CgoPkgConfig, &p.CFiles, &p.CXXFiles, &p.MFiles, &p.HFiles, &p.FFiles, &p.SFiles, &p.SwigFiles, &p.SwigCXXFiles, &p.SysoFiles, &p.EmbedFiles, &p.EmbedPatterns, &p.TestEmbedPatterns, &p.XTestEmbedPatterns, &p.CgoLDFLAGS, &p.Imports, &p.Deps} {
			var err error
			*list, err = c.strings(*list)
			if err != nil {
				return nil, err
			}
		}
		var err error
		p.Module, err = module(p.Module, 0)
		if err != nil {
			return nil, err
		}
		if p.Error != nil {
			if err := c.charge(len(p.Error.Err)); err != nil {
				return nil, err
			}
			v := *p.Error
			p.Error = &v
		}
	}
	return c, nil
}

// binder gives initialization only the unspent allowance, then retains the full
// ledger for all later binding/interpretation. Capture is charged exactly once.
func (c *selectedSourceCapture) binder(ctx context.Context, root *ssa.Function) (*selectedSourceBinder, error) {
	remaining := c.limits
	remaining.work -= c.work
	remaining.bytes -= c.bytes
	b, err := newSelectedSourceBinder(ctx, c.source, root, remaining)
	if err != nil {
		return nil, err
	}
	b.limits, b.work, b.bytes = c.limits, b.work+c.work, b.bytes+c.bytes
	return b, nil
}
