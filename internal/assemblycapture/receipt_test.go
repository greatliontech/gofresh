//go:build linux && !android

package assemblycapture

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestActualReceiptRosterAndProfileRefusals(t *testing.T) {
	if testing.Short() {
		t.Skip("actual cold actions and profile receipts")
	}
	f := newActionFixture(t, true)
	shim, err := buildShim(t.Context(), f.selection, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	c, err := runActionBuild(ctx, cancel, f, shim, shortCaptureDir(t), true)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := c.finish()
	if err != nil {
		t.Fatal(err)
	}
	if len(packet.Providers()) != 2 {
		t.Fatal("baseline lacks complete final roster")
	}
	asm, compile, profile := -1, -1, -1
	for i, a := range c.actions {
		switch filepath.Base(a.inv.Tool) {
		case "asm":
			if asm < 0 {
				asm = i
			}
		case "compile":
			if a.inv.Instance == f.provider.ID {
				compile = i
			}
		case "preprofile":
			profile = i
		}
	}
	if asm < 0 || compile < 0 || profile < 0 {
		t.Fatal("actual compiler/final-assembler/preprofile receipts missing")
	}
	for _, tc := range []struct {
		name, want string
		edit       func([]*capturedAction) []*capturedAction
	}{
		{"missing-one-final", "missing final assembler actions", func(a []*capturedAction) []*capturedAction { return slices.Delete(a, asm, asm+1) }},
		{"duplicate-final", "missing or duplicate final provider action", func(a []*capturedAction) []*capturedAction { return append(a, a[asm]) }},
		{"missing-compiler", "provider compiler action absent", func(a []*capturedAction) []*capturedAction { return slices.Delete(a, compile, compile+1) }},
		{"missing-profile", "compiler profile lacks captured selected-input derivation", func(a []*capturedAction) []*capturedAction { return slices.Delete(a, profile, profile+1) }},
		{"changed-profile-output", "compiler profile lacks captured selected-input derivation", func(a []*capturedAction) []*capturedAction {
			x := *a[profile]
			x.output = slices.Clone(x.output)
			x.output[0] ^= 1
			a[profile] = &x
			return a
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actions := tc.edit(slices.Clone(c.actions))
			view := receiptView(c, actions)
			packet, err := view.finish()
			if err == nil || packet != nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("wrong obligation: packet=%v error=%v, want %q", packet, err, tc.want)
			}
		})
	}
	if _, err = c.finish(); err != nil {
		t.Fatal("negative projections mutated actual baseline receipts", err)
	}
	// This is a real successful cache-hit build under the same tool boundary,
	// not an empty server fabricated as an alleged execution receipt.
	warmCtx, warmCancel := context.WithCancel(t.Context())
	defer warmCancel()
	warm, err := runActionBuild(warmCtx, warmCancel, f, shim, shortCaptureDir(t), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range warm.actions {
		if filepath.Base(a.inv.Tool) == "asm" {
			t.Fatal("fixture did not obtain a real no-final-action cache hit")
		}
	}
	if packet, err := warm.finish(); err == nil || packet != nil || !strings.Contains(err.Error(), "missing final assembler actions") {
		t.Fatalf("cache-only execution gained authority: packet=%v err=%v", packet, err)
	}
}
