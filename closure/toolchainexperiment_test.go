package closure

import (
	"context"
	"maps"
	"os"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
)

func TestAuditedExperimentRejectsUnverifiedSourceChanges(t *testing.T) {
	if testing.Short() {
		t.Skip("lists the standard library")
	}
	isolateProofCache(t)
	ctx := context.Background()
	dir := t.TempDir()
	snapshot, err := (gotool.Runner{}).TakeEnvSnapshot(ctx, dir, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	env, err := gotool.NormalizeEnv(os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	d, err := toolchainSourceDigests(ctx, gotool.Runner{}, dir, env, snapshot, nil)
	if err != nil {
		t.Fatal(err)
	}
	if deg := toolchainSourceDegradation("rebuilt-toolchain", d, nil); !deg.audited() {
		t.Fatalf("verified content rejected under a different label: %s", deg.notice())
	}
	for _, key := range []string{"internal/goexperiment", "runtime", "strings"} {
		changed := d
		changed.Packages = maps.Clone(d.Packages)
		changed.Packages[key] = "unverified-source-change"
		deg := toolchainSourceDegradation("rebuilt-toolchain", changed, nil)
		if deg.audited() || !strings.Contains(deg.notice(), key) {
			t.Fatalf("changed %s admitted or not named: %s", key, deg.notice())
		}
	}
}
