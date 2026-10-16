package runtimeinput

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/internal/outcome"
)

// Pre-v4 values cannot distinguish demonstrated movement from inferred refusal;
// pre-v3 values may also omit PWD. Even internally sealed history cannot upgrade.
func FuzzHistoricalPWDManifestDoesNotUpgrade(f *testing.F) {
	for version := uint8(1); version <= 3; version++ {
		f.Add([]byte("empty"), false, false, version)
		f.Add([]byte("pwd"), true, false, version)
		f.Add([]byte("supported"), true, true, version)
	}
	f.Fuzz(func(t *testing.T, value []byte, withEnv, supported bool, version uint8) {
		dir := t.TempDir()
		env := []string{"PWD=" + dir, "OBSERVED=" + base64.RawURLEncoding.EncodeToString(value)}
		m := manifest{Version: manifestVersion}
		if withEnv {
			m.Env = []envInput{{Name: "PWD"}, {Name: "OBSERVED"}}
		}
		if supported {
			m.Outcome, m.Subjects = outcome.Method, []string{supportedSubject}
		}
		current, err := stateFromManifest(context.Background(), m, dir, env)
		if err != nil {
			t.Fatal(err)
		}
		fresh := newObservation(current, "fresh", "fixture")
		if _, err := Adopt(current.Manifest, dir, "current", env); err != nil {
			t.Fatalf("current control: %v", err)
		}
		if HasOutcomeSupport(current.Manifest, supportedSubject) != supported {
			t.Fatal("current support control disagrees")
		}
		legacy, err := decode(current.Manifest)
		if err != nil {
			t.Fatal(err)
		}
		legacy.Version = 1 + (int(version)+2)%3
		raw, err := json.Marshal(legacy)
		if err != nil {
			t.Fatal(err)
		}
		encoded := base64.RawURLEncoding.EncodeToString(raw)
		old := newObservation(State{Manifest: encoded, Digest: manifestDigest(legacy), OK: true}, "historical", "fixture")
		if HasOutcomeSupport(encoded, supportedSubject) {
			t.Fatal("historical manifest gained outcome support")
		}
		for name, check := range map[string]func() error{
			"current":         func() error { _, err := Current(context.Background(), encoded, dir, env); return err },
			"adopt":           func() error { _, err := Adopt(encoded, dir, "old", env); return err },
			"absolute":        func() error { _, err := Absolute(old, dir, env); return err },
			"relative":        func() error { _, err := Relative(old, dir, env); return err },
			"merge old first": func() error { _, err := Merge(dir, env, old, fresh); return err },
			"merge old last":  func() error { _, err := Merge(dir, env, fresh, old); return err },
		} {
			if err := check(); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("unsupported manifest version %d", legacy.Version)) {
				t.Fatalf("%s upgraded history: %v", name, err)
			}
		}
		if old.Manifest != encoded {
			t.Fatal("historical bytes changed")
		}
	})
}
