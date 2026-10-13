package runtimeinput

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func FuzzPWDObservationBindsOnlyTheObservedValue(f *testing.F) {
	f.Add([]byte("unread environment"))
	f.Add([]byte{0, 255, '\n'})
	f.Fuzz(func(t *testing.T, unread []byte) {
		dir := t.TempDir()
		other := filepath.Join(dir, "other")
		if err := os.Mkdir(other, 0o700); err != nil {
			t.Fatal(err)
		}
		env := []string{"PWD=" + dir, "UNREAD=" + base64.RawURLEncoding.EncodeToString(unread)}
		obs, err := FromTestLog([]byte("getenv PWD\ngetenv PWD\n"), dir, dir, env, WithCompletedProcess("worker"), WithBracket(testBracket(t, dir)))
		if err != nil || obs.Unverifiable {
			t.Fatalf("truthful capture: %+v, %v", obs, err)
		}
		d, err := Describe(obs.Manifest, dir)
		if err != nil || !slices.Equal(d.EnvNames, []string{"PWD"}) {
			t.Fatalf("observed names: %+v, %v", d, err)
		}
		for _, same := range [][]string{env, {"PWD=" + dir}, {"UNREAD=other", "PWD=" + dir}} {
			current, err := Current(context.Background(), obs.Manifest, dir, same)
			if err != nil || current != obs.State {
				t.Fatalf("unread value affected PWD: %+v, %v", current, err)
			}
		}
		for _, changed := range [][]string{{"PWD=" + other}, {}, {"PWD="}} {
			current, err := Current(context.Background(), obs.Manifest, dir, changed)
			if err != nil || current.Digest == obs.Digest {
				t.Fatalf("changed PWD did not move: %+v, %v", current, err)
			}
		}
	})
}
