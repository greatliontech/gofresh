package runtimeinput

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestMovedInputsNamesTheMover pins the attribution behind a digest mismatch
// (REQ-inputs-guard): each input carries its own recorded digest, so a moved
// environment value or path names itself — values never disclosed — and an
// unmoved manifest names nothing.
func TestMovedInputsNamesTheMover(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(dir, "data", "fixture.txt")
	if err := os.WriteFile(fixture, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := []string{"MOVED_INPUT_PROBE=alpha", "PATH=/bin"}
	bracket, err := CaptureBracket(dir, []string{"data"})
	if err != nil {
		t.Fatal(err)
	}
	obs, err := FromTestLogEnv([]byte("getenv MOVED_INPUT_PROBE\nopen data/fixture.txt\n"), dir, dir, env,
		WithCompletedProcess("package-test-binary:moved"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	st, err := CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}

	if moved, err := MovedInputs(st.Manifest, dir, env); err != nil || len(moved) != 0 {
		t.Fatalf("unmoved manifest attributed %v (%v)", moved, err)
	}

	// The environment value moves: exactly that input is named, value unseen.
	envMoved := []string{"MOVED_INPUT_PROBE=beta", "PATH=/bin"}
	moved, err := MovedInputs(st.Manifest, dir, envMoved)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(moved, []string{"env MOVED_INPUT_PROBE"}) {
		t.Fatalf("moved = %v, want the env input alone", moved)
	}

	// The file moves: exactly that input is named.
	if err := os.WriteFile(fixture, []byte("v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	moved, err = MovedInputs(st.Manifest, dir, env)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(moved, []string{"path data/fixture.txt"}) {
		t.Fatalf("moved = %v, want the path input alone", moved)
	}

	// The combined digest agrees with the attribution: moved inputs exist
	// exactly when the state digest moved.
	cur, err := CurrentEnv(st.Manifest, dir, env)
	if err != nil {
		t.Fatal(err)
	}
	if cur.Digest == st.Digest {
		t.Fatal("combined digest still matches after the input moved")
	}
}

// TestStateManifestRoundTripsUnmoved pins the shared seal: a recorded
// manifest whose inputs are unmoved recomputes to a byte-identical manifest
// and digest — the equality Merge and Absolute rely on.
func TestStateManifestRoundTripsUnmoved(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data", "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := []string{"ROUNDTRIP_PROBE=v", "PATH=/bin"}
	bracket, err := CaptureBracket(dir, []string{"data"})
	if err != nil {
		t.Fatal(err)
	}
	obs, err := FromTestLogEnv([]byte("getenv ROUNDTRIP_PROBE\nopen data/f.txt\n"), dir, dir, env,
		WithCompletedProcess("package-test-binary:roundtrip"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	st, err := CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	cur, err := CurrentEnv(st.Manifest, dir, env)
	if err != nil {
		t.Fatal(err)
	}
	if cur != st {
		t.Fatalf("unmoved state did not round-trip:\nrecorded %+v\ncurrent  %+v", st, cur)
	}
}

// TestManifestRejectsMalformedEntryDigests pins the digest-shape half of the
// canonical encoding: an entry digest that is not 32 lowercase hex characters
// refuses encode and decode alike.
func TestManifestRejectsMalformedEntryDigests(t *testing.T) {
	for _, bad := range []string{"", "short", "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
		"0000000000000000000000000000000000000000000000000000000000000000"} {
		if _, err := encode(manifest{Version: manifestVersion, Env: []envInput{{Name: "A", Digest: bad}}}); err == nil {
			t.Fatalf("env digest %q encoded", bad)
		}
		if _, err := encode(manifest{Version: manifestVersion, Paths: []pathInput{{pathID: pathID{Kind: pathRel, Path: "x"}, Digest: bad}}}); err == nil {
			t.Fatalf("path digest %q encoded", bad)
		}
	}
	raw := `{"v":1,"env":[{"n":"A","d":"nothex"}]}`
	if _, err := Current(base64.RawURLEncoding.EncodeToString([]byte(raw)), t.TempDir()); err == nil {
		t.Fatal("malformed entry digest decoded")
	}
}

// TestManifestRejectsDuplicateIdentities pins the set-per-identity reader rule:
// duplicate identities — including ones distinguished only by digest, which
// byte-level compaction cannot collapse — refuse decode and encode alike.
func TestManifestRejectsDuplicateIdentities(t *testing.T) {
	dupEnv := `{"v":1,"env":[{"n":"A","d":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"n":"A","d":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}`
	if _, err := Current(base64.RawURLEncoding.EncodeToString([]byte(dupEnv)), t.TempDir()); err == nil {
		t.Fatal("duplicate env identity decoded")
	}
	dupPath := `{"v":1,"paths":[{"k":"rel","p":"x","d":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"k":"rel","p":"x","d":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}`
	if _, err := Current(base64.RawURLEncoding.EncodeToString([]byte(dupPath)), t.TempDir()); err == nil {
		t.Fatal("duplicate path identity decoded")
	}
	if _, err := encode(manifest{Version: manifestVersion, Env: []envInput{
		{Name: "A", Digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{Name: "A", Digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
	}}); err == nil {
		t.Fatal("duplicate env identity encoded")
	}
}

// TestManifestRejectsOlderToolEncodings pins the one-format sentence: the
// schemas older tools produced — env as bare strings, digest-less path
// objects — fail validation rather than reading as anything.
func TestManifestRejectsOlderToolEncodings(t *testing.T) {
	for _, raw := range []string{
		`{"v":1,"env":["A","B"]}`,
		`{"v":1,"paths":[{"k":"rel","p":"tracked"}]}`,
	} {
		if _, err := Current(base64.RawURLEncoding.EncodeToString([]byte(raw)), t.TempDir()); err == nil {
			t.Fatalf("older-tool encoding decoded: %s", raw)
		}
	}
}
