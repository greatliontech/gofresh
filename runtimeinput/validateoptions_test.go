package runtimeinput

import (
	"strings"
	"testing"
)

// A malformed declaration refuses before the producer spawns anything:
// the same refusals ingest would raise, available pre-spawn.
func TestValidateTestLogOptionsRefusesMalformedDeclarationsPreSpawn(t *testing.T) {
	for _, tc := range []struct {
		name string
		opt  TestLogOption
		want string
	}{
		{"relative toolchain root", WithToolchainRoot("relative/go"), "clean absolute path"},
		{"unclean module cache root", WithModuleCacheRoot("/tmp/../tmp/mod"), "clean absolute path"},
		{"relative temp root", WithEphemeralTempRoot("tmp"), "clean absolute path"},
		{"absolute static-input root", WithStaticInputRoot("/abs/corpus"), "module-relative"},
		{"escaping static-input root", WithStaticInputRoot("../corpus"), "proper in-module surface"},
	} {
		err := ValidateTestLogOptions(tc.opt)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
	if err := ValidateTestLogOptions(WithToolchainRoot("/usr/local/go"), WithStaticInputRoot("testdata/corpus")); err != nil {
		t.Errorf("well-formed declarations refused: %v", err)
	}
	// Pre-spawn validation and ingest apply the options through one path:
	// two malformed declarations name the same (first) refusal on both.
	opts := []TestLogOption{WithToolchainRoot("relative/go"), WithStaticInputRoot("/abs/corpus")}
	pre := ValidateTestLogOptions(opts...)
	_, ingest := FromTestLogEnv(nil, "/tmp/m", "/tmp/m", nil, opts...)
	if pre == nil || ingest == nil || pre.Error() != ingest.Error() {
		t.Errorf("pre-spawn %v and ingest %v disagree", pre, ingest)
	}
}
