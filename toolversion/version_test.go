package toolversion

import (
	"runtime/debug"
	"strings"
	"testing"
)

func TestEmbeddedIdentity(t *testing.T) {
	for _, tc := range []struct {
		name string
		info *debug.BuildInfo
		want string
	}{
		{"unavailable", nil, "unknown (revision=unknown, modified=unknown, go=unknown, gofresh=unknown)"},
		{"missing", &debug.BuildInfo{}, "unknown (revision=unknown, modified=unknown, go=unknown, gofresh=not-linked)"},
		{"release", &debug.BuildInfo{Main: debug.Module{Version: "v1.2.3"}, GoVersion: "go1.27.2", Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "abc123"}, {Key: "vcs.modified", Value: "false"}}, Deps: []*debug.Module{{Path: gofreshPath, Version: "v0.116.3"}}}, "v1.2.3 (revision=abc123, modified=false, go=go1.27.2, gofresh=v0.116.3)"},
		{"dirty release", &debug.BuildInfo{Main: debug.Module{Version: "v1.2.3"}, Settings: []debug.BuildSetting{{Key: "vcs.modified", Value: "true"}}}, "v1.2.3 (revision=unknown, modified=true, go=unknown, gofresh=not-linked)"},
		{"development", &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "def456"}}}, "devel (revision=def456, modified=unknown, go=unknown, gofresh=not-linked)"},
		{"invalid modified", &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "vcs.modified", Value: "maybe"}}}, "unknown (revision=unknown, modified=unknown, go=unknown, gofresh=not-linked)"},
		{"replacement", &debug.BuildInfo{Deps: []*debug.Module{{Path: gofreshPath, Version: "v0.116.3", Replace: &debug.Module{Path: "example.com/fork", Version: "v0.2.0"}}}}, "unknown (revision=unknown, modified=unknown, go=unknown, gofresh=v0.116.3=>example.com/fork@v0.2.0)"},
		{"local replacement", &debug.BuildInfo{Deps: []*debug.Module{{Path: gofreshPath, Version: "v0.116.3", Replace: &debug.Module{Path: "../a b\nlocal"}}}}, "unknown (revision=unknown, modified=unknown, go=unknown, gofresh=\"v0.116.3=>local:../a b\\nlocal\")"},
		{"different dependency", &debug.BuildInfo{Deps: []*debug.Module{{Path: gofreshPath + "/toolversion", Version: "v0.1.0"}}}, "unknown (revision=unknown, modified=unknown, go=unknown, gofresh=not-linked)"},
		{"compiler local replacement", &debug.BuildInfo{Deps: []*debug.Module{{Path: gofreshPath, Version: "v0.115.1", Replace: &debug.Module{Path: "../gofresh", Version: "(devel)"}}}}, "unknown (revision=unknown, modified=unknown, go=unknown, gofresh=v0.115.1=>local:../gofresh)"},
		{"workspace dependency", &debug.BuildInfo{Deps: []*debug.Module{{Path: gofreshPath, Version: "(devel)"}}}, "unknown (revision=unknown, modified=unknown, go=unknown, gofresh=devel)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := identity(tc.info); got != tc.want {
				t.Fatalf("identity=%q, want %q", got, tc.want)
			}
		})
	}
}

func FuzzIdentityKeepsMetadataOnOneLine(f *testing.F) {
	f.Add("devel", "abcdef", "go1.27.2", "../local replacement")
	f.Add("v1\nspoof", "a\r\tb", "devel go1.28", "../(a),\nnext")
	f.Fuzz(func(t *testing.T, version, revision, compiler, local string) {
		info := &debug.BuildInfo{Main: debug.Module{Version: version}, GoVersion: compiler,
			Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: revision}, {Key: "vcs.modified", Value: "true"}},
			Deps:     []*debug.Module{{Path: gofreshPath, Version: "v0.1.0", Replace: &debug.Module{Path: local}}}}
		got := identity(info)
		if strings.ContainsAny(got, "\r\n\t") || !strings.Contains(got, "modified=true") {
			t.Fatalf("metadata broke framing or lost modified state: %q", got)
		}
	})
}

func TestRunningIdentity(t *testing.T) {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.GoVersion == "" {
		t.Fatal("the test executable has no compiler metadata")
	}
	if got := Identity(); !strings.Contains(got, "go="+word(info.GoVersion)) {
		t.Fatalf("running identity=%q, compiler=%q", got, info.GoVersion)
	}
}
