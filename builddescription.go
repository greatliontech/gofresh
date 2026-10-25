package gofresh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/internal/buildflags"
)

// completeBuildGoEnvKeys are the resolved `go env -json` settings that determine
// compilation output (beyond GOGCCFLAGS, which is normalized separately, and
// GOWORK, whose on/off workspace mode is recorded without pinning the local
// checkout path). Local checkout and cache paths (GOMOD, GOCACHE, GOTMPDIR,
// GOPATH, GOMODCACHE, GOBIN, GOTOOLDIR, GOROOT, GOENV) are excluded so
// relocating a checkout or isolating a cache does not falsify the build guard.
var completeBuildGoEnvKeys = []string{
	"AR",
	"CC",
	"CGO_CFLAGS",
	"CGO_CPPFLAGS",
	"CGO_CXXFLAGS",
	"CGO_ENABLED",
	"CGO_FFLAGS",
	"CGO_LDFLAGS",
	"CXX",
	"FC",
	"GCCGO",
	"GO111MODULE",
	"GO386",
	"GOAMD64",
	"GOARCH",
	"GOARM",
	"GOARM64",
	"GODEBUG",
	"GOEXPERIMENT",
	"GOFIPS140",
	"GOFLAGS",
	"GOHOSTARCH",
	"GOHOSTOS",
	"GOMIPS",
	"GOMIPS64",
	"GOOS",
	"GOPPC64",
	"GORISCV64",
	"GOVERSION",
	"GOWASM",
	"PKG_CONFIG",
}

// completeBuildOSEnvKeys are the process-environment variables outside `go env`
// that affect cgo/pkg-config resolution and reproducible compilation output.
var completeBuildOSEnvKeys = []string{
	"CGO_CFLAGS_ALLOW",
	"CGO_CFLAGS_DISALLOW",
	"CGO_CPPFLAGS_ALLOW",
	"CGO_CPPFLAGS_DISALLOW",
	"CGO_CXXFLAGS_ALLOW",
	"CGO_CXXFLAGS_DISALLOW",
	"CGO_FFLAGS_ALLOW",
	"CGO_FFLAGS_DISALLOW",
	"CGO_LDFLAGS_ALLOW",
	"CGO_LDFLAGS_DISALLOW",
	"PKG_CONFIG_LIBDIR",
	"PKG_CONFIG_PATH",
	"PKG_CONFIG_SYSROOT_DIR",
	"SOURCE_DATE_EPOCH",
}

// completeBuildEnvironment supplements the ordinary build guard's flag/input
// framing with the build-determining compilation environment and resolved Go
// settings. Ambient shell variables and local checkout or cache directory paths
// are excluded so moving checkouts, isolating caches, or changing non-build
// shell variables does not falsify the build guard. The go command's generated
// work-directory operand is normalized under its documented compiler
// prefix-mapping premise, and a declared GOENV file remains a content-byte
// dependency.
func completeBuildEnvironment(ctx context.Context, snapshot *gotool.EnvSnapshot, dir string, env []string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	var values map[string]string
	if snapshot == nil {
		return "", fmt.Errorf("gofresh: build description has no environment snapshot")
	}
	if err := json.Unmarshal(snapshot.JSON, &values); err != nil {
		return "", err
	}
	gcc, ok := values["GOGCCFLAGS"]
	if !ok {
		return "", fmt.Errorf("gofresh: build description has no GOGCCFLAGS")
	}
	flags, err := normalizedGCCFlags(gcc)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	write := func(s string) { fmt.Fprintf(h, "%d:", len(s)); _, _ = h.Write([]byte(s)) }
	sequence := func(values []string) {
		fmt.Fprintf(h, "%d:", len(values))
		for _, value := range values {
			write(value)
		}
	}
	write("gofresh/build-environment@2")
	fmt.Fprintf(h, "%d:", len(completeBuildOSEnvKeys))
	for _, key := range completeBuildOSEnvKeys {
		write(key)
		if val, ok := gotool.LookupEnv(env, key); ok {
			write("present")
			write(val)
		} else {
			write("absent")
		}
	}
	fmt.Fprintf(h, "%d:", len(completeBuildGoEnvKeys))
	for _, key := range completeBuildGoEnvKeys {
		write(key)
		write(values[key])
	}
	if gowork := values["GOWORK"]; gowork != "" && gowork != "off" {
		write("gowork=on")
	} else {
		write("gowork=off")
	}
	sequence(flags)
	path := values["GOENV"]
	if path == "" || path == "off" {
		write("no-environment-file")
	} else {
		if !filepath.IsAbs(path) {
			path = filepath.Join(dir, path)
		}
		if err := ctx.Err(); err != nil {
			return "", err
		}
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			write("absent-environment-file")
		} else {
			if err != nil {
				return "", fmt.Errorf("gofresh: build environment file: %w", err)
			}
			if !info.Mode().IsRegular() {
				return "", fmt.Errorf("gofresh: build environment file %q is not regular", path)
			}
			if err := ctx.Err(); err != nil {
				return "", err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return "", fmt.Errorf("gofresh: build environment file: %w", err)
			}
			write("environment-file")
			write(string(data))
		}
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func normalizedGCCFlags(text string) ([]string, error) {
	flags, err := buildflags.Fields(text)
	if err != nil {
		return nil, fmt.Errorf("gofresh: GOGCCFLAGS: %w", err)
	}
	maps := 0
	for i, flag := range flags {
		for _, prefix := range []string{"-ffile-prefix-map=", "-fdebug-prefix-map="} {
			if !strings.HasPrefix(flag, prefix) {
				continue
			}
			maps++
			operand, mapped := strings.CutSuffix(strings.TrimPrefix(flag, prefix), "=/tmp/go-build")
			if !mapped || !filepath.IsAbs(operand) || !strings.HasPrefix(filepath.Base(operand), "go-build") || maps > 1 {
				return nil, fmt.Errorf("gofresh: GOGCCFLAGS has an unrecognized generated prefix mapping %q", flag)
			}
			flags[i] = prefix + "<generated-work-directory>=/tmp/go-build"
		}
	}
	return flags, nil
}
