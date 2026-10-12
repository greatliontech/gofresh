package gofresh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/greatliontech/gofresh/gotool"
)

// completeBuildEnvironment supplements the ordinary build guard's flag/input
// framing with the complete compilation environment. Runtime variables are not
// projected out: a compiler wrapper may consume any of them. Only the go
// command's generated work-directory operand is normalized, under its documented
// compiler prefix-mapping premise. The GOENV file remains a byte dependency.
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
	delete(values, "GOGCCFLAGS")
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	h := sha256.New()
	write := func(s string) { fmt.Fprintf(h, "%d:", len(s)); _, _ = h.Write([]byte(s)) }
	sequence := func(values []string) {
		fmt.Fprintf(h, "%d:", len(values))
		for _, value := range values {
			write(value)
		}
	}
	write("gofresh/build-environment@1")
	sequence(env)
	sequence(keys)
	for _, key := range keys {
		write(values[key])
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
	flags, err := goQuotedFields(text)
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

// goQuotedFields follows cmd/internal/quoted's argument form: quotes delimit a
// whole leading field, bytes inside are not escaped, and interior quotes are
// literal. GOGCCFLAGS is emitted with that package's Join, never shell grammar.
func goQuotedFields(text string) ([]string, error) {
	var fields []string
	for {
		text = strings.TrimLeft(text, " \t\r\n")
		if text == "" {
			return fields, nil
		}
		if quote := text[0]; quote == '\'' || quote == '"' {
			end := strings.IndexByte(text[1:], quote)
			if end < 0 {
				return nil, fmt.Errorf("unterminated %c field", quote)
			}
			fields = append(fields, text[1:1+end])
			text = text[2+end:]
		} else {
			end := strings.IndexAny(text, " \t\r\n")
			if end < 0 {
				return append(fields, text), nil
			}
			fields = append(fields, text[:end])
			text = text[end:]
		}
	}
}
