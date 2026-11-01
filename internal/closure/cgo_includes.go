package closure

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

// resolveReal follows symlinks to a path's real target, resolving `..` at the OS
// level so a directory-symlink component cannot be lexically cleaned away. Falls
// back to a lexical clean when the path does not exist.
func resolveReal(path string) string {
	if r, err := filepath.EvalSymlinks(path); err == nil {
		return r
	}
	return filepath.Clean(path)
}

// cgoIncludeRootOutsideDir returns a cgo `-I` search root the caller must fail
// closed on because it can pull in-tree headers the package-dir hash would miss.
// A root is safe only when it is under the package dir (hashed by allPackageFiles)
// or under the module cache (a version-pinned dependency whose C headers ride the
// cache guard, REQ-closure-mutable-local). Any other root — an in-module sibling, a local `replace`/
// `go.work` sibling module, or a directory the analysis cannot prove is a pinned dependency —
// is mutable in-tree source and fails closed. A genuine system `-I` root is
// indistinguishable from a mutable local one, so it fails closed too; system headers
// reached by the C compiler's *default* search (no in-tree `-I`) are still skipped
// via the not-found path in cgoEscapingInclude. The `-I` value is resolved through
// symlink components before the check (a lexical clean would hide a `symlink/..`
// escape). modCache is GOMODCACHE (empty when unknown → fail closed, never skipped).
func cgoIncludeRootOutsideDir(p *listPkg, modCache string) string {
	if p == nil || p.Dir == "" {
		return ""
	}
	pkgDir := resolveReal(p.Dir)
	for _, dir := range cgoIncludeFlagDirs(p) {
		raw := expandCgoIncludeDir(p, dir)
		if !filepath.IsAbs(raw) {
			raw = p.Dir + string(filepath.Separator) + raw
		}
		real := resolveReal(raw)
		if pathWithin(real, pkgDir) {
			continue // under the package dir → hashed by allPackageFiles
		}
		if modCache != "" && pathWithin(real, resolveReal(modCache)) {
			// Module-cache dependency → version-pinned (REQ-closure-mutable-local); its C headers ride the
			// cache guard. We trust the cached tree whole: the module cache is immutable
			// and module zips carry no symlinks, so a header inside it cannot symlink
			// back out to mutable in-tree source.
			continue
		}
		return real
	}
	return ""
}

func cgoIncludeFlagDirs(p *listPkg) []string {
	flags := append([]string{}, p.CgoCPPFLAGS...)
	flags = append(flags, p.CgoCFLAGS...)
	flags = append(flags, p.CgoCXXFLAGS...)
	flags = append(flags, p.CgoFFLAGS...)
	var dirs []string
	for i := 0; i < len(flags); i++ {
		flag := flags[i]
		dir := ""
		switch {
		case flag == "-I" || flag == "-iquote" || flag == "-isystem" || flag == "-idirafter":
			if i+1 >= len(flags) {
				continue
			}
			i++
			dir = flags[i]
		case strings.HasPrefix(flag, "-I") && flag != "-I":
			dir = flag[2:]
		case strings.HasPrefix(flag, "-iquote") && flag != "-iquote":
			dir = strings.TrimSpace(strings.TrimPrefix(flag, "-iquote"))
		case strings.HasPrefix(flag, "-isystem") && flag != "-isystem":
			dir = strings.TrimSpace(strings.TrimPrefix(flag, "-isystem"))
		case strings.HasPrefix(flag, "-idirafter") && flag != "-idirafter":
			dir = strings.TrimSpace(strings.TrimPrefix(flag, "-idirafter"))
		}
		if dir == "" {
			continue
		}
		dirs = append(dirs, dir)
	}
	return dirs
}

func cgoIncludeSearchDirs(p *listPkg) []string {
	if p == nil || p.Dir == "" {
		return nil
	}
	var dirs []string
	for _, dir := range cgoIncludeFlagDirs(p) {
		dir = cleanCgoIncludeDir(p, expandCgoIncludeDir(p, dir))
		if pathWithin(dir, p.Dir) {
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

func expandCgoIncludeDir(p *listPkg, dir string) string {
	return strings.ReplaceAll(dir, "${SRCDIR}", p.Dir)
}

func cleanCgoIncludeDir(p *listPkg, dir string) string {
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(p.Dir, dir)
	}
	return filepath.Clean(dir)
}

func cgoEscapingInclude(p *listPkg, files []string) (string, error) {
	return cgoEscapingIncludeWith(p, files, readBytes)
}

func cgoEscapingIncludeWith(p *listPkg, files []string, read func(string) (fileBytes, error)) (string, error) {
	if p == nil || p.Dir == "" {
		return "", nil
	}
	realPkgDir := resolveReal(p.Dir)
	includeDirs := cgoIncludeSearchDirs(p)
	for _, rel := range files {
		if !isNativeIncludeSource(rel) {
			continue
		}
		path := filepath.Join(p.Dir, rel)
		fb, err := read(path)
		if err != nil {
			return "", fmt.Errorf("closure: read %s: %w", path, err)
		}
		content := fb.content
		text := string(content)
		if strings.EqualFold(filepath.Ext(rel), ".go") {
			preamble, err := goCgoPreamble(content)
			if err != nil {
				return "", fmt.Errorf("closure: parse %s: %w", path, err)
			}
			text = preamble
		}
		text = spliceCPreprocessorLines(text)
		lines, hasRawString := stripCComments(text)
		if hasRawString {
			return "", fmt.Errorf("closure: unsupported cgo raw string in %s", path)
		}
		for _, line := range lines {
			include, quoted, ok := cgoIncludeDirective(line)
			if !ok {
				continue
			}
			if !quoted {
				// `#include <name>` is an angle-bracket header: resolve it like a
				// quoted include; if it is not found in-tree it is a system/toolchain
				// header (skipped below, REQ-closure-coverage). A bare token that is neither quoted nor
				// angle-bracketed is an opaque macro/computed include whose expansion
				// could reach in-tree source, so fail closed.
				if !strings.HasPrefix(include, "<") || !strings.HasSuffix(include, ">") {
					return "", fmt.Errorf("closure: unresolved cgo include %s", include)
				}
				include = strings.TrimSpace(include[1 : len(include)-1])
			} else {
				include = strings.TrimSpace(include)
			}
			if include == "" {
				return "", fmt.Errorf("closure: empty cgo include directive")
			}
			if include == "_cgo_export.h" {
				continue
			}
			if symlinkDir := symlinkDirInPath(include, filepath.Dir(path)); symlinkDir != "" {
				return symlinkDir, nil
			}
			searchDirs := []string{filepath.Dir(path)}
			if !filepath.IsAbs(include) {
				searchDirs = append(searchDirs, includeDirs...)
			}
			found := false
			for _, dir := range searchDirs {
				if symlinkDir := symlinkDirInPath(include, dir); symlinkDir != "" {
					return symlinkDir, nil
				}
				resolved := include
				if !filepath.IsAbs(resolved) {
					resolved = filepath.Join(dir, resolved)
				}
				resolved = filepath.Clean(resolved)
				if !pathWithin(resolved, p.Dir) {
					return resolved, nil
				}
				parent := filepath.Dir(resolved)
				if realParent, err := filepath.EvalSymlinks(parent); err == nil && !pathWithin(realParent, realPkgDir) {
					return realParent, nil
				}
				if _, err := os.Stat(resolved); err == nil {
					if realResolved, err := filepath.EvalSymlinks(resolved); err == nil && !pathWithin(realResolved, realPkgDir) {
						return realResolved, nil
					}
					if relResolved, err := filepath.Rel(p.Dir, resolved); err == nil && (!isNativeIncludeSource(relResolved) || strings.EqualFold(filepath.Ext(relResolved), ".go")) {
						return "", fmt.Errorf("closure: unsupported cgo include source %s", include)
					}
					found = true
					break
				}
			}
			if !found {
				// Not found under the package or its in-package `-I` roots → a
				// system/toolchain header found by the C compiler's default search
				// path (REQ-closure-coverage). Skip; build environment, not hashed. cgoIncludeRootOutsideDir
				// has already refused any in-module `-I` root, so no in-tree source hides here.
				continue
			}
		}
	}
	return "", nil
}

func spliceCPreprocessorLines(text string) string {
	text = strings.ReplaceAll(text, "\\\r\n", "")
	return strings.ReplaceAll(text, "\\\n", "")
}

func goCgoPreamble(content []byte) (string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", content, parser.ImportsOnly|parser.ParseComments)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.IMPORT {
			continue
		}
		for _, spec := range gen.Specs {
			imp, ok := spec.(*ast.ImportSpec)
			if !ok || imp.Path == nil || imp.Path.Value != `"C"` {
				continue
			}
			if imp.Doc != nil {
				appendCgoCommentGroup(&b, imp.Doc)
			} else if len(gen.Specs) == 1 {
				appendCgoCommentGroup(&b, gen.Doc)
			}
		}
	}
	return b.String(), nil
}

func appendCgoCommentGroup(b *strings.Builder, cg *ast.CommentGroup) {
	if cg == nil {
		return
	}
	for _, c := range cg.List {
		text := c.Text
		if after, ok := strings.CutPrefix(text, "//"); ok {
			b.WriteString(after)
			b.WriteByte('\n')
			continue
		}
		if after, ok := strings.CutPrefix(text, "/*"); ok {
			after = strings.TrimSuffix(after, "*/")
			b.WriteString(after)
		}
	}
	b.WriteByte('\n')
}

func isNativeIncludeSource(rel string) bool {
	ext := strings.ToLower(filepath.Ext(rel))
	switch ext {
	case ".syso", ".a", ".o", ".obj", ".so", ".dylib", ".dll", ".lib":
		return false
	}
	return true
}

func hasRawStringPrefix(before string) bool {
	for _, prefix := range []string{"u8R", "uR", "UR", "LR", "R"} {
		if strings.HasSuffix(before, prefix) {
			rest := before[:len(before)-len(prefix)]
			return len(rest) == 0 || !isCIdentByte(rest[len(rest)-1])
		}
	}
	return false
}

func isCCharLiteralStart(before string) bool {
	if len(before) == 0 || !isCIdentByte(before[len(before)-1]) {
		return true
	}
	i := len(before) - 1
	for i > 0 && (isCIdentByte(before[i-1]) || before[i-1] == '\'') {
		i--
	}
	return before[i] < '0' || before[i] > '9'
}

func isCIdentByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '$'
}

func cgoIncludeDirective(line string) (string, bool, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "#") {
		return "", false, false
	}
	line = strings.TrimSpace(strings.TrimPrefix(line, "#"))
	if strings.HasPrefix(line, "include") {
		line = strings.TrimSpace(strings.TrimPrefix(line, "include"))
	} else if strings.HasPrefix(line, "import") {
		line = strings.TrimSpace(strings.TrimPrefix(line, "import"))
	} else {
		return "", false, false
	}
	if strings.HasPrefix(line, "<") {
		end := strings.IndexByte(line, '>')
		if end < 0 {
			return line, false, true
		}
		return line[:end+1], false, true
	}
	if !strings.HasPrefix(line, "\"") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			return "", false, false
		}
		return fields[0], false, true
	}
	end := strings.IndexByte(line[1:], '"')
	if end < 0 {
		return line, false, true
	}
	return line[1 : 1+end], true, true
}

func stripCComments(text string) ([]string, bool) {
	lines := strings.Split(text, "\n")
	inBlock := false
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		var b strings.Builder
		inString := false
		inChar := false
		escaped := false
		for i := 0; i < len(line); {
			if inBlock {
				end := strings.Index(line[i:], "*/")
				if end < 0 {
					break
				}
				i += end + len("*/")
				inBlock = false
				b.WriteByte(' ')
				continue
			}
			c := line[i]
			if inString || inChar {
				b.WriteByte(c)
				i++
				if escaped {
					escaped = false
					continue
				}
				if c == '\\' {
					escaped = true
					continue
				}
				if inString && c == '"' {
					inString = false
				}
				if inChar && c == '\'' {
					inChar = false
				}
				continue
			}
			if c == '"' {
				if hasRawStringPrefix(b.String()) {
					return nil, true
				}
				inString = true
				b.WriteByte(c)
				i++
				continue
			}
			if c == '\'' && isCCharLiteralStart(b.String()) {
				inChar = true
				b.WriteByte(c)
				i++
				continue
			}
			if i+1 < len(line) && line[i:i+2] == "//" {
				break
			}
			if i+1 < len(line) && line[i:i+2] == "/*" {
				inBlock = true
				b.WriteByte(' ')
				i += len("/*")
				continue
			}
			b.WriteByte(c)
			i++
		}
		out = append(out, b.String())
	}
	return out, false
}

func symlinkDirInPath(path, base string) string {
	path = filepath.FromSlash(path)
	var current string
	var rest string
	if !filepath.IsAbs(path) {
		current = resolveReal(filepath.Clean(base))
		rest = path
	} else if base != "" && pathWithin(path, base) {
		rel, err := filepath.Rel(base, path)
		if err == nil {
			current = resolveReal(filepath.Clean(base))
			rest = rel
		}
	}
	if current == "" {
		volume := filepath.VolumeName(path)
		rest = path[len(volume):]
		current = volume
		if strings.HasPrefix(rest, string(filepath.Separator)) {
			current += string(filepath.Separator)
			rest = strings.TrimLeft(rest, string(filepath.Separator))
		}
	}
	for _, part := range strings.Split(rest, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			current = filepath.Dir(strings.TrimSuffix(current, string(filepath.Separator)))
			continue
		}
		next := filepath.Join(current, part)
		info, err := os.Lstat(next)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			if targetInfo, err := os.Stat(next); err == nil && targetInfo.IsDir() {
				return next
			}
		}
		current = next
	}
	return ""
}

func pathWithin(path, root string) bool {
	if root == "" {
		return false
	}
	path = filepath.Clean(path)
	root = filepath.Clean(root)
	if path == root {
		return true
	}
	if root == string(filepath.Separator) {
		return strings.HasPrefix(path, root)
	}
	return strings.HasPrefix(path, root+string(filepath.Separator))
}
