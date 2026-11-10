package cprep

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ExtractCgoPreamble extracts the C preamble text from an import "C" comment group,
// matching cmd/cgo's commentText rule (// comments end with '\n'; /* */ block
// comments concatenate directly and the group ends with '\n').
func ExtractCgoPreamble(doc *ast.CommentGroup) string {
	if doc == nil {
		return ""
	}
	var b strings.Builder
	for _, c := range doc.List {
		if strings.HasPrefix(c.Text, "//") {
			b.WriteString(c.Text[2:])
			b.WriteByte('\n')
		} else if strings.HasPrefix(c.Text, "/*") && strings.HasSuffix(c.Text, "*/") && len(c.Text) >= 4 {
			b.WriteString(c.Text[2 : len(c.Text)-2])
		}
	}
	if b.Len() > 0 {
		b.WriteByte('\n')
	}
	return b.String()
}

// IsCgoImportLit reports whether lit is a Go string literal spelling "C".
func IsCgoImportLit(lit string) bool {
	if lit == `"C"` || lit == "`C`" {
		return true
	}
	if len(lit) < 3 || (lit[0] != '"' && lit[0] != '`') {
		return false
	}
	unquoted, err := strconv.Unquote(lit)
	return err == nil && unquoted == "C"
}

// SourceMayImportC reports whether a Go source file's raw text could contain an import "C" declaration.
func SourceMayImportC(text string) bool {
	return strings.Contains(text, `"C"`) ||
		strings.Contains(text, "`C`") ||
		(strings.Contains(text, "import") && strings.IndexByte(text, '\\') >= 0)
}

// ExtractFileCgoPreambles extracts all Cgo preamble blocks from a parsed *ast.File.
func ExtractFileCgoPreambles(file *ast.File) []string {
	if file == nil {
		return nil
	}
	var out []string
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.IMPORT {
			continue
		}
		for _, spec := range gd.Specs {
			imp, ok := spec.(*ast.ImportSpec)
			if !ok || imp.Path == nil || !IsCgoImportLit(imp.Path.Value) {
				continue
			}
			cg := imp.Doc
			if cg == nil && len(gd.Specs) == 1 {
				cg = gd.Doc
			}
			if cg != nil {
				if p := ExtractCgoPreamble(cg); p != "" {
					out = append(out, p)
				}
			}
		}
	}
	return out
}

// GoCgoPreamble parses the import section of content and returns the concatenated Cgo preamble text.
func GoCgoPreamble(content []byte) (string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", content, parser.ImportsOnly|parser.ParseComments)
	if err != nil {
		return "", err
	}
	preambles := ExtractFileCgoPreambles(f)
	if len(preambles) == 0 {
		return "", nil
	}
	return strings.Join(preambles, "\n") + "\n", nil
}

// SpliceCPreprocessorLines removes backslash-newline continuations from text.
func SpliceCPreprocessorLines(text string) string {
	text = strings.ReplaceAll(text, "\\\r\n", "")
	return strings.ReplaceAll(text, "\\\n", "")
}

// IsNativeIncludeSource reports whether rel is a source/header file rather than a precompiled binary object.
func IsNativeIncludeSource(rel string) bool {
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

// CgoIncludeDirective parses a #include or #import line.
func CgoIncludeDirective(line string) (string, bool, bool) {
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

// StripCComments strips // and /* */ comments from C/C++ text while detecting C++ raw strings.
func StripCComments(text string) ([]string, bool) {
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

func matchCStringPrefixAt(s string, idx int) (quoteIdx int, ok bool) {
	if idx >= len(s) {
		return 0, false
	}
	if s[idx] == '"' {
		return idx, true
	}
	if idx > 0 && IsASCIIIdentByte(s[idx-1]) {
		return 0, false
	}
	if idx+1 < len(s) && (s[idx] == 'L' || s[idx] == 'u' || s[idx] == 'U') && s[idx+1] == '"' {
		return idx + 1, true
	}
	if idx+2 < len(s) && s[idx] == 'u' && s[idx+1] == '8' && s[idx+2] == '"' {
		return idx + 2, true
	}
	return 0, false
}

func writeNormalizedCStringByte(b *strings.Builder, ch byte) {
	switch ch {
	case '"':
		b.WriteString(`\"`)
	case '\\':
		b.WriteString(`\\`)
	default:
		b.WriteByte(ch)
	}
}

// NormalizeCStringLiterals normalizes C string literal escapes and adjacent string concatenation.
func NormalizeCStringLiterals(s string, allowNewlineConcat bool) string {
	if strings.IndexByte(s, '"') < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '\'' {
			end := SkipQuotedLiteral(s, i)
			b.WriteString(s[i:end])
			i = end
			continue
		}
		if qIdx, ok := matchCStringPrefixAt(s, i); ok {
			b.WriteByte('"')
			i = qIdx + 1
			for {
				for i < len(s) && s[i] != '"' {
					if s[i] != '\\' || i+1 >= len(s) {
						b.WriteByte(s[i])
						i++
						continue
					}
					esc := s[i+1]
					switch {
					case esc == 'x':
						j := i + 2
						var val uint32
						digits := 0
						for j < len(s) {
							d, okD := isHexDigitByte(s[j])
							if !okD {
								break
							}
							val = (val << 4) | d
							digits++
							j++
						}
						if digits > 0 {
							writeNormalizedCStringByte(&b, byte(val))
							i = j
							continue
						}
					case esc >= '0' && esc <= '7':
						j := i + 1
						var val uint32
						for k := 0; k < 3 && j < len(s) && s[j] >= '0' && s[j] <= '7'; k++ {
							val = (val << 3) | uint32(s[j]-'0')
							j++
						}
						writeNormalizedCStringByte(&b, byte(val))
						i = j
						continue
					case esc == 'u' || esc == 'U':
						want := 4
						if esc == 'U' {
							want = 8
						}
						if i+2+want <= len(s) {
							var val uint32
							okU := true
							for k := 0; k < want; k++ {
								d, okD := isHexDigitByte(s[i+2+k])
								if !okD {
									okU = false
									break
								}
								val = (val << 4) | d
							}
							if okU && utf8.ValidRune(rune(val)) {
								r := rune(val)
								if r == '"' {
									b.WriteString(`\"`)
								} else if r == '\\' {
									b.WriteString(`\\`)
								} else {
									b.WriteRune(r)
								}
								i += 2 + want
								continue
							}
						}
					}
					switch esc {
					case '"':
						b.WriteString(`\"`)
					case '\\':
						b.WriteString(`\\`)
					case '\'':
						b.WriteByte('\'')
					case '?':
						b.WriteByte('?')
					case 'n':
						b.WriteByte('\n')
					case 'r':
						b.WriteByte('\r')
					case 't':
						b.WriteByte('\t')
					case 'v':
						b.WriteByte('\v')
					case 'b':
						b.WriteByte('\b')
					case 'f':
						b.WriteByte('\f')
					case 'a':
						b.WriteByte('\a')
					default:
						b.WriteByte(esc)
					}
					i += 2
				}
				if i < len(s) && s[i] == '"' {
					i++
				}
				k := i
				for k < len(s) {
					if s[k] == ' ' || s[k] == '\t' {
						k++
						continue
					}
					if allowNewlineConcat && (s[k] == '\r' || s[k] == '\n') {
						k++
						continue
					}
					break
				}
				if nextQ, okNext := matchCStringPrefixAt(s, k); okNext {
					i = nextQ + 1
					continue
				}
				b.WriteByte('"')
				break
			}
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// CgoPkgConfig holds the package directory and Cgo compiler flag slices
// needed to validate Cgo include roots and header references.
type CgoPkgConfig struct {
	Dir         string
	CgoCPPFLAGS []string
	CgoCFLAGS   []string
	CgoCXXFLAGS []string
	CgoFFLAGS   []string
}

// ResolveReal follows symlinks to a path's real target, resolving `..` at the OS
// level so a directory-symlink component cannot be lexically cleaned away. Falls
// back to a lexical clean when the path does not exist.
func ResolveReal(path string) string {
	if r, err := filepath.EvalSymlinks(path); err == nil {
		return r
	}
	return filepath.Clean(path)
}

// PathWithin reports whether path is lexically inside root (or equal to root).
func PathWithin(path, root string) bool {
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

// SymlinkDirInPath returns the first directory-symlink component traversed when
// resolving path relative to base, or "" if none is traversed.
func SymlinkDirInPath(path, base string) string {
	path = filepath.FromSlash(path)
	var current string
	var rest string
	if !filepath.IsAbs(path) {
		current = ResolveReal(filepath.Clean(base))
		rest = path
	} else if base != "" && PathWithin(path, base) {
		rel, err := filepath.Rel(base, path)
		if err == nil {
			current = ResolveReal(filepath.Clean(base))
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

// CgoIncludeFlagDirs extracts -I, -iquote, -isystem, and -idirafter directories from p.
func CgoIncludeFlagDirs(p CgoPkgConfig) []string {
	flags := make([]string, 0, len(p.CgoCPPFLAGS)+len(p.CgoCFLAGS)+len(p.CgoCXXFLAGS)+len(p.CgoFFLAGS))
	flags = append(flags, p.CgoCPPFLAGS...)
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

func expandCgoIncludeDir(pkgDir, dir string) string {
	return strings.ReplaceAll(dir, "${SRCDIR}", pkgDir)
}

func cleanCgoIncludeDir(pkgDir, dir string) string {
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(pkgDir, dir)
	}
	return filepath.Clean(dir)
}

// CgoIncludeSearchDirs returns in-package -I search directories for p.
func CgoIncludeSearchDirs(p CgoPkgConfig) []string {
	if p.Dir == "" {
		return nil
	}
	var dirs []string
	for _, dir := range CgoIncludeFlagDirs(p) {
		dir = cleanCgoIncludeDir(p.Dir, expandCgoIncludeDir(p.Dir, dir))
		if PathWithin(dir, p.Dir) {
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

// CgoIncludeRootOutsideDir returns a cgo `-I` search root the caller must fail
// closed on because it can pull in-tree headers the package-dir hash would miss.
func CgoIncludeRootOutsideDir(p CgoPkgConfig, modCache string) string {
	if p.Dir == "" {
		return ""
	}
	flagDirs := CgoIncludeFlagDirs(p)
	if len(flagDirs) == 0 {
		return ""
	}
	pkgDir := ResolveReal(p.Dir)
	realModCache := ""
	if modCache != "" {
		realModCache = ResolveReal(modCache)
	}
	for _, dir := range flagDirs {
		raw := expandCgoIncludeDir(p.Dir, dir)
		if !filepath.IsAbs(raw) {
			raw = p.Dir + string(filepath.Separator) + raw
		}
		real := ResolveReal(raw)
		if PathWithin(real, pkgDir) {
			continue
		}
		if realModCache != "" && PathWithin(real, realModCache) {
			continue
		}
		return real
	}
	return ""
}

// CgoEscapingIncludeWith scans Cgo/native source files in p for #include
// directives that escape p.Dir or traverse directory symlinks.
func CgoEscapingIncludeWith(p CgoPkgConfig, files []string, read func(string) ([]byte, error)) (string, error) {
	if p.Dir == "" {
		return "", nil
	}
	realPkgDir := ResolveReal(p.Dir)
	includeDirs := CgoIncludeSearchDirs(p)
	for _, rel := range files {
		if !IsNativeIncludeSource(rel) {
			continue
		}
		path := filepath.Join(p.Dir, rel)
		content, err := read(path)
		if err != nil {
			return "", fmt.Errorf("closure: read %s: %w", path, err)
		}
		text := string(content)
		if strings.EqualFold(filepath.Ext(rel), ".go") {
			preamble, err := GoCgoPreamble(content)
			if err != nil {
				return "", fmt.Errorf("closure: parse %s: %w", path, err)
			}
			text = preamble
		}
		text = SpliceCPreprocessorLines(text)
		lines, hasRawString := StripCComments(text)
		if hasRawString {
			return "", fmt.Errorf("closure: unsupported cgo raw string in %s", path)
		}
		for _, line := range lines {
			include, quoted, ok := CgoIncludeDirective(line)
			if !ok {
				continue
			}
			if !quoted {
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
			searchDirs := []string{filepath.Dir(path)}
			if !filepath.IsAbs(include) {
				searchDirs = append(searchDirs, includeDirs...)
			}
			found := false
			for _, dir := range searchDirs {
				if symlinkDir := SymlinkDirInPath(include, dir); symlinkDir != "" {
					return symlinkDir, nil
				}
				resolved := include
				if !filepath.IsAbs(resolved) {
					resolved = filepath.Join(dir, resolved)
				}
				resolved = filepath.Clean(resolved)
				if !PathWithin(resolved, p.Dir) {
					return resolved, nil
				}
				parent := filepath.Dir(resolved)
				if realParent, err := filepath.EvalSymlinks(parent); err == nil && !PathWithin(realParent, realPkgDir) {
					return realParent, nil
				}
				if _, err := os.Stat(resolved); err == nil {
					if relResolved, err := filepath.Rel(p.Dir, resolved); err == nil && (!IsNativeIncludeSource(relResolved) || strings.EqualFold(filepath.Ext(relResolved), ".go")) {
						return "", fmt.Errorf("closure: unsupported cgo include source %s", include)
					}
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
	}
	return "", nil
}
