package auditset

import (
	"slices"
	"unicode/utf8"
)

// fmtWriterFuncs lists fmt's writer-first print functions whose effect is
// Sprint-equivalent value computation when the writer operand is proven to be
// an in-memory sink or unmutated io.Discard (REQ-closure-observability-writer-sink).
var fmtWriterFuncs = map[string]bool{
	"Fprint":   true,
	"Fprintf":  true,
	"Fprintln": true,
}

// FmtWriterFunc reports whether name is a writer-first fmt print function.
func FmtWriterFunc(name string) bool { return fmtWriterFuncs[name] }

// fmtReaderFuncs lists fmt's reader-first scan functions.
var fmtReaderFuncs = map[string]bool{
	"Fscan":   true,
	"Fscanf":  true,
	"Fscanln": true,
}

// FmtReaderFunc reports whether name is a reader-first fmt scan function.
func FmtReaderFunc(name string) bool { return fmtReaderFuncs[name] }

// inMemoryWriterTypes maps standard packages to exported struct types whose
// pointer receivers implement io.Writer purely over process memory without
// acquiring ambient state.
var inMemoryWriterTypes = map[string][]string{
	"bytes":   {"Buffer"},
	"strings": {"Builder"},
}

// InMemoryWriterPointerType reports whether *pkgPath.typeName is an audited
// standard in-memory io.Writer implementation.
func InMemoryWriterPointerType(pkgPath, typeName string) bool {
	return slices.Contains(inMemoryWriterTypes[pkgPath], typeName)
}

// inMemoryReaderTypes maps standard packages to exported struct types whose
// pointer receivers implement io.Reader purely over process memory without
// acquiring ambient state.
var inMemoryReaderTypes = map[string][]string{
	"bytes":   {"Buffer", "Reader"},
	"strings": {"Reader"},
}

// InMemoryReaderPointerType reports whether *pkgPath.typeName is an audited
// standard in-memory io.Reader implementation.
func InMemoryReaderPointerType(pkgPath, typeName string) bool {
	return slices.Contains(inMemoryReaderTypes[pkgPath], typeName)
}

// valuePlaneFuncs lists generic standard container helpers whose results carry
// shallow copies of their input container's elements with no environment or
// backing-storage aliasing of their own.
var valuePlaneFuncs = map[string][]string{
	"maps":   {"Clone"},
	"slices": {"Clone", "Concat"},
}

// ValuePlaneClone reports whether pkgPath.name is an audited value-plane
// shallow container clone or concatenation helper.
func ValuePlaneClone(pkgPath, name string) bool {
	return slices.Contains(valuePlaneFuncs[pkgPath], name)
}

// readOnlySliceInspectFuncs lists standard functions that synchronously
// inspect slice arguments without user callbacks, never mutate or retain them,
// and return only scalar or immutable-descriptor values (never an alias into
// the input slice).
var readOnlySliceInspectFuncs = map[string][]string{
	"bytes": {
		"Compare", "Contains", "ContainsAny", "ContainsRune",
		"Count", "Equal", "EqualFold", "HasPrefix", "HasSuffix",
		"Index", "IndexAny", "IndexByte", "IndexRune",
		"LastIndex", "LastIndexAny", "LastIndexByte",
	},
	"reflect": {"TypeOf"},
	"slices":  {"BinarySearch", "Compare", "Contains", "Equal", "Index", "Max", "Min"},
	"unicode/utf8": {
		"DecodeLastRune", "DecodeLastRuneInString",
		"DecodeRune", "DecodeRuneInString",
		"FullRune", "FullRuneInString",
		"RuneCount", "RuneCountInString",
		"RuneLen", "RuneStart",
		"Valid", "ValidRune", "ValidString",
	},
}

// readOnlySliceCopyFuncs lists standard functions that read slice arguments
// without mutating or retaining them and return a freshly allocated backing
// array.
var readOnlySliceCopyFuncs = map[string][]string{
	"bytes":  {"Clone"},
	"slices": {"Clone", "Concat"},
}

// inPlaceContainerMutateFuncs lists deterministic standard functions that
// reorder elements of a caller-supplied slice in place without user callbacks
// or ambient channels.
var inPlaceContainerMutateFuncs = map[string][]string{
	"slices": {"Reverse", "Sort"},
	"sort":   {"Float64s", "Ints", "Strings"},
}

// pureScalarOrValuePackages lists pure-computation standard packages whose
// non-interface-streaming top-level functions compute deterministically over
// scalar/value arguments without user callbacks.
var pureScalarOrValuePackages = map[string]bool{
	"bytes":         true,
	"cmp":           true,
	"math/bits":     true,
	"path":          true,
	"strconv":       true,
	"strings":       true,
	"unicode":       true,
	"unicode/utf16": true,
	"unicode/utf8":  true,
}

// pureScalarOrValueFuncs lists individual pure deterministic constructors and
// descriptor helpers outside pureScalarOrValuePackages.
var pureScalarOrValueFuncs = map[string][]string{
	"errors":  {"New"},
	"reflect": {"PointerTo", "PtrTo", "TypeOf"},
}

// StdCallTraits classifies the value-flow and determinism properties of a
// standard-library function pkgPath.name for shared-dynamic-state and
// confinement analyses.
type StdCallTraits struct {
	ValuePlaneClone        bool
	ReadOnlySliceInspect   bool
	ReadOnlySliceCopy      bool
	InPlaceContainerMutate bool
	PureScalarOrValue      bool
}

// DeterministicStdCallTraits returns the deterministic value-computation traits
// for standard-library function pkgPath.name.
func DeterministicStdCallTraits(pkgPath, name string) StdCallTraits {
	if pkgPath == "" || name == "" {
		return StdCallTraits{}
	}
	vp := ValuePlaneClone(pkgPath, name)
	roInspect := slices.Contains(readOnlySliceInspectFuncs[pkgPath], name)
	roCopy := slices.Contains(readOnlySliceCopyFuncs[pkgPath], name)
	inPlace := slices.Contains(inPlaceContainerMutateFuncs[pkgPath], name)
	pureVal := pureScalarOrValuePackages[pkgPath] ||
		slices.Contains(pureScalarOrValueFuncs[pkgPath], name) ||
		(pkgPath == "math" && MathPureFunc(name))
	return StdCallTraits{
		ValuePlaneClone:        vp,
		ReadOnlySliceInspect:   roInspect,
		ReadOnlySliceCopy:      roCopy,
		InPlaceContainerMutate: inPlace,
		PureScalarOrValue:      pureVal,
	}
}

// FmtDirective describes one parsed format directive in a Go fmt format string.
type FmtDirective struct {
	Verb         rune
	Sharp        bool
	Plus         bool
	Minus        bool
	Space        bool
	Zero         bool
	HasArgIndex  bool
	DynamicWidth bool
	DynamicPrec  bool
}

// ExposesPointerIdentity reports whether d formats pointer addresses (%p or
// %#v) on non-scalar values.
func (d FmtDirective) ExposesPointerIdentity() bool {
	return d.Verb == 'p' || (d.Verb == 'v' && d.Sharp)
}

// InvokesStringerOnly reports whether d is guaranteed to invoke String() or
// Error() (or print the static type name via %T) on fmt.Stringer / error
// arguments without reflecting into underlying struct fields.
func (d FmtDirective) InvokesStringerOnly() bool {
	if d.Sharp {
		return false
	}
	switch d.Verb {
	case 'v', 's', 'q', 'x', 'X', 'T':
		return true
	default:
		return false
	}
}

func parseFmtArgIndex(fmtStr string, i int) (next int, ok bool) {
	// fmtStr[i] == '['; require non-empty decimal digits followed by ']'.
	end := len(fmtStr)
	if end-i < 3 {
		return end, false
	}
	j := i + 1
	digits := 0
	val := 0
	for j < end && fmtStr[j] >= '0' && fmtStr[j] <= '9' {
		if val <= 1_000_000 {
			val = val*10 + int(fmtStr[j]-'0')
		}
		digits++
		j++
	}
	if digits == 0 || j >= end || fmtStr[j] != ']' || val <= 0 || val > 1_000_000 {
		return end, false
	}
	return j + 1, true
}

func skipFmtDecimalDigits(fmtStr string, i int) (next int, present bool) {
	start := i
	for i < len(fmtStr) && fmtStr[i] >= '0' && fmtStr[i] <= '9' {
		i++
	}
	return i, i > start
}

// ScanFmtDirectives parses every non-escaped format directive in fmtStr
// following stdlib fmt/print.go's doPrintf state machine. It returns false if
// fmtStr ends with an incomplete directive or contains a malformed argument
// index (such as unclosed '[', non-digits, '[0]', or width/precision digits
// immediately following an explicit '[n]' index), or if visit returns false.
// Plain '%%' escapes without argument indices or dynamic '*' width/precision
// are skipped; malformed '%[1]%' or '%*%' forms still invoke visit with
// Verb == '%' so positional/index callers reject them.
func ScanFmtDirectives(fmtStr string, visit func(FmtDirective) bool) bool {
	end := len(fmtStr)
	for i := 0; i < end; {
		if fmtStr[i] != '%' {
			i++
			continue
		}
		i++
		if i >= end {
			return false
		}
		var d FmtDirective
	flagLoop:
		for i < end {
			switch fmtStr[i] {
			case '#':
				d.Sharp = true
				i++
			case '+':
				d.Plus = true
				i++
			case '-':
				d.Minus = true
				i++
			case ' ':
				d.Space = true
				i++
			case '0':
				d.Zero = true
				i++
			default:
				break flagLoop
			}
		}
		if i >= end {
			return false
		}
		afterIndex := false
		if fmtStr[i] == '[' {
			next, ok := parseFmtArgIndex(fmtStr, i)
			if !ok {
				return false
			}
			i = next
			d.HasArgIndex = true
			afterIndex = true
		}
		// Optional width: '*' or decimal digits.
		hasWidOrPrec := false
		if i < end && fmtStr[i] == '*' {
			i++
			d.DynamicWidth = true
			hasWidOrPrec = true
			afterIndex = false
		} else {
			next, widPresent := skipFmtDecimalDigits(fmtStr, i)
			if afterIndex && widPresent {
				return false
			}
			if widPresent {
				hasWidOrPrec = true
			}
			i = next
		}
		// Optional precision: '.' followed by optional [n] and '*' or digits.
		if i < end && fmtStr[i] == '.' {
			if afterIndex {
				return false
			}
			hasWidOrPrec = true
			i++
			if i < end && fmtStr[i] == '[' {
				next, ok := parseFmtArgIndex(fmtStr, i)
				if !ok {
					return false
				}
				i = next
				d.HasArgIndex = true
				afterIndex = true
			}
			if i < end && fmtStr[i] == '*' {
				i++
				d.DynamicPrec = true
				afterIndex = false
			} else {
				next, precPresent := skipFmtDecimalDigits(fmtStr, i)
				if afterIndex && precPresent {
					return false
				}
				i = next
			}
		}
		if !afterIndex && i < end && fmtStr[i] == '[' {
			next, ok := parseFmtArgIndex(fmtStr, i)
			if !ok {
				return false
			}
			i = next
			d.HasArgIndex = true
		}
		if i >= end {
			return false
		}
		verb, size := utf8.DecodeRuneInString(fmtStr[i:])
		if verb == utf8.RuneError && size == 1 {
			return false
		}
		i += size
		d.Verb = verb
		if verb == '%' {
			if d.Sharp || d.Plus || d.Minus || d.Space || d.Zero || hasWidOrPrec || d.HasArgIndex || d.DynamicWidth || d.DynamicPrec {
				return false
			}
			continue
		}
		if visit != nil && !visit(d) {
			return false
		}
	}
	return true
}

// FormatStringExposesPointerIdentity reports whether fmtStr is malformed or
// contains a directive that exposes pointer addresses (%p or %#v).
func FormatStringExposesPointerIdentity(fmtStr string) bool {
	return !ScanFmtDirectives(fmtStr, func(d FmtDirective) bool {
		return !d.ExposesPointerIdentity()
	})
}
