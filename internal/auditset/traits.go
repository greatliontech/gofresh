package auditset

import (
	"go/types"
	"slices"
	"strings"
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
	"slices":       {"Reverse", "Sort"},
	"sort":         {"Float64s", "Ints", "Strings"},
	"unicode/utf8": {"EncodeRune"},
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

// pureHashPackages lists verified deterministic hash packages whose concrete
// hash.Hash implementations compute purely over process memory without ambient
// seeds (hash/maphash is excluded).
var pureHashPackages = map[string]bool{
	"crypto/internal/fips140/sha256": true,
	"crypto/internal/fips140/sha3":   true,
	"crypto/internal/fips140/sha512": true,
	"crypto/md5":                     true,
	"crypto/sha1":                    true,
	"crypto/sha256":                  true,
	"crypto/sha512":                  true,
	"hash/adler32":                   true,
	"hash/crc32":                     true,
	"hash/crc64":                     true,
	"hash/fnv":                       true,
}

// PureHashPackage reports whether pkgPath is an audited seed-free deterministic
// hash package.
func PureHashPackage(pkgPath string) bool { return pureHashPackages[pkgPath] }

// goASTNodeInterfaces lists package go/ast's syntax-node interfaces.
var goASTNodeInterfaces = map[string]bool{
	"Decl": true, "Expr": true, "Node": true, "Spec": true, "Stmt": true,
}

// GoASTNodeInterface reports whether name is one of go/ast's syntax-node
// interfaces (Node, Expr, Stmt, Decl, Spec).
func GoASTNodeInterface(name string) bool { return goASTNodeInterfaces[name] }

var writerFirstExtraStdFuncs = map[string][]string{
	"go/scanner": {"PrintError"},
}

// WriterFirstStdFunc reports whether pkgPath.name is a standard-library
// function whose first argument is its output io.Writer sink.
func WriterFirstStdFunc(pkgPath, name string) bool {
	return (pkgPath == "fmt" && FmtWriterFunc(name)) || slices.Contains(writerFirstExtraStdFuncs[pkgPath], name)
}

var goParserSourceFuncs = map[string]bool{
	"ParseExprFrom": true,
	"ParseFile":     true,
}

// GoParserSourceFunc reports whether name is a go/parser entry point whose src
// parameter selects between in-memory source (src != nil) and filesystem reads
// (src == nil).
func GoParserSourceFunc(name string) bool { return goParserSourceFuncs[name] }

// tabwriterSymbols is the audited surface of package text/tabwriter: the Writer
// filter, its constructor and formatting methods, and its flag/escape constants.
var tabwriterSymbols = map[string]bool{
	"Writer": true, "NewWriter": true, "Init": true, "Write": true, "Flush": true,
	"FilterHTML": true, "StripEscape": true, "AlignRight": true, "DiscardEmptyColumns": true,
	"TabIndent": true, "Debug": true, "Escape": true,
}

// goTokenSymbols is the audited surface of package go/token: Token, Pos,
// Position, File, FileSet, all lexical token and precedence constants, and all
// pure methods (excluding (*FileSet).Read and (*FileSet).Write, which invoke
// arbitrary func(any) error serialization callbacks).
var goTokenSymbols = map[string]bool{
	"Token": true, "Pos": true, "NoPos": true, "Position": true, "File": true, "FileSet": true,
	"NewFileSet": true, "Lookup": true, "IsExported": true, "IsKeyword": true, "IsIdentifier": true,
	"LowestPrec": true, "UnaryPrec": true, "HighestPrec": true,
	"ILLEGAL": true, "EOF": true, "COMMENT": true,
	"IDENT": true, "INT": true, "FLOAT": true, "IMAG": true, "CHAR": true, "STRING": true,
	"ADD": true, "SUB": true, "MUL": true, "QUO": true, "REM": true,
	"AND": true, "OR": true, "XOR": true, "SHL": true, "SHR": true, "AND_NOT": true,
	"ADD_ASSIGN": true, "SUB_ASSIGN": true, "MUL_ASSIGN": true, "QUO_ASSIGN": true, "REM_ASSIGN": true,
	"AND_ASSIGN": true, "OR_ASSIGN": true, "XOR_ASSIGN": true, "SHL_ASSIGN": true, "SHR_ASSIGN": true, "AND_NOT_ASSIGN": true,
	"LAND": true, "LOR": true, "ARROW": true, "INC": true, "DEC": true,
	"EQL": true, "LSS": true, "GTR": true, "ASSIGN": true, "NOT": true,
	"NEQ": true, "LEQ": true, "GEQ": true, "DEFINE": true, "ELLIPSIS": true,
	"LPAREN": true, "LBRACK": true, "LBRACE": true, "COMMA": true, "PERIOD": true,
	"RPAREN": true, "RBRACK": true, "RBRACE": true, "SEMICOLON": true, "COLON": true,
	"BREAK": true, "CASE": true, "CHAN": true, "CONST": true, "CONTINUE": true,
	"DEFAULT": true, "DEFER": true, "ELSE": true, "FALLTHROUGH": true, "FOR": true,
	"FUNC": true, "GO": true, "GOTO": true, "IF": true, "IMPORT": true,
	"INTERFACE": true, "MAP": true, "PACKAGE": true, "RANGE": true, "RETURN": true,
	"SELECT": true, "STRUCT": true, "SWITCH": true, "TYPE": true, "VAR": true, "TILDE": true,
	"String": true, "Precedence": true, "IsLiteral": true, "IsOperator": true, "IsValid": true,
	"Name": true, "Base": true, "Size": true, "End": true, "LineCount": true,
	"AddLine": true, "MergeLine": true, "Lines": true, "SetLines": true, "SetLinesForContent": true,
	"LineStart": true, "AddLineInfo": true, "AddLineColumnInfo": true, "Offset": true, "Line": true,
	"PositionFor": true, "AddFile": true, "AddExistingFiles": true, "RemoveFile": true, "Iterate": true,
}

// goScannerSymbols is the audited bare-name surface of package go/scanner:
// Scanner, Error, ErrorList, ErrorHandler, Mode, ScanComments, and their pure
// methods (PrintError is writer-gated via WriterFirstStdFunc).
var goScannerSymbols = map[string]bool{
	"Error": true, "ErrorList": true, "ErrorHandler": true, "Mode": true, "ScanComments": true, "Scanner": true,
	"Add": true, "Reset": true, "Len": true, "Swap": true, "Less": true,
	"Sort": true, "RemoveMultiples": true, "Err": true, "Init": true, "Scan": true, "End": true,
}

// goASTSymbols is the audited bare-name surface of package go/ast: all syntax
// node, comment, directive, visitor, scope, and filter types, constants, and
// pure operations. Print and Fprint (which reflect via reflect.ValueOf/FieldFilter
// and iterate unsorted Scope maps), NotNilFilter, deprecated unsorted-map
// NewPackage / Importer, and bare String (shared with pointer-exposing
// CommentMap.String and Scope.String) are excluded; pure Ident.String and
// ObjKind.String live in goASTMethods.
var goASTSymbols = map[string]bool{
	"Node": true, "Expr": true, "Stmt": true, "Decl": true, "Spec": true, "Visitor": true,
	"Comment": true, "CommentGroup": true, "CommentMap": true, "Directive": true, "DirectiveArg": true,
	"Field": true, "FieldList": true, "BadExpr": true, "Ident": true, "Ellipsis": true, "BasicLit": true,
	"FuncLit": true, "CompositeLit": true, "ParenExpr": true, "SelectorExpr": true, "IndexExpr": true,
	"IndexListExpr": true, "SliceExpr": true, "TypeAssertExpr": true, "CallExpr": true, "StarExpr": true,
	"UnaryExpr": true, "BinaryExpr": true, "KeyValueExpr": true, "ArrayType": true, "StructType": true,
	"FuncType": true, "InterfaceType": true, "MapType": true, "ChanType": true, "ChanDir": true, "SEND": true, "RECV": true,
	"BadStmt": true, "DeclStmt": true, "EmptyStmt": true, "LabeledStmt": true, "ExprStmt": true,
	"SendStmt": true, "IncDecStmt": true, "AssignStmt": true, "GoStmt": true, "DeferStmt": true,
	"ReturnStmt": true, "BranchStmt": true, "BlockStmt": true, "IfStmt": true, "CaseClause": true,
	"SwitchStmt": true, "TypeSwitchStmt": true, "CommClause": true, "SelectStmt": true, "ForStmt": true, "RangeStmt": true,
	"ImportSpec": true, "ValueSpec": true, "TypeSpec": true, "BadDecl": true, "GenDecl": true, "FuncDecl": true,
	"File": true, "Package": true, "Scope": true, "Object": true, "ObjKind": true,
	"Bad": true, "Pkg": true, "Con": true, "Typ": true, "Var": true, "Fun": true, "Lbl": true,
	"Filter": true, "FieldFilter": true, "MergeMode": true,
	"FilterFuncDuplicates": true, "FilterUnassociatedComments": true, "FilterImportDuplicates": true,
	"Pos": true, "End": true, "Text": true, "NumFields": true, "IsExported": true, "NewIdent": true,
	"Inspect": true, "Preorder": true, "PreorderStack": true, "Walk": true, "Visit": true,
	"NewCommentMap": true, "Update": true, "Comments": true, "ParseDirective": true, "ParseArgs": true,
	"SortImports": true, "FileExports": true, "PackageExports": true,
	"FilterDecl": true, "FilterFile": true, "FilterPackage": true, "MergePackageFiles": true,
	"NewScope": true, "Insert": true, "Lookup": true, "NewObj": true, "IsGenerated": true, "Unparen": true,
}

var goASTMethods = map[string][]string{
	"Ident":   {"String"},
	"ObjKind": {"String"},
}

// GoASTMethod reports whether a go/ast receiver's method is in the audited
// receiver-qualified set.
func GoASTMethod(receiver, method string) bool {
	return slices.Contains(goASTMethods[receiver], method)
}

// goParserSymbols is the audited unconditional bare-name surface of package
// go/parser: Mode, its flag constants, and in-memory ParseExpr (ParseFile and
// ParseExprFrom are source-gated via GoParserSourceFunc; ParseDir is refused).
var goParserSymbols = map[string]bool{
	"Mode": true, "PackageClauseOnly": true, "ImportsOnly": true, "ParseComments": true,
	"Trace": true, "DeclarationErrors": true, "SpuriousErrors": true,
	"SkipObjectResolution": true, "AllErrors": true, "ParseExpr": true,
}

// runtimeDebugSymbols is the audited unconditional bare-name surface of package
// runtime/debug: pure string parser ParseBuildInfo and the BuildInfo, Module,
// and BuildSetting value shapes (ReadBuildInfo is gated on -buildvcs and
// runtime.modinfo; GC/stack/crash operations are excluded).
var runtimeDebugSymbols = map[string]bool{
	"ParseBuildInfo": true, "BuildInfo": true, "Module": true, "BuildSetting": true,
}

var runtimeDebugMethods = map[string][]string{
	"BuildInfo": {"String"},
}

// RuntimeDebugMethod reports whether a runtime/debug receiver's method is in
// the audited receiver-qualified set.
func RuntimeDebugMethod(receiver, method string) bool {
	return slices.Contains(runtimeDebugMethods[receiver], method)
}

// BoundedToken reports whether text begins with marker as a whole token
// — marker followed by end of text or by one of the bound bytes — and
// returns the remainder after the marker. A directive or token prefix
// matched this way can never be shadowed by a longer name sharing its
// prefix; each caller names the delimiter bytes its grammar allows.
func BoundedToken(text, marker, bounds string) (rest string, ok bool) {
	if !strings.HasPrefix(text, marker) {
		return "", false
	}
	rest = text[len(marker):]
	if rest == "" || strings.IndexByte(bounds, rest[0]) >= 0 {
		return rest, true
	}
	return "", false
}

// IsGeneratedMarker reports whether text is a standard Go generated-file marker
// line (`^// Code generated .* DO NOT EDIT\.$` over the line's trimmed text),
// retained in the canonical member token form.
func IsGeneratedMarker(text string) bool {
	trimmed := strings.TrimSpace(text)
	return strings.HasPrefix(trimmed, "// Code generated ") &&
		strings.HasSuffix(trimmed, " DO NOT EDIT.") &&
		len(trimmed) >= len("// Code generated  DO NOT EDIT.") &&
		!strings.ContainsAny(trimmed, "\r\n")
}

// nonRetainingStdPackages lists standard-library packages whose functions and
// methods never retain caller-supplied carrier values in package-scope state
// after initialization.
var nonRetainingStdPackages = map[string]bool{
	"bytes":           true,
	"cmp":             true,
	"encoding/binary": true,
	"errors":          true,
	"fmt":             true,
	"go/token":        true,
	"hash/fnv":        true,
	"io":              true,
	"math":            true,
	"math/bits":       true,
	"slices":          true,
	"sort":            true,
	"strconv":         true,
	"strings":         true,
	"unicode":         true,
	"unicode/utf16":   true,
	"unicode/utf8":    true,
}

var nonRetainingSyncReceivers = map[string]bool{
	"Mutex":   true,
	"Once":    true,
	"RWMutex": true,
}

var nonRetainingAtomicPrefixes = map[string]bool{
	"Load": true,
}

var nonRetainingAtomicFuncs = map[string]bool{
	"AddInt32":    true,
	"AddInt64":    true,
	"AddUint32":   true,
	"AddUint64":   true,
	"StoreInt32":  true,
	"StoreUint32": true,
}

var retainingReflectExcludedPrefixes = map[string]bool{
	"Make": true,
	"Set":  true,
}

var retainingReflectExcludedFuncs = map[string]bool{
	"Append":      true,
	"AppendSlice": true,
	"Call":        true,
	"CallSlice":   true,
	"Clear":       true,
	"Close":       true,
	"Copy":        true,
	"Grow":        true,
	"NewAt":       true,
	"Recv":        true,
	"Select":      true,
	"Send":        true,
	"SliceAt":     true,
	"Swapper":     true,
	"TryRecv":     true,
	"TrySend":     true,
}

// NonRetainingStdCallee reports whether standard-library function or method fn
// is audited not to write or retain caller-supplied dynamic-carrier arguments
// into standard-library package-scope state after initialization.
func NonRetainingStdCallee(fn *types.Func) bool {
	if fn == nil || fn.Pkg() == nil {
		return false
	}
	pkgPath := fn.Pkg().Path()
	if nonRetainingStdPackages[pkgPath] {
		return true
	}
	name := fn.Name()
	switch pkgPath {
	case "reflect":
		if retainingReflectExcludedFuncs[name] {
			return false
		}
		for prefix := range retainingReflectExcludedPrefixes {
			if strings.HasPrefix(name, prefix) {
				return false
			}
		}
		return true
	case "sync":
		return ReceiverMethod(fn, "sync", func(receiver, _ string) bool {
			return nonRetainingSyncReceivers[receiver]
		})
	case "sync/atomic":
		if nonRetainingAtomicFuncs[name] {
			return true
		}
		for prefix := range nonRetainingAtomicPrefixes {
			if strings.HasPrefix(name, prefix) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

var nonMutatingAtomicLoadFuncs = map[string]bool{
	"LoadInt32":   true,
	"LoadInt64":   true,
	"LoadUint32":  true,
	"LoadUint64":  true,
	"LoadUintptr": true,
}

var nonMutatingAtomicLoadReceivers = map[string]bool{
	"Bool":    true,
	"Int32":   true,
	"Int64":   true,
	"Pointer": true,
	"Uint32":  true,
	"Uint64":  true,
	"Uintptr": true,
}

var nonMutatingValuePackages = map[string]bool{
	"errors":        true,
	"go/token":      true,
	"math":          true,
	"math/bits":     true,
	"path":          true,
	"strconv":       true,
	"strings":       true,
	"unicode":       true,
	"unicode/utf16": true,
}

var nonMutatingExtraSliceFuncs = map[string][]string{
	"cmp":           {"Compare", "Less"},
	"reflect":       {"PointerTo", "PtrTo", "TypeFor", "TypeOf"},
	"strings":       {"Join"},
	"unicode/utf16": {"Decode", "Encode"},
}

var nonMutatingValueReceiverTypes = map[string][]string{
	"go/token": {"Pos", "Position", "Token"},
	"reflect":  {"ChanDir", "Kind", "StructTag"},
	"time":     {"Duration", "Month", "Time", "Weekday"},
}

var nonMutatingValueReceiverMethods = map[string][]string{
	"go/token": {"IsKeyword", "IsLiteral", "IsOperator", "IsValid", "Precedence", "String"},
	"reflect":  {"Get", "Lookup", "String"},
	"time": {
		"Abs", "Add", "AddDate", "After", "Before", "Clock", "Compare", "Day", "Equal",
		"Format", "Hours", "ISOWeek", "In", "IsZero", "Microseconds", "Milliseconds",
		"Minutes", "Nanoseconds", "Round", "Seconds", "String", "Sub", "Truncate",
		"UTC", "Unix", "UnixMicro", "UnixMilli", "UnixNano", "Year", "YearDay",
		"Zone", "ZoneBounds",
	},
}

func sigParamsValueOnly(sig *types.Signature) bool {
	if sig == nil {
		return false
	}
	seen := map[types.Type]bool{}
	ok := true
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil || !ok {
			return
		}
		t = types.Unalias(t)
		if seen[t] {
			return
		}
		seen[t] = true
		switch u := t.Underlying().(type) {
		case *types.Basic:
			if u.Kind() == types.UnsafePointer {
				ok = false
			}
		case *types.Array:
			walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				walk(u.Field(i).Type())
			}
		default:
			ok = false
		}
	}
	for i := 0; i < sig.Params().Len(); i++ {
		walk(sig.Params().At(i).Type())
		if !ok {
			return false
		}
	}
	return ok
}

// NonMutatingStdCallee reports whether standard-library function or method fn
// is audited to perform zero mutations on its receiver, its arguments (including
// spare slice capacity), and package-scope state.
func NonMutatingStdCallee(fn *types.Func) bool {
	if fn == nil || fn.Pkg() == nil {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		return false
	}
	pkgPath, name := fn.Pkg().Path(), fn.Name()
	if sig.Recv() != nil {
		if pkgPath == "sync/atomic" {
			return name == "Load" && ReceiverMethod(fn, "sync/atomic", func(receiver, _ string) bool {
				return nonMutatingAtomicLoadReceivers[receiver]
			})
		}
		if pkgPath == "reflect" && ReceiverMethod(fn, "reflect", ReflectMethod) {
			return true
		}
		rt := types.Unalias(sig.Recv().Type())
		if _, isPtr := rt.(*types.Pointer); isPtr {
			return false
		}
		named, isNamed := rt.(*types.Named)
		if !isNamed || named.Obj() == nil {
			return false
		}
		if !slices.Contains(nonMutatingValueReceiverTypes[pkgPath], named.Obj().Name()) {
			return false
		}
		if !slices.Contains(nonMutatingValueReceiverMethods[pkgPath], name) {
			return false
		}
		return sigParamsValueOnly(sig)
	}
	if pkgPath == "sync/atomic" {
		return nonMutatingAtomicLoadFuncs[name]
	}
	if slices.Contains(readOnlySliceInspectFuncs[pkgPath], name) ||
		slices.Contains(readOnlySliceCopyFuncs[pkgPath], name) ||
		ValuePlaneClone(pkgPath, name) ||
		slices.Contains(nonMutatingExtraSliceFuncs[pkgPath], name) {
		return true
	}
	if !nonMutatingValuePackages[pkgPath] {
		return false
	}
	switch pkgPath {
	case "errors":
		if name != "New" {
			return false
		}
	case "go/token":
		if name != "IsExported" && name != "IsIdentifier" && name != "IsKeyword" && name != "Lookup" {
			return false
		}
	case "math":
		if !MathPureFunc(name) {
			return false
		}
	}
	return sigParamsValueOnly(sig)
}
