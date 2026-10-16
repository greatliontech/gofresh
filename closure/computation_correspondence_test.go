package closure

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
)

func correspondenceFace(arguments, results []computationScalarLocation) nativeproof.Interface {
	face := nativeproof.Interface{Conditions: nativeproof.Conditions{Machine: nativeproof.MachineModel,
		InstructionMapping: true, ReturnSlot: true, EntryInputs: true, IsolatedInvocation: true}}
	face.Preserved[nativeproof.RBP], face.Preserved[nativeproof.R14] = ^uint64(0), ^uint64(0)
	for _, x := range arguments {
		face.Inputs[x.register] |= (^uint64(0) >> (64 - x.width)) << x.offset
	}
	for _, x := range results {
		face.Results[x.register] |= (^uint64(0) >> (64 - x.width)) << x.offset
	}
	return face
}

// Tiny symbol-free executable mapping for composition boundary controls only.
// The integration below derives its values from the actual package-test image.
func correspondenceImage(t *testing.T, code string) *nativeproof.Image {
	t.Helper()
	instructions, err := hex.DecodeString(code)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 4096+len(instructions))
	copy(data, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	u16 := func(at int, v uint16) { binary.LittleEndian.PutUint16(data[at:], v) }
	u32 := func(at int, v uint32) { binary.LittleEndian.PutUint32(data[at:], v) }
	u64 := func(at int, v uint64) { binary.LittleEndian.PutUint64(data[at:], v) }
	u16(16, 2)
	u16(18, 62)
	u32(20, 1)
	u64(24, 0x401000)
	u64(32, 64)
	u16(52, 64)
	u16(54, 56)
	u16(56, 1)
	u32(64, 1)
	u32(68, 5)
	u64(72, 4096)
	u64(80, 0x401000)
	u64(96, uint64(len(instructions)))
	u64(104, uint64(len(instructions)))
	u64(112, 4096)
	copy(data[4096:], instructions)
	image, err := nativeproof.NewImage(t.Context(), data)
	if err != nil {
		t.Fatal(err)
	}
	return image
}

func requireCorrespondenceWitnesses(t *testing.T, c *computationCorrespondence, count int) {
	t.Helper()
	if c == nil || c.source == nil {
		t.Fatal("missing correspondence or source relation")
	}
	native := c.native.Results()
	if len(c.equalities) != count || len(c.source.outputs) != count || len(c.source.root.results) != count || len(c.results) != count || len(native) != count {
		t.Fatalf("result/witness arity: witnesses=%d source=%d types=%d mapping=%d native=%d want=%d", len(c.equalities), len(c.source.outputs), len(c.source.root.results), len(c.results), len(native), count)
	}
	for i, witness := range c.equalities {
		if !witness.Valid() {
			t.Fatalf("result %d has no checked equality", i)
		}
		left, right := witness.Roots()
		output := c.source.outputs[i]
		if output.Sort() != c.source.root.results[i].sort {
			t.Fatalf("result %d lost its selected source type", i)
		}
		if output.Sort().IsBool() {
			view := left.View()
			if view.Op != bitrelation.BoolToBits || view.Sort != bitrelation.Bits(8) || view.Immediate != 0 || len(view.Args) != 1 || view.Args[0] != output {
				t.Fatalf("result %d witness does not bind the exact canonical-byte source projection", i)
			}
		} else if left != output {
			t.Fatalf("result %d witness substituted the selected source output", i)
		}
		location := c.results[i]
		if right != native[i].Value || native[i].Register != location.register || native[i].Offset != location.offset || right.Sort() != bitrelation.Bits(location.width) {
			t.Fatalf("result %d witness does not bind the exact retained native projection", i)
		}
	}
}

func TestComputationCorrespondenceComposition(t *testing.T) {
	u64 := computationScalarLocation{nativeproof.RAX, 0, 64}
	y64 := computationScalarLocation{nativeproof.RBX, 0, 64}
	u32 := computationScalarLocation{nativeproof.RAX, 0, 32}
	b8 := computationScalarLocation{nativeproof.RAX, 0, 8}
	for _, tc := range []struct {
		name, source, code string
		args, results      []computationScalarLocation
	}{
		{"add", "func F(x,y uint64)uint64{return x+y}", "4801d8c3", []computationScalarLocation{u64, y64}, []computationScalarLocation{u64}},
		{"signed-bits", "func F(x rune)rune{return x}", "c3", []computationScalarLocation{u32}, []computationScalarLocation{u32}},
		{"canonical-bool", "func F(x bool)bool{return x}", "c3", []computationScalarLocation{b8}, []computationScalarLocation{b8}},
		{"two-results", "func F(x,y uint64)(uint64,uint64){return x,y}", "c3", []computationScalarLocation{u64, y64}, []computationScalarLocation{u64, y64}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := relationFixture(t, tc.source, 64)
			c, err := deriveComputationCorrespondence(t.Context(), s, s.prog.Roots["F"], correspondenceImage(t, tc.code), 0x401000, correspondenceFace(tc.args, tc.results), tc.args, tc.results)
			if err != nil {
				t.Fatal(err)
			}
			if c.source.owner != s.prog || len(c.source.dependencies) == 0 || c.rules == "" || c.open != (computationCorrespondenceObligations{true, true, true, true, true}) {
				t.Fatal("lost dependency or open obligation")
			}
			requireCorrespondenceWitnesses(t, c, len(tc.results))
			if bound, ok := c.native.Bound(); !ok || len(bound.Instructions) == 0 {
				t.Fatal("missing effect/frame evidence")
			}
		})
	}
}

func TestComputationCorrespondenceRefusals(t *testing.T) {
	x := computationScalarLocation{nativeproof.RAX, 0, 64}
	y := computationScalarLocation{nativeproof.RBX, 0, 64}
	args, results := []computationScalarLocation{x, y}, []computationScalarLocation{x}
	face := correspondenceFace(args, results)
	s := relationFixture(t, "func F(x,y uint64)uint64{return x}", 64)
	good := correspondenceImage(t, "c3")
	wrong := correspondenceImage(t, "4801d8c3")
	// A genuine effect certificate for a wrong pure body must not prove equality.
	proposal, err := nativeproof.Propose(t.Context(), wrong, 0x401000, face)
	if err != nil {
		t.Fatal(err)
	}
	effect, err := nativeproof.Check(t.Context(), wrong, 0x401000, face, proposal)
	if _, ok := effect.Bound(); err != nil || !ok {
		t.Fatalf("wrong pure effect theorem: %v", err)
	}
	other := relationFixture(t, "func F(x,y uint64)uint64{return x}", 64)
	for _, tc := range []struct {
		name          string
		root          *ssa.Function
		image         *nativeproof.Image
		args, results []computationScalarLocation
		face          nativeproof.Interface
		want          string
	}{
		{"wrong-pure-body", s.prog.Roots["F"], wrong, args, results, face, "equality"},
		{"swapped-arguments", s.prog.Roots["F"], good, []computationScalarLocation{y, x}, results, face, "equality"},
		{"foreign-owner", other.prog.Roots["F"], good, args, results, face, "owned"},
		{"missing-image", s.prog.Roots["F"], nil, args, results, face, "image"},
		{"wrong-width", s.prog.Roots["F"], good, args, []computationScalarLocation{{nativeproof.RAX, 0, 32}}, face, "width"},
		{"wrong-offset", s.prog.Roots["F"], good, args, []computationScalarLocation{{nativeproof.RAX, 1, 64}}, face, "interval"},
		{"wrong-register", s.prog.Roots["F"], good, args, []computationScalarLocation{y}, face, "mapping"},
		{"discarded-native-load", s.prog.Roots["F"], correspondenceImage(t, "488b0bc3"), args, results, face, "data-memory"},
		{"clobbered-frame", s.prog.Roots["F"], correspondenceImage(t, "4889c5c3"), args, results, face, "preserv"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := deriveComputationCorrespondence(t.Context(), s, tc.root, tc.image, 0x401000, tc.face, tc.args, tc.results)
			if c != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("certificate=%v error=%v", c, err)
			}
		})
	}
	t.Run("missing-second-result", func(t *testing.T) {
		pair := relationFixture(t, "func F(x,y uint64)(uint64,uint64){return x,y}", 64)
		if c, err := deriveComputationCorrespondence(t.Context(), pair, pair.prog.Roots["F"], good, 0x401000, face, args, results); c != nil || err == nil || !strings.Contains(err.Error(), "arity") {
			t.Fatalf("%v %v", c, err)
		}
	})
	t.Run("wrong-second-result", func(t *testing.T) {
		pair := relationFixture(t, "func F(x,y uint64)(uint64,uint64){return x,y}", 64)
		complete := []computationScalarLocation{x, y}
		// XOR EBX,EBX; RET preserves the correct first result while replacing
		// only the second result with zero. Both exact interface maps are complete.
		c, err := deriveComputationCorrespondence(t.Context(), pair, pair.prog.Roots["F"], correspondenceImage(t, "31dbc3"), 0x401000, correspondenceFace(complete, complete), complete, complete)
		var refusal *computationCorrespondenceEqualityRefusal
		if c != nil || !errors.As(err, &refusal) || refusal.result != 1 {
			t.Fatalf("wrong second result must fail its equality: certificate=%v error=%v", c, err)
		}
	})
	t.Run("result-order", func(t *testing.T) {
		pair := relationFixture(t, "func F(x,y uint64)(uint64,uint64){return x,y}", 64)
		ordered := []computationScalarLocation{x, y}
		if c, err := deriveComputationCorrespondence(t.Context(), pair, pair.prog.Roots["F"], good, 0x401000, correspondenceFace(args, ordered), args, []computationScalarLocation{y, x}); c != nil || err == nil || !strings.Contains(err.Error(), "order") {
			t.Fatalf("%v %v", c, err)
		}
	})
	t.Run("discarded-source-effect", func(t *testing.T) {
		effectful := relationFixture(t, "var state uint64\nfunc hook(){state++}\nfunc F(x,y uint64)uint64{hook();return x-y}", 64)
		if c, err := deriveComputationCorrespondence(t.Context(), effectful, effectful.prog.Roots["F"], good, 0x401000, face, args, results); c != nil || err == nil || !strings.Contains(err.Error(), "source") {
			t.Fatalf("%v %v", c, err)
		}
	})
	t.Run("noncanonical-bool-result", func(t *testing.T) {
		boolean := relationFixture(t, "func F(x bool)bool{return x}", 64)
		loc := []computationScalarLocation{{nativeproof.RAX, 0, 8}}
		if c, err := deriveComputationCorrespondence(t.Context(), boolean, boolean.prog.Roots["F"], correspondenceImage(t, "b002c3"), 0x401000, correspondenceFace(loc, loc), loc, loc); c != nil || err == nil || !strings.Contains(err.Error(), "equality") {
			t.Fatalf("%v %v", c, err)
		}
	})
	t.Run("typed-projection", func(t *testing.T) {
		b := bitrelation.NewBuilder(0)
		value, _ := b.Const(bitrelation.Bits(64), 0)
		for _, sort := range []bitrelation.Sort{bitrelation.Bool(), bitrelation.Bits(32)} {
			if _, err := correspondenceStorage(b, computationRelationType{sort: sort}, value); err == nil {
				t.Fatal("source metadata permitted a silent narrowing or Boolean reinterpretation")
			}
		}
	})
	t.Run("changed-proof-endpoint", func(t *testing.T) {
		c, err := deriveComputationCorrespondence(t.Context(), s, s.prog.Roots["F"], good, 0x401000, face, args, results)
		if err != nil {
			t.Fatal(err)
		}
		left, right := c.equalities[0].Roots()
		proof, err := bitrelation.Propose(t.Context(), left, right, bitrelation.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		zero, _ := bitrelation.NewBuilder(0).Const(bitrelation.Bits(64), 0)
		if w, err := bitrelation.Check(t.Context(), zero, right, proof, bitrelation.Limits{}); w.Valid() || err == nil {
			t.Fatal("substituted endpoint accepted")
		}
	})
}

type correspondenceCallbackContext struct {
	context.Context
	mutate func()
}

func (c *correspondenceCallbackContext) Err() error {
	if f := c.mutate; f != nil {
		c.mutate = nil
		f()
	}
	return c.Context.Err()
}

func TestComputationCorrespondenceOwnsInputs(t *testing.T) {
	s := relationFixture(t, "func F(x,y uint64)uint64{return x+y}", 64)
	args := []computationScalarLocation{{nativeproof.RAX, 0, 64}, {nativeproof.RBX, 0, 64}}
	results := []computationScalarLocation{{nativeproof.RAX, 0, 64}}
	face := correspondenceFace(args, results)
	image := correspondenceImage(t, "4801d8c3")
	ctx := &correspondenceCallbackContext{Context: t.Context(), mutate: func() {
		*image = nativeproof.Image{}
		args[0] = computationScalarLocation{}
		results[0] = computationScalarLocation{}
	}}
	c, err := deriveComputationCorrespondence(ctx, s, s.prog.Roots["F"], image, 0x401000, face, args, results)
	if err != nil {
		t.Fatal(err)
	}
	if c.arguments[0].width != 64 || c.results[0].width != 64 {
		t.Fatal("caller mapping aliases certificate")
	}
	bound, _ := c.native.Bound()
	bound.Instructions[0] = nativeproof.Span{}
	outputs := c.native.Results()
	outputs[0].Value = bitrelation.Term{}
	inputs := c.native.Inputs()
	inputs[0].Value = bitrelation.Term{}
	view := c.source.outputs[0].View()
	view.Args[0] = bitrelation.Term{}
	retainedBound, ok := c.native.Bound()
	if !ok || retainedBound.Instructions[0].Start != 0x401000 || !c.native.Results()[0].Value.Valid() || !c.native.Inputs()[0].Value.Valid() || !c.source.outputs[0].View().Args[0].Valid() {
		t.Fatal("mutable projection damaged retained subordinate evidence")
	}
	left, right := c.equalities[0].Roots()
	if w, err := bitrelation.Prove(t.Context(), left, right, bitrelation.Limits{}); err != nil || !w.Valid() {
		t.Fatalf("mutable projection damaged certificate: %v", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if c, err := deriveComputationCorrespondence(cancelled, s, s.prog.Roots["F"], correspondenceImage(t, "4801d8c3"), 0x401000, face, c.arguments, c.results); c != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v %v", c, err)
	}
}

const correspondencePackageSource = `package kernels
import("unicode/utf16";"math/bits")
func Add(x,y uint64)uint64{return x+y}
func First(x,y uint64)uint64{return x}
func Wrong(x,y uint64)uint64{return x^y}
func Branch(x,y uint64)uint64{if x<y{return x+y};return x^y}
func Normalize(r rune)rune{if r<0||r>0x10ffff||utf16.IsSurrogate(r){return 0xfffd};return r}
func Pair(x,y uint64)(uint64,bool){s:=x+y;return s,s<x}
func Boolean(x bool)bool{return x}
func Count(x uint64)int{return bits.OnesCount64(x)}
var state uint64
func Discarded(x,y uint64)uint64{state++;return x+y}
`
const correspondencePackageTest = `package kernels
import("testing";"unicode/utf16")
var binary=map[string]func(uint64,uint64)uint64{"add":Add,"first":First,"wrong":Wrong,"branch":Branch,"discarded":Discarded}
var normalizers=map[string]func(rune)rune{"normalize":Normalize}
var predicates=map[string]func(rune)bool{"surrogate":utf16.IsSurrogate}
var pairs=map[string]func(uint64,uint64)(uint64,bool){"pair":Pair}
var booleans=map[string]func(bool)bool{"boolean":Boolean}
var counts=map[string]func(uint64)int{"count":Count}
func TestSelected(t *testing.T){
 for name,f:=range binary{t.Log(name,f(3,5))}
 for name,f:=range normalizers{t.Log(name,f(0xd800))}
 for name,f:=range predicates{t.Log(name,f(0xd800))}
 for name,f:=range pairs{a,b:=f(3,5);t.Log(name,a,b)}
 for name,f:=range booleans{t.Log(name,f(true))}
 for name,f:=range counts{t.Log(name,f(17))}
}
`

func TestComputationCorrespondenceSelectedPackageArtifact(t *testing.T) {
	if testing.Short() {
		t.Skip("loads and builds the actual default-optimized package-test selection")
	}
	const pkg = "example.com/correspondence"
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"go.mod": "module " + pkg + "\n\ngo 1.27\n", "p.go": correspondencePackageSource, "p_test.go": correspondencePackageTest})
	// This is an explicitly selected linux/amd64 baseline fixture, not a claim
	// about the host. Keep ambient CGO and requested flags: unsupported image
	// formats or instrumentation must refuse rather than silently changing them.
	env := os.Environ()
	for key, value := range map[string]string{"GOOS": "linux", "GOARCH": "amd64", "GOAMD64": "v1", "GOWORK": "off"} {
		env = gotool.SetEnv(env, key, value)
	}
	h, err := newAtEnv(t.Context(), dir, env)
	if err != nil {
		t.Fatal(err)
	}
	loader := newFixturePrograms(t, h)
	loader.supply(t, pkg)
	metas, err := h.list(pkg)
	if err != nil {
		t.Fatal(err)
	}
	source := computationSource{prog: loader.loaded, metas: metas}
	mainFound, variantFound := false, false
	for _, p := range source.prog.Pkgs {
		mainFound = mainFound || p.PkgPath == pkg+".test" && source.prog.Prog.Package(p.Types).Func("main") != nil
		variantFound = variantFound || p.ForTest == pkg && p.Types == source.prog.Roots["Add"].Pkg.Pkg
	}
	if !mainFound || !variantFound {
		t.Fatalf("actual test main=%v source test variant=%v", mainFound, variantFound)
	}
	artifact := filepath.Join(dir, "package.test")
	command := append([]string{"test", "-c", "-o", artifact}, h.buildFlags...)
	command = append(command, ".")
	if _, err := (gotool.Runner{}).Run(t.Context(), dir, h.packageEnv, command...); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	image, err := nativeproof.NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	file, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	syms, err := file.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	entries := map[string]uint64{}
	// Candidate entry discovery only: no symbol sizes enter any proof.
	for _, symbol := range syms {
		entries[symbol.Name] = symbol.Value
	}
	entry := func(name string) uint64 {
		t.Helper()
		v := entries[name]
		if v == 0 {
			t.Fatalf("runtime table did not retain %s", name)
		}
		return v
	}
	u64 := computationScalarLocation{nativeproof.RAX, 0, 64}
	y64 := computationScalarLocation{nativeproof.RBX, 0, 64}
	u32 := computationScalarLocation{nativeproof.RAX, 0, 32}
	b8 := computationScalarLocation{nativeproof.RAX, 0, 8}
	args := []computationScalarLocation{u64, y64}
	result := []computationScalarLocation{u64}
	var surrogate *ssa.Function
	for _, p := range source.prog.Pkgs {
		if p.PkgPath == "unicode/utf16" {
			surrogate = source.prog.Prog.Package(p.Types).Func("IsSurrogate")
		}
	}
	if surrogate == nil {
		t.Fatal("selected stdlib root absent")
	}
	for _, tc := range []struct {
		name          string
		root          *ssa.Function
		symbol        string
		args, results []computationScalarLocation
	}{
		{"Add", source.prog.Roots["Add"], pkg + ".Add", args, result},
		{"First", source.prog.Roots["First"], pkg + ".First", args, result},
		{"Branch", source.prog.Roots["Branch"], pkg + ".Branch", args, result},
		{"Normalize", source.prog.Roots["Normalize"], pkg + ".Normalize", []computationScalarLocation{u32}, []computationScalarLocation{u32}},
		{"IsSurrogate", surrogate, "unicode/utf16.IsSurrogate", []computationScalarLocation{u32}, []computationScalarLocation{b8}},
		{"Pair", source.prog.Roots["Pair"], pkg + ".Pair", args, []computationScalarLocation{u64, {nativeproof.RBX, 0, 8}}},
		{"Boolean", source.prog.Roots["Boolean"], pkg + ".Boolean", []computationScalarLocation{b8}, []computationScalarLocation{b8}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := deriveComputationCorrespondence(t.Context(), source, tc.root, image, entry(tc.symbol), correspondenceFace(tc.args, tc.results), tc.args, tc.results)
			if err != nil {
				var refusal *computationCorrespondenceEqualityRefusal
				if errors.As(err, &refusal) {
					t.Logf("independent equality endpoints:\n%s", correspondenceExpressionPair(refusal.source, refusal.native))
				}
				t.Fatal(err)
			}
			bound, ok := c.native.Bound()
			if !ok || bound.ImageDigest != sha256.Sum256(raw) || c.source.owner != source.prog {
				t.Fatal("lost selected inputs")
			}
			if !c.open.sourceArtifactSpan || !c.open.actualUse || !c.open.harness {
				t.Fatal("subordinate relation acquired runtime authority")
			}
			requireCorrespondenceWitnesses(t, c, len(tc.results))
			t.Logf("checked source=%s native=%#x instructions=%d results=%d", c.source.root.function, bound.Entry, len(bound.Instructions), len(c.equalities))
		})
	}
	t.Run("wrong-pure-kernel", func(t *testing.T) {
		face := correspondenceFace(args, result)
		proposal, err := nativeproof.Propose(t.Context(), image, entry(pkg+".Wrong"), face)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := nativeproof.Check(t.Context(), image, entry(pkg+".Wrong"), face, proposal); err != nil {
			t.Fatal(err)
		}
		if c, err := deriveComputationCorrespondence(t.Context(), source, source.prog.Roots["Add"], image, entry(pkg+".Wrong"), face, args, result); c != nil || err == nil || !strings.Contains(err.Error(), "equality") {
			t.Fatalf("%v %v", c, err)
		}
	})
	t.Run("original-cpu-dispatch", func(t *testing.T) {
		face := correspondenceFace([]computationScalarLocation{u64}, result)
		if _, err := nativeproof.Propose(t.Context(), image, entry(pkg+".Count"), face); err == nil {
			t.Fatal("original stack/runtime/CPU dispatch accepted")
		}
	})
	t.Run("discarded-effect", func(t *testing.T) {
		if c, err := deriveComputationCorrespondence(t.Context(), source, source.prog.Roots["Discarded"], image, entry(pkg+".Add"), correspondenceFace(args, result), args, result); c != nil || err == nil || !strings.Contains(err.Error(), "source") {
			t.Fatalf("%v %v", c, err)
		}
	})
	// This reread detects persistent artifact motion only. It is not a public
	// snapshot close and does not authenticate common source/build provenance.
	end, err := os.ReadFile(artifact)
	if err != nil || !bytes.Equal(raw, end) {
		t.Fatalf("artifact changed: %v", err)
	}
}

// Shared node numbers make missing rewrites diagnosable without sampling values
// or replacing either independently derived endpoint with a desired expression.
func correspondenceExpressionPair(source, native bitrelation.Term) string {
	names := []string{"invalid", "const", "variable", "not", "and", "or", "ite", "eq", "ult", "ule", "slt", "sle", "add", "sub", "bitand", "bitor", "bitxor", "bitnot", "shl", "lshr", "ashr", "trunc", "zext", "sext", "concat", "extract", "boolbits", "nonzero"}
	seen := map[bitrelation.Term]int{}
	var lines strings.Builder
	var visit func(bitrelation.Term) int
	visit = func(term bitrelation.Term) int {
		if n := seen[term]; n != 0 {
			return n
		}
		view := term.View()
		var args []int
		for _, arg := range view.Args {
			args = append(args, visit(arg))
		}
		n := len(seen) + 1
		seen[term] = n
		fmt.Fprintf(&lines, "%d: %s sort=%v imm=%d scratch=%v args=%v\n", n, names[int(view.Op)], view.Sort, view.Immediate, view.Scratch, args)
		return n
	}
	left, right := visit(source), visit(native)
	fmt.Fprintf(&lines, "source=%d native=%d", left, right)
	return lines.String()
}
