package refconfine_test

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
	"pgregory.net/rapid"
)

func mustTypecheckLockPkg(t testing.TB, src string) (*packages.Package, *refconfine.PkgIndex) {
	t.Helper()
	pkg, idx, ok := tryTypecheckLockPkg(src)
	if !ok {
		t.Fatalf("failed to parse/typecheck source:\n%s", src)
	}
	return pkg, idx
}

func tryTypecheckLockPkg(src string) (*packages.Package, *refconfine.PkgIndex, bool) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "lock.go", src, parser.ParseComments)
	if err != nil {
		return nil, nil, false
	}
	info := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Instances:  make(map[*ast.Ident]types.Instance),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Implicits:  make(map[ast.Node]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
		Scopes:     make(map[ast.Node]*types.Scope),
	}
	tpkg, err := (&types.Config{Importer: importer.Default()}).Check("example.com/locktest", fset, []*ast.File{file}, info)
	if err != nil {
		return nil, nil, false
	}
	pkg := &packages.Package{
		ID:        "example.com/locktest",
		PkgPath:   "example.com/locktest",
		Name:      tpkg.Name(),
		Fset:      fset,
		Syntax:    []*ast.File{file},
		Types:     tpkg,
		TypesInfo: info,
		Module:    &packages.Module{Path: "example.com/locktest"},
	}
	return pkg, refconfine.BuildPkgIndex(pkg), true
}

func TestVerifyBodyLockRegionsAndMutexMapMatrix(t *testing.T) {
	t.Run("BodyLockRegions", func(t *testing.T) {
		cases := []struct {
			name     string
			isRecv   bool
			rw       bool
			funcName string
			src      string
			wantOK   bool
		}{
			{
				name:     "global_mutex_defer_unlock_early_and_fallthrough_return",
				rw:       false,
				funcName: "Do",
				src: `package locktest
import "sync"
var mu sync.Mutex
var count int
func Do(cond bool) int {
	mu.Lock()
	defer mu.Unlock()
	if cond {
		return count
	}
	count++
	return count
}`,
				wantOK: true,
			},
			{
				name:     "global_rwmutex_double_checked_locking_branch_unlocks",
				rw:       true,
				funcName: "Get",
				src: `package locktest
import "sync"
var mu sync.RWMutex
var val int
func Get(hit bool) int {
	mu.RLock()
	if hit {
		mu.RUnlock()
		return 1
	}
	mu.RUnlock()
	computed := 42
	mu.Lock()
	if val != 0 {
		mu.Unlock()
		return val
	}
	val = computed
	mu.Unlock()
	return val
}`,
				wantOK: true,
			},
			{
				name:     "global_mutex_switch_with_default_balanced_unlocks",
				rw:       false,
				funcName: "Step",
				src: `package locktest
import "sync"
var mu sync.Mutex
func Step(k int) int {
	mu.Lock()
	switch k {
	case 0:
		mu.Unlock()
		return 0
	case 1:
		mu.Unlock()
	default:
		mu.Unlock()
	}
	return 1
}`,
				wantOK: true,
			},
			{
				name:     "global_mutex_type_switch_and_loop_invariant_held",
				rw:       false,
				funcName: "Run",
				src: `package locktest
import "sync"
var mu sync.Mutex
func Run(x any, xs []int) int {
	mu.Lock()
	sum := 0
	for _, v := range xs {
		sum += v
	}
	for i := 0; i < 3; i++ {
		sum += i
	}
	switch v := x.(type) {
	case int:
		sum += v
	default:
		sum++
	}
	mu.Unlock()
	return sum
}`,
				wantOK: true,
			},
			{
				name:     "panic_allowed_when_unlocked_or_deferred",
				rw:       false,
				funcName: "Guard",
				src: `package locktest
import "sync"
var mu sync.Mutex
func Guard(bad, worse bool) {
	if bad {
		panic("pre-lock")
	}
	mu.Lock()
	defer mu.Unlock()
	if worse {
		panic("under-defer")
	}
}`,
				wantOK: true,
			},
			{
				name:     "recv_embedded_two_hop_mutex_field",
				isRecv:   true,
				rw:       false,
				funcName: "Act",
				src: `package locktest
import "sync"
type inner struct {
	sync.Mutex
	n int
}
type outer struct {
	inner
}
func (o *outer) Act(flag bool) int {
	o.Lock()
	if flag {
		o.Unlock()
		return 0
	}
	o.n++
	v := o.n
	o.Unlock()
	return v
}`,
				wantOK: true,
			},
			{
				name:     "reject_early_return_while_non_deferred_lock_held",
				rw:       false,
				funcName: "Leak",
				src: `package locktest
import "sync"
var mu sync.Mutex
func Leak(cond bool) int {
	mu.Lock()
	if cond {
		return 1
	}
	mu.Unlock()
	return 0
}`,
				wantOK: false,
			},
			{
				name:     "reject_if_branch_lock_mode_mismatch",
				rw:       false,
				funcName: "Mismatch",
				src: `package locktest
import "sync"
var mu sync.Mutex
func Mismatch(cond bool) {
	mu.Lock()
	if cond {
		mu.Unlock()
	}
	mu.Unlock()
}`,
				wantOK: false,
			},
			{
				name:     "reject_switch_missing_default_unlock_mismatch",
				rw:       false,
				funcName: "BadSwitch",
				src: `package locktest
import "sync"
var mu sync.Mutex
func BadSwitch(k int) {
	mu.Lock()
	switch k {
	case 1:
		mu.Unlock()
	}
}`,
				wantOK: false,
			},
			{
				name:     "reject_switch_break_with_mismatched_mode",
				rw:       false,
				funcName: "BadBreak",
				src: `package locktest
import "sync"
var mu sync.Mutex
func BadBreak(k int, early bool) {
	mu.Lock()
	switch k {
	case 1:
		if early {
			break
		}
		mu.Unlock()
	default:
		mu.Unlock()
	}
}`,
				wantOK: false,
			},
			{
				name:     "reject_double_lock",
				rw:       false,
				funcName: "Double",
				src: `package locktest
import "sync"
var mu sync.Mutex
func Double() {
	mu.Lock()
	mu.Lock()
	mu.Unlock()
}`,
				wantOK: false,
			},
			{
				name:     "reject_runlock_on_write_lock",
				rw:       true,
				funcName: "CrossUnlock",
				src: `package locktest
import "sync"
var mu sync.RWMutex
func CrossUnlock() {
	mu.Lock()
	mu.RUnlock()
}`,
				wantOK: false,
			},
			{
				name:     "reject_lock_transition_inside_loop",
				rw:       false,
				funcName: "LoopLock",
				src: `package locktest
import "sync"
var mu sync.Mutex
func LoopLock() {
	for i := 0; i < 2; i++ {
		mu.Lock()
		mu.Unlock()
	}
}`,
				wantOK: false,
			},
			{
				name:     "reject_panic_while_non_deferred_lock_held",
				rw:       false,
				funcName: "PanicHeld",
				src: `package locktest
import "sync"
var mu sync.Mutex
func PanicHeld(bad bool) {
	mu.Lock()
	if bad {
		panic("wedged")
	}
	mu.Unlock()
}`,
				wantOK: false,
			},
			{
				name:     "reject_goto_statement",
				rw:       false,
				funcName: "WithGoto",
				src: `package locktest
import "sync"
var mu sync.Mutex
func WithGoto() {
	mu.Lock()
	goto out
out:
	mu.Unlock()
}`,
				wantOK: false,
			},
			{
				name:     "reject_mutex_addr_or_closure_capture",
				rw:       false,
				funcName: "Capture",
				src: `package locktest
import "sync"
var mu sync.Mutex
func Capture() {
	mu.Lock()
	f := func() { mu.Unlock() }
	_ = f
	mu.Unlock()
}`,
				wantOK: false,
			},
			{
				name:     "reject_whole_recv_deref_copying_embedded_mutex",
				isRecv:   true,
				rw:       false,
				funcName: "CopyRecv",
				src: `package locktest
import "sync"
type holder struct {
	sync.Mutex
	n int
}
func (h *holder) CopyRecv() holder {
	h.Lock()
	cp := *h
	h.Unlock()
	return cp
}`,
				wantOK: false,
			},
			{
				name:     "reject_bound_mutex_method_value",
				isRecv:   true,
				rw:       false,
				funcName: "BindLock",
				src: `package locktest
import "sync"
type holder struct {
	sync.Mutex
}
func (h *holder) BindLock() func() {
	h.Lock()
	fn := h.Unlock
	h.Unlock()
	return fn
}`,
				wantOK: false,
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				pkg, idx := mustTypecheckLockPkg(t, tc.src)
				fc := idx.FlowCache(pkg)
				var targetFD *ast.FuncDecl
				for _, fd := range fc.FuncDecls {
					if fd.Name != nil && fd.Name.Name == tc.funcName {
						targetFD = fd
						break
					}
				}
				if targetFD == nil {
					t.Fatalf("missing FuncDecl %s", tc.funcName)
				}
				body := fc.FuncBody(targetFD)
				var target refconfine.LockTarget
				if tc.isRecv {
					var lockField *types.Var
					ptr := types.Unalias(body.Recv.Type()).(*types.Pointer)
					st := ptr.Elem().Underlying().(*types.Struct)
					for i := 0; i < st.NumFields(); i++ {
						f := st.Field(i)
						if syntaxutil.IsNamedInPkg(f.Type(), "sync", "Mutex") {
							lockField = f
							break
						}
						if subSt, ok := f.Type().Underlying().(*types.Struct); ok {
							for j := 0; j < subSt.NumFields(); j++ {
								if sf := subSt.Field(j); syntaxutil.IsNamedInPkg(sf.Type(), "sync", "Mutex") {
									lockField = sf
									break
								}
							}
						}
					}
					target = refconfine.LockTarget{
						Kind:      refconfine.LockRecvField,
						RecvVar:   body.Recv,
						LockField: lockField,
						IsRWMutex: tc.rw,
					}
				} else {
					muVar := pkg.Types.Scope().Lookup("mu").(*types.Var)
					target = refconfine.LockTarget{
						Kind:      refconfine.LockPkgGlobalVar,
						MutexVar:  muVar,
						IsRWMutex: tc.rw,
					}
				}
				_, gotOK := refconfine.VerifyBodyLockRegions(pkg, idx, body, target)
				if gotOK != tc.wantOK {
					t.Fatalf("VerifyBodyLockRegions() = %v, want %v", gotOK, tc.wantOK)
				}
			})
		}
	})

	t.Run("MutexConfinedMap", func(t *testing.T) {
		cases := []struct {
			name   string
			cfg    refconfine.MutexMapConfig
			src    string
			wantOK bool
		}{
			{
				name: "lazy_nil_init_and_write_locked_exclusive_helper",
				cfg: refconfine.MutexMapConfig{
					AllowNilLazyInit:     true,
					AllowIntraPkgHelpers: true,
					KeyPred:              syntaxutil.IsReflectType,
				},
				src: `package locktest
import (
	"reflect"
	"sync"
)
type entry struct{ n int }
var (
	mu    sync.RWMutex
	cache map[reflect.Type]*entry
)
func populate(t reflect.Type) *entry {
	if cache == nil {
		cache = make(map[reflect.Type]*entry)
	}
	e := &entry{n: t.Bits()}
	cache[t] = e
	return e
}
func Lookup(t reflect.Type) *entry {
	mu.RLock()
	if e, ok := cache[t]; ok {
		mu.RUnlock()
		return e
	}
	mu.RUnlock()
	mu.Lock()
	defer mu.Unlock()
	if e, ok := cache[t]; ok {
		return e
	}
	return populate(t)
}`,
				wantOK: true,
			},
			{
				name: "reject_direct_map_store_under_read_lock",
				cfg: refconfine.MutexMapConfig{
					AllowNilLazyInit:     false,
					AllowIntraPkgHelpers: false,
					RequireEntryParamKey: true,
					RequireAtLeastOneSet: true,
					KeyPred:              syntaxutil.IsReflectType,
				},
				src: `package locktest
import (
	"reflect"
	"sync"
)
type entry struct{ n int }
var (
	mu    sync.RWMutex
	cache = map[reflect.Type]*entry{}
)
func Lookup(t reflect.Type) *entry {
	mu.RLock()
	defer mu.RUnlock()
	if e, ok := cache[t]; ok {
		return e
	}
	built := &entry{n: 1}
	cache[t] = built
	return built
}`,
				wantOK: false,
			},
			{
				name: "reject_helper_called_under_read_lock",
				cfg: refconfine.MutexMapConfig{
					AllowNilLazyInit:     true,
					AllowIntraPkgHelpers: true,
					KeyPred:              syntaxutil.IsReflectType,
				},
				src: `package locktest
import (
	"reflect"
	"sync"
)
type entry struct{ n int }
var (
	mu    sync.RWMutex
	cache = map[reflect.Type]*entry{}
)
func populate(t reflect.Type) *entry {
	e := &entry{n: 1}
	cache[t] = e
	return e
}
func Lookup(t reflect.Type) *entry {
	mu.RLock()
	defer mu.RUnlock()
	return populate(t)
}`,
				wantOK: false,
			},
			{
				name: "reject_looked_up_entry_mutated_via_bare_alias",
				cfg: refconfine.MutexMapConfig{
					AllowNilLazyInit:     false,
					AllowIntraPkgHelpers: false,
					RequireEntryParamKey: true,
					RequireAtLeastOneSet: true,
					KeyPred:              syntaxutil.IsReflectType,
				},
				src: `package locktest
import (
	"reflect"
	"sync"
)
type entry struct{ n int }
var (
	mu    sync.Mutex
	cache = make(map[reflect.Type]*entry)
)
func Lookup(t reflect.Type) *entry {
	mu.Lock()
	defer mu.Unlock()
	if e, ok := cache[t]; ok {
		alias := e
		alias.n = 99
		return alias
	}
	built := &entry{n: 1}
	cache[t] = built
	return built
}`,
				wantOK: false,
			},
			{
				name: "reject_unlocked_map_read",
				cfg: refconfine.MutexMapConfig{
					AllowNilLazyInit:     false,
					AllowIntraPkgHelpers: false,
					RequireEntryParamKey: true,
					RequireAtLeastOneSet: true,
					KeyPred:              syntaxutil.IsReflectType,
				},
				src: `package locktest
import (
	"reflect"
	"sync"
)
type entry struct{ n int }
var (
	mu    sync.Mutex
	cache = make(map[reflect.Type]*entry)
)
func Lookup(t reflect.Type) *entry {
	if e, ok := cache[t]; ok {
		return e
	}
	mu.Lock()
	defer mu.Unlock()
	built := &entry{n: 1}
	cache[t] = built
	return built
}`,
				wantOK: false,
			},
			{
				name: "reject_lazy_init_under_non_nil_condition",
				cfg: refconfine.MutexMapConfig{
					AllowNilLazyInit:     true,
					AllowIntraPkgHelpers: true,
					KeyPred:              syntaxutil.IsReflectType,
				},
				src: `package locktest
import (
	"reflect"
	"sync"
)
type entry struct{ n int }
var (
	mu    sync.Mutex
	cache map[reflect.Type]*entry
)
func Lookup(t reflect.Type, wipe bool) *entry {
	mu.Lock()
	defer mu.Unlock()
	if wipe {
		cache = make(map[reflect.Type]*entry)
	}
	if e, ok := cache[t]; ok {
		return e
	}
	e := &entry{n: 1}
	cache[t] = e
	return e
}`,
				wantOK: false,
			},
			{
				name: "reject_looked_up_entry_mutated_via_conversion",
				cfg: refconfine.MutexMapConfig{
					AllowNilLazyInit:     true,
					AllowIntraPkgHelpers: true,
					KeyPred:              syntaxutil.IsReflectType,
				},
				src: `package locktest
import (
	"reflect"
	"sync"
)
type items []int
var (
	mu    sync.Mutex
	cache = map[reflect.Type]items{}
)
func Lookup(t reflect.Type) items {
	mu.Lock()
	defer mu.Unlock()
	if e, ok := cache[t]; ok {
		raw := ([]int)(e)
		raw[0] = 99
		return e
	}
	e := items{1}
	cache[t] = e
	return e
}`,
				wantOK: false,
			},
			{
				name: "reject_looked_up_entry_mutated_via_transient_conversion",
				cfg: refconfine.MutexMapConfig{
					AllowNilLazyInit:     true,
					AllowIntraPkgHelpers: true,
					KeyPred:              syntaxutil.IsReflectType,
				},
				src: `package locktest
import (
	"reflect"
	"sync"
)
type items []int
var (
	mu    sync.Mutex
	cache = map[reflect.Type]items{}
)
func Lookup(t reflect.Type) items {
	mu.Lock()
	defer mu.Unlock()
	if e, ok := cache[t]; ok {
		(([]int)(e))[0] = 99
		return e
	}
	e := items{1}
	cache[t] = e
	return e
}`,
				wantOK: false,
			},
			{
				name: "reject_looked_up_entry_mutated_via_subslice_projection",
				cfg: refconfine.MutexMapConfig{
					AllowNilLazyInit:     true,
					AllowIntraPkgHelpers: true,
					KeyPred:              syntaxutil.IsReflectType,
				},
				src: `package locktest
import (
	"reflect"
	"sync"
)
type entry struct{ items []int }
var (
	mu    sync.Mutex
	cache = map[reflect.Type]*entry{}
)
func Lookup(t reflect.Type) *entry {
	mu.Lock()
	defer mu.Unlock()
	if e, ok := cache[t]; ok {
		s := e.items
		s[0] = 99
		return e
	}
	e := &entry{items: []int{1}}
	cache[t] = e
	return e
}`,
				wantOK: false,
			},
			{
				name: "reject_looked_up_entry_mutated_via_helper_call",
				cfg: refconfine.MutexMapConfig{
					AllowNilLazyInit:     true,
					AllowIntraPkgHelpers: true,
					KeyPred:              syntaxutil.IsReflectType,
				},
				src: `package locktest
import (
	"reflect"
	"sync"
)
type entry struct{ n int }
var (
	mu    sync.Mutex
	cache = map[reflect.Type]*entry{}
)
func clobber(e *entry) { e.n = 99 }
func Lookup(t reflect.Type) *entry {
	mu.Lock()
	defer mu.Unlock()
	if e, ok := cache[t]; ok {
		clobber(e)
		return e
	}
	e := &entry{n: 1}
	cache[t] = e
	return e
}`,
				wantOK: false,
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				pkg, idx := mustTypecheckLockPkg(t, tc.src)
				mapVar := pkg.Types.Scope().Lookup("cache").(*types.Var)
				_, gotOK := refconfine.VerifyMutexConfinedMap(pkg, idx, mapVar, tc.cfg)
				if gotOK != tc.wantOK {
					t.Fatalf("VerifyMutexConfinedMap() = %v, want %v", gotOK, tc.wantOK)
				}
			})
		}
	})
}

type lockActKind uint8

const (
	actNoop lockActKind = iota
	actLock
	actUnlock
	actRLock
	actRUnlock
	actDeferUnlock
	actDeferRUnlock
	actReturn
	actPanic
	actIf
)

type lockProgNode struct {
	kind   lockActKind
	condID int
	thenS  []lockProgNode
	elseS  []lockProgNode
}

// oracleVerifyLockProg is an independent concrete path-set simulator over the
// generated structured AST program (with zero shared code with VerifyBodyLockRegions).
func oracleVerifyLockProg(nodes []lockProgNode, rw bool) bool {
	type simState struct {
		held   int   // 0=unlocked, 1=read, 2=write
		defers []int // 1=RUnlock, 2=Unlock
	}
	validExit := func(s simState) bool {
		h := s.held
		for i := len(s.defers) - 1; i >= 0; i-- {
			d := s.defers[i]
			if d == 1 {
				if h != 1 {
					return false
				}
				h = 0
			} else {
				if h != 2 {
					return false
				}
				h = 0
			}
		}
		return h == 0 && len(s.defers) <= 1
	}

	var execList func(list []lockProgNode, cur simState) (simState, bool, bool)
	execNode := func(n lockProgNode, cur simState) (simState, bool, bool) {
		cpDef := append([]int(nil), cur.defers...)
		cur.defers = cpDef
		switch n.kind {
		case actNoop:
			return cur, false, true
		case actLock:
			if cur.held != 0 || len(cur.defers) > 0 {
				return simState{}, false, false
			}
			cur.held = 2
			return cur, false, true
		case actRLock:
			if !rw || cur.held != 0 || len(cur.defers) > 0 {
				return simState{}, false, false
			}
			cur.held = 1
			return cur, false, true
		case actUnlock:
			if cur.held != 2 || len(cur.defers) > 0 {
				return simState{}, false, false
			}
			cur.held = 0
			return cur, false, true
		case actRUnlock:
			if !rw || cur.held != 1 || len(cur.defers) > 0 {
				return simState{}, false, false
			}
			cur.held = 0
			return cur, false, true
		case actDeferUnlock:
			if cur.held != 2 || len(cur.defers) > 0 {
				return simState{}, false, false
			}
			cur.defers = append(cur.defers, 2)
			return cur, false, true
		case actDeferRUnlock:
			if !rw || cur.held != 1 || len(cur.defers) > 0 {
				return simState{}, false, false
			}
			cur.defers = append(cur.defers, 1)
			return cur, false, true
		case actReturn, actPanic:
			if !validExit(cur) {
				return simState{}, false, false
			}
			return cur, true, true
		case actIf:
			s1, t1, ok1 := execList(n.thenS, cur)
			if !ok1 {
				return simState{}, false, false
			}
			s2, t2, ok2 := execList(n.elseS, cur)
			if !ok2 {
				return simState{}, false, false
			}
			switch {
			case t1 && t2:
				return simState{}, true, true
			case t1:
				return s2, false, true
			case t2:
				return s1, false, true
			default:
				if s1.held != s2.held || len(s1.defers) != len(s2.defers) {
					return simState{}, false, false
				}
				for i := range s1.defers {
					if s1.defers[i] != s2.defers[i] {
						return simState{}, false, false
					}
				}
				return s1, false, true
			}
		}
		return simState{}, false, false
	}
	execList = func(list []lockProgNode, cur simState) (simState, bool, bool) {
		for idx, n := range list {
			var term, ok bool
			cur, term, ok = execNode(n, cur)
			if !ok {
				return simState{}, false, false
			}
			if term {
				if idx+1 < len(list) {
					return simState{}, false, false
				}
				return cur, true, true
			}
		}
		return cur, false, true
	}

	end, term, ok := execList(nodes, simState{})
	if !ok {
		return false
	}
	if !term && !validExit(end) {
		return false
	}
	return true
}

func renderLockProg(nodes []lockProgNode, rw bool) string {
	var b strings.Builder
	b.WriteString("package locktest\nimport \"sync\"\n")
	if rw {
		b.WriteString("var mu sync.RWMutex\n")
	} else {
		b.WriteString("var mu sync.Mutex\n")
	}
	b.WriteString("var sink int\n")
	b.WriteString("func Sim(c0, c1, c2 bool) {\n\t_ = c0; _ = c1; _ = c2\n")
	var emit func(list []lockProgNode, indent string)
	emit = func(list []lockProgNode, indent string) {
		for _, n := range list {
			switch n.kind {
			case actNoop:
				b.WriteString(indent + "sink++\n")
			case actLock:
				b.WriteString(indent + "mu.Lock()\n")
			case actUnlock:
				b.WriteString(indent + "mu.Unlock()\n")
			case actRLock:
				b.WriteString(indent + "mu.RLock()\n")
			case actRUnlock:
				b.WriteString(indent + "mu.RUnlock()\n")
			case actDeferUnlock:
				b.WriteString(indent + "defer mu.Unlock()\n")
			case actDeferRUnlock:
				b.WriteString(indent + "defer mu.RUnlock()\n")
			case actReturn:
				b.WriteString(indent + "return\n")
			case actPanic:
				b.WriteString(indent + "panic(\"stop\")\n")
			case actIf:
				b.WriteString(fmt.Sprintf("%sif c%d {\n", indent, n.condID%3))
				emit(n.thenS, indent+"\t")
				if len(n.elseS) > 0 {
					b.WriteString(indent + "} else {\n")
					emit(n.elseS, indent+"\t")
				}
				b.WriteString(indent + "}\n")
			}
		}
	}
	emit(nodes, "\t")
	b.WriteString("}\n")
	return b.String()
}

func drawLockProgList(rt *rapid.T, rw bool, depth int) []lockProgNode {
	n := rapid.IntRange(1, 4).Draw(rt, "len")
	out := make([]lockProgNode, 0, n)
	for i := 0; i < n; i++ {
		maxKind := 8
		if depth < 2 {
			maxKind = 9
		}
		k := lockActKind(rapid.IntRange(0, maxKind).Draw(rt, "kind"))
		if !rw && (k == actRLock || k == actRUnlock || k == actDeferRUnlock) {
			k = actLock
		}
		if k == actIf {
			out = append(out, lockProgNode{
				kind:   actIf,
				condID: rapid.IntRange(0, 2).Draw(rt, "cond"),
				thenS:  drawLockProgList(rt, rw, depth+1),
				elseS:  drawLockProgList(rt, rw, depth+1),
			})
			continue
		}
		out = append(out, lockProgNode{kind: k})
		if k == actReturn || k == actPanic {
			break
		}
	}
	return out
}

func TestPropertyVerifyBodyLockRegionsPathSimulationOracle(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		rw := rapid.Bool().Draw(rt, "rw")
		// Ensure at least one mutex mention so mu is referenced in Sim.
		prefix := lockProgNode{kind: actLock}
		if rw && rapid.Bool().Draw(rt, "startRead") {
			prefix = lockProgNode{kind: actRLock}
		}
		nodes := append([]lockProgNode{prefix}, drawLockProgList(rt, rw, 0)...)
		src := renderLockProg(nodes, rw)
		pkg, idx := mustTypecheckLockPkg(t, src)
		fc := idx.FlowCache(pkg)
		body := fc.FuncBody(fc.FuncDecls[0])
		muVar := pkg.Types.Scope().Lookup("mu").(*types.Var)

		_, got := refconfine.VerifyBodyLockRegions(pkg, idx, body, refconfine.LockTarget{
			Kind:      refconfine.LockPkgGlobalVar,
			MutexVar:  muVar,
			IsRWMutex: rw,
		})
		want := oracleVerifyLockProg(nodes, rw)
		if got != want {
			t.Fatalf("VerifyBodyLockRegions() = %v, oracle = %v\nsrc:\n%s", got, want, src)
		}
	})
}

func FuzzVerifyBodyLockRegionsAndMutexMap(f *testing.F) {
	seeds := []string{
		"package locktest\nimport (\"reflect\"; \"sync\")\ntype e struct{ n int }\nvar mu sync.RWMutex\nvar m = make(map[reflect.Type]*e)\nfunc F(t reflect.Type) *e { mu.RLock(); v := m[t]; mu.RUnlock(); if v != nil { return v }; mu.Lock(); m[t] = &e{n: 1}; mu.Unlock(); return &e{n: 1} }\n",
		"package locktest\nimport \"sync\"\nvar mu sync.Mutex\nfunc F(b bool) { mu.Lock(); if b { mu.Unlock(); return }; defer mu.Unlock() }\n",
		"package locktest\nimport \"sync\"\nvar mu sync.Mutex\nfunc F() { mu.Lock(); panic(\"x\") }\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		pkg, idx, ok := tryTypecheckLockPkg(src)
		if !ok {
			return
		}
		fc := idx.FlowCache(pkg)
		for _, name := range pkg.Types.Scope().Names() {
			v, isV := pkg.Types.Scope().Lookup(name).(*types.Var)
			if !isV || v == nil {
				continue
			}
			rw := syntaxutil.IsNamedInPkg(v.Type(), "sync", "RWMutex")
			plain := syntaxutil.IsNamedInPkg(v.Type(), "sync", "Mutex")
			if rw || plain {
				for _, fd := range fc.FuncDecls {
					b := fc.FuncBody(fd)
					_, r1 := refconfine.VerifyBodyLockRegions(pkg, idx, b, refconfine.LockTarget{
						Kind:      refconfine.LockPkgGlobalVar,
						MutexVar:  v,
						IsRWMutex: rw,
					})
					_, r2 := refconfine.VerifyBodyLockRegions(pkg, idx, b, refconfine.LockTarget{
						Kind:      refconfine.LockPkgGlobalVar,
						MutexVar:  v,
						IsRWMutex: rw,
					})
					if r1 != r2 {
						t.Fatalf("non-deterministic VerifyBodyLockRegions on %s", fd.Name.Name)
					}
				}
			}
			if _, isMap := types.Unalias(v.Type()).Underlying().(*types.Map); isMap {
				_, m1 := refconfine.VerifyMutexConfinedMap(pkg, idx, v, refconfine.MutexMapConfig{
					AllowNilLazyInit:     true,
					AllowIntraPkgHelpers: true,
				})
				_, m2 := refconfine.VerifyMutexConfinedMap(pkg, idx, v, refconfine.MutexMapConfig{
					AllowNilLazyInit:     true,
					AllowIntraPkgHelpers: true,
				})
				if m1 != m2 {
					t.Fatalf("non-deterministic VerifyMutexConfinedMap on %s", v.Name())
				}
			}
		}
	})
}
