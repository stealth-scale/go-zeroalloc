// Copyright Stealth Scale B.V. 2026
// SPDX-License-Identifier: MIT

package gcopt

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/constant"
	"go/format"
	"go/token"
	"go/types"
	"sort"
	"strings"
	"sync"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
	"golang.org/x/tools/go/ssa"
)

// NewPlugin allows this analyzer to also be loaded by golangci-lint v2 custom module plugins.
func NewPlugin(conf any) ([]*analysis.Analyzer, error) {
	return []*analysis.Analyzer{Analyzer}, nil
}

// ZeroAllocFact marks functions annotated with //gc:zeroalloc across package boundaries.
type ZeroAllocFact struct{}

func (*ZeroAllocFact) AFact() {}
func (*ZeroAllocFact) String() string {
	return "gc:zeroalloc"
}

// AllocatesFact marks a function that allocates on a path that does not end in an error or a
// panic, as the compiler's escape analysis decides. Direct is the first allocation in the
// function's own compiled body, and Call is the first call of a function that allocates. One
// of them is not empty.
type AllocatesFact struct {
	Direct string
	Call   string
}

func (*AllocatesFact) AFact() {}
func (f *AllocatesFact) String() string {
	if f.Direct != "" {
		return "allocates(" + f.Direct + ")"
	}
	return "allocates(" + f.Call + ")"
}

// Analyzer enforces strict zero-allocation & GC noscan invariants using AST/Types, SSA, and Facts.
var Analyzer = &analysis.Analyzer{
	Name: "gcopt",
	Doc:  "reports the heap allocations that the compiler's escape analysis finds in functions marked //gc:zeroalloc, verifies //gc:noscan types and //gc:inline functions, and with -hints reports layout and latency hints",
	Requires: []*analysis.Analyzer{
		inspect.Analyzer,
		buildssa.Analyzer,
	},
	FactTypes: []analysis.Fact{
		(*ZeroAllocFact)(nil),
		(*AllocatesFact)(nil),
	},
	Run: run,
}

// pointerAnalysis summarizes why a type is or isn't GC-noscan.
type pointerAnalysis struct {
	hasPointers      bool
	onlyStringPtrs   bool
	firstPointerPath string
	pointerByteSpan  int64
	totalSize        int64
}

const cacheLineSize = 64

// goSizeClasses mirrors runtime/sizeclasses.go (67 span size classes up to 32KB).
// Used to detect structs or slices that barely cross a size class boundary and waste memory.
var goSizeClasses = []int64{
	0, 8, 16, 24, 32, 48, 64, 80, 96, 112, 128,
	144, 160, 176, 192, 208, 224, 240, 256, 288, 320,
	352, 384, 416, 448, 480, 512, 576, 640, 704, 768,
	896, 1024, 1152, 1280, 1408, 1536, 1792, 2048, 2304, 2688,
	3072, 3200, 3456, 4096, 4864, 5376, 6144, 6528, 6784, 6912,
	8192, 9472, 9728, 10240, 10880, 12288, 13568, 14336, 16384, 18432,
	19072, 20480, 21760, 24576, 27264, 28672, 32768,
}

var (
	flagCheckFalseSharing bool
	flagWriteBarriers     bool
	flagSizeClasses       bool
	flagSwissMap          bool
	flagDisruptor         bool
	flagInlining          bool
	flagSoACache          bool
	flagSubslicePinning   bool
	flagHotLoopCalls      bool
	flagStackGrowth       bool
	flagOffHeapMmap       bool
	flagStrictNoscanTypes bool
	flagOptInOnly         bool
	flagIncludeTests      bool
	flagIncludeGenerated  bool
	flagHints             bool
	flagConditional       bool
)

func init() {
	Analyzer.Flags.BoolVar(&flagHints, "hints", false, "also report the layout, loop and latency hints, which are not allocations; the flags falsesharing, sizeclasses, swissmap, disruptor, soa, subslicepin, hotloop, offheap and stackgrowth select among them")
	Analyzer.Flags.BoolVar(&flagConditional, "conditional", false, "also report the appends in //gc:zeroalloc functions whose growth the compiler allocates on the heap")
	Analyzer.Flags.BoolVar(&flagCheckFalseSharing, "falsesharing", true, "detect CPU L1/L2 cache-line false sharing between atomic/mutex fields in structs")
	Analyzer.Flags.BoolVar(&flagWriteBarriers, "writebarriers", false, "also report the write barriers that the compiler emits in //gc:zeroalloc functions")
	Analyzer.Flags.BoolVar(&flagSizeClasses, "sizeclasses", true, "detect structs that barely spill into the next Go runtime mspan size class (>15% internal fragmentation)")
	Analyzer.Flags.BoolVar(&flagSwissMap, "swissmap", true, "detect Go 1.24+ SwissTable maps with a key or a value of more than 128 bytes, because the runtime allocates each such key or value separately")
	Analyzer.Flags.BoolVar(&flagDisruptor, "disruptor", true, "detect LMAX Disruptor / ring-buffer hazards: unpadded atomic cursors (<64B), pointer-bearing ring slots, and integer modulo (%) indexing")
	Analyzer.Flags.BoolVar(&flagInlining, "inlining", true, "report the //gc:inline functions that the compiler does not inline")
	Analyzer.Flags.BoolVar(&flagSoACache, "soa", true, "detect Array-of-Structs (AoS) loops that waste >75% of CPU L1d cache bandwidth and should be refactored to Struct-of-Arrays (SoA)")
	Analyzer.Flags.BoolVar(&flagSubslicePinning, "subslicepin", true, "detect returning unclamped subslices that pin large backing arrays in the GC heap")
	Analyzer.Flags.BoolVar(&flagHotLoopCalls, "hotloop", true, "detect string concatenation (+=), interface dynamic dispatch, strconv.Itoa/Format*, and reflection/json encoders inside loops")
	Analyzer.Flags.BoolVar(&flagStackGrowth, "stackgrowth", true, "detect local stack variables >2KB inside functions that risk triggering runtime.morestack stack splits")
	Analyzer.Flags.BoolVar(&flagOffHeapMmap, "offheap", true, "detect large >=1MB slice allocations or ring arrays that should be allocated off-heap via unix.Mmap (MAP_HUGETLB|MAP_POPULATE)")
	Analyzer.Flags.BoolVar(&flagStrictNoscanTypes, "strict-noscan", false, "enforce that all structs are 100% pointer-free (noscan) unless opted out via //gc:allowscan")
	Analyzer.Flags.BoolVar(&flagOptInOnly, "opt-in", true, "check only the functions annotated with //gc:zeroalloc; with -opt-in=false, check every function that //gc:allowalloc does not exclude")
	Analyzer.Flags.BoolVar(&flagIncludeTests, "include-tests", false, "include *_test.go files and *test packages in GC and cache-line analysis")
	Analyzer.Flags.BoolVar(&flagIncludeGenerated, "include-generated", false, "include generated files (e.g. *.kanon.go, *.pb.go, // Code generated) in analysis")
}

func run(pass *analysis.Pass) (any, error) {
	// Skip pure test helper packages (like placementtest, storetest, membershiptest, protocoltest) unless -include-tests is set
	if !flagIncludeTests && (strings.HasSuffix(pass.Pkg.Name(), "test") || strings.HasSuffix(pass.Pkg.Path(), "_test")) {
		return nil, nil
	}

	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	ssaInput := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA)

	// Collect line numbers suppressed via //gc:ignore as well as excluded test/generated files
	ignoredLines := collectIgnoredLines(pass)

	zeroAllocFuncs := make(map[*types.Func]bool)
	var inlineDecls []*ast.FuncDecl
	FindDirectives(pass, insp, zeroAllocFuncs, &inlineDecls, ignoredLines)

	// The compiler decides every allocation, every inlined call and every write barrier.
	recs, err := loadCompilerRecords(pass)
	if err != nil {
		return nil, err
	}
	checkAllocations(pass, recs, zeroAllocFuncs, ignoredLines)
	reportCompilerHints(pass, recs, zeroAllocFuncs, ignoredLines)
	checkInlineDirectives(pass, recs, inlineDecls)

	if flagHints {
		runASTChecks(pass, insp, ignoredLines, nil)
		runSSAChecks(pass, ssaInput, zeroAllocFuncs, ignoredLines)
	}
	return nil, nil
}

// collectIgnoredLines scans all comments in the package for //gc:ignore so engineers can
// suppress intentional allocations or audited unsafe patterns on that line or the immediately following line.
func collectIgnoredLines(pass *analysis.Pass) map[string]bool {
	ignored := make(map[string]bool)
	for _, file := range pass.Files {
		filename := pass.Fset.Position(file.Pos()).Filename
		if !flagIncludeTests && strings.HasSuffix(filename, "_test.go") {
			ignored["FILE:"+filename] = true
			continue
		}
		if !flagIncludeGenerated && isGeneratedFile(file, filename) {
			ignored["FILE:"+filename] = true
			continue
		}
		// File-level opt-out directive: placing //gc:ignore-file or //gc:allowalloc-file anywhere in a file skips it
		for _, cg := range file.Comments {
			for _, c := range cg.List {
				if strings.Contains(c.Text, "gc:ignore-file") || strings.Contains(c.Text, "gc:allowalloc-file") {
					ignored["FILE:"+filename] = true
					break
				}
				if strings.Contains(c.Text, "gc:ignore") {
					pos := pass.Fset.Position(c.Pos())
					ignored[fmt.Sprintf("%s:%d", pos.Filename, pos.Line)] = true
					ignored[fmt.Sprintf("%s:%d", pos.Filename, pos.Line+1)] = true
				}
			}
		}
	}
	return ignored
}

func isGeneratedFile(file *ast.File, filename string) bool {
	if strings.HasSuffix(filename, ".kanon.go") || strings.HasSuffix(filename, ".pb.go") || strings.HasSuffix(filename, "_gen.go") {
		return true
	}
	for _, cg := range file.Comments {
		for _, c := range cg.List {
			if strings.HasPrefix(c.Text, "// Code generated ") || strings.HasPrefix(c.Text, "// DO NOT EDIT") {
				return true
			}
		}
	}
	return false
}

func isIgnored(pass *analysis.Pass, pos token.Pos, ignored map[string]bool) bool {
	if !pos.IsValid() {
		return false
	}
	p := pass.Fset.Position(pos)
	if ignored["FILE:"+p.Filename] {
		return true
	}
	return ignored[fmt.Sprintf("%s:%d", p.Filename, p.Line)]
}

// isSizedConcreteType returns false if t is nil, invalid, an uninstantiated generic *types.TypeParam,
// an untyped constant basic type, or a struct/array containing a TypeParam.
// Calling go/types.(*gcSizes).Sizeof, Alignof, or Offsetsof on a TypeParam triggers an assertion panic in go/types!
func isSizedConcreteType(t types.Type, seen map[types.Type]bool) bool {
	if t == nil {
		return false
	}
	if seen == nil {
		seen = make(map[types.Type]bool)
	}
	if seen[t] {
		return true
	}
	seen[t] = true

	if _, isTP := t.(*types.TypeParam); isTP {
		return false
	}
	switch u := t.Underlying().(type) {
	case nil, *types.TypeParam, *types.Signature, *types.Tuple:
		return false
	case *types.Basic:
		if u.Kind() == types.Invalid || (u.Info()&types.IsUntyped) != 0 {
			return false
		}
		return true
	case *types.Array:
		return isSizedConcreteType(u.Elem(), seen)
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			if !isSizedConcreteType(u.Field(i).Type(), seen) {
				return false
			}
		}
		return true
	default:
		return true
	}
}

func safeSizeof(sizes types.Sizes, t types.Type) (int64, bool) {
	if !isSizedConcreteType(t, nil) {
		return 0, false
	}
	return sizes.Sizeof(t), true
}

func safeAlignof(sizes types.Sizes, t types.Type) (int64, bool) {
	if !isSizedConcreteType(t, nil) {
		return 1, false
	}
	return sizes.Alignof(t), true
}

func safeOffsetsof(sizes types.Sizes, fields []*types.Var) ([]int64, bool) {
	for _, f := range fields {
		if f == nil || !isSizedConcreteType(f.Type(), nil) {
			return nil, false
		}
	}
	return sizes.Offsetsof(fields), true
}

// isOptedOutFunc returns true if the function has an opt-out comment (//gc:allowalloc, //gc:cold, or //gc:ignore)
// or is a package init() function.
func isOptedOutFunc(decl *ast.FuncDecl) bool {
	if decl.Name.Name == "init" {
		return true
	}
	return hasDirective(decl.Doc, "gc:allowalloc") ||
		hasDirective(decl.Doc, "gc:cold") ||
		hasDirective(decl.Doc, "gc:ignore")
}

// isOptedOutScanType returns true if a type declaration opts out of strict pointer-free noscan checks.
func isOptedOutScanType(declDoc, tsDoc, tsComment *ast.CommentGroup) bool {
	return hasDirective(declDoc, "gc:allowscan") ||
		hasDirective(declDoc, "gc:allownoscan") ||
		hasDirective(declDoc, "gc:ignore") ||
		hasDirective(tsDoc, "gc:allowscan") ||
		hasDirective(tsDoc, "gc:allownoscan") ||
		hasDirective(tsDoc, "gc:ignore") ||
		hasDirective(tsComment, "gc:allowscan") ||
		hasDirective(tsComment, "gc:allownoscan") ||
		hasDirective(tsComment, "gc:ignore")
}

// FindDirectives collects the functions that the analyzer checks into zeroAllocFuncs: those
// with //gc:zeroalloc, or with -opt-in=false every function that //gc:allowalloc does not
// exclude. It collects the functions with //gc:inline into inlineDecls, and verifies the
// //gc:noscan types. With -hints it also runs the layout hints of struct types.
func FindDirectives(pass *analysis.Pass, insp *inspector.Inspector, zeroAllocFuncs map[*types.Func]bool, inlineDecls *[]*ast.FuncDecl, ignored map[string]bool) {
	nodeFilter := []ast.Node{
		(*ast.FuncDecl)(nil),
		(*ast.GenDecl)(nil),
	}

	insp.Preorder(nodeFilter, func(n ast.Node) {
		switch decl := n.(type) {
		case *ast.FuncDecl:
			if isIgnored(pass, decl.Pos(), ignored) {
				return
			}
			enforceZeroAlloc := !isOptedOutFunc(decl)
			if flagOptInOnly {
				enforceZeroAlloc = hasDirective(decl.Doc, "gc:zeroalloc")
			}

			if enforceZeroAlloc {
				if obj, ok := pass.TypesInfo.Defs[decl.Name].(*types.Func); ok {
					zeroAllocFuncs[obj] = true
					pass.ExportObjectFact(obj, &ZeroAllocFact{})
				}
				if flagHints && flagStackGrowth {
					checkStackFrameSize(pass, decl)
				}
			}

			if flagInlining && hasDirective(decl.Doc, "gc:inline") {
				*inlineDecls = append(*inlineDecls, decl)
			}

		case *ast.GenDecl:
			if decl.Tok != token.TYPE {
				return
			}
			declHasNoscan := hasDirective(decl.Doc, "gc:noscan")
			for _, spec := range decl.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok || isIgnored(pass, ts.Pos(), ignored) {
					continue
				}
				optedOutScan := isOptedOutScanType(decl.Doc, ts.Doc, ts.Comment)
				if !optedOutScan && (flagStrictNoscanTypes || declHasNoscan || hasDirective(ts.Doc, "gc:noscan") || hasDirective(ts.Comment, "gc:noscan")) {
					if obj, ok := pass.TypesInfo.Defs[ts.Name]; ok {
						verifyNoscanType(pass, ts.Pos(), ts.Name.Name, obj.Type())
					}
				}
				// With -hints, inspect struct declarations for GC pointer-byte packing, false sharing and size-class waste,
				// unless //gc:ignore or //gc:allowscan opts them out.
				if st, ok := ts.Type.(*ast.StructType); ok && flagHints && !optedOutScan {
					if obj, ok := pass.TypesInfo.Defs[ts.Name]; ok {
						checkStructPointerPacking(pass, ts, st, obj.Type())
						if flagCheckFalseSharing {
							checkStructFalseSharing(pass, ts, obj.Type())
						}
						if flagSizeClasses {
							checkStructSizeClassFragmentation(pass, ts, obj.Type())
						}
						if flagDisruptor {
							checkDisruptorRingLayout(pass, ts, obj.Type())
						}
					}
				}
			}
		}
	})
}

// checkDisruptorRingLayout inspects ring-buffer and sequence/cursor structs for three LMAX Disruptor mechanical-sympathy laws:
//  1. A struct mixing an atomic sequence counter and a slice/array in the same 64B cache line causes false sharing between
//     the producer advancing the cursor and the consumer reading the ring buffer header.
//  2. Ring buffer backing arrays/slices (`[N]Event` or `[]Event`) must hold pointer-free (`noscan`) value structs so
//     publishing events never triggers Go's GC Hybrid Write Barrier (`runtime.gcWriteBarrier`) or GC mark traversal.
//  3. Standalone atomic cursor wrapper structs (e.g., `type Cursor struct { val atomic.Int64 }`) should be padded to
//     at least 64 bytes (or 128 bytes on x86_64/ARM64 with adjacent-line spatial prefetchers) so arrays of cursors
//     (`[]Cursor`) don't false-share.
func checkDisruptorRingLayout(pass *analysis.Pass, ts *ast.TypeSpec, t types.Type) {
	if !isSizedConcreteType(t, nil) {
		return
	}
	st, ok := t.Underlying().(*types.Struct)
	if !ok || st.NumFields() == 0 {
		return
	}

	fields := make([]*types.Var, st.NumFields())
	for i := 0; i < st.NumFields(); i++ {
		fields[i] = st.Field(i)
	}
	offsets, ok := safeOffsetsof(pass.TypesSizes, fields)
	if !ok {
		return
	}
	structSize, ok := safeSizeof(pass.TypesSizes, st)
	if !ok {
		return
	}

	// Rule 1: Standalone atomic cursor/sequence struct that is < 64 bytes
	if st.NumFields() == 1 && isAtomicOrSyncPrimitive(fields[0].Type()) && structSize < cacheLineSize {
		padNeeded := cacheLineSize - structSize
		pass.Reportf(ts.Pos(),
			"LMAX Disruptor cursor hazard: atomic wrapper struct %s is only %d bytes; pad to 64B (or 128B for Intel/AMD spatial prefetcher isolation) with `_ [%d]byte` so adjacent cursors never share a cache line",
			ts.Name.Name, structSize, padNeeded)
		return
	}

	// Rule 2: Check if an atomic field shares a 64B cache line with a read-mostly ring-buffer field (mask, capacity, or slice header),
	// and check if a fixed-size ring buffer array `[N]T` contains pointers.
	for i, f := range fields {
		// Check fixed-size ring buffer arrays `[N]Event` (where N >= 64 and power of 2) for pointer-bearing elements
		if arr, isArr := f.Type().Underlying().(*types.Array); isArr && arr.Len() >= 64 && (arr.Len()&(arr.Len()-1)) == 0 {
			elemRes := inspectTypePointers(pass.TypesSizes, arr.Elem(), f.Name()+"[0]", make(map[types.Type]bool))
			if elemRes.hasPointers {
				pass.Reportf(f.Pos(),
					"LMAX Disruptor ring-buffer hazard: power-of-two ring array %s.%s ([%d]%s) contains pointers at %s, forcing GC mark scanning across %d bytes and triggering GC write barriers on every event publish; make %s 100%% pointer-free (noscan)",
					ts.Name.Name, f.Name(), arr.Len(), arr.Elem().String(), elemRes.firstPointerPath, elemRes.pointerByteSpan, arr.Elem().String())
			}
		}

		if !isAtomicOrSyncPrimitive(f.Type()) {
			continue
		}
		atomicLine := offsets[i] / cacheLineSize
		// Check if any non-blank, non-atomic field (like `mask uint64` or `buf []T`) lives on the same cache line
		for j, other := range fields {
			if i == j || other.Name() == "_" || isAtomicOrSyncPrimitive(other.Type()) {
				continue
			}
			otherLine := offsets[j] / cacheLineSize
			if atomicLine == otherLine {
				pass.Reportf(f.Pos(),
					"CPU cache-line false sharing: hot atomic field %s.%s (offset %dB) shares 64B cache line #%d with read-mostly field %s.%s (offset %dB); every atomic store invalidates %s in L1d cache across all cores—insert cache-line padding between them",
					ts.Name.Name, f.Name(), offsets[i], atomicLine, ts.Name.Name, other.Name(), offsets[j], other.Name())
				break
			}
		}
	}
}

// checkStructSizeClassFragmentation checks if a struct's size barely crosses a Go mspan size-class boundary
// (e.g., a 65-byte or 72-byte struct forces an 80-byte size class, or a 1032-byte struct forces 1152 bytes).
func checkStructSizeClassFragmentation(pass *analysis.Pass, ts *ast.TypeSpec, t types.Type) {
	if !isSizedConcreteType(t, nil) {
		return
	}
	st, ok := t.Underlying().(*types.Struct)
	if !ok || st.NumFields() < 2 {
		return
	}

	sz, ok := safeSizeof(pass.TypesSizes, st)
	if !ok || sz <= 32 || sz > 32768 {
		return
	}

	for i := 1; i < len(goSizeClasses); i++ {
		classSz := goSizeClasses[i]
		prevClassSz := goSizeClasses[i-1]
		if sz > prevClassSz && sz <= classSz {
			wasted := classSz - sz
			spillover := sz - prevClassSz
			// Flag if the struct spilled over the previous size class by <= 8 bytes AND wastes >= 12% of the allocated span slot
			if spillover <= 8 && wasted >= 16 && (wasted*100)/classSz >= 12 {
				pass.Reportf(ts.Pos(),
					"mspan size-class fragmentation: struct %s is %d bytes (spills over %dB size class by just %dB), rounding up to the %dB allocator size class (%dB / %d%% wasted per heap allocation)",
					ts.Name.Name, sz, prevClassSz, spillover, classSz, wasted, (wasted*100)/classSz)
			}
			break
		}
	}
}

// checkStructFalseSharing detects multiple concurrency primitives (sync/atomic or sync.Mutex/RWMutex)
// sharing the same 64-byte CPU L1/L2 cache line without explicit padding.
func checkStructFalseSharing(pass *analysis.Pass, ts *ast.TypeSpec, t types.Type) {
	if !isSizedConcreteType(t, nil) {
		return
	}
	st, ok := t.Underlying().(*types.Struct)
	if !ok || st.NumFields() < 2 {
		return
	}

	fields := make([]*types.Var, st.NumFields())
	for i := 0; i < st.NumFields(); i++ {
		fields[i] = st.Field(i)
	}
	offsets, ok := safeOffsetsof(pass.TypesSizes, fields)
	if !ok {
		return
	}

	type syncField struct {
		name      string
		offset    int64
		size      int64
		cacheLine int64
	}

	var prev *syncField
	for i, f := range fields {
		if !isAtomicOrSyncPrimitive(f.Type()) {
			continue
		}
		sz, ok := safeSizeof(pass.TypesSizes, f.Type())
		if !ok {
			continue
		}
		cl := offsets[i] / cacheLineSize
		cur := &syncField{
			name:      f.Name(),
			offset:    offsets[i],
			size:      sz,
			cacheLine: cl,
		}
		if prev != nil && prev.cacheLine == cur.cacheLine {
			padNeeded := ((prev.cacheLine + 1) * cacheLineSize) - (prev.offset + prev.size)
			if padNeeded > 0 {
				pass.Reportf(f.Pos(),
					"CPU cache-line false sharing: concurrency primitives %s.%s (offset %dB) and %s.%s (offset %dB) share 64B cache line #%d; insert `_ [%d]byte` padding between them",
					ts.Name.Name, prev.name, prev.offset, ts.Name.Name, cur.name, cur.offset, cur.cacheLine, padNeeded)
			}
		}
		prev = cur
	}
}

func isAtomicOrSyncPrimitive(t types.Type) bool {
	named, ok := t.(*types.Named)
	if !ok {
		if ptr, isPtr := t.(*types.Pointer); isPtr {
			named, ok = ptr.Elem().(*types.Named)
		}
	}
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return false
	}
	pkgPath := named.Obj().Pkg().Path()
	name := named.Obj().Name()
	if pkgPath == "sync/atomic" {
		return true
	}
	if pkgPath == "sync" && (name == "Mutex" || name == "RWMutex" || name == "WaitGroup" || name == "Map") {
		return true
	}
	return false
}

func hasDirective(cg *ast.CommentGroup, directive string) bool {
	if cg == nil {
		return false
	}
	for _, c := range cg.List {
		text := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
		if strings.HasPrefix(text, directive) {
			return true
		}
	}
	return false
}

// verifyNoscanType strictly fails if a type marked //gc:noscan contains any pointers.
func verifyNoscanType(pass *analysis.Pass, pos token.Pos, name string, t types.Type) {
	res := inspectTypePointers(pass.TypesSizes, t, name, make(map[types.Type]bool))
	if res.hasPointers {
		pass.Reportf(pos,
			"type %s is marked //gc:noscan but contains pointer at %s (forces GC mark scanning across %d/%d bytes)",
			name, res.firstPointerPath, res.pointerByteSpan, res.totalSize)
	}
}

// checkStructPointerPacking computes the current GC pointer-scan span of a struct and compares it
// against an optimal packing where pointer-bearing fields are grouped at the start of the struct.
func checkStructPointerPacking(pass *analysis.Pass, ts *ast.TypeSpec, astStruct *ast.StructType, t types.Type) {
	if !isSizedConcreteType(t, nil) {
		return
	}
	st, ok := t.Underlying().(*types.Struct)
	if !ok || st.NumFields() < 2 {
		return
	}

	// Skip structs with blank/unnamed padding fields or cgo directives to avoid breaking ABI layout.
	for i := 0; i < st.NumFields(); i++ {
		if st.Field(i).Name() == "_" {
			return
		}
	}

	curRes := inspectTypePointers(pass.TypesSizes, st, ts.Name.Name, make(map[types.Type]bool))
	if !curRes.hasPointers {
		return
	}

	// Build an optimally packed field list: pointers first (largest alignment first), then scalars.
	type fieldInfo struct {
		v        *types.Var
		tag      string
		hasPtr   bool
		ptrBytes int64
		size     int64
		align    int64
	}

	fields := make([]fieldInfo, st.NumFields())
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		fRes := inspectTypePointers(pass.TypesSizes, f.Type(), f.Name(), make(map[types.Type]bool))
		fSz, _ := safeSizeof(pass.TypesSizes, f.Type())
		fAlign, _ := safeAlignof(pass.TypesSizes, f.Type())
		fields[i] = fieldInfo{
			v:        f,
			tag:      st.Tag(i),
			hasPtr:   fRes.hasPointers,
			ptrBytes: fRes.pointerByteSpan,
			size:     fSz,
			align:    fAlign,
		}
	}

	sort.SliceStable(fields, func(i, j int) bool {
		if fields[i].hasPtr != fields[j].hasPtr {
			return fields[i].hasPtr // Pointers always come first so GC stops scanning early
		}
		if fields[i].align != fields[j].align {
			return fields[i].align > fields[j].align
		}
		return fields[i].size > fields[j].size
	})

	sortedVars := make([]*types.Var, len(fields))
	for i, fi := range fields {
		sortedVars[i] = types.NewField(fi.v.Pos(), fi.v.Pkg(), fi.v.Name(), fi.v.Type(), fi.v.Embedded())
	}

	optOffsets, ok := safeOffsetsof(pass.TypesSizes, sortedVars)
	if !ok {
		return
	}
	var optPtrSpan int64
	for i, fi := range fields {
		if fi.hasPtr {
			end := optOffsets[i] + fi.ptrBytes
			if end > optPtrSpan {
				optPtrSpan = end
			}
		}
	}

	// Only report if reordering saves at least one 8-byte word of GC pointer scanning.
	wordSz := pass.TypesSizes.Sizeof(types.Typ[types.Uintptr])
	if curRes.pointerByteSpan-optPtrSpan >= wordSz {
		diag := analysis.Diagnostic{
			Pos: ts.Pos(),
			Message: fmt.Sprintf(
				"struct %s forces GC to scan %d/%d bytes; grouping pointer fields first shrinks GC pointer scan span to %d bytes (-%d%% mark work)",
				ts.Name.Name, curRes.pointerByteSpan, curRes.totalSize, optPtrSpan,
				((curRes.pointerByteSpan-optPtrSpan)*100)/curRes.pointerByteSpan,
			),
		}

		if newSrc, ok := formatReorderedStruct(pass, astStruct, fields); ok {
			diag.SuggestedFixes = []analysis.SuggestedFix{
				{
					Message: "Reorder struct fields to minimize GC pointer-scan bytes",
					TextEdits: []analysis.TextEdit{
						{
							Pos:     astStruct.Pos(),
							End:     astStruct.End(),
							NewText: newSrc,
						},
					},
				},
			}
		}
		pass.Report(diag)
	}
}

func formatReorderedStruct(pass *analysis.Pass, astStruct *ast.StructType, sortedFields interface{}) ([]byte, bool) {
	// Only auto-generate text edit if every AST field declares a single name and has no inline comments.
	if astStruct.Fields == nil {
		return nil, false
	}
	byName := make(map[string]*ast.Field)
	for _, f := range astStruct.Fields.List {
		if len(f.Names) != 1 || f.Doc != nil || f.Comment != nil {
			return nil, false
		}
		byName[f.Names[0].Name] = f
	}

	// Use reflection-free slice extraction via types.Struct order
	var buf bytes.Buffer
	buf.WriteString("struct {\n")
	// Re-sort AST fields by pointer presence then alignment
	astList := make([]*ast.Field, len(astStruct.Fields.List))
	copy(astList, astStruct.Fields.List)
	sort.SliceStable(astList, func(i, j int) bool {
		ti := pass.TypesInfo.TypeOf(astList[i].Type)
		tj := pass.TypesInfo.TypeOf(astList[j].Type)
		if !isSizedConcreteType(ti, nil) || !isSizedConcreteType(tj, nil) {
			return false
		}
		ri := inspectTypePointers(pass.TypesSizes, ti, "", make(map[types.Type]bool))
		rj := inspectTypePointers(pass.TypesSizes, tj, "", make(map[types.Type]bool))
		if ri.hasPointers != rj.hasPointers {
			return ri.hasPointers
		}
		ai, _ := safeAlignof(pass.TypesSizes, ti)
		aj, _ := safeAlignof(pass.TypesSizes, tj)
		if ai != aj {
			return ai > aj
		}
		si, _ := safeSizeof(pass.TypesSizes, ti)
		sj, _ := safeSizeof(pass.TypesSizes, tj)
		return si > sj
	})

	for _, f := range astList {
		var fBuf bytes.Buffer
		if err := format.Node(&fBuf, pass.Fset, f); err != nil {
			return nil, false
		}
		buf.WriteString("\t")
		buf.Write(fBuf.Bytes())
		buf.WriteString("\n")
	}
	buf.WriteString("}")
	return buf.Bytes(), true
}

// runASTChecks performs structural and loop-context checks across the package.
func runASTChecks(pass *analysis.Pass, insp *inspector.Inspector, ignored map[string]bool, mu *sync.Mutex) {
	if mu != nil {
		origReport := pass.Report
		passCopy := *pass
		passCopy.Report = func(d analysis.Diagnostic) {
			mu.Lock()
			origReport(d)
			mu.Unlock()
		}
		pass = &passCopy
	}

	nodeFilter := []ast.Node{
		(*ast.MapType)(nil),
		(*ast.ForStmt)(nil),
		(*ast.RangeStmt)(nil),
		(*ast.CallExpr)(nil),
		(*ast.ReturnStmt)(nil),
	}

	insp.WithStack(nodeFilter, func(n ast.Node, push bool, stack []ast.Node) bool {
		if !push || isIgnored(pass, n.Pos(), ignored) {
			return true
		}

		switch node := n.(type) {
		case *ast.MapType:
			checkMapGCScan(pass, node)
		case *ast.ForStmt:
			checkLoopHazards(pass, node.Body)
		case *ast.RangeStmt:
			checkRangeCopyAndHazards(pass, node)
			checkSliceZeroingLoop(pass, node)
			if flagSoACache {
				checkAoSCacheLineWaste(pass, node)
			}
		case *ast.CallExpr:
			checkSyncPoolValueBoxing(pass, node)
			checkAppendUnclampedSubslice(pass, node)
			checkModernGoRuntimeCalls(pass, node)
			if flagOffHeapMmap {
				checkLargeHeapMakeForMmap(pass, node)
			}
		case *ast.ReturnStmt:
			if flagSubslicePinning {
				checkSubsliceMemoryPinning(pass, node, stack)
			}
		}
		return true
	})
}

// checkAoSCacheLineWaste detects ranging over a slice of large structs (`>= 128B`, i.e., 2+ CPU cache lines per element)
// where the loop body only touches 1 or 2 small fields—wasting >75% of L1d memory bandwidth (Array-of-Structs trap).
func checkAoSCacheLineWaste(pass *analysis.Pass, rng *ast.RangeStmt) {
	if rng.Body == nil {
		return
	}
	seqType := pass.TypesInfo.TypeOf(rng.X)
	if seqType == nil {
		return
	}
	sliceType, ok := seqType.Underlying().(*types.Slice)
	if !ok {
		return
	}
	elemType := sliceType.Elem()
	if ptr, isPtr := elemType.Underlying().(*types.Pointer); isPtr {
		elemType = ptr.Elem()
	}
	if !isSizedConcreteType(elemType, nil) {
		return
	}
	st, ok := elemType.Underlying().(*types.Struct)
	if !ok || st.NumFields() < 4 {
		return
	}

	elemSize, ok := safeSizeof(pass.TypesSizes, st)
	if !ok || elemSize < 128 {
		return // Only inspect structs spanning at least 2 full 64B cache lines
	}

	// Count which struct fields of `elemType` are actually referenced inside the loop body
	touchedFields := make(map[string]int64)
	escapedWholeStruct := false

	ast.Inspect(rng.Body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if xType := pass.TypesInfo.TypeOf(sel.X); xType != nil {
			if ptr, isPtr := xType.Underlying().(*types.Pointer); isPtr {
				xType = ptr.Elem()
			}
			if types.Identical(xType.Underlying(), st) {
				if selObj, ok := pass.TypesInfo.Selections[sel]; ok && selObj.Kind() == types.FieldVal {
					if fSz, ok := safeSizeof(pass.TypesSizes, selObj.Type()); ok {
						touchedFields[sel.Sel.Name] = fSz
					}
				} else {
					// Calling a method on the struct may access arbitrary fields
					escapedWholeStruct = true
				}
			}
		}
		return true
	})

	if escapedWholeStruct || len(touchedFields) == 0 || len(touchedFields) > 2 {
		return
	}

	var usedBytes int64
	var fieldNames []string
	for name, sz := range touchedFields {
		usedBytes += sz
		fieldNames = append(fieldNames, name)
	}
	sort.Strings(fieldNames)

	// If the loop reads <= 16 bytes out of a >= 128 byte struct, >= 87.5% of every L1d cache line transfer is wasted!
	if usedBytes*4 <= elemSize {
		wastePct := ((elemSize - usedBytes) * 100) / elemSize
		pass.Reportf(rng.Pos(),
			"CPU L1d cache-bandwidth waste (AoS vs. SoA): loop iterates over %s (%dB / %d cache lines per element) but only reads field(s) [%s] (%dB used, %d%% of fetched cache lines wasted); split hot fields into a contiguous Struct-of-Arrays (SoA) slice",
			elemType.String(), elemSize, (elemSize+63)/64, strings.Join(fieldNames, ", "), usedBytes, wastePct)
	}
}

// checkModernGoRuntimeCalls inspects calls for legacy finalizers and pull-based iterator coroutines.
func checkModernGoRuntimeCalls(pass *analysis.Pass, call *ast.CallExpr) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	obj, ok := pass.TypesInfo.Uses[sel.Sel]
	if !ok || obj.Pkg() == nil {
		return
	}

	pkgPath := obj.Pkg().Path()
	funcName := obj.Name()

	// 1. Flag legacy runtime.SetFinalizer in favor of Go 1.24+ runtime.AddCleanup.
	if pkgPath == "runtime" && funcName == "SetFinalizer" {
		pass.Reportf(call.Pos(),
			"runtime.SetFinalizer resurrects objects for an extra GC cycle and leaks on reference cycles; use Go 1.24+ runtime.AddCleanup(ptr, cleanup, arg) which supports multiple cleanups, interior pointers, and zero-resurrection GC collection")
		return
	}

	// 2. Flag iter.Pull / iter.Pull2 which allocate coroutine state machines on the heap.
	if pkgPath == "iter" && (funcName == "Pull" || funcName == "Pull2") {
		pass.Reportf(call.Pos(),
			"iter.%s allocates a runtime coroutine (coro) and closure channels on the heap; prefer push-based `for v := range seq` so the Go compiler can inline the yield body with zero allocations",
			funcName)
	}
}

// checkAppendUnclampedSubslice detects `append(s[:n], elem...)` without a 3-index capacity clamp `s[:n:n]`,
// which silently overwrites the caller's backing array or pins a massive buffer in memory.
func checkAppendUnclampedSubslice(pass *analysis.Pass, call *ast.CallExpr) {
	ident, ok := call.Fun.(*ast.Ident)
	if !ok || ident.Name != "append" || len(call.Args) < 2 {
		return
	}
	sliceExpr, ok := call.Args[0].(*ast.SliceExpr)
	if !ok || sliceExpr.Slice3 || sliceExpr.High == nil {
		return
	}
	// If High is constant 0 (`s[:0]`), resetting a buffer for reuse is intentional; ignore `s[:0]`.
	if lit, isLit := sliceExpr.High.(*ast.BasicLit); isLit && lit.Value == "0" {
		return
	}
	pass.Reportf(sliceExpr.Pos(),
		"appending to 2-index subslice `s[low:high]` mutates shared backing memory if capacity remains; use 3-index slice `s[low:high:high]` to clamp capacity or `s[:0]` if intentionally reusing a buffer")
}

// checkSyncPoolValueBoxing detects passing non-pointer values (e.g. []byte slice headers or structs)
// into sync.Pool.Put(x), which boxes the 24-byte slice header onto the heap on every Put!
func checkSyncPoolValueBoxing(pass *analysis.Pass, call *ast.CallExpr) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Put" || len(call.Args) != 1 {
		return
	}

	recvType := pass.TypesInfo.TypeOf(sel.X)
	if recvType == nil {
		return
	}
	if ptr, isPtr := recvType.(*types.Pointer); isPtr {
		recvType = ptr.Elem()
	}
	named, ok := recvType.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return
	}
	if named.Obj().Pkg().Path() != "sync" || named.Obj().Name() != "Pool" {
		return
	}

	argType := pass.TypesInfo.TypeOf(call.Args[0])
	if argType == nil {
		return
	}

	// Note: In Go, a slice ([]byte) is a 24-byte 3-word struct header, NOT a single-word pointer!
	// Passing []byte to sync.Pool.Put(any) allocates 24 bytes on the heap via runtime.convTslice.
	if _, isSlice := argType.Underlying().(*types.Slice); isSlice {
		pass.Reportf(call.Args[0].Pos(),
			"sync.Pool.Put(%s) boxes the 24-byte slice header into `any`, allocating 24B on the heap per Put; store a pointer `*%s` (or `*bytes.Buffer`) in sync.Pool instead",
			argType.String(), argType.String())
		return
	}

	if argSz, ok := safeSizeof(pass.TypesSizes, argType); ok && !types.IsInterface(argType) && !isDirectIface(pass.TypesSizes, argType) && argSz > 0 {
		pass.Reportf(call.Args[0].Pos(),
			"sync.Pool.Put(%s) boxes a non-pointer value (%d bytes) into `any`, allocating on the heap; pass a pointer to sync.Pool.Put",
			argType.String(), argSz)
	}
}

// checkMapGCScan flags maps that fail to be 'noscan' due to strings/pointers and checks Go 1.24+ SwissTable
// 8-slot group geometry (128-byte inline key/elem threshold and 64B cache-line group sizing).
func checkMapGCScan(pass *analysis.Pass, mt *ast.MapType) {
	mtType := pass.TypesInfo.TypeOf(mt)
	if mtType == nil {
		return
	}
	mapType, ok := mtType.Underlying().(*types.Map)
	if !ok {
		return
	}

	kType := mapType.Key()
	vType := mapType.Elem()
	if !isSizedConcreteType(kType, nil) || !isSizedConcreteType(vType, nil) {
		return
	}
	kSz, _ := safeSizeof(pass.TypesSizes, kType)
	vSz, _ := safeSizeof(pass.TypesSizes, vType)

	// Rule 0: Detect maps keyed by bool or uint8/int8 where a fixed array ([2]V or [256]V) is O(1) with 0 hashing and 0 heap allocs.
	if basicKey, ok := kType.Underlying().(*types.Basic); ok {
		if basicKey.Kind() == types.Bool || basicKey.Kind() == types.Uint8 || basicKey.Kind() == types.Int8 {
			arrayLen := 256
			if basicKey.Kind() == types.Bool {
				arrayLen = 2
			}
			pass.Reportf(mt.Pos(),
				"lookup table hazard: map[%s]%s uses SwissTable hashing and heap buckets for a tiny key domain; replace with a flat value array `[%d]%s` for 1-cycle L1 cache indexing and 0 heap allocations",
				shortTypeString(kType), shortTypeString(vType), arrayLen, shortTypeString(vType))
		}
	}

	// Go 1.24+ SwissTable maps store 8 key-value slots per group with an 8-byte SIMD control word.
	// If Key or Value exceeds 128 bytes (maxKeySize / maxElemSize), the runtime silently converts the slot
	// into an indirect heap pointer, destroying SwissTable SIMD cache locality and forcing GC pointer scanning!
	if flagSwissMap && (kSz > 128 || vSz > 128) {
		pass.Reportf(mt.Pos(),
			"SwissTable indirect-allocation hazard: map[%s]%s has key=%dB, elem=%dB (>128B runtime inline limit), forcing the runtime to heap-allocate indirect pointers per entry and adding GC scan overhead; shrink below 128B or store a uint32 arena index",
			shortTypeString(kType), shortTypeString(vType), kSz, vSz)
	}

	kRes := inspectTypePointers(pass.TypesSizes, kType, "key", make(map[types.Type]bool))
	vRes := inspectTypePointers(pass.TypesSizes, vType, "value", make(map[types.Type]bool))

	if !kRes.hasPointers && !vRes.hasPointers {
		return // Already 100% GC noscan!
	}

	if kRes.onlyStringPtrs && vRes.onlyStringPtrs {
		pass.Reportf(mt.Pos(),
			"GC scan hazard: map[%s]%s is scanned on every GC cycle solely due to string headers (%s); integer IDs or fixed [N]byte keys make its groups pointer-free ('noscan')",
			shortTypeString(kType), shortTypeString(vType), firstNonEmpty(kRes.firstPointerPath, vRes.firstPointerPath))
	}
}

// checkLoopHazards detects heap-allocating defers, leaky time.After calls, string concatenation,
// dynamic interface dispatch, strconv.Format*/Itoa, and unsized map/slice allocations inside loops.
func checkLoopHazards(pass *analysis.Pass, body *ast.BlockStmt) {
	if body == nil {
		return
	}
	ast.Inspect(body, func(n ast.Node) bool {
		// If a function literal is defined inside a loop, warn if it captures outer variables
		if funcLit, isFuncLit := n.(*ast.FuncLit); isFuncLit {
			if flagHotLoopCalls {
				pass.Reportf(funcLit.Pos(),
					"closure literal inside loop risks allocating a closure context struct on the heap each iteration if it escapes; hoist helper function outside the loop")
			}
			return false
		}

		switch stmt := n.(type) {
		case *ast.DeferStmt:
			pass.Reportf(stmt.Pos(),
				"defer inside loop runs each deferred call only when the function returns, and every iteration adds one; call the function directly or move the loop body into a function")

		case *ast.AssignStmt:
			// Detect string concatenation `s += str` or `s = s + str` inside a loop
			if flagHotLoopCalls && len(stmt.Lhs) == 1 {
				if stmt.Tok == token.ADD_ASSIGN {
					if t := pass.TypesInfo.TypeOf(stmt.Lhs[0]); t != nil {
						if basic, ok := t.Underlying().(*types.Basic); ok && basic.Kind() == types.String {
							pass.Reportf(stmt.Pos(),
								"string concatenation (`+=`) inside loop calls `runtime.concatstrings` and allocates a new backing array every iteration; pre-allocate a `[]byte` buffer with `strconv.Append*` or `strings.Builder.Grow(n)`")
						}
					}
				} else if stmt.Tok == token.ASSIGN && len(stmt.Rhs) == 1 {
					if bin, isBin := stmt.Rhs[0].(*ast.BinaryExpr); isBin && bin.Op == token.ADD {
						if t := pass.TypesInfo.TypeOf(bin); t != nil {
							if basic, ok := t.Underlying().(*types.Basic); ok && basic.Kind() == types.String {
								pass.Reportf(stmt.Pos(),
									"string concatenation (`+`) inside loop calls `runtime.concatstrings` and allocates a new backing array every iteration; use `strconv.Append*` into a pre-allocated `[]byte` buffer")
							}
						}
					}
				}
			}

		case *ast.CallExpr:
			if sel, ok := stmt.Fun.(*ast.SelectorExpr); ok {
				if pkgIdent, ok := sel.X.(*ast.Ident); ok && pkgIdent.Name == "time" && sel.Sel.Name == "After" {
					pass.Reportf(stmt.Pos(),
						"time.After inside loop allocates a timer and a channel on every iteration; reuse one time.Timer with Reset")
				}
				if flagHotLoopCalls {
					// 1. Check for dynamic interface method dispatch inside a loop
					if selVal, ok := pass.TypesInfo.Selections[sel]; ok && selVal.Kind() == types.MethodVal {
						if recvType := selVal.Recv(); recvType != nil && types.IsInterface(recvType) {
							// Ignore error.Error() on cold return branches
							if recvType.String() != "error" {
								pass.Reportf(stmt.Pos(),
									"dynamic interface method call `%s.%s()` inside loop incurs `itab` pointer indirection, blocks compiler inlining, and forces pointer/slice arguments to escape to the heap; use generics or a concrete type on hot loops",
									shortTypeString(recvType), sel.Sel.Name)
							}
						}
					}
					// 2. Check for encoding/json, encoding/gob, fmt, and strconv.Itoa/Format* inside loops
					if obj, ok := pass.TypesInfo.Uses[sel.Sel]; ok && obj.Pkg() != nil {
						pkgPath := obj.Pkg().Path()
						fnName := sel.Sel.Name
						if (pkgPath == "encoding/json" || pkgPath == "encoding/gob") && (fnName == "Marshal" || fnName == "Unmarshal" || fnName == "Encode" || fnName == "Decode") {
							pass.Reportf(stmt.Pos(),
								"calling `%s.%s` inside loop triggers heavy reflection and heap allocations per iteration; use a zero-alloc binary codec or pooled buffer",
								obj.Pkg().Name(), fnName)
						} else if pkgPath == "strconv" && (fnName == "Itoa" || strings.HasPrefix(fnName, "Format")) {
							appendEquiv := strings.Replace(fnName, "Format", "Append", 1)
							if fnName == "Itoa" {
								appendEquiv = "AppendInt"
							}
							pass.Reportf(stmt.Pos(),
								"calling `strconv.%s` inside loop allocates a new heap string every iteration; use `strconv.%s(buf[:0], ...)` into a stack-allocated `[64]byte` scratch buffer for 0 allocations",
								fnName, appendEquiv)
						} else if pkgPath == "fmt" && strings.HasPrefix(fnName, "Sprint") {
							pass.Reportf(stmt.Pos(),
								"calling `fmt.%s` inside loop boxes arguments into `any` and allocates a new string every iteration; use `strconv.Append*` into a pre-allocated `[]byte` buffer",
								fnName)
						}
					}
				}
			}
			// Detect make(map[K]V) without capacity hint inside a loop
			if ident, ok := stmt.Fun.(*ast.Ident); ok && ident.Name == "make" && len(stmt.Args) == 1 {
				if mt := pass.TypesInfo.TypeOf(stmt.Args[0]); mt != nil {
					if _, isMap := mt.Underlying().(*types.Map); isMap {
						pass.Reportf(stmt.Pos(),
							"unsized `make(%s)` inside loop allocates a new map without capacity hint on each iteration; hoist map outside the loop and reuse via `clear(m)` (0 allocs), or pass an initial size hint `make(%s, cap)`",
							shortTypeString(mt), shortTypeString(mt))
					}
				}
			}
		}
		return true
	})
}

// checkStackFrameSize inspects //gc:zeroalloc functions for large local stack variables (>= 2048 bytes)
// that risk exceeding a fresh goroutine's 2KB stack and triggering a `runtime.morestack` stack-copying pause.
func checkStackFrameSize(pass *analysis.Pass, fn *ast.FuncDecl) {
	if fn.Body == nil {
		return
	}
	var totalStackBytes int64
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		decl, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for _, name := range decl.Names {
			if obj, ok := pass.TypesInfo.Defs[name]; ok && obj != nil {
				if sz, ok := safeSizeof(pass.TypesSizes, obj.Type()); ok && sz >= 256 {
					totalStackBytes += sz
				}
			}
		}
		return true
	})

	if totalStackBytes >= 2048 {
		pass.Reportf(fn.Pos(),
			"[//gc:zeroalloc] function %s allocates %d bytes of large local stack variables (>= 2KB fresh goroutine stack), risking a `runtime.morestack` stack-split & copy pause; call `gcopt.WarmGoroutineStack()` at worker startup",
			fn.Name.Name, totalStackBytes)
	}
}

// checkLargeHeapMakeForMmap detects `make([]T, N)` where total size >= 1 MiB and suggests
// off-heap anonymous `mmap` (`MAP_HUGETLB | MAP_POPULATE`) so the buffer is 100% invisible to Go's GC and GOMEMLIMIT.
func checkLargeHeapMakeForMmap(pass *analysis.Pass, call *ast.CallExpr) {
	ident, ok := call.Fun.(*ast.Ident)
	if !ok || ident.Name != "make" || len(call.Args) < 2 {
		return
	}
	sliceType, ok := pass.TypesInfo.TypeOf(call.Args[0]).Underlying().(*types.Slice)
	if !ok {
		return
	}
	elemSz, ok := safeSizeof(pass.TypesSizes, sliceType.Elem())
	if !ok || elemSz == 0 {
		return
	}
	sizeArg := call.Args[1]
	if len(call.Args) == 3 {
		sizeArg = call.Args[2]
	}
	if tv, ok := pass.TypesInfo.Types[sizeArg]; ok && tv.Value != nil && tv.Value.Kind() == constant.Int {
		if nElem, ok := constant.Int64Val(tv.Value); ok {
			totalBytes := nElem * elemSz
			if totalBytes >= 1024*1024 {
				pass.Reportf(call.Pos(),
					"large heap allocation: `make(%s, %d)` allocates %d KiB inside Go's GC-managed mheap; for ultra-low-latency zero-GC arenas, allocate off-heap via `unix.Mmap` with `MAP_HUGETLB|MAP_POPULATE` (or `gcopt.AllocOffHeapSlice`)",
					shortTypeString(sliceType), nElem, totalBytes/1024)
			}
		}
	}
}

func findLargeLocalMakeSize(pass *analysis.Pass, target types.Object, stack []ast.Node) int64 {
	var fnBody *ast.BlockStmt
	for i := len(stack) - 1; i >= 0; i-- {
		if fn, ok := stack[i].(*ast.FuncDecl); ok && fn.Body != nil {
			fnBody = fn.Body
			break
		}
	}
	if fnBody == nil {
		return 0
	}

	var foundBytes int64
	ast.Inspect(fnBody, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		lhsIdent, ok := assign.Lhs[0].(*ast.Ident)
		if !ok || pass.TypesInfo.Defs[lhsIdent] != target {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok || len(call.Args) < 2 {
			return true
		}
		if funIdent, ok := call.Fun.(*ast.Ident); !ok || funIdent.Name != "make" {
			return true
		}
		sliceType, ok := pass.TypesInfo.TypeOf(call.Args[0]).Underlying().(*types.Slice)
		if !ok {
			return true
		}
		elemSz, ok := safeSizeof(pass.TypesSizes, sliceType.Elem())
		if !ok {
			return true
		}
		sizeArg := call.Args[1]
		if len(call.Args) == 3 {
			sizeArg = call.Args[2]
		}
		if tv, ok := pass.TypesInfo.Types[sizeArg]; ok && tv.Value != nil && tv.Value.Kind() == constant.Int {
			if nElem, ok := constant.Int64Val(tv.Value); ok {
				foundBytes = nElem * elemSz
			}
		}
		return false
	})
	return foundBytes
}

// checkSliceZeroingLoop detects manual zeroing loops (`for i := range s { s[i] = 0 }`)
// and recommends the Go 1.21+ `clear(s)` builtin for vectorized memclr lowering.
func checkSliceZeroingLoop(pass *analysis.Pass, rng *ast.RangeStmt) {
	if rng.Value != nil || rng.Key == nil || rng.Body == nil || len(rng.Body.List) != 1 {
		return
	}
	keyIdent, ok := rng.Key.(*ast.Ident)
	if !ok {
		return
	}
	assign, ok := rng.Body.List[0].(*ast.AssignStmt)
	if !ok || assign.Tok != token.ASSIGN || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return
	}
	idxExpr, ok := assign.Lhs[0].(*ast.IndexExpr)
	if !ok {
		return
	}
	idxIdent, ok := idxExpr.Index.(*ast.Ident)
	if !ok || pass.TypesInfo.Uses[idxIdent] != pass.TypesInfo.Defs[keyIdent] {
		return
	}

	// Ensure the indexed slice is the exact same variable being ranged over
	sliceIdent1, ok1 := rng.X.(*ast.Ident)
	sliceIdent2, ok2 := idxExpr.X.(*ast.Ident)
	if !ok1 || !ok2 || pass.TypesInfo.Uses[sliceIdent1] != pass.TypesInfo.Uses[sliceIdent2] {
		return
	}

	// Check if RHS is a zero literal (`0`, `""`, `nil`, or empty composite literal `T{}`)
	isZeroVal := false
	switch rhs := assign.Rhs[0].(type) {
	case *ast.BasicLit:
		if rhs.Value == "0" || rhs.Value == `""` || rhs.Value == "0.0" {
			isZeroVal = true
		}
	case *ast.Ident:
		if rhs.Name == "nil" || rhs.Name == "false" {
			isZeroVal = true
		}
	case *ast.CompositeLit:
		if len(rhs.Elts) == 0 {
			isZeroVal = true
		}
	}

	if isZeroVal {
		pass.Reportf(rng.Pos(),
			"manual slice-zeroing loop over `%s`; use the Go 1.21+ `clear(%s)` builtin to guarantee bulk vectorized `runtime.memclrNoHeapPointers` without per-element write barriers",
			sliceIdent1.Name, sliceIdent1.Name)
	}
}

// checkSubsliceMemoryPinning detects returning an unclamped subslice (`return buf[low:high]`)
// of a locally allocated large slice (>= 4096B), which pins the entire backing array in the GC heap.
func checkSubsliceMemoryPinning(pass *analysis.Pass, ret *ast.ReturnStmt, stack []ast.Node) {
	for _, res := range ret.Results {
		sliceExpr, ok := res.(*ast.SliceExpr)
		if !ok || sliceExpr.Slice3 {
			continue
		}
		baseIdent, ok := sliceExpr.X.(*ast.Ident)
		if !ok {
			continue
		}
		obj := pass.TypesInfo.Uses[baseIdent]
		if obj == nil {
			continue
		}
		if allocBytes := findLargeLocalMakeSize(pass, obj, stack); allocBytes >= 4096 {
			pass.Reportf(sliceExpr.Pos(),
				"subslice memory pinning hazard: returning subslice `%s[...]` pins the entire %d-byte backing array in the GC live heap; copy into a tight slice (`bytes.Clone` / `slices.Clone`) if long-lived",
				baseIdent.Name, allocBytes)
		}
	}
}

// checkRangeCopyAndHazards checks both loop hazards and large value copies in range loops.
func checkRangeCopyAndHazards(pass *analysis.Pass, rng *ast.RangeStmt) {
	checkLoopHazards(pass, rng.Body)

	if rng.Value == nil {
		return
	}
	valType := pass.TypesInfo.TypeOf(rng.Value)
	if !isSizedConcreteType(valType, nil) {
		return
	}
	sz, ok := safeSizeof(pass.TypesSizes, valType)
	if !ok {
		return
	}

	// The loop copies each element into the value variable on the stack. A store to the stack does not
	// need a write barrier. The copy costs the same for an element with pointers and an element without.
	if sz >= 64 {
		pass.Reportf(rng.Value.Pos(),
			"ranging by value over %s copies %d bytes per iteration; use index-based iteration (for i := range s) to avoid the copy",
			valType.String(), sz)
	}
}

// runSSAChecks reports, with -hints, the latency hints of the functions that the analyzer
// checks: goroutines, channel operations, locks, map iteration, modulo and pointers passed to
// interface methods. The compiler's records decide every allocation, so these checks report
// none.
func runSSAChecks(pass *analysis.Pass, ssaInput *buildssa.SSA, zeroAllocFuncs map[*types.Func]bool, ignored map[string]bool) {
	for _, fn := range ssaInput.SrcFuncs {
		fnObj, ok := fn.Object().(*types.Func)
		if !ok || fnObj == nil || !zeroAllocFuncs[fnObj] {
			continue
		}
		for _, block := range fn.Blocks {
			// Harden against false positives: skip cold panic/fatal/error-construction basic blocks
			if isColdErrorOrPanicBlock(block) {
				continue
			}
			for _, instr := range block.Instrs {
				if isIgnored(pass, instr.Pos(), ignored) {
					continue
				}
				checkSSAInstruction(pass, fn, instr)
			}
		}
	}
}

// isColdErrorOrPanicBlock returns true if a basic block unconditionally terminates in a panic
// or returns a newly constructed error on a cold failure branch, preventing false positives on hot paths.
func isColdErrorOrPanicBlock(b *ssa.BasicBlock) bool {
	if len(b.Instrs) == 0 {
		return false
	}
	last := b.Instrs[len(b.Instrs)-1]
	if _, isPanic := last.(*ssa.Panic); isPanic {
		return true
	}
	return false
}

// localRoot returns the variable or the allocation of the calling function that v points into.
// It follows slices, field addresses, element addresses and conversions back to that variable.
// It returns nil when v comes from a parameter, a global, a loaded pointer or a call result.
func localRoot(v ssa.Value) *ssa.Alloc {
	for {
		switch x := v.(type) {
		case *ssa.Alloc:
			return x
		case *ssa.Slice:
			v = x.X
		case *ssa.FieldAddr:
			v = x.X
		case *ssa.IndexAddr:
			v = x.X
		case *ssa.ChangeType:
			v = x.X
		case *ssa.MakeInterface:
			v = x.X
		default:
			return nil
		}
	}
}

// interfaceArgRoot returns the first argument of an interface method call that points into a
// variable of the calling function. It also returns that variable. The compiler cannot see
// the method that the call runs, so it moves the variable to the heap. The compiler keeps the
// variable on the stack when it inlines the constructor of the receiver and calls the method
// directly. The call h.Write(buf[:]) after h := sha256.New() is such a case, so the finding is
// a hint. interfaceArgRoot returns nils for a static call. It also returns nils when every
// argument points to memory that exists before the call, as an interface value and a
// parameter do.
func interfaceArgRoot(call *ssa.Call) (ssa.Value, *ssa.Alloc) {
	if !call.Call.IsInvoke() {
		return nil, nil
	}
	for _, arg := range call.Call.Args {
		if root := localRoot(arg); root != nil {
			return arg, root
		}
	}
	return nil, nil
}

// reportPos returns the position at which to report instr. go/ssa does not give a position to
// an instruction that it synthesizes. The boxing of a returned value is one example. For such an
// instruction, reportPos returns the position of the first instruction that uses it, or else
// the position of the function.
func reportPos(fn *ssa.Function, instr ssa.Instruction) token.Pos {
	if pos := instr.Pos(); pos.IsValid() {
		return pos
	}
	if v, ok := instr.(ssa.Value); ok && v.Referrers() != nil {
		for _, ref := range *v.Referrers() {
			if pos := ref.Pos(); pos.IsValid() {
				return pos
			}
		}
	}
	return fn.Pos()
}

// checkSSAInstruction reports the latency hint of one instruction, with -hints.
func checkSSAInstruction(pass *analysis.Pass, fn *ssa.Function, instr ssa.Instruction) {
	pos := reportPos(fn, instr)
	switch ins := instr.(type) {
	case *ssa.Go:
		// Spawning a goroutine inside a zero-alloc hot path allocates or acquires a 2KB stack and runtime.g.
		pass.Reportf(pos,
			"[//gc:zeroalloc] spawning a goroutine (`go ...`) in %s allocates a goroutine descriptor/stack and adds scheduler latency; dispatch to a pre-spawned worker pool",
			fn.Name())

	case *ssa.MapUpdate:
		// Map assignment `m[k] = v` compiles to an *ssa.MapUpdate (not an *ssa.Call), which invokes runtime.mapassign
		// and dynamically allocates overflow buckets or triggers evacuation growth on the heap.
		pass.Reportf(pos,
			"[//gc:zeroalloc] map mutation `m[%s] = %s` in %s invokes `runtime.mapassign`, which may allocate overflow buckets on the heap and triggers GC write barriers; use a pre-allocated flat slice/arena on the hot path",
			ins.Key.Type().String(), ins.Value.Type().String(), fn.Name())

	case *ssa.Send:
		// Sending on a Go channel (`ch <- v`) inside a zero-alloc / low-latency hot path acquires `hchan.lock`
		// (a runtime spin-mutex), copies data, and can park the goroutine via `gopark`.
		pass.Reportf(pos,
			"[//gc:zeroalloc] channel send (`ch <- ...`) in %s acquires an internal `hchan.lock` mutex and triggers Go scheduler context switches; use a lock-free SPSC/MPSC ring buffer (`SPSCDisruptor`) on hot paths",
			fn.Name())

	case *ssa.Select:
		// `select` sorts channel pointers, locks every case's `hchan.lock`, and allocates/queues `runtime.sudog` on blocking paths.
		pass.Reportf(pos,
			"[//gc:zeroalloc] `select` statement in %s locks all participating channels and allocates/links `runtime.sudog` wait nodes when contended; use non-blocking atomic sequence polling instead",
			fn.Name())

	case *ssa.Range:
		// In Go SSA, *ssa.Range is emitted ONLY for `for range string` or `for range map` (slice/array ranges lower to index loops).
		// Ranging over a map in a hot path initializes a 96-byte runtime.hiter struct containing pointers (triggering write barriers).
		if _, isMap := ins.X.Type().Underlying().(*types.Map); isMap {
			pass.Reportf(pos,
				"[//gc:zeroalloc] ranging over %s in %s initializes a `runtime.hiter` iterator with GC write barriers and non-deterministic bucket scans; iterate over a flat slice on hot paths",
				ins.X.Type().String(), fn.Name())
		}

	case *ssa.BinOp:
		// LMAX Disruptor / Ring-Buffer rule: integer modulo (`seq % capacity`) compiles to IDIV/UDIV (~20-40 CPU cycles).
		// Power-of-two capacity with bitwise AND (`seq & mask`) compiles to a 1-cycle AND instruction.
		if flagDisruptor && ins.Op == token.REM {
			if basic, ok := ins.X.Type().Underlying().(*types.Basic); ok && (basic.Info()&types.IsInteger) != 0 {
				// Only flag if the divisor is NOT a compile-time constant power of two (which the compiler already optimizes).
				if c, isConst := ins.Y.(*ssa.Const); !isConst || !isPowerOfTwoConst(c) {
					pass.Reportf(pos,
						"[//gc:zeroalloc] integer modulo by a non-constant divisor in %s compiles to a division instruction of tens of cycles; a power-of-two capacity lets a bitwise AND (`seq & indexMask`) take one cycle",
						fn.Name())
				}
			}
		}

	case *ssa.Call:
		if ins.Call.IsInvoke() {
			// The compiler cannot see the method. It moves a local variable to the heap when an argument points into it.
			if arg, _ := interfaceArgRoot(ins); arg != nil {
				pass.Reportf(pos,
					"[//gc:zeroalloc] passing pointer/slice argument (%s) to interface method %s.%s defeats compiler escape analysis and forces arguments onto the heap",
					arg.Type().String(), ins.Call.Value.Type().String(), ins.Call.Method.Name())
			}
			return
		}

		// unique.Make, iter.Pull and the locks of package sync.
		if callee := ins.Call.StaticCallee(); callee != nil {
			isModernStdlibHotPathHazard(pass, ins, callee, fn)
		}
	}
}

func isPowerOfTwoConst(c *ssa.Const) bool {
	v, ok := constInt64(c)
	return ok && v > 0 && (v&(v-1)) == 0
}

func constInt64(val ssa.Value) (int64, bool) {
	c, ok := val.(*ssa.Const)
	if !ok || c == nil || c.IsNil() || c.Value == nil || c.Value.Kind() != constant.Int {
		return 0, false
	}
	return constant.Int64Val(c.Value)
}

// shortTypeString strips full module import paths (e.g. "go.thesmos.sh/sharder/shard.NodeID" -> "shard.NodeID")
// so diagnostic output stays compact and readable.
func shortTypeString(t types.Type) string {
	if t == nil {
		return "<nil>"
	}
	return types.TypeString(t, func(pkg *types.Package) string {
		if pkg == nil {
			return ""
		}
		return pkg.Name()
	})
}

// isModernStdlibHotPathHazard checks calls to `unique.Make` and `iter.Pull` inside `//gc:zeroalloc` functions.
func isModernStdlibHotPathHazard(pass *analysis.Pass, call *ssa.Call, callee *ssa.Function, caller *ssa.Function) bool {
	if callee.Pkg == nil || callee.Pkg.Pkg == nil {
		return false
	}
	pkgPath := callee.Pkg.Pkg.Path()
	name := callee.Name()

	// unique.Make[T](val) consults a concurrent global canonicalization map and allocates a weak clone on cache misses.
	if pkgPath == "unique" && strings.HasPrefix(name, "Make") {
		pass.Reportf(call.Pos(),
			"[//gc:zeroalloc] calling unique.Make in %s performs global concurrent trie-map lookups and allocates on uncached values; canonicalize values into unique.Handle[T] at ingestion/config time outside the hot loop",
			caller.Name())
		return true
	}

	// iter.Pull / iter.Pull2 allocates coroutine state on the heap.
	if pkgPath == "iter" && strings.HasPrefix(name, "Pull") {
		pass.Reportf(call.Pos(),
			"[//gc:zeroalloc] calling %s in %s allocates a heap coroutine (`runtime.coro`); use a push iterator (`for x := range seq`) instead",
			name, caller.Name())
		return true
	}

	// sync.Mutex.Lock / sync.RWMutex.RLock inside //gc:zeroalloc hot path risks parking the goroutine via runtime.gopark
	if pkgPath == "sync" && (name == "Lock" || name == "RLock") {
		pass.Reportf(call.Pos(),
			"[//gc:zeroalloc] calling %s in %s risks goroutine parking (`runtime.gopark` / `semacquire`) under contention; prefer lock-free `sync/atomic` operations or per-core sharding on ultra-low-latency paths",
			callee.String(), caller.Name())
		return true
	}

	return false
}

// inspectTypePointers recursively computes exact pointer byte spans and checks if pointers are exclusively strings.
func inspectTypePointers(sizes types.Sizes, t types.Type, path string, seen map[types.Type]bool) pointerAnalysis {
	if !isSizedConcreteType(t, nil) {
		return pointerAnalysis{hasPointers: false, onlyStringPtrs: true, totalSize: 0}
	}
	if seen[t] {
		return pointerAnalysis{hasPointers: true, onlyStringPtrs: false, firstPointerPath: path}
	}
	seen[t] = true
	defer delete(seen, t)

	totalSz, ok := safeSizeof(sizes, t)
	if !ok {
		return pointerAnalysis{hasPointers: false, onlyStringPtrs: true, totalSize: 0}
	}
	wordSz := sizes.Sizeof(types.Typ[types.Uintptr])

	switch u := t.Underlying().(type) {
	case *types.Basic:
		if u.Kind() == types.String {
			// String header is {Data *byte, Len int} -> pointer is in the first word
			return pointerAnalysis{
				hasPointers:      true,
				onlyStringPtrs:   true,
				firstPointerPath: path + " (string)",
				pointerByteSpan:  wordSz,
				totalSize:        totalSz,
			}
		}
		if u.Kind() == types.UnsafePointer {
			return pointerAnalysis{
				hasPointers:      true,
				onlyStringPtrs:   false,
				firstPointerPath: path + " (unsafe.Pointer)",
				pointerByteSpan:  wordSz,
				totalSize:        totalSz,
			}
		}
		return pointerAnalysis{hasPointers: false, onlyStringPtrs: true, totalSize: totalSz}

	case *types.Pointer, *types.Map, *types.Chan, *types.Signature:
		return pointerAnalysis{
			hasPointers:      true,
			onlyStringPtrs:   false,
			firstPointerPath: fmt.Sprintf("%s (%s)", path, u.String()),
			pointerByteSpan:  wordSz,
			totalSize:        totalSz,
		}

	case *types.Slice:
		// Slice header is {Data *T, Len int, Cap int} -> pointer in first word
		return pointerAnalysis{
			hasPointers:      true,
			onlyStringPtrs:   false,
			firstPointerPath: fmt.Sprintf("%s ([]%s)", path, u.Elem().String()),
			pointerByteSpan:  wordSz,
			totalSize:        totalSz,
		}

	case *types.Interface:
		return pointerAnalysis{
			hasPointers:      true,
			onlyStringPtrs:   false,
			firstPointerPath: path + " (interface)",
			pointerByteSpan:  totalSz,
			totalSize:        totalSz,
		}

	case *types.Array:
		if u.Len() == 0 {
			return pointerAnalysis{hasPointers: false, onlyStringPtrs: true, totalSize: 0}
		}
		elemRes := inspectTypePointers(sizes, u.Elem(), path+"[0]", seen)
		if !elemRes.hasPointers {
			return pointerAnalysis{hasPointers: false, onlyStringPtrs: true, totalSize: totalSz}
		}
		elemSz, _ := safeSizeof(sizes, u.Elem())
		ptrSpan := (u.Len()-1)*elemSz + elemRes.pointerByteSpan
		return pointerAnalysis{
			hasPointers:      true,
			onlyStringPtrs:   elemRes.onlyStringPtrs,
			firstPointerPath: elemRes.firstPointerPath,
			pointerByteSpan:  ptrSpan,
			totalSize:        totalSz,
		}

	case *types.Struct:
		numFields := u.NumFields()
		if numFields == 0 {
			return pointerAnalysis{hasPointers: false, onlyStringPtrs: true, totalSize: 0}
		}

		fields := make([]*types.Var, numFields)
		for i := 0; i < numFields; i++ {
			fields[i] = u.Field(i)
		}
		offsets, ok := safeOffsetsof(sizes, fields)
		if !ok {
			return pointerAnalysis{hasPointers: false, onlyStringPtrs: true, totalSize: totalSz}
		}

		hasPtr := false
		onlyStrings := true
		firstPath := ""
		var lastPtrByte int64 = 0

		for i, f := range fields {
			fPath := path + "." + f.Name()
			fRes := inspectTypePointers(sizes, f.Type(), fPath, seen)
			if fRes.hasPointers {
				if !hasPtr {
					firstPath = fRes.firstPointerPath
				}
				hasPtr = true
				if !fRes.onlyStringPtrs {
					onlyStrings = false
				}
				endPtr := offsets[i] + fRes.pointerByteSpan
				if endPtr > lastPtrByte {
					lastPtrByte = endPtr
				}
			}
		}

		return pointerAnalysis{
			hasPointers:      hasPtr,
			onlyStringPtrs:   onlyStrings,
			firstPointerPath: firstPath,
			pointerByteSpan:  lastPtrByte,
			totalSize:        totalSz,
		}

	default:
		return pointerAnalysis{hasPointers: false, onlyStringPtrs: true, totalSize: totalSz}
	}
}

// isDirectIface reports whether the compiler stores a value of type t in the data word of an
// interface. Such a conversion does not allocate. The compiler's rule in types.IsDirectIface
// requires that t is one word long and that the word is a pointer. Pointers, maps, channels,
// funcs and unsafe.Pointer meet the rule. A struct of one such field and an array of one such
// element meet it too. A string, a slice and an interface are longer than one word.
func isDirectIface(sizes types.Sizes, t types.Type) bool {
	res := inspectTypePointers(sizes, t, "", make(map[types.Type]bool))
	wordSz := sizes.Sizeof(types.Typ[types.Uintptr])
	return res.hasPointers && res.totalSize == wordSz && res.pointerByteSpan == wordSz
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
