// Copyright Stealth Scale B.V. 2026
// SPDX-License-Identifier: MIT

package gcopt

import (
	"cmp"
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/go/types/typeutil"
)

// allocSite is an allocation in the body of a function: a heap record of the compiler, or a
// make of a channel, which the compiler does not report.
type allocSite struct {
	pos token.Pos
	msg string
}

// inlinedSite is an allocation that the compiler reports at a call site that it inlined. The
// body of callee produced it, and it counts only when callee allocates in its own body.
type inlinedSite struct {
	pos    token.Pos
	callee *types.Func
	msg    string
}

// callSite is a static call that runs on a path that does not end in an error or a panic.
type callSite struct {
	pos     token.Pos
	callee  *types.Func
	inlined bool
}

// funcAllocs contains the allocations of one function and the reasons that it allocates.
type funcAllocs struct {
	obj     *types.Func
	decl    *ast.FuncDecl
	allocs  []allocSite
	inlined []inlinedSite
	calls   []callSite
	direct  string // the first allocation in the function's own compiled body, or ""
	call    string // the first call of a function that allocates, or ""
}

// checkAllocations exports an AllocatesFact for every function of the package that allocates
// on a path that does not end in an error or a panic, and reports the allocations of each
// function in zeroAllocFuncs. The compiler's escape analysis decides every allocation:
//
//   - A "moved to heap" variable allocates.
//   - An "escapes to heap" expression allocates unless the compiler stores it without an
//     allocation: a constant, a static composite literal, a zero-sized value, a bool or a
//     single byte, a pointer-shaped value and a func literal without captured variables.
//   - The compiler reports the allocations of an inlined callee at the call site. They count
//     when the callee allocates in its own body, so an allocation on the error path of the
//     callee does not count.
//   - A call that the compiler does not inline allocates when its callee has an AllocatesFact.
//     An inlined call allocates when the callee calls a function that allocates.
//   - make(chan T) allocates, because the runtime creates every channel on the heap.
//
// Allocations in a branch that returns an error or panics do not count, nor do allocations
// on a line that //gc:ignore covers.
func checkAllocations(pass *analysis.Pass, recs *compilerRecords, zeroAllocFuncs map[*types.Func]bool, ignored map[string]bool) {
	var fns []*funcAllocs
	byObj := make(map[*types.Func]*funcAllocs)
	for _, file := range pass.Files {
		for _, d := range file.Decls {
			decl, ok := d.(*ast.FuncDecl)
			if !ok || decl.Body == nil {
				continue
			}
			obj, ok := pass.TypesInfo.Defs[decl.Name].(*types.Func)
			if !ok {
				continue
			}
			fa := collectFuncAllocs(pass, recs, file, decl, obj, ignored)
			fns = append(fns, fa)
			byObj[obj] = fa
		}
	}

	// Each pass of the loop can only turn an empty reason into a non-empty one, so the loop ends.
	for changed := true; changed; {
		changed = false
		for _, fa := range fns {
			if fa.direct == "" {
				for _, s := range fa.inlined {
					if calleeDirect(pass, byObj, s.callee) != "" {
						fa.direct = siteReason(pass, s.pos, s.msg)
						changed = true
						break
					}
				}
			}
			if fa.call == "" {
				for _, c := range fa.calls {
					if r := inheritedReason(pass, byObj, c); r != "" {
						fa.call = "calls " + c.callee.Name() + " -> " + r
						changed = true
						break
					}
				}
			}
		}
	}

	for _, fa := range fns {
		if fa.direct != "" || fa.call != "" {
			pass.ExportObjectFact(fa.obj, &AllocatesFact{Direct: fa.direct, Call: fa.call})
		}
		if zeroAllocFuncs[fa.obj] {
			reportAllocations(pass, byObj, fa, ignored)
		}
	}
}

// collectFuncAllocs gathers the allocation records, the allocating makes and the static calls
// of decl that run on a path that does not end in an error or a panic.
//
// The body of a func literal counts only when decl calls the literal itself, as in
// func() { ... }() and defer func() { ... }(), and the compiler does not inline that call. The
// compiler reports an inlined call at its opening parenthesis. A literal that decl passes to
// another function or starts as a goroutine runs when and where that function or goroutine
// decides, such as the constructor that a cache calls on a miss.
//
// ponytail: the compiler reports the allocations of a range-over-func loop body at the for
// statement, so an allocation on an error path inside such a body counts. The JSON log of
// the compiler (-gcflags=-json=0,DIR) has the inner positions, but the build cache does not
// replay it.
func collectFuncAllocs(pass *analysis.Pass, recs *compilerRecords, file *ast.File, decl *ast.FuncDecl, obj *types.Func, ignored map[string]bool) *funcAllocs {
	fa := &funcAllocs{obj: obj, decl: decl}
	name := canonicalPath(pass.Fset.Position(file.Pos()).Filename)

	// Static calls by the position of their opening parenthesis, where the compiler reports an
	// inlined call and the allocations of the inlined body.
	callees := make(map[token.Pos]*types.Func)
	invoked := make(map[*ast.FuncLit]bool)
	goroutines := make(map[*ast.FuncLit]bool)
	var elsewhere [][2]token.Pos // bodies of the func literals that run elsewhere
	ast.Inspect(decl.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.GoStmt:
			if lit, ok := ast.Unparen(n.Call.Fun).(*ast.FuncLit); ok {
				goroutines[lit] = true
			}
			return true
		case *ast.FuncLit:
			if !invoked[n] {
				elsewhere = append(elsewhere, [2]token.Pos{n.Body.Lbrace, n.Body.Rbrace})
				return false
			}
			return true
		case *ast.CallExpr:
			// When the compiler inlines the call, the inlined copy at the call site runs, and the
			// records in the body of the literal belong to its own compiled function.
			if lit, ok := ast.Unparen(n.Fun).(*ast.FuncLit); ok && !goroutines[lit] && !recs.inlined[compilerKey(pass, n.Lparen)] {
				invoked[lit] = true
			}
		default:
			return true
		}

		call := n.(*ast.CallExpr)
		if t, ok := makeChanType(pass.TypesInfo, call); ok {
			if hot(pass, file, call.Pos(), true, ignored) {
				fa.allocs = append(fa.allocs, allocSite{
					pos: call.Pos(),
					msg: fmt.Sprintf("make(%s) allocates a channel", types.TypeString(t, types.RelativeTo(pass.Pkg))),
				})
			}
			return true
		}
		callee := typeutil.StaticCallee(pass.TypesInfo, call)
		if callee == nil {
			return true
		}
		callees[call.Lparen] = callee
		if hot(pass, file, call.Lparen, false, ignored) {
			fa.calls = append(fa.calls, callSite{
				pos:     call.Lparen,
				callee:  callee,
				inlined: recs.inlined[compilerKey(pass, call.Lparen)],
			})
		}
		return true
	})
	runsElsewhere := func(pos token.Pos) bool {
		for _, span := range elsewhere {
			if span[0] <= pos && pos <= span[1] {
				return true
			}
		}
		return false
	}

	for _, rec := range recs.heap[name] {
		pos, ok := recordPos(pass, file, rec)
		if !ok || pos < decl.Pos() || pos > decl.End() || runsElsewhere(pos) || !hot(pass, file, pos, true, ignored) {
			continue
		}
		if !recordAllocates(pass, file, pos, rec.msg) {
			continue
		}
		// A value whose type implements error is an error under construction, such as
		// e := &StatusError{...} before the function returns e.
		if e := exprAt(file, pos); e != nil && implementsError(pass.TypesInfo.TypeOf(e)) && !types.IsInterface(pass.TypesInfo.TypeOf(e)) {
			continue
		}
		callee := callees[pos]
		if callee != nil && recs.inlined[compilerKey(pass, pos)] && !strings.HasPrefix(rec.msg, compilerArgument) {
			fa.inlined = append(fa.inlined, inlinedSite{pos: pos, callee: callee, msg: rec.msg})
			continue
		}
		fa.allocs = append(fa.allocs, allocSite{pos: pos, msg: rec.msg})
	}
	slices.SortStableFunc(fa.allocs, func(a, b allocSite) int { return cmp.Compare(a.pos, b.pos) })
	if len(fa.allocs) > 0 {
		fa.direct = siteReason(pass, fa.allocs[0].pos, fa.allocs[0].msg)
	}
	return fa
}

// reportAllocations reports the allocations, the counted inlined allocations and the
// allocating calls of fa, and with -writebarriers and -conditional the write barriers and
// the appends that can grow.
func reportAllocations(pass *analysis.Pass, byObj map[*types.Func]*funcAllocs, fa *funcAllocs, ignored map[string]bool) {
	name := fa.obj.Name()
	for _, s := range fa.allocs {
		if !isIgnored(pass, s.pos, ignored) {
			pass.Reportf(s.pos, "[//gc:zeroalloc] %s allocates: %s", name, s.msg)
		}
	}
	for _, s := range fa.inlined {
		if calleeDirect(pass, byObj, s.callee) != "" && !isIgnored(pass, s.pos, ignored) {
			pass.Reportf(s.pos, "[//gc:zeroalloc] %s allocates in inlined %s: %s", name, s.callee.Name(), s.msg)
		}
	}
	for _, c := range fa.calls {
		if r := inheritedReason(pass, byObj, c); r != "" && !isIgnored(pass, c.pos, ignored) {
			pass.Reportf(c.pos, "[//gc:zeroalloc] %s calls %s, which allocates: %s", name, c.callee.Name(), r)
		}
	}
}

// reportCompilerHints reports, for each function in zeroAllocFuncs, the write barriers with
// -writebarriers and the appends whose growth allocates with -conditional.
func reportCompilerHints(pass *analysis.Pass, recs *compilerRecords, zeroAllocFuncs map[*types.Func]bool, ignored map[string]bool) {
	if !flagWriteBarriers && !flagConditional {
		return
	}
	for _, file := range pass.Files {
		name := canonicalPath(pass.Fset.Position(file.Pos()).Filename)
		for _, d := range file.Decls {
			decl, ok := d.(*ast.FuncDecl)
			if !ok || decl.Body == nil {
				continue
			}
			obj, ok := pass.TypesInfo.Defs[decl.Name].(*types.Func)
			if !ok || !zeroAllocFuncs[obj] {
				continue
			}
			report := func(rs []compilerRecord, format string) {
				for _, rec := range rs {
					pos, ok := recordPos(pass, file, rec)
					if ok && pos >= decl.Pos() && pos <= decl.End() && hot(pass, file, pos, true, ignored) && !isIgnored(pass, pos, ignored) {
						pass.Reportf(pos, format, obj.Name())
					}
				}
			}
			if flagWriteBarriers {
				report(recs.barriers[name], "[//gc:zeroalloc] %s has a write barrier: the store calls runtime.gcWriteBarrier while the GC marks")
			}
			if flagConditional {
				report(recs.appends[name], "[//gc:zeroalloc] %s may allocate: append grows the slice on the heap when it lacks capacity")
			}
		}
	}
}

// checkInlineDirectives reports each function of decls that the compiler does not inline.
func checkInlineDirectives(pass *analysis.Pass, recs *compilerRecords, decls []*ast.FuncDecl) {
	for _, decl := range decls {
		key := compilerKey(pass, decl.Pos())
		key.col = 0
		if !recs.canInline[key] {
			pass.Reportf(decl.Pos(), "[//gc:inline] the compiler does not inline %s; build with -gcflags=-m=2 for the reason", decl.Name.Name)
		}
	}
}

// warmFuncs lists functions of the standard library that allocate only on a path that a warm
// caller does not take, so a call of one of them does not count:
//
//   - sync.Pool allocates its per-P array on the first use and a ring of its chain when the
//     chain grows.
//   - strconv.AppendInt and strconv.AppendUint reach the string allocation of formatBits only
//     on the path of FormatInt.
//
// testing.AllocsPerRun measures 0 allocations for a warm call of each on Go 1.27.2.
var warmFuncs = map[string]bool{
	"(*sync.Pool).Get":   true,
	"(*sync.Pool).Put":   true,
	"strconv.AppendInt":  true,
	"strconv.AppendUint": true,
}

// calleeDirect returns the first allocation in the own body of callee, from this package or
// from the AllocatesFact of another package.
func calleeDirect(pass *analysis.Pass, byObj map[*types.Func]*funcAllocs, callee *types.Func) string {
	if warmFuncs[callee.FullName()] {
		return ""
	}
	if fa, ok := byObj[callee]; ok {
		return fa.direct
	}
	var fact AllocatesFact
	if pass.ImportObjectFact(callee, &fact) {
		return fact.Direct
	}
	return ""
}

// inheritedReason returns why the call c allocates, or "". An inlined call allocates through
// the calls of its callee. Other calls allocate when the callee allocates at all.
func inheritedReason(pass *analysis.Pass, byObj map[*types.Func]*funcAllocs, c callSite) string {
	if warmFuncs[c.callee.FullName()] {
		return ""
	}
	var direct, call string
	if fa, ok := byObj[c.callee]; ok {
		direct, call = fa.direct, fa.call
	} else {
		var fact AllocatesFact
		if !pass.ImportObjectFact(c.callee, &fact) {
			return ""
		}
		direct, call = fact.Direct, fact.Call
	}
	if c.inlined || direct == "" {
		return call
	}
	return direct
}

// siteReason returns the reason of an AllocatesFact for the record msg at pos.
func siteReason(pass *analysis.Pass, pos token.Pos, msg string) string {
	p := pass.Fset.Position(pos)
	return fmt.Sprintf("%s:%d: %s", filepath.Base(p.Filename), p.Line, msg)
}

// compilerKey returns the compiler's position for pos.
func compilerKey(pass *analysis.Pass, pos token.Pos) compilerPos {
	p := pass.Fset.Position(pos)
	return compilerPos{file: canonicalPath(p.Filename), line: p.Line, col: p.Column}
}

// recordPos returns the position in file of a compiler record, and false when the record is
// outside the file, as for a file that cgo generates.
func recordPos(pass *analysis.Pass, file *ast.File, rec compilerRecord) (token.Pos, bool) {
	tf := pass.Fset.File(file.Pos())
	if tf == nil || rec.line < 1 || rec.line > tf.LineCount() || rec.col < 1 {
		return token.NoPos, false
	}
	offset := tf.Offset(tf.LineStart(rec.line)) + rec.col - 1
	if offset > tf.Size() {
		return token.NoPos, false
	}
	return tf.Pos(offset), true
}

// hot reports whether pos runs on a path that does not end in an error or a panic, and is
// not on a line that //gc:ignore covers. construction is true for an allocation of the
// compiler, which counts as part of an error when it is inside the expression of the error.
// It is false for a call, whose callee can do work before it returns an error.
func hot(pass *analysis.Pass, file *ast.File, pos token.Pos, construction bool, ignored map[string]bool) bool {
	p := pass.Fset.Position(pos)
	if ignored[fmt.Sprintf("%s:%d", p.Filename, p.Line)] {
		return false
	}
	return !onColdPath(pass.TypesInfo, file, pos, construction)
}

// onColdPath reports whether pos is inside a call of panic or of an error constructor, inside
// a branch whose last statement returns an error or panics, or inside a branch that a
// constant condition excludes. With construction it also reports whether pos is inside the
// error result of a return statement, or inside a value that a statement assigns to a
// variable whose type implements error.
func onColdPath(info *types.Info, file *ast.File, pos token.Pos, construction bool) bool {
	path, _ := astutil.PathEnclosingInterval(file, pos, pos)
	sig := enclosingSignature(info, path)
	for i, n := range path {
		switch n := n.(type) {
		case *ast.FuncLit, *ast.FuncDecl:
			return false
		case *ast.CallExpr:
			if isPanicCall(info, n) {
				return true
			}
			if callee := typeutil.StaticCallee(info, n); callee != nil && errorConstructors[callee.FullName()] {
				return true // the call and its arguments build an error
			}
		case *ast.ReturnStmt:
			if e := errorResult(info, sig, n); construction && e != nil && e.Pos() <= pos && pos < e.End() {
				return true
			}
		case *ast.AssignStmt:
			if construction && len(n.Lhs) == len(n.Rhs) {
				for j, rhs := range n.Rhs {
					if rhs.Pos() <= pos && pos < rhs.End() && isErrorValue(info, n.Lhs[j], rhs) {
						return true
					}
				}
			}
		case *ast.ValueSpec:
			if construction && len(n.Names) == len(n.Values) {
				for j, v := range n.Values {
					if v.Pos() <= pos && pos < v.End() && isErrorValue(info, n.Names[j], v) {
						return true
					}
				}
			}
		case *ast.CaseClause:
			if endsInErrorOrPanic(info, sig, n.Body) {
				return true
			}
		case *ast.CommClause:
			if endsInErrorOrPanic(info, sig, n.Body) {
				return true
			}
		case *ast.BlockStmt:
			if i+1 < len(path) {
				if parent, ok := path[i+1].(*ast.IfStmt); ok {
					if endsInErrorOrPanic(info, sig, n.List) {
						return true
					}
					if tv, ok := info.Types[parent.Cond]; ok && tv.Value != nil && tv.Value.Kind() == constant.Bool {
						// A constant condition removes the branch that it does not take.
						if constant.BoolVal(tv.Value) != (n == parent.Body) {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// enclosingSignature returns the signature of the innermost function in path.
func enclosingSignature(info *types.Info, path []ast.Node) *types.Signature {
	for _, n := range path {
		switch n := n.(type) {
		case *ast.FuncLit:
			sig, _ := info.TypeOf(n).(*types.Signature)
			return sig
		case *ast.FuncDecl:
			if obj, ok := info.Defs[n.Name].(*types.Func); ok {
				return obj.Signature()
			}
			return nil
		}
	}
	return nil
}

// errorResult returns the last result of ret when the function returns an error last and ret
// returns a value other than nil there.
func errorResult(info *types.Info, sig *types.Signature, ret *ast.ReturnStmt) ast.Expr {
	if sig == nil || sig.Results().Len() == 0 || len(ret.Results) != sig.Results().Len() {
		return nil
	}
	last := sig.Results().At(sig.Results().Len() - 1).Type()
	if !types.Identical(last, types.Universe.Lookup("error").Type()) {
		return nil
	}
	e := ret.Results[len(ret.Results)-1]
	if tv, ok := info.Types[e]; ok && tv.IsNil() {
		return nil
	}
	return e
}

// isErrorValue reports whether a statement assigns the value v other than nil to lhs, a
// variable whose type implements error.
func isErrorValue(info *types.Info, lhs, v ast.Expr) bool {
	if !implementsError(info.TypeOf(lhs)) {
		return false
	}
	tv, ok := info.Types[v]
	return !ok || !tv.IsNil()
}

// implementsError reports whether t is error or implements it.
func implementsError(t types.Type) bool {
	if t == nil {
		return false
	}
	iface := types.Universe.Lookup("error").Type().Underlying().(*types.Interface)
	return types.Implements(t, iface)
}

// errorConstructors lists the functions of the standard library that build an error. A call of
// one of them and its arguments run on an error path wherever the call is.
var errorConstructors = map[string]bool{
	"errors.New":  true,
	"errors.Join": true,
	"fmt.Errorf":  true,
}

// endsInErrorOrPanic reports whether the last statement of list returns an error or panics.
func endsInErrorOrPanic(info *types.Info, sig *types.Signature, list []ast.Stmt) bool {
	if len(list) == 0 {
		return false
	}
	switch s := list[len(list)-1].(type) {
	case *ast.ReturnStmt:
		return errorResult(info, sig, s) != nil
	case *ast.ExprStmt:
		call, ok := s.X.(*ast.CallExpr)
		return ok && isPanicCall(info, call)
	}
	return false
}

// isPanicCall reports whether call calls the builtin panic.
func isPanicCall(info *types.Info, call *ast.CallExpr) bool {
	id, ok := ast.Unparen(call.Fun).(*ast.Ident)
	if !ok {
		return false
	}
	b, ok := info.Uses[id].(*types.Builtin)
	return ok && b.Name() == "panic"
}

// makeChanType returns the channel type of a call of the builtin make that makes a channel.
func makeChanType(info *types.Info, call *ast.CallExpr) (types.Type, bool) {
	id, ok := ast.Unparen(call.Fun).(*ast.Ident)
	if !ok || len(call.Args) == 0 {
		return nil, false
	}
	if b, ok := info.Uses[id].(*types.Builtin); !ok || b.Name() != "make" {
		return nil, false
	}
	t := info.TypeOf(call.Args[0])
	if t == nil {
		return nil, false
	}
	if _, ok := t.Underlying().(*types.Chan); !ok {
		return nil, false
	}
	return t, true
}

// recordAllocates reports whether the heap record msg at pos allocates when it runs. The
// compiler reports "escapes to heap" for a value that it stores without an allocation too,
// as walk/convert.go and walk/order.go of the compiler define:
//
//   - a constant and a composite literal of constants, which it keeps in read-only data
//   - a zero-sized value, a bool and a single byte, which use runtime tables
//   - a value that is one pointer, which the interface contains directly
//   - a func literal that captures no variable, which is a static function value
func recordAllocates(pass *analysis.Pass, file *ast.File, pos token.Pos, msg string) bool {
	if strings.HasPrefix(msg, compilerMovedToHeap) {
		return true
	}
	expr := strings.TrimSuffix(msg, compilerEscapesToHeap)
	if strings.HasPrefix(expr, compilerFuncLiteral) {
		lit := funcLitAt(file, pos)
		return lit == nil || capturesVariable(pass, lit)
	}
	for _, prefix := range []string{"&", "new(", "make(", "[]", "map[", compilerArgument, "string(", "([]"} {
		if strings.HasPrefix(expr, prefix) {
			return true
		}
	}
	// An empty composite literal, such as context.backgroundCtx{} that an inlined callee
	// converts, is a static value. The compiler prints the elements of a literal as {...}.
	if strings.HasSuffix(expr, "{}") {
		return false
	}

	e := exprAt(file, pos)
	if e == nil {
		return true
	}
	if sel, ok := e.(*ast.SelectorExpr); ok {
		if s, ok := pass.TypesInfo.Selections[sel]; ok && s.Kind() == types.MethodVal {
			return true // a method value is a closure
		}
	}
	tv, ok := pass.TypesInfo.Types[e]
	if !ok || tv.Type == nil {
		return true
	}
	if tv.Value != nil || isStaticCompositeLit(pass.TypesInfo, e) {
		return false
	}
	t := tv.Type
	if types.IsInterface(t) || isDirectIface(pass.TypesSizes, t) {
		return false
	}
	if sz, ok := safeSizeof(pass.TypesSizes, t); ok && sz == 0 {
		return false
	}
	if b, ok := soleComponent(t).Underlying().(*types.Basic); ok {
		if b.Info()&types.IsBoolean != 0 {
			return false
		}
		if sz, ok := safeSizeof(pass.TypesSizes, b); ok && sz == 1 && b.Info()&types.IsInteger != 0 {
			return false
		}
	}
	return true
}

// soleComponent returns the type of the only field or element of t, recursively, or t when t
// is not a struct of one field or an array of one element.
func soleComponent(t types.Type) types.Type {
	for {
		switch u := t.Underlying().(type) {
		case *types.Struct:
			if u.NumFields() != 1 {
				return t
			}
			t = u.Field(0).Type()
		case *types.Array:
			if u.Len() != 1 {
				return t
			}
			t = u.Elem()
		default:
			return t
		}
	}
}

// isStaticCompositeLit reports whether e is a composite literal of constants, which the
// compiler keeps in read-only data.
func isStaticCompositeLit(info *types.Info, e ast.Expr) bool {
	lit, ok := ast.Unparen(e).(*ast.CompositeLit)
	if !ok {
		return false
	}
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			elt = kv.Value
		}
		if tv, ok := info.Types[elt]; ok && tv.Value != nil {
			continue
		}
		if !isStaticCompositeLit(info, elt) {
			return false
		}
	}
	return true
}

// exprAt returns the largest expression of file that starts at pos, or the composite literal
// whose opening brace is at pos, where the compiler places the position of a literal.
func exprAt(file *ast.File, pos token.Pos) ast.Expr {
	path, _ := astutil.PathEnclosingInterval(file, pos, pos)
	var found ast.Expr
	for _, n := range path {
		if lit, ok := n.(*ast.CompositeLit); ok && lit.Lbrace == pos {
			return lit
		}
		e, ok := n.(ast.Expr)
		if !ok || n.Pos() != pos {
			break
		}
		found = e
	}
	return found
}

// funcLitAt returns the func literal of file that starts at pos.
func funcLitAt(file *ast.File, pos token.Pos) *ast.FuncLit {
	path, _ := astutil.PathEnclosingInterval(file, pos, pos)
	for _, n := range path {
		if lit, ok := n.(*ast.FuncLit); ok && lit.Pos() == pos {
			return lit
		}
	}
	return nil
}

// capturesVariable reports whether lit refers to a local variable of an enclosing function.
func capturesVariable(pass *analysis.Pass, lit *ast.FuncLit) bool {
	captures := false
	ast.Inspect(lit.Body, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok || captures {
			return !captures
		}
		v, ok := pass.TypesInfo.Uses[id].(*types.Var)
		if !ok || v.IsField() || v.Parent() == nil || v.Parent() == pass.Pkg.Scope() {
			return true
		}
		if v.Pos() < lit.Pos() || v.Pos() >= lit.End() {
			captures = true
		}
		return !captures
	})
	return captures
}
