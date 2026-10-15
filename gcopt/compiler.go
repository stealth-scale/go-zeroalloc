// Copyright Stealth Scale B.V. 2026
// SPDX-License-Identifier: MIT

package gcopt

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/tools/go/analysis"
)

// Texts of the compiler's -m=1 and -d=wb diagnostics that the analyzer reads.
const (
	compilerMovedToHeap   = "moved to heap: "
	compilerEscapesToHeap = " escapes to heap"
	compilerInliningCall  = "inlining call to "
	compilerCanInline     = "can inline "
	compilerWriteBarrier  = "write barrier"
	compilerAppend        = "append"
	compilerArgument      = "... argument"
	compilerFuncLiteral   = "func literal"
)

// compilerPos is a position in a diagnostic of the compiler. file is absolute, with the
// symbolic links of its directory resolved.
type compilerPos struct {
	file string
	line int
	col  int
}

// compilerRecord is one diagnostic of the compiler in a file.
type compilerRecord struct {
	line int
	col  int
	msg  string
}

// compilerRecords contains the decisions of the compiler about the files of one package.
type compilerRecords struct {
	heap      map[string][]compilerRecord // per file: "escapes to heap" and "moved to heap"
	appends   map[string][]compilerRecord // per file: appends whose growth the heap holds
	barriers  map[string][]compilerRecord // per file: stores with a write barrier
	inlined   map[compilerPos]bool        // call sites, at the opening parenthesis, that the compiler inlined
	canInline map[compilerPos]bool        // file and line, with column 0, of each function that the compiler can inline
}

// compilerEntry builds the records of one package once per process.
type compilerEntry struct {
	once sync.Once
	recs *compilerRecords
	err  error
}

var (
	// compilerCache maps an import path, a directory and the compiler flags to a *compilerEntry.
	compilerCache sync.Map

	// compilerSlots limits the go commands that run at once. The checker analyzes every
	// package of the import graph in a goroutine of its own.
	compilerSlots = make(chan struct{}, runtime.GOMAXPROCS(0))

	modCacheOnce sync.Once
	modCacheDir  string

	// canonicalDirs maps a directory to the same directory with its symbolic links resolved.
	canonicalDirs sync.Map
)

// loadCompilerRecords returns the decisions that the compiler makes when it builds the
// package of pass. It runs go build with -gcflags=-m=1, and with -d=wb for -writebarriers.
// The go command replays the diagnostics of a package from its build cache, so a package
// that has not changed costs one go command and no compile.
//
// It returns empty records for a package without a non-test Go file, such as an external
// test package, because go build compiles none of its files.
func loadCompilerRecords(pass *analysis.Pass) (*compilerRecords, error) {
	dir := packageDir(pass)
	if dir == "" {
		return newCompilerRecords(), nil
	}
	gcflags := "-m=1"
	if flagWriteBarriers {
		gcflags += " -d=wb"
	}
	key := pass.Pkg.Path() + "\x00" + dir + "\x00" + gcflags
	v, _ := compilerCache.LoadOrStore(key, new(compilerEntry))
	e := v.(*compilerEntry)
	e.once.Do(func() {
		e.recs, e.err = buildCompilerRecords(pass.Pkg.Path(), dir, gcflags)
	})
	return e.recs, e.err
}

// packageDir returns the directory of the first non-test Go file of pass, or "" when the
// package has none.
func packageDir(pass *analysis.Pass) string {
	for _, f := range pass.Files {
		name := pass.Fset.Position(f.Pos()).Filename
		if strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
			return filepath.Dir(name)
		}
	}
	return ""
}

// buildCompilerRecords runs the compiler on one package and parses its diagnostics. It builds
// a package in the module cache by its import path from the working directory, so that the
// versions of the main module apply. It builds every other package as "." in its directory.
func buildCompilerRecords(importPath, dir, gcflags string) (*compilerRecords, error) {
	cmdDir, target := dir, "."
	if inModuleCache(dir) {
		wd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("gcopt: working directory: %w", err)
		}
		cmdDir, target = wd, importPath
	}

	compilerSlots <- struct{}{}
	defer func() { <-compilerSlots }()

	cmd := exec.Command("go", "build", "-gcflags="+gcflags, "-o", os.DevNull, target)
	cmd.Dir = cmdDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("gcopt: go build -gcflags=%q %s in %s: %w\n%s", gcflags, target, cmdDir, err, out)
	}
	return parseCompilerRecords(out, cmdDir)
}

// inModuleCache reports whether dir is inside the module cache of the go command.
func inModuleCache(dir string) bool {
	modCacheOnce.Do(func() {
		out, err := exec.Command("go", "env", "GOMODCACHE").Output()
		if err == nil {
			modCacheDir = strings.TrimSpace(string(out))
		}
	})
	if modCacheDir == "" {
		return false
	}
	rel, err := filepath.Rel(modCacheDir, dir)
	return err == nil && filepath.IsLocal(rel)
}

// newCompilerRecords returns records without a decision.
func newCompilerRecords() *compilerRecords {
	return &compilerRecords{
		heap:      make(map[string][]compilerRecord),
		appends:   make(map[string][]compilerRecord),
		barriers:  make(map[string][]compilerRecord),
		inlined:   make(map[compilerPos]bool),
		canInline: make(map[compilerPos]bool),
	}
}

// parseCompilerRecords parses the output of go build. base is the directory against which
// the go command printed relative file names. A line that is not a diagnostic of a Go file,
// such as "# pkg" or a position in <autogenerated>, is skipped.
func parseCompilerRecords(out []byte, base string) (*compilerRecords, error) {
	recs := newCompilerRecords()
	seen := make(map[compilerPos]map[string]bool)
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		pos, msg, ok := splitCompilerLine(sc.Text(), base)
		if !ok {
			continue
		}
		// The compiler prints a diagnostic once per instantiation of a generic function.
		if seen[pos][msg] {
			continue
		}
		if seen[pos] == nil {
			seen[pos] = make(map[string]bool)
		}
		seen[pos][msg] = true

		rec := compilerRecord{line: pos.line, col: pos.col, msg: msg}
		switch {
		case strings.HasPrefix(msg, compilerMovedToHeap):
			recs.heap[pos.file] = append(recs.heap[pos.file], rec)
		case msg == compilerAppend+compilerEscapesToHeap:
			recs.appends[pos.file] = append(recs.appends[pos.file], rec)
		case strings.HasSuffix(msg, compilerEscapesToHeap):
			recs.heap[pos.file] = append(recs.heap[pos.file], rec)
		case strings.HasPrefix(msg, compilerInliningCall):
			recs.inlined[pos] = true
		case strings.HasPrefix(msg, compilerCanInline):
			recs.canInline[compilerPos{file: pos.file, line: pos.line}] = true
		case msg == compilerWriteBarrier:
			recs.barriers[pos.file] = append(recs.barriers[pos.file], rec)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("gcopt: read compiler output: %w", err)
	}
	return recs, nil
}

// splitCompilerLine splits a diagnostic of the form file:line:col: message.
func splitCompilerLine(line, base string) (compilerPos, string, bool) {
	head, msg, ok := strings.Cut(line, ": ")
	if !ok {
		return compilerPos{}, "", false
	}
	i := strings.LastIndexByte(head, ':')
	if i < 0 {
		return compilerPos{}, "", false
	}
	col, err := strconv.Atoi(head[i+1:])
	if err != nil {
		return compilerPos{}, "", false
	}
	j := strings.LastIndexByte(head[:i], ':')
	if j < 0 {
		return compilerPos{}, "", false
	}
	ln, err := strconv.Atoi(head[j+1 : i])
	if err != nil {
		return compilerPos{}, "", false
	}
	file := head[:j]
	if !strings.HasSuffix(file, ".go") {
		return compilerPos{}, "", false
	}
	if !filepath.IsAbs(file) {
		file = filepath.Join(base, file)
	}
	return compilerPos{file: canonicalPath(file), line: ln, col: col}, msg, true
}

// canonicalPath returns name with the symbolic links of its directory resolved, so that the
// file names of the compiler and of the loader compare equal.
func canonicalPath(name string) string {
	dir, file := filepath.Split(filepath.Clean(name))
	if v, ok := canonicalDirs.Load(dir); ok {
		return filepath.Join(v.(string), file)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		resolved = dir
	}
	canonicalDirs.Store(dir, resolved)
	return filepath.Join(resolved, file)
}
