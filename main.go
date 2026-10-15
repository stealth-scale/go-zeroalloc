// Copyright Stealth Scale B.V. 2026
// SPDX-License-Identifier: MIT

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/tools/go/analysis/singlechecker"

	"github.com/stealth-scale/go-zeroalloc/gcopt"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-bench-disruptor", "--bench-disruptor":
			runDisruptorBenchmark(os.Args[2:])
			return
		case "-bench-parallel", "--bench-parallel":
			runParallelMulticastBenchmark(os.Args[2:])
			return
		}
	}

	// If the user passes a relative path to another Go module (e.g. `../../thesmos/sharder/...`),
	// `go/packages` inside singlechecker needs the working directory to be inside that module's `go.mod` root.
	if handled := runCrossModuleIfNeeded(os.Args[1:]); handled {
		return
	}

	// If invoked directly inside the current repository (not already wrapped by our path-relativizer),
	// wrap singlechecker so any absolute `/path/to/cwd/file.go` prefixes are stripped to relative paths.
	if os.Getenv("GCOPT_RAW_SINGLECHECKER") == "" {
		if cwd, err := os.Getwd(); err == nil {
			runRelativizedChild(cwd, os.Args[1:])
			return
		}
	}

	// Default mode: run ALL gcopt analyzer passes simultaneously over target packages!
	singlechecker.Main(gcopt.Analyzer)
}

// runRelativizedChild runs the analyzer subprocess and strips `baseDir` (and module path prefixes)
// from every diagnostic line so output paths are always clean relative paths.
func runRelativizedChild(baseDir string, cmdArgs []string) {
	selfBin, err := os.Executable()
	if err != nil {
		singlechecker.Main(gcopt.Analyzer)
		return
	}

	cmd := exec.Command(selfBin, cmdArgs...)
	cmd.Dir = baseDir
	cmd.Env = append(os.Environ(), "GCOPT_RAW_SINGLECHECKER=1")

	stdoutPipe, _ := cmd.StdoutPipe()
	stderrPipe, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		singlechecker.Main(gcopt.Analyzer)
		return
	}

	modPrefix := readModulePrefix(baseDir)
	absPrefix := filepath.Clean(baseDir) + string(filepath.Separator)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		filterOutputPaths(stdoutPipe, os.Stdout, absPrefix, modPrefix)
	}()
	go func() {
		defer wg.Done()
		filterOutputPaths(stderrPipe, os.Stderr, absPrefix, modPrefix)
	}()
	wg.Wait()

	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
	}
}

func filterOutputPaths(r io.Reader, w io.Writer, absPrefix, modPrefix string) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.ReplaceAll(line, absPrefix, "")
		if modPrefix != "" {
			line = strings.ReplaceAll(line, modPrefix+"/", "")
		}
		fmt.Fprintln(w, line)
	}
}

func readModulePrefix(modDir string) string {
	data, err := os.ReadFile(filepath.Join(modDir, "go.mod"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}
	return ""
}

// runCrossModuleIfNeeded detects if a target package argument points to an external directory with its own go.mod
// (like `../../thesmos/sharder/...`) and automatically invokes this analyzer inside that module's directory.
func runCrossModuleIfNeeded(args []string) bool {
	if os.Getenv("GCOPT_RAW_SINGLECHECKER") != "" {
		return false
	}

	var flags []string
	var externalTargets []string

	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
			continue
		}
		// Check if the argument is a relative path pointing outside the current directory
		if strings.HasPrefix(arg, "../") || strings.HasPrefix(arg, "/") {
			externalTargets = append(externalTargets, arg)
		}
	}

	if len(externalTargets) == 0 {
		return false
	}

	for _, target := range externalTargets {
		cleanTarget := strings.TrimSuffix(target, "/...")
		cleanTarget = strings.TrimSuffix(cleanTarget, "/")
		absTarget, err := filepath.Abs(cleanTarget)
		if err != nil {
			continue
		}

		// Find the nearest parent directory containing go.mod, or use absTarget
		modDir := findGoModRoot(absTarget)
		relPkg := "./..."
		if modDir != "" && strings.HasPrefix(absTarget, modDir) {
			if rel, err := filepath.Rel(modDir, absTarget); err == nil && rel != "." {
				if strings.HasSuffix(target, "...") {
					relPkg = "./" + filepath.ToSlash(rel) + "/..."
				} else {
					relPkg = "./" + filepath.ToSlash(rel)
				}
			}
		} else {
			modDir = absTarget
		}

		fmt.Printf("==> Running gcopt analyzer on %s (module: %s)\n", relPkg, filepath.Base(modDir))
		cmdArgs := append(append([]string{}, flags...), relPkg)
		runRelativizedChild(modDir, cmdArgs)
	}
	return true
}

func findGoModRoot(startDir string) string {
	dir := startDir
	for {
		if info, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil && !info.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// runParallelMulticastBenchmark runs 4 distinct business-logic functions IN PARALLEL at the exact same time
// over the exact same stream of OrderEvents using the LMAX Multicast Disruptor (zero copies, zero locks, 0 allocs).
func runParallelMulticastBenchmark(args []string) {
	fs := flag.NewFlagSet("bench-parallel", flag.ExitOnError)
	numEvents := fs.Int64("events", 50_000_000, "number of OrderEvents to multicast across all parallel functions")
	_ = fs.Parse(args)

	// Define 4 independent functions that will ALL run at the exact same time over every OrderEvent:
	parallelFuncs := []struct {
		name string
		fn   gcopt.EventProcessor
	}{
		{
			name: "1. RiskCheck (Notional Value)",
			fn:   func(ev *gcopt.OrderEvent) int64 { return ev.Price * ev.Quantity },
		},
		{
			name: "2. VWAP Volume Accumulator",
			fn:   func(ev *gcopt.OrderEvent) int64 { return ev.Quantity },
		},
		{
			name: "3. Sequence Integrity Audit",
			fn:   func(ev *gcopt.OrderEvent) int64 { return int64(ev.OrderID ^ ev.AccountID) },
		},
		{
			name: "4. Matching Engine Side Filter",
			fn:   func(ev *gcopt.OrderEvent) int64 { return int64(ev.Side) * ev.Price },
		},
	}

	ring := gcopt.NewMulticastDisruptor(len(parallelFuncs))

	totalEvents := *numEvents
	symbol := [12]byte{'B', 'T', 'C', '-', 'U', 'S', 'D', 'T', 0, 0, 0, 0}

	var wg sync.WaitGroup
	wg.Add(len(parallelFuncs))

	// Atomic start barrier so all 4 worker goroutines and their OS threads are 100% allocated and pinned
	// BEFORE we snapshot runtime.ReadMemStats(&memBefore) for the hot loop!
	var readyWorkers atomic.Int32
	var startGate atomic.Bool

	// Pre-spawn 1 OS-thread-pinned goroutine per parallel function BEFORE the hot loop starts
	for idx, p := range parallelFuncs {
		consumerIdx := idx
		processorFn := p.fn
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			defer wg.Done()

			readyWorkers.Add(1)
			// Spin-wait on atomic startGate without calling runtime.Gosched(), because Gosched()
			// on a LockOSThread() goroutine forces the Go scheduler to allocate new runtime.m OS thread structs!
			for !startGate.Load() {
			}

			var consumed int64
			for consumed < totalEvents {
				n := ring.ConsumeParallelBatch(consumerIdx, 4096, processorFn)
				if n == 0 {
					continue
				}
				consumed += n
			}
		}()
	}

	// Wait until all 4 consumer goroutines have spawned and locked their OS threads
	for readyWorkers.Load() < int32(len(parallelFuncs)) {
		runtime.Gosched()
	}
	runtime.LockOSThread()

	debug.SetGCPercent(-1)
	debug.SetMemoryLimit(1 << 30)
	runtime.GC()

	// Snapshot heap allocations AFTER goroutine startup so we measure strictly the 200M hot-loop evaluations
	var memBefore, memAfter runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	startGate.Store(true)
	start := time.Now()

	// Producer publishes each event ONCE; all 4 parallel functions read it from L1/L2 cache concurrently!
	for i := int64(0); i < totalEvents; i++ {
		ring.PublishMulticast(uint64(i), 1001, 65000, 2, i, symbol, 1)
	}
	runtime.UnlockOSThread()

	wg.Wait()
	elapsed := time.Since(start)

	runtime.ReadMemStats(&memAfter)
	heapAllocs := memAfter.Mallocs - memBefore.Mallocs
	bytesAllocated := memAfter.TotalAlloc - memBefore.TotalAlloc

	fmt.Printf("=== LMAX Multicast Disruptor (4 Functions in Parallel) ===\n")
	fmt.Printf("Events Published     : %d (x4 parallel consumers = %d total fn evaluations)\n", totalEvents, totalEvents*int64(len(parallelFuncs)))
	fmt.Printf("Elapsed Time         : %v\n", elapsed.Round(time.Millisecond))
	fmt.Printf("Effective Throughput : %.2f million fn-evals/sec\n", float64(totalEvents*int64(len(parallelFuncs)))/elapsed.Seconds()/1e6)
	fmt.Printf("Heap Allocations     : %d allocs (%d bytes) during hot loop\n", heapAllocs, bytesAllocated)
	for i, p := range parallelFuncs {
		fmt.Printf("  -> %-32s Result: %d\n", p.name, ring.Accumulator(i))
	}

	// If the user also passed package paths after the benchmark flags (e.g. `../../thesmos/sharder/...`),
	// run the static analyzer on them right after the benchmark!
	if fs.NArg() > 0 {
		fmt.Println()
		if !runCrossModuleIfNeeded(fs.Args()) {
			os.Args = append([]string{os.Args[0]}, fs.Args()...)
			singlechecker.Main(gcopt.Analyzer)
		}
	}
}

func runDisruptorBenchmark(args []string) {
	fs := flag.NewFlagSet("bench-disruptor", flag.ExitOnError)
	numEvents := fs.Int64("events", 50_000_000, "number of OrderEvents to publish and consume through the SPSC Disruptor")
	disableGC := fs.Bool("gogc-off", true, "disable automatic GC (SetGCPercent(-1)) during the hot loop")
	_ = fs.Parse(args)

	// Pre-allocate the 4MB noscan ring buffer outside the hot loop
	ring := gcopt.NewSPSCDisruptor()

	if *disableGC {
		debug.SetGCPercent(-1)
		debug.SetMemoryLimit(1 << 30) // 1 GiB safety ceiling
	}

	// Force a clean GC baseline and snapshot heap allocations before starting
	runtime.GC()
	var memBefore, memAfter runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	totalEvents := *numEvents
	symbol := [12]byte{'B', 'T', 'C', '-', 'U', 'S', 'D', 'T', 0, 0, 0, 0}
	done := make(chan int64, 1)

	start := time.Now()

	// Spawn Consumer Goroutine pinned to a dedicated OS thread for L1d cache locality
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		var consumed, sumNotional int64
		for consumed < totalEvents {
			n, notional := ring.ConsumeBatch(4096)
			if n == 0 {
				runtime.Gosched()
				continue
			}
			consumed += n
			sumNotional += notional
		}
		done <- sumNotional
	}()

	// Run Producer on the current Goroutine pinned to its own OS thread
	runtime.LockOSThread()
	for i := int64(0); i < totalEvents; i++ {
		ring.Publish(uint64(i), 1001, 65000, 2, i, symbol, 1)
	}
	runtime.UnlockOSThread()

	checksum := <-done
	elapsed := time.Since(start)

	runtime.ReadMemStats(&memAfter)
	heapAllocs := memAfter.Mallocs - memBefore.Mallocs
	bytesAllocated := memAfter.TotalAlloc - memBefore.TotalAlloc
	nsPerOp := float64(elapsed.Nanoseconds()) / float64(totalEvents)
	opsPerSec := float64(totalEvents) / elapsed.Seconds()

	fmt.Printf("=== LMAX SPSC Disruptor Benchmark ===\n")
	fmt.Printf("Events Processed : %d\n", totalEvents)
	fmt.Printf("Elapsed Time     : %v\n", elapsed.Round(time.Millisecond))
	fmt.Printf("Throughput       : %.2f million msgs/sec (%.2f ns/event)\n", opsPerSec/1e6, nsPerOp)
	fmt.Printf("Heap Allocations : %d allocs (%d bytes) during hot loop\n", heapAllocs, bytesAllocated)
	fmt.Printf("Notional Checksum: %d\n", checksum)
}
