// Copyright Stealth Scale B.V. 2026
// SPDX-License-Identifier: MIT

package gcopt

import (
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"
)

// CacheLinePadSize is set to 128 bytes (two 64-byte cache lines) because modern x86_64 (Intel/AMD)
// and Apple Silicon / ARM64 L2 spatial hardware prefetchers fetch cache lines in 128-byte pairs!
// Padding critical producer/consumer sequence cursors by 128B guarantees zero false sharing.
const CacheLinePadSize = 128

// PaddedSequence wraps an atomic sequence cursor isolated on its own 128-byte cache-line pair.
//
//gc:noscan
type PaddedSequence struct {
	value atomic.Int64
	_     [CacheLinePadSize - 8]byte
}

// OrderEvent is a 64-byte (exact 1 L1 cache line), 100% pointer-free (//gc:noscan) ring buffer slot.
// Because it contains zero pointers (using fixed [16]byte Symbol and uint64 IDs instead of string/*Order),
// a 65,536-slot ring buffer (4 MB) has ZERO GC scan overhead and ZERO GC write barriers when mutated!
//
//gc:noscan
type OrderEvent struct {
	Sequence  int64
	OrderID   uint64
	AccountID uint64
	Price     int64    // Fixed-point ticks (e.g., price * 1e8), never float64/big.Int pointers
	Quantity  int64    // Lot quantity
	Timestamp int64    // Monotonic nanoseconds
	Symbol    [12]byte // Fixed-size ASCII ticker symbol (avoids 16B string pointer header!)
	Side      uint8    // 1 = Buy, 2 = Sell
	Flags     uint8    // Execution bitflags
	_         [2]byte  // Explicit alignment to exactly 64 bytes (1 CPU cache line per event)
}

// RingCapacity must be a power of two so sequence-to-slot indexing uses a 1-cycle bitwise AND (`seq & IndexMask`)
// instead of a 25-cycle integer division (`IDIV` via `%`).
const (
	RingCapacity = 65536
	IndexMask    = RingCapacity - 1
)

// SPSCDisruptor implements the LMAX Disruptor pattern with mechanical sympathy for CPU L1d caches:
//  1. Pre-allocated, contiguous, pointer-free (`noscan`) `[RingCapacity]OrderEvent` value array.
//  2. Producer and Consumer sequence cursors separated onto independent 128B cache-line pairs.
//  3. Local sequence caching (`cachedConsumerSeq` and `cachedProducerSeq`): the producer NEVER reads
//     the consumer's atomic sequence until the ring buffer actually wraps around, eliminating cross-core
//     MESI cache-coherency traffic on 99.99% of publishes!
//
//gc:noscan
type SPSCDisruptor struct {
	// Cache Line Pair 0: Producer-owned state (written exclusively by Producer goroutine/thread)
	producerSeq       atomic.Int64
	cachedConsumerSeq int64 // Non-atomic local cache of consumer's progress!
	_                 [CacheLinePadSize - 16]byte

	// Cache Line Pair 1: Consumer-owned state (written exclusively by Consumer goroutine/thread)
	consumerSeq       atomic.Int64
	cachedProducerSeq int64 // Non-atomic local cache of producer's progress!
	_                 [CacheLinePadSize - 16]byte

	// Cache Line Pair 2+: Contiguous, pointer-free (`noscan`) ring buffer slots (64B aligned)
	ring [RingCapacity]OrderEvent
}

// NewSPSCDisruptor initializes the ring buffer with sequences starting at -1 (LMAX convention).
// Marked //gc:allowalloc because ring buffer allocation happens once at startup outside the hot loop.
//
//gc:allowalloc
func NewSPSCDisruptor() *SPSCDisruptor {
	d := &SPSCDisruptor{
		cachedConsumerSeq: -1,
		cachedProducerSeq: -1,
	}
	d.producerSeq.Store(-1)
	d.consumerSeq.Store(-1)
	return d
}

// waitForConsumer is the cold slow-path extracted into a separate helper so Publish() stays well below
// the Go compiler's 80-node AST inlining budget (//gc:inline).
//
//go:noinline
//gc:zeroalloc
func (d *SPSCDisruptor) waitForConsumer(wrapPoint int64) {
	for {
		conSeq := d.consumerSeq.Load()
		d.cachedConsumerSeq = conSeq
		if wrapPoint <= conSeq {
			return
		}
		// Progressive backpressure wait strategy: yield without allocating timers
		runtime.Gosched()
	}
}

// Publish claims the next slot in the Disruptor, writes the event in-place without GC write barriers,
// and commits the sequence with release semantics (`atomic.Int64.Store`).
//
//gc:zeroalloc
//gc:inline
func (d *SPSCDisruptor) Publish(orderID, accountID uint64, price, qty, ts int64, symbol [12]byte, side uint8) {
	nextSeq := d.producerSeq.Load() + 1

	// Fast path: check against our core-local `cachedConsumerSeq` without touching the consumer's cache line!
	// Because the slow spin-loop is in waitForConsumer(), this fast path inlines directly into the caller.
	if wrapPoint := nextSeq - RingCapacity; wrapPoint > d.cachedConsumerSeq {
		d.waitForConsumer(wrapPoint)
	}

	// 1-cycle bitwise AND indexing (`nextSeq & IndexMask`).
	// Mutating a pointer-free value struct inside `d.ring` emits ZERO GC write barriers!
	slot := &d.ring[nextSeq&IndexMask]
	slot.Sequence = nextSeq
	slot.OrderID = orderID
	slot.AccountID = accountID
	slot.Price = price
	slot.Quantity = qty
	slot.Timestamp = ts
	slot.Symbol = symbol
	slot.Side = side

	// Commit publication with Release memory ordering so Consumer sees all slot fields before nextSeq.
	d.producerSeq.Store(nextSeq)
}

// ConsumeBatch processes all available published events in a single batch (the LMAX "Batching Effect").
// Even if the Consumer falls behind, a single atomic `d.producerSeq.Load()` lets it process hundreds
// of contiguous cache-line events in a tight loop before issuing a single `d.consumerSeq.Store()` at the end.
//
//gc:zeroalloc
func (d *SPSCDisruptor) ConsumeBatch(maxBatch int64) (processed int64, totalNotional int64) {
	nextToRead := d.consumerSeq.Load() + 1

	// Only read the producer's atomic cursor if we've exhausted our locally cached upper bound.
	if nextToRead > d.cachedProducerSeq {
		d.cachedProducerSeq = d.producerSeq.Load()
		if nextToRead > d.cachedProducerSeq {
			return 0, 0 // No new events available
		}
	}

	// Bound batch size to prevent starvation if desired
	upperBound := d.cachedProducerSeq
	if limit := nextToRead + maxBatch - 1; limit < upperBound {
		upperBound = limit
	}

	// Tight sequential scan over contiguous 64-byte `OrderEvent` slots—hardware L1d streamer prefetcher heaven!
	for seq := nextToRead; seq <= upperBound; seq++ {
		ev := &d.ring[seq&IndexMask]
		totalNotional += ev.Price * ev.Quantity
		processed++
	}

	// Single atomic Store updates the gating cursor for the entire batch!
	d.consumerSeq.Store(upperBound)
	return processed, totalNotional
}

// EventProcessor is a zero-allocation handler function that inspects an OrderEvent in-place.
type EventProcessor func(ev *OrderEvent) int64

// MulticastConsumerState holds a 128-byte cache-line isolated sequence cursor and result accumulator
// for a single parallel function running over the shared ring buffer.
//
//gc:noscan
type MulticastConsumerState struct {
	cursor            atomic.Int64
	cachedProducerSeq int64
	accumulator       int64
	_                 [CacheLinePadSize - 24]byte
}

// MaxParallelConsumers is the maximum number of parallel consumer functions supported in a zero-alloc fan-out.
const MaxParallelConsumers = 8

// MulticastDisruptor implements the LMAX "Diamond / Multicast" pattern:
// One producer writes to the pointer-free ring buffer ONCE, and N independent consumer functions
// process the exact same events IN PARALLEL at the same time—each tracking its own 128B-padded cursor!
// The producer only wraps around when the SLOWEST parallel consumer has advanced (`minConsumerSeq`).
//
//gc:noscan
type MulticastDisruptor struct {
	producerSeq          atomic.Int64
	cachedMinConsumerSeq int64
	numConsumers         int64
	_                    [CacheLinePadSize - 24]byte

	consumers [MaxParallelConsumers]MulticastConsumerState
	ring      [RingCapacity]OrderEvent
}

// NewMulticastDisruptor initializes a fan-out ring buffer for `numConsumers` parallel functions.
// Marked //gc:allowalloc because allocation happens once at startup.
//
//gc:allowalloc
func NewMulticastDisruptor(numConsumers int) *MulticastDisruptor {
	if numConsumers < 1 {
		numConsumers = 1
	}
	if numConsumers > MaxParallelConsumers {
		numConsumers = MaxParallelConsumers
	}
	d := &MulticastDisruptor{
		cachedMinConsumerSeq: -1,
		numConsumers:         int64(numConsumers),
	}
	d.producerSeq.Store(-1)
	for i := 0; i < MaxParallelConsumers; i++ {
		d.consumers[i].cursor.Store(-1)
		d.consumers[i].cachedProducerSeq = -1
	}
	return d
}

// minConsumerSequence scans the 128B-padded cursors of all active parallel consumers and returns the slowest one.
//
//go:noinline
//gc:zeroalloc
func (d *MulticastDisruptor) waitForSlowestConsumer(wrapPoint int64) {
	for {
		minSeq := d.consumers[0].cursor.Load()
		for i := int64(1); i < d.numConsumers; i++ {
			if cSeq := d.consumers[i].cursor.Load(); cSeq < minSeq {
				minSeq = cSeq
			}
		}
		d.cachedMinConsumerSeq = minSeq
		if wrapPoint <= minSeq {
			return
		}
		runtime.Gosched()
	}
}

// PublishMulticast publishes an OrderEvent once so all parallel consumer functions can read it simultaneously.
//
//gc:zeroalloc
//gc:inline
func (d *MulticastDisruptor) PublishMulticast(orderID, accountID uint64, price, qty, ts int64, symbol [12]byte, side uint8) {
	nextSeq := d.producerSeq.Load() + 1

	// Only check consumer cursors when wrapping the 65,536-slot ring buffer
	if wrapPoint := nextSeq - RingCapacity; wrapPoint > d.cachedMinConsumerSeq {
		d.waitForSlowestConsumer(wrapPoint)
	}

	slot := &d.ring[nextSeq&IndexMask]
	slot.Sequence = nextSeq
	slot.OrderID = orderID
	slot.AccountID = accountID
	slot.Price = price
	slot.Quantity = qty
	slot.Timestamp = ts
	slot.Symbol = symbol
	slot.Side = side

	d.producerSeq.Store(nextSeq)
}

// ConsumeParallelBatch is called by consumer `consumerIdx` (0..N-1) on its own OS thread to run `fn`
// over every new batch of events concurrently with all other consumers.
//
//gc:zeroalloc
func (d *MulticastDisruptor) ConsumeParallelBatch(consumerIdx int, maxBatch int64, fn EventProcessor) int64 {
	state := &d.consumers[consumerIdx]
	nextToRead := state.cursor.Load() + 1

	if nextToRead > state.cachedProducerSeq {
		state.cachedProducerSeq = d.producerSeq.Load()
		if nextToRead > state.cachedProducerSeq {
			return 0
		}
	}

	upperBound := state.cachedProducerSeq
	if limit := nextToRead + maxBatch - 1; limit < upperBound {
		upperBound = limit
	}

	var acc int64
	for seq := nextToRead; seq <= upperBound; seq++ {
		ev := &d.ring[seq&IndexMask]
		acc += fn(ev)
	}

	state.accumulator += acc
	state.cursor.Store(upperBound)
	return upperBound - nextToRead + 1
}

// Accumulator returns the final computed state for parallel consumer `consumerIdx`.
//
//gc:zeroalloc
//gc:inline
func (d *MulticastDisruptor) Accumulator(consumerIdx int) int64 {
	return d.consumers[consumerIdx].accumulator
}

// WarmGoroutineStack pre-expands the calling goroutine's stack from Go's default 2 KB to >32 KB
// BEFORE entering a //gc:zeroalloc hot loop. When paired with GOGC=off (so stacks never shrink),
// this guarantees the goroutine will never suffer a `runtime.morestack` stack-split & copy pause on the hot path.
//
//go:noinline
//gc:allowalloc
func WarmGoroutineStack() {
	var stackPad [32768]byte
	stackPad[0] = 1
	stackPad[len(stackPad)-1] = 1
	runtime.KeepAlive(&stackPad)
}

// AllocOffHeapSlice allocates a contiguous slice of N elements of type T directly from the OS kernel
// via anonymous `mmap` (`MAP_ANON | MAP_PRIVATE`), completely bypassing Go's garbage collector and `GOMEMLIMIT`.
// Because the memory resides outside `runtime.mheap`, Go's GC never scans it and never counts it toward heap pacing.
//
//gc:allowalloc
func AllocOffHeapSlice[T any](length int) ([]T, func() error, error) {
	if length <= 0 {
		return nil, func() error { return nil }, nil
	}
	var zero T
	elemSize := int(unsafe.Sizeof(zero))
	totalBytes := length * elemSize
	// Round up to 4096-byte OS page boundary
	pageSize := syscall.Getpagesize()
	if rem := totalBytes % pageSize; rem != 0 {
		totalBytes += pageSize - rem
	}

	raw, err := syscall.Mmap(-1, 0, totalBytes, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		return nil, nil, err
	}

	// Pre-fault every page into physical RAM (`MAP_POPULATE` equivalent) so the first write in a hot loop
	// never triggers a 4-microsecond Linux kernel minor page fault!
	for i := 0; i < len(raw); i += pageSize {
		raw[i] = 0
	}

	ptr := (*T)(unsafe.Pointer(&raw[0]))
	slice := unsafe.Slice(ptr, length)
	freeFn := func() error {
		return syscall.Munmap(raw)
	}
	return slice, freeFn, nil
}
