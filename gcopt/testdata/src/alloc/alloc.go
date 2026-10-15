// Copyright Stealth Scale B.V. 2026
// SPDX-License-Identifier: MIT

// Package alloc is the test input of the gcopt analyzer. Each function exercises one rule.
// The expectations on its lines list the diagnostics and the facts that the analyzer reports
// for it. The analyzer checks the functions that carry //gc:zeroalloc.
package alloc

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strconv"
	"sync"
)

var (
	sink   any
	global *int
	pool   = sync.Pool{New: func() any { return new([64]byte) }}
)

// T has one pointer field.
type T struct{ p *int }

// escapingLiteral returns a pointer to a composite literal. The compiler moves the literal to
// the heap.
//
//go:noinline
//gc:zeroalloc
func escapingLiteral() *T { // want escapingLiteral:"gc:zeroalloc" escapingLiteral:"allocates\\(alloc.go:\\d+: &T\\{\\} escapes to heap\\)"
	return &T{} // want `escapingLiteral allocates: &T\{\} escapes to heap`
}

// localLiteral takes the address of a composite literal that stays on the stack.
//
//gc:zeroalloc
func localLiteral() bool { // want localLiteral:"gc:zeroalloc"
	t := &T{}
	return t.p == nil
}

// callsEscaping calls a function that the compiler does not inline and that allocates.
//
//gc:zeroalloc
func callsEscaping() *T { // want callsEscaping:"gc:zeroalloc" callsEscaping:"allocates\\(calls escapingLiteral -> alloc.go:\\d+: &T\\{\\} escapes to heap\\)"
	return escapingLiteral() // want `callsEscaping calls escapingLiteral, which allocates: alloc.go:\d+: &T\{\} escapes to heap`
}

// newT is small enough for the compiler to inline.
func newT() *T { // want newT:"allocates\\(alloc.go:\\d+: &T\\{\\} escapes to heap\\)"
	return &T{}
}

// inlinedLiteral calls newT. The compiler inlines newT, so the literal stays on the stack.
//
//gc:zeroalloc
func inlinedLiteral() bool { // want inlinedLiteral:"gc:zeroalloc"
	return newT().p == nil
}

// keyID hashes a name through a buffer on the stack. The compiler inlines sha256.New and calls
// the methods of the digest directly, so nothing escapes.
//
//gc:zeroalloc
func keyID(name string) [4]byte { // want keyID:"gc:zeroalloc"
	h := sha256.New()
	var chunk [64]byte
	for s := name; s != ""; {
		n := copy(chunk[:], s)
		h.Write(chunk[:n])
		s = s[n:]
	}
	var sum [sha256.Size]byte
	var id [4]byte
	copy(id[:], h.Sum(sum[:0]))
	return id
}

// parse builds an error only when s is empty, and an error path does not count.
//
//gc:zeroalloc
func parse(s string) (int, error) { // want parse:"gc:zeroalloc"
	if s == "" {
		return 0, fmt.Errorf("parse: empty input %q", s)
	}
	return len(s), nil
}

// corrupt is an error of the size of an int.
type corrupt int

// Error returns the text of the error.
func (corrupt) Error() string { return "corrupt" }

// decode assigns an error to a variable of type error, and building an error does not count.
//
//gc:zeroalloc
func decode(n int) (err error) { // want decode:"gc:zeroalloc"
	if n < 0 {
		err = corrupt(n)
	}
	return err
}

// StatusError is an error with a code.
type StatusError struct{ code int }

// Error returns the text of the error.
func (*StatusError) Error() string { return "status" }

// status builds an error in a variable of its own type before it returns the error.
//
//gc:zeroalloc
func status(code int) error { // want status:"gc:zeroalloc"
	if code == 0 {
		return nil
	}
	e := &StatusError{code: code}
	return e
}

// check returns an error from its last statement when n is too small.
//
//gc:zeroalloc
func check(n int) error { // want check:"gc:zeroalloc"
	if n >= 10 {
		return nil
	}
	return fmt.Errorf("check: %d is below 10", n)
}

// collect appends an error to a list. A call of fmt.Errorf builds an error wherever it is.
//
//gc:zeroalloc
func collect(errs []error, n int) []error { // want collect:"gc:zeroalloc"
	if n < 0 {
		errs = append(errs, fmt.Errorf("collect: %d is negative", n))
	}
	return errs
}

// cached passes a constructor to a function that calls it on a miss, so the allocation of the
// constructor does not count for cached.
//
//gc:zeroalloc
func cached(get func(func() *T) *T) *T { // want cached:"gc:zeroalloc"
	return get(func() *T { return &T{} })
}

// immediate calls a func literal itself, so the allocation of the literal counts.
//
//gc:zeroalloc
func immediate() *T { // want immediate:"gc:zeroalloc" immediate:"allocates\\(alloc.go:\\d+: &T\\{\\} escapes to heap\\)"
	return func() *T { return &T{} }() // want `immediate allocates: &T\{\} escapes to heap`
}

// key is a context key without fields.
type key struct{}

// fromContext converts an empty struct literal to an interface, which is a static value.
//
//gc:zeroalloc
func fromContext(ctx context.Context) any { // want fromContext:"gc:zeroalloc"
	return ctx.Value(key{})
}

// pooled gets a buffer from a warm pool and puts it back.
//
//gc:zeroalloc
func pooled() { // want pooled:"gc:zeroalloc"
	b := pool.Get()
	pool.Put(b)
}

// appendUint appends the decimal form of v to the buffer of the caller.
//
//gc:zeroalloc
func appendUint(dst []byte, v uint64) []byte { // want appendUint:"gc:zeroalloc"
	return strconv.AppendUint(dst, v, 10)
}

// boxConstant stores a constant in an interface. The compiler points the interface at
// read-only data.
//
//gc:zeroalloc
func boxConstant() { // want boxConstant:"gc:zeroalloc"
	sink = 1000
}

// boxByte stores a byte in an interface. The interface points into a static table.
//
//gc:zeroalloc
func boxByte(b byte) { // want boxByte:"gc:zeroalloc"
	sink = b
}

// boxInt stores an int in an interface, which allocates for a value of 256 or more.
//
//gc:zeroalloc
func boxInt(n int) { // want boxInt:"gc:zeroalloc" boxInt:"allocates\\(alloc.go:\\d+: n escapes to heap\\)"
	sink = n // want `boxInt allocates: n escapes to heap`
}

// staticFunc returns a func literal that captures nothing. The compiler makes it a static value.
//
//gc:zeroalloc
func staticFunc() func() int { // want staticFunc:"gc:zeroalloc"
	return func() int { return 1 }
}

// capturingFunc returns a func literal that captures n, so the closure escapes to the heap.
//
//gc:zeroalloc
func capturingFunc(n int) func() int { // want capturingFunc:"gc:zeroalloc" capturingFunc:"allocates\\(alloc.go:\\d+: func literal escapes to heap\\)"
	return func() int { return n } // want `capturingFunc allocates: func literal escapes to heap`
}

// newChan makes a channel, which the runtime always allocates.
//
//gc:zeroalloc
func newChan() chan int { // want newChan:"gc:zeroalloc" newChan:"allocates\\(alloc.go:\\d+: make\\(chan int\\) allocates a channel\\)"
	return make(chan int) // want `newChan allocates: make\(chan int\) allocates a channel`
}

// appendByte appends to the buffer of the caller, which allocates only when the buffer is full.
//
//gc:zeroalloc
func appendByte(dst []byte) []byte { // want appendByte:"gc:zeroalloc"
	return append(dst, 1)
}

// putUint appends eight bytes through a function of the standard library that the compiler
// inlines.
//
//gc:zeroalloc
func putUint(dst []byte, v uint64) []byte { // want putUint:"gc:zeroalloc"
	return binary.BigEndian.AppendUint64(dst, v)
}

// itoa formats n. strconv.Itoa calls a function that allocates the string.
//
//gc:zeroalloc
func itoa(n int) string { // want itoa:"gc:zeroalloc" itoa:"allocates\\(calls Itoa -> "
	return strconv.Itoa(n) // want `itoa calls Itoa, which allocates`
}

// storeGlobal stores a pointer into a global. The store has a write barrier, and the analyzer
// reports write barriers only with -writebarriers.
//
//gc:zeroalloc
func storeGlobal(p *int) { // want storeGlobal:"gc:zeroalloc"
	global = p
}

// locked locks and unlocks mu. The analyzer reports locks only with -hints.
//
//gc:zeroalloc
func locked(mu *sync.Mutex) { // want locked:"gc:zeroalloc"
	mu.Lock()
	mu.Unlock()
}

// unchecked allocates, and the analyzer does not check it, because it has no //gc:zeroalloc.
func unchecked() *T { // want unchecked:"allocates\\(alloc.go:\\d+: &T\\{\\} escapes to heap\\)"
	return &T{}
}

// add is small, so the compiler inlines it.
//
//gc:inline
func add(a, b int) int { return a + b }

// multiply has //go:noinline, so the compiler does not inline it.
//
//go:noinline
//gc:inline
func multiply(a, b int) int { // want `the compiler does not inline multiply`
	return a * b
}
