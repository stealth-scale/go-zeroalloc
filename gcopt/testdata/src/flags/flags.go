// Copyright Stealth Scale B.V. 2026
// SPDX-License-Identifier: MIT

// Package flags is the test input of the gcopt analyzer with -writebarriers and -conditional.
package flags

var global *int

// storeGlobal stores a pointer into a global, which needs a write barrier.
//
//gc:zeroalloc
func storeGlobal(p *int) { // want storeGlobal:"gc:zeroalloc"
	global = p // want `storeGlobal has a write barrier`
}

// appendByte appends to the buffer of the caller, which allocates when the buffer is full.
//
//gc:zeroalloc
func appendByte(dst []byte) []byte { // want appendByte:"gc:zeroalloc"
	return append(dst, 1) // want `appendByte may allocate: append grows the slice`
}
