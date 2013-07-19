// Copyright 2013 Mathew Yates

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package adler32 implements the Adler-32 checksum.
//
// It is defined in RFC 1950:
//	Adler-32 is composed of two sums accumulated per byte: s1 is
//	the sum of all bytes, s2 is the sum of all s1 values. Both sums
//	are done modulo 65521. s1 is initialized to 1, s2 to zero.  The
//	Adler-32 checksum is stored as s2*65536 + s1 in most-
//	significant-byte first (network) order.
package adler32

import (
	"container/ring"
	"rollinghash"
)

const (
	// mod is the largest prime that is less than 65536.
	mod = 65521
	// nmax is the largest n such that
	// 255 * n * (n+1) / 2 + (n+1) * (mod-1) <= 2^32-1.
	// It is mentioned in RFC 1950 (search for "5552").
	nmax = 5552
)

// The size of an Adler-32 checksum in bytes.
const Size = 4

// digest represents the partial evaluation of a checksum.
// The low 16 bits are s1, the high 16 bits are s2.
type digest struct {
	s1, s2       uint32
	windowSize   int
	removeLookup [256]uint32
	buffer       *ring.Ring
}

func (d *digest) Reset() {
	d.buffer = ring.New(d.windowSize)
    d.s1 = 1
    d.s2 = 0

	for i := 0; i < d.windowSize; i++ {
		d.buffer.Value = byte(0)
		d.buffer = d.buffer.Next()
	}

	for i := 0; i < 256; i++ {
		d.removeLookup[i] = uint32(i * d.windowSize)
	}
}

// New returns a new hash.Hash32 computing the Adler-32 checksum.
func New(windowSize int) rollinghash.RollingHash32 {
	d := new(digest)
    d.windowSize = windowSize
	d.Reset()
	return d
}

func (d *digest) Size() int { return Size }

func (d *digest) BlockSize() int { return 1 }

// Add byte p to the digest and remove the byte
// leaving the window
func (d *digest) Update(inByte byte) {
	// Replace the byte leaving the buffer with the incoming
	// byte and advance the buffer
	outByte := d.buffer.Value.(byte)
	d.buffer.Value = inByte
	d.buffer = d.buffer.Next()

    // update the hash
	d.s1 = (d.s2 + uint32(inByte)) - uint32(outByte)
	d.s2 = (d.s2 + d.s1) - (d.removeLookup[outByte]) - 1
    d.s1 %= mod
    d.s2 %= mod
}

func (d *digest) Write(p []byte) (nn int, err error) {
	for _, v := range p {
		d.Update(v)
	}
	return len(p), nil
}

func (d *digest) Sum32() uint32 { return d.s2 << 16 | d.s1}

func (d *digest) Sum(in []byte) []byte {
	s := d.Sum32()
	return append(in, byte(s>>24), byte(s>>16), byte(s>>8), byte(s))
}

// Checksum returns the Adler-32 checksum of data.
func Checksum(data []byte) uint32 {
	d := new(digest)
    d.windowSize = len(data)
	d.Reset()

	for _, v := range data {
		d.Update(v)
	}

	return d.Sum32()
}
