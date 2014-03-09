// Copyright 2013 Mathew Yates

package rabinkarp

import (
	"container/ring"
	"github.com/Logibox/rollinghash"
)

type digest struct {
	value, prime uint64
	windowSize   int
	removeLookup [256]uint64
	buffer       *ring.Ring
}

func (d *digest) Reset() {
	d.buffer = ring.New(d.windowSize)
	d.value = 0

	// calcuate the nth power of the prime
	// and zero out the buffer
	primeNthPower := uint64(1)
	for i := 0; i < d.windowSize; i++ {
		d.buffer.Value = byte(0)
		d.buffer = d.buffer.Next()

		primeNthPower *= d.prime
	}

	// create the nth prime look up table
	for i := uint64(0); i < 256; i++ {
		d.removeLookup[i] = i * primeNthPower
	}
}

func New(windowSize, prime int) rollinghash.RollingHash64 {
	d := new(digest)
	d.windowSize = windowSize
	d.prime = uint64(prime)
	d.Reset()
	return d
}

func NewDefault() rollinghash.RollingHash64 {
	return New(48, 61)
}

func (d *digest) Size() int { return 8 }

func (d *digest) WindowSize() int { return d.windowSize }

func (d *digest) BlockSize() int { return 1 }

func (d *digest) AddByte(inByte byte) {
	// Replace the byte leaving the buffer with the incoming
	// byte and advance the buffer
	outByte := d.buffer.Value.(byte)
	d.buffer.Value = inByte
	d.buffer = d.buffer.Next()

	// update the hash
	d.value *= d.prime
	d.value = (d.value + uint64(inByte)) - d.removeLookup[outByte]
}

func (d *digest) AddBytes(inBytes []byte) {
	for _, b := range inBytes {
		d.AddByte(b)
	}
}

func (d *digest) Write(p []byte) (nn int, err error) {
	for _, v := range p {
		d.AddByte(v)
	}
	return len(p), nil
}

func (d *digest) Sum64() uint64 { return d.value }

// appends four bytes if the hash will fit, else 8 bytes
func (d *digest) Sum(p []byte) []byte {
	s := d.Sum64()
	p = append(p, byte(s>>56), byte(s>>48), byte(s>>40), byte(s>>32), byte(s>>24), byte(s>>16), byte(s>>8), byte(s))
	return p
}

// Checksum returns the rabin checksum of data.
func Checksum(data []byte, prime int) uint64 {
	d := new(digest)
	d.windowSize = len(data)
	d.prime = uint64(prime)
	d.Reset()

	for _, v := range data {
		d.AddByte(v)
	}

	return d.Sum64()
}
