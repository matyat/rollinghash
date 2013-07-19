// Copyright 2013 Mathew Yates

package rabinkarp

import (
	"container/ring"
	"github.com/Logibox/rollinghash"
)

type digest struct {
	value, prime, mask   uint64
	windowSize, hashSize int
	removeLookup         [256]uint64
	buffer               *ring.Ring
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
	for i := 0; i < 256; i++ {
		d.removeLookup[i] = uint64(i * primeNthPower)
	}

	d.mask = (1 << d.hashSize) - 1
}

func New(windowSize, hashSize, prime int) rollinghash.RollingHash {
	d := new(digest)
	d.windowSize = windowSize
	d.hashSize = hashSize
	d.prime = uint64(prime)
	d.Reset()
	return d
}

func (d *digest) Size() int { return d.hashSize }

func (d *digest) BlockSize() int { return 1 }

func (d *digest) Update(inByte byte) {
	// Replace the byte leaving the buffer with the incoming
	// byte and advance the buffer
	outByte := d.buffer.Value.(byte)
	d.buffer.Value = inByte
	d.buffer = d.buffer.Next()

	// update the hash
	d.value *= d.prime
	d.value = (d.value + uint64(inByte)) - d.removeLookup[outByte]
	d.value &= d.mask
}

func (d *digest) Write(p []byte) (nn int, err error) {
	for _, v := range p {
		d.Update(v)
	}
	return len(p), nil
}

func (d *digest) Sum32() uint32 {
	if d.hashSize <= 32 {
		return uint32(d.value)
	} else {
		return 0
	}
}

func (d *digest) Sum64() uint64 { return d.value }

// appends four bytes if the hash will fit, else 8 bytes
func (d *digest) Sum(in []byte) []byte {
	if d.hashSize <= 32 {
		s := d.Sum32()
		return append(in, byte(s>>24), byte(s>>16), byte(s>>8), byte(s))
	} else {
		s := d.Sum64()
		return append(in, byte(s>>56), byte(s>>48), byte(s>>40), byte(s>>32), byte(s>>24), byte(s>>16), byte(s>>8), byte(s))
	}
}

// Checksum returns the rabin checksum of data.
func Checksum(data []byte, prime int) uint32 {
	d := new(digest)
	d.windowSize = len(data)
	d.prime = uint64(prime)
	d.Reset()

	for _, v := range data {
		d.Update(v)
	}

	return d.Sum32()
}