// Copyright 2013 Mathew Yates

package rollinghash

import (
	"hash"
)

type RollingHash interface {
	hash.Hash
	// update the hash with a new byte
	// internally a byte is dropped from the buffer
	AddByte(byte)
	AddBytes([]byte)

	// Size of the interal window/buffer
	WindowSize() int
}

type RollingHash32 interface {
	RollingHash
	Sum32() uint32
}

type RollingHash64 interface {
	RollingHash
	Sum64() uint64
}
