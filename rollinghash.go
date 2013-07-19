// Copyright 2013 Mathew Yates

package rollinghash

import (
	"hash"
)

type RollingHash interface {
	hash.Hash
	// update the hash with a new byte
	// internally a byte is drop from the buffer
	Update(inByte byte)
}

type RollingHash32 interface {
	RollingHash
	Sum32() uint32
}

type RollingHash64 interface {
	RollingHash
	Sum64() uint64
}
