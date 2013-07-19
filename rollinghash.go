package rollinghash

import (
    "hash"
)

type RollingHash interface {
    hash.Hash

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