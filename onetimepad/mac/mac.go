package mac

import (
	"encoding/binary"
	"fmt"
)

const (
	BlockSize = 16 // 128-bit blocks
	KeySize   = 32 // 16 bytes hash key r + 16 bytes mask s
	TagSize   = 16
)

// gfMul multiplies two elements in GF(2^128) using the GHASH convention:
// bits are numbered from the most-significant end and reduction uses the
// irreducible polynomial x^128 + x^7 + x^2 + x + 1.
func gfMul(a, b [2]uint64) [2]uint64 {
	var z [2]uint64 // accumulator
	v := b          // shifted copy of b

	// Walk every bit of a (128 bits total, MSB first).
	for i := 0; i < 128; i++ {
		// Which word and bit position within that word?
		word := i / 64
		bit := uint(63 - (i % 64))

		if (a[word]>>bit)&1 == 1 {
			z[0] ^= v[0]
			z[1] ^= v[1]
		}

		// Shift v right by 1 (MSB→LSB direction in the GHASH sense).
		lsb := v[1] & 1
		v[1] = (v[1] >> 1) | (v[0] << 63)
		v[0] >>= 1

		// If the bit shifted out was 1, reduce by the polynomial.
		// x^128 + x^7 + x^2 + x + 1 → 0xE1 in the high byte.
		if lsb == 1 {
			v[0] ^= 0xE100000000000000
		}
	}
	return z
}

func bytesToBlock(b []byte) [2]uint64 {
	return [2]uint64{
		binary.BigEndian.Uint64(b[:8]),
		binary.BigEndian.Uint64(b[8:16]),
	}
}

func blockToBytes(bl [2]uint64) []byte {
	out := make([]byte, BlockSize)
	binary.BigEndian.PutUint64(out[:8], bl[0])
	binary.BigEndian.PutUint64(out[8:16], bl[1])
	return out
}

// polyHash computes the polynomial hash of data using hash key r.
// The data is zero-padded to a multiple of BlockSize.
// H_r(m_1, ..., m_n) = m_1·r^n ⊕ m_2·r^(n-1) ⊕ ... ⊕ m_n·r
// computed via Horner's method: ((m_1·r ⊕ m_2)·r ⊕ m_3)·r ...
func polyHash(r [2]uint64, data []byte) [2]uint64 {
	var acc [2]uint64

	for len(data) > 0 {
		var block [2]uint64
		if len(data) >= BlockSize {
			block = bytesToBlock(data[:BlockSize])
			data = data[BlockSize:]
		} else {
			// Zero-pad the final partial block.
			var padded [BlockSize]byte
			copy(padded[:], data)
			block = bytesToBlock(padded[:])
			data = nil
		}

		acc[0] ^= block[0]
		acc[1] ^= block[1]
		acc = gfMul(acc, r)
	}

	return acc
}

// Tag computes a Wegman-Carter MAC tag over data.
// key must be KeySize (32) bytes: first 16 bytes are hash key r,
// last 16 bytes are one-time mask s.
// tag = polyHash(r, data) ⊕ s
func Tag(key, data []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("mac: key must be %d bytes, got %d", KeySize, len(key))
	}

	r := bytesToBlock(key[:BlockSize])
	s := bytesToBlock(key[BlockSize:])

	h := polyHash(r, data)
	h[0] ^= s[0]
	h[1] ^= s[1]

	return blockToBytes(h), nil
}

// Verify checks that tag is a valid Wegman-Carter MAC for data under key.
func Verify(key, data, tag []byte) (bool, error) {
	if len(tag) != TagSize {
		return false, fmt.Errorf("mac: tag must be %d bytes, got %d", TagSize, len(tag))
	}

	expected, err := Tag(key, data)
	if err != nil {
		return false, err
	}

	// Constant-time comparison.
	var diff byte
	for i := range expected {
		diff |= expected[i] ^ tag[i]
	}
	return diff == 0, nil
}
