package mac

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestGfMul_Zero(t *testing.T) {
	a := [2]uint64{0x1234, 0x5678}
	zero := [2]uint64{0, 0}

	if gfMul(a, zero) != zero {
		t.Error("a * 0 should be 0")
	}
	if gfMul(zero, a) != zero {
		t.Error("0 * a should be 0")
	}
}

func TestGfMul_One(t *testing.T) {
	// In GHASH convention, the multiplicative identity is the element
	// with only the MSB set: 0x80000000_00000000_00000000_00000000.
	one := [2]uint64{0x8000000000000000, 0}
	a := [2]uint64{0xDEADBEEFCAFEBABE, 0x0123456789ABCDEF}

	if gfMul(a, one) != a {
		t.Errorf("a * 1 = %x, want %x", gfMul(a, one), a)
	}
	if gfMul(one, a) != a {
		t.Errorf("1 * a = %x, want %x", gfMul(one, a), a)
	}
}

func TestGfMul_Commutative(t *testing.T) {
	a := [2]uint64{0xA5A5A5A5A5A5A5A5, 0x5A5A5A5A5A5A5A5A}
	b := [2]uint64{0x1234567890ABCDEF, 0xFEDCBA0987654321}

	ab := gfMul(a, b)
	ba := gfMul(b, a)
	if ab != ba {
		t.Errorf("a*b = %x, b*a = %x", ab, ba)
	}
}

func TestGfMul_KnownAnswer_XSquared(t *testing.T) {
	// In GHASH bit convention, x = 0x40..., x^2 = 0x20...
	// x * x = x^2 (no reduction needed, well below degree 128).
	x := [2]uint64{0x4000000000000000, 0}
	want := [2]uint64{0x2000000000000000, 0}

	got := gfMul(x, x)
	if got != want {
		t.Errorf("x * x = %016x_%016x, want %016x_%016x", got[0], got[1], want[0], want[1])
	}
}

func TestGfMul_KnownAnswer_Reduction(t *testing.T) {
	// x^127 * x = x^128 mod (x^128 + x^7 + x^2 + x + 1) = x^7 + x^2 + x + 1
	// In GHASH convention: x^127 = 0x00...01, x = 0x40...
	// x^7+x^2+x+1 = 0xE1 in byte 0 = 0xE100000000000000
	x127 := [2]uint64{0, 1}
	x := [2]uint64{0x4000000000000000, 0}
	want := [2]uint64{0xE100000000000000, 0}

	got := gfMul(x127, x)
	if got != want {
		t.Errorf("x^127 * x = %016x_%016x, want %016x_%016x", got[0], got[1], want[0], want[1])
	}
}

// TestPolyHash_GHASH_NIST_TC2 verifies polyHash against NIST SP 800-38D
// Test Case 2. In that test case:
//
//	H = 66e94bd4ef8a2c3b884cfa59ca342b2e  (= AES_K(0^128), K=0^128)
//	GHASH input = C || len_block (two 16-byte blocks)
//	C         = 0388dace60b6a392f328c2b971b2fe78
//	len_block = 00000000000000000000000000000080  (0-bit AAD, 128-bit C)
//	Expected  = f38cbb1ad69223dcc3457ae5b6b0f885
func TestPolyHash_GHASH_NIST_TC2(t *testing.T) {
	h := [2]uint64{0x66e94bd4ef8a2c3b, 0x884cfa59ca342b2e}

	// Two-block input: C || len_block
	data := []byte{
		// C
		0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
		0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78,
		// len_block: 0 bits AAD, 128 bits ciphertext
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
	}

	want := [2]uint64{0xf38cbb1ad69223dc, 0xc3457ae5b6b0f885}

	got := polyHash(h, data)
	if got != want {
		t.Errorf("GHASH NIST TC2:\ngot  %016x_%016x\nwant %016x_%016x",
			got[0], got[1], want[0], want[1])
	}
}

func TestPolyHash_Empty(t *testing.T) {
	r := [2]uint64{0x1234, 0x5678}
	h := polyHash(r, nil)
	if h != ([2]uint64{0, 0}) {
		t.Errorf("hash of empty input should be zero, got %x", h)
	}
}

func TestPolyHash_DifferentInputs(t *testing.T) {
	r := [2]uint64{0xDEADBEEF, 0xCAFEBABE}
	h1 := polyHash(r, []byte("hello"))
	h2 := polyHash(r, []byte("world"))
	if h1 == h2 {
		t.Error("different inputs should produce different hashes (with overwhelming probability)")
	}
}

func TestTag_Roundtrip(t *testing.T) {
	key := make([]byte, KeySize)
	rand.Read(key)
	data := []byte("authenticate me")

	tag, err := Tag(key, data)
	if err != nil {
		t.Fatalf("Tag: %v", err)
	}
	if len(tag) != TagSize {
		t.Fatalf("tag length = %d, want %d", len(tag), TagSize)
	}

	ok, err := Verify(key, data, tag)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Error("valid tag rejected")
	}
}

func TestVerify_RejectsTamperedData(t *testing.T) {
	key := make([]byte, KeySize)
	rand.Read(key)
	data := []byte("authenticate me")

	tag, _ := Tag(key, data)

	tampered := append([]byte{}, data...)
	tampered[0] ^= 0xFF

	ok, err := Verify(key, tampered, tag)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Error("tampered data should not verify")
	}
}

func TestVerify_RejectsTamperedTag(t *testing.T) {
	key := make([]byte, KeySize)
	rand.Read(key)
	data := []byte("authenticate me")

	tag, _ := Tag(key, data)

	badTag := append([]byte{}, tag...)
	badTag[0] ^= 0x01

	ok, err := Verify(key, data, badTag)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Error("tampered tag should not verify")
	}
}

func TestTag_MaskHidesHash(t *testing.T) {
	// Same data, same hash key r, different mask s → different tags.
	key1 := make([]byte, KeySize)
	key2 := make([]byte, KeySize)
	rand.Read(key1)
	copy(key2, key1)
	// Flip a bit in the mask (second half).
	key2[BlockSize] ^= 0x01

	data := []byte("same input")
	tag1, _ := Tag(key1, data)
	tag2, _ := Tag(key2, data)

	if bytes.Equal(tag1, tag2) {
		t.Error("different masks should produce different tags")
	}
}

func TestTag_InvalidKeySize(t *testing.T) {
	_, err := Tag(make([]byte, 10), []byte("data"))
	if err == nil {
		t.Error("expected error for wrong key size")
	}
}

func TestVerify_InvalidTagSize(t *testing.T) {
	key := make([]byte, KeySize)
	_, err := Verify(key, []byte("data"), []byte("short"))
	if err == nil {
		t.Error("expected error for wrong tag size")
	}
}
