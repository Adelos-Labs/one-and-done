package message

import (
	"bytes"
	"testing"
)

func TestXOR(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03}
	key := []byte{0xFF, 0x00, 0xAA}
	got := xor(data, key)
	want := []byte{0xFE, 0x02, 0xA9}
	if !bytes.Equal(got, want) {
		t.Errorf("XOR(%x, %x) = %x, want %x", data, key, got, want)
	}
}

func TestXOR_ZeroKey(t *testing.T) {
	data := []byte("hello")
	key := make([]byte, len(data))
	got := xor(data, key)
	if !bytes.Equal(got, data) {
		t.Errorf("XOR with zero key should return original data, got %x", got)
	}
}

func TestEncipherDecipher_Roundtrip(t *testing.T) {
	plaintext := []byte("attack at dawn")
	key := []byte("secretkeysecretk") // longer than plaintext

	cipher, err := Encipher(plaintext, key)
	if err != nil {
		t.Fatalf("Encipher: %v", err)
	}

	if bytes.Equal(cipher, plaintext) {
		t.Error("ciphertext should differ from plaintext")
	}

	result, err := Decipher(cipher, key)
	if err != nil {
		t.Fatalf("Decipher: %v", err)
	}

	if !bytes.Equal(result, plaintext) {
		t.Errorf("roundtrip failed: got %q, want %q", result, plaintext)
	}
}

func TestEncipher_KeyTooShort(t *testing.T) {
	_, err := Encipher([]byte("hello"), []byte("hi"))
	if err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestDecipher_KeyTooShort(t *testing.T) {
	_, err := Decipher([]byte("hello"), []byte("hi"))
	if err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestEncipherDecipher_EmptyInput(t *testing.T) {
	empty := []byte{}
	key := []byte("anykey")

	cipher, err := Encipher(empty, key)
	if err != nil {
		t.Fatalf("Encipher empty: %v", err)
	}
	if len(cipher) != 0 {
		t.Errorf("Encipher empty: got %x, want empty", cipher)
	}

	plain, err := Decipher(empty, key)
	if err != nil {
		t.Fatalf("Decipher empty: %v", err)
	}
	if len(plain) != 0 {
		t.Errorf("Decipher empty: got %x, want empty", plain)
	}
}

func TestEncipher_ExactLengthKey(t *testing.T) {
	plaintext := []byte("abc")
	key := []byte("xyz")
	_, err := Encipher(plaintext, key)
	if err != nil {
		t.Fatalf("exact-length key should work: %v", err)
	}
}
