package message

import "fmt"

func xor(data, key []byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i]
	}
	return out
}

func applyXor(data, key []byte) ([]byte, error) {
	if len(key) < len(data) {
		return nil, fmt.Errorf("key too short: need %d bytes, have %d", len(data), len(key))
	}
	return xor(data, key), nil
}

func Encipher(plaintext, key []byte) ([]byte, error) {
	return applyXor(plaintext, key)
}

func Decipher(cipher, key []byte) ([]byte, error) {
	return applyXor(cipher, key)
}
