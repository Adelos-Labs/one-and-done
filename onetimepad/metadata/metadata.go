package metadata

import (
	"fmt"
	"os"

	"github.com/adelos-labs/one-and-done/onetimepad/message"
	"github.com/adelos-labs/one-and-done/keymanagement"
)

// Encipher encrypts plaintext using key material consumed from keyFile.
// It returns the key file length before encryption (so the recipient can
// verify message ordering), the ciphertext, and the number of key bytes
// still available.
func Encipher(keyFile string, plaintext []byte) (keyLen int, ciphertext []byte, remaining int, err error) {
	info, err := os.Stat(keyFile)
	if err != nil {
		return 0, nil, 0, fmt.Errorf("error reading key file %s: %w", keyFile, err)
	}
	keyLen = int(info.Size())

	key, remaining, err := keymanagement.ConsumeKey(keyFile, len(plaintext))
	if err != nil {
		return 0, nil, 0, err
	}
	defer clear(key)

	ciphertext, err = message.Encipher(plaintext, key)
	if err != nil {
		return 0, nil, 0, err
	}

	return keyLen, ciphertext, remaining, nil
}

// Decipher decrypts ciphertext using key material consumed from keyFile.
// keyLen is the key file length reported by the sender at encryption time.
// If it does not match the receiver's current key file length, the message
// is out of order and decryption is refused.
func Decipher(keyFile string, keyLen int, ciphertext []byte) (plaintext []byte, remaining int, err error) {
	info, err := os.Stat(keyFile)
	if err != nil {
		return nil, 0, fmt.Errorf("error reading key file %s: %w", keyFile, err)
	}
	currentLen := int(info.Size())

	if currentLen != keyLen {
		return nil, 0, fmt.Errorf(
			"key length mismatch: message expects %d bytes but key file has %d bytes (messages may be out of order)",
			keyLen, currentLen,
		)
	}

	key, remaining, err := keymanagement.ConsumeKey(keyFile, len(ciphertext))
	if err != nil {
		return nil, 0, err
	}
	defer clear(key)

	plaintext, err = message.Decipher(ciphertext, key)
	if err != nil {
		return nil, 0, err
	}

	return plaintext, remaining, nil
}
