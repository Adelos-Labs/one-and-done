package metadata

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/adelos-labs/one-and-done/keymanagement"
	"github.com/adelos-labs/one-and-done/onetimepad/message"
)

type envelope struct {
	Message string `json:"m"`
	KeyID   string `json:"k_id"`
	KeyLen  int    `json:"k_len"`
}

// Encipher encrypts plaintext and returns a base64-encoded JSON envelope
// containing the ciphertext, key ID, and key file length (for ordering).
func Encipher(keyFile, keyID string, plaintext []byte) (string, int, error) {
	info, err := os.Stat(keyFile)
	if err != nil {
		return "", 0, fmt.Errorf("error reading key file %s: %w", keyFile, err)
	}
	keyLen := int(info.Size())

	key, remaining, err := keymanagement.ConsumeKey(keyFile, len(plaintext))
	if err != nil {
		return "", 0, err
	}
	defer clear(key)

	ciphertext, err := message.Encipher(plaintext, key)
	if err != nil {
		return "", 0, err
	}

	env := envelope{
		Message: base64.StdEncoding.EncodeToString(ciphertext),
		KeyID:   keyID,
		KeyLen:  keyLen,
	}

	jsonBytes, err := json.Marshal(env)
	if err != nil {
		return "", 0, fmt.Errorf("error encoding envelope: %w", err)
	}

	return base64.StdEncoding.EncodeToString(jsonBytes), remaining, nil
}

// Decipher decodes a base64-encoded JSON envelope and decrypts the message.
// expectedKeyID is the key ID the caller expects; if the envelope's key ID
// does not match, decryption is refused before any key material is consumed.
// It also validates that the envelope's key length matches the current key
// file, refusing to decrypt if messages are out of order.
func Decipher(keyFile, expectedKeyID, encoded string) (plaintext []byte, remaining int, err error) {
	jsonBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid envelope encoding: %w", err)
	}

	var env envelope
	if err := json.Unmarshal(jsonBytes, &env); err != nil {
		return nil, 0, fmt.Errorf("invalid envelope format: %w", err)
	}

	if env.KeyID != expectedKeyID {
		return nil, 0, fmt.Errorf(
			"key ID mismatch: message has %q but expected %q",
			env.KeyID, expectedKeyID,
		)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(env.Message)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid ciphertext encoding: %w", err)
	}

	info, err := os.Stat(keyFile)
	if err != nil {
		return nil, 0, fmt.Errorf("error reading key file %s: %w", keyFile, err)
	}
	currentLen := int(info.Size())

	if currentLen != env.KeyLen {
		return nil, 0, fmt.Errorf(
			"key length mismatch: message expects %d bytes but key file has %d bytes (messages may be out of order)",
			env.KeyLen, currentLen,
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
