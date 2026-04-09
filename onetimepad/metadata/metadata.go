package metadata

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"

	"github.com/adelos-labs/one-and-done/keymanagement"
	"github.com/adelos-labs/one-and-done/onetimepad/mac"
	"github.com/adelos-labs/one-and-done/onetimepad/message"
)

// envelopeVersion is the on-wire envelope format version. Checked before
// any cryptographic operations so that future format changes produce a
// clear error rather than an opaque MAC failure.
const envelopeVersion = 1

type envelope struct {
	Version int    `json:"v"`
	Message string `json:"m"`
	KeyID   string `json:"k_id"`
	KeyLen  int    `json:"k_len"`
	Tag     string `json:"tag"`
}

// macInput builds the canonical, self-delimiting byte sequence authenticated
// by the MAC:
//
//	version (1 byte) || keyIDLen (8-byte BE) || keyID || keyLen (8-byte BE) || ciphertextLen (8-byte BE) || ciphertext
const macVersion = 0x01

func macInput(keyID string, keyLen int, ciphertext []byte) []byte {
	idBytes := []byte(keyID)

	// 1 + 8 + len(idBytes) + 8 + 8 + len(ciphertext)
	out := make([]byte, 0, 25+len(idBytes)+len(ciphertext))

	out = append(out, macVersion)

	out = binary.BigEndian.AppendUint64(out, uint64(len(idBytes)))
	out = append(out, idBytes...)

	out = binary.BigEndian.AppendUint64(out, uint64(keyLen))

	out = binary.BigEndian.AppendUint64(out, uint64(len(ciphertext)))
	out = append(out, ciphertext...)

	return out
}

// Encipher encrypts plaintext and returns a base64-encoded JSON envelope
// containing the ciphertext, key ID, key file length (for ordering), and
// a Wegman-Carter MAC tag over the ciphertext and metadata.
// Consumes len(plaintext) + mac.KeySize bytes from the key file.
func Encipher(keyFile, keyID string, plaintext []byte) (string, int, error) {
	info, err := os.Stat(keyFile)
	if err != nil {
		return "", 0, fmt.Errorf("error reading key file %s: %w", keyFile, err)
	}
	keyLen := int(info.Size())

	totalKeyNeeded := len(plaintext) + mac.KeySize
	key, remaining, err := keymanagement.ConsumeKey(keyFile, totalKeyNeeded)
	if err != nil {
		return "", 0, err
	}
	defer clear(key)

	encKey := key[:len(plaintext)]
	macKey := key[len(plaintext):]

	ciphertext, err := message.Encipher(plaintext, encKey)
	if err != nil {
		return "", 0, err
	}

	tag, err := mac.Tag(macKey, macInput(keyID, keyLen, ciphertext))
	if err != nil {
		return "", 0, err
	}

	env := envelope{
		Version: envelopeVersion,
		Message: base64.StdEncoding.EncodeToString(ciphertext),
		KeyID:   keyID,
		KeyLen:  keyLen,
		Tag:     base64.StdEncoding.EncodeToString(tag),
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
// The MAC tag is verified by reading (not consuming) key material first;
// key bytes are only consumed after authentication succeeds.
func Decipher(keyFile, expectedKeyID, encoded string) (plaintext []byte, remaining int, err error) {
	jsonBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid envelope encoding: %w", err)
	}

	var env envelope
	if err := json.Unmarshal(jsonBytes, &env); err != nil {
		return nil, 0, fmt.Errorf("invalid envelope format: %w", err)
	}

	if env.Version != envelopeVersion {
		return nil, 0, fmt.Errorf(
			"unsupported envelope version: got %d, expected %d",
			env.Version, envelopeVersion,
		)
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

	tag, err := base64.StdEncoding.DecodeString(env.Tag)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid tag encoding: %w", err)
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

	// Read key material non-destructively to verify the MAC first.
	totalKeyNeeded := len(ciphertext) + mac.KeySize
	peekKey, err := keymanagement.ReadKey(keyFile, totalKeyNeeded)
	if err != nil {
		return nil, 0, err
	}
	macKey := peekKey[len(ciphertext):]

	ok, err := mac.Verify(macKey, macInput(env.KeyID, env.KeyLen, ciphertext), tag)
	clear(peekKey)
	if err != nil {
		return nil, 0, fmt.Errorf("mac verification error: %w", err)
	}
	if !ok {
		return nil, 0, fmt.Errorf("authentication failed: message may have been tampered with")
	}

	// MAC verified — now consume the key material destructively.
	key, remaining, err := keymanagement.ConsumeKey(keyFile, totalKeyNeeded)
	if err != nil {
		return nil, 0, err
	}
	defer clear(key)

	plaintext, err = message.Decipher(ciphertext, key[:len(ciphertext)])
	if err != nil {
		return nil, 0, err
	}

	return plaintext, remaining, nil
}
