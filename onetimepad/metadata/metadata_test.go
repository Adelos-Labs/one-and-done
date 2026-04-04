package metadata_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adelos-labs/one-and-done/keymanagement"
	"github.com/adelos-labs/one-and-done/onetimepad/metadata"
)

func writeTestKey(t *testing.T, dir, name string, size int) string {
	t.Helper()
	path := filepath.Join(dir, name)
	key, err := keymanagement.GenKey(size)
	if err != nil {
		t.Fatalf("GenKey: %v", err)
	}
	if err := os.WriteFile(path, key, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if err := os.WriteFile(dst, data, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func TestRoundtrip(t *testing.T) {
	dir := t.TempDir()
	senderKey := writeTestKey(t, dir, "sender.key", 64)
	receiverKey := filepath.Join(dir, "receiver.key")
	copyFile(t, senderKey, receiverKey)

	msg := []byte("hello world")

	envelope, remaining, err := metadata.Encipher(senderKey, "test-key", msg)
	if err != nil {
		t.Fatalf("Encipher: %v", err)
	}
	if remaining != 64-len(msg) {
		t.Errorf("remaining = %d, want %d", remaining, 64-len(msg))
	}

	plaintext, keyID, remaining, err := metadata.Decipher(receiverKey, envelope)
	if err != nil {
		t.Fatalf("Decipher: %v", err)
	}
	if string(plaintext) != "hello world" {
		t.Errorf("plaintext = %q, want %q", plaintext, "hello world")
	}
	if keyID != "test-key" {
		t.Errorf("keyID = %q, want %q", keyID, "test-key")
	}
	if remaining != 64-len(msg) {
		t.Errorf("remaining = %d, want %d", remaining, 64-len(msg))
	}
}

func TestEnvelopeFormat(t *testing.T) {
	dir := t.TempDir()
	senderKey := writeTestKey(t, dir, "sender.key", 64)

	envelope, _, err := metadata.Encipher(senderKey, "my-key", []byte("hi"))
	if err != nil {
		t.Fatalf("Encipher: %v", err)
	}

	// Envelope should be valid base64.
	jsonBytes, err := base64.StdEncoding.DecodeString(envelope)
	if err != nil {
		t.Fatalf("envelope is not valid base64: %v", err)
	}

	// Inner JSON should have expected fields.
	var parsed map[string]any
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("envelope JSON is invalid: %v", err)
	}
	if parsed["k_id"] != "my-key" {
		t.Errorf("k_id = %v, want %q", parsed["k_id"], "my-key")
	}
	if parsed["k_len"] != float64(64) {
		t.Errorf("k_len = %v, want 64", parsed["k_len"])
	}
	if _, ok := parsed["m"]; !ok {
		t.Error("envelope missing 'm' field")
	}
}

func TestMultipleMessagesInOrder(t *testing.T) {
	dir := t.TempDir()
	senderKey := writeTestKey(t, dir, "sender.key", 64)
	receiverKey := filepath.Join(dir, "receiver.key")
	copyFile(t, senderKey, receiverKey)

	messages := []string{"aaa", "bbb", "ccc"}
	var envelopes []string

	for _, msg := range messages {
		env, _, err := metadata.Encipher(senderKey, "k", []byte(msg))
		if err != nil {
			t.Fatalf("Encipher(%q): %v", msg, err)
		}
		envelopes = append(envelopes, env)
	}

	for i, env := range envelopes {
		pt, _, _, err := metadata.Decipher(receiverKey, env)
		if err != nil {
			t.Fatalf("Decipher message %d: %v", i, err)
		}
		if string(pt) != messages[i] {
			t.Errorf("message %d: got %q, want %q", i, pt, messages[i])
		}
	}
}

func TestOutOfOrderDetected(t *testing.T) {
	dir := t.TempDir()
	senderKey := writeTestKey(t, dir, "sender.key", 64)
	receiverKey := filepath.Join(dir, "receiver.key")
	copyFile(t, senderKey, receiverKey)

	env1, _, err := metadata.Encipher(senderKey, "k", []byte("first"))
	if err != nil {
		t.Fatalf("Encipher first: %v", err)
	}
	env2, _, err := metadata.Encipher(senderKey, "k", []byte("second"))
	if err != nil {
		t.Fatalf("Encipher second: %v", err)
	}

	// Receive second message first — should fail.
	_, _, _, err = metadata.Decipher(receiverKey, env2)
	if err == nil {
		t.Fatal("expected error when deciphering out-of-order message")
	}
	if !strings.Contains(err.Error(), "key length mismatch") {
		t.Errorf("expected key length mismatch error, got: %v", err)
	}

	// Receive first message — should succeed.
	pt, _, _, err := metadata.Decipher(receiverKey, env1)
	if err != nil {
		t.Fatalf("Decipher first: %v", err)
	}
	if string(pt) != "first" {
		t.Errorf("got %q, want %q", pt, "first")
	}

	// Now second message should succeed.
	pt, _, _, err = metadata.Decipher(receiverKey, env2)
	if err != nil {
		t.Fatalf("Decipher second: %v", err)
	}
	if string(pt) != "second" {
		t.Errorf("got %q, want %q", pt, "second")
	}
}

func TestMissingKeyFile(t *testing.T) {
	missing := "/nonexistent/key.bin"

	_, _, err := metadata.Encipher(missing, "k", []byte("hello"))
	if err == nil {
		t.Error("Encipher: expected error for missing key file")
	}

	// Decipher needs a valid envelope even though the key file is missing.
	// Craft a minimal valid envelope pointing at the missing file.
	dir := t.TempDir()
	senderKey := writeTestKey(t, dir, "sender.key", 16)
	env, _, err := metadata.Encipher(senderKey, "k", []byte("hi"))
	if err != nil {
		t.Fatalf("setup Encipher: %v", err)
	}

	_, _, _, err = metadata.Decipher(missing, env)
	if err == nil {
		t.Error("Decipher: expected error for missing key file")
	}
}

func TestKeyTooShort(t *testing.T) {
	dir := t.TempDir()
	keyFile := writeTestKey(t, dir, "short.key", 3)

	_, _, err := metadata.Encipher(keyFile, "k", []byte("longer than key"))
	if err == nil {
		t.Error("expected error for key too short")
	}
}

func TestDecipherInvalidEnvelope(t *testing.T) {
	dir := t.TempDir()
	keyFile := writeTestKey(t, dir, "test.key", 16)

	// Not valid base64.
	_, _, _, err := metadata.Decipher(keyFile, "!!!invalid!!!")
	if err == nil {
		t.Error("expected error for invalid base64")
	}

	// Valid base64 but not JSON.
	_, _, _, err = metadata.Decipher(keyFile, base64.StdEncoding.EncodeToString([]byte("not json")))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}
