package metadata_test

import (
	"os"
	"path/filepath"
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

	message := []byte("hello world")

	keyLen, ciphertext, remaining, err := metadata.Encipher(senderKey, message)
	if err != nil {
		t.Fatalf("Encipher: %v", err)
	}
	if keyLen != 64 {
		t.Errorf("keyLen = %d, want 64", keyLen)
	}
	if remaining != 64-len(message) {
		t.Errorf("remaining = %d, want %d", remaining, 64-len(message))
	}

	plaintext, remaining, err := metadata.Decipher(receiverKey, keyLen, ciphertext)
	if err != nil {
		t.Fatalf("Decipher: %v", err)
	}
	if string(plaintext) != "hello world" {
		t.Errorf("plaintext = %q, want %q", plaintext, "hello world")
	}
	if remaining != 64-len(message) {
		t.Errorf("remaining = %d, want %d", remaining, 64-len(message))
	}
}

func TestMultipleMessagesInOrder(t *testing.T) {
	dir := t.TempDir()
	senderKey := writeTestKey(t, dir, "sender.key", 64)
	receiverKey := filepath.Join(dir, "receiver.key")
	copyFile(t, senderKey, receiverKey)

	messages := []string{"aaa", "bbb", "ccc"}

	type envelope struct {
		keyLen     int
		ciphertext []byte
	}
	var sent []envelope

	for _, msg := range messages {
		keyLen, ct, _, err := metadata.Encipher(senderKey, []byte(msg))
		if err != nil {
			t.Fatalf("Encipher(%q): %v", msg, err)
		}
		sent = append(sent, envelope{keyLen, ct})
	}

	for i, env := range sent {
		pt, _, err := metadata.Decipher(receiverKey, env.keyLen, env.ciphertext)
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

	// Send two messages.
	keyLen1, ct1, _, err := metadata.Encipher(senderKey, []byte("first"))
	if err != nil {
		t.Fatalf("Encipher first: %v", err)
	}
	keyLen2, ct2, _, err := metadata.Encipher(senderKey, []byte("second"))
	if err != nil {
		t.Fatalf("Encipher second: %v", err)
	}

	// Receive second message first — should fail.
	_, _, err = metadata.Decipher(receiverKey, keyLen2, ct2)
	if err == nil {
		t.Fatal("expected error when deciphering out-of-order message")
	}

	// Receive first message — should succeed.
	pt, _, err := metadata.Decipher(receiverKey, keyLen1, ct1)
	if err != nil {
		t.Fatalf("Decipher first: %v", err)
	}
	if string(pt) != "first" {
		t.Errorf("got %q, want %q", pt, "first")
	}

	// Now second message should succeed.
	pt, _, err = metadata.Decipher(receiverKey, keyLen2, ct2)
	if err != nil {
		t.Fatalf("Decipher second: %v", err)
	}
	if string(pt) != "second" {
		t.Errorf("got %q, want %q", pt, "second")
	}
}

func TestMissingKeyFile(t *testing.T) {
	missing := "/nonexistent/key.bin"

	_, _, _, err := metadata.Encipher(missing, []byte("hello"))
	if err == nil {
		t.Error("Encipher: expected error for missing key file")
	}

	_, _, err = metadata.Decipher(missing, 100, []byte("hello"))
	if err == nil {
		t.Error("Decipher: expected error for missing key file")
	}
}

func TestKeyTooShort(t *testing.T) {
	dir := t.TempDir()
	keyFile := writeTestKey(t, dir, "short.key", 3)

	_, _, _, err := metadata.Encipher(keyFile, []byte("longer than key"))
	if err == nil {
		t.Error("expected error for key too short")
	}
}
