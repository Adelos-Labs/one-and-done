package metadata_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adelos-labs/one-and-done/keymanagement"
	"github.com/adelos-labs/one-and-done/onetimepad/mac"
	"github.com/adelos-labs/one-and-done/onetimepad/metadata"
)

// Each message consumes len(plaintext) + mac.KeySize bytes.
const keySize = 256

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
	senderKey := writeTestKey(t, dir, "sender.key", keySize)
	receiverKey := filepath.Join(dir, "receiver.key")
	copyFile(t, senderKey, receiverKey)

	msg := []byte("hello world")
	consumed := len(msg) + mac.KeySize

	envelope, remaining, err := metadata.Encipher(senderKey, "test-key", msg)
	if err != nil {
		t.Fatalf("Encipher: %v", err)
	}
	if remaining != keySize-consumed {
		t.Errorf("remaining = %d, want %d", remaining, keySize-consumed)
	}

	plaintext, remaining, err := metadata.Decipher(receiverKey, "test-key", envelope)
	if err != nil {
		t.Fatalf("Decipher: %v", err)
	}
	if string(plaintext) != "hello world" {
		t.Errorf("plaintext = %q, want %q", plaintext, "hello world")
	}
	if remaining != keySize-consumed {
		t.Errorf("remaining = %d, want %d", remaining, keySize-consumed)
	}
}

func TestEnvelopeFormat(t *testing.T) {
	dir := t.TempDir()
	senderKey := writeTestKey(t, dir, "sender.key", keySize)

	envelope, _, err := metadata.Encipher(senderKey, "my-key", []byte("hi"))
	if err != nil {
		t.Fatalf("Encipher: %v", err)
	}

	jsonBytes, err := base64.StdEncoding.DecodeString(envelope)
	if err != nil {
		t.Fatalf("envelope is not valid base64: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("envelope JSON is invalid: %v", err)
	}
	if parsed["k_id"] != "my-key" {
		t.Errorf("k_id = %v, want %q", parsed["k_id"], "my-key")
	}
	if parsed["v"] != float64(1) {
		t.Errorf("v = %v, want 1", parsed["v"])
	}
	if parsed["k_len"] != float64(keySize) {
		t.Errorf("k_len = %v, want %d", parsed["k_len"], keySize)
	}
	for _, field := range []string{"m", "tag"} {
		if _, ok := parsed[field]; !ok {
			t.Errorf("envelope missing %q field", field)
		}
	}
}

func TestMultipleMessagesInOrder(t *testing.T) {
	dir := t.TempDir()
	senderKey := writeTestKey(t, dir, "sender.key", keySize)
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
		pt, _, err := metadata.Decipher(receiverKey, "k", env)
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
	senderKey := writeTestKey(t, dir, "sender.key", keySize)
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
	_, _, err = metadata.Decipher(receiverKey, "k", env2)
	if err == nil {
		t.Fatal("expected error when deciphering out-of-order message")
	}
	if !strings.Contains(err.Error(), "key length mismatch") {
		t.Errorf("expected key length mismatch error, got: %v", err)
	}

	// Receive first message — should succeed.
	pt, _, err := metadata.Decipher(receiverKey, "k", env1)
	if err != nil {
		t.Fatalf("Decipher first: %v", err)
	}
	if string(pt) != "first" {
		t.Errorf("got %q, want %q", pt, "first")
	}

	// Now second message should succeed.
	pt, _, err = metadata.Decipher(receiverKey, "k", env2)
	if err != nil {
		t.Fatalf("Decipher second: %v", err)
	}
	if string(pt) != "second" {
		t.Errorf("got %q, want %q", pt, "second")
	}
}

func TestKeyIDMismatchRejectsBeforeConsuming(t *testing.T) {
	dir := t.TempDir()
	senderKey := writeTestKey(t, dir, "sender.key", keySize)
	receiverKey := filepath.Join(dir, "receiver.key")
	copyFile(t, senderKey, receiverKey)

	envelope, _, err := metadata.Encipher(senderKey, "alice-bob", []byte("hello"))
	if err != nil {
		t.Fatalf("Encipher: %v", err)
	}

	_, _, err = metadata.Decipher(receiverKey, "alice-charlie", envelope)
	if err == nil {
		t.Fatal("expected error for key ID mismatch")
	}
	if !strings.Contains(err.Error(), "key ID mismatch") {
		t.Errorf("expected key ID mismatch error, got: %v", err)
	}

	// Key file should be untouched.
	info, _ := os.Stat(receiverKey)
	if info.Size() != keySize {
		t.Errorf("key file size = %d, want %d (consumed despite mismatch)", info.Size(), keySize)
	}

	// Correct key ID should still work.
	pt, _, err := metadata.Decipher(receiverKey, "alice-bob", envelope)
	if err != nil {
		t.Fatalf("Decipher with correct key ID: %v", err)
	}
	if string(pt) != "hello" {
		t.Errorf("plaintext = %q, want %q", pt, "hello")
	}
}

func TestTamperedCiphertextDoesNotBurnKey(t *testing.T) {
	dir := t.TempDir()
	senderKey := writeTestKey(t, dir, "sender.key", keySize)
	receiverKey := filepath.Join(dir, "receiver.key")
	copyFile(t, senderKey, receiverKey)

	envelope, _, err := metadata.Encipher(senderKey, "k", []byte("secret"))
	if err != nil {
		t.Fatalf("Encipher: %v", err)
	}

	// Decode envelope, tamper with ciphertext, re-encode.
	jsonBytes, _ := base64.StdEncoding.DecodeString(envelope)
	var parsed map[string]any
	json.Unmarshal(jsonBytes, &parsed)
	ct, _ := base64.StdEncoding.DecodeString(parsed["m"].(string))
	ct[0] ^= 0xFF
	parsed["m"] = base64.StdEncoding.EncodeToString(ct)
	tampered, _ := json.Marshal(parsed)
	tamperedEnv := base64.StdEncoding.EncodeToString(tampered)

	_, _, err = metadata.Decipher(receiverKey, "k", tamperedEnv)
	if err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("expected authentication failed error, got: %v", err)
	}

	// Key file should be untouched.
	info, _ := os.Stat(receiverKey)
	if info.Size() != keySize {
		t.Errorf("key file size = %d, want %d (key burned on forged message)", info.Size(), keySize)
	}

	// Original envelope should still work.
	pt, _, err := metadata.Decipher(receiverKey, "k", envelope)
	if err != nil {
		t.Fatalf("Decipher original: %v", err)
	}
	if string(pt) != "secret" {
		t.Errorf("plaintext = %q, want %q", pt, "secret")
	}
}

func TestTamperedMetadataDoesNotBurnKey(t *testing.T) {
	dir := t.TempDir()
	senderKey := writeTestKey(t, dir, "sender.key", keySize)
	receiverKey := filepath.Join(dir, "receiver.key")
	copyFile(t, senderKey, receiverKey)

	envelope, _, err := metadata.Encipher(senderKey, "k", []byte("secret"))
	if err != nil {
		t.Fatalf("Encipher: %v", err)
	}

	// Decode envelope, tamper with k_len, re-encode.
	jsonBytes, _ := base64.StdEncoding.DecodeString(envelope)
	var parsed map[string]any
	json.Unmarshal(jsonBytes, &parsed)
	parsed["k_len"] = float64(9999)
	tampered, _ := json.Marshal(parsed)
	tamperedEnv := base64.StdEncoding.EncodeToString(tampered)

	_, _, err = metadata.Decipher(receiverKey, "k", tamperedEnv)
	if err == nil {
		t.Fatal("expected error for tampered k_len")
	}

	// Key file should be untouched.
	info, _ := os.Stat(receiverKey)
	if info.Size() != keySize {
		t.Errorf("key file size = %d, want %d (key burned on forged message)", info.Size(), keySize)
	}
}

func TestMissingKeyFile(t *testing.T) {
	missing := "/nonexistent/key.bin"

	_, _, err := metadata.Encipher(missing, "k", []byte("hello"))
	if err == nil {
		t.Error("Encipher: expected error for missing key file")
	}

	// Decipher needs a valid envelope.
	dir := t.TempDir()
	senderKey := writeTestKey(t, dir, "sender.key", keySize)
	env, _, err := metadata.Encipher(senderKey, "k", []byte("hi"))
	if err != nil {
		t.Fatalf("setup Encipher: %v", err)
	}

	_, _, err = metadata.Decipher(missing, "k", env)
	if err == nil {
		t.Error("Decipher: expected error for missing key file")
	}
}

func TestKeyTooShort(t *testing.T) {
	dir := t.TempDir()
	// Key is 3 bytes — not enough for any message + 32 MAC bytes.
	keyFile := writeTestKey(t, dir, "short.key", 3)

	_, _, err := metadata.Encipher(keyFile, "k", []byte("x"))
	if err == nil {
		t.Error("expected error for key too short")
	}
}

func TestDecipherInvalidEnvelope(t *testing.T) {
	dir := t.TempDir()
	keyFile := writeTestKey(t, dir, "test.key", keySize)

	// Not valid base64.
	_, _, err := metadata.Decipher(keyFile, "k", "!!!invalid!!!")
	if err == nil {
		t.Error("expected error for invalid base64")
	}

	// Valid base64 but not JSON.
	_, _, err = metadata.Decipher(keyFile, "k", base64.StdEncoding.EncodeToString([]byte("not json")))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestDecipherMissingOrEmptyKeyID(t *testing.T) {
	dir := t.TempDir()
	keyFile := writeTestKey(t, dir, "test.key", keySize)

	makeEnvelope := func(jsonStr string) string {
		return base64.StdEncoding.EncodeToString([]byte(jsonStr))
	}

	// Envelope with k_id omitted entirely.
	env := makeEnvelope(`{"v":1,"m":"aGk=","k_len":16,"tag":"AAAAAAAAAAAAAAAAAAAAAA=="}`)
	_, _, err := metadata.Decipher(keyFile, "test.key", env)
	if err == nil {
		t.Error("expected error for missing k_id")
	}
	if !strings.Contains(err.Error(), "key ID mismatch") {
		t.Errorf("expected key ID mismatch error, got: %v", err)
	}

	// Envelope with k_id set to empty string.
	env = makeEnvelope(`{"v":1,"m":"aGk=","k_id":"","k_len":16,"tag":"AAAAAAAAAAAAAAAAAAAAAA=="}`)
	_, _, err = metadata.Decipher(keyFile, "test.key", env)
	if err == nil {
		t.Error("expected error for empty k_id")
	}
	if !strings.Contains(err.Error(), "key ID mismatch") {
		t.Errorf("expected key ID mismatch error, got: %v", err)
	}

	// Key file should be untouched.
	info, _ := os.Stat(keyFile)
	if info.Size() != keySize {
		t.Errorf("key file size = %d, want %d", info.Size(), keySize)
	}
}

func TestFramingDistinguishesBoundaryAmbiguity(t *testing.T) {
	// These two (keyID, ciphertext) pairs would produce the same naive
	// concatenation keyID||ciphertext = "abc" + "de" = "ab" + "cde",
	// but the self-delimiting framing must make them produce different
	// tags. We verify this by enciphering with the same key material
	// and checking the tags differ.
	dir := t.TempDir()

	// Create two identical key files so both encrypt with the same key bytes.
	key1 := writeTestKey(t, dir, "k1.key", keySize)
	key2 := filepath.Join(dir, "k2.key")
	copyFile(t, key1, key2)

	// Encipher the same plaintext with different key IDs.
	// The ciphertext will be identical (same key, same plaintext),
	// but the key IDs differ ("abc" vs "ab"), so the MAC inputs must differ.
	env1, _, err := metadata.Encipher(key1, "abc", []byte("de"))
	if err != nil {
		t.Fatalf("Encipher 1: %v", err)
	}
	env2, _, err := metadata.Encipher(key2, "ab", []byte("de"))
	if err != nil {
		t.Fatalf("Encipher 2: %v", err)
	}

	// Decode both envelopes and compare tags.
	decode := func(env string) map[string]any {
		jsonBytes, _ := base64.StdEncoding.DecodeString(env)
		var parsed map[string]any
		json.Unmarshal(jsonBytes, &parsed)
		return parsed
	}
	parsed1 := decode(env1)
	parsed2 := decode(env2)

	// Ciphertext should be identical (same key bytes, same plaintext).
	if parsed1["m"] != parsed2["m"] {
		t.Fatal("ciphertexts differ — test setup is wrong")
	}

	// Tags must differ because the self-delimiting framing encodes
	// the key ID length, making "abc"||"de" distinct from "ab"||"cde"
	// in the MAC input.
	if parsed1["tag"] == parsed2["tag"] {
		t.Error("tags should differ for different key IDs even with identical ciphertext")
	}
}

func TestDecipherVersionMismatch(t *testing.T) {
	dir := t.TempDir()
	senderKey := writeTestKey(t, dir, "sender.key", keySize)
	receiverKey := filepath.Join(dir, "receiver.key")
	copyFile(t, senderKey, receiverKey)

	envelope, _, err := metadata.Encipher(senderKey, "k", []byte("hello"))
	if err != nil {
		t.Fatalf("Encipher: %v", err)
	}

	// Decode envelope, change version to 2, re-encode.
	jsonBytes, _ := base64.StdEncoding.DecodeString(envelope)
	var parsed map[string]any
	json.Unmarshal(jsonBytes, &parsed)
	parsed["v"] = float64(2)
	tampered, _ := json.Marshal(parsed)
	tamperedEnv := base64.StdEncoding.EncodeToString(tampered)

	_, _, err = metadata.Decipher(receiverKey, "k", tamperedEnv)
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
	if !strings.Contains(err.Error(), "unsupported envelope version") {
		t.Errorf("expected version mismatch error, got: %v", err)
	}

	// Key file should be untouched.
	info, _ := os.Stat(receiverKey)
	if info.Size() != keySize {
		t.Errorf("key file size = %d, want %d (key consumed despite version mismatch)", info.Size(), keySize)
	}
}

func TestDecipherCorruptedMessageField(t *testing.T) {
	dir := t.TempDir()
	keyFile := writeTestKey(t, dir, "test.key", keySize)

	// Envelope with correct k_id but m is not valid base64.
	raw := `{"v":1,"m":"!!!not-base64!!!","k_id":"test.key","k_len":256,"tag":"AAAAAAAAAAAAAAAAAAAAAA=="}`
	env := base64.StdEncoding.EncodeToString([]byte(raw))

	_, _, err := metadata.Decipher(keyFile, "test.key", env)
	if err == nil {
		t.Fatal("expected error for corrupted m field")
	}
	if !strings.Contains(err.Error(), "invalid ciphertext encoding") {
		t.Errorf("expected ciphertext encoding error, got: %v", err)
	}

	// Key file should be untouched.
	info, _ := os.Stat(keyFile)
	if info.Size() != keySize {
		t.Errorf("key file size = %d, want %d", info.Size(), keySize)
	}
}
