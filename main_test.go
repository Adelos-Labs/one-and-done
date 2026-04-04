package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "otp")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build failed: %v", err)
	}
	return bin
}

func TestCLI_Help(t *testing.T) {
	bin := buildBinary(t)

	for _, args := range [][]string{{}, {"help"}, {"-h"}, {"--help"}} {
		out, err := exec.Command(bin, args...).CombinedOutput()
		if err != nil {
			t.Errorf("otp %v failed: %v\n%s", args, err, out)
			continue
		}
		if !strings.Contains(string(out), "Usage:") {
			t.Errorf("otp %v: expected help text, got %q", args, out)
		}
	}
}

func TestCLI_UnknownCommand(t *testing.T) {
	bin := buildBinary(t)
	out, err := exec.Command(bin, "bogus").CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit for unknown command")
	}
	if !strings.Contains(string(out), "unknown command: bogus") {
		t.Errorf("unexpected output: %s", out)
	}
}

func TestCLI_MissingArgs(t *testing.T) {
	bin := buildBinary(t)

	for _, cmd := range []string{"encipher", "decipher", "genkey"} {
		out, err := exec.Command(bin, cmd).CombinedOutput()
		if err == nil {
			t.Errorf("otp %s with no args should fail", cmd)
			continue
		}
		if !strings.Contains(string(out), "Usage:") {
			t.Errorf("otp %s: expected help text on missing args, got %q", cmd, out)
		}
	}
}

func TestCLI_PartialArgs(t *testing.T) {
	bin := buildBinary(t)

	for _, cmd := range []string{"encipher", "decipher", "genkey"} {
		out, err := exec.Command(bin, cmd, "only-one-arg").CombinedOutput()
		if err == nil {
			t.Errorf("otp %s with one arg should fail", cmd)
			continue
		}
		if !strings.Contains(string(out), "Usage:") {
			t.Errorf("otp %s: expected help text on partial args, got %q", cmd, out)
		}
	}
}

func TestCLI_GenkeyEncipherDecipher(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	senderKey := filepath.Join(dir, "sender.key")
	receiverKey := filepath.Join(dir, "receiver.key")
	message := "hello world"

	// genkey
	out, err := exec.Command(bin, "genkey", senderKey, "64").CombinedOutput()
	if err != nil {
		t.Fatalf("genkey failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "wrote 64-byte key to "+senderKey) {
		t.Fatalf("genkey success output = %q, want success message", out)
	}
	keyData, err := os.ReadFile(senderKey)
	if err != nil {
		t.Fatalf("key file not created: %v", err)
	}
	if len(keyData) != 64 {
		t.Fatalf("key file has %d bytes, want 64", len(keyData))
	}

	// Copy key for the receiver (simulating secure key distribution).
	if err := os.WriteFile(receiverKey, keyData, 0600); err != nil {
		t.Fatal(err)
	}

	// encipher with sender's key
	encCmd := exec.Command(bin, "encipher", senderKey, message)
	var encStdout bytes.Buffer
	encCmd.Stdout = &encStdout
	if err := encCmd.Run(); err != nil {
		t.Fatalf("encipher failed: %v", err)
	}
	envelope := strings.TrimSpace(encStdout.String())
	if envelope == "" {
		t.Fatal("encipher produced empty output")
	}
	// Output should be keylen:base64
	parts := strings.SplitN(envelope, ":", 2)
	if len(parts) != 2 {
		t.Fatalf("expected keylen:base64 format, got %q", envelope)
	}
	keyLen, err := strconv.Atoi(parts[0])
	if err != nil {
		t.Fatalf("invalid key length in output: %v", err)
	}
	if keyLen != 64 {
		t.Errorf("key length = %d, want 64", keyLen)
	}
	ciphertext := envelope

	// Verify sender's key was partially consumed.
	senderRemaining, err := os.ReadFile(senderKey)
	if err != nil {
		t.Fatalf("read sender key after encipher: %v", err)
	}
	if len(senderRemaining) != 64-len(message) {
		t.Errorf("sender key has %d bytes remaining, want %d", len(senderRemaining), 64-len(message))
	}

	// decipher with receiver's key
	decCmd := exec.Command(bin, "decipher", receiverKey, ciphertext)
	var decStdout bytes.Buffer
	decCmd.Stdout = &decStdout
	if err := decCmd.Run(); err != nil {
		t.Fatalf("decipher failed: %v", err)
	}
	got := strings.TrimSpace(decStdout.String())
	if got != message {
		t.Errorf("roundtrip failed: got %q, want %q", got, message)
	}

	// Verify receiver's key was partially consumed.
	receiverRemaining, err := os.ReadFile(receiverKey)
	if err != nil {
		t.Fatalf("read receiver key after decipher: %v", err)
	}
	if len(receiverRemaining) != 64-len(message) {
		t.Errorf("receiver key has %d bytes remaining, want %d", len(receiverRemaining), 64-len(message))
	}
}

func TestCLI_FullKeyConsumption(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "exact.key")
	message := "hello"

	// Generate a key exactly the length of the message.
	out, err := exec.Command(bin, "genkey", keyFile, strconv.Itoa(len(message))).CombinedOutput()
	if err != nil {
		t.Fatalf("genkey: %v\n%s", err, out)
	}

	// Encipher should fully consume the key and remove the file.
	encCmd := exec.Command(bin, "encipher", keyFile, message)
	var encStderr bytes.Buffer
	encCmd.Stdout = io.Discard
	encCmd.Stderr = &encStderr
	if err := encCmd.Run(); err != nil {
		t.Fatalf("encipher: %v\n%s", err, encStderr.String())
	}
	if !strings.Contains(encStderr.String(), "key fully consumed") {
		t.Errorf("expected key-fully-consumed message, got: %q", encStderr.String())
	}
	if _, err := os.Stat(keyFile); !os.IsNotExist(err) {
		t.Errorf("key file should have been removed after full consumption")
	}
}

func TestCLI_GenkeyRefusesOverwrite(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "existing.key")
	original := []byte{0xAA, 0xBB, 0xCC}
	if err := os.WriteFile(keyFile, original, 0600); err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command(bin, "genkey", keyFile, "32").CombinedOutput()
	if err == nil {
		t.Fatal("expected genkey to fail when key file already exists")
	}
	if !strings.Contains(string(out), "key file already exists, refusing to overwrite: "+keyFile) {
		t.Errorf("expected overwrite refusal message, got: %s", out)
	}

	got, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("os.ReadFile: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("existing key file was modified: got %x, want %x", got, original)
	}
}

func TestCLI_MissingKeyFile(t *testing.T) {
	bin := buildBinary(t)
	missing := "/nonexistent/path/key.bin"

	for _, tt := range []struct {
		cmd  string
		args []string
	}{
		{"encipher", []string{"encipher", missing, "hello"}},
		{"decipher", []string{"decipher", missing, "100:aGVsbG8="}},
	} {
		out, err := exec.Command(bin, tt.args...).CombinedOutput()
		if err == nil {
			t.Errorf("otp %s with missing key file should fail", tt.cmd)
			continue
		}
		if !strings.Contains(string(out), "error reading") {
			t.Errorf("otp %s: expected key read error, got %q", tt.cmd, out)
		}
	}
}

func TestCLI_KeyTooShort(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "short.key")
	if err := os.WriteFile(keyFile, []byte{0x01}, 0600); err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		cmd  string
		args []string
	}{
		{"encipher", []string{"encipher", keyFile, "hello world"}},
		{"decipher", []string{"decipher", keyFile, "1:aGVsbG8gd29ybGQ="}},
	} {
		out, err := exec.Command(bin, tt.args...).CombinedOutput()
		if err == nil {
			t.Errorf("otp %s with short key should fail", tt.cmd)
			continue
		}
		if !strings.Contains(string(out), "key too short") {
			t.Errorf("otp %s: expected key too short error, got %q", tt.cmd, out)
		}
	}
}

func TestCLI_GenkeyInvalidLength(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()

	for _, length := range []string{"abc", "0", "-5"} {
		keyFile := filepath.Join(dir, "key-"+length+".key")
		out, err := exec.Command(bin, "genkey", keyFile, length).CombinedOutput()
		if err == nil {
			t.Errorf("otp genkey %s should fail", length)
			continue
		}
		if !strings.Contains(string(out), "length must be a positive integer") {
			t.Errorf("otp genkey %s: expected length error, got %q", length, out)
		}
	}
}

func TestCLI_GenkeyWriteFailure(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "missing", "key.bin")

	out, err := exec.Command(bin, "genkey", keyFile, "16").CombinedOutput()
	if err == nil {
		t.Fatal("expected failure for unwritable key path")
	}
	if !strings.Contains(string(out), "error writing key file:") {
		t.Fatalf("expected write failure prefix, got %q", out)
	}
	if !strings.Contains(string(out), "write key "+keyFile+":") {
		t.Fatalf("expected wrapped path in write failure, got %q", out)
	}
}

func TestCLI_DecipherInvalidBase64(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "test.key")
	if err := os.WriteFile(keyFile, []byte("key"), 0600); err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command(bin, "decipher", keyFile, "3:not-valid-base64!!!").CombinedOutput()
	if err == nil {
		t.Fatal("expected failure for invalid base64")
	}
	if !strings.Contains(string(out), "invalid base64") {
		t.Errorf("unexpected error message: %s", out)
	}
}

func TestCLI_DecipherInvalidFormat(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "test.key")
	if err := os.WriteFile(keyFile, []byte("key"), 0600); err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command(bin, "decipher", keyFile, "no-colon-here").CombinedOutput()
	if err == nil {
		t.Fatal("expected failure for missing keylen prefix")
	}
	if !strings.Contains(string(out), "invalid message format") {
		t.Errorf("unexpected error message: %s", out)
	}
}

func TestCLI_OutOfOrderDetected(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	senderKey := filepath.Join(dir, "sender.key")
	receiverKey := filepath.Join(dir, "receiver.key")

	// Generate key and copy to receiver.
	out, err := exec.Command(bin, "genkey", senderKey, "64").CombinedOutput()
	if err != nil {
		t.Fatalf("genkey: %v\n%s", err, out)
	}
	keyData, _ := os.ReadFile(senderKey)
	os.WriteFile(receiverKey, keyData, 0600)

	// Send two messages.
	enc1 := exec.Command(bin, "encipher", senderKey, "first")
	var out1 bytes.Buffer
	enc1.Stdout = &out1
	if err := enc1.Run(); err != nil {
		t.Fatalf("encipher first: %v", err)
	}
	msg1 := strings.TrimSpace(out1.String())

	enc2 := exec.Command(bin, "encipher", senderKey, "second")
	var out2 bytes.Buffer
	enc2.Stdout = &out2
	if err := enc2.Run(); err != nil {
		t.Fatalf("encipher second: %v", err)
	}
	msg2 := strings.TrimSpace(out2.String())

	// Try to decipher second message first — should fail with mismatch error.
	decOut, err := exec.Command(bin, "decipher", receiverKey, msg2).CombinedOutput()
	if err == nil {
		t.Fatal("expected error deciphering out-of-order message")
	}
	if !strings.Contains(string(decOut), "key length mismatch") {
		t.Errorf("expected key length mismatch error, got: %s", decOut)
	}

	// Decipher first message — should succeed.
	dec1 := exec.Command(bin, "decipher", receiverKey, msg1)
	var dec1Out bytes.Buffer
	dec1.Stdout = &dec1Out
	if err := dec1.Run(); err != nil {
		t.Fatalf("decipher first: %v", err)
	}
	if got := strings.TrimSpace(dec1Out.String()); got != "first" {
		t.Errorf("first message = %q, want %q", got, "first")
	}

	// Now second message should succeed.
	dec2 := exec.Command(bin, "decipher", receiverKey, msg2)
	var dec2Out bytes.Buffer
	dec2.Stdout = &dec2Out
	if err := dec2.Run(); err != nil {
		t.Fatalf("decipher second: %v", err)
	}
	if got := strings.TrimSpace(dec2Out.String()); got != "second" {
		t.Errorf("second message = %q, want %q", got, "second")
	}
}
