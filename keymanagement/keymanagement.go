package keymanagement

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
)

var ErrKeyExists = errors.New("key file already exists")

func GenKey(length int) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("key length must be positive")
	}

	key := make([]byte, length)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func ReadKey(path string, requiredLength int) ([]byte, error) {
	full, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading %s: %w", path, err)
	}
	if requiredLength < 0 {
		clear(full)
		return nil, fmt.Errorf("length must be non-negative, got %d", requiredLength)
	}
	if len(full) < requiredLength {
		clear(full)
		return nil, fmt.Errorf("key too short: need %d bytes, have %d", requiredLength, len(full))
	}
	out := make([]byte, requiredLength)
	copy(out, full[:requiredLength])
	clear(full)
	return out, nil
}

// ConsumeKey reads length bytes from the front of the key file, securely
// overwrites the used portion on disk, and rewrites the file with only the
// remaining bytes. Returns the consumed key material and the number of
// bytes still available. Deletes the file when fully consumed.
func ConsumeKey(path string, length int) ([]byte, int, error) {
	full, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, fmt.Errorf("error reading %s: %w", path, err)
	}
	if length < 0 {
		clear(full)
		return nil, 0, fmt.Errorf("length must be non-negative, got %d", length)
	}
	if len(full) < length {
		clear(full)
		return nil, 0, fmt.Errorf("key too short: need %d bytes, have %d", length, len(full))
	}

	key := make([]byte, length)
	copy(key, full[:length])

	if err := secureRewrite(path, full, length); err != nil {
		clear(key)
		return nil, 0, err
	}

	return key, len(full) - length, nil
}

// secureRewrite overwrites the entire key file with zeros (flushed to disk),
// then rewrites it with only the unconsumed tail. If the key is fully
// consumed the file is removed.
func secureRewrite(path string, full []byte, consumed int) error {
	remaining := len(full) - consumed

	// Copy the unconsumed tail before we zero the buffer.
	tail := make([]byte, remaining)
	copy(tail, full[consumed:])

	// Clear the original buffer as soon as the tail is copied out.
	// Every exit path below only needs tail, not full.
	clear(full)

	f, err := os.OpenFile(path, os.O_WRONLY, 0600)
	if err != nil {
		clear(tail)
		return fmt.Errorf("error opening key for rewrite %s: %w", path, err)
	}
	defer f.Close()

	// Overwrite entire file with zeros to destroy used key material on disk.
	// len(full) is still valid after clear — only the contents are zeroed.
	if err := writeFull(f, make([]byte, len(full))); err != nil {
		clear(tail)
		return fmt.Errorf("error zeroing key %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		clear(tail)
		return fmt.Errorf("error syncing key %s: %w", path, err)
	}

	// From this point, the file on disk is all zeros. Any failure must
	// remove it so stale zeros are never mistaken for valid key material.

	if remaining == 0 {
		return os.Remove(path)
	}

	// Write the unconsumed tail back from the start of the file.
	if err := restoreTail(f, path, tail); err != nil {
		clear(tail)
		_ = os.Remove(path)
		return err
	}

	clear(tail)
	return nil
}

func restoreTail(f *os.File, path string, tail []byte) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("error seeking key %s: %w", path, err)
	}
	if err := writeFull(f, tail); err != nil {
		return fmt.Errorf("error writing remaining key %s: %w", path, err)
	}
	if err := f.Truncate(int64(len(tail))); err != nil {
		return fmt.Errorf("error truncating key %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("error syncing key %s: %w", path, err)
	}
	return nil
}

func WriteKey(path string, key []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return ErrKeyExists
		}
		return fmt.Errorf("write key %s: %w", path, err)
	}
	defer file.Close()

	if err := writeFull(file, key); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("write key %s: %w", path, err)
	}
	return nil
}

func writeFull(w io.Writer, data []byte) error {
	written, err := w.Write(data)
	if err != nil {
		return err
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	return nil
}
