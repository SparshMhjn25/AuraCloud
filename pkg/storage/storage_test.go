package storage

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestStorageOperations(t *testing.T) {
	tempDir := t.TempDir()

	cid := "testcid1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	nonce := []byte("123456789012") // 12 bytes
	ciphertext := []byte("encrypted_payload_bytes_here")

	err := SaveEncryptedChunk(tempDir, cid, nonce, ciphertext)
	if err != nil {
		t.Fatalf("SaveEncryptedChunk failed: %v", err)
	}

	loadedNonce, loadedCiphertext, err := LoadEncryptedChunk(tempDir, cid)
	if err != nil {
		t.Fatalf("LoadEncryptedChunk failed: %v", err)
	}

	if !bytes.Equal(nonce, loadedNonce) {
		t.Errorf("Loaded nonce %s does not match original %s", loadedNonce, nonce)
	}

	if !bytes.Equal(ciphertext, loadedCiphertext) {
		t.Errorf("Loaded ciphertext %s does not match original %s", loadedCiphertext, ciphertext)
	}

	// Reassembly test
	chunk1 := []byte("Hello ")
	chunk2 := []byte("World!")
	outputPath := filepath.Join(tempDir, "reassembled.txt")

	err = ReassembleFile(outputPath, [][]byte{chunk1, chunk2})
	if err != nil {
		t.Fatalf("ReassembleFile failed: %v", err)
	}

	resBytes, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	if string(resBytes) != "Hello World!" {
		t.Fatalf("Reassembled string got %q, expected %q", string(resBytes), "Hello World!")
	}
}
