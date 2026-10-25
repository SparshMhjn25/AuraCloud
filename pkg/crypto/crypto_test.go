package crypto

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCryptoOperations(t *testing.T) {
	key, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey failed: %v", err)
	}

	if len(key) != KeySize {
		t.Fatalf("Expected key length %d, got %d", KeySize, len(key))
	}

	data := []byte("AuraCloud Peer-to-Peer Backup System Test Payload")
	cid := GenerateCID(data)
	if len(cid) != 64 { // SHA-256 hex string is 64 characters
		t.Fatalf("Expected 64 char hex string for CID, got %d chars: %s", len(cid), cid)
	}

	ciphertext, nonce, err := EncryptChunk(data, key)
	if err != nil {
		t.Fatalf("EncryptChunk failed: %v", err)
	}

	decrypted, err := DecryptChunk(ciphertext, nonce, key)
	if err != nil {
		t.Fatalf("DecryptChunk failed: %v", err)
	}

	if !bytes.Equal(data, decrypted) {
		t.Fatalf("Decrypted data does not match original data")
	}

	// Test Tampering Detection
	corruptedCiphertext := make([]byte, len(ciphertext))
	copy(corruptedCiphertext, ciphertext)
	corruptedCiphertext[0] ^= 0xFF // Flip a bit

	_, err = DecryptChunk(corruptedCiphertext, nonce, key)
	if err == nil {
		t.Fatalf("Expected error when decrypting tampered ciphertext, but got nil")
	}
}

func TestLoadOrCreateMasterKey(t *testing.T) {
	t.Run("generates then reloads file key", func(t *testing.T) {
		storageDir := t.TempDir()
		first, source, err := LoadOrCreateMasterKey(storageDir)
		if err != nil || source != "generated" {
			t.Fatalf("first key load = source %q, err %v", source, err)
		}
		second, source, err := LoadOrCreateMasterKey(storageDir)
		if err != nil || source != "file" {
			t.Fatalf("second key load = source %q, err %v", source, err)
		}
		if !bytes.Equal(first, second) {
			t.Fatal("reloaded key differs from generated key")
		}
		info, err := os.Stat(filepath.Join(storageDir, masterKeyFileName))
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
			t.Fatalf("master key permissions = %o, want 0600", info.Mode().Perm())
		}
	})

	t.Run("uses hex environment key", func(t *testing.T) {
		t.Setenv("AURA_MASTER_KEY", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
		key, source, err := LoadOrCreateMasterKey(t.TempDir())
		if err != nil || source != "environment" || len(key) != KeySize || key[0] != 0 || key[31] != 31 {
			t.Fatalf("environment key = %x, source %q, err %v", key, source, err)
		}
	})

	t.Run("derives non-hex environment value", func(t *testing.T) {
		t.Setenv("AURA_MASTER_KEY", "passphrase shared by mesh nodes")
		first, source, err := LoadOrCreateMasterKey(t.TempDir())
		if err != nil || source != "environment" || len(first) != KeySize {
			t.Fatalf("derived environment key source %q, err %v", source, err)
		}
		second, _, err := LoadOrCreateMasterKey(t.TempDir())
		if err != nil || !bytes.Equal(first, second) {
			t.Fatal("environment derivation is not deterministic")
		}
	})
}
