package storage

import (
	"fmt"
	"os"
	"path/filepath"
)

// Architectural Concept: Local Chunk Storage & File Reconstruction
//
// In peer-to-peer backup engines:
// 1. Files are stored as independent encrypted blob files on disk.
// 2. We use Content Identifiers (CIDs) as filenames (e.g., `.auracloud_data/chunks/<CID>.chunk`).
// 3. Disk Persistence Format for each chunk file:
//    [ First 12 Bytes: Nonce ] + [ Remaining Bytes: Encrypted Ciphertext + Tag ]
//    By prepending the 12-byte initialization vector (nonce) to the ciphertext,
//    each chunk file remains self-contained. Any peer holding the master key can decrypt
//    a chunk directly from disk without needing an external database to lookup nonces.

const (
	// DefaultDataDir is the root directory where local backup assets reside.
	DefaultDataDir = ".auracloud_data"
	// ChunksSubDir is the subdirectory storing individual encrypted chunks.
	ChunksSubDir = "chunks"
	// StandardNonceSize is the fixed 12-byte nonce size for AES-GCM.
	StandardNonceSize = 12
)

// DefaultStoragePath returns `.auracloud_data/chunks`.
func DefaultStoragePath() string {
	return filepath.Join(DefaultDataDir, ChunksSubDir)
}

// EnsureStorageDir verifies or creates the specified directory path on disk.
// Uses `os.MkdirAll` with perm 0755 so parent directories are created if missing.
func EnsureStorageDir(dirPath string) error {
	if dirPath == "" {
		dirPath = DefaultStoragePath()
	}

	err := os.MkdirAll(dirPath, 0755)
	if err != nil {
		return fmt.Errorf("storage: failed to create storage directory %s: %w", dirPath, err)
	}

	return nil
}

// ChunkExists returns true if a chunk file `<cid>.chunk` already exists on disk.
func ChunkExists(dirPath string, cid string) bool {
	if dirPath == "" {
		dirPath = DefaultStoragePath()
	}
	chunkFilePath := filepath.Join(dirPath, cid+".chunk")
	_, err := os.Stat(chunkFilePath)
	return err == nil
}

// SaveEncryptedChunk persists an encrypted chunk to disk named `<cid>.chunk`.
// It prepends the 12-byte nonce to the ciphertext before writing.
//
// Parameters:
//   - dirPath: Target directory path (e.g., `.auracloud_data/chunks`).
//   - cid: Hex SHA-256 hash of plain chunk content.
//   - nonce: 12-byte AES-GCM nonce.
//   - ciphertext: Encrypted chunk payload.
//
// Returns:
//   - error: I/O error if write fails.
func SaveEncryptedChunk(dirPath string, cid string, nonce []byte, ciphertext []byte) error {
	if dirPath == "" {
		dirPath = DefaultStoragePath()
	}

	if err := EnsureStorageDir(dirPath); err != nil {
		return err
	}

	if len(nonce) != StandardNonceSize {
		return fmt.Errorf("storage: invalid nonce size: got %d bytes, expected %d bytes", len(nonce), StandardNonceSize)
	}

	chunkFilePath := filepath.Join(dirPath, cid+".chunk")

	// Allocate a slice combining [Nonce (12B)] + [Ciphertext]
	fileBuffer := make([]byte, len(nonce)+len(ciphertext))
	copy(fileBuffer[:StandardNonceSize], nonce)
	copy(fileBuffer[StandardNonceSize:], ciphertext)

	// Write to disk with restricted permissions (0600 = read/write by owner only).
	err := os.WriteFile(chunkFilePath, fileBuffer, 0600)
	if err != nil {
		return fmt.Errorf("storage: failed to write chunk file %s: %w", chunkFilePath, err)
	}

	return nil
}

// LoadEncryptedChunk reads a chunk file `<cid>.chunk` from disk and extracts the nonce and ciphertext.
func LoadEncryptedChunk(dirPath string, cid string) ([]byte, []byte, error) {
	if dirPath == "" {
		dirPath = DefaultStoragePath()
	}

	chunkFilePath := filepath.Join(dirPath, cid+".chunk")

	data, err := os.ReadFile(chunkFilePath)
	if err != nil {
		return nil, nil, fmt.Errorf("storage: failed to read chunk file %s: %w", chunkFilePath, err)
	}

	if len(data) < StandardNonceSize {
		return nil, nil, fmt.Errorf("storage: chunk file %s is corrupted (size %d bytes, expected >= %d bytes)", chunkFilePath, len(data), StandardNonceSize)
	}

	nonce := make([]byte, StandardNonceSize)
	copy(nonce, data[:StandardNonceSize])

	ciphertext := make([]byte, len(data)-StandardNonceSize)
	copy(ciphertext, data[StandardNonceSize:])

	return nonce, ciphertext, nil
}

// ReassembleFile writes ordered decrypted chunk byte slices sequentially into a destination file.
func ReassembleFile(outputPath string, orderedChunks [][]byte) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("storage: failed to create output file %s: %w", outputPath, err)
	}
	defer file.Close()

	for index, chunkData := range orderedChunks {
		n, err := file.Write(chunkData)
		if err != nil {
			return fmt.Errorf("storage: failed to write chunk index %d to output file: %w", index, err)
		}
		if n != len(chunkData) {
			return fmt.Errorf("storage: short write at chunk index %d (wrote %d of %d bytes)", index, n, len(chunkData))
		}
	}

	return nil
}
