package chunker

import (
	"bytes"
	"testing"
)

func TestChunkReader(t *testing.T) {
	// 5MB of test data
	dataSize := 5 * 1024 * 1024
	testData := make([]byte, dataSize)
	for i := range testData {
		testData[i] = byte(i % 251)
	}

	chunkSize := int64(2 * 1024 * 1024) // 2MB
	reader := bytes.NewReader(testData)

	chunks, err := ChunkReader(reader, chunkSize)
	if err != nil {
		t.Fatalf("ChunkReader failed: %v", err)
	}

	if len(chunks) != 3 {
		t.Fatalf("Expected 3 chunks, got %d", len(chunks))
	}

	if chunks[0].Size != chunkSize || chunks[1].Size != chunkSize {
		t.Errorf("First two chunks should be 2MB, got %d and %d", chunks[0].Size, chunks[1].Size)
	}

	expectedLastSize := int64(1 * 1024 * 1024)
	if chunks[2].Size != expectedLastSize {
		t.Errorf("Last chunk should be 1MB (%d), got %d", expectedLastSize, chunks[2].Size)
	}

	// Verify total byte length reassembled matches original
	totalBytes := int64(0)
	for _, c := range chunks {
		totalBytes += c.Size
	}
	if totalBytes != int64(dataSize) {
		t.Errorf("Total chunk bytes %d does not match original data size %d", totalBytes, dataSize)
	}
}
