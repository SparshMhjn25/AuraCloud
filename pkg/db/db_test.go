package db

import (
	"path/filepath"
	"testing"
	"time"
)

func TestDatabaseOperations(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_manifest.db")

	database, err := InitDB(dbPath)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	defer database.Close()

	// 1. Register File Manifest
	fileRec := FileRecord{
		ID:          "test-file-uuid-12345",
		FileName:    "sample_image.png",
		FileSize:    5242880,
		MimeType:    "image/png",
		TotalChunks: 2,
		CreatedAt:   time.Now().Truncate(time.Second),
	}

	chunks := []ChunkRecord{
		{
			ChunkIndex: 0,
			CID:        "cid_chunk_0000000000000000000000000000000000000000000000000000000001",
			NonceHex:   "0102030405060708090a0b0c",
			ChunkSize:  2097152,
		},
		{
			ChunkIndex: 1,
			CID:        "cid_chunk_0000000000000000000000000000000000000000000000000000000002",
			NonceHex:   "0d0e0f101112131415161718",
			ChunkSize:  3145728,
		},
	}

	err = database.RegisterFile(fileRec, chunks)
	if err != nil {
		t.Fatalf("RegisterFile failed: %v", err)
	}

	// 2. Fetch Manifest by ID
	manifest, err := database.GetFileManifest(fileRec.ID)
	if err != nil {
		t.Fatalf("GetFileManifest failed: %v", err)
	}

	if manifest.File.FileName != fileRec.FileName {
		t.Errorf("Expected filename %s, got %s", fileRec.FileName, manifest.File.FileName)
	}

	if len(manifest.Chunks) != 2 {
		t.Fatalf("Expected 2 chunk records, got %d", len(manifest.Chunks))
	}

	if manifest.Chunks[0].ChunkIndex != 0 || manifest.Chunks[1].ChunkIndex != 1 {
		t.Errorf("Chunks are not ordered properly: %v", manifest.Chunks)
	}

	if manifest.Chunks[0].NonceHex != chunks[0].NonceHex {
		t.Errorf("Expected nonce %s, got %s", chunks[0].NonceHex, manifest.Chunks[0].NonceHex)
	}

	// 3. Fetch Manifest by Name
	manifestByName, err := database.GetFileManifestByName("sample_image.png")
	if err != nil {
		t.Fatalf("GetFileManifestByName failed: %v", err)
	}
	if manifestByName.File.ID != fileRec.ID {
		t.Errorf("GetFileManifestByName returned wrong ID %s, expected %s", manifestByName.File.ID, fileRec.ID)
	}

	// 4. List Files
	fileList, err := database.ListFiles()
	if err != nil {
		t.Fatalf("ListFiles failed: %v", err)
	}

	if len(fileList) != 1 {
		t.Fatalf("Expected 1 file in list, got %d", len(fileList))
	}

	if fileList[0].ID != fileRec.ID {
		t.Errorf("ListFiles returned wrong file ID %s", fileList[0].ID)
	}

	// 5. Phase 2 durable store-and-forward queue lifecycle.
	if err := database.EnqueueSyncChunks(fileRec.ID, []string{chunks[0].CID, chunks[1].CID}, "100.64.0.10"); err != nil {
		t.Fatalf("EnqueueSyncChunks failed: %v", err)
	}
	queued, err := database.ListEligibleSyncQueue("100.64.0.10")
	if err != nil || len(queued) != 2 {
		t.Fatalf("Expected two eligible sync jobs, got %d (err=%v)", len(queued), err)
	}
	claimed, err := database.ClaimSyncQueueItem(queued[0].ID)
	if err != nil || !claimed {
		t.Fatalf("ClaimSyncQueueItem failed: claimed=%v err=%v", claimed, err)
	}
	if err := database.MarkSyncQueueFailed(queued[0].ID); err != nil {
		t.Fatalf("MarkSyncQueueFailed failed: %v", err)
	}
	if err := database.MarkSyncQueueCompleted(queued[1].ID); err != nil {
		t.Fatalf("MarkSyncQueueCompleted failed: %v", err)
	}
	complete, err := database.PeerFileSyncComplete(fileRec.ID, "100.64.0.10")
	if err != nil || complete {
		t.Fatalf("Expected failed job to keep peer/file incomplete, complete=%v err=%v", complete, err)
	}
	stats, err := database.GetSyncQueueStats()
	if err != nil || stats.PendingChunks != 1 {
		t.Fatalf("Expected one retryable sync job, got %+v (err=%v)", stats, err)
	}
}

func TestRegisterReplicatedManifestIsIdempotent(t *testing.T) {
	database, err := InitDB(filepath.Join(t.TempDir(), "replicated_manifest.db"))
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	defer database.Close()

	file := FileRecord{
		ID:          "replicated-file-123",
		FileName:    "replicated.bin",
		FileSize:    42,
		MimeType:    "application/octet-stream",
		TotalChunks: 1,
		CreatedAt:   time.Now().UTC(),
	}
	chunks := []ChunkRecord{{ChunkIndex: 0, CID: "replicated-cid", NonceHex: "0102030405060708090a0b0c", ChunkSize: 42}}

	inserted, err := database.RegisterReplicatedManifest(file, chunks)
	if err != nil || !inserted {
		t.Fatalf("Expected initial replicated manifest insert, inserted=%v err=%v", inserted, err)
	}
	inserted, err = database.RegisterReplicatedManifest(file, chunks)
	if err != nil || inserted {
		t.Fatalf("Expected duplicate replicated manifest to be in sync, inserted=%v err=%v", inserted, err)
	}

	manifest, err := database.GetFileManifest(file.ID)
	if err != nil || len(manifest.Chunks) != 1 {
		t.Fatalf("Expected one persisted chunk after duplicate manifest, manifest=%+v err=%v", manifest, err)
	}
}
