package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"auracloud/pkg/crypto"
	"auracloud/pkg/db"
	"auracloud/pkg/network"
)

func setupTestServer(t *testing.T) *Server {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_manifest.db")
	storageDir := filepath.Join(tempDir, "chunks")

	database, err := db.InitDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to init test DB: %v", err)
	}

	t.Cleanup(func() {
		database.Close()
	})

	masterKey, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	// Server with NO Node (local-only mode) for standard API tests
	config := ServerConfig{
		Port:       8080,
		StorageDir: storageDir,
		MasterKey:  masterKey,
		Node:       nil, // local-only mode
	}

	return NewServer(database, config)
}

func TestHealthEndpoint(t *testing.T) {
	server := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200 OK, got %d", resp.StatusCode)
	}

	var body HealthResponse
	err := json.NewDecoder(resp.Body).Decode(&body)
	if err != nil {
		t.Fatalf("Failed to decode JSON response: %v", err)
	}

	if body.Status != "online" || body.System != "AuraCloud Core" {
		t.Errorf("Unexpected health response payload: %+v", body)
	}
}

// TestNodeStatusLocalOnlyMode verifies that when the server has no Tailscale node configured,
// GET /api/v1/node/status returns a "local_only" status with MeshEnabled=false.
func TestNodeStatusLocalOnlyMode(t *testing.T) {
	server := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/node/status", nil)
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for node status, got %d: %s", w.Code, w.Body.String())
	}

	var status network.NodeStatus
	err := json.NewDecoder(w.Body).Decode(&status)
	if err != nil {
		t.Fatalf("Failed to decode node status response: %v", err)
	}

	if status.MeshEnabled {
		t.Errorf("Expected MeshEnabled=false in local-only mode, got true")
	}
	if status.Status != "local_only" {
		t.Errorf("Expected status='local_only', got '%s'", status.Status)
	}
	if status.Hostname != "localhost" {
		t.Errorf("Expected hostname='localhost' in local-only mode, got '%s'", status.Hostname)
	}
}

func TestSyncStatusLocalOnlyMode(t *testing.T) {
	server := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sync/status", nil)
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for sync status, got %d: %s", w.Code, w.Body.String())
	}

	var status SyncStatusResponse
	if err := json.NewDecoder(w.Body).Decode(&status); err != nil {
		t.Fatalf("Failed to decode sync status response: %v", err)
	}
	if status.MeshEnabled || status.PeersOnline != 0 || status.PendingChunks != 0 {
		t.Errorf("Unexpected local-only sync status: %+v", status)
	}
}

func TestSyncManifestIsIdempotent(t *testing.T) {
	server := setupTestServer(t)
	payload := struct {
		File   db.FileRecord    `json:"file"`
		Chunks []db.ChunkRecord `json:"chunks"`
	}{
		File:   db.FileRecord{ID: "peer-file-123", FileName: "peer-file.bin", FileSize: 10, MimeType: "application/octet-stream", TotalChunks: 1, CreatedAt: time.Now().UTC()},
		Chunks: []db.ChunkRecord{{ChunkIndex: 0, CID: "peer-cid", NonceHex: "0102030405060708090a0b0c", ChunkSize: 10}},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal manifest: %v", err)
	}

	first := httptest.NewRecorder()
	server.Handler().ServeHTTP(first, httptest.NewRequest(http.MethodPost, "/api/v1/manifest/sync", bytes.NewReader(body)))
	if first.Code != http.StatusOK || !strings.Contains(first.Body.String(), "manifest_synced") {
		t.Fatalf("Expected first manifest to sync, got %d: %s", first.Code, first.Body.String())
	}

	second := httptest.NewRecorder()
	server.Handler().ServeHTTP(second, httptest.NewRequest(http.MethodPost, "/api/v1/manifest/sync", bytes.NewReader(body)))
	if second.Code != http.StatusOK || !strings.Contains(second.Body.String(), "in_sync") {
		t.Fatalf("Expected duplicate manifest to be in sync, got %d: %s", second.Code, second.Body.String())
	}
}

func TestUploadListDownloadDeletePipeline(t *testing.T) {
	server := setupTestServer(t)

	// 1. Create a synthetic test file payload (3MB to force multiple 2MB chunks)
	payloadSize := 3 * 1024 * 1024
	originalBytes := make([]byte, payloadSize)
	for i := range originalBytes {
		originalBytes[i] = byte((i * 17) % 256)
	}

	// 2. Perform Multipart Form File Upload (POST /api/v1/files/upload)
	bodyBuffer := new(bytes.Buffer)
	writer := multipart.NewWriter(bodyBuffer)
	part, err := writer.CreateFormFile("file", "api_test_image.png")
	if err != nil {
		t.Fatalf("Failed to create form file: %v", err)
	}
	part.Write(originalBytes)
	writer.Close()

	uploadReq := httptest.NewRequest(http.MethodPost, "/api/v1/files/upload", bodyBuffer)
	uploadReq.Header.Set("Content-Type", writer.FormDataContentType())
	uploadRec := httptest.NewRecorder()

	server.Handler().ServeHTTP(uploadRec, uploadReq)

	uploadResp := uploadRec.Result()
	if uploadResp.StatusCode != http.StatusCreated {
		t.Fatalf("Upload failed with status %d: %s", uploadResp.StatusCode, uploadRec.Body.String())
	}

	var uploadResult UploadResponse
	json.NewDecoder(uploadResp.Body).Decode(&uploadResult)

	if uploadResult.FileID == "" || uploadResult.FileName != "api_test_image.png" {
		t.Fatalf("Unexpected upload result: %+v", uploadResult)
	}
	if uploadResult.TotalChunks != 2 {
		t.Errorf("Expected 2 chunks for 3MB file, got %d", uploadResult.TotalChunks)
	}

	fileID := uploadResult.FileID

	// 3. List Files (GET /api/v1/files)
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/files", nil)
	listRec := httptest.NewRecorder()

	server.Handler().ServeHTTP(listRec, listReq)

	if listRec.Code != http.StatusOK {
		t.Fatalf("List files failed with status %d", listRec.Code)
	}

	var fileList []db.FileRecord
	json.NewDecoder(listRec.Body).Decode(&fileList)

	if len(fileList) != 1 || fileList[0].ID != fileID {
		t.Fatalf("Expected file list to contain ID %s, got: %+v", fileID, fileList)
	}

	// 4. Download File (GET /api/v1/files/download/{id})
	downloadReq := httptest.NewRequest(http.MethodGet, "/api/v1/files/download/"+fileID, nil)
	downloadRec := httptest.NewRecorder()

	server.Handler().ServeHTTP(downloadRec, downloadReq)

	downloadResp := downloadRec.Result()
	if downloadResp.StatusCode != http.StatusOK {
		t.Fatalf("Download failed with status %d", downloadResp.StatusCode)
	}

	downloadedBytes, err := io.ReadAll(downloadResp.Body)
	if err != nil {
		t.Fatalf("Failed to read download response body: %v", err)
	}

	if !bytes.Equal(originalBytes, downloadedBytes) {
		t.Fatalf("Downloaded payload does not match original uploaded bytes! Got size %d, expected %d", len(downloadedBytes), len(originalBytes))
	}

	// 5. Delete File (DELETE /api/v1/files/delete/{id})
	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/v1/files/delete/"+fileID, nil)
	deleteRec := httptest.NewRecorder()

	server.Handler().ServeHTTP(deleteRec, deleteReq)

	if deleteRec.Code != http.StatusOK {
		t.Fatalf("Delete failed with status %d: %s", deleteRec.Code, deleteRec.Body.String())
	}

	var deleteResult DeleteResponse
	json.NewDecoder(deleteRec.Body).Decode(&deleteResult)

	if deleteResult.FileID != fileID || deleteResult.PurgedChunks < 1 {
		t.Errorf("Unexpected delete response: %+v", deleteResult)
	}

	// 6. Verify File is 404 Not Found after deletion
	verifyReq := httptest.NewRequest(http.MethodGet, "/api/v1/files/download/"+fileID, nil)
	verifyRec := httptest.NewRecorder()

	server.Handler().ServeHTTP(verifyRec, verifyReq)

	if verifyRec.Code != http.StatusNotFound {
		t.Errorf("Expected status 404 Not Found for deleted file, got %d", verifyRec.Code)
	}
}

// TestEmbeddedWebDashboardServer verifies that GET / serves the embedded index.html dashboard file.
func TestEmbeddedWebDashboardServer(t *testing.T) {
	server := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200 OK for embedded Web UI dashboard, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read web dashboard response body: %v", err)
	}

	bodyStr := string(body)
	if !strings.Contains(bodyStr, "<title>AuraCloud - P2P Encrypted Backup Dashboard</title>") {
		t.Errorf("Expected embedded HTML title in dashboard response, got: %s", bodyStr[:100])
	}
	if !strings.Contains(bodyStr, "Tailscale Mesh Node Status") {
		t.Errorf("Expected node status panel in embedded HTML dashboard")
	}
}

// TestDownloadHandlerPreCheckAndSHA256Integrity verifies:
// 1. Correct response headers (Content-Type, Content-Disposition, Content-Length) before streaming.
// 2. Byte-for-byte SHA-256 integrity match between uploaded & downloaded file.
// 3. Pre-check chunk file existence on disk returning 404 if a chunk is missing.
func TestDownloadHandlerPreCheckAndSHA256Integrity(t *testing.T) {
	server := setupTestServer(t)

	// 1. Create a synthetic test file payload (5MB)
	payloadSize := 5 * 1024 * 1024
	originalBytes := make([]byte, payloadSize)
	for i := range originalBytes {
		originalBytes[i] = byte((i*31 + 7) % 256)
	}

	h := sha256.New()
	h.Write(originalBytes)
	origHash := hex.EncodeToString(h.Sum(nil))

	// 2. Upload file via POST /api/v1/files/upload
	bodyBuffer := new(bytes.Buffer)
	writer := multipart.NewWriter(bodyBuffer)
	part, err := writer.CreateFormFile("file", "e2e_test_file.dat")
	if err != nil {
		t.Fatalf("Failed to create form file: %v", err)
	}
	part.Write(originalBytes)
	writer.Close()

	uploadReq := httptest.NewRequest(http.MethodPost, "/api/v1/files/upload", bodyBuffer)
	uploadReq.Header.Set("Content-Type", writer.FormDataContentType())
	uploadRec := httptest.NewRecorder()

	server.Handler().ServeHTTP(uploadRec, uploadReq)
	if uploadRec.Code != http.StatusCreated {
		t.Fatalf("Upload failed: %s", uploadRec.Body.String())
	}

	var uploadResult UploadResponse
	json.NewDecoder(uploadRec.Body).Decode(&uploadResult)
	fileID := uploadResult.FileID

	// 3. Download file via GET /api/v1/files/download/{id}
	downloadReq := httptest.NewRequest(http.MethodGet, "/api/v1/files/download/"+fileID, nil)
	downloadRec := httptest.NewRecorder()

	server.Handler().ServeHTTP(downloadRec, downloadReq)
	resp := downloadRec.Result()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200 OK for download, got %d: %s", resp.StatusCode, downloadRec.Body.String())
	}

	// Verify Headers BEFORE reading body
	cd := resp.Header.Get("Content-Disposition")
	expectedCD := fmt.Sprintf("attachment; filename=\"%s\"", "e2e_test_file.dat")
	if cd != expectedCD {
		t.Errorf("Expected Content-Disposition '%s', got '%s'", expectedCD, cd)
	}

	cl := resp.Header.Get("Content-Length")
	expectedCL := fmt.Sprintf("%d", payloadSize)
	if cl != expectedCL {
		t.Errorf("Expected Content-Length '%s', got '%s'", expectedCL, cl)
	}

	downloadedBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read download response body: %v", err)
	}

	dh := sha256.New()
	dh.Write(downloadedBytes)
	downloadedHash := hex.EncodeToString(dh.Sum(nil))

	if origHash != downloadedHash {
		t.Fatalf("SHA-256 digest mismatch! Expected %s, got %s", origHash, downloadedHash)
	}

	// 4. Test Missing Chunk Pre-check behavior:
	// Remove one chunk file from storage dir and verify that download returns HTTP 404 BEFORE stream headers
	manifest, err := server.database.GetFileManifest(fileID)
	if err != nil || len(manifest.Chunks) == 0 {
		t.Fatalf("Failed to get manifest: %v", err)
	}

	missingChunkCID := manifest.Chunks[0].CID
	chunkPath := filepath.Join(server.config.StorageDir, missingChunkCID+".chunk")
	os.Remove(chunkPath) // Delete chunk file

	missingReq := httptest.NewRequest(http.MethodGet, "/api/v1/files/download/"+fileID, nil)
	missingRec := httptest.NewRecorder()

	server.Handler().ServeHTTP(missingRec, missingReq)
	if missingRec.Code != http.StatusNotFound {
		t.Errorf("Expected 404 Not Found when chunk file is missing on disk, got %d", missingRec.Code)
	}
}
