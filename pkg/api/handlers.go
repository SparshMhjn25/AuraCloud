package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"auracloud/pkg/chunker"
	"auracloud/pkg/crypto"
	"auracloud/pkg/db"
	"auracloud/pkg/network"
	"auracloud/pkg/storage"

	"github.com/google/uuid"
)

// Response Data Transfer Objects (DTOs)

type HealthResponse struct {
	Status string `json:"status"`
	System string `json:"system"`
}

type UploadResponse struct {
	FileID      string `json:"file_id"`
	FileName    string `json:"file_name"`
	FileSize    int64  `json:"file_size"`
	TotalChunks int    `json:"total_chunks"`
	MimeType    string `json:"mime_type"`
	Status      string `json:"status"`
}

type DeleteResponse struct {
	FileID       string `json:"file_id"`
	PurgedChunks int    `json:"purged_chunks"`
	Status       string `json:"status"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

// SyncStatusResponse contains only live operational status needed by the UI.
// A peer is counted only after its AuraCloud health endpoint answers over tsnet.
type SyncStatusResponse struct {
	MeshEnabled   bool `json:"mesh_enabled"`
	PeersOnline   int  `json:"peers_online"`
	PendingChunks int  `json:"pending_chunks"`
}

// JSON Helper Utilities

func renderJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

func renderError(w http.ResponseWriter, statusCode int, message string) {
	renderJSON(w, statusCode, ErrorResponse{Error: message})
}

// -----------------------------------------------------------------------------
// HTTP Handlers
// -----------------------------------------------------------------------------

// handleHealth returns HTTP 200 with JSON payload verifying the AuraCloud core node status.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		renderError(w, http.StatusMethodNotAllowed, "Method not allowed. Use GET.")
		return
	}

	renderJSON(w, http.StatusOK, HealthResponse{
		Status: "online",
		System: "AuraCloud Core",
	})
}

// handleSyncStatus combines durable SQLite queue state with a short, concurrent
// health check of tsnet-reported online peers. It is read-only and does not
// trigger replication work.
func (s *Server) handleSyncStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		renderError(w, http.StatusMethodNotAllowed, "Method not allowed. Use GET.")
		return
	}

	queueStats, err := s.database.GetSyncQueueStats()
	if err != nil {
		renderError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to query sync queue: %v", err))
		return
	}

	status := SyncStatusResponse{PendingChunks: queueStats.PendingChunks}
	if s.config.Node == nil {
		renderJSON(w, http.StatusOK, status)
		return
	}
	status.MeshEnabled = true

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	peerIPs, err := s.config.Node.GetOnlinePeerIPs(ctx)
	if err == nil {
		status.PeersOnline = s.countReachablePeers(ctx, peerIPs)
	}
	renderJSON(w, http.StatusOK, status)
}

func (s *Server) countReachablePeers(ctx context.Context, peerIPs []string) int {
	results := make(chan bool, len(peerIPs))
	for _, peerIP := range peerIPs {
		go func(ip string) { results <- s.peerHealthy(ctx, ip) }(peerIP)
	}
	count := 0
	for range peerIPs {
		if <-results {
			count++
		}
	}
	return count
}

// handleFilesRoot handles GET requests to list all registered files from SQLite.
func (s *Server) handleFilesRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		renderError(w, http.StatusMethodNotAllowed, "Method not allowed. Use GET.")
		return
	}

	files, err := s.database.ListFiles()
	if err != nil {
		renderError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to query files: %v", err))
		return
	}

	if files == nil {
		files = []db.FileRecord{}
	}

	renderJSON(w, http.StatusOK, files)
}

// handleUploadFile accepts `multipart/form-data` uploads (field "file"), streams bytes through
// the chunker, encrypts each chunk with AES-256-GCM, stores chunks on disk, and saves the manifest to SQLite.
func (s *Server) handleUploadFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		renderError(w, http.StatusMethodNotAllowed, "Method not allowed. Use POST.")
		return
	}

	err := r.ParseMultipartForm(32 << 20)
	if err != nil {
		renderError(w, http.StatusBadRequest, fmt.Sprintf("Failed to parse multipart form: %v", err))
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		renderError(w, http.StatusBadRequest, "Missing 'file' field in multipart upload form.")
		return
	}
	defer file.Close()

	fileName := filepath.Base(header.Filename)

	chunks, err := chunker.ChunkReader(file, chunker.DefaultChunkSize)
	if err != nil {
		renderError(w, http.StatusInternalServerError, fmt.Sprintf("Chunking failed: %v", err))
		return
	}

	if len(chunks) == 0 {
		renderError(w, http.StatusBadRequest, "Uploaded file is empty.")
		return
	}

	fileID := uuid.New().String()
	var chunkRecords []db.ChunkRecord
	var totalSize int64

	for _, c := range chunks {
		totalSize += c.Size
		cid := crypto.GenerateCID(c.Data)

		ciphertext, nonce, err := crypto.EncryptChunk(c.Data, s.config.MasterKey)
		if err != nil {
			renderError(w, http.StatusInternalServerError, fmt.Sprintf("Encryption failed on chunk #%d: %v", c.Index, err))
			return
		}

		err = storage.SaveEncryptedChunk(s.config.StorageDir, cid, nonce, ciphertext)
		if err != nil {
			renderError(w, http.StatusInternalServerError, fmt.Sprintf("Disk storage failed for chunk CID %s: %v", cid, err))
			return
		}

		chunkRecords = append(chunkRecords, db.ChunkRecord{
			FileID:     fileID,
			ChunkIndex: c.Index,
			CID:        cid,
			NonceHex:   hex.EncodeToString(nonce),
			ChunkSize:  c.Size,
		})
	}

	mimeType := header.Header.Get("Content-Type")
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	fileRecord := db.FileRecord{
		ID:          fileID,
		FileName:    fileName,
		FileSize:    totalSize,
		MimeType:    mimeType,
		TotalChunks: len(chunks),
		CreatedAt:   time.Now(),
	}

	err = s.database.RegisterFile(fileRecord, chunkRecords)
	if err != nil {
		renderError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to save manifest to database: %v", err))
		return
	}

	// -------------------------------------------------------------------------
	// 🌐 P2P Mesh Chunk & Manifest Replication to Active Tailscale Peers
	// -------------------------------------------------------------------------
	if s.config.Node != nil {
		go func(fRec db.FileRecord, cRecs []db.ChunkRecord, storageDir string) {
			s.replicateToMeshPeers(fRec, cRecs, storageDir)
		}(fileRecord, chunkRecords, s.config.StorageDir)
		fmt.Println("[P2P MESH] Initiated background mesh replication to online peers.")
	}

	renderJSON(w, http.StatusCreated, UploadResponse{
		FileID:      fileID,
		FileName:    fileName,
		FileSize:    totalSize,
		TotalChunks: len(chunks),
		MimeType:    mimeType,
		Status:      "uploaded_and_encrypted",
	})
}

func (s *Server) replicateToMeshPeers(fileRecord db.FileRecord, chunkRecords []db.ChunkRecord, _ string) {
	if s.config.Node == nil {
		return
	}

	peerIPs, err := s.config.Node.GetOnlinePeerIPs(context.Background())
	if err != nil {
		fmt.Printf("[P2P REPLICATION] Could not retrieve online mesh peers: %v\n", err)
		return
	}

	cids := make([]string, 0, len(chunkRecords))
	for _, chunk := range chunkRecords {
		cids = append(cids, chunk.CID)
	}
	for _, peerIP := range peerIPs {
		if err := s.database.EnqueueSyncChunks(fileRecord.ID, cids, peerIP); err != nil {
			fmt.Printf("[P2P REPLICATION] Could not queue chunks for %s: %v\n", peerIP, err)
			continue
		}
		items, err := s.database.ListEligibleSyncQueue(peerIP)
		if err != nil {
			fmt.Printf("[P2P REPLICATION] Could not read queue for %s: %v\n", peerIP, err)
			continue
		}
		s.dispatchSyncJobs(context.Background(), items)
	}
}

const syncWorkerCount = 3

// dispatchSyncJobs uses a bounded worker pool so a slow peer/chunk cannot block
// unrelated queued transfers. Claims in SQLite make concurrent dispatch calls safe.
func (s *Server) dispatchSyncJobs(ctx context.Context, items []db.SyncQueueItem) {
	if len(items) == 0 || s.config.Node == nil {
		return
	}
	jobs := make(chan db.SyncQueueItem)
	var wg sync.WaitGroup
	for i := 0; i < syncWorkerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				claimed, err := s.database.ClaimSyncQueueItem(item.ID)
				if err != nil || !claimed {
					continue
				}
				if err := s.transferQueuedChunk(ctx, item); err != nil {
					fmt.Printf("[SYNC QUEUE] Chunk %s -> %s failed: %v\n", item.ChunkCID, item.PeerIP, err)
					if markErr := s.database.MarkSyncQueueFailed(item.ID); markErr != nil {
						fmt.Printf("[SYNC QUEUE] Could not record failed job %d: %v\n", item.ID, markErr)
					}
					continue
				}
				if err := s.database.MarkSyncQueueCompleted(item.ID); err != nil {
					fmt.Printf("[SYNC QUEUE] Could not complete job %d: %v\n", item.ID, err)
				}
			}
		}()
	}
	for _, item := range items {
		select {
		case jobs <- item:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return
		}
	}
	close(jobs)
	wg.Wait()
	s.syncCompletedManifests(items)
}

// transferQueuedChunk streams the already AES-GCM-encrypted on-disk chunk through
// tsnet's HTTP client. No plaintext, CID, or storage behavior is changed here.
func (s *Server) transferQueuedChunk(ctx context.Context, item db.SyncQueueItem) error {
	client := s.config.Node.Client()
	if client == nil {
		return fmt.Errorf("embedded Tailscale HTTP client unavailable")
	}
	chunkPath := filepath.Join(s.config.StorageDir, item.ChunkCID+".chunk")
	file, err := os.Open(chunkPath)
	if err != nil {
		return fmt.Errorf("open local encrypted chunk: %w", err)
	}
	defer file.Close()
	requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	peerAddress := net.JoinHostPort(item.PeerIP, strconv.Itoa(s.config.Port))
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, fmt.Sprintf("http://%s/api/v1/chunks/receive", peerAddress), file)
	if err != nil {
		return fmt.Errorf("create chunk request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-AuraCloud-CID", item.ChunkCID)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("peer returned %s", resp.Status)
	}
	return nil
}

// StartSyncQueueWorker starts Phase 2 store-and-forward recovery for mesh mode.
// It is intentionally a no-op in local-only mode.
func (s *Server) StartSyncQueueWorker(ctx context.Context) {
	if s.config.Node == nil {
		return
	}
	if err := s.database.RequeueInProgressSyncItems(); err != nil {
		fmt.Printf("[SYNC QUEUE] Could not recover interrupted jobs: %v\n", err)
	}
	go s.runSyncQueueWorker(ctx)
}

// runSyncQueueWorker checks durable failed/pending work every 20 seconds. Work
// is grouped by peer so an unavailable peer costs only one fast health request.
func (s *Server) runSyncQueueWorker(ctx context.Context) {
	run := func() {
		items, err := s.database.ListEligibleSyncQueue("")
		if err != nil || len(items) == 0 {
			if err != nil {
				fmt.Printf("[SYNC QUEUE] Could not scan recovery queue: %v\n", err)
			}
			return
		}
		byPeer := make(map[string][]db.SyncQueueItem)
		for _, item := range items {
			byPeer[item.PeerIP] = append(byPeer[item.PeerIP], item)
		}
		for peerIP, peerItems := range byPeer {
			if !s.peerHealthy(ctx, peerIP) {
				continue
			}
			s.dispatchSyncJobs(ctx, peerItems)
		}
	}
	run() // Also recover pending work immediately after startup.
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

func (s *Server) peerHealthy(parent context.Context, peerIP string) bool {
	client := s.config.Node.Client()
	if client == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	peerAddress := net.JoinHostPort(peerIP, strconv.Itoa(s.config.Port))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://%s/api/v1/health", peerAddress), nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// syncCompletedManifests advertises metadata only after a peer has received all
// encrypted chunks belonging to that file. The data plane remains resumable via
// sync_queue; failed metadata delivery is logged without changing chunk state.
func (s *Server) syncCompletedManifests(items []db.SyncQueueItem) {
	seen := make(map[string]struct{})
	for _, item := range items {
		key := item.FileID + "\x00" + item.PeerIP
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		complete, err := s.database.PeerFileSyncComplete(item.FileID, item.PeerIP)
		if err != nil || !complete {
			continue
		}
		manifest, err := s.database.GetFileManifest(item.FileID)
		if err != nil {
			fmt.Printf("[P2P REPLICATION] Could not read manifest %s: %v\n", item.FileID, err)
			continue
		}
		payload, err := json.Marshal(manifest)
		if err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		peerAddress := net.JoinHostPort(item.PeerIP, strconv.Itoa(s.config.Port))
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("http://%s/api/v1/manifest/sync", peerAddress), bytes.NewReader(payload))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
			resp, doErr := s.config.Node.Client().Do(req)
			if doErr != nil {
				err = doErr
			} else {
				resp.Body.Close()
				if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
					err = fmt.Errorf("peer returned %s", resp.Status)
				}
			}
		}
		cancel()
		if err != nil {
			fmt.Printf("[P2P REPLICATION] Manifest %s -> %s failed: %v\n", item.FileID, item.PeerIP, err)
		}
	}
}

func (s *Server) handleReceiveChunk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		renderError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	data, err := io.ReadAll(r.Body)
	if err != nil || len(data) == 0 {
		renderError(w, http.StatusBadRequest, "Invalid chunk payload")
		return
	}

	cid := r.Header.Get("X-AuraCloud-CID")
	if cid == "" || filepath.Base(cid) != cid {
		renderError(w, http.StatusBadRequest, "Missing or invalid X-AuraCloud-CID header")
		return
	}
	if err := os.MkdirAll(s.config.StorageDir, 0755); err != nil {
		renderError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to create chunk storage: %v", err))
		return
	}

	filePath := filepath.Join(s.config.StorageDir, cid+".chunk")
	err = os.WriteFile(filePath, data, 0644)
	if err != nil {
		renderError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to write replicated chunk: %v", err))
		return
	}

	fmt.Printf("[P2P RECEIVER] Successfully saved replicated chunk %s to disk!\n", cid)
	renderJSON(w, http.StatusOK, map[string]string{"status": "chunk_received", "cid": cid})
}

func (s *Server) handleSyncManifest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		renderError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var payload struct {
		File   db.FileRecord    `json:"file"`
		Chunks []db.ChunkRecord `json:"chunks"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		renderError(w, http.StatusBadRequest, "Invalid manifest JSON")
		return
	}

	inserted, err := s.database.RegisterReplicatedManifest(payload.File, payload.Chunks)
	if err != nil {
		renderError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to register replicated manifest: %v", err))
		return
	}
	if !inserted {
		renderJSON(w, http.StatusOK, map[string]string{"status": "in_sync"})
		return
	}

	fmt.Printf("[P2P RECEIVER] Successfully registered file '%s' in local database!\n", payload.File.FileName)
	renderJSON(w, http.StatusOK, map[string]string{"status": "manifest_synced"})
}

// handleDownloadFile retrieves a file manifest from SQLite, decrypts ALL chunks into
// memory first, then writes HTTP headers and the complete payload atomically.
//
// WHY BUFFER FIRST:
// Once w.WriteHeader(200) is called, HTTP headers are committed and cannot be changed.
// If decryption fails mid-stream, Go closes the writer leaving the client with a
// truncated response body — Chrome reports "Couldn't finish download".
// By buffering all decrypted bytes before writing any headers, any error can still
// be returned as a clean HTTP 4xx/5xx JSON response.
func (s *Server) handleDownloadFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		renderError(w, http.StatusMethodNotAllowed, "Method not allowed. Use GET.")
		return
	}

	target := strings.TrimPrefix(r.URL.Path, "/api/v1/files/download/")
	if target == "" {
		target = r.URL.Query().Get("id")
	}
	if target == "" {
		target = r.URL.Query().Get("name")
	}

	if target == "" {
		renderError(w, http.StatusBadRequest, "Missing file ID or name in download request path or query parameter.")
		return
	}

	// Step 1: Look up the file manifest from SQLite.
	manifest, err := s.database.GetFileManifest(target)
	if err != nil {
		manifest, err = s.database.GetFileManifestByName(target)
		if err != nil {
			renderError(w, http.StatusNotFound, fmt.Sprintf("File not found in SQLite manifest DB: %v", err))
			return
		}
	}

	// Step 2: Verify ALL chunk files exist on disk before touching the HTTP response.
	for _, chunkRec := range manifest.Chunks {
		chunkPath := filepath.Join(s.config.StorageDir, chunkRec.CID+".chunk")
		if _, statErr := os.Stat(chunkPath); os.IsNotExist(statErr) {
			renderError(w, http.StatusNotFound, fmt.Sprintf("Encrypted chunk file missing on disk for CID %s", chunkRec.CID))
			return
		}
	}

	// Step 3: Decrypt all chunks into a memory buffer BEFORE writing HTTP headers.
	// Any decryption error at this stage can still be surfaced as a clean HTTP 500.
	var buf bytes.Buffer
	for _, chunkRec := range manifest.Chunks {
		nonceFromDisk, ciphertext, loadErr := storage.LoadEncryptedChunk(s.config.StorageDir, chunkRec.CID)
		if loadErr != nil {
			renderError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to load encrypted chunk CID %s: %v", chunkRec.CID, loadErr))
			return
		}

		plainBytes, decErr := crypto.DecryptChunk(ciphertext, nonceFromDisk, s.config.MasterKey)
		if decErr != nil {
			renderError(w, http.StatusInternalServerError, fmt.Sprintf("AES-256-GCM decryption failed for chunk index %d (CID %s): %v", chunkRec.ChunkIndex, chunkRec.CID, decErr))
			return
		}

		buf.Write(plainBytes)
	}

	// Step 4: All chunks decrypted successfully. Now commit HTTP response headers.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", manifest.File.FileName))
	w.Header().Set("Content-Length", strconv.FormatInt(int64(buf.Len()), 10))
	w.WriteHeader(http.StatusOK)

	// Step 5: Write the fully assembled decrypted payload.
	_, writeErr := w.Write(buf.Bytes())
	if writeErr != nil {
		fmt.Printf("WARNING: Failed to write decrypted payload to client for file %s: %v\n", manifest.File.FileName, writeErr)
	}
}

// handleDeleteFile removes a file record from SQLite and purges unreferenced `.chunk` files from disk.
func (s *Server) handleDeleteFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
		renderError(w, http.StatusMethodNotAllowed, "Method not allowed. Use DELETE.")
		return
	}

	fileID := strings.TrimPrefix(r.URL.Path, "/api/v1/files/delete/")
	if fileID == "" {
		fileID = r.URL.Query().Get("id")
	}

	if fileID == "" {
		renderError(w, http.StatusBadRequest, "Missing file ID in delete request path or query parameter.")
		return
	}

	cids, err := s.database.DeleteFile(fileID)
	if err != nil {
		renderError(w, http.StatusNotFound, fmt.Sprintf("Failed to delete file: %v", err))
		return
	}

	orphanCIDs, err := s.database.FilterUnreferencedCIDs(cids)
	if err != nil {
		renderError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to filter orphan CIDs: %v", err))
		return
	}

	purgedCount := 0
	for _, cid := range orphanCIDs {
		chunkPath := filepath.Join(s.config.StorageDir, cid+".chunk")
		if err := os.Remove(chunkPath); err == nil {
			purgedCount++
		}
	}

	renderJSON(w, http.StatusOK, DeleteResponse{
		FileID:       fileID,
		PurgedChunks: purgedCount,
		Status:       "deleted_and_garbage_collected",
	})
}

// handleNodeStatus returns the current Tailscale mesh node status:
// its hostname, assigned Tailscale IP addresses, connectivity status, and whether P2P mesh mode is active.
//
// When the server was started WITHOUT a Tailscale node (local-only mode), this endpoint returns
// a graceful "mesh_disabled" status without error.
//
// When the server was started WITH a tsnet node (P2P Mesh Mode), it queries the live WireGuard
// node for its actual IP assignments and peer connectivity state.
func (s *Server) handleNodeStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		renderError(w, http.StatusMethodNotAllowed, "Method not allowed. Use GET.")
		return
	}

	// LOCAL-ONLY MODE: No tsnet node is configured. Return a clean "mesh disabled" status.
	if s.config.Node == nil {
		renderJSON(w, http.StatusOK, network.NodeStatus{
			Hostname:     "localhost",
			TailscaleIPs: []string{},
			Status:       "local_only",
			MeshEnabled:  false,
			StateDir:     "",
		})
		return
	}

	// MESH MODE: Query the live embedded tsnet node for its current mesh status.
	status, err := s.config.Node.GetStatus(r.Context())
	if err != nil {
		// Node may still be authenticating. Return a partial status rather than a hard error.
		renderJSON(w, http.StatusOK, network.NodeStatus{
			Hostname:     s.config.Node.Config().Hostname,
			TailscaleIPs: []string{},
			Status:       "authenticating",
			MeshEnabled:  true,
			StateDir:     s.config.Node.Config().StateDir,
		})
		return
	}

	renderJSON(w, http.StatusOK, status)
}
