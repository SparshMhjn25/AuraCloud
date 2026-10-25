package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	// Register pure-Go CGO-free SQLite driver with database/sql
	_ "modernc.org/sqlite"
)

// Architectural Concept: Embedded Local Manifest Database
//
// In AuraCloud, local backup state (which files were backed up, how many chunks they were
// split into, their CIDs, and nonces) is maintained in an embedded SQLite database (`manifest.db`).

const (
	// DefaultDBPath is the relative path to the SQLite manifest database file.
	DefaultDBPath = ".auracloud_data/manifest.db"
)

// FileRecord represents the root metadata entry for a backed-up file in the SQLite `files` table.
type FileRecord struct {
	ID          string    `json:"id"`           // Unique identifier (UUID string)
	FileName    string    `json:"file_name"`    // Original file name (e.g., "vacation.png")
	FileSize    int64     `json:"file_size"`    // Total original file size in bytes
	MimeType    string    `json:"mime_type"`    // Detected MIME content type (e.g., "image/png", "video/mp4")
	TotalChunks int       `json:"total_chunks"` // Total number of 2MB chunks required to store this file
	CreatedAt   time.Time `json:"created_at"`   // Timestamp when file was backed up
}

// ChunkRecord represents an ordered chunk entry in the SQLite `chunks` table.
type ChunkRecord struct {
	ID         int64  `json:"id"`          // Autoincrement primary key
	FileID     string `json:"file_id"`     // Foreign key pointing to files.id
	ChunkIndex int    `json:"chunk_index"` // Zero-indexed position of chunk in file reassembly sequence
	CID        string `json:"cid"`         // Cryptographic Content ID (Hex SHA-256 hash of plain data)
	NonceHex   string `json:"nonce_hex"`   // Hex-encoded 12-byte AES-GCM encryption nonce
	ChunkSize  int64  `json:"chunk_size"`  // Byte size of this specific chunk
}

// FileManifest aggregates a FileRecord with its ordered slice of ChunkRecords.
type FileManifest struct {
	File   FileRecord    `json:"file"`
	Chunks []ChunkRecord `json:"chunks"`
}

// SyncQueueItem is one durable encrypted-chunk transfer to a mesh peer.
// A row is retained after success so restarting a node never re-sends completed work.
type SyncQueueItem struct {
	ID          int64
	ChunkCID    string
	FileID      string
	PeerIP      string
	Status      string
	RetryCount  int
	LastAttempt *time.Time
}

// SyncQueueStats is the dashboard-safe summary of retryable replication work.
// Completed items are intentionally excluded: they are retained for durability,
// but should not be presented as work waiting to be delivered.
type SyncQueueStats struct {
	PendingChunks int `json:"pending_chunks"`
}

// DB wraps the underlying standard library *sql.DB instance.
type DB struct {
	conn *sql.DB
}

// InitDB initializes the SQLite database at the specified path, creating directories and schema if missing.
func InitDB(dbPath string) (*DB, error) {
	if dbPath == "" {
		dbPath = DefaultDBPath
	}

	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("db: failed to create database directory %s: %w", dir, err)
	}

	dsn := fmt.Sprintf("%s?_pragma=foreign_keys(1)", dbPath)
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("db: failed to open sqlite connection: %w", err)
	}
	// SQLite permits a single writer. Keep all application work on one pooled
	// connection and make short contention wait rather than fail immediately.
	conn.SetMaxOpenConns(1)
	conn.SetMaxIdleConns(1)
	for _, pragma := range []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA busy_timeout = 5000",
		"PRAGMA synchronous = NORMAL",
	} {
		if _, err := conn.Exec(pragma); err != nil {
			conn.Close()
			return nil, fmt.Errorf("db: failed to apply %q: %w", pragma, err)
		}
	}

	if err := conn.Ping(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("db: failed to ping sqlite database: %w", err)
	}

	db := &DB{conn: conn}

	if err := db.createSchema(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("db: failed to initialize schema: %w", err)
	}

	return db, nil
}

// createSchema executes DDL statements to build the `files` and `chunks` tables.
func (db *DB) createSchema() error {
	schemaSQL := `
	CREATE TABLE IF NOT EXISTS files (
		id TEXT PRIMARY KEY,
		file_name TEXT NOT NULL,
		file_size INTEGER NOT NULL,
		mime_type TEXT NOT NULL,
		total_chunks INTEGER NOT NULL,
		created_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS chunks (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		file_id TEXT NOT NULL,
		chunk_index INTEGER NOT NULL,
		cid TEXT NOT NULL,
		nonce_hex TEXT NOT NULL,
		chunk_size INTEGER NOT NULL,
		FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_chunks_file_id_index ON chunks(file_id, chunk_index);

	CREATE TABLE IF NOT EXISTS sync_queue (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		chunk_cid TEXT NOT NULL,
		file_id TEXT NOT NULL,
		peer_ip TEXT NOT NULL,
		status TEXT DEFAULT 'PENDING',
		retry_count INTEGER DEFAULT 0,
		last_attempt DATETIME,
		UNIQUE(chunk_cid, peer_ip)
	);

	CREATE INDEX IF NOT EXISTS idx_sync_queue_dispatch
		ON sync_queue(status, retry_count, peer_ip);
	`

	_, err := db.conn.Exec(schemaSQL)
	if err != nil {
		return fmt.Errorf("db: schema creation failed: %w", err)
	}

	return nil
}

// EnqueueSyncChunks adds durable transfer work for a peer. Existing completed
// rows remain completed; an unfinished row is reset to PENDING so a new upload
// can prompt another delivery attempt without duplicating a transfer.
func (db *DB) EnqueueSyncChunks(fileID string, chunkCIDs []string, peerIP string) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return fmt.Errorf("db: begin sync queue transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO sync_queue (chunk_cid, file_id, peer_ip, status)
		VALUES (?, ?, ?, 'PENDING')
		ON CONFLICT(chunk_cid, peer_ip) DO UPDATE SET
			file_id = excluded.file_id,
			status = CASE WHEN sync_queue.status = 'COMPLETED' THEN 'COMPLETED' ELSE 'PENDING' END;
	`)
	if err != nil {
		return fmt.Errorf("db: prepare sync queue insert: %w", err)
	}
	defer stmt.Close()
	for _, cid := range chunkCIDs {
		if _, err := stmt.Exec(cid, fileID, peerIP); err != nil {
			return fmt.Errorf("db: enqueue chunk %s for peer %s: %w", cid, peerIP, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("db: commit sync queue transaction: %w", err)
	}
	return nil
}

// ListEligibleSyncQueue returns work that has not exhausted its retry budget.
func (db *DB) ListEligibleSyncQueue(peerIP string) ([]SyncQueueItem, error) {
	query := `SELECT id, chunk_cid, file_id, peer_ip, status, retry_count, last_attempt
		FROM sync_queue
		WHERE status IN ('PENDING', 'FAILED') AND retry_count < 5`
	args := []any{}
	if peerIP != "" {
		query += ` AND peer_ip = ?`
		args = append(args, peerIP)
	}
	query += ` ORDER BY peer_ip, id`
	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("db: list eligible sync queue: %w", err)
	}
	defer rows.Close()
	var items []SyncQueueItem
	for rows.Next() {
		var item SyncQueueItem
		var lastAttempt sql.NullString
		if err := rows.Scan(&item.ID, &item.ChunkCID, &item.FileID, &item.PeerIP, &item.Status, &item.RetryCount, &lastAttempt); err != nil {
			return nil, fmt.Errorf("db: scan sync queue item: %w", err)
		}
		if lastAttempt.Valid {
			if parsed, err := time.Parse(time.RFC3339Nano, lastAttempt.String); err == nil {
				item.LastAttempt = &parsed
			}
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// GetSyncQueueStats returns jobs the recovery worker may still deliver. It
// mirrors the worker's retry eligibility so the UI never counts completed or
// exhausted queue items as pending work.
func (db *DB) GetSyncQueueStats() (SyncQueueStats, error) {
	var stats SyncQueueStats
	err := db.conn.QueryRow(`SELECT COUNT(*) FROM sync_queue
		WHERE status IN ('PENDING', 'FAILED', 'IN_PROGRESS') AND retry_count < 5`).Scan(&stats.PendingChunks)
	if err != nil {
		return SyncQueueStats{}, fmt.Errorf("db: get sync queue stats: %w", err)
	}
	return stats, nil
}

// ClaimSyncQueueItem atomically reserves work for one worker. It makes queue
// dispatch safe when an upload and the recovery loop run at the same time.
func (db *DB) ClaimSyncQueueItem(id int64) (bool, error) {
	res, err := db.conn.Exec(`UPDATE sync_queue
		SET status = 'IN_PROGRESS', last_attempt = ?
		WHERE id = ? AND status IN ('PENDING', 'FAILED') AND retry_count < 5`, time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return false, fmt.Errorf("db: claim sync queue item: %w", err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (db *DB) MarkSyncQueueCompleted(id int64) error {
	_, err := db.conn.Exec(`UPDATE sync_queue SET status = 'COMPLETED', last_attempt = ? WHERE id = ?`, time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return fmt.Errorf("db: mark sync queue item completed: %w", err)
	}
	return nil
}

// MarkSyncQueueFailed records an individual transfer failure without affecting
// other workers.
func (db *DB) MarkSyncQueueFailed(id int64) error {
	_, err := db.conn.Exec(`UPDATE sync_queue
		SET status = 'FAILED', retry_count = retry_count + 1, last_attempt = ?
		WHERE id = ?`, time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return fmt.Errorf("db: mark sync queue item failed: %w", err)
	}
	return nil
}

// RequeueInProgressSyncItems recovers work claimed by a process that exited
// before it could record a result. Call it once during mesh server startup.
func (db *DB) RequeueInProgressSyncItems() error {
	_, err := db.conn.Exec(`UPDATE sync_queue SET status = 'FAILED' WHERE status = 'IN_PROGRESS'`)
	if err != nil {
		return fmt.Errorf("db: requeue in-progress sync items: %w", err)
	}
	return nil
}

// PeerFileSyncComplete reports whether every queued chunk for a peer/file has
// been delivered. It is used before sending the manifest metadata.
func (db *DB) PeerFileSyncComplete(fileID, peerIP string) (bool, error) {
	var pending int
	err := db.conn.QueryRow(`SELECT COUNT(*) FROM sync_queue WHERE file_id = ? AND peer_ip = ? AND status != 'COMPLETED'`, fileID, peerIP).Scan(&pending)
	if err != nil {
		return false, fmt.Errorf("db: check peer file sync completion: %w", err)
	}
	return pending == 0, nil
}

// RegisterFile inserts a FileRecord and its associated ChunkRecords within a single SQL transaction.
func (db *DB) RegisterFile(file FileRecord, chunks []ChunkRecord) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return fmt.Errorf("db: failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	insertFileSQL := `
	INSERT INTO files (id, file_name, file_size, mime_type, total_chunks, created_at)
	VALUES (?, ?, ?, ?, ?, ?);
	`
	_, err = tx.Exec(insertFileSQL, file.ID, file.FileName, file.FileSize, file.MimeType, file.TotalChunks, file.CreatedAt.Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("db: failed to insert file record (ID %s): %w", file.ID, err)
	}

	insertChunkSQL := `
	INSERT INTO chunks (file_id, chunk_index, cid, nonce_hex, chunk_size)
	VALUES (?, ?, ?, ?, ?);
	`
	stmt, err := tx.Prepare(insertChunkSQL)
	if err != nil {
		return fmt.Errorf("db: failed to prepare chunk statement: %w", err)
	}
	defer stmt.Close()

	for _, c := range chunks {
		_, err := stmt.Exec(file.ID, c.ChunkIndex, c.CID, c.NonceHex, c.ChunkSize)
		if err != nil {
			return fmt.Errorf("db: failed to insert chunk index %d for file ID %s: %w", c.ChunkIndex, file.ID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("db: transaction commit failed: %w", err)
	}

	return nil
}

// RegisterReplicatedManifest records a peer manifest exactly once. A duplicate
// file ID is expected after a sender retries a completed manifest request, so
// it returns inserted=false rather than treating that condition as an error.
func (db *DB) RegisterReplicatedManifest(file FileRecord, chunks []ChunkRecord) (inserted bool, err error) {
	tx, err := db.conn.Begin()
	if err != nil {
		return false, fmt.Errorf("db: failed to begin replicated manifest transaction: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.Exec(`
		INSERT OR IGNORE INTO files (id, file_name, file_size, mime_type, total_chunks, created_at)
		VALUES (?, ?, ?, ?, ?, ?);`,
		file.ID, file.FileName, file.FileSize, file.MimeType, file.TotalChunks, file.CreatedAt.Format(time.RFC3339))
	if err != nil {
		return false, fmt.Errorf("db: failed to insert replicated file record (ID %s): %w", file.ID, err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("db: failed to read replicated manifest insert result: %w", err)
	}
	if rows == 0 {
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("db: commit duplicate replicated manifest: %w", err)
		}
		return false, nil
	}

	stmt, err := tx.Prepare(`
		INSERT INTO chunks (file_id, chunk_index, cid, nonce_hex, chunk_size)
		VALUES (?, ?, ?, ?, ?);`)
	if err != nil {
		return false, fmt.Errorf("db: failed to prepare replicated chunk statement: %w", err)
	}
	defer stmt.Close()
	for _, chunk := range chunks {
		if _, err := stmt.Exec(file.ID, chunk.ChunkIndex, chunk.CID, chunk.NonceHex, chunk.ChunkSize); err != nil {
			return false, fmt.Errorf("db: failed to insert replicated chunk index %d for file ID %s: %w", chunk.ChunkIndex, file.ID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("db: commit replicated manifest: %w", err)
	}
	return true, nil
}

// GetFileManifest retrieves a file record and all its ordered chunk records by File ID.
func (db *DB) GetFileManifest(fileID string) (*FileManifest, error) {
	fileQuery := `SELECT id, file_name, file_size, mime_type, total_chunks, created_at FROM files WHERE id = ?;`
	row := db.conn.QueryRow(fileQuery, fileID)

	var f FileRecord
	var createdAtStr string
	err := row.Scan(&f.ID, &f.FileName, &f.FileSize, &f.MimeType, &f.TotalChunks, &createdAtStr)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("db: file not found with ID %s", fileID)
	} else if err != nil {
		return nil, fmt.Errorf("db: failed to query file record: %w", err)
	}

	f.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)

	chunkQuery := `SELECT id, file_id, chunk_index, cid, nonce_hex, chunk_size FROM chunks WHERE file_id = ? ORDER BY chunk_index ASC;`
	rows, err := db.conn.Query(chunkQuery, fileID)
	if err != nil {
		return nil, fmt.Errorf("db: failed to query chunks for file ID %s: %w", fileID, err)
	}
	defer rows.Close()

	var chunks []ChunkRecord
	for rows.Next() {
		var c ChunkRecord
		err := rows.Scan(&c.ID, &c.FileID, &c.ChunkIndex, &c.CID, &c.NonceHex, &c.ChunkSize)
		if err != nil {
			return nil, fmt.Errorf("db: failed to scan chunk row: %w", err)
		}
		chunks = append(chunks, c)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("db: error iterating chunk rows: %w", err)
	}

	return &FileManifest{
		File:   f,
		Chunks: chunks,
	}, nil
}

// GetFileManifestByName fetches the most recent file manifest matching the given file name.
func (db *DB) GetFileManifestByName(fileName string) (*FileManifest, error) {
	fileQuery := `SELECT id FROM files WHERE file_name = ? ORDER BY created_at DESC LIMIT 1;`
	var fileID string
	err := db.conn.QueryRow(fileQuery, fileName).Scan(&fileID)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("db: no file found with name '%s'", fileName)
	} else if err != nil {
		return nil, fmt.Errorf("db: failed to query file by name: %w", err)
	}

	return db.GetFileManifest(fileID)
}

// ListFiles returns all registered file records ordered by creation date descending.
func (db *DB) ListFiles() ([]FileRecord, error) {
	query := `SELECT id, file_name, file_size, mime_type, total_chunks, created_at FROM files ORDER BY created_at DESC;`
	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, fmt.Errorf("db: failed to list files: %w", err)
	}
	defer rows.Close()

	var files []FileRecord
	for rows.Next() {
		var f FileRecord
		var createdAtStr string
		err := rows.Scan(&f.ID, &f.FileName, &f.FileSize, &f.MimeType, &f.TotalChunks, &createdAtStr)
		if err != nil {
			return nil, fmt.Errorf("db: failed to scan file record: %w", err)
		}
		f.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)
		files = append(files, f)
	}

	return files, nil
}

// DeleteFile removes a file record by ID from the database within a transaction.
// Because the `chunks` table has `FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE`,
// deleting the row from `files` automatically removes all associated chunk mapping rows in `chunks`.
// It returns the list of CIDs that belonged to the deleted file so callers can check for unreferenced orphan chunks.
func (db *DB) DeleteFile(fileID string) ([]string, error) {
	// 1. Fetch chunk CIDs belonging to this file BEFORE deleting
	queryCIDs := `SELECT DISTINCT cid FROM chunks WHERE file_id = ?;`
	rows, err := db.conn.Query(queryCIDs, fileID)
	if err != nil {
		return nil, fmt.Errorf("db: failed to query chunk CIDs for file ID %s: %w", fileID, err)
	}

	var cids []string
	for rows.Next() {
		var cid string
		if err := rows.Scan(&cid); err != nil {
			rows.Close()
			return nil, fmt.Errorf("db: failed to scan CID: %w", err)
		}
		cids = append(cids, cid)
	}
	rows.Close()

	// 2. Delete file record from `files` table (foreign key CASCADE deletes child rows in `chunks`)
	deleteSQL := `DELETE FROM files WHERE id = ?;`
	res, err := db.conn.Exec(deleteSQL, fileID)
	if err != nil {
		return nil, fmt.Errorf("db: failed to delete file record ID %s: %w", fileID, err)
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		return nil, fmt.Errorf("db: file not found with ID %s", fileID)
	}

	// Queue entries are not foreign-keyed because a transfer can outlive a
	// process restart. Remove them explicitly when their source file is deleted.
	if _, err := db.conn.Exec(`DELETE FROM sync_queue WHERE file_id = ?`, fileID); err != nil {
		return nil, fmt.Errorf("db: failed to remove sync queue items for file ID %s: %w", fileID, err)
	}

	return cids, nil
}

// FilterUnreferencedCIDs checks a slice of CIDs and returns those that have 0 remaining references in the `chunks` table.
// WHY: In content addressable storage, multiple files might reference the same chunk CID.
// We must ONLY delete a `.chunk` file from disk if NO OTHER file in SQLite references it.
func (db *DB) FilterUnreferencedCIDs(cids []string) ([]string, error) {
	var orphanCIDs []string

	query := `SELECT COUNT(*) FROM chunks WHERE cid = ?;`
	stmt, err := db.conn.Prepare(query)
	if err != nil {
		return nil, fmt.Errorf("db: failed to prepare count query: %w", err)
	}
	defer stmt.Close()

	for _, cid := range cids {
		var count int
		err := stmt.QueryRow(cid).Scan(&count)
		if err != nil {
			return nil, fmt.Errorf("db: failed to check CID reference count: %w", err)
		}
		if count == 0 {
			orphanCIDs = append(orphanCIDs, cid)
		}
	}

	return orphanCIDs, nil
}

// Close closes the underlying database connection pool.
func (db *DB) Close() error {
	if db.conn != nil {
		return db.conn.Close()
	}
	return nil
}
