import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';

const dataDir = process.env.AURA_DATA_DIR ?? '.auracloud_data';
fs.mkdirSync(dataDir, { recursive: true });
export const db = new Database(path.join(dataDir, 'manifest.db'));
db.pragma('journal_mode = WAL');
db.pragma('busy_timeout = 5000');
db.pragma('foreign_keys = ON');
db.pragma('synchronous = NORMAL');
db.exec(`
CREATE TABLE IF NOT EXISTS files (
 id TEXT PRIMARY KEY, file_name TEXT NOT NULL, file_size INTEGER NOT NULL,
 mime_type TEXT NOT NULL, total_chunks INTEGER NOT NULL, created_at DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS chunks (
 id INTEGER PRIMARY KEY AUTOINCREMENT, file_id TEXT NOT NULL, chunk_index INTEGER NOT NULL,
 cid TEXT NOT NULL, nonce_hex TEXT NOT NULL, chunk_size INTEGER NOT NULL,
 FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_chunks_file_id_index ON chunks(file_id, chunk_index);
CREATE TABLE IF NOT EXISTS sync_queue (
 id INTEGER PRIMARY KEY AUTOINCREMENT, chunk_cid TEXT NOT NULL, file_id TEXT NOT NULL,
 peer_ip TEXT NOT NULL, status TEXT DEFAULT 'PENDING', retry_count INTEGER DEFAULT 0,
 last_attempt DATETIME, UNIQUE(chunk_cid, peer_ip)
);
CREATE INDEX IF NOT EXISTS idx_sync_queue_dispatch ON sync_queue(status, retry_count, peer_ip);
`);
export const statements = {
  insertFile: db.prepare('INSERT INTO files(id,file_name,file_size,mime_type,total_chunks,created_at) VALUES(?,?,?,?,?,?)'),
  insertChunk: db.prepare('INSERT INTO chunks(file_id,chunk_index,cid,nonce_hex,chunk_size) VALUES(?,?,?,?,?)'),
  listFiles: db.prepare('SELECT * FROM files ORDER BY created_at DESC'),
  getFile: db.prepare('SELECT * FROM files WHERE id=?'),
  getChunks: db.prepare('SELECT * FROM chunks WHERE file_id=? ORDER BY chunk_index'),
  enqueue: db.prepare(`INSERT INTO sync_queue(chunk_cid,file_id,peer_ip,status) VALUES(?,?,?,'PENDING') ON CONFLICT(chunk_cid,peer_ip) DO UPDATE SET file_id=excluded.file_id,status=CASE WHEN sync_queue.status='COMPLETED' THEN 'COMPLETED' ELSE 'PENDING' END`),
  pending: db.prepare(`SELECT * FROM sync_queue WHERE status IN ('PENDING','FAILED') AND retry_count<8 AND (last_attempt IS NULL OR datetime(last_attempt, '+' || min(3600, 5 * (1 << min(retry_count,10))) || ' seconds') <= datetime('now')) ORDER BY id LIMIT 100`),
  claim: db.prepare(`UPDATE sync_queue SET status='IN_PROGRESS',last_attempt=? WHERE id=? AND status IN ('PENDING','FAILED')`),
  done: db.prepare(`UPDATE sync_queue SET status='COMPLETED',last_attempt=? WHERE id=?`),
  fail: db.prepare(`UPDATE sync_queue SET status='FAILED',retry_count=retry_count+1,last_attempt=? WHERE id=?`),
  recover: db.prepare(`UPDATE sync_queue SET status='FAILED' WHERE status='IN_PROGRESS'`),
  stats: db.prepare(`SELECT status,count(*) AS count FROM sync_queue GROUP BY status`),
};
export { dataDir };
