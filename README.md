# AuraCloud P2P Mesh Backup Engine

AuraCloud is a Go-based, zero-knowledge peer-to-peer backup prototype. It turns an uploaded file into encrypted, content-addressed chunks, records the file manifest in SQLite, and can replicate the encrypted chunks and manifest metadata to online peers through an embedded Tailscale mesh.

The project is designed around a simple security boundary: encrypted payload data may move between peers, but the AES-256 master key remains local to the owner of each node. A peer can store and index a replicated backup without being able to read it.

## Core capabilities

- Browser dashboard and REST API for upload, file listing, download, and deletion.
- Fixed-size file chunking (2 MiB chunks by default).
- AES-256-GCM authenticated encryption, with a fresh random nonce per chunk.
- SHA-256 content identifiers (CIDs) for chunk naming and addressing.
- SQLite manifests linking a file record to its ordered chunk records, plus a durable `sync_queue` for peer delivery work.
- Local key persistence through `AURA_MASTER_KEY` or a node-local `master.key` file.
- Embedded Tailscale (`tsnet`) networking: no system Tailscale adapter is required.
- Store-and-forward peer replication with resumable retries for offline or churning peers.
- A bounded, three-worker chunk-transfer pool to avoid head-of-line blocking on slow peers.
- Dual HTTP listeners: localhost for the dashboard and a private WireGuard mesh listener for peers.

## Technology stack

| Area | Technology |
| --- | --- |
| Language | Go |
| HTTP server/router | Go standard library `net/http` |
| Encryption | AES-256-GCM (`crypto/aes`, `crypto/cipher`, `crypto/rand`) |
| Content IDs | SHA-256 |
| Metadata database | SQLite |
| Mesh overlay | Tailscale `tsnet` / WireGuard |
| Front end | Embedded static HTML/CSS/JavaScript dashboard |
| Identifier generation | `github.com/google/uuid` |

## The five milestones

### Milestone 1 — File processing and chunking

The initial pipeline accepts a file, splits it into fixed-size chunks, and retains the original ordering. Chunking makes large files manageable and provides the unit of storage, encryption, integrity tracking, and peer transfer.

### Milestone 2 — Encryption and content-addressed storage

Each plaintext chunk receives a SHA-256 CID and is encrypted using AES-256-GCM. The encrypted on-disk chunk format is:

```text
[12-byte GCM nonce][ciphertext + GCM authentication tag]
```

Chunks are stored as `<CID>.chunk` files in the configured storage directory (by default `.auracloud_data/chunks`). The CID is calculated from plaintext data, while the stored file remains encrypted.

### Milestone 3 — SQLite manifest and restoration pipeline

AuraCloud introduced a local SQLite manifest database. A `files` record holds file metadata, while ordered `chunks` records map every file to its CIDs, indices, nonces, and plaintext sizes. Restoration loads the manifest, checks for all required chunks, decrypts them with the local master key, and reassembles them in order.

### Milestone 4 — Private P2P mesh networking

The application embeds a Tailscale node with `tsnet`. It exposes the same HTTP API on a Tailscale/WireGuard listener and discovers online tailnet peers through the tsnet local client. Mesh traffic uses `tsnet.Server.HTTPClient()`, ensuring that peer requests travel through the embedded userspace Tailscale stack even on systems without a Tailscale network adapter.

### Milestone 5 — Dashboard and single-binary release

The static dashboard is embedded in the binary and served alongside the REST API. In mesh mode, the application starts a local HTTP listener for the browser dashboard and a separate private tsnet listener for peer traffic. The project builds into `auracloud.exe`.

### Phase 2 — Resumable mesh synchronization and parallel replication

Mesh replication is durable rather than best-effort. Each encrypted chunk destined for an active peer is recorded in SQLite before transfer. A three-goroutine worker pool streams independent queue items through the embedded tsnet HTTP client, so one slow transfer does not block the remaining chunks. Failed transfers are recorded independently and retried by a background recovery worker when the peer returns.

## Architecture

```text
Browser Dashboard / REST Client
             |
             v
      Go HTTP API Server
             |
    +--------+---------+-------------------+
    |                  |                   |
    v                  v                   v
Chunker       SQLite Manifest + Queue  Local Chunk Store
    |                  |                   |
    v                  v                   |
AES-256-GCM    3-worker sync pool       |
    |                  |                   |
    +------------------+-------------------+
                       |
                       v
        tsnet HTTP client / WireGuard mesh
                       |
                       v
      Peer chunk receiver + peer SQLite manifest
```

### Upload and local persistence flow

1. A user uploads a file through `POST /api/v1/files/upload`.
2. The API divides the file into 2 MiB chunks.
3. Each chunk gets a plaintext SHA-256 CID.
4. The chunk is encrypted with the local AES-256-GCM master key and a new random nonce.
5. The nonce and ciphertext are saved in `<CID>.chunk`.
6. The file record and ordered chunk records are committed to SQLite in a transaction.
7. If mesh mode is enabled, a `sync_queue` row is durably created for each chunk and each currently active peer before asynchronous replication begins.

### Mesh replication flow

1. The sender asks `network.Node.GetOnlinePeerIPs` for online Tailscale peers.
2. For every `(chunk CID, peer IP)` pair, it inserts a `PENDING` queue item before any network transfer. The uniqueness rule prevents duplicate deliveries for the same chunk and peer.
3. Up to three worker goroutines atomically claim queue items and stream each local encrypted chunk file exactly as stored to `POST /api/v1/chunks/receive` using `Node.Client()`.
4. The sender includes the original plaintext CID in the `X-AuraCloud-CID` header; the peer stores the received bytes unchanged as `<CID>.chunk`.
5. A `2xx` response marks only that queue item `COMPLETED`. A transport or peer error marks only that item `FAILED` and increments its retry count; the other workers continue.
6. When every chunk for a file and peer is complete, the sender posts the file and chunk manifest to `POST /api/v1/manifest/sync`.
7. The peer indexes the metadata in its local SQLite database, allowing its dashboard to show the replicated file.

### Store-and-forward recovery

At mesh startup, AuraCloud changes any interrupted `IN_PROGRESS` queue items back to retryable work. A background recovery goroutine runs immediately and then every 20 seconds. It selects `PENDING` and `FAILED` rows with fewer than five attempts, groups them by peer IP, and performs one fast tsnet health request to `GET /api/v1/health` for each peer. Only healthy peers are dispatched to the same three-worker pool. This gives offline peers and transient peer churn a bounded, resumable delivery path without blocking new uploads.

The `sync_queue` table contains `id`, `chunk_cid`, `file_id`, `peer_ip`, `status`, `retry_count`, and `last_attempt`. Status values are `PENDING`, `IN_PROGRESS`, `COMPLETED`, and `FAILED`.

`Node.Client()` is important: it returns the HTTP client backed by the embedded `tsnet` transport. Standard Windows sockets may not have a route to `100.x.x.x` Tailscale addresses when no system-level Tailscale adapter is installed.

## Zero-knowledge model

AuraCloud does not distribute master keys over the mesh.

- A replicated peer receives encrypted chunk bytes and non-secret manifest metadata only.
- The receiver does not decrypt, inspect, or re-encrypt incoming chunks.
- A receiver can display and retain a replicated file but can restore its plaintext only when it independently possesses the matching AES-256 key.
- `AURA_MASTER_KEY` can be used to deliberately configure the same key on trusted owner-controlled nodes; it is never sent by AuraCloud itself.

This keeps storage replication separate from data access. Tailscale/WireGuard protects transport between authorized mesh nodes, while AES-GCM protects backup contents at rest and from storage-only peers.

## Master key management

At local or mesh API startup, AuraCloud resolves the encryption key in this order:

1. `AURA_MASTER_KEY`, when present. A 64-character hexadecimal value is decoded as a 32-byte AES key; another non-empty value is deterministically SHA-256-derived into a 32-byte key.
2. `master.key` in the configured storage directory, if it already exists.
3. A newly generated cryptographically secure 32-byte key, written as hexadecimal to `master.key`.

New key files are explicitly created with `0600` permissions on platforms that support POSIX permissions. Startup logs whether the key came from the environment, a file, or fresh generation. The key itself is never logged.

## Important directories and files

```text
main.go                  CLI entry point and runtime startup modes
pkg/api/                 REST handlers, routing, dashboard serving, replication
pkg/chunker/             Fixed-size chunk generation
pkg/crypto/              CIDs, AES-GCM, persistent master-key management
pkg/db/                  SQLite schema and manifest operations
pkg/network/             Embedded tsnet node, discovery, and mesh HTTP client
pkg/storage/             Encrypted chunk persistence and reconstruction helpers
web/                     Embedded dashboard assets
.auracloud_data/         Default runtime data directory
  chunks/                Encrypted chunk payloads and default master.key location
  manifest.db            SQLite file/chunk manifest database and sync_queue state
  tsnet/                 Embedded Tailscale state
```

## Runtime modes

The command-line menu supports:

- End-to-end pipeline verification.
- Custom file processing and restoration.
- SQLite file listing.
- Local REST API/dashboard mode (`http://localhost:8080` by default).
- Tailscale P2P mesh mode with both local and private mesh listeners.

Relevant configuration variables are `PORT`, `STORAGE_DIR`, `AURA_MASTER_KEY`, `TAILSCALE_AUTHKEY`, `TSNET_HOSTNAME`, and `TSNET_DIR`.

## REST API summary

| Endpoint | Purpose |
| --- | --- |
| `GET /health` | Service health status |
| `GET /api/v1/health` | Versioned service health status used by mesh recovery |
| `GET /api/v1/files` | List locally indexed files |
| `POST /api/v1/files/upload` | Upload, chunk, encrypt, and register a file |
| `GET /api/v1/files/download/{id}` | Restore a file when the local key matches |
| `DELETE /api/v1/files/delete/{id}` | Delete a registered file and its eligible chunks |
| `GET /api/v1/node/status` | Local mesh/node status |
| `POST /api/v1/chunks/receive` | Receive raw encrypted chunk payloads from a peer |
| `POST /api/v1/manifest/sync` | Receive a file/chunk manifest from a peer |

## Verification

The project includes package tests for the API, chunker, cryptography, database, network configuration, and storage. The normal verification commands are:

```powershell
go test ./...
go build -o auracloud.exe main.go
```

## Operational note

For an actual two-PC replication test, both nodes must authenticate into the same tailnet and start in mesh mode. If a target peer is offline at upload time, it must have been an active peer when the work was queued; queued work resumes when its health endpoint becomes reachable, up to five attempts. The receiving dashboard should show the replicated manifest and encrypted chunks should appear in its local chunk directory. Plaintext restoration is intentionally unavailable unless that node has the matching owner-managed master key.
