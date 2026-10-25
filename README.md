# AuraCloud — Decentralized Peer-to-Peer Storage Engine

AuraCloud is a local-first, decentralized peer-to-peer storage engine designed to store encrypted files and replicate data across connected peers without relying on a conventional centralized storage provider.

The application combines **TypeScript, Node.js, Fastify, and SQLite** for application orchestration, file processing, metadata management, and persistent replication workflows. A lightweight **Go networking sidecar** integrates Tailscale's userspace networking capabilities to enable private peer connectivity.

## Core Features

- **File chunking:** Splits files into fixed-size chunks of 2 MiB by default.
- **Client-side encryption:** Uses AES-256-GCM authenticated encryption with a fresh nonce per chunk.
- **Content-addressed storage:** Uses SHA-256 hashes to identify chunks.
- **File reconstruction:** Uses ordered chunk metadata to reconstruct stored files.
- **Persistent replication queue:** Uses SQLite in WAL mode to maintain replication state.
- **Concurrent transfers:** Uses a bounded three-worker pool for independent transfer tasks.
- **Retry handling:** Uses exponential backoff to handle recoverable transfer failures.
- **Peer-to-peer networking:** Integrates Tailscale networking through a Go sidecar.
- **Local dashboard and API:** Provides an interface for interacting with the storage engine.
- **Persistent metadata:** Maintains file and chunk records for storage and restoration workflows.

## Architecture

AuraCloud separates application-level storage orchestration from peer networking.

```text
             Dashboard / API Client
                      |
                      v
             TypeScript / Node.js
                      |
              Fastify Application
                      |
          +-----------+-----------+
          |           |           |
          v           v           v
      Chunking     SQLite      Replication
      and File     Metadata       Queue
      Processing   and State         |
          |                      Worker Pool
          v                          |
    AES-256-GCM                      v
          |                  Go Networking Sidecar
          v                          |
    Local Chunk Store                v
                             Tailscale / WireGuard
                                      |
                                      v
                                Remote Peers
```

### Application Layer

The TypeScript/Node.js layer coordinates file processing, storage operations, metadata management, and replication workflows. Fastify provides the HTTP API used by the dashboard and other clients.

### Storage and Metadata

Files are divided into chunks, encrypted locally, and stored alongside metadata that maps each file to its ordered chunks. SQLite maintains the file manifest and persistent replication queue.

### Replication Engine

Replication work is persisted so that pending tasks can be recovered after interruptions. A three-worker pool processes transfers concurrently, while retry handling supports recovery from temporary peer or network failures.

### Networking Layer

A Go sidecar integrates Tailscale's `tsnet` networking capabilities to support connectivity between authorized peers without requiring manually configured public IP addresses or port forwarding.

## Technology Stack

| Component | Technology |
|---|---|
| Application language | TypeScript |
| Runtime | Node.js |
| HTTP framework | Fastify |
| Metadata database | SQLite |
| Database mode | WAL |
| File chunking | Fixed-size, 2 MiB default |
| Encryption | AES-256-GCM |
| Content addressing | SHA-256 |
| Transfer management | Three-worker concurrency pool |
| Retry strategy | Exponential backoff |
| Peer networking | Tailscale `tsnet` / WireGuard |
| Networking integration | Go |
| Frontend | Web dashboard |

## How It Works

### 1. File Upload and Chunking

A file is submitted through the application interface or API. The storage pipeline divides it into chunks and preserves their ordering in the file metadata.

### 2. Encryption and Content Addressing

Each chunk is encrypted using AES-256-GCM with a fresh nonce. SHA-256 provides content-derived chunk identifiers, while the stored payload remains encrypted.

### 3. Metadata Persistence

The file manifest and associated chunk records are stored in SQLite. The manifest enables the application to locate the chunks needed for restoration.

### 4. Peer Replication

When peer networking is enabled, the replication workflow queues transfer tasks for eligible peers. Workers send encrypted chunk payloads through the networking layer and track individual transfer outcomes.

### 5. Recovery and Reconstruction

Failed replication tasks can be retried when peers become reachable. For restoration, the application retrieves the required chunks, decrypts them with the matching key, and reassembles the file in its original order.

## Security Model

AuraCloud is designed to keep encryption separate from storage and replication.

- File contents are encrypted before their stored payloads are replicated.
- AES-256-GCM provides authenticated encryption.
- Encryption keys are managed separately from replicated chunk payloads.
- Peer networking provides a private communication path between authorized nodes.
- File restoration requires the appropriate encryption key and the necessary chunk data.

**Security considerations:** The strength of this model depends on correct key management, nonce handling, metadata protection, and authorization of peer operations. Content addressing alone does not establish authenticity, and encrypted storage does not eliminate all metadata leakage.

## Running AuraCloud

### Prerequisites

- Node.js and npm
- Go, if building or running the networking sidecar from source
- Tailscale configuration and authentication for peer networking

### Installation

Clone the repository:

```bash
git clone YOUR_REPOSITORY_URL
cd AuraCloud
npm install
```

Build and start the complete Node.js application and Go sidecar with `npm run start:hybrid`. The dashboard is served at `http://127.0.0.1:3000`. On Windows, `./scripts/run.ps1` installs dependencies, builds the sidecar to `bin/aura-engine.exe`, compiles TypeScript, and launches AuraCloud. On Linux/macOS, use `./scripts/run.sh`.

Peer networking requires the relevant Tailscale configuration. Keep authentication credentials and encryption keys out of source control.

## API and Runtime

AuraCloud's API and runtime functionality are implemented in the application layer. Depending on the enabled runtime mode, the application supports storage operations, file listing and restoration, node status, and peer replication.

Consult the implementation for the current endpoint paths, request formats, configuration variables, and startup scripts.

## Testing and Verification

Run the tests and build commands supported by the current project configuration before making a release.

Verification should cover:

- File chunking and reconstruction
- Encryption and decryption
- Chunk integrity and metadata consistency
- SQLite persistence
- Replication queue state transitions
- Retry behavior after peer failures
- Peer-to-peer transfer and restoration

## Project Structure

| Path | Purpose |
|---|---|
| `src/` | TypeScript application, API, SQLite database, and replication workers |
| `web/index.html` | Dashboard served by Fastify |
| `cmd/aura-engine/` | Minimal Go `tsnet` sidecar and localhost control API |
| `scripts/` | Cross-platform sidecar build and launch scripts |
| `package.json` | Node.js dependencies and build/run commands |
| `go.mod` / `go.sum` | Go sidecar dependency configuration |
| `tsconfig.json` | TypeScript compiler configuration |

The Go source is limited to `cmd/aura-engine/`; all application orchestration and metadata logic lives in TypeScript.
## Demo

A demonstration video will be added here to show the application interface and actual storage and replication workflows.


