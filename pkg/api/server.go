package api

import (
	"fmt"
	"net"
	"net/http"

	"auracloud/pkg/db"
	"auracloud/pkg/network"
	"auracloud/pkg/storage"
	"auracloud/web"
)

// Architectural Concept: Standard Library Zero-Dependency REST API Router
//
// In AuraCloud, we build the REST API router using Go's standard library `net/http`.
// Milestone 4 extends the server to support dual-listener architecture:
//
// 1. LOCAL MODE: Standard TCP listener on localhost:8080 (development and single-machine use).
// 2. MESH MODE: tsnet WireGuard listener on the private Tailscale interface, so that ONLY
//    authenticated AuraCloud peer nodes on the same encrypted mesh can reach the API.
//    This is the cornerstone of the P2P backup security model.
//
// By accepting any `net.Listener` interface via StartWithListener(), the same HTTP server
// and handler code runs identically in both modes — no code duplication.

// ServerConfig encapsulates configuration settings for the AuraCloud REST API server.
type ServerConfig struct {
	Port       int           // Port to listen on (e.g., 8080)
	StorageDir string        // Directory path where encrypted chunks are persisted
	MasterKey  []byte        // 32-byte AES secret key used for encryption and decryption
	Node       *network.Node // Optional: embedded Tailscale mesh node (nil = local-only mode)
}

// Server holds the HTTP router, database handle, and runtime configuration.
type Server struct {
	database   *db.DB
	config     ServerConfig
	router     *http.ServeMux
	httpServer *http.Server
}

// NewServer initializes a new REST API Server with registered routes and dependencies.
func NewServer(database *db.DB, config ServerConfig) *Server {
	if config.Port <= 0 {
		config.Port = 8080
	}
	if config.StorageDir == "" {
		config.StorageDir = storage.DefaultStoragePath()
	}

	mux := http.NewServeMux()

	server := &Server{
		database: database,
		config:   config,
		router:   mux,
	}

	// Register HTTP Route Handlers
	server.registerRoutes()

	server.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", config.Port),
		Handler: server.router,
	}

	return server
}

// registerRoutes maps endpoint paths to their respective handler functions.
func (s *Server) registerRoutes() {
	// 1. System Health Status Endpoint
	s.router.HandleFunc("/health", s.handleHealth)
	// Mesh recovery uses the versioned API path; keep /health for backwards compatibility.
	s.router.HandleFunc("/api/v1/health", s.handleHealth)

	// 2. File Listing Endpoint
	s.router.HandleFunc("/api/v1/files", s.handleFilesRoot)

	// 3. File Upload Endpoint
	s.router.HandleFunc("/api/v1/files/upload", s.handleUploadFile)

	// 4. File Download Endpoint (/api/v1/files/download/{id_or_name})
	s.router.HandleFunc("/api/v1/files/download/", s.handleDownloadFile)

	// 5. File Delete Endpoint (/api/v1/files/delete/{id})
	s.router.HandleFunc("/api/v1/files/delete/", s.handleDeleteFile)

	// 6. Node Mesh Status Endpoint (Milestone 4)
	s.router.HandleFunc("/api/v1/node/status", s.handleNodeStatus)
	// Phase 2 queue and reachable-peer status for the dashboard.
	s.router.HandleFunc("/api/v1/sync/status", s.handleSyncStatus)

	// P2P Mesh Synchronization Endpoints
	s.router.HandleFunc("/api/v1/chunks/receive", s.handleReceiveChunk)
	s.router.HandleFunc("/api/v1/manifest/sync", s.handleSyncManifest)

	// 7. Embedded Web UI Dashboard Static File Server (Milestone 5)
	s.router.Handle("/", http.FileServer(http.FS(web.Assets)))
}

// Start launches the HTTP server bound to a standard local TCP listener on the configured port.
// This is the "LOCAL MODE" entry point.
func (s *Server) Start() error {
	fmt.Printf("[REST API] AuraCloud HTTP Router listening on http://localhost:%d\n", s.config.Port)
	err := s.httpServer.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("api: server execution error: %w", err)
	}
	return nil
}

// StartWithListener launches the HTTP server bound to an injected net.Listener.
// This is the "MESH MODE" entry point — the caller provides a tsnet WireGuard mesh listener,
// and the HTTP server runs on the encrypted private network interface instead of localhost.
//
// WHY LISTENER INJECTION:
// Go's `net/http` server calls `l.Accept()` on whatever listener is provided.
// By injecting a tsnet listener, all TCP traffic the server sees has already passed through
// WireGuard decryption — effectively giving us a zero-config mTLS-equivalent security layer.
func (s *Server) StartWithListener(listener net.Listener) error {
	fmt.Printf("[REST API] AuraCloud HTTP Router listening on Tailscale mesh: %s\n", listener.Addr().String())
	err := s.httpServer.Serve(listener)
	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("api: server execution error on mesh listener: %w", err)
	}
	return nil
}

// Close gracefully closes the HTTP server listener.
func (s *Server) Close() error {
	if s.httpServer != nil {
		return s.httpServer.Close()
	}
	return nil
}

// Handler returns the underlying http.Handler (useful for testing with httptest).
func (s *Server) Handler() http.Handler {
	return s.router
}
