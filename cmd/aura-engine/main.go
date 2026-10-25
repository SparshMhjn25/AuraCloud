package main

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"tailscale.com/tsnet"
)

const maxChunkPayload = 2<<20 + 12 + 16

type engine struct {
	ts         *tsnet.Server
	meshClient *http.Client
	nodeClient *http.Client
	nodeURL    string
	token      string
}

type meshStatus struct {
	Hostname     string   `json:"hostname"`
	TailscaleIPs []string `json:"tailscale_ips"`
	Status       string   `json:"status"`
	MeshEnabled  bool     `json:"mesh_enabled"`
	StateDir     string   `json:"state_dir"`
}

func main() {
	dataDir := envOr("AURA_DATA_DIR", ".auracloud_data")
	stateDir := envOr("TSNET_DIR", filepath.Join(dataDir, "tsnet"))
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		log.Fatal(err)
	}
	hostname := envOr("TSNET_HOSTNAME", "auracloud-node")
	ts := &tsnet.Server{
		Hostname: hostname,
		Dir:      stateDir,
		AuthKey:  os.Getenv("TAILSCALE_AUTHKEY"),
		Logf:     func(format string, args ...any) { log.Printf("[tsnet] "+format, args...) },
	}
	defer ts.Close()
	listener, err := ts.Listen("tcp", ":8080")
	if err != nil {
		log.Fatal(err)
	}

	e := &engine{
		ts:         ts,
		meshClient: ts.HTTPClient(),
		nodeClient: &http.Client{Timeout: 2 * time.Minute},
		nodeURL:    strings.TrimRight(envOr("AURA_NODE_URL", "http://127.0.0.1:3000"), "/"),
		token:      os.Getenv("AURA_ENGINE_TOKEN"),
	}
	meshMux := http.NewServeMux()
	meshMux.HandleFunc("POST /api/v1/chunks/receive", e.receiveFromPeer)
	meshServer := &http.Server{Handler: meshMux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		log.Printf("[mesh] listening on tsnet :8080")
		if err := meshServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("mesh server: %v", err)
		}
	}()

	controlMux := http.NewServeMux()
	controlMux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	controlMux.HandleFunc("POST /proxy/send-to-peer", e.sendToPeer)
	controlMux.HandleFunc("GET /engine/status", e.status)
	localListener, err := net.Listen("tcp", "127.0.0.1:9091")
	if err != nil {
		log.Fatal(err)
	}
	controlServer := &http.Server{Handler: localAuth(controlMux, e.token), ReadHeaderTimeout: 10 * time.Second}

	stopped := make(chan os.Signal, 1)
	signal.Notify(stopped, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stopped
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = controlServer.Shutdown(ctx)
		_ = meshServer.Shutdown(ctx)
	}()
	log.Printf("[control] listening on 127.0.0.1:9091")
	if err := controlServer.Serve(localListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

// Peer payloads are streamed unchanged to Node, which owns validation and disk storage.
func (e *engine) receiveFromPeer(w http.ResponseWriter, r *http.Request) {
	cid := r.Header.Get("X-AuraCloud-CID")
	if !validCID(cid) {
		http.Error(w, "invalid cid", http.StatusBadRequest)
		return
	}
	if r.ContentLength > maxChunkPayload {
		http.Error(w, "chunk payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	out, err := http.NewRequestWithContext(ctx, http.MethodPost, e.nodeURL+"/internal/chunks/receive", http.MaxBytesReader(w, r.Body, maxChunkPayload))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	out.ContentLength = r.ContentLength
	out.Header.Set("Content-Type", "application/octet-stream")
	out.Header.Set("X-AuraCloud-CID", cid)
	out.Header.Set("Authorization", "Bearer "+e.token)
	resp, err := e.nodeClient.Do(out)
	if err != nil {
		http.Error(w, "Node receiver unavailable: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// Node streams the encrypted chunk body here; Go forwards it unchanged over tsnet.
func (e *engine) sendToPeer(w http.ResponseWriter, r *http.Request) {
	peerIP := strings.Trim(r.Header.Get("X-AuraCloud-Peer"), "[]")
	cid := r.Header.Get("X-AuraCloud-CID")
	if net.ParseIP(peerIP) == nil || !validCID(cid) {
		http.Error(w, "invalid peer or cid", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	url := "http://" + net.JoinHostPort(peerIP, "8080") + "/api/v1/chunks/receive"
	out, err := http.NewRequestWithContext(ctx, http.MethodPost, url, http.MaxBytesReader(w, r.Body, maxChunkPayload))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	out.ContentLength = r.ContentLength
	out.Header.Set("Content-Type", "application/octet-stream")
	out.Header.Set("X-AuraCloud-CID", cid)
	resp, err := e.meshClient.Do(out)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (e *engine) status(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	client, err := e.ts.LocalClient()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	st, err := client.Status(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	ips := make([]string, 0, len(st.TailscaleIPs))
	for _, ip := range st.TailscaleIPs {
		ips = append(ips, ip.String())
	}
	stateDir := envOr("TSNET_DIR", filepath.Join(envOr("AURA_DATA_DIR", ".auracloud_data"), "tsnet"))
	status := "connected"
	if len(ips) == 0 {
		status = "authenticating"
	}
	peers := make([]string, 0)
	for _, peer := range st.Peer {
		if peer == nil || !peer.Online {
			continue
		}
		for _, ip := range peer.TailscaleIPs {
			parsed := net.ParseIP(ip.String())
			if parsed != nil && parsed.To4() != nil {
				peers = append(peers, parsed.To4().String())
			}
		}
	}
	mesh := meshStatus{Hostname: envOr("TSNET_HOSTNAME", "auracloud-node"), TailscaleIPs: ips, Status: status, MeshEnabled: true, StateDir: stateDir}
	localPeerID := mesh.Hostname
	if len(ips) > 0 {
		localPeerID = ips[0]
	}
	writeJSON(w, http.StatusOK, map[string]any{"mesh": mesh, "localPeerID": localPeerID, "onlinePeers": peers})
}

func localAuth(next http.Handler, token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" || len(provided) != len(token) || subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func validCID(cid string) bool {
	if len(cid) != 64 {
		return false
	}
	_, err := hex.DecodeString(cid)
	return err == nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
