package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
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

const (
	chunkLimit = 2 << 20
	nonceSize  = 12
	keySize    = 32
)

type engine struct {
	chunksDir  string
	key        []byte
	ts         *tsnet.Server
	meshClient *http.Client
}

type replicateRequest struct {
	CID  string `json:"cid"`
	Peer string `json:"peer"`
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
	chunksDir := filepath.Join(dataDir, "chunks")
	if err := os.MkdirAll(chunksDir, 0700); err != nil {
		log.Fatal(err)
	}
	key, err := loadOrCreateKey(chunksDir)
	if err != nil {
		log.Fatal(err)
	}

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

	e := &engine{chunksDir: chunksDir, key: key, ts: ts, meshClient: ts.HTTPClient()}
	meshMux := http.NewServeMux()
	meshMux.HandleFunc("POST /api/v1/chunks/receive", e.receive)
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
	controlMux.HandleFunc("POST /engine/chunks/store", e.store)
	controlMux.HandleFunc("GET /engine/chunks/", e.get)
	controlMux.HandleFunc("POST /engine/peers/replicate", e.replicate)
	controlMux.HandleFunc("GET /engine/status", e.status)
	listenerLocal, err := net.Listen("tcp", "127.0.0.1:9091")
	if err != nil {
		log.Fatal(err)
	}
	controlServer := &http.Server{Handler: localAuth(controlMux, os.Getenv("AURA_ENGINE_TOKEN")), ReadHeaderTimeout: 10 * time.Second}

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
	if err := controlServer.Serve(listenerLocal); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
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

func (e *engine) store(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	plain, err := io.ReadAll(http.MaxBytesReader(w, r.Body, chunkLimit))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cid := sha256.Sum256(plain)
	id := hex.EncodeToString(cid[:])
	block, err := aes.NewCipher(e.key)
	if err != nil {
		http.Error(w, "cipher initialization failed", http.StatusInternalServerError)
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		http.Error(w, "cipher initialization failed", http.StatusInternalServerError)
		return
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	stored := append(nonce, gcm.Seal(nil, nonce, plain, nil)...)
	if err = os.WriteFile(filepath.Join(e.chunksDir, id+".chunk"), stored, 0600); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cid": id, "size": len(plain), "nonce_hex": hex.EncodeToString(nonce)})
}

func (e *engine) get(w http.ResponseWriter, r *http.Request) {
	cid := strings.TrimPrefix(r.URL.Path, "/engine/chunks/")
	if !validCID(cid) {
		http.Error(w, "invalid cid", http.StatusBadRequest)
		return
	}
	stored, err := os.ReadFile(filepath.Join(e.chunksDir, cid+".chunk"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	plain, err := e.decrypt(stored)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	digest := sha256.Sum256(plain)
	if hex.EncodeToString(digest[:]) != cid {
		http.Error(w, "chunk CID integrity check failed", http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(plain)
}

func (e *engine) receive(w http.ResponseWriter, r *http.Request) {
	cid := r.Header.Get("X-AuraCloud-CID")
	if !validCID(cid) {
		http.Error(w, "invalid cid", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()
	stored, err := io.ReadAll(http.MaxBytesReader(w, r.Body, chunkLimit+nonceSize+16))
	if err != nil || len(stored) < nonceSize+16 {
		http.Error(w, "invalid chunk payload", http.StatusBadRequest)
		return
	}
	if err := os.WriteFile(filepath.Join(e.chunksDir, cid+".chunk"), stored, 0600); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (e *engine) replicate(w http.ResponseWriter, r *http.Request) {
	var req replicateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	peerIP := strings.Trim(req.Peer, "[]")
	if !validCID(req.CID) || net.ParseIP(peerIP) == nil {
		http.Error(w, "invalid cid or peer", http.StatusBadRequest)
		return
	}
	f, err := os.Open(filepath.Join(e.chunksDir, req.CID+".chunk"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	defer f.Close()
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	url := "http://" + net.JoinHostPort(peerIP, "8080") + "/api/v1/chunks/receive"
	out, err := http.NewRequestWithContext(ctx, http.MethodPost, url, f)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out.Header.Set("X-AuraCloud-CID", req.CID)
	out.Header.Set("Content-Type", "application/octet-stream")
	resp, err := e.meshClient.Do(out)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		http.Error(w, "peer returned "+resp.Status, http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusAccepted)
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
	mesh := meshStatus{Hostname: envOr("TSNET_HOSTNAME", "auracloud-node"), TailscaleIPs: ips, Status: status, MeshEnabled: true, StateDir: envOr("TSNET_DIR", filepath.Join(envOr("AURA_DATA_DIR", ".auracloud_data"), "tsnet"))}
	localPeerID := mesh.Hostname
	if len(ips) > 0 {
		localPeerID = ips[0]
	}
	writeJSON(w, http.StatusOK, map[string]any{"mesh": mesh, "localPeerID": localPeerID, "onlinePeers": peers})
}

func (e *engine) decrypt(stored []byte) ([]byte, error) {
	if len(stored) < nonceSize+16 {
		return nil, errors.New("corrupt encrypted chunk")
	}
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, stored[:nonceSize], stored[nonceSize:], nil)
}

func loadOrCreateKey(dir string) ([]byte, error) {
	if value := strings.TrimSpace(os.Getenv("AURA_MASTER_KEY")); value != "" {
		hexValue := strings.TrimPrefix(value, "0x")
		if key, err := hex.DecodeString(hexValue); err == nil && len(key) == keySize {
			return key, nil
		}
		key := sha256.Sum256([]byte(value))
		return key[:], nil
	}
	keyPath := filepath.Join(dir, "master.key")
	contents, err := os.ReadFile(keyPath)
	if err == nil {
		key, decodeErr := hex.DecodeString(strings.TrimSpace(string(contents)))
		if decodeErr != nil || len(key) != keySize {
			return nil, errors.New("master.key must contain a 32-byte hexadecimal key")
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil && errors.Is(err, os.ErrExist) {
		contents, err = os.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}
		key, err = hex.DecodeString(strings.TrimSpace(string(contents)))
		if err != nil || len(key) != keySize {
			return nil, errors.New("master.key must contain a 32-byte hexadecimal key")
		}
		return key, nil
	}
	if err != nil {
		return nil, err
	}
	if _, err = io.WriteString(file, hex.EncodeToString(key)+"\n"); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err = file.Close(); err != nil {
		return nil, err
	}
	return key, nil
}

func validCID(cid string) bool {
	if len(cid) != sha256.Size*2 {
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
