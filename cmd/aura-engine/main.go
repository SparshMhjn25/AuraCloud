package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
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

	acrypto "auracloud/pkg/crypto"
	"auracloud/pkg/network"
	"auracloud/pkg/storage"
)

const chunkSize = 2 << 20

type engine struct {
	root   string
	key    []byte
	node   *network.Node
	client *http.Client
}
type replicateRequest struct {
	CID  string `json:"cid"`
	Peer string `json:"peer"`
}

func main() {
	root := os.Getenv("AURA_DATA_DIR")
	if root == "" {
		root = ".auracloud_data"
	}
	chunks := filepath.Join(root, "chunks")
	if err := storage.EnsureStorageDir(chunks); err != nil {
		log.Fatal(err)
	}
	key, source, err := acrypto.LoadOrCreateMasterKey(chunks)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("master key loaded from %s", source)
	cfg := network.DefaultNodeConfig()
	cfg.Port = 8080
	if v := os.Getenv("TSNET_HOSTNAME"); v != "" {
		cfg.Hostname = v
	}
	if v := os.Getenv("TSNET_DIR"); v != "" {
		cfg.StateDir = v
	} else {
		cfg.StateDir = filepath.Join(root, "tsnet")
	}
	if v := os.Getenv("TAILSCALE_AUTHKEY"); v != "" {
		cfg.AuthKey = v
	}
	node, err := network.NewNode(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer node.Close()
	meshListener, err := node.StartListener("tcp", ":8080")
	if err != nil {
		log.Fatal(err)
	}
	e := &engine{root: chunks, key: key, node: node, client: node.Client()}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/chunks/receive", e.receive)
	mesh := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		log.Printf("[mesh] listening on tsnet :8080")
		if err := mesh.Serve(meshListener); err != nil && err != http.ErrServerClosed {
			log.Printf("mesh server: %v", err)
		}
	}()
	localMux := http.NewServeMux()
	localMux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	localMux.HandleFunc("POST /engine/chunks/store", e.store)
	localMux.HandleFunc("GET /engine/chunks/", e.get)
	localMux.HandleFunc("POST /engine/peers/replicate", e.replicate)
	localMux.HandleFunc("GET /engine/status", e.status)
	ln, err := net.Listen("tcp", "127.0.0.1:9091")
	if err != nil {
		log.Fatal(err)
	}
	local := &http.Server{Handler: localAuth(localMux, os.Getenv("AURA_ENGINE_TOKEN")), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-shutdown()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = local.Shutdown(ctx)
		_ = mesh.Shutdown(ctx)
	}()
	log.Printf("[control] listening on 127.0.0.1:9091")
	if err := local.Serve(ln); err != nil && err != http.ErrServerClosed {
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

func shutdown() <-chan struct{} {
	ch := make(chan struct{})
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() { <-c; close(ch) }()
	return ch
}
func (e *engine) store(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, chunkSize))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cid := sha256.Sum256(data)
	id := hex.EncodeToString(cid[:])
	ciphertext, nonce, err := acrypto.EncryptChunk(data, e.key)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if err = storage.SaveEncryptedChunk(e.root, id, nonce, ciphertext); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"cid": id, "size": len(data), "nonce_hex": hex.EncodeToString(nonce)})
}
func (e *engine) get(w http.ResponseWriter, r *http.Request) {
	cid := strings.TrimPrefix(r.URL.Path, "/engine/chunks/")
	if len(cid) != 64 {
		http.Error(w, "invalid cid", 400)
		return
	}
	nonce, ct, err := storage.LoadEncryptedChunk(e.root, cid)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	plain, err := acrypto.DecryptChunk(ct, nonce, e.key)
	if err != nil {
		http.Error(w, err.Error(), 500)
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
	if len(cid) != 64 {
		http.Error(w, "invalid cid", 400)
		return
	}
	if _, err := hex.DecodeString(cid); err != nil {
		http.Error(w, "invalid cid", 400)
		return
	}
	defer r.Body.Close()
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, chunkSize+64))
	if err != nil || len(data) < 12 {
		http.Error(w, "invalid chunk", 400)
		return
	}
	if err = os.WriteFile(filepath.Join(e.root, cid+".chunk"), data, 0600); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.WriteHeader(http.StatusCreated)
}
func (e *engine) replicate(w http.ResponseWriter, r *http.Request) {
	var req replicateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", 400)
		return
	}
	if len(req.CID) != 64 || strings.ContainsAny(req.Peer, "/\\") || net.ParseIP(strings.Trim(req.Peer, "[]")) == nil {
		http.Error(w, "invalid cid or peer", 400)
		return
	}
	if _, err := hex.DecodeString(req.CID); err != nil {
		http.Error(w, "invalid cid", 400)
		return
	}
	path := filepath.Join(e.root, req.CID+".chunk")
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	defer f.Close()
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	target := "http://" + net.JoinHostPort(strings.Trim(req.Peer, "[]"), "8080") + "/api/v1/chunks/receive"
	out, err := http.NewRequestWithContext(ctx, http.MethodPost, target, f)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	out.Header.Set("X-AuraCloud-CID", req.CID)
	out.Header.Set("Content-Type", "application/octet-stream")
	resp, err := e.client.Do(out)
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		http.Error(w, "peer returned "+resp.Status, 502)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}
func (e *engine) status(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	st, err := e.node.GetStatus(ctx)
	if err != nil {
		http.Error(w, err.Error(), 503)
		return
	}
	peers, _ := e.node.GetOnlinePeerIPs(ctx)
	json.NewEncoder(w).Encode(map[string]any{"mesh": st, "localPeerID": st.Hostname, "onlinePeers": peers})
}
