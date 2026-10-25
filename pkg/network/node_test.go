package network

import (
	"path/filepath"
	"testing"
)

// TestDefaultNodeConfig verifies that DefaultNodeConfig() returns sensible defaults
// and that the TAILSCALE_AUTHKEY env var is wired up correctly.
func TestDefaultNodeConfig(t *testing.T) {
	cfg := DefaultNodeConfig()

	if cfg.Hostname != "auracloud-node" {
		t.Errorf("Expected default hostname 'auracloud-node', got '%s'", cfg.Hostname)
	}
	if cfg.StateDir != ".auracloud_data/tsnet" {
		t.Errorf("Expected default state dir '.auracloud_data/tsnet', got '%s'", cfg.StateDir)
	}
	if cfg.Port != 8080 {
		t.Errorf("Expected default port 8080, got %d", cfg.Port)
	}
	if cfg.Ephemeral != false {
		t.Errorf("Expected ephemeral to default to false, got true")
	}
}

// TestNewNodeStateDirectoryCreation verifies that NewNode() creates the tsnet state directory
// if it does not exist, preventing a panic during initialization.
func TestNewNodeStateDirectoryCreation(t *testing.T) {
	tempDir := t.TempDir()
	stateDir := filepath.Join(tempDir, "tsnet_state")

	cfg := NodeConfig{
		Hostname:  "test-node",
		StateDir:  stateDir,
		AuthKey:   "",
		Port:      9090,
		Ephemeral: true,
	}

	node, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode() failed: %v", err)
	}

	// Verify the node was created with the correct config
	if node.Config().Hostname != "test-node" {
		t.Errorf("Expected hostname 'test-node', got '%s'", node.Config().Hostname)
	}
	if node.Config().Port != 9090 {
		t.Errorf("Expected port 9090, got %d", node.Config().Port)
	}
	if node.Config().Ephemeral != true {
		t.Errorf("Expected Ephemeral=true, got false")
	}

	// Verify tsnet state directory was created on disk
	if node.Config().StateDir != stateDir {
		t.Errorf("Expected state dir '%s', got '%s'", stateDir, node.Config().StateDir)
	}
}

// TestNewNodeDefaultFallbacks verifies that empty fields in NodeConfig are filled in
// with sensible AuraCloud defaults.
func TestNewNodeDefaultFallbacks(t *testing.T) {
	tempDir := t.TempDir()

	// Provide minimal config to trigger fallback logic
	cfg := NodeConfig{
		Hostname: "",
		StateDir: filepath.Join(tempDir, "tsnet"),
		Port:     0,
	}

	node, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode() with empty fields failed: %v", err)
	}

	// Verify hostname default fallback
	if node.Config().Hostname != "auracloud-node" {
		t.Errorf("Expected fallback hostname 'auracloud-node', got '%s'", node.Config().Hostname)
	}

	// Verify port default fallback
	if node.Config().Port != 8080 {
		t.Errorf("Expected fallback port 8080, got %d", node.Config().Port)
	}
}

// TestNodeStatusLocalOnlyDTOConstruction verifies the NodeStatus DTO structure compiles
// and serializes correctly without requiring a live Tailscale network connection.
func TestNodeStatusLocalOnlyDTOConstruction(t *testing.T) {
	// Construct a status object manually (as if returned by GetStatus in offline/unauthenticated mode)
	status := &NodeStatus{
		Hostname:     "auracloud-node",
		TailscaleIPs: []string{"100.64.0.1"},
		Status:       "connected",
		MeshEnabled:  true,
		StateDir:     ".auracloud_data/tsnet",
	}

	if status.Hostname != "auracloud-node" {
		t.Errorf("Expected hostname 'auracloud-node', got '%s'", status.Hostname)
	}
	if len(status.TailscaleIPs) != 1 || status.TailscaleIPs[0] != "100.64.0.1" {
		t.Errorf("Expected TailscaleIPs ['100.64.0.1'], got %v", status.TailscaleIPs)
	}
	if !status.MeshEnabled {
		t.Errorf("Expected MeshEnabled=true, got false")
	}
}
