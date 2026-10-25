package network

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"

	"tailscale.com/tsnet"
)

// Architectural Concept: Embedded Tailscale WireGuard Mesh Node (tsnet)
//
// In AuraCloud's P2P model, each running instance is a *node* in a private encrypted mesh.
// Nodes communicate through WireGuard tunnels without exposing anything to the public internet.
//
// How tsnet Works:
// 1. WireGuard: Every message between AuraCloud nodes is encrypted with WireGuard, a modern
//    kernel-bypass VPN protocol. tsnet implements WireGuard entirely in userspace Go code
//    (no kernel modules, no admin rights, no external VPN client required).
//
// 2. Tailscale Control Plane: When a node first starts, it contacts the Tailscale coordination
//    server to register its public WireGuard key and receive a stable private IP address
//    (e.g., 100.64.0.1). This is a one-time handshake; after that, peers communicate directly.
//
// 3. NAT Traversal & DERP Relays: Tailscale uses a technique called "DERP" (Distributed Relay
//    for Encrypted Packets) as a fallback relay when two peers cannot punch through NAT
//    firewalls directly. Direct WireGuard is always preferred when possible.
//
// 4. Ephemeral Nodes: Nodes marked `Ephemeral: true` are automatically removed from the
//    mesh when they disconnect. This is ideal for short-lived backup processes.

// NodeConfig holds all configuration parameters for an AuraCloud tsnet mesh node.
type NodeConfig struct {
	// Hostname is the unique name the node registers under in the Tailscale mesh.
	// It becomes resolvable as `<hostname>.tailXXXX.ts.net` or `<hostname>` via MagicDNS.
	Hostname string `json:"hostname"`

	// StateDir is the local directory where tsnet persists node identity (WireGuard keypair,
	// IP assignment, trusted peers). Reusing the same StateDir across restarts means the node
	// keeps the same stable mesh IP address.
	StateDir string `json:"state_dir"`

	// AuthKey is a pre-authentication key from the Tailscale admin panel.
	// When provided, the node joins the mesh immediately without browser login.
	// If empty, tsnet prints a login URL to stdout for interactive browser pairing.
	AuthKey string `json:"auth_key"`

	// Port is the TCP port the embedded HTTP server will listen on within the mesh interface.
	Port int `json:"port"`

	// Ephemeral marks the node as temporary. On disconnect, Tailscale removes it from the mesh.
	// Useful for CI/CD environments or short-lived backup agents.
	Ephemeral bool `json:"ephemeral"`
}

// NodeStatus is the data transfer object returned by GET /api/v1/node/status.
// It describes the current mesh connectivity state of this AuraCloud instance.
type NodeStatus struct {
	Hostname     string   `json:"hostname"`
	TailscaleIPs []string `json:"tailscale_ips"`
	Status       string   `json:"status"`
	MeshEnabled  bool     `json:"mesh_enabled"`
	StateDir     string   `json:"state_dir"`
}

// Node wraps the embedded tsnet.Server and its configuration.
type Node struct {
	config NodeConfig
	ts     *tsnet.Server
}

// DefaultNodeConfig returns a NodeConfig with sensible AuraCloud defaults.
// The hostname is set to "auracloud-node", state dir to .auracloud_data/tsnet/,
// and the auth key is read from the TAILSCALE_AUTHKEY environment variable.
func DefaultNodeConfig() NodeConfig {
	return NodeConfig{
		Hostname:  "auracloud-node",
		StateDir:  ".auracloud_data/tsnet",
		AuthKey:   os.Getenv("TAILSCALE_AUTHKEY"),
		Port:      8080,
		Ephemeral: false,
	}
}

// NewNode constructs and configures a new embedded Tailscale mesh node.
// It does NOT start the node or make any network connections; call StartListener to activate.
func NewNode(config NodeConfig) (*Node, error) {
	if config.Hostname == "" {
		config.Hostname = "auracloud-node"
	}
	if config.StateDir == "" {
		config.StateDir = ".auracloud_data/tsnet"
	}
	if config.Port <= 0 {
		config.Port = 8080
	}

	// Ensure the state directory exists on disk before tsnet attempts to write to it.
	// WHY: tsnet writes the WireGuard private key, network map, and control plane state
	// into this directory. If it doesn't exist, tsnet initialization panics.
	if err := os.MkdirAll(config.StateDir, 0700); err != nil {
		return nil, fmt.Errorf("network: failed to create tsnet state directory %s: %w", config.StateDir, err)
	}

	// Construct the embedded tsnet.Server.
	// tsnet.Server IS the entire Tailscale network stack: WireGuard, DERP, DNS, NATTraversal.
	ts := &tsnet.Server{
		// Hostname: The name that other Tailscale mesh nodes and devices see for this node.
		Hostname: config.Hostname,

		// Dir: The filesystem path where tsnet stores its persistent state (keys, IP, peers).
		Dir: config.StateDir,

		// AuthKey: Pre-shared authentication key from Tailscale Admin Console.
		// Allows headless node joining without browser authentication.
		// If empty, tsnet falls back to printing a login URL to stdout.
		AuthKey: config.AuthKey,

		// Ephemeral: If true, Tailscale removes this node from the mesh on disconnect.
		// Great for serverless or disposable backup agent deployments.
		Ephemeral: config.Ephemeral,

		// Logf: Suppress verbose tsnet internal logs to keep our terminal output clean.
		// In production, wire this to a structured logger (slog, zerolog, etc.).
		Logf: func(format string, args ...any) {
			// Intentionally suppressed for clean CLI output.
			// Replace with: log.Printf("[tsnet] "+format, args...) for debug mode.
		},
	}

	return &Node{
		config: config,
		ts:     ts,
	}, nil
}

// StartListener activates the tsnet node on the Tailscale mesh and returns a net.Listener
// bound to the private WireGuard mesh interface.
//
// The returned net.Listener is fully compatible with the standard `net.Listener` interface,
// which means our existing `pkg/api` HTTP server can accept it without any modification.
//
// Parameters:
//   - network: "tcp", "tcp4", or "tcp6"
//   - addr:    ":8080" or specific port string
func (n *Node) StartListener(network, addr string) (net.Listener, error) {
	// ts.Listen creates a TCP listener on the tsnet virtual network interface.
	// WHY: This listener only accepts connections arriving through the encrypted WireGuard
	// mesh — not from the public internet or local network. This is the core security guarantee.
	ln, err := n.ts.Listen(network, addr)
	if err != nil {
		return nil, fmt.Errorf("network: failed to start tsnet listener on %s%s: %w", network, addr, err)
	}

	return ln, nil
}

// GetStatus queries the running tsnet node for its current Tailscale IP addresses and returns
// a NodeStatus DTO for use in the /api/v1/node/status HTTP endpoint.
func (n *Node) GetStatus(ctx context.Context) (*NodeStatus, error) {
	// ts.LocalClient() returns a local Tailscale API client scoped to this embedded node.
	lc, err := n.ts.LocalClient()
	if err != nil {
		return nil, fmt.Errorf("network: failed to get tsnet local client: %w", err)
	}

	// Status() queries the local node's mesh status: IP addresses, peers, DERP state, etc.
	st, err := lc.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("network: failed to query tsnet node status: %w", err)
	}

	// Collect all assigned Tailscale IP addresses (may include both IPv4 and IPv6 mesh IPs).
	var ips []string
	for _, ip := range st.TailscaleIPs {
		ips = append(ips, ip.String())
	}

	meshStatus := "connected"
	if len(ips) == 0 {
		meshStatus = "authenticating"
	}

	return &NodeStatus{
		Hostname:     n.config.Hostname,
		TailscaleIPs: ips,
		Status:       meshStatus,
		MeshEnabled:  true,
		StateDir:     n.config.StateDir,
	}, nil
}

// GetOnlinePeerIPs returns only IPv4 Tailscale addresses of online peers. AuraCloud
// replication uses net.JoinHostPort with these 100.x.x.x endpoints and deliberately
// ignores fd7a: IPv6 addresses to avoid inconsistent dual-stack reachability.
func (n *Node) GetOnlinePeerIPs(ctx context.Context) ([]string, error) {
	if n == nil || n.ts == nil {
		return nil, fmt.Errorf("network: node or tsnet server is uninitialized")
	}

	lc, err := n.ts.LocalClient()
	if err != nil {
		return nil, fmt.Errorf("network: failed to get tsnet local client: %w", err)
	}

	st, err := lc.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("network: failed to query tsnet peer status: %w", err)
	}
	if st == nil {
		return nil, fmt.Errorf("network: tsnet peer status is unavailable")
	}

	peerIPs := make([]string, 0)
	seen := make(map[string]struct{})
	for _, peer := range st.Peer {
		if peer == nil || !peer.Online {
			continue
		}
		for _, ip := range peer.TailscaleIPs {
			ipv4 := net.ParseIP(ip.String())
			if ipv4 == nil || ipv4.To4() == nil {
				continue
			}
			address := ipv4.To4().String()
			if _, exists := seen[address]; exists {
				continue
			}
			seen[address] = struct{}{}
			peerIPs = append(peerIPs, address)
		}
	}

	return peerIPs, nil
}

// Client returns an HTTP client whose transport dials through this embedded
// tsnet node. Calls to Tailscale IP addresses must use this client: the host OS
// may not have a Tailscale network adapter, especially when tsnet is embedded.
func (n *Node) Client() *http.Client {
	if n == nil || n.ts == nil {
		return nil
	}
	return n.ts.HTTPClient()
}

// Close gracefully shuts down the embedded tsnet node, closing all WireGuard tunnels
// and releasing the Tailscale control plane connection.
func (n *Node) Close() error {
	if n.ts != nil {
		return n.ts.Close()
	}
	return nil
}

// Config returns the current NodeConfig (read-only accessor for testing and status display).
func (n *Node) Config() NodeConfig {
	return n.config
}
