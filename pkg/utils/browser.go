package utils

import (
	"fmt"
	"os/exec"
	"runtime"
)

// OpenBrowser attempts to launch the system default web browser targeting the given URL.
// Supports Windows (rundll32), macOS (open), and Linux (xdg-open).
func OpenBrowser(url string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	default:
		return fmt.Errorf("unsupported OS platform: %s", runtime.GOOS)
	}

	return cmd.Start()
}
