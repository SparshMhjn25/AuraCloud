package web

import "embed"

// Assets holds the embedded static web dashboard assets (HTML/CSS/JS).
//
//go:embed index.html
var Assets embed.FS
