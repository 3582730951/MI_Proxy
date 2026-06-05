package web

import (
	"embed"
	"net/http"
)

//go:embed index.html styles.css app.js
var assets embed.FS

func Handler() http.Handler {
	return http.FileServer(http.FS(assets))
}
