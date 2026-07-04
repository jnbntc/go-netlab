package web

import "net/http"

func NewRouter() http.Handler {
	mux := http.NewServeMux()
	h := NewHandlers()

	// Rutas dinámicas
	mux.HandleFunc("/", h.Index)
	mux.HandleFunc("/ping", h.Ping)
	mux.HandleFunc("/arp", h.Arp)
	mux.HandleFunc("/dns", h.Dns)
	mux.HandleFunc("/headers", h.Headers)
	mux.HandleFunc("/nmap", h.Nmap)
	mux.HandleFunc("/traceroute", h.Traceroute)
	mux.HandleFunc("/dhcp", h.Dhcp)
	mux.HandleFunc("/whois", h.Whois)

	// Servidor de archivos estáticos (CSS/JS propios)
	fs := http.FileServer(http.Dir("web/static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	return mux
}
