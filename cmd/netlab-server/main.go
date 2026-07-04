package main

import (
	"log"
	"net/http"
	"time"

	"github.com/jnbntc/go-netlab/internal/web"
)

func main() {
	router := web.NewRouter()

	srv := &http.Server{
		Addr:         ":8080",
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second, // Alto timeout para permitir escaneos largos
		IdleTimeout:  120 * time.Second,
	}

	log.Println("--- Netlab Go Engine ---")
	log.Println("[INFO] Servidor escuchando en http://0.0.0.0:8080")
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("[FATAL] Fallo en el servidor HTTP: %v", err)
	}
}
