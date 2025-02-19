package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"github.com/google/uuid"
	"github.com/jacobshu/chirp/api/handler"
	"github.com/jacobshu/chirp/api/middleware"
	"github.com/jacobshu/chirp/internal/auth"
	"github.com/jacobshu/chirp/internal/database"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type Metrics struct {
	Hits atomic.Int32
}

type App struct {
	Metrics    Metrics
	DB         *database.Queries
	Enviroment string
	Auth       auth.Service
	signingKey string
	polkaKey   string
}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")
	key := os.Getenv("TOKEN_STRING")
	polkaAPIKey := os.Getenv("POLKA_KEY")

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Printf("error loading postgres: %v\n", err)
	}

	dbQueries := database.New(db)

	serveMux := http.NewServeMux()
	server := http.Server{
		Addr:    ":8080",
		Handler: middleware.NewRequestLogger(serveMux),
	}

	fmt.Print("starting server...\n")
	authService, err := auth.NewAuthService(auth.Config{
		SigningKey: []byte(key),
		BcryptCost: 10,
	})
	if err != nil {
		fmt.Println(color.RedString("error creating auth service: %v", err))
	}

	app := App{
		DB:         dbQueries,
		Enviroment: platform,
		Auth:       *authService,
		signingKey: key,
		polkaKey:   polkaAPIKey,
	}

	handler, err := handler.NewHandlerService()
	if err != nil {
		fmt.Println(color.RedString("error creating handler service: %v", err))
	}

	serveMux.HandleFunc("GET /api/healthz", healthHandler)
	serveMux.HandleFunc("GET /api/chirps", app.getChirpsHandler)
	serveMux.HandleFunc("GET /api/chirps/{chirpID}", app.getChirpHandler)
	serveMux.HandleFunc("DELETE /api/chirps/{chirpID}", app.deleteChirpHandler)
	serveMux.HandleFunc("POST /api/chirps", app.createChirpHandler)
	serveMux.HandleFunc("POST /api/login", app.loginHandler)
	serveMux.HandleFunc("POST /api/polka/webhooks", app.webhooksHandler)
	serveMux.HandleFunc("POST /api/refresh", app.refreshHandler)
	serveMux.HandleFunc("POST /api/revoke", app.revokeHandler)
	serveMux.HandleFunc("POST /api/users", app.userHandler)
	serveMux.HandleFunc("PUT /api/users", app.updateUserHandler)

	serveMux.HandleFunc("GET /admin/metrics", app.metricsHandler)
	serveMux.HandleFunc("POST /admin/reset", app.resetHandler)

	// fileServerHandler := http.StripPrefix("/app/", http.FileServer(http.Dir(".")))
	// serveMux.Handle("/app/", middleware.middlewareMetricsInc(fileServerHandler))

	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("error during serve: %v\n", err)
	}

}

func (app *App) metricsHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	template := fmt.Sprintf(`<html>
    <body>
      <h1>Welcome, Chirpy Admin</h1>
      <p>Chirpy has been visited %d times!</p>
    </body>
  </html>`, app.Metrics.Hits.Load())

	w.Write([]byte(template))
}

func healthHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}
