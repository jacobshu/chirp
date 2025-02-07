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

	"github.com/google/uuid"
	"github.com/jacobshu/chirp/internal/database"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
}

type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
}

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Printf("error loading postgres: %v", err)
	}

	dbQueries := database.New(db)

	serveMux := http.NewServeMux()
	server := http.Server{
		Addr:    ":8080",
		Handler: serveMux,
	}

	fmt.Print("starting server...\n")
	apiCfg := apiConfig{
		db:       dbQueries,
		platform: platform,
	}

	serveMux.HandleFunc("GET /api/healthz", healthHandler)
	serveMux.HandleFunc("GET /api/chirps", apiCfg.getChirpsHandler)
	serveMux.HandleFunc("POST /api/chirps", apiCfg.createChirpHandler)
	serveMux.HandleFunc("POST /api/users", apiCfg.userHandler)

	serveMux.HandleFunc("GET /admin/metrics", apiCfg.metricsHandler)
	serveMux.HandleFunc("POST /admin/reset", apiCfg.resetHandler)

	fileServerHandler := http.StripPrefix("/app/", http.FileServer(http.Dir(".")))
	serveMux.Handle("/app/", apiCfg.middlewareMetricsInc(fileServerHandler))

	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("error during serve: %v", err)
	}

}

func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	template := fmt.Sprintf(`<html>
    <body>
      <h1>Welcome, Chirpy Admin</h1>
      <p>Chirpy has been visited %d times!</p>
    </body>
  </html>`, cfg.fileserverHits.Load())

	w.Write([]byte(template))
}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, req *http.Request) {
	cfg.fileserverHits = atomic.Int32{}
	if cfg.platform != "dev" {
		respondWithError(w, http.StatusForbidden, "Forbidden")
		return
	} else {
		cfg.db.Reset(req.Context())
	}
}

func healthHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (cfg *apiConfig) userHandler(w http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Email string `json:"email"`
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		fmt.Printf("error during param decode: %v\n", err)
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	user, err := cfg.db.CreateUser(req.Context(), params.Email)
	usrData := User{
		ID:        user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email:     user.Email,
	}

	if err != nil {
		fmt.Printf("error during query: %v\n", err)
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	respondWithJSON(w, http.StatusCreated, usrData)
}

func (cfg *apiConfig) createChirpHandler(w http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Body   string `json:"body"`
		UserID string `json:"user_id"`
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		fmt.Printf("error during param decode: %v\n", err)
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	if len(params.Body) > 140 {
		respondWithError(w, http.StatusBadRequest, "Chirp is too long")
	} else {
		words := strings.Split(params.Body, " ")
		profanity := []string{"kerfuffle", "sharbert", "fornax"}

		var sanitized = []string{}
		for _, word := range words {
			lower := strings.ToLower(word)
			if slices.Contains(profanity, lower) {
				sanitized = append(sanitized, "****")
			} else {
				sanitized = append(sanitized, word)
			}
		}
		clean := strings.Join(sanitized, " ")

		params.Body = clean
		user_id, err := uuid.Parse(params.UserID)
		if err != nil {
			fmt.Printf("createChirpHandler: error in parsing user_id: %v", err)
			respondWithError(w, http.StatusInternalServerError, "something went wrong")
			return
		}

		dbChirp, err := cfg.db.CreateChirp(req.Context(), database.CreateChirpParams{
			Body:   clean,
			UserID: user_id,
		})
		if err != nil {
			fmt.Printf("createChirpHandler: error inserting new chirp: %v", err)
			respondWithError(w, http.StatusInternalServerError, "something went wrong")
			return
		}

		respondWithJSON(w, http.StatusCreated, Chirp{
			ID:        dbChirp.ID,
			CreatedAt: dbChirp.CreatedAt,
			UpdatedAt: dbChirp.UpdatedAt,
			Body:      clean,
			UserID:    dbChirp.UserID,
		})
	}
}

func (cfg *apiConfig) getChirpsHandler(w http.ResponseWriter, req *http.Request) {
	dbChirps, err := cfg.db.GetAllChirps(req.Context())
	if err != nil {
		fmt.Printf("getChirpsHandler: error querying for chirps: %v", err)
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	chirps := []Chirp{}
	for _, c := range dbChirps {
		chirps = append(chirps, Chirp{
			ID:        c.ID,
			CreatedAt: c.CreatedAt,
			UpdatedAt: c.UpdatedAt,
			Body:      c.Body,
			UserID:    c.UserID,
		})
	}

	respondWithJSON(w, http.StatusOK, chirps)
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	type errorResp struct {
		Error string `json:"error"`
	}

	errorBody := errorResp{
		Error: msg,
	}

	w.Header().Add("Content-Type", "application/json")

	errMsg, err := json.Marshal(errorBody)
	if err != nil {
		fmt.Printf("error during respondWithError: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("something went wrong"))
		return
	}

	w.WriteHeader(code)
	w.Write(errMsg)
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Add("Content-Type", "application/json")

	data, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("error during respondWithJSON: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("something went wrong"))
		return
	}

	w.WriteHeader(code)
	w.Write(data)
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}
