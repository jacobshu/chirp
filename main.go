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
	"github.com/jacobshu/chirp/internal/auth"
	"github.com/jacobshu/chirp/internal/database"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
	auth           auth.Service
	signingKey     string
	polkaKey       string
}

type User struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	IsChirpyRed  bool      `json:"is_chirpy_red"`
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
		Handler: NewRequestLogger(serveMux),
	}

	fmt.Print("starting server...\n")
	authService, err := auth.NewAuthService(auth.Config{
		SigningKey: []byte(key),
		BcryptCost: 10,
	})
	if err != nil {
		fmt.Printf("error creating auth service: %v\n", err)
	}

	apiCfg := apiConfig{
		db:         dbQueries,
		platform:   platform,
		auth:       *authService,
		signingKey: key,
		polkaKey:   polkaAPIKey,
	}

	serveMux.HandleFunc("GET /api/healthz", healthHandler)
	serveMux.HandleFunc("GET /api/chirps", apiCfg.getChirpsHandler)
	serveMux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirpHandler)
	serveMux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.deleteChirpHandler)
	serveMux.HandleFunc("POST /api/chirps", apiCfg.createChirpHandler)
	serveMux.HandleFunc("POST /api/login", apiCfg.loginHandler)
	serveMux.HandleFunc("POST /api/polka/webhooks", apiCfg.webhooksHandler)
	serveMux.HandleFunc("POST /api/refresh", apiCfg.refreshHandler)
	serveMux.HandleFunc("POST /api/revoke", apiCfg.revokeHandler)
	serveMux.HandleFunc("POST /api/users", apiCfg.userHandler)
	serveMux.HandleFunc("PUT /api/users", apiCfg.updateUserHandler)

	serveMux.HandleFunc("GET /admin/metrics", apiCfg.metricsHandler)
	serveMux.HandleFunc("POST /admin/reset", apiCfg.resetHandler)

	fileServerHandler := http.StripPrefix("/app/", http.FileServer(http.Dir(".")))
	serveMux.Handle("/app/", apiCfg.middlewareMetricsInc(fileServerHandler))

	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("error during serve: %v\n", err)
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
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		fmt.Printf("error during param decode: %v\n", err)
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	hashedPass, err := cfg.auth.HashPassword(params.Password)
	if err != nil {
		fmt.Printf("userHandler: error hashing user password: %v\n", err)
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	user, err := cfg.db.CreateUser(req.Context(), database.CreateUserParams{
		Email:          params.Email,
		HashedPassword: hashedPass,
	})
	if err != nil {
		fmt.Printf("error during query: %v\n", err)
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	respondWithJSON(w, http.StatusCreated, User{
		ID:          user.ID,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed,
	})
}

func (cfg *apiConfig) updateUserHandler(w http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		fmt.Println(color.RedString("error getting params: %v", err))
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
	}

	userID, err := cfg.auth.Authorize(req.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "")
	}

	hash, err := cfg.auth.HashPassword(params.Password)
	if err != nil {
		fmt.Println(color.RedString("error hashing password: %v", err))
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	err = cfg.db.UpdateUser(req.Context(), database.UpdateUserParams{
		ID:             userID,
		Email:          params.Email,
		HashedPassword: hash,
	})

	if err != nil {
		fmt.Println(color.RedString("error updating user: %v", err))
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	respondWithJSON(w, http.StatusOK, User{
		Email: params.Email,
	})
}

func (cfg *apiConfig) loginHandler(w http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		fmt.Printf("loginHandler: error decoding parameters: %v\n", err)
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	dbUser, err := cfg.db.GetUserByEmail(req.Context(), params.Email)
	if err != nil {
		fmt.Printf("loginHandler: error querying user: %v\n", err)
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}

	err = cfg.auth.CheckPasswordHash(params.Password, dbUser.HashedPassword)
	if err != nil {
		fmt.Printf("loginHandler: error verifying password hash: %v\n", err)
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
	} else {
		expiry := time.Second * time.Duration(60*60)

		token, err := cfg.auth.MakeJWT(dbUser.ID, expiry)
		if err != nil {
			fmt.Printf("loginHandler: error creating JWT: %v\n", err)
			respondWithError(w, http.StatusInternalServerError, "something went wrong")
		}

		refresh_token, err := cfg.auth.MakeRefreshToken()
		cfg.db.CreateRefreshToken(req.Context(), database.CreateRefreshTokenParams{
			Token:     refresh_token,
			UserID:    dbUser.ID,
			ExpiresAt: time.Now().Add(time.Duration(24*60) * time.Hour),
		})
		if err != nil {
			fmt.Printf("loginHandler: error creating refresh token: %v\n", err)
			respondWithError(w, http.StatusInternalServerError, "something went wrong")
		}

		respondWithJSON(w, http.StatusOK, User{
			ID:           dbUser.ID,
			CreatedAt:    dbUser.CreatedAt,
			UpdatedAt:    dbUser.UpdatedAt,
			Email:        dbUser.Email,
			IsChirpyRed:  dbUser.IsChirpyRed,
			Token:        token,
			RefreshToken: refresh_token,
		})
	}
}

func (cfg *apiConfig) refreshHandler(w http.ResponseWriter, req *http.Request) {
	token, err := cfg.auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
	}

	rt, err := cfg.db.GetRefreshToken(req.Context(), token)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Println(color.YellowString("token not in db"))
			respondWithError(w, http.StatusUnauthorized, "")
			return
		}
		fmt.Printf("error querying refresh token: %v", err)
		return
	}

	if time.Now().After(rt.ExpiresAt) {
		fmt.Println(color.YellowString("token expired"))
		respondWithError(w, http.StatusUnauthorized, "")
		return
	}

	type responseToken struct {
		Token string `json:"token"`
	}

	exp := time.Second * time.Duration(60*60)
	t, err := cfg.auth.MakeJWT(rt.UserID, exp)
	if err != nil {
		fmt.Printf("error creating refresh JWT response: %v", err)
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
	}
	respondWithJSON(w, http.StatusOK, responseToken{Token: t})
}

func (cfg *apiConfig) revokeHandler(w http.ResponseWriter, req *http.Request) {
	token, err := cfg.auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
	}

	err = cfg.db.RevokeRefreshToken(req.Context(), token)
	if err != nil {
		fmt.Printf("revokeHandler: error revoking token: %v", err)
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) webhooksHandler(w http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Event string `json:"event"`
		Data  struct {
			UserID string `json:"user_id"`
		} `json:"data"`
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		fmt.Println(color.RedString("error parsing body: %v", err))
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	headerKey, err := cfg.auth.GetAPIKey(req.Header)
	if err != nil {
		fmt.Println(color.RedString("error getting API key from headers: %v", err))
		respondWithError(w, http.StatusUnauthorized, "")
		return
	}

	if headerKey != cfg.polkaKey {
		respondWithError(w, http.StatusUnauthorized, "")
		return
	}

	if params.Event != "user.upgraded" {
		respondWithError(w, http.StatusNoContent, "")
		return
	} else {
		userID, err := uuid.Parse(params.Data.UserID)
		if err != nil {
			fmt.Println(color.RedString("error parsing user ID: %v", err))
		}

		_, err = cfg.db.UpgradeToChirpyRed(req.Context(), userID)
		if err != nil {
			fmt.Println(color.RedString("error upgrading to chirpy red: %v", err))
			respondWithError(w, http.StatusNotFound, "")
			return
		}
		respondWithJSON(w, http.StatusNoContent, "")
	}
}

func (cfg *apiConfig) createChirpHandler(w http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Body string `json:"body"`
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		fmt.Printf("error during param decode: %v\n", err)
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	userID, err := cfg.auth.Authorize(req.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "")
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

		dbChirp, err := cfg.db.CreateChirp(req.Context(), database.CreateChirpParams{
			Body:   clean,
			UserID: userID,
		})
		if err != nil {
			fmt.Printf("createChirpHandler: error inserting new chirp: %v\n", err)
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

func (cfg *apiConfig) deleteChirpHandler(w http.ResponseWriter, req *http.Request) {
	chirpID, err := uuid.Parse(req.PathValue("chirpID"))
	if err != nil {
		fmt.Printf("deleteChirpHandler: error parsing chirp from endpoint: %v\n", err)
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	userID, err := cfg.auth.Authorize(req.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "")
		return
	}

	dbChirp, err := cfg.db.GetChirp(req.Context(), chirpID)
	if err != nil {
		fmt.Println(color.RedString("deleteChirpHandler: error querying for chirp: %v\n", err))
		respondWithError(w, http.StatusNotFound, "chirp not found")
		return
	}

	if dbChirp.UserID != userID {
		respondWithError(w, http.StatusForbidden, "")
		return
	}

	err = cfg.db.DeleteChirp(req.Context(), chirpID)
	if err != nil {
		fmt.Println(color.RedString("error deleting chirp: %v", err))
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	respondWithJSON(w, http.StatusNoContent, "")
}

func (cfg *apiConfig) getChirpsHandler(w http.ResponseWriter, req *http.Request) {
	aid := req.URL.Query().Get("author_id")
	fmt.Println(color.YellowString(aid))

	dbChirps, err := cfg.db.GetAllChirps(req.Context())
	if err != nil {
		fmt.Printf("getChirpsHandler: error querying for chirps: %v\n", err)
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

func (cfg *apiConfig) getChirpHandler(w http.ResponseWriter, req *http.Request) {
	chirpID, err := uuid.Parse(req.PathValue("chirpID"))
	if err != nil {
		fmt.Printf("getChirpHandler: error parsing chirp from endpoint: %v\n", err)
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	dbChirp, err := cfg.db.GetChirp(req.Context(), chirpID)
	if err != nil {
		fmt.Println(color.RedString("getChirpHandler: error querying for chirp: %v", err))
		respondWithError(w, http.StatusNotFound, "chirp not found")
		return
	}

	respondWithJSON(w, http.StatusOK, Chirp{
		ID:        dbChirp.ID,
		CreatedAt: dbChirp.CreatedAt,
		UpdatedAt: dbChirp.UpdatedAt,
		Body:      dbChirp.Body,
		UserID:    dbChirp.UserID,
	})
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	type errorResp struct {
		Error string `json:"error"`
	}

	errorBody := errorResp{
		Error: msg,
	}

	w.WriteHeader(code)
	if msg != "" {
		w.Header().Add("Content-Type", "application/json")
		errMsg, err := json.Marshal(errorBody)
		if err != nil {
			fmt.Printf("error during respondWithError: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("something went wrong"))
			return
		}
		w.Write(errMsg)
	}
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

type RequestLogger struct {
	handler http.Handler
}

func (l *RequestLogger) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	l.handler.ServeHTTP(w, r)
	fmt.Println(color.MagentaString("%s %s %v", r.Method, r.URL.String(), time.Since(start)))
}

func NewRequestLogger(handlerToWrap http.Handler) *RequestLogger {
	return &RequestLogger{handlerToWrap}
}
