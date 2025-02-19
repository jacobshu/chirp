package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"github.com/google/uuid"
	"github.com/jacobshu/chirp/api/middleware"
	"github.com/jacobshu/chirp/internal/auth"
	"github.com/jacobshu/chirp/internal/database"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type App struct {
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
		Handler: middleware.NewRequestLogger(serveMux),
	}

	fmt.Print("starting server...\n")
	authService, err := auth.NewAuthService(auth.Config{
		SigningKey: []byte(key),
		BcryptCost: 10,
	})
	if err != nil {
		fmt.Printf("error creating auth service: %v\n", err)
	}

	app := App{
		db:         dbQueries,
		platform:   platform,
		auth:       *authService,
		signingKey: key,
		polkaKey:   polkaAPIKey,
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
  </html>`, app.fileserverHits.Load())

	w.Write([]byte(template))
}

func (app *App) resetHandler(w http.ResponseWriter, req *http.Request) {
	app.fileserverHits = atomic.Int32{}
	if app.platform != "dev" {
		respondWithError(w, http.StatusForbidden, "Forbidden")
		return
	} else {
		app.db.Reset(req.Context())
	}
}

func healthHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (app *App) userHandler(w http.ResponseWriter, req *http.Request) {
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

	hashedPass, err := app.auth.HashPassword(params.Password)
	if err != nil {
		fmt.Printf("userHandler: error hashing user password: %v\n", err)
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	user, err := app.db.CreateUser(req.Context(), database.CreateUserParams{
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

func (app *App) updateUserHandler(w http.ResponseWriter, req *http.Request) {
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

	userID, err := app.auth.Authorize(req.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "")
	}

	hash, err := app.auth.HashPassword(params.Password)
	if err != nil {
		fmt.Println(color.RedString("error hashing password: %v", err))
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	err = app.db.UpdateUser(req.Context(), database.UpdateUserParams{
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

func (app *App) loginHandler(w http.ResponseWriter, req *http.Request) {
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

	dbUser, err := app.db.GetUserByEmail(req.Context(), params.Email)
	if err != nil {
		fmt.Printf("loginHandler: error querying user: %v\n", err)
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}

	err = app.auth.CheckPasswordHash(params.Password, dbUser.HashedPassword)
	if err != nil {
		fmt.Printf("loginHandler: error verifying password hash: %v\n", err)
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
	} else {
		expiry := time.Second * time.Duration(60*60)

		token, err := app.auth.MakeJWT(dbUser.ID, expiry)
		if err != nil {
			fmt.Printf("loginHandler: error creating JWT: %v\n", err)
			respondWithError(w, http.StatusInternalServerError, "something went wrong")
		}

		refresh_token, err := app.auth.MakeRefreshToken()
		app.db.CreateRefreshToken(req.Context(), database.CreateRefreshTokenParams{
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

func (app *App) refreshHandler(w http.ResponseWriter, req *http.Request) {
	token, err := app.auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
	}

	rt, err := app.db.GetRefreshToken(req.Context(), token)
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
	t, err := app.auth.MakeJWT(rt.UserID, exp)
	if err != nil {
		fmt.Printf("error creating refresh JWT response: %v", err)
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
	}
	respondWithJSON(w, http.StatusOK, responseToken{Token: t})
}

func (app *App) revokeHandler(w http.ResponseWriter, req *http.Request) {
	token, err := app.auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
	}

	err = app.db.RevokeRefreshToken(req.Context(), token)
	if err != nil {
		fmt.Printf("revokeHandler: error revoking token: %v", err)
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (app *App) webhooksHandler(w http.ResponseWriter, req *http.Request) {
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

	headerKey, err := app.auth.GetAPIKey(req.Header)
	if err != nil {
		fmt.Println(color.RedString("error getting API key from headers: %v", err))
		respondWithError(w, http.StatusUnauthorized, "")
		return
	}

	if headerKey != app.polkaKey {
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

		_, err = app.db.UpgradeToChirpyRed(req.Context(), userID)
		if err != nil {
			fmt.Println(color.RedString("error upgrading to chirpy red: %v", err))
			respondWithError(w, http.StatusNotFound, "")
			return
		}
		respondWithJSON(w, http.StatusNoContent, "")
	}
}

func (app *App) createChirpHandler(w http.ResponseWriter, req *http.Request) {
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

	userID, err := app.auth.Authorize(req.Header)
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

		dbChirp, err := app.db.CreateChirp(req.Context(), database.CreateChirpParams{
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

func (app *App) deleteChirpHandler(w http.ResponseWriter, req *http.Request) {
	chirpID, err := uuid.Parse(req.PathValue("chirpID"))
	if err != nil {
		fmt.Printf("deleteChirpHandler: error parsing chirp from endpoint: %v\n", err)
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	userID, err := app.auth.Authorize(req.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "")
		return
	}

	dbChirp, err := app.db.GetChirp(req.Context(), chirpID)
	if err != nil {
		fmt.Println(color.RedString("deleteChirpHandler: error querying for chirp: %v\n", err))
		respondWithError(w, http.StatusNotFound, "chirp not found")
		return
	}

	if dbChirp.UserID != userID {
		respondWithError(w, http.StatusForbidden, "")
		return
	}

	err = app.db.DeleteChirp(req.Context(), chirpID)
	if err != nil {
		fmt.Println(color.RedString("error deleting chirp: %v", err))
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	respondWithJSON(w, http.StatusNoContent, "")
}

func (app *App) getChirpsHandler(w http.ResponseWriter, req *http.Request) {
	aid := req.URL.Query().Get("author_id")
	sortDir := req.URL.Query().Get("sort")
	fmt.Println(color.YellowString("author_id ? %s", aid))
	fmt.Println(color.YellowString("sort ? %s", sortDir))

	var dbChirps []database.Chirp
	if aid != "" {
		userID, err := uuid.Parse(aid)
		if err != nil {
			fmt.Println(color.RedString("invalid author_id parameter: %v", aid))
			dbChirps, err = app.db.GetAllChirps(req.Context())
			if err != nil {
				fmt.Printf("getChirpsHandler: error querying for chirps: %v\n", err)
				respondWithError(w, http.StatusInternalServerError, "something went wrong")
				return
			}
		} else {
			dbChirps, err = app.db.GetChirpsByUserID(req.Context(), userID)
		}
	} else {
		dbc, err := app.db.GetAllChirps(req.Context())
		if err != nil {
			fmt.Printf("getChirpsHandler: error querying for chirps: %v\n", err)
			respondWithError(w, http.StatusInternalServerError, "something went wrong")
			return
		}
		dbChirps = dbc
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

	if sortDir == "desc" {
		sort.Slice(chirps, func(i, j int) bool { return chirps[i].CreatedAt.After(chirps[j].CreatedAt) })
	}
	respondWithJSON(w, http.StatusOK, chirps)
}

func (app *App) getChirpHandler(w http.ResponseWriter, req *http.Request) {
	chirpID, err := uuid.Parse(req.PathValue("chirpID"))
	if err != nil {
		fmt.Printf("getChirpHandler: error parsing chirp from endpoint: %v\n", err)
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	dbChirp, err := app.db.GetChirp(req.Context(), chirpID)
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
