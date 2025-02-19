package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/fatih/color"
	"github.com/jacobshu/chirp/internal/core"
	"github.com/jacobshu/chirp/internal/database"
	"github.com/jacobshu/chirp/internal/types"
)

func (s *Service) createChirpHandler(app *core.App, w http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Body string `json:"body"`
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		fmt.Println(color.RedString("error during param decode: %v\n", err))
		s.respondInternalServerError(w)
		return
	}

	userID, err := app.Auth.Authorize(req.Header)
	if err != nil {
		s.respond(w, http.StatusUnauthorized, "")
	}

	if len(params.Body) > 140 {
		s.respond(w, http.StatusBadRequest, "Chirp is too long")
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

		dbChirp, err := app.DB.CreateChirp(req.Context(), database.CreateChirpParams{
			Body:   clean,
			UserID: userID,
		})
		if err != nil {
			fmt.Printf("createChirpHandler: error inserting new chirp: %v\n", err)
			s.respondInternalServerError(w)
			return
		}

		s.respond(w, http.StatusCreated, types.Chirp{
			ID:        dbChirp.ID,
			CreatedAt: dbChirp.CreatedAt,
			UpdatedAt: dbChirp.UpdatedAt,
			Body:      clean,
			UserID:    dbChirp.UserID,
		})
	}
}
