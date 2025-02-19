package handler

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/fatih/color"
	"github.com/jacobshu/chirp/internal/core"
	"github.com/jacobshu/chirp/internal/database"
	"github.com/jacobshu/chirp/internal/types"
)

func (s *Service) UserHandler(app *core.App, w http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		fmt.Println(color.RedString("error during param decode: %v", err))
		s.respondInternalServerError(w)
		return
	}

	hashedPass, err := app.Auth.HashPassword(params.Password)
	if err != nil {
		fmt.Println(color.RedString("userHandler: error hashing user password: %v", err))
		s.respondInternalServerError(w)
		return
	}

	user, err := app.DB.CreateUser(req.Context(), database.CreateUserParams{
		Email:          params.Email,
		HashedPassword: hashedPass,
	})
	if err != nil {
		fmt.Println(color.RedString("error during query: %v", err))
		s.respondInternalServerError(w)
		return
	}

	s.respond(w, http.StatusCreated, types.User{
		ID:          user.ID,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed,
	})
}
