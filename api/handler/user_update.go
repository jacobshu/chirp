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

func (s *Service) UpdateUserHandler(app *core.App, w http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		fmt.Println(color.RedString("error getting params: %v", err))
		s.respond(w, http.StatusInternalServerError, ErrorResponse{Error: "something went wrong"})
	}

	userID, err := app.Auth.Authorize(req.Header)
	if err != nil {
		s.respond(w, http.StatusUnauthorized, nil)
	}

	hash, err := app.Auth.HashPassword(params.Password)
	if err != nil {
		fmt.Println(color.RedString("error hashing password: %v", err))
		s.respond(w, http.StatusInternalServerError, ErrorResponse{Error: "something went wrong"})
		return
	}

	err = app.DB.UpdateUser(req.Context(), database.UpdateUserParams{
		ID:             userID,
		Email:          params.Email,
		HashedPassword: hash,
	})

	if err != nil {
		fmt.Println(color.RedString("error updating user: %v", err))
		s.respond(w, http.StatusInternalServerError, ErrorResponse{Error: "something went wrong"})
		return
	}

	s.respond(w, http.StatusOK, types.User{
		Email: params.Email,
	})
}
