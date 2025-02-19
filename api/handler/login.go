package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/fatih/color"
	"github.com/jacobshu/chirp/internal/core"
	"github.com/jacobshu/chirp/internal/database"
	"github.com/jacobshu/chirp/internal/types"
)

func (s *Service) LoginHandler(app *core.App, w http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		fmt.Println(color.RedString("error decoding parameters: %v", err))
		s.respondInternalServerError(w)
		return
	}

	dbUser, err := app.DB.GetUserByEmail(req.Context(), params.Email)
	if err != nil {
		fmt.Println(color.RedString("error querying user: %v", err))
		s.respond(w, http.StatusUnauthorized, ErrorResponse{Error: "incorrect email or password"})
		return
	}

	err = app.Auth.CheckPasswordHash(params.Password, dbUser.HashedPassword)
	if err != nil {
		fmt.Println(color.RedString("error verifying password hash: %v", err))
		s.respond(w, http.StatusUnauthorized, ErrorResponse{Error: "incorrect email or password"})
	} else {
		expiry := time.Second * time.Duration(60*60)

		token, err := app.Auth.MakeJWT(dbUser.ID, expiry)
		if err != nil {
			fmt.Println(color.RedString("error creating JWT: %v", err))
			s.respondInternalServerError(w)
		}

		refresh_token, err := app.Auth.MakeRefreshToken()
		app.DB.CreateRefreshToken(req.Context(), database.CreateRefreshTokenParams{
			Token:     refresh_token,
			UserID:    dbUser.ID,
			ExpiresAt: time.Now().Add(time.Duration(24*60) * time.Hour),
		})
		if err != nil {
			fmt.Println(color.RedString("error creating refresh token: %v", err))
			s.respondInternalServerError(w)
		}

		s.respond(w, http.StatusOK, types.User{
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
