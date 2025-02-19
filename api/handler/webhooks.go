package handler

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/fatih/color"
	"github.com/google/uuid"
	"github.com/jacobshu/chirp/internal/core"
)

func (s *Service) webhooksHandler(app *core.App, w http.ResponseWriter, req *http.Request) {
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
		s.respondInternalServerError(w)
		return
	}

	headerKey, err := app.Auth.GetAPIKey(req.Header)
	if err != nil {
		fmt.Println(color.RedString("error getting API key from headers: %v", err))
		s.respond(w, http.StatusUnauthorized, nil)
		return
	}

	if headerKey != app.PolkaKey {
		s.respond(w, http.StatusUnauthorized, nil)
		return
	}

	if params.Event != "user.upgraded" {
		s.respond(w, http.StatusNoContent, nil)
		return
	} else {
		userID, err := uuid.Parse(params.Data.UserID)
		if err != nil {
			fmt.Println(color.RedString("error parsing user ID: %v", err))
		}

		_, err = app.DB.UpgradeToChirpyRed(req.Context(), userID)
		if err != nil {
			fmt.Println(color.RedString("error upgrading to chirpy red: %v", err))
			s.respond(w, http.StatusNotFound, nil)
			return
		}
		s.respond(w, http.StatusNoContent, nil)
	}
}
