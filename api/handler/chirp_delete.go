package handler

import (
	"fmt"
	"net/http"

	"github.com/fatih/color"
	"github.com/google/uuid"
	"github.com/jacobshu/chirp/internal/core"
)

func (s *Service) DeleteChirpHandler(app *core.App, w http.ResponseWriter, req *http.Request) {
	chirpID, err := uuid.Parse(req.PathValue("chirpID"))
	if err != nil {
		fmt.Println(color.RedString("deleteChirpHandler: error parsing chirp from endpoint: %v", err))
		s.respondInternalServerError(w)
		return
	}

	userID, err := app.Auth.Authorize(req.Header)
	if err != nil {
		s.respond(w, http.StatusUnauthorized, nil)
		return
	}

	dbChirp, err := app.DB.GetChirp(req.Context(), chirpID)
	if err != nil {
		fmt.Println(color.RedString("deleteChirpHandler: error querying for chirp: %v", err))
		s.respond(w, http.StatusNotFound, ErrorResponse{Error: "chirp not found"})
		return
	}

	if dbChirp.UserID != userID {
		s.respond(w, http.StatusForbidden, nil)
		return
	}

	err = app.DB.DeleteChirp(req.Context(), chirpID)
	if err != nil {
		fmt.Println(color.RedString("error deleting chirp: %v", err))
		s.respondInternalServerError(w)
		return
	}

	s.respond(w, http.StatusNoContent, nil)
}
