package handler

import (
	"fmt"
	"net/http"

	"github.com/fatih/color"
	"github.com/jacobshu/chirp/internal/core"
)

func (s *Service) RevokeHandler(app *core.App, w http.ResponseWriter, req *http.Request) {
	token, err := app.Auth.GetBearerToken(req.Header)
	if err != nil {
		s.respondInternalServerError(w)
	}

	err = app.DB.RevokeRefreshToken(req.Context(), token)
	if err != nil {
		fmt.Println(color.RedString("error revoking token: %v", err))
		s.respondInternalServerError(w)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
