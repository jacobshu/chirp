package handler

import (
	"net/http"
	"sync/atomic"

	"github.com/jacobshu/chirp/internal/core"
)

func (s *Service) ResetHandler(app *core.App, w http.ResponseWriter, req *http.Request) {
	app.Metrics.Hits = atomic.Int32{}
	if app.Environment != "dev" {
		s.respond(w, http.StatusForbidden, nil)
		return
	} else {
		app.DB.Reset(req.Context())
	}
}
