package handler

import (
	"net/http"
)

func (app *App) resetHandler(w http.ResponseWriter, req *http.Request) {
	app.fileserverHits = atomic.Int32{}
	if app.platform != "dev" {
		respondWithError(w, http.StatusForbidden, "Forbidden")
		return
	} else {
		app.db.Reset(req.Context())
	}
}
