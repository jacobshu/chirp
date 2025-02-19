package middleware

import (
	"net/http"

	"github.com/jacobshu/chirp/internal/app"
)

func (app *App) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		app.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}
