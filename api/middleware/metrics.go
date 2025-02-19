package middleware

import (
	"net/http"
)

func (s *Service) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		app.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}
