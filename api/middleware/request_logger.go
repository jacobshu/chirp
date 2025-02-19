package middleware

import (
	"fmt"
	"net/http"
	"time"

	"github.com/fatih/color"
)

type RequestLogger struct {
	handler http.Handler
}

func (l *RequestLogger) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	l.handler.ServeHTTP(w, r)
	fmt.Println(color.MagentaString("%s %s %v", r.Method, r.URL.String(), time.Since(start)))
}

func NewRequestLogger(handlerToWrap http.Handler) *RequestLogger {
	return &RequestLogger{handlerToWrap}
}
