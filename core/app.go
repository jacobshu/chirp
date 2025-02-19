package core

import (
	"sync/atomic"
)

type App struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
	auth           auth.Service
	signingKey     string
	polkaKey       string
}
