package core

import (
	"sync/atomic"

	"github.com/jacobshu/chirp/internal/auth"
	"github.com/jacobshu/chirp/internal/database"
)

type Metrics struct {
	Hits atomic.Int32
}

type App struct {
	Metrics     Metrics
	DB          *database.Queries
	Environment string
	Auth        auth.Service
	signingKey  string
	PolkaKey    string
}
