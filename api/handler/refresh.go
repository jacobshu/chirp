package handler

import (
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/fatih/color"
	"github.com/jacobshu/chirp/internal/core"
)

func (s *Service) RefreshHandler(app *core.App, w http.ResponseWriter, req *http.Request) {
	token, err := app.Auth.GetBearerToken(req.Header)
	if err != nil {
		s.respondInternalServerError(w)
	}

	rt, err := app.DB.GetRefreshToken(req.Context(), token)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Println(color.YellowString("token not in db"))
			s.respond(w, http.StatusUnauthorized, nil)
			return
		}
		fmt.Println(color.RedString("error querying refresh token: %v", err))
		return
	}

	if time.Now().After(rt.ExpiresAt) {
		fmt.Println(color.YellowString("token expired"))
		s.respond(w, http.StatusUnauthorized, nil)
		return
	}

	type responseToken struct {
		Token string `json:"token"`
	}

	exp := time.Second * time.Duration(60*60)
	t, err := app.Auth.MakeJWT(rt.UserID, exp)
	if err != nil {
		fmt.Println(color.RedString("error creating refresh JWT response: %v", err))
		s.respondInternalServerError(w)
	}
	s.respond(w, http.StatusOK, responseToken{Token: t})
}
