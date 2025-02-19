package handler

import (
	"fmt"
	"net/http"
	"sort"

	"github.com/fatih/color"
	"github.com/google/uuid"
	"github.com/jacobshu/chirp/internal/core"
	"github.com/jacobshu/chirp/internal/database"
	"github.com/jacobshu/chirp/internal/types"
)

func (s *Service) GetChirpHandler(app *core.App, w http.ResponseWriter, req *http.Request) {
	chirpID, err := uuid.Parse(req.PathValue("chirpID"))
	if err != nil {
		fmt.Printf("getChirpHandler: error parsing chirp from endpoint: %v\n", err)
		s.respondInternalServerError(w)
		return
	}

	dbChirp, err := app.DB.GetChirp(req.Context(), chirpID)
	if err != nil {
		fmt.Println(color.RedString("getChirpHandler: error querying for chirp: %v", err))
		s.respond(w, http.StatusNotFound, ErrorResponse{Error: "chirp not found"})
		return
	}

	s.respond(w, http.StatusOK, types.Chirp{
		ID:        dbChirp.ID,
		CreatedAt: dbChirp.CreatedAt,
		UpdatedAt: dbChirp.UpdatedAt,
		Body:      dbChirp.Body,
		UserID:    dbChirp.UserID,
	})
}

func (s *Service) GetChirpsHandler(app *core.App, w http.ResponseWriter, req *http.Request) {
	aid := req.URL.Query().Get("author_id")
	sortDir := req.URL.Query().Get("sort")
	fmt.Println(color.YellowString("author_id ? %s", aid))
	fmt.Println(color.YellowString("sort ? %s", sortDir))

	var dbChirps []database.Chirp
	if aid != "" {
		userID, err := uuid.Parse(aid)
		if err != nil {
			fmt.Println(color.RedString("invalid author_id parameter: %v", aid))
			dbChirps, err = app.DB.GetAllChirps(req.Context())
			if err != nil {
				fmt.Printf("getChirpsHandler: error querying for chirps: %v\n", err)
				s.respondInternalServerError(w)
				return
			}
		} else {
			dbChirps, err = app.DB.GetChirpsByUserID(req.Context(), userID)
		}
	} else {
		dbc, err := app.DB.GetAllChirps(req.Context())
		if err != nil {
			fmt.Printf("getChirpsHandler: error querying for chirps: %v\n", err)
			s.respondInternalServerError(w)
			return
		}
		dbChirps = dbc
	}

	chirps := []types.Chirp{}
	for _, c := range dbChirps {
		chirps = append(chirps, types.Chirp{
			ID:        c.ID,
			CreatedAt: c.CreatedAt,
			UpdatedAt: c.UpdatedAt,
			Body:      c.Body,
			UserID:    c.UserID,
		})
	}

	if sortDir == "desc" {
		sort.Slice(chirps, func(i, j int) bool { return chirps[i].CreatedAt.After(chirps[j].CreatedAt) })
	}
	s.respond(w, http.StatusOK, chirps)
}
