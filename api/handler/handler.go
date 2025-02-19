package handler

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/fatih/color"
)

type Config struct {
	SigningKey []byte
}

type Service struct {
	config Config
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func NewHandlerService() (*Service, error) {
	return &Service{}, nil
}

func (s *Service) respondWithError(w http.ResponseWriter, code int, msg string) {
	type errorResp struct {
		Error string `json:"error"`
	}

	errorBody := errorResp{
		Error: msg,
	}

	w.WriteHeader(code)
	if msg != "" {
		w.Header().Add("Content-Type", "application/json")
		errMsg, err := json.Marshal(errorBody)
		if err != nil {
			fmt.Printf("error during respondWithError: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("something went wrong"))
			return
		}
		w.Write(errMsg)
	}
}

func (s *Service) respondInternalServerError(w http.ResponseWriter) {
	s.respond(w, http.StatusInternalServerError, nil)
}

func (s *Service) respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Add("Content-Type", "application/json")

	data, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("error during respondWithJSON: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("something went wrong"))
		return
	}

	w.WriteHeader(code)
	w.Write(data)
}

func (s *Service) respond(w http.ResponseWriter, code int, payload interface{}) {
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			fmt.Printf(color.RedString("error serializing data for response: %v", err))
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("something went wrong"))
			return
		}
		w.WriteHeader(code)
		w.Write(data)
		return
	}

	w.WriteHeader(code)
}
