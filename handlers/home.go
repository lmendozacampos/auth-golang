package handlers

import (
	"encoding/json"
	"net/http"

	"example.com/auth/server"
)

// Estructura de la respuesta
type HomeResponse struct {
	Message string `json:"message"`
	Status  bool   `json:"status"`
}

// Devuelve la respuesta al Cliente con un codigo de estado y un mensaje
func HomeHandler(s server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(HomeResponse{
			Message: "Welcome to Lumen Labs",
			Status:  true,
		})
	}
}
