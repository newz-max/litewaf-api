package httpserver

import (
	"encoding/json"
	"net/http"
)

type envelope map[string]any

func writeJSON(w http.ResponseWriter, status int, data envelope) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, envelope{
		"error": envelope{
			"code":    http.StatusText(status),
			"message": message,
		},
	})
}
