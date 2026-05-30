package httpserver

import (
	"log/slog"
	"net/http"
	"time"

	"litewaf-api/internal/app"
	"litewaf-api/internal/config"
)

func New(cfg config.Config, logger *slog.Logger, application *app.App) *http.Server {
	mux := http.NewServeMux()
	registerRoutes(mux, logger, application)

	return &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           recoverer(logger, requestLogger(logger, mux)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}
