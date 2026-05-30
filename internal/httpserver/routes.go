package httpserver

import (
	"log/slog"
	"net/http"

	"litewaf-api/internal/app"
)

func registerRoutes(mux *http.ServeMux, logger *slog.Logger, application *app.App) {
	handlers := newHandlers(logger, application)

	mux.HandleFunc("GET /healthz", handlers.healthz)
	mux.HandleFunc("GET /api/v1/version", handlers.version)

	mux.HandleFunc("GET /api/v1/sites", handlers.listSites)
	mux.HandleFunc("POST /api/v1/sites", handlers.createSite)
	mux.HandleFunc("GET /api/v1/sites/{id}", handlers.getSite)
	mux.HandleFunc("PUT /api/v1/sites/{id}", handlers.updateSite)
	mux.HandleFunc("DELETE /api/v1/sites/{id}", handlers.deleteSite)

	mux.HandleFunc("GET /api/v1/rules", handlers.listRules)
	mux.HandleFunc("POST /api/v1/rules", handlers.createRule)
	mux.HandleFunc("GET /api/v1/rules/{id}", handlers.getRule)
	mux.HandleFunc("PUT /api/v1/rules/{id}", handlers.updateRule)
	mux.HandleFunc("DELETE /api/v1/rules/{id}", handlers.deleteRule)

	mux.HandleFunc("GET /api/v1/policies", handlers.listPolicies)
	mux.HandleFunc("POST /api/v1/policies", handlers.createPolicy)
	mux.HandleFunc("GET /api/v1/policies/{id}", handlers.getPolicy)
	mux.HandleFunc("PUT /api/v1/policies/{id}", handlers.updatePolicy)
	mux.HandleFunc("DELETE /api/v1/policies/{id}", handlers.deletePolicy)

	mux.HandleFunc("GET /api/v1/attack-logs", handlers.listAttackLogs)
	mux.HandleFunc("GET /api/v1/releases", handlers.listReleases)
	mux.HandleFunc("POST /api/v1/releases", handlers.createRelease)
}
