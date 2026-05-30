package httpserver

import (
	"log/slog"
	"net/http"

	"litewaf-api/internal/app"
)

func registerRoutes(mux *http.ServeMux, logger *slog.Logger, application *app.App) {
	handlers := newHandlers(logger, application)

	mux.HandleFunc("GET /healthz", handlers.healthz)
	mux.HandleFunc("GET /metrics", handlers.metrics)
	mux.HandleFunc("GET /api/v1/version", handlers.version)
	mux.HandleFunc("POST /api/v1/auth/login", handlers.login)

	mux.HandleFunc("GET /api/v1/sites", handlers.require(permissionRead, handlers.listSites))
	mux.HandleFunc("POST /api/v1/sites", handlers.require(permissionWrite, handlers.createSite))
	mux.HandleFunc("GET /api/v1/sites/{id}", handlers.require(permissionRead, handlers.getSite))
	mux.HandleFunc("PUT /api/v1/sites/{id}", handlers.require(permissionWrite, handlers.updateSite))
	mux.HandleFunc("DELETE /api/v1/sites/{id}", handlers.require(permissionWrite, handlers.deleteSite))

	mux.HandleFunc("GET /api/v1/rules", handlers.require(permissionRead, handlers.listRules))
	mux.HandleFunc("POST /api/v1/rules", handlers.require(permissionWrite, handlers.createRule))
	mux.HandleFunc("GET /api/v1/rules/{id}", handlers.require(permissionRead, handlers.getRule))
	mux.HandleFunc("PUT /api/v1/rules/{id}", handlers.require(permissionWrite, handlers.updateRule))
	mux.HandleFunc("DELETE /api/v1/rules/{id}", handlers.require(permissionWrite, handlers.deleteRule))

	mux.HandleFunc("GET /api/v1/policies", handlers.require(permissionRead, handlers.listPolicies))
	mux.HandleFunc("POST /api/v1/policies", handlers.require(permissionWrite, handlers.createPolicy))
	mux.HandleFunc("GET /api/v1/policies/{id}", handlers.require(permissionRead, handlers.getPolicy))
	mux.HandleFunc("PUT /api/v1/policies/{id}", handlers.require(permissionWrite, handlers.updatePolicy))
	mux.HandleFunc("DELETE /api/v1/policies/{id}", handlers.require(permissionWrite, handlers.deletePolicy))

	mux.HandleFunc("POST /api/v1/ingest/access-logs", handlers.requireGatewayIngestion(handlers.ingestAccessLog))
	mux.HandleFunc("POST /api/v1/ingest/waf-events", handlers.requireGatewayIngestion(handlers.ingestWAFEvent))
	mux.HandleFunc("GET /api/v1/access-logs", handlers.require(permissionRead, handlers.listAccessLogs))
	mux.HandleFunc("GET /api/v1/attack-logs", handlers.require(permissionRead, handlers.listAttackLogs))
	mux.HandleFunc("GET /api/v1/observability/summary", handlers.require(permissionRead, handlers.observabilitySummary))
	mux.HandleFunc("GET /api/v1/releases", handlers.require(permissionRead, handlers.listReleases))
	mux.HandleFunc("POST /api/v1/releases", handlers.require(permissionPublish, handlers.createRelease))
	mux.HandleFunc("GET /api/v1/releases/preview", handlers.require(permissionPublish, handlers.previewRelease))
	mux.HandleFunc("POST /api/v1/releases/{version}/rollback", handlers.require(permissionPublish, handlers.rollbackRelease))

	mux.HandleFunc("GET /api/v1/audit-logs", handlers.require(permissionAudit, handlers.listAuditLogs))

	mux.HandleFunc("GET /api/v1/access-lists", handlers.require(permissionRead, handlers.listAccessLists))
	mux.HandleFunc("POST /api/v1/access-lists", handlers.require(permissionWrite, handlers.createAccessList))
	mux.HandleFunc("GET /api/v1/access-lists/{id}", handlers.require(permissionRead, handlers.getAccessList))
	mux.HandleFunc("PUT /api/v1/access-lists/{id}", handlers.require(permissionWrite, handlers.updateAccessList))
	mux.HandleFunc("DELETE /api/v1/access-lists/{id}", handlers.require(permissionWrite, handlers.deleteAccessList))

	mux.HandleFunc("GET /api/v1/rate-limits", handlers.require(permissionRead, handlers.listRateLimits))
	mux.HandleFunc("POST /api/v1/rate-limits", handlers.require(permissionWrite, handlers.createRateLimit))
	mux.HandleFunc("GET /api/v1/rate-limits/{id}", handlers.require(permissionRead, handlers.getRateLimit))
	mux.HandleFunc("PUT /api/v1/rate-limits/{id}", handlers.require(permissionWrite, handlers.updateRateLimit))
	mux.HandleFunc("DELETE /api/v1/rate-limits/{id}", handlers.require(permissionWrite, handlers.deleteRateLimit))
}
