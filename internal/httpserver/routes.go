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
	mux.HandleFunc("POST /api/v1/rules/test", handlers.require(permissionWrite, handlers.testRule))

	mux.HandleFunc("GET /api/v1/rule-packages", handlers.require(permissionRead, handlers.listRulePackages))
	mux.HandleFunc("POST /api/v1/rule-packages/preview", handlers.require(permissionWrite, handlers.previewRulePackage))
	mux.HandleFunc("POST /api/v1/rule-packages/import", handlers.require(permissionWrite, handlers.importRulePackage))
	mux.HandleFunc("GET /api/v1/rule-packages/{id}", handlers.require(permissionRead, handlers.getRulePackage))
	mux.HandleFunc("DELETE /api/v1/rule-packages/{id}", handlers.require(permissionWrite, handlers.deleteRulePackage))

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

	mux.HandleFunc("GET /api/v1/access-control/rules", handlers.require(permissionRead, handlers.listAccessControlRules))
	mux.HandleFunc("POST /api/v1/access-control/rules", handlers.require(permissionWrite, handlers.createAccessControlRule))
	mux.HandleFunc("GET /api/v1/access-control/rules/{id}", handlers.require(permissionRead, handlers.getAccessControlRule))
	mux.HandleFunc("PUT /api/v1/access-control/rules/{id}", handlers.require(permissionWrite, handlers.updateAccessControlRule))
	mux.HandleFunc("DELETE /api/v1/access-control/rules/{id}", handlers.require(permissionWrite, handlers.deleteAccessControlRule))

	mux.HandleFunc("GET /api/v1/rate-limits", handlers.require(permissionRead, handlers.listRateLimits))
	mux.HandleFunc("POST /api/v1/rate-limits", handlers.require(permissionWrite, handlers.createRateLimit))
	mux.HandleFunc("GET /api/v1/rate-limits/{id}", handlers.require(permissionRead, handlers.getRateLimit))
	mux.HandleFunc("PUT /api/v1/rate-limits/{id}", handlers.require(permissionWrite, handlers.updateRateLimit))
	mux.HandleFunc("DELETE /api/v1/rate-limits/{id}", handlers.require(permissionWrite, handlers.deleteRateLimit))

	mux.HandleFunc("GET /api/v1/cc-protection/rules", handlers.require(permissionRead, handlers.listCCProtectionRules))
	mux.HandleFunc("POST /api/v1/cc-protection/rules", handlers.require(permissionWrite, handlers.createCCProtectionRule))
	mux.HandleFunc("GET /api/v1/cc-protection/rules/{id}", handlers.require(permissionRead, handlers.getCCProtectionRule))
	mux.HandleFunc("PUT /api/v1/cc-protection/rules/{id}", handlers.require(permissionWrite, handlers.updateCCProtectionRule))
	mux.HandleFunc("DELETE /api/v1/cc-protection/rules/{id}", handlers.require(permissionWrite, handlers.deleteCCProtectionRule))

	mux.HandleFunc("GET /api/v1/upload-protection/rules", handlers.require(permissionRead, handlers.listUploadProtectionRules))
	mux.HandleFunc("POST /api/v1/upload-protection/rules", handlers.require(permissionWrite, handlers.createUploadProtectionRule))
	mux.HandleFunc("GET /api/v1/upload-protection/rules/{id}", handlers.require(permissionRead, handlers.getUploadProtectionRule))
	mux.HandleFunc("PUT /api/v1/upload-protection/rules/{id}", handlers.require(permissionWrite, handlers.updateUploadProtectionRule))
	mux.HandleFunc("DELETE /api/v1/upload-protection/rules/{id}", handlers.require(permissionWrite, handlers.deleteUploadProtectionRule))

	mux.HandleFunc("GET /api/v1/bot-protection/rules", handlers.require(permissionRead, handlers.listBotProtectionRules))
	mux.HandleFunc("POST /api/v1/bot-protection/rules", handlers.require(permissionWrite, handlers.createBotProtectionRule))
	mux.HandleFunc("GET /api/v1/bot-protection/rules/{id}", handlers.require(permissionRead, handlers.getBotProtectionRule))
	mux.HandleFunc("PUT /api/v1/bot-protection/rules/{id}", handlers.require(permissionWrite, handlers.updateBotProtectionRule))
	mux.HandleFunc("DELETE /api/v1/bot-protection/rules/{id}", handlers.require(permissionWrite, handlers.deleteBotProtectionRule))

	mux.HandleFunc("GET /api/v1/dynamic-protection/rules", handlers.require(permissionRead, handlers.listDynamicProtectionRules))
	mux.HandleFunc("POST /api/v1/dynamic-protection/rules", handlers.require(permissionWrite, handlers.createDynamicProtectionRule))
	mux.HandleFunc("GET /api/v1/dynamic-protection/rules/{id}", handlers.require(permissionRead, handlers.getDynamicProtectionRule))
	mux.HandleFunc("PUT /api/v1/dynamic-protection/rules/{id}", handlers.require(permissionWrite, handlers.updateDynamicProtectionRule))
	mux.HandleFunc("DELETE /api/v1/dynamic-protection/rules/{id}", handlers.require(permissionWrite, handlers.deleteDynamicProtectionRule))

	mux.HandleFunc("GET /api/v1/attack-protection/groups", handlers.require(permissionRead, handlers.listAttackProtectionGroups))
	mux.HandleFunc("PUT /api/v1/attack-protection/groups/{attack_type}", handlers.require(permissionWrite, handlers.updateAttackProtectionGroup))
}
