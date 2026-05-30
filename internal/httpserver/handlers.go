package httpserver

import (
	"log/slog"
	"net/http"
	"time"

	"litewaf-api/internal/app"
)

type handlers struct {
	logger *slog.Logger
	app    *app.App
}

func newHandlers(logger *slog.Logger, application *app.App) handlers {
	return handlers{
		logger: logger,
		app:    application,
	}
}

func (h handlers) healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, envelope{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

func (h handlers) version(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, envelope{
		"name":    h.app.Config.AppName,
		"version": app.Version,
		"env":     h.app.Config.Env,
	})
}

func (h handlers) listSites(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, envelope{
		"items": []envelope{},
	})
}

func (h handlers) createSite(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusCreated, envelope{
		"message": "site creation endpoint placeholder",
	})
}

func (h handlers) listRules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, envelope{
		"items": []envelope{},
	})
}

func (h handlers) createRule(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusCreated, envelope{
		"message": "rule creation endpoint placeholder",
	})
}

func (h handlers) listPolicies(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, envelope{
		"items": []envelope{},
	})
}

func (h handlers) createPolicy(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusCreated, envelope{
		"message": "policy creation endpoint placeholder",
	})
}

func (h handlers) listAttackLogs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, envelope{
		"items": []envelope{},
	})
}

func (h handlers) listReleases(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, envelope{
		"items": []envelope{},
	})
}

func (h handlers) createRelease(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusCreated, envelope{
		"message": "release creation endpoint placeholder",
		"version": "ruleset-0001",
	})
}
