package httpserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"litewaf-api/internal/app"
	"litewaf-api/internal/model"
	"litewaf-api/internal/publish"
	"litewaf-api/internal/store"
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
	if err := h.app.Store.Ping(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, envelope{
			"status": "degraded",
			"error":  "database unavailable",
			"time":   time.Now().UTC().Format(time.RFC3339),
		})
		return
	}
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
	items, err := h.app.Store.ListSites(r.Context())
	h.writeList(w, items, err)
}

func (h handlers) getSite(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	item, err := h.app.Store.GetSite(r.Context(), id)
	h.writeItem(w, item, err)
}

func (h handlers) createSite(w http.ResponseWriter, r *http.Request) {
	var req siteRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	input := req.toModel()
	input.Enabled = boolValue(req.Enabled, true)
	normalizeSite(&input)
	if err := validateSite(input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	item, err := h.app.Store.CreateSite(r.Context(), input)
	h.writeCreated(w, item, err)
}

func (h handlers) updateSite(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var req siteRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	input := req.toModel()
	input.Enabled = boolValue(req.Enabled, true)
	normalizeSite(&input)
	if err := validateSite(input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	item, err := h.app.Store.UpdateSite(r.Context(), id, input)
	h.writeItem(w, item, err)
}

func (h handlers) deleteSite(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	h.writeNoContent(w, h.app.Store.DeleteSite(r.Context(), id))
}

func (h handlers) listRules(w http.ResponseWriter, r *http.Request) {
	items, err := h.app.Store.ListRules(r.Context())
	h.writeList(w, items, err)
}

func (h handlers) getRule(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	item, err := h.app.Store.GetRule(r.Context(), id)
	h.writeItem(w, item, err)
}

func (h handlers) createRule(w http.ResponseWriter, r *http.Request) {
	var req ruleRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	input := req.toModel()
	input.Enabled = boolValue(req.Enabled, true)
	normalizeRule(&input)
	if err := validateRule(input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	item, err := h.app.Store.CreateRule(r.Context(), input)
	h.writeCreated(w, item, err)
}

func (h handlers) updateRule(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var req ruleRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	input := req.toModel()
	input.Enabled = boolValue(req.Enabled, true)
	normalizeRule(&input)
	if err := validateRule(input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	item, err := h.app.Store.UpdateRule(r.Context(), id, input)
	h.writeItem(w, item, err)
}

func (h handlers) deleteRule(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	h.writeNoContent(w, h.app.Store.DeleteRule(r.Context(), id))
}

func (h handlers) listPolicies(w http.ResponseWriter, r *http.Request) {
	items, err := h.app.Store.ListPolicies(r.Context())
	h.writeList(w, items, err)
}

func (h handlers) getPolicy(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	item, err := h.app.Store.GetPolicy(r.Context(), id)
	h.writeItem(w, item, err)
}

func (h handlers) createPolicy(w http.ResponseWriter, r *http.Request) {
	var req policyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	input := req.toModel()
	input.Enabled = boolValue(req.Enabled, true)
	normalizePolicy(&input)
	if err := validatePolicy(input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	item, err := h.app.Store.CreatePolicy(r.Context(), input)
	h.writeCreated(w, item, err)
}

func (h handlers) updatePolicy(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var req policyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	input := req.toModel()
	input.Enabled = boolValue(req.Enabled, true)
	normalizePolicy(&input)
	if err := validatePolicy(input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	item, err := h.app.Store.UpdatePolicy(r.Context(), id, input)
	h.writeItem(w, item, err)
}

func (h handlers) deletePolicy(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	h.writeNoContent(w, h.app.Store.DeletePolicy(r.Context(), id))
}

func (h handlers) listAttackLogs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, envelope{"items": []envelope{}})
}

func (h handlers) listReleases(w http.ResponseWriter, r *http.Request) {
	items, err := h.app.Store.ListPublishRecords(r.Context())
	h.writeList(w, items, err)
}

func (h handlers) createRelease(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Operator string `json:"operator"`
		Note     string `json:"note"`
	}
	if r.Body != nil && r.ContentLength != 0 {
		if !decodeJSON(w, r, &input) {
			return
		}
	}
	operator := strings.TrimSpace(input.Operator)
	if operator == "" {
		operator = h.app.Config.PublishOperator
	}
	next, err := h.app.Store.NextPublishVersion(r.Context())
	if err != nil {
		h.writeServerError(w, err)
		return
	}
	version := fmt.Sprintf("ruleset-%04d", next)
	_, payload, checksum, err := publish.Generate(r.Context(), h.app.Store, version)
	if err != nil {
		h.writeServerError(w, err)
		return
	}
	if err := publish.WriteAtomic(h.app.Config.GatewayConfigPath, payload); err != nil {
		h.writeServerError(w, err)
		return
	}
	record, err := h.app.Store.CreatePublishRecord(r.Context(), model.PublishRecord{
		Version:    version,
		Operator:   operator,
		Status:     "success",
		ConfigPath: h.app.Config.GatewayConfigPath,
		Checksum:   checksum,
		Note:       strings.TrimSpace(input.Note),
	})
	h.writeCreated(w, record, err)
}

type siteRequest struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	Upstream string `json:"upstream"`
	Mode     string `json:"mode"`
	Enabled  *bool  `json:"enabled"`
}

func (r siteRequest) toModel() model.Site {
	return model.Site{
		Name:     r.Name,
		Host:     r.Host,
		Upstream: r.Upstream,
		Mode:     r.Mode,
	}
}

type ruleRequest struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Target     string `json:"target"`
	Action     string `json:"action"`
	Expression string `json:"expression"`
	Score      int    `json:"score"`
	Enabled    *bool  `json:"enabled"`
}

func (r ruleRequest) toModel() model.Rule {
	return model.Rule{
		Name:       r.Name,
		Type:       r.Type,
		Target:     r.Target,
		Action:     r.Action,
		Expression: r.Expression,
		Score:      r.Score,
	}
}

type policyRequest struct {
	Name          string  `json:"name"`
	RiskThreshold int     `json:"risk_threshold"`
	DefaultAction string  `json:"default_action"`
	Enabled       *bool   `json:"enabled"`
	SiteIDs       []int64 `json:"site_ids"`
	RuleIDs       []int64 `json:"rule_ids"`
}

func (r policyRequest) toModel() model.Policy {
	return model.Policy{
		Name:          r.Name,
		RiskThreshold: r.RiskThreshold,
		DefaultAction: r.DefaultAction,
		SiteIDs:       cloneIDs(r.SiteIDs),
		RuleIDs:       cloneIDs(r.RuleIDs),
	}
}

func boolValue(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

func cloneIDs(ids []int64) []int64 {
	if ids == nil {
		return []int64{}
	}
	out := make([]int64, len(ids))
	copy(out, ids)
	return out
}

func (h handlers) writeList(w http.ResponseWriter, items any, err error) {
	if err != nil {
		h.writeServerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envelope{"items": items})
}

func (h handlers) writeItem(w http.ResponseWriter, item any, err error) {
	if err != nil {
		h.writeKnownError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envelope{"item": item})
}

func (h handlers) writeCreated(w http.ResponseWriter, item any, err error) {
	if err != nil {
		h.writeKnownError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, envelope{"item": item})
}

func (h handlers) writeNoContent(w http.ResponseWriter, err error) {
	if err != nil {
		h.writeKnownError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h handlers) writeKnownError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "resource not found")
		return
	}
	h.writeServerError(w, err)
}

func (h handlers) writeServerError(w http.ResponseWriter, err error) {
	h.logger.Error("request failed", "error", err)
	writeError(w, http.StatusInternalServerError, "internal server error")
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return false
	}
	return true
}

func parseID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid resource id")
		return 0, false
	}
	return id, true
}

func normalizeSite(site *model.Site) {
	site.Name = strings.TrimSpace(site.Name)
	site.Host = strings.ToLower(strings.TrimSpace(site.Host))
	site.Upstream = strings.TrimSpace(site.Upstream)
	site.Mode = strings.ToLower(strings.TrimSpace(site.Mode))
	if site.Mode == "" {
		site.Mode = "monitor"
	}
}

func validateSite(site model.Site) error {
	if site.Name == "" {
		return errors.New("site name is required")
	}
	if site.Host == "" {
		return errors.New("site host is required")
	}
	if strings.Contains(site.Host, "://") || strings.ContainsAny(site.Host, "/ ") {
		return errors.New("site host must be a hostname")
	}
	parsed, err := url.Parse(site.Upstream)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return errors.New("site upstream must be an absolute URL")
	}
	if !oneOf(site.Mode, "monitor", "protect", "off") {
		return errors.New("site mode must be monitor, protect, or off")
	}
	return nil
}

func normalizeRule(rule *model.Rule) {
	rule.Name = strings.TrimSpace(rule.Name)
	rule.Type = strings.ToLower(strings.TrimSpace(rule.Type))
	rule.Target = strings.ToLower(strings.TrimSpace(rule.Target))
	rule.Action = strings.ToLower(strings.TrimSpace(rule.Action))
	rule.Expression = strings.TrimSpace(rule.Expression)
	if rule.Target == "" {
		rule.Target = "args"
	}
	if rule.Action == "" {
		rule.Action = "block"
	}
}

func validateRule(rule model.Rule) error {
	if rule.Name == "" {
		return errors.New("rule name is required")
	}
	if !oneOf(rule.Type, "sqli", "xss", "rce", "cc", "bot", "custom") {
		return errors.New("rule type is unsupported")
	}
	if !oneOf(rule.Target, "args", "uri", "headers") {
		return errors.New("rule target must be args, uri, or headers")
	}
	if !oneOf(rule.Action, "pass", "block", "log-only") {
		return errors.New("rule action must be pass, block, or log-only")
	}
	if rule.Expression == "" {
		return errors.New("rule expression is required")
	}
	if rule.Score < 0 || rule.Score > 1000 {
		return errors.New("rule score must be between 0 and 1000")
	}
	return nil
}

func normalizePolicy(policy *model.Policy) {
	policy.Name = strings.TrimSpace(policy.Name)
	policy.DefaultAction = strings.ToLower(strings.TrimSpace(policy.DefaultAction))
	if policy.DefaultAction == "" {
		policy.DefaultAction = "block"
	}
	if policy.RiskThreshold == 0 {
		policy.RiskThreshold = 100
	}
}

func validatePolicy(policy model.Policy) error {
	if policy.Name == "" {
		return errors.New("policy name is required")
	}
	if policy.RiskThreshold < 1 || policy.RiskThreshold > 1000 {
		return errors.New("policy risk_threshold must be between 1 and 1000")
	}
	if !oneOf(policy.DefaultAction, "pass", "block", "log-only") {
		return errors.New("policy default_action must be pass, block, or log-only")
	}
	if len(policy.SiteIDs) == 0 {
		return errors.New("policy site_ids is required")
	}
	if len(policy.RuleIDs) == 0 {
		return errors.New("policy rule_ids is required")
	}
	return nil
}

func oneOf(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}
