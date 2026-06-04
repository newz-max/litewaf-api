package httpserver

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"litewaf-api/internal/model"
	"litewaf-api/internal/protectionrules"
	"litewaf-api/internal/publish"
	"litewaf-api/internal/store"
)

const (
	ccProtectionModule = "cc-protection"
	rateLimitCategory  = "rate-limit"
)

type ccProtectionFilter struct {
	SiteID       int64
	Enabled      bool
	EnabledIsSet bool
}

func (h handlers) listCCProtectionRules(w http.ResponseWriter, r *http.Request) {
	filter, ok := parseCCProtectionFilter(w, r)
	if !ok {
		return
	}
	protectionRules, err := h.app.Store.ListProtectionRules(r.Context())
	if err != nil {
		h.writeServerError(w, err)
		return
	}
	items := make([]model.ProtectionRule, 0, len(protectionRules))
	seenLegacy := map[string]bool{}
	for _, rule := range protectionRules {
		if rule.Module != ccProtectionModule {
			continue
		}
		seenLegacy[rule.LegacyRef] = true
		if ccProtectionMatches(rule, filter) {
			items = append(items, rule)
		}
	}
	rateLimits, err := h.app.Store.ListRateLimitRules(r.Context())
	if err != nil {
		h.writeServerError(w, err)
		return
	}
	for _, item := range rateLimits {
		if seenLegacy[protectionrules.LegacyRef("rate_limits", item.ID)] {
			continue
		}
		rule := ccProtectionFromRateLimit(item)
		if ccProtectionMatches(rule, filter) {
			items = append(items, rule)
		}
	}
	writeJSON(w, http.StatusOK, envelope{"items": items})
}

func (h handlers) getCCProtectionRule(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	item, err := h.app.Store.GetProtectionRule(r.Context(), id)
	if err != nil {
		legacy, legacyErr := h.app.Store.GetRateLimitRule(r.Context(), id)
		if legacyErr != nil {
			h.writeKnownError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, envelope{"item": ccProtectionFromRateLimit(legacy)})
		return
	}
	if item.Module != ccProtectionModule {
		h.writeKnownError(w, store.ErrNotFound)
		return
	}
	writeJSON(w, http.StatusOK, envelope{"item": item})
}

func (h handlers) createCCProtectionRule(w http.ResponseWriter, r *http.Request) {
	var req ccProtectionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := req.toProtectionRule()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	created, err := h.app.Store.CreateProtectionRule(r.Context(), item)
	h.audit(r, "create", "cc_protection_rule", created.ID, resultFromErr(err), err)
	h.writeCreated(w, created, err)
}

func (h handlers) updateCCProtectionRule(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var req ccProtectionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := req.toProtectionRule()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	updated, err := h.app.Store.UpdateProtectionRule(r.Context(), id, item)
	if errors.Is(err, store.ErrNotFound) {
		legacy, legacyErr := h.app.Store.UpdateRateLimitRule(r.Context(), id, protectionrules.ToRateLimit(item))
		if legacyErr == nil {
			updated = ccProtectionFromRateLimit(legacy)
		}
		err = legacyErr
	}
	h.audit(r, "update", "cc_protection_rule", id, resultFromErr(err), err)
	h.writeItem(w, updated, err)
}

func (h handlers) deleteCCProtectionRule(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	err := h.app.Store.DeleteProtectionRule(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		err = h.app.Store.DeleteRateLimitRule(r.Context(), id)
	}
	h.audit(r, "delete", "cc_protection_rule", id, resultFromErr(err), err)
	h.writeNoContent(w, err)
}

type ccProtectionRequest struct {
	Name     string                     `json:"name"`
	SiteID   int64                      `json:"site_id"`
	Enabled  *bool                      `json:"enabled"`
	Priority int                        `json:"priority"`
	Match    model.ProtectionRuleMatch  `json:"match"`
	Limit    model.ProtectionRuleLimit  `json:"limit"`
	Action   model.ProtectionRuleAction `json:"action"`
	Module   string                     `json:"module"`
	Category string                     `json:"category"`
}

func (r ccProtectionRequest) toRateLimit() (model.RateLimitRule, error) {
	rule, err := r.toProtectionRule()
	if err != nil {
		return model.RateLimitRule{}, err
	}
	return protectionrules.ToRateLimit(rule), nil
}

func (r ccProtectionRequest) toProtectionRule() (model.ProtectionRule, error) {
	r.normalize()
	if err := r.validate(); err != nil {
		return model.ProtectionRule{}, err
	}
	return model.ProtectionRule{
		Name:     r.Name,
		Module:   r.Module,
		Category: r.Category,
		SiteID:   r.SiteID,
		Enabled:  boolValue(r.Enabled, true),
		Priority: protectionRequestPriority(r.Priority),
		Match:    r.Match,
		Limit:    r.Limit,
		Action:   r.Action,
		Source:   protectionrules.SourceNative,
	}, nil
}

func (r *ccProtectionRequest) normalize() {
	r.Name = strings.TrimSpace(r.Name)
	r.Module = strings.TrimSpace(r.Module)
	r.Category = strings.TrimSpace(r.Category)
	r.Match.Path = strings.TrimSpace(r.Match.Path)
	r.Match.PathMatch = strings.ToLower(strings.TrimSpace(r.Match.PathMatch))
	r.Match.Methods = normalizeHTTPMethods(r.Match.Methods)
	r.Limit.Counter = strings.ToLower(strings.TrimSpace(r.Limit.Counter))
	r.Action.Type = strings.ToLower(strings.TrimSpace(r.Action.Type))
	if r.Module == "" {
		r.Module = ccProtectionModule
	}
	if r.Category == "" {
		r.Category = rateLimitCategory
	}
	if r.Match.PathMatch == "" {
		r.Match.PathMatch = "exact"
	}
	if r.Action.Type == "" {
		r.Action.Type = "rate-limit"
	}
}

func (r ccProtectionRequest) validate() error {
	if r.Name == "" {
		return errors.New("cc protection rule name is required")
	}
	if r.Module != ccProtectionModule {
		return errors.New("cc protection module must be cc-protection")
	}
	if r.Category != rateLimitCategory {
		return errors.New("cc protection category must be rate-limit")
	}
	if !strings.HasPrefix(r.Match.Path, "/") {
		return errors.New("cc protection path must start with /")
	}
	if !oneOf(r.Match.PathMatch, "exact", "prefix") {
		return errors.New("cc protection path_match must be exact or prefix")
	}
	for _, method := range r.Match.Methods {
		if !oneOf(method, "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS") {
			return errors.New("cc protection method is unsupported")
		}
	}
	if !oneOf(r.Limit.Counter, "client_ip", "client_ip_path", "global") {
		return errors.New("cc protection counter is unsupported")
	}
	if r.Limit.Threshold <= 0 {
		return errors.New("cc protection threshold must be positive")
	}
	if r.Limit.WindowSec <= 0 {
		return errors.New("cc protection window_sec must be positive")
	}
	if r.Limit.BanDurationSec < 0 {
		return errors.New("cc protection ban_duration_sec cannot be negative")
	}
	if !oneOf(r.Action.Type, "log-only", "block", "rate-limit", "ban") {
		return errors.New("cc protection action is unsupported")
	}
	return nil
}

func parseCCProtectionFilter(w http.ResponseWriter, r *http.Request) (ccProtectionFilter, bool) {
	query := r.URL.Query()
	filter := ccProtectionFilter{}
	if value := strings.TrimSpace(query.Get("site_id")); value != "" {
		id, err := strconv.ParseInt(value, 10, 64)
		if err != nil || id < 0 {
			writeError(w, http.StatusBadRequest, "invalid site_id filter")
			return ccProtectionFilter{}, false
		}
		filter.SiteID = id
	}
	if value := strings.TrimSpace(query.Get("enabled")); value != "" {
		enabled, err := parseBoolFilter(value)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid enabled filter")
			return ccProtectionFilter{}, false
		}
		filter.Enabled = enabled
		filter.EnabledIsSet = true
	}
	return filter, true
}

func parseBoolFilter(value string) (bool, error) {
	switch strings.ToLower(value) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, errors.New("invalid bool")
	}
}

func ccProtectionMatches(rule model.ProtectionRule, filter ccProtectionFilter) bool {
	if filter.SiteID > 0 && rule.SiteID != filter.SiteID {
		return false
	}
	if filter.EnabledIsSet && rule.Enabled != filter.Enabled {
		return false
	}
	return true
}

func ccProtectionFromRateLimit(item model.RateLimitRule) model.ProtectionRule {
	return publish.CCProtectionFromRateLimit(item)
}

func normalizeHTTPMethods(methods []string) []string {
	if methods == nil {
		return []string{}
	}
	out := make([]string, 0, len(methods))
	seen := map[string]bool{}
	for _, method := range methods {
		item := strings.ToUpper(strings.TrimSpace(method))
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func ccRateLimitScope(counter string) string {
	switch counter {
	case "client_ip":
		return "ip"
	case "client_ip_path":
		return "uri"
	case "global":
		return "site"
	default:
		return "ip"
	}
}

func ccRateLimitMatchValue(match model.ProtectionRuleMatch) string {
	if match.Path == "/" {
		return ""
	}
	return match.Path
}

func ccRateLimitAction(action string) string {
	switch action {
	case "log-only":
		return "log-only"
	default:
		return "block"
	}
}
