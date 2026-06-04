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
	botProtectionModule   = "bot-protection"
	botProtectionCategory = "challenge"
	defaultBotVerifyTTL   = 300
	maxBotVerifyTTL       = 86400
)

type botProtectionFilter struct {
	SiteID       int64
	Enabled      bool
	EnabledIsSet bool
}

func (h handlers) listBotProtectionRules(w http.ResponseWriter, r *http.Request) {
	filter, ok := parseBotProtectionFilter(w, r)
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
		if rule.Module != botProtectionModule {
			continue
		}
		seenLegacy[rule.LegacyRef] = true
		if botProtectionMatches(rule, filter) {
			items = append(items, rule)
		}
	}
	rules, err := h.app.Store.ListBotProtectionRules(r.Context())
	if err != nil {
		h.writeServerError(w, err)
		return
	}
	for _, item := range rules {
		if seenLegacy[protectionrules.LegacyRef("bot_protection_rules", item.ID)] {
			continue
		}
		rule := botProtectionFromRule(item)
		if botProtectionMatches(rule, filter) {
			items = append(items, rule)
		}
	}
	writeJSON(w, http.StatusOK, envelope{"items": items})
}

func (h handlers) getBotProtectionRule(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	item, err := h.app.Store.GetProtectionRule(r.Context(), id)
	if err != nil {
		legacy, legacyErr := h.app.Store.GetBotProtectionRule(r.Context(), id)
		if legacyErr != nil {
			h.writeKnownError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, envelope{"item": botProtectionFromRule(legacy)})
		return
	}
	if item.Module != botProtectionModule {
		h.writeKnownError(w, store.ErrNotFound)
		return
	}
	writeJSON(w, http.StatusOK, envelope{"item": item})
}

func (h handlers) createBotProtectionRule(w http.ResponseWriter, r *http.Request) {
	var req botProtectionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := req.toProtectionRule()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	created, err := h.app.Store.CreateProtectionRule(r.Context(), item)
	h.audit(r, "create", "bot_protection_rule", created.ID, resultFromErr(err), err)
	h.writeCreated(w, created, err)
}

func (h handlers) updateBotProtectionRule(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var req botProtectionRequest
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
		legacy, legacyErr := h.app.Store.UpdateBotProtectionRule(r.Context(), id, protectionrules.ToBot(item))
		if legacyErr == nil {
			updated = botProtectionFromRule(legacy)
		}
		err = legacyErr
	}
	h.audit(r, "update", "bot_protection_rule", id, resultFromErr(err), err)
	h.writeItem(w, updated, err)
}

func (h handlers) deleteBotProtectionRule(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	err := h.app.Store.DeleteProtectionRule(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		err = h.app.Store.DeleteBotProtectionRule(r.Context(), id)
	}
	h.audit(r, "delete", "bot_protection_rule", id, resultFromErr(err), err)
	h.writeNoContent(w, err)
}

type botProtectionRequest struct {
	Name      string                         `json:"name"`
	SiteID    int64                          `json:"site_id"`
	Enabled   *bool                          `json:"enabled"`
	Priority  int                            `json:"priority"`
	Match     model.ProtectionRuleMatch      `json:"match"`
	Challenge *model.ProtectionRuleChallenge `json:"challenge"`
	Action    model.ProtectionRuleAction     `json:"action"`
	Module    string                         `json:"module"`
	Category  string                         `json:"category"`
}

func (r botProtectionRequest) toModel() (model.BotProtectionRule, error) {
	rule, err := r.toProtectionRule()
	if err != nil {
		return model.BotProtectionRule{}, err
	}
	return protectionrules.ToBot(rule), nil
}

func (r botProtectionRequest) toProtectionRule() (model.ProtectionRule, error) {
	r.normalize()
	if err := r.validate(); err != nil {
		return model.ProtectionRule{}, err
	}
	return model.ProtectionRule{
		Name:      r.Name,
		Module:    r.Module,
		Category:  r.Category,
		SiteID:    r.SiteID,
		Enabled:   boolValue(r.Enabled, true),
		Priority:  protectionRequestPriority(r.Priority),
		Match:     r.Match,
		Challenge: r.Challenge,
		Action:    r.Action,
		Source:    protectionrules.SourceNative,
	}, nil
}

func (r *botProtectionRequest) normalize() {
	r.Name = strings.TrimSpace(r.Name)
	r.Module = strings.TrimSpace(r.Module)
	r.Category = strings.TrimSpace(r.Category)
	r.Match.Path = strings.TrimSpace(r.Match.Path)
	r.Match.PathMatch = strings.ToLower(strings.TrimSpace(r.Match.PathMatch))
	r.Match.Methods = normalizeHTTPMethods(r.Match.Methods)
	if r.Challenge == nil {
		r.Challenge = &model.ProtectionRuleChallenge{}
	}
	r.Challenge.Mode = strings.ToLower(strings.TrimSpace(r.Challenge.Mode))
	r.Challenge.FailureAction = strings.ToLower(strings.TrimSpace(r.Challenge.FailureAction))
	r.Action.Type = strings.ToLower(strings.TrimSpace(r.Action.Type))
	if r.Module == "" {
		r.Module = botProtectionModule
	}
	if r.Category == "" {
		r.Category = botProtectionCategory
	}
	if r.Match.Path == "" {
		r.Match.Path = "/"
	}
	if r.Match.PathMatch == "" {
		r.Match.PathMatch = "prefix"
	}
	if r.Challenge.Mode == "" {
		r.Challenge.Mode = "js-challenge"
	}
	if r.Challenge.FailureAction == "" {
		r.Challenge.FailureAction = "block"
	}
	if r.Action.Type == "" {
		r.Action.Type = r.Challenge.FailureAction
	}
}

func (r botProtectionRequest) validate() error {
	if r.Name == "" {
		return errors.New("bot protection rule name is required")
	}
	if r.Module != botProtectionModule {
		return errors.New("bot protection module must be bot-protection")
	}
	if r.Category != botProtectionCategory {
		return errors.New("bot protection category must be challenge")
	}
	if r.Priority < 0 {
		return errors.New("bot protection priority cannot be negative")
	}
	if !strings.HasPrefix(r.Match.Path, "/") {
		return errors.New("bot protection path must start with /")
	}
	if !oneOf(r.Match.PathMatch, "exact", "prefix") {
		return errors.New("bot protection path_match must be exact or prefix")
	}
	for _, method := range r.Match.Methods {
		if !oneOf(method, "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS") {
			return errors.New("bot protection method is unsupported")
		}
	}
	if r.Challenge == nil {
		return errors.New("bot protection challenge is required")
	}
	if r.Challenge.Mode != "js-challenge" {
		return errors.New("bot protection challenge mode must be js-challenge")
	}
	if r.Challenge.VerifyTTL <= 0 || r.Challenge.VerifyTTL > maxBotVerifyTTL {
		return errors.New("bot protection verify_ttl_sec is invalid")
	}
	if !oneOf(r.Challenge.FailureAction, "log-only", "block") {
		return errors.New("bot protection failure_action is unsupported")
	}
	if !oneOf(r.Action.Type, "", r.Challenge.FailureAction) {
		return errors.New("bot protection action must match failure_action")
	}
	return nil
}

func parseBotProtectionFilter(w http.ResponseWriter, r *http.Request) (botProtectionFilter, bool) {
	query := r.URL.Query()
	filter := botProtectionFilter{}
	if value := strings.TrimSpace(query.Get("site_id")); value != "" {
		id, err := strconv.ParseInt(value, 10, 64)
		if err != nil || id < 0 {
			writeError(w, http.StatusBadRequest, "invalid site_id filter")
			return botProtectionFilter{}, false
		}
		filter.SiteID = id
	}
	if value := strings.TrimSpace(query.Get("enabled")); value != "" {
		enabled, err := parseBoolFilter(value)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid enabled filter")
			return botProtectionFilter{}, false
		}
		filter.Enabled = enabled
		filter.EnabledIsSet = true
	}
	return filter, true
}

func botProtectionMatches(rule model.ProtectionRule, filter botProtectionFilter) bool {
	if filter.SiteID > 0 && rule.SiteID != filter.SiteID {
		return false
	}
	if filter.EnabledIsSet && rule.Enabled != filter.Enabled {
		return false
	}
	return true
}

func botProtectionFromRule(item model.BotProtectionRule) model.ProtectionRule {
	return publish.BotProtectionFromRule(item)
}
