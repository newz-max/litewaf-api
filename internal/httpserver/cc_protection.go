package httpserver

import (
	"errors"
	"fmt"
	"net/http"
	"path"
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

type ccProtectionPreviewRequest struct {
	SiteID          int64   `json:"application_id"`
	LegacySiteID    int64   `json:"site_id"`
	Path            string  `json:"path"`
	Method          string  `json:"method"`
	ClientIP        string  `json:"client_ip"`
	SessionID       string  `json:"session_id"`
	DeviceID        string  `json:"device_id"`
	Status          int     `json:"status"`
	AttackMatched   bool    `json:"attack_matched"`
	RuleIDs         []int64 `json:"rule_ids"`
	IncludeDisabled bool    `json:"include_disabled"`
}

type ccProtectionPreviewMatch struct {
	RuleID      int64                        `json:"rule_id"`
	RuleName    string                       `json:"rule_name"`
	Matched     bool                         `json:"matched"`
	Enabled     bool                         `json:"enabled"`
	Counter     string                       `json:"counter"`
	CounterKey  string                       `json:"counter_key"`
	Threshold   int                          `json:"threshold"`
	WindowSec   int                          `json:"window_sec"`
	Action      string                       `json:"action"`
	Explanation string                       `json:"explanation"`
	Partial     bool                         `json:"partial"`
	Warnings    []string                     `json:"warnings"`
	RiskDetails []model.ProtectionModuleRisk `json:"risk_details,omitempty"`
}

type ccProtectionPreviewResponse struct {
	Matches []ccProtectionPreviewMatch `json:"matches"`
}

func (h handlers) previewCCProtection(w http.ResponseWriter, r *http.Request) {
	var input ccProtectionPreviewRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	input.normalize()
	rules, err := h.listPreviewCCRules(r, input)
	if err != nil {
		h.writeServerError(w, err)
		return
	}
	matches := []ccProtectionPreviewMatch{}
	for _, rule := range rules {
		match := previewCCRule(rule, input)
		if match.Matched {
			matches = append(matches, match)
		}
	}
	writeJSON(w, http.StatusOK, envelope{"item": ccProtectionPreviewResponse{Matches: matches}})
}

func (r *ccProtectionPreviewRequest) normalize() {
	if r.SiteID == 0 {
		r.SiteID = r.LegacySiteID
	}
	r.Path = strings.TrimSpace(r.Path)
	r.Method = strings.ToUpper(strings.TrimSpace(r.Method))
	r.ClientIP = strings.TrimSpace(r.ClientIP)
	r.SessionID = strings.TrimSpace(r.SessionID)
	r.DeviceID = strings.TrimSpace(r.DeviceID)
}

func (h handlers) listPreviewCCRules(r *http.Request, input ccProtectionPreviewRequest) ([]model.ProtectionRule, error) {
	protectionRules, err := h.app.Store.ListProtectionRules(r.Context())
	if err != nil {
		return nil, err
	}
	rateLimits, err := h.app.Store.ListRateLimitRules(r.Context())
	if err != nil {
		return nil, err
	}
	rules := mergedCCProtectionRules(protectionRules, rateLimits)
	selected := map[int64]bool{}
	for _, id := range input.RuleIDs {
		if id > 0 {
			selected[id] = true
		}
	}
	out := []model.ProtectionRule{}
	for _, rule := range rules {
		if rule.Module != ccProtectionModule || rule.Category != rateLimitCategory {
			continue
		}
		if input.SiteID > 0 && rule.SiteID > 0 && rule.SiteID != input.SiteID {
			continue
		}
		if len(selected) > 0 && !selected[rule.ID] {
			continue
		}
		if !rule.Enabled && !input.IncludeDisabled {
			continue
		}
		out = append(out, rule)
	}
	return out, nil
}

func previewCCRule(rule model.ProtectionRule, input ccProtectionPreviewRequest) ccProtectionPreviewMatch {
	match := ccProtectionPreviewMatch{
		RuleID:      rule.ID,
		RuleName:    rule.Name,
		Enabled:     rule.Enabled,
		Counter:     rule.Limit.Counter,
		Threshold:   rule.Limit.Threshold,
		WindowSec:   rule.Limit.WindowSec,
		Action:      rule.Action.Type,
		Explanation: "rule matched supplied request facts",
		Warnings:    ccRuleRiskWarnings(rule),
		RiskDetails: ccRuleRiskDetails(rule),
	}
	if !ccPreviewMethodMatches(rule.Match.Methods, input.Method) {
		return match
	}
	if !ccPreviewPathMatches(rule.Match, input.Path) {
		return match
	}
	match.Matched = true
	match.CounterKey, match.Partial = ccPreviewCounterKey(rule, input)
	return match
}

func ccPreviewMethodMatches(methods []string, method string) bool {
	if len(methods) == 0 {
		return true
	}
	for _, item := range methods {
		if item == method {
			return true
		}
	}
	return false
}

func ccPreviewPathMatches(match model.ProtectionRuleMatch, requestPath string) bool {
	if requestPath == "" {
		requestPath = "/"
	}
	rulePath := match.Path
	if rulePath == "" {
		rulePath = "/"
	}
	switch match.PathMatch {
	case "prefix":
		return pathPrefixMatches(rulePath, requestPath)
	case "glob":
		ok, err := path.Match(rulePath, requestPath)
		return err == nil && ok
	default:
		return requestPath == rulePath
	}
}

func pathPrefixMatches(prefix, requestPath string) bool {
	if prefix == "" {
		return false
	}
	if prefix == "/" {
		return true
	}
	if strings.HasSuffix(prefix, "/") {
		base := strings.TrimSuffix(prefix, "/")
		return requestPath == base || requestPath == prefix || strings.HasPrefix(requestPath, prefix)
	}
	return requestPath == prefix || strings.HasPrefix(requestPath, prefix+"/")
}

func ccPreviewCounterKey(rule model.ProtectionRule, input ccProtectionPreviewRequest) (string, bool) {
	site := fmt.Sprintf("site:%d", rule.SiteID)
	if input.SiteID > 0 {
		site = fmt.Sprintf("site:%d", input.SiteID)
	}
	switch rule.Limit.Counter {
	case "client_ip_path":
		if input.ClientIP == "" {
			return site + ":client_ip_path:<missing-client-ip>:" + input.Path, true
		}
		return site + ":client_ip_path:" + input.ClientIP + ":" + input.Path, false
	case "global":
		return site + ":global", false
	case "session":
		if input.SessionID == "" {
			return site + ":session:<missing-session>", true
		}
		return site + ":session:" + input.SessionID, false
	case "device":
		if input.DeviceID == "" {
			return site + ":device:<missing-device>", true
		}
		return site + ":device:" + input.DeviceID, false
	case "not_found_frequency":
		if input.Status == 0 {
			return site + ":not_found:<missing-status>", true
		}
		if input.Status != http.StatusNotFound {
			return site + ":not_found:status-" + strconv.Itoa(input.Status), false
		}
		return site + ":not_found:404", false
	case "attack_frequency":
		if !input.AttackMatched {
			return site + ":attack:not-matched", true
		}
		return site + ":attack:matched", false
	default:
		if input.ClientIP == "" {
			return site + ":client_ip:<missing-client-ip>", true
		}
		return site + ":client_ip:" + input.ClientIP, false
	}
}

type ccProtectionRequest struct {
	Name         string                     `json:"name"`
	SiteID       int64                      `json:"application_id"`
	LegacySiteID int64                      `json:"site_id"`
	Enabled      *bool                      `json:"enabled"`
	Priority     int                        `json:"priority"`
	Match        model.ProtectionRuleMatch  `json:"match"`
	Limit        model.ProtectionRuleLimit  `json:"limit"`
	Action       model.ProtectionRuleAction `json:"action"`
	Module       string                     `json:"module"`
	Category     string                     `json:"category"`
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
	if r.SiteID == 0 {
		r.SiteID = r.LegacySiteID
	}
	r.Name = strings.TrimSpace(r.Name)
	r.Module = strings.TrimSpace(r.Module)
	r.Category = strings.TrimSpace(r.Category)
	r.Match.Path = strings.TrimSpace(r.Match.Path)
	r.Match.PathMatch = strings.ToLower(strings.TrimSpace(r.Match.PathMatch))
	r.Match.Methods = normalizeHTTPMethods(r.Match.Methods)
	r.Limit.Counter = strings.ToLower(strings.TrimSpace(r.Limit.Counter))
	r.Limit.SessionSource = strings.ToLower(strings.TrimSpace(r.Limit.SessionSource))
	r.Limit.SessionName = strings.TrimSpace(r.Limit.SessionName)
	r.Limit.DeviceStrategy = strings.ToLower(strings.TrimSpace(r.Limit.DeviceStrategy))
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
	if r.Limit.Counter == "" {
		r.Limit.Counter = "client_ip"
	}
	if r.Limit.Counter == "session" && r.Limit.SessionSource == "" {
		r.Limit.SessionSource = "cookie"
	}
	if r.Limit.Counter == "device" && r.Limit.DeviceStrategy == "" {
		r.Limit.DeviceStrategy = "coarse"
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
	if !protectionrules.IsCCPathMatch(r.Match.PathMatch) {
		return errors.New("cc protection path_match must be exact, prefix, or glob")
	}
	if r.Match.PathMatch == "glob" && !ccGlobPathValid(r.Match.Path) {
		return errors.New("cc protection glob path is invalid")
	}
	for _, method := range r.Match.Methods {
		if !oneOf(method, "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS") {
			return errors.New("cc protection method is unsupported")
		}
	}
	if !protectionrules.IsCCCounter(r.Limit.Counter) {
		return errors.New("cc protection counter is unsupported")
	}
	if r.Limit.Counter == "session" {
		if !oneOf(r.Limit.SessionSource, "cookie", "header") {
			return errors.New("cc protection session_source is unsupported")
		}
		if r.Limit.SessionName == "" || len(r.Limit.SessionName) > 64 || strings.ContainsAny(r.Limit.SessionName, "\r\n:;") {
			return errors.New("cc protection session_name is invalid")
		}
	} else if r.Limit.SessionSource != "" || r.Limit.SessionName != "" {
		return errors.New("cc protection session options require session counter")
	}
	if r.Limit.Counter == "device" {
		if !oneOf(r.Limit.DeviceStrategy, "coarse") {
			return errors.New("cc protection device_strategy is unsupported")
		}
	} else if r.Limit.DeviceStrategy != "" {
		return errors.New("cc protection device options require device counter")
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

func ccGlobPathValid(value string) bool {
	if value == "" || !strings.HasPrefix(value, "/") {
		return false
	}
	if strings.Contains(value, "**") || strings.Contains(value, "\\") || strings.ContainsAny(value, "[]{}") {
		return false
	}
	_, err := path.Match(value, value)
	return err == nil
}

func ccRuleRiskWarnings(rule model.ProtectionRule) []string {
	warnings := []string{}
	for _, risk := range ccRuleRiskDetails(rule) {
		warnings = append(warnings, risk.Message)
	}
	return warnings
}

func ccRuleRiskDetails(rule model.ProtectionRule) []model.ProtectionModuleRisk {
	if !rule.Enabled {
		return []model.ProtectionModuleRisk{}
	}
	risks := []model.ProtectionModuleRisk{}
	blocking := rule.Action.Type == "block" || rule.Action.Type == "ban" || rule.Action.Type == "rate-limit"
	lowThreshold := rule.Limit.Threshold > 0 && rule.Limit.Threshold < 60 && rule.Limit.WindowSec > 0 && rule.Limit.WindowSec <= 60
	scope := fmt.Sprintf("%s %s，方法 %s", rule.Match.PathMatch, rule.Match.Path, methodScope(rule.Match.Methods))
	if blocking && lowThreshold && rule.Match.Path == "/" && (rule.Match.PathMatch == "prefix" || rule.Match.PathMatch == "glob") {
		risks = append(risks, protectionRiskDetail("cc-protection", "CC 防护", rule.Name, scope, rule.Action.Type, "全站低阈值可能限制正常用户访问", "先使用观察模式或提高阈值，确认业务峰值后再发布", fmt.Sprintf("规则 %s 对全站路径使用较低阈值", rule.Name)))
	}
	if blocking && lowThreshold && rule.Match.PathMatch == "glob" && broadCCGlob(rule.Match.Path) {
		risks = append(risks, protectionRiskDetail("cc-protection", "CC 防护", rule.Name, scope, rule.Action.Type, "宽泛 glob 与低阈值组合可能覆盖非预期接口", "收窄 glob 范围或先通过 CC 模拟预览验证命中", fmt.Sprintf("规则 %s 使用较宽泛 glob 匹配和较低阈值", rule.Name)))
	}
	return risks
}

func broadCCGlob(value string) bool {
	return value == "/*" || value == "/*/" || value == "/**" || strings.HasPrefix(value, "/*")
}

func parseCCProtectionFilter(w http.ResponseWriter, r *http.Request) (ccProtectionFilter, bool) {
	query := r.URL.Query()
	filter := ccProtectionFilter{}
	var ok bool
	if filter.SiteID, ok = parseApplicationIDQuery(w, query); !ok {
		return ccProtectionFilter{}, false
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
