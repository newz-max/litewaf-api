package httpserver

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"litewaf-api/internal/model"
	"litewaf-api/internal/publish"
)

const (
	dynamicProtectionModule          = "dynamic-protection"
	dynamicTokenCategory             = "dynamic-token"
	pageMutationCategory             = "page-mutation"
	waitingRoomCategory              = "waiting-room"
	maxDynamicTokenTTL               = 86400
	maxDynamicMutationMaxBytes       = 1048576
	maxDynamicQueueCapacity          = 100000
	maxDynamicWaitingRoomDurationSec = 86400
)

type dynamicProtectionFilter struct {
	SiteID       int64
	Enabled      bool
	EnabledIsSet bool
}

func (h handlers) listDynamicProtectionRules(w http.ResponseWriter, r *http.Request) {
	filter, ok := parseDynamicProtectionFilter(w, r)
	if !ok {
		return
	}
	rules, err := h.app.Store.ListDynamicProtectionRules(r.Context())
	if err != nil {
		h.writeServerError(w, err)
		return
	}
	items := make([]model.ProtectionRule, 0, len(rules))
	for _, item := range rules {
		rule := dynamicProtectionFromRule(item)
		if dynamicProtectionMatches(rule, filter) {
			items = append(items, rule)
		}
	}
	writeJSON(w, http.StatusOK, envelope{"items": items})
}

func (h handlers) getDynamicProtectionRule(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	item, err := h.app.Store.GetDynamicProtectionRule(r.Context(), id)
	if err != nil {
		h.writeKnownError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envelope{"item": dynamicProtectionFromRule(item)})
}

func (h handlers) createDynamicProtectionRule(w http.ResponseWriter, r *http.Request) {
	var req dynamicProtectionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := req.toModel()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	created, err := h.app.Store.CreateDynamicProtectionRule(r.Context(), item)
	h.audit(r, "create", "dynamic_protection_rule", created.ID, resultFromErr(err), err)
	h.writeCreated(w, dynamicProtectionFromRule(created), err)
}

func (h handlers) updateDynamicProtectionRule(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var req dynamicProtectionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := req.toModel()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	updated, err := h.app.Store.UpdateDynamicProtectionRule(r.Context(), id, item)
	h.audit(r, "update", "dynamic_protection_rule", id, resultFromErr(err), err)
	h.writeItem(w, dynamicProtectionFromRule(updated), err)
}

func (h handlers) deleteDynamicProtectionRule(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	err := h.app.Store.DeleteDynamicProtectionRule(r.Context(), id)
	h.audit(r, "delete", "dynamic_protection_rule", id, resultFromErr(err), err)
	h.writeNoContent(w, err)
}

type dynamicProtectionRequest struct {
	Name     string                       `json:"name"`
	SiteID   int64                        `json:"site_id"`
	Enabled  *bool                        `json:"enabled"`
	Priority int                          `json:"priority"`
	Match    model.ProtectionRuleMatch    `json:"match"`
	Dynamic  *model.ProtectionRuleDynamic `json:"dynamic"`
	Action   model.ProtectionRuleAction   `json:"action"`
	Module   string                       `json:"module"`
	Category string                       `json:"category"`
}

func (r dynamicProtectionRequest) toModel() (model.DynamicProtectionRule, error) {
	r.normalize()
	if err := r.validate(); err != nil {
		return model.DynamicProtectionRule{}, err
	}
	return model.DynamicProtectionRule{
		Name:             r.Name,
		Category:         r.Category,
		Path:             r.Match.Path,
		PathMatch:        r.Match.PathMatch,
		Methods:          cloneStrings(r.Match.Methods),
		TokenTTL:         r.Dynamic.TokenTTL,
		TokenPlacement:   r.Dynamic.TokenPlacement,
		FailureAction:    r.Dynamic.FailureAction,
		MutationMarker:   r.Dynamic.MutationMarker,
		MutationMaxBytes: r.Dynamic.MutationMaxBytes,
		QueueCapacity:    r.Dynamic.QueueCapacity,
		AdmissionTTL:     r.Dynamic.AdmissionTTL,
		RetryInterval:    r.Dynamic.RetryInterval,
		OverflowAction:   r.Dynamic.OverflowAction,
		SiteID:           r.SiteID,
		Enabled:          boolValue(r.Enabled, true),
		Priority:         protectionRequestPriority(r.Priority),
	}, nil
}

func (r *dynamicProtectionRequest) normalize() {
	r.Name = strings.TrimSpace(r.Name)
	r.Module = strings.TrimSpace(r.Module)
	r.Category = strings.ToLower(strings.TrimSpace(r.Category))
	r.Match.Path = strings.TrimSpace(r.Match.Path)
	r.Match.PathMatch = strings.ToLower(strings.TrimSpace(r.Match.PathMatch))
	r.Match.Methods = normalizeHTTPMethods(r.Match.Methods)
	r.Action.Type = strings.ToLower(strings.TrimSpace(r.Action.Type))
	if r.Dynamic == nil {
		r.Dynamic = &model.ProtectionRuleDynamic{}
	}
	r.Dynamic.Mode = strings.ToLower(strings.TrimSpace(r.Dynamic.Mode))
	r.Dynamic.TokenPlacement = strings.ToLower(strings.TrimSpace(r.Dynamic.TokenPlacement))
	r.Dynamic.FailureAction = strings.ToLower(strings.TrimSpace(r.Dynamic.FailureAction))
	r.Dynamic.MutationMarker = strings.ToLower(strings.TrimSpace(r.Dynamic.MutationMarker))
	r.Dynamic.OverflowAction = strings.ToLower(strings.TrimSpace(r.Dynamic.OverflowAction))
	if r.Module == "" {
		r.Module = dynamicProtectionModule
	}
	if r.Category == "" {
		r.Category = dynamicTokenCategory
	}
	if r.Match.Path == "" {
		r.Match.Path = "/"
	}
	if r.Match.PathMatch == "" {
		r.Match.PathMatch = "prefix"
	}
	if r.Dynamic.Mode == "" {
		r.Dynamic.Mode = r.Category
	}
	if r.Dynamic.TokenPlacement == "" {
		r.Dynamic.TokenPlacement = "cookie"
	}
	if r.Dynamic.FailureAction == "" {
		r.Dynamic.FailureAction = "block"
	}
	if r.Dynamic.MutationMarker == "" {
		r.Dynamic.MutationMarker = "body-end"
	}
	if r.Dynamic.OverflowAction == "" {
		r.Dynamic.OverflowAction = "waiting-room"
	}
	if r.Action.Type == "" {
		if r.Category == waitingRoomCategory {
			r.Action.Type = r.Dynamic.OverflowAction
		} else {
			r.Action.Type = r.Dynamic.FailureAction
		}
	}
}

func (r dynamicProtectionRequest) validate() error {
	if r.Name == "" {
		return errors.New("dynamic protection rule name is required")
	}
	if r.Module != dynamicProtectionModule {
		return errors.New("dynamic protection module must be dynamic-protection")
	}
	if !oneOf(r.Category, dynamicTokenCategory, pageMutationCategory, waitingRoomCategory) {
		return errors.New("dynamic protection category is unsupported")
	}
	if r.Priority < 0 {
		return errors.New("dynamic protection priority cannot be negative")
	}
	if !strings.HasPrefix(r.Match.Path, "/") {
		return errors.New("dynamic protection path must start with /")
	}
	if !oneOf(r.Match.PathMatch, "exact", "prefix") {
		return errors.New("dynamic protection path_match must be exact or prefix")
	}
	for _, method := range r.Match.Methods {
		if !oneOf(method, "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS") {
			return errors.New("dynamic protection method is unsupported")
		}
	}
	if r.Dynamic == nil {
		return errors.New("dynamic protection config is required")
	}
	if r.Dynamic.Mode != "" && r.Dynamic.Mode != r.Category {
		return errors.New("dynamic protection mode must match category")
	}
	switch r.Category {
	case dynamicTokenCategory:
		return validateDynamicTokenRequest(r)
	case pageMutationCategory:
		return validateDynamicMutationRequest(r)
	case waitingRoomCategory:
		return validateDynamicWaitingRoomRequest(r)
	}
	return nil
}

func validateDynamicTokenRequest(r dynamicProtectionRequest) error {
	if r.Dynamic.TokenTTL <= 0 || r.Dynamic.TokenTTL > maxDynamicTokenTTL {
		return errors.New("dynamic protection token_ttl_sec is invalid")
	}
	if !oneOf(r.Dynamic.TokenPlacement, "cookie", "header", "query") {
		return errors.New("dynamic protection token_placement is unsupported")
	}
	if !oneOf(r.Dynamic.FailureAction, "log-only", "block") {
		return errors.New("dynamic protection failure_action is unsupported")
	}
	if !oneOf(r.Action.Type, "", r.Dynamic.FailureAction) {
		return errors.New("dynamic protection action must match failure_action")
	}
	return nil
}

func validateDynamicMutationRequest(r dynamicProtectionRequest) error {
	if !oneOf(r.Dynamic.MutationMarker, "head-end", "body-end") {
		return errors.New("dynamic protection mutation_marker is unsupported")
	}
	if r.Dynamic.MutationMaxBytes <= 0 || r.Dynamic.MutationMaxBytes > maxDynamicMutationMaxBytes {
		return errors.New("dynamic protection mutation_max_bytes is invalid")
	}
	if !oneOf(r.Action.Type, "log-only", "allow") {
		return errors.New("dynamic protection mutation action is unsupported")
	}
	return nil
}

func validateDynamicWaitingRoomRequest(r dynamicProtectionRequest) error {
	if r.Dynamic.QueueCapacity <= 0 || r.Dynamic.QueueCapacity > maxDynamicQueueCapacity {
		return errors.New("dynamic protection queue_capacity is invalid")
	}
	if r.Dynamic.AdmissionTTL <= 0 || r.Dynamic.AdmissionTTL > maxDynamicWaitingRoomDurationSec {
		return errors.New("dynamic protection admission_ttl_sec is invalid")
	}
	if r.Dynamic.RetryInterval <= 0 || r.Dynamic.RetryInterval > maxDynamicWaitingRoomDurationSec {
		return errors.New("dynamic protection retry_interval_sec is invalid")
	}
	if !oneOf(r.Dynamic.OverflowAction, "waiting-room", "block", "log-only") {
		return errors.New("dynamic protection overflow_action is unsupported")
	}
	if !oneOf(r.Action.Type, "", r.Dynamic.OverflowAction) {
		return errors.New("dynamic protection action must match overflow_action")
	}
	return nil
}

func parseDynamicProtectionFilter(w http.ResponseWriter, r *http.Request) (dynamicProtectionFilter, bool) {
	query := r.URL.Query()
	filter := dynamicProtectionFilter{}
	if value := strings.TrimSpace(query.Get("site_id")); value != "" {
		id, err := strconv.ParseInt(value, 10, 64)
		if err != nil || id < 0 {
			writeError(w, http.StatusBadRequest, "invalid site_id filter")
			return dynamicProtectionFilter{}, false
		}
		filter.SiteID = id
	}
	if value := strings.TrimSpace(query.Get("enabled")); value != "" {
		enabled, err := parseBoolFilter(value)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid enabled filter")
			return dynamicProtectionFilter{}, false
		}
		filter.Enabled = enabled
		filter.EnabledIsSet = true
	}
	return filter, true
}

func dynamicProtectionMatches(rule model.ProtectionRule, filter dynamicProtectionFilter) bool {
	if filter.SiteID > 0 && rule.SiteID != filter.SiteID {
		return false
	}
	if filter.EnabledIsSet && rule.Enabled != filter.Enabled {
		return false
	}
	return true
}

func dynamicProtectionFromRule(item model.DynamicProtectionRule) model.ProtectionRule {
	return publish.DynamicProtectionFromRule(item)
}
