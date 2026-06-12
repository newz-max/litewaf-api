package httpserver

import (
	"errors"
	"net/http"
	"strings"

	"litewaf-api/internal/model"
	"litewaf-api/internal/protectionrules"
	"litewaf-api/internal/publish"
	"litewaf-api/internal/store"
)

const (
	uploadProtectionModule   = "upload-protection"
	uploadProtectionCategory = "upload"
)

type uploadProtectionFilter struct {
	SiteID       int64
	Enabled      bool
	EnabledIsSet bool
}

func (h handlers) listUploadProtectionRules(w http.ResponseWriter, r *http.Request) {
	filter, ok := parseUploadProtectionFilter(w, r)
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
		if rule.Module != uploadProtectionModule {
			continue
		}
		seenLegacy[rule.LegacyRef] = true
		if uploadProtectionMatches(rule, filter) {
			items = append(items, rule)
		}
	}
	rules, err := h.app.Store.ListUploadProtectionRules(r.Context())
	if err != nil {
		h.writeServerError(w, err)
		return
	}
	for _, item := range rules {
		if seenLegacy[protectionrules.LegacyRef("upload_protection_rules", item.ID)] {
			continue
		}
		rule := uploadProtectionFromRule(item)
		if uploadProtectionMatches(rule, filter) {
			items = append(items, rule)
		}
	}
	writeJSON(w, http.StatusOK, envelope{"items": items})
}

func (h handlers) getUploadProtectionRule(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	item, err := h.app.Store.GetProtectionRule(r.Context(), id)
	if err != nil {
		legacy, legacyErr := h.app.Store.GetUploadProtectionRule(r.Context(), id)
		if legacyErr != nil {
			h.writeKnownError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, envelope{"item": uploadProtectionFromRule(legacy)})
		return
	}
	if item.Module != uploadProtectionModule {
		h.writeKnownError(w, store.ErrNotFound)
		return
	}
	writeJSON(w, http.StatusOK, envelope{"item": item})
}

func (h handlers) createUploadProtectionRule(w http.ResponseWriter, r *http.Request) {
	var req uploadProtectionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := req.toProtectionRule()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	created, err := h.app.Store.CreateProtectionRule(r.Context(), item)
	h.audit(r, "create", "upload_protection_rule", created.ID, resultFromErr(err), err)
	h.writeCreated(w, created, err)
}

func (h handlers) updateUploadProtectionRule(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var req uploadProtectionRequest
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
		legacy, legacyErr := h.app.Store.UpdateUploadProtectionRule(r.Context(), id, protectionrules.ToUpload(item))
		if legacyErr == nil {
			updated = uploadProtectionFromRule(legacy)
		}
		err = legacyErr
	}
	h.audit(r, "update", "upload_protection_rule", id, resultFromErr(err), err)
	h.writeItem(w, updated, err)
}

func (h handlers) deleteUploadProtectionRule(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	err := h.app.Store.DeleteProtectionRule(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		err = h.app.Store.DeleteUploadProtectionRule(r.Context(), id)
	}
	h.audit(r, "delete", "upload_protection_rule", id, resultFromErr(err), err)
	h.writeNoContent(w, err)
}

type uploadProtectionRequest struct {
	Name         string                      `json:"name"`
	SiteID       int64                       `json:"application_id"`
	LegacySiteID int64                       `json:"site_id"`
	Enabled      *bool                       `json:"enabled"`
	Priority     int                         `json:"priority"`
	Match        model.ProtectionRuleMatch   `json:"match"`
	Upload       *model.ProtectionRuleUpload `json:"upload"`
	Action       model.ProtectionRuleAction  `json:"action"`
	Module       string                      `json:"module"`
	Category     string                      `json:"category"`
}

func (r uploadProtectionRequest) toModel() (model.UploadProtectionRule, error) {
	rule, err := r.toProtectionRule()
	if err != nil {
		return model.UploadProtectionRule{}, err
	}
	return protectionrules.ToUpload(rule), nil
}

func (r uploadProtectionRequest) toProtectionRule() (model.ProtectionRule, error) {
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
		Upload:   r.Upload,
		Action:   r.Action,
		Source:   protectionrules.SourceNative,
	}, nil
}

func (r *uploadProtectionRequest) normalize() {
	if r.SiteID == 0 {
		r.SiteID = r.LegacySiteID
	}
	r.Name = strings.TrimSpace(r.Name)
	r.Module = strings.TrimSpace(r.Module)
	r.Category = strings.TrimSpace(r.Category)
	r.Match.Path = strings.TrimSpace(r.Match.Path)
	r.Match.PathMatch = strings.ToLower(strings.TrimSpace(r.Match.PathMatch))
	r.Match.Methods = normalizeHTTPMethods(r.Match.Methods)
	r.Action.Type = strings.ToLower(strings.TrimSpace(r.Action.Type))
	if r.Upload == nil {
		r.Upload = &model.ProtectionRuleUpload{}
	}
	r.Upload.Extensions = normalizeUploadExtensions(r.Upload.Extensions)
	if r.Module == "" {
		r.Module = uploadProtectionModule
	}
	if r.Category == "" {
		r.Category = uploadProtectionCategory
	}
	if r.Match.Path == "" {
		r.Match.Path = "/"
	}
	if r.Match.PathMatch == "" {
		r.Match.PathMatch = "prefix"
	}
	if r.Action.Type == "" {
		r.Action.Type = "block"
	}
}

func (r uploadProtectionRequest) validate() error {
	if r.Name == "" {
		return errors.New("upload protection rule name is required")
	}
	if r.Module != uploadProtectionModule {
		return errors.New("upload protection module must be upload-protection")
	}
	if r.Category != uploadProtectionCategory {
		return errors.New("upload protection category must be upload")
	}
	if r.Priority < 0 {
		return errors.New("upload protection priority cannot be negative")
	}
	if err := protectionrules.ValidatePathMatch("upload protection", r.Match.PathMatch, r.Match.Path); err != nil {
		return errors.New(err.Error())
	}
	for _, method := range r.Match.Methods {
		if !oneOf(method, "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS") {
			return errors.New("upload protection method is unsupported")
		}
	}
	if len(r.Upload.Extensions) == 0 && r.Upload.MaxBytes <= 0 {
		return errors.New("upload protection requires extensions or max_bytes")
	}
	for _, extension := range r.Upload.Extensions {
		if extension == "" || strings.ContainsAny(extension, `/\`) || strings.Contains(extension, "..") {
			return errors.New("upload protection extension is invalid")
		}
	}
	if r.Upload.MaxBytes < 0 {
		return errors.New("upload protection max_bytes cannot be negative")
	}
	if !oneOf(r.Action.Type, "log-only", "block") {
		return errors.New("upload protection action is unsupported")
	}
	return nil
}

func parseUploadProtectionFilter(w http.ResponseWriter, r *http.Request) (uploadProtectionFilter, bool) {
	query := r.URL.Query()
	filter := uploadProtectionFilter{}
	var ok bool
	if filter.SiteID, ok = parseApplicationIDQuery(w, query); !ok {
		return uploadProtectionFilter{}, false
	}
	if value := strings.TrimSpace(query.Get("enabled")); value != "" {
		enabled, err := parseBoolFilter(value)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid enabled filter")
			return uploadProtectionFilter{}, false
		}
		filter.Enabled = enabled
		filter.EnabledIsSet = true
	}
	return filter, true
}

func uploadProtectionMatches(rule model.ProtectionRule, filter uploadProtectionFilter) bool {
	if filter.SiteID > 0 && rule.SiteID != filter.SiteID {
		return false
	}
	if filter.EnabledIsSet && rule.Enabled != filter.Enabled {
		return false
	}
	return true
}

func uploadProtectionFromRule(item model.UploadProtectionRule) model.ProtectionRule {
	return publish.UploadProtectionFromRule(item)
}

func normalizeUploadExtensions(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		item := strings.ToLower(strings.TrimSpace(value))
		item = strings.TrimPrefix(item, ".")
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func protectionRequestPriority(priority int) int {
	if priority <= 0 {
		return 100
	}
	return priority
}
