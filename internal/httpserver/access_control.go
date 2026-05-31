package httpserver

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"

	"litewaf-api/internal/model"
	"litewaf-api/internal/publish"
)

const (
	accessControlModule   = "access-control"
	accessControlCategory = "access-control"
)

type accessControlFilter struct {
	SiteID       int64
	Enabled      bool
	EnabledIsSet bool
}

func (h handlers) listAccessControlRules(w http.ResponseWriter, r *http.Request) {
	filter, ok := parseAccessControlFilter(w, r)
	if !ok {
		return
	}
	entries, err := h.app.Store.ListAccessListEntries(r.Context())
	if err != nil {
		h.writeServerError(w, err)
		return
	}
	items := make([]model.ProtectionRule, 0, len(entries))
	for _, entry := range entries {
		rule := accessControlFromAccessList(entry)
		if accessControlMatches(rule, filter) {
			items = append(items, rule)
		}
	}
	writeJSON(w, http.StatusOK, envelope{"items": items})
}

func (h handlers) getAccessControlRule(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	entry, err := h.app.Store.GetAccessListEntry(r.Context(), id)
	if err != nil {
		h.writeKnownError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envelope{"item": accessControlFromAccessList(entry)})
}

func (h handlers) createAccessControlRule(w http.ResponseWriter, r *http.Request) {
	var req accessControlRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	entry, err := req.toAccessList()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	created, err := h.app.Store.CreateAccessListEntry(r.Context(), entry)
	h.audit(r, "create", "access_control_rule", created.ID, resultFromErr(err), err)
	h.writeCreated(w, accessControlFromAccessList(created), err)
}

func (h handlers) updateAccessControlRule(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var req accessControlRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	entry, err := req.toAccessList()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	updated, err := h.app.Store.UpdateAccessListEntry(r.Context(), id, entry)
	h.audit(r, "update", "access_control_rule", id, resultFromErr(err), err)
	h.writeItem(w, accessControlFromAccessList(updated), err)
}

func (h handlers) deleteAccessControlRule(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	err := h.app.Store.DeleteAccessListEntry(r.Context(), id)
	h.audit(r, "delete", "access_control_rule", id, resultFromErr(err), err)
	h.writeNoContent(w, err)
}

type accessControlRequest struct {
	Name     string                     `json:"name"`
	SiteID   int64                      `json:"site_id"`
	Enabled  *bool                      `json:"enabled"`
	Priority int                        `json:"priority"`
	Match    model.ProtectionRuleMatch  `json:"match"`
	Action   model.ProtectionRuleAction `json:"action"`
	Module   string                     `json:"module"`
	Category string                     `json:"category"`
}

func (r accessControlRequest) toAccessList() (model.AccessListEntry, error) {
	r.normalize()
	if err := r.validate(); err != nil {
		return model.AccessListEntry{}, err
	}
	target := r.Match.Target
	value := r.Match.Value
	headerName := r.Match.HeaderName
	operator := r.Match.Operator
	switch target {
	case "path":
		target = "uri"
		value = r.Match.Path
		operator = r.Match.PathMatch
	case "header":
		target = "header"
	case "host":
		target = "host"
		value = r.Match.Host
	}
	kind := "blacklist"
	if r.Action.Type == "allow" {
		kind = "whitelist"
	}
	return model.AccessListEntry{
		Name:          r.Name,
		Kind:          kind,
		Target:        target,
		Value:         value,
		MatchOperator: operator,
		HeaderName:    headerName,
		Action:        accessControlLegacyAction(r.Action.Type),
		SiteID:        r.SiteID,
		Enabled:       boolValue(r.Enabled, true),
		Priority:      accessControlPriority(r.Priority),
	}, nil
}

func (r *accessControlRequest) normalize() {
	r.Name = strings.TrimSpace(r.Name)
	r.Module = strings.TrimSpace(r.Module)
	r.Category = strings.TrimSpace(r.Category)
	r.Match.Target = strings.ToLower(strings.TrimSpace(r.Match.Target))
	r.Match.Value = strings.TrimSpace(r.Match.Value)
	r.Match.Operator = strings.ToLower(strings.TrimSpace(r.Match.Operator))
	r.Match.HeaderName = strings.TrimSpace(r.Match.HeaderName)
	r.Match.Host = strings.ToLower(strings.TrimSpace(r.Match.Host))
	r.Match.Path = strings.TrimSpace(r.Match.Path)
	r.Match.PathMatch = strings.ToLower(strings.TrimSpace(r.Match.PathMatch))
	r.Match.Methods = normalizeHTTPMethods(r.Match.Methods)
	r.Action.Type = strings.ToLower(strings.TrimSpace(r.Action.Type))
	if r.Module == "" {
		r.Module = accessControlModule
	}
	if r.Category == "" {
		r.Category = accessControlCategory
	}
	if r.Match.Target == "" {
		r.Match.Target = inferAccessControlTarget(r.Match)
	}
	if r.Match.Operator == "" {
		r.Match.Operator = "exact"
	}
	if r.Match.PathMatch == "" {
		r.Match.PathMatch = r.Match.Operator
	}
	if r.Action.Type == "" {
		r.Action.Type = "block"
	}
}

func (r accessControlRequest) validate() error {
	if r.Name == "" {
		return errors.New("access control rule name is required")
	}
	if r.Module != accessControlModule {
		return errors.New("access control module must be access-control")
	}
	if r.Category != accessControlCategory {
		return errors.New("access control category must be access-control")
	}
	if r.Priority < 0 {
		return errors.New("access control priority cannot be negative")
	}
	if !oneOf(r.Action.Type, "allow", "log-only", "block") {
		return errors.New("access control action is unsupported")
	}
	for _, method := range r.Match.Methods {
		if !oneOf(method, "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS") {
			return errors.New("access control method is unsupported")
		}
	}
	switch r.Match.Target {
	case "ip":
		if net.ParseIP(r.Match.Value) == nil {
			return errors.New("access control ip value is invalid")
		}
	case "cidr":
		if _, _, err := net.ParseCIDR(r.Match.Value); err != nil {
			return errors.New("access control cidr value is invalid")
		}
	case "path":
		if !strings.HasPrefix(r.Match.Path, "/") {
			return errors.New("access control path must start with /")
		}
		if !oneOf(r.Match.PathMatch, "exact", "prefix") {
			return errors.New("access control path_match must be exact or prefix")
		}
	case "header":
		if r.Match.HeaderName == "" {
			return errors.New("access control header name is required")
		}
		if r.Match.Value == "" {
			return errors.New("access control header value is required")
		}
		if !oneOf(r.Match.Operator, "exact", "contains") {
			return errors.New("access control header operator must be exact or contains")
		}
	case "host":
		if r.Match.Host == "" {
			return errors.New("access control host is required")
		}
		if !oneOf(r.Match.Operator, "exact", "suffix") {
			return errors.New("access control host operator must be exact or suffix")
		}
	default:
		return errors.New("access control target is unsupported")
	}
	return nil
}

func parseAccessControlFilter(w http.ResponseWriter, r *http.Request) (accessControlFilter, bool) {
	query := r.URL.Query()
	filter := accessControlFilter{}
	if value := strings.TrimSpace(query.Get("site_id")); value != "" {
		id, err := strconv.ParseInt(value, 10, 64)
		if err != nil || id < 0 {
			writeError(w, http.StatusBadRequest, "invalid site_id filter")
			return accessControlFilter{}, false
		}
		filter.SiteID = id
	}
	if value := strings.TrimSpace(query.Get("enabled")); value != "" {
		enabled, err := parseBoolFilter(value)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid enabled filter")
			return accessControlFilter{}, false
		}
		filter.Enabled = enabled
		filter.EnabledIsSet = true
	}
	return filter, true
}

func accessControlMatches(rule model.ProtectionRule, filter accessControlFilter) bool {
	if filter.SiteID > 0 && rule.SiteID != filter.SiteID {
		return false
	}
	if filter.EnabledIsSet && rule.Enabled != filter.Enabled {
		return false
	}
	return true
}

func accessControlFromAccessList(item model.AccessListEntry) model.ProtectionRule {
	return publish.AccessControlFromAccessList(item)
}

func inferAccessControlTarget(match model.ProtectionRuleMatch) string {
	switch {
	case match.Path != "":
		return "path"
	case match.HeaderName != "":
		return "header"
	case match.Host != "":
		return "host"
	default:
		return "ip"
	}
}

func accessControlLegacyAction(action string) string {
	switch action {
	case "allow":
		return "allow"
	case "log-only":
		return "log-only"
	default:
		return "block"
	}
}

func accessControlPriority(priority int) int {
	if priority <= 0 {
		return 100
	}
	return priority
}
