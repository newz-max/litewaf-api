package httpserver

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"litewaf-api/internal/attackmeta"
	"litewaf-api/internal/model"
)

type attackProtectionRequest struct {
	AttackType string `json:"attack_type"`
	Action     string `json:"action"`
	Enabled    *bool  `json:"enabled"`
	Priority   int    `json:"priority"`
}

func (h handlers) listAttackProtectionGroups(w http.ResponseWriter, r *http.Request) {
	rules, err := h.app.Store.ListRules(r.Context())
	if err != nil {
		h.writeServerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envelope{"items": attackProtectionGroupsFromRules(rules)})
}

func (h handlers) updateAttackProtectionGroup(w http.ResponseWriter, r *http.Request) {
	attackType := strings.ToLower(strings.TrimSpace(r.PathValue("attack_type")))
	var req attackProtectionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.AttackType = attackType
	req.normalize()
	if err := req.validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	rules, err := h.app.Store.ListRules(r.Context())
	if err != nil {
		h.writeServerError(w, err)
		return
	}
	matched := false
	for _, rule := range rules {
		rule = attackmeta.NormalizeRule(rule)
		if rule.Module != attackmeta.Module || rule.Category != attackmeta.Category || rule.AttackType != req.AttackType {
			continue
		}
		matched = true
		rule.Action = req.Action
		rule.Enabled = boolValue(req.Enabled, true)
		rule.Priority = req.Priority
		if rule.Priority == 0 {
			rule.Priority = 100
		}
		rule = attackmeta.NormalizeRule(rule)
		if _, err := h.app.Store.UpdateRule(r.Context(), rule.ID, rule); err != nil {
			h.audit(r, "update", "attack_protection_group", 0, "failure", err)
			h.writeKnownError(w, err)
			return
		}
	}
	if !matched {
		err := errors.New("attack protection group not found")
		h.audit(r, "update", "attack_protection_group", 0, "failure", err)
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	rules, err = h.app.Store.ListRules(r.Context())
	if err != nil {
		h.writeServerError(w, err)
		return
	}
	groups := attackProtectionGroupsFromRules(rules)
	for _, group := range groups {
		if group.AttackType == req.AttackType {
			h.audit(r, "update", "attack_protection_group", 0, "success", nil)
			writeJSON(w, http.StatusOK, envelope{"item": group})
			return
		}
	}
	writeError(w, http.StatusNotFound, "attack protection group not found")
}

func (r *attackProtectionRequest) normalize() {
	r.AttackType = strings.ToLower(strings.TrimSpace(r.AttackType))
	r.Action = strings.ToLower(strings.TrimSpace(r.Action))
	if r.Action == "" {
		r.Action = "block"
	}
}

func (r attackProtectionRequest) validate() error {
	if !attackmeta.ValidAttackType(r.AttackType) {
		return errors.New("attack protection attack_type is unsupported")
	}
	if !oneOf(r.Action, "log-only", "block") {
		return errors.New("attack protection action must be log-only or block")
	}
	if r.Priority <= 0 {
		return errors.New("attack protection priority must be positive")
	}
	return nil
}

func attackProtectionGroupsFromRules(rules []model.Rule) []model.AttackProtectionGroup {
	groups := map[string]*model.AttackProtectionGroup{}
	for _, raw := range rules {
		rule := attackmeta.NormalizeRule(raw)
		if rule.Module != attackmeta.Module || rule.Category != attackmeta.Category || !attackmeta.ValidAttackType(rule.AttackType) {
			continue
		}
		group := groups[rule.AttackType]
		if group == nil {
			group = &model.AttackProtectionGroup{
				ID:         rule.AttackType,
				Name:       rule.Group,
				Module:     attackmeta.Module,
				Category:   attackmeta.Category,
				AttackType: rule.AttackType,
				Action:     rule.Action,
				Enabled:    true,
				Priority:   rule.Priority,
				Rules:      []model.AttackProtectionRuleRef{},
			}
			groups[rule.AttackType] = group
		}
		group.RuleCount++
		if rule.Enabled {
			group.EnabledRuleCount++
		}
		group.Enabled = group.Enabled && rule.Enabled
		if rule.Priority < group.Priority || group.Priority == 0 {
			group.Priority = rule.Priority
		}
		if group.Action == "" || rule.Action == "block" {
			group.Action = rule.Action
		}
		if rule.UpdatedAt.After(group.UpdatedAt) {
			group.UpdatedAt = rule.UpdatedAt
		}
		group.Rules = append(group.Rules, model.AttackProtectionRuleRef{
			ID:         rule.ID,
			Name:       rule.Name,
			Type:       rule.Type,
			Target:     rule.Target,
			Action:     rule.Action,
			Score:      rule.Score,
			Enabled:    rule.Enabled,
			AttackType: rule.AttackType,
			Group:      rule.Group,
		})
	}
	items := make([]model.AttackProtectionGroup, 0, len(groups))
	for _, group := range groups {
		if group.Name == "" {
			group.Name = attackmeta.GroupName(group.AttackType)
		}
		if group.Action == "" {
			group.Action = "block"
		}
		if group.Priority == 0 {
			group.Priority = 100
		}
		if group.UpdatedAt.IsZero() {
			group.UpdatedAt = time.Time{}
		}
		sort.Slice(group.Rules, func(i, j int) bool { return group.Rules[i].ID < group.Rules[j].ID })
		items = append(items, *group)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Priority == items[j].Priority {
			return items[i].AttackType < items[j].AttackType
		}
		return items[i].Priority < items[j].Priority
	})
	return items
}
