package httpserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"litewaf-api/internal/app"
	"litewaf-api/internal/attackmeta"
	"litewaf-api/internal/auth"
	"litewaf-api/internal/defaults"
	"litewaf-api/internal/model"
	"litewaf-api/internal/publish"
	"litewaf-api/internal/rulepkg"
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

func (h handlers) login(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	username := strings.TrimSpace(input.Username)
	user, err := h.app.Store.GetUserByUsername(r.Context(), username)
	if err != nil || !user.Enabled || !auth.VerifyPassword(user.PasswordHash, input.Password) {
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	token, expires, err := auth.IssueToken(h.app.Config.AuthTokenSecret, user.Username, user.ID, user.Role, h.app.Config.AuthTokenTTL)
	if err != nil {
		h.writeServerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envelope{
		"access_token": token,
		"expires_at":   expires.Format(time.RFC3339),
		"user": envelope{
			"id":       user.ID,
			"username": user.Username,
			"role":     user.Role,
		},
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
	h.audit(r, "create", "site", item.ID, resultFromErr(err), err)
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
	h.audit(r, "update", "site", id, resultFromErr(err), err)
	h.writeItem(w, item, err)
}

func (h handlers) deleteSite(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	err := h.app.Store.DeleteSite(r.Context(), id)
	h.audit(r, "delete", "site", id, resultFromErr(err), err)
	h.writeNoContent(w, err)
}

func (h handlers) listRules(w http.ResponseWriter, r *http.Request) {
	items, err := h.app.Store.ListRules(r.Context())
	for i := range items {
		items[i] = rulepkg.EvaluateRuleExportEligibility(items[i])
	}
	h.writeList(w, items, err)
}

func (h handlers) listRulePackages(w http.ResponseWriter, r *http.Request) {
	rules, err := h.app.Store.ListRules(r.Context())
	if err != nil {
		h.writeServerError(w, err)
		return
	}
	items := rulepkg.PackagesFromRules(rules)
	if len(items) == 0 {
		items = append(items, defaults.DefaultRulePackage().Metadata)
	}
	writeJSON(w, http.StatusOK, envelope{"items": items})
}

func (h handlers) getRulePackage(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	rules, err := h.app.Store.ListRules(r.Context())
	if err != nil {
		h.writeServerError(w, err)
		return
	}
	for _, item := range rulepkg.PackagesFromRules(rules) {
		if item.ID == id {
			writeJSON(w, http.StatusOK, envelope{"item": item})
			return
		}
	}
	if id == defaults.RulePackageID {
		writeJSON(w, http.StatusOK, envelope{"item": defaults.DefaultRulePackage().Metadata})
		return
	}
	writeError(w, http.StatusNotFound, "resource not found")
}

func (h handlers) previewRulePackage(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Package json.RawMessage `json:"package"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	data := []byte(input.Package)
	if len(data) == 0 {
		data = defaults.DefaultRulePackageJSON()
	}
	trustKeys, _ := h.app.Store.ListRuleTrustKeys(r.Context())
	preview, err := rulepkg.PreviewWithTrustKeys(r.Context(), h.app.Store, data, trustKeys)
	h.audit(r, "preview", "rule_package", 0, resultFromErr(err), err)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, envelope{"item": preview})
}

func (h handlers) importRulePackage(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Package json.RawMessage `json:"package"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	data := []byte(input.Package)
	if len(data) == 0 {
		data = defaults.DefaultRulePackageJSON()
	}
	trustKeys, _ := h.app.Store.ListRuleTrustKeys(r.Context())
	result, err := rulepkg.ImportWithTrustKeys(r.Context(), h.app.Store, data, trustKeys)
	h.audit(r, "import", "rule_package", 0, resultFromErr(err), err)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, envelope{"item": result})
}

func (h handlers) deleteRulePackage(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	rules, err := h.app.Store.ListRules(r.Context())
	if err != nil {
		h.writeServerError(w, err)
		return
	}
	for _, rule := range rules {
		if rule.PackageID == id {
			if err := h.app.Store.DeleteRule(r.Context(), rule.ID); err != nil {
				h.audit(r, "delete", "rule_package", 0, "failure", err)
				h.writeKnownError(w, err)
				return
			}
		}
	}
	h.audit(r, "delete", "rule_package", 0, "success", nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h handlers) testRule(w http.ResponseWriter, r *http.Request) {
	var input model.RuleTestRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	rule := input.Rule
	if input.RuleID > 0 {
		item, err := h.app.Store.GetRule(r.Context(), input.RuleID)
		if err != nil {
			h.writeKnownError(w, err)
			return
		}
		rule = item
	}
	result, err := rulepkg.TestRule(rule, input.Sample)
	if err != nil {
		h.audit(r, "test", "rule", rule.ID, "failure", err)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if rule.ID > 0 {
		_, err = h.app.Store.UpdateRule(r.Context(), rule.ID, rulepkg.MarkTested(rule, result))
	}
	h.audit(r, "test", "rule", rule.ID, resultFromErr(err), err)
	if err != nil {
		h.writeServerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envelope{"item": result})
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
	input = attackmeta.NormalizeRule(input)
	if err := validateRule(input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	item, err := h.app.Store.CreateRule(r.Context(), input)
	h.audit(r, "create", "rule", item.ID, resultFromErr(err), err)
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
	input = attackmeta.NormalizeRule(input)
	if err := validateRule(input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	item, err := h.app.Store.UpdateRule(r.Context(), id, input)
	h.audit(r, "update", "rule", id, resultFromErr(err), err)
	h.writeItem(w, item, err)
}

func (h handlers) deleteRule(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	err := h.app.Store.DeleteRule(r.Context(), id)
	h.audit(r, "delete", "rule", id, resultFromErr(err), err)
	h.writeNoContent(w, err)
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
	h.audit(r, "create", "policy", item.ID, resultFromErr(err), err)
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
	h.audit(r, "update", "policy", id, resultFromErr(err), err)
	h.writeItem(w, item, err)
}

func (h handlers) deletePolicy(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	err := h.app.Store.DeletePolicy(r.Context(), id)
	h.audit(r, "delete", "policy", id, resultFromErr(err), err)
	h.writeNoContent(w, err)
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
	operator := currentActor(r).Username
	if operator == "" || operator == "anonymous" {
		operator = strings.TrimSpace(input.Operator)
	}
	if operator == "" {
		operator = h.app.Config.PublishOperator
	}
	next, err := h.app.Store.NextPublishVersion(r.Context())
	if err != nil {
		h.writeServerError(w, err)
		return
	}
	version := fmt.Sprintf("ruleset-%04d", next)
	_, payload, checksum, err := publish.GenerateExtended(r.Context(), h.app.Store, version)
	if err != nil {
		h.audit(r, "publish", "release", 0, "failure", err)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := publish.WriteAtomic(h.app.Config.GatewayConfigPath, payload); err != nil {
		h.audit(r, "publish", "release", 0, "failure", err)
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
		ConfigJSON: string(payload),
	})
	h.audit(r, "publish", "release", record.ID, resultFromErr(err), err)
	h.writeCreated(w, record, err)
}

func (h handlers) previewRelease(w http.ResponseWriter, r *http.Request) {
	if err := publish.Validate(r.Context(), h.app.Store); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	sites, _ := h.app.Store.ListSites(r.Context())
	rules, _ := h.app.Store.ListRules(r.Context())
	policies, _ := h.app.Store.ListPolicies(r.Context())
	accessLists, _ := h.app.Store.ListAccessListEntries(r.Context())
	rateLimits, _ := h.app.Store.ListRateLimitRules(r.Context())
	uploadRules, _ := h.app.Store.ListUploadProtectionRules(r.Context())
	botRules, _ := h.app.Store.ListBotProtectionRules(r.Context())
	dynamicRules, _ := h.app.Store.ListDynamicProtectionRules(r.Context())
	catalogs, _ := h.app.Store.ListRuleCatalogSources(r.Context())
	catalogPackages, _ := h.app.Store.ListRuleCatalogPackages(r.Context(), 0)
	trustKeys, _ := h.app.Store.ListRuleTrustKeys(r.Context())
	ccSummary := ccProtectionSummary(rateLimits)
	accessControlSummary := accessControlSummary(accessLists)
	attackSummary := attackProtectionSummary(rules)
	uploadSummary := uploadProtectionSummary(uploadRules)
	botSummary := botProtectionSummary(botRules)
	dynamicSummary := dynamicProtectionSummary(dynamicRules)
	ecosystemSummary := ruleEcosystemSummary(rules, catalogs, catalogPackages, trustKeys)
	writeJSON(w, http.StatusOK, envelope{
		"summary": envelope{
			"sites":               len(sites),
			"rules":               len(rules),
			"policies":            len(policies),
			"access_lists":        len(accessLists),
			"access_control":      accessControlSummary,
			"rate_limits":         len(rateLimits),
			"cc_protection":       ccSummary,
			"attack_protection":   attackSummary,
			"upload_protection":   uploadSummary,
			"bot_protection":      botSummary,
			"dynamic_protection":  dynamicSummary,
			"rule_ecosystem":      ecosystemSummary,
			"advanced_protection": countAdvancedProtection(policies, rules, rateLimits),
		},
	})
}

func ruleEcosystemSummary(rules []model.Rule, catalogs []model.RuleCatalogSource, catalogPackages []model.RuleCatalogPackage, trustKeys []model.RuleTrustKey) envelope {
	packages := rulepkg.PackagesFromRules(rules)
	signatures := map[string]int{}
	disabledImported := 0
	untestedBlocking := 0
	pendingUpdates := 0
	remoteOriginPackages := map[string]bool{}
	warnings := []string{}
	for _, rule := range rules {
		if rule.PackageID == "" {
			continue
		}
		status := rule.SignatureStatus
		if status == "" {
			status = rulepkg.SignatureUnsigned
		}
		signatures[status]++
		if !rule.Enabled {
			disabledImported++
		}
		if rule.Enabled && rule.Action == "block" && rule.LastTestStatus != rulepkg.TestPassed {
			untestedBlocking++
			warnings = append(warnings, fmt.Sprintf("导入规则 %s 使用阻断动作但尚未通过规则测试", rule.Name))
		}
		if status != rulepkg.SignatureVerified {
			warnings = append(warnings, fmt.Sprintf("规则 %s 来源包签名状态为 %s", rule.Name, status))
		}
		if rule.RemoteCatalogID != "" {
			remoteOriginPackages[rule.PackageID] = true
		}
		if rule.PendingUpdateState == rulepkg.UpdatePending {
			pendingUpdates++
			warnings = append(warnings, fmt.Sprintf("规则 %s 来源包存在待审核更新", rule.Name))
		}
	}
	for _, item := range catalogPackages {
		status := item.SignatureStatus
		if status == "" {
			status = rulepkg.SignatureUnsigned
		}
		signatures[status] += 0
		if status == rulepkg.SignatureRevokedKey || status == rulepkg.SignatureExpired || status == rulepkg.SignatureInvalid || status == rulepkg.SignatureUntrustedKey {
			warnings = append(warnings, fmt.Sprintf("目录包 %s@%s 信任状态为 %s", item.PackageID, item.Version, status))
		}
	}
	for _, key := range trustKeys {
		if key.Revoked {
			warnings = append(warnings, fmt.Sprintf("信任密钥 %s 已撤销", key.KeyID))
		}
		if !key.ExpiresAt.IsZero() && time.Now().UTC().After(key.ExpiresAt) {
			warnings = append(warnings, fmt.Sprintf("信任密钥 %s 已过期", key.KeyID))
		}
	}
	packageIDs := make([]string, 0, len(packages))
	for _, item := range packages {
		packageIDs = append(packageIDs, item.ID+"@"+item.Version)
	}
	return envelope{
		"packages":               len(packages),
		"package_ids":            packageIDs,
		"signature_status":       signatures,
		"disabled_imported":      disabledImported,
		"untested_blocking":      untestedBlocking,
		"catalog_sources":        len(catalogs),
		"catalog_packages":       len(catalogPackages),
		"remote_origin_packages": len(remoteOriginPackages),
		"pending_updates":        pendingUpdates,
		"warnings":               warnings,
		"gateway_hot_path":       "published-rules-only",
		"remote_sync_enabled":    len(catalogs) > 0,
	}
}

func accessControlSummary(accessLists []model.AccessListEntry) envelope {
	enabled := 0
	allow := 0
	block := 0
	logOnly := 0
	warnings := []string{}
	for _, item := range accessLists {
		if !item.Enabled {
			continue
		}
		enabled++
		rule := publish.AccessControlFromAccessList(item)
		switch rule.Action.Type {
		case "allow":
			allow++
			if rule.Match.Target == "ip" && (rule.Match.Value == "0.0.0.0" || rule.Match.Value == "::") {
				warnings = append(warnings, fmt.Sprintf("规则 %s 使用较宽泛的来源放行", rule.Name))
			}
			if rule.Match.Target == "path" && rule.Match.Path == "/" && rule.Match.PathMatch == "prefix" {
				warnings = append(warnings, fmt.Sprintf("规则 %s 对全站路径使用放行动作", rule.Name))
			}
		case "log-only":
			logOnly++
		case "block":
			block++
		}
	}
	return envelope{
		"rules":    len(accessLists),
		"enabled":  enabled,
		"allow":    allow,
		"block":    block,
		"log_only": logOnly,
		"warnings": warnings,
	}
}

func ccProtectionSummary(rateLimits []model.RateLimitRule) envelope {
	enabled := 0
	warnings := []string{}
	for _, item := range rateLimits {
		if item.Enabled {
			enabled++
			rule := publish.CCProtectionFromRateLimit(item)
			if rule.Match.Path == "/" && rule.Match.PathMatch == "prefix" && rule.Limit.Threshold > 0 && rule.Limit.Threshold < 60 && rule.Limit.WindowSec <= 60 {
				warnings = append(warnings, fmt.Sprintf("规则 %s 对全站路径使用较低阈值", rule.Name))
			}
		}
	}
	return envelope{
		"rules":    len(rateLimits),
		"enabled":  enabled,
		"warnings": warnings,
	}
}

func attackProtectionSummary(rules []model.Rule) envelope {
	groups := attackProtectionGroupsFromRules(rules)
	enabled := 0
	observe := 0
	block := 0
	attackTypes := []string{}
	for _, group := range groups {
		attackTypes = append(attackTypes, group.AttackType)
		if group.Enabled {
			enabled++
		}
		switch group.Action {
		case "log-only":
			observe++
		case "block":
			block++
		}
	}
	return envelope{
		"groups":       len(groups),
		"enabled":      enabled,
		"observe":      observe,
		"block":        block,
		"attack_types": attackTypes,
	}
}

func uploadProtectionSummary(rules []model.UploadProtectionRule) envelope {
	enabled := 0
	extensionRules := 0
	sizeRules := 0
	block := 0
	logOnly := 0
	warnings := []string{}
	for _, item := range rules {
		if !item.Enabled {
			continue
		}
		enabled++
		if len(item.Extensions) > 0 {
			extensionRules++
		}
		if item.MaxBytes > 0 {
			sizeRules++
			if item.MaxBytes < 1024*1024 {
				warnings = append(warnings, fmt.Sprintf("规则 %s 使用较小上传大小限制", item.Name))
			}
		}
		switch item.Action {
		case "log-only":
			logOnly++
		case "block":
			block++
			if item.Path == "/" && item.PathMatch == "prefix" {
				warnings = append(warnings, fmt.Sprintf("规则 %s 对全站上传使用阻断动作", item.Name))
			}
		}
	}
	return envelope{
		"rules":           len(rules),
		"enabled":         enabled,
		"extension_rules": extensionRules,
		"size_rules":      sizeRules,
		"block":           block,
		"log_only":        logOnly,
		"warnings":        warnings,
	}
}

func botProtectionSummary(rules []model.BotProtectionRule) envelope {
	enabled := 0
	challenges := 0
	block := 0
	logOnly := 0
	warnings := []string{}
	for _, item := range rules {
		if !item.Enabled {
			continue
		}
		enabled++
		if item.ChallengeMode == "js-challenge" {
			challenges++
		}
		switch item.FailureAction {
		case "log-only":
			logOnly++
		case "block":
			block++
			if item.Path == "/" && item.PathMatch == "prefix" {
				warnings = append(warnings, fmt.Sprintf("规则 %s 对全站路径启用 JS Challenge 阻断", item.Name))
			}
			if len(item.Methods) == 0 {
				warnings = append(warnings, fmt.Sprintf("规则 %s 对全部方法启用 JS Challenge 阻断", item.Name))
			}
		}
	}
	return envelope{
		"rules":      len(rules),
		"enabled":    enabled,
		"challenges": challenges,
		"block":      block,
		"log_only":   logOnly,
		"warnings":   warnings,
	}
}

func dynamicProtectionSummary(rules []model.DynamicProtectionRule) envelope {
	enabled := 0
	dynamicTokens := 0
	pageMutations := 0
	waitingRooms := 0
	block := 0
	logOnly := 0
	waitingRoomAction := 0
	warnings := []string{}
	for _, item := range rules {
		if !item.Enabled {
			continue
		}
		enabled++
		switch item.Category {
		case "dynamic-token":
			dynamicTokens++
			switch item.FailureAction {
			case "block":
				block++
				if item.Path == "/" && item.PathMatch == "prefix" {
					warnings = append(warnings, fmt.Sprintf("规则 %s 对全站路径启用动态令牌阻断", item.Name))
				}
				if len(item.Methods) == 0 {
					warnings = append(warnings, fmt.Sprintf("规则 %s 对全部方法启用动态令牌阻断", item.Name))
				}
			case "log-only":
				logOnly++
			}
		case "page-mutation":
			pageMutations++
			logOnly++
			if item.Path == "/" && item.PathMatch == "prefix" {
				warnings = append(warnings, fmt.Sprintf("规则 %s 对全站 HTML 响应启用页面动态化", item.Name))
			}
		case "waiting-room":
			waitingRooms++
			switch item.OverflowAction {
			case "waiting-room":
				waitingRoomAction++
				if item.Path == "/" && item.PathMatch == "prefix" && item.QueueCapacity < 50 {
					warnings = append(warnings, fmt.Sprintf("规则 %s 对全站使用较低等候室容量", item.Name))
				}
			case "block":
				block++
			case "log-only":
				logOnly++
			}
		}
	}
	return envelope{
		"rules":               len(rules),
		"enabled":             enabled,
		"dynamic_tokens":      dynamicTokens,
		"page_mutations":      pageMutations,
		"waiting_rooms":       waitingRooms,
		"block":               block,
		"log_only":            logOnly,
		"waiting_room_action": waitingRoomAction,
		"warnings":            warnings,
	}
}

func (h handlers) rollbackRelease(w http.ResponseWriter, r *http.Request) {
	version := strings.TrimSpace(r.PathValue("version"))
	record, err := h.app.Store.GetPublishRecordByVersion(r.Context(), version)
	if err != nil || record.Status != "success" || record.ConfigJSON == "" {
		h.audit(r, "rollback", "release", 0, "failure", err)
		writeError(w, http.StatusBadRequest, "release version cannot be rolled back")
		return
	}
	if err := publish.WriteAtomic(h.app.Config.GatewayConfigPath, []byte(record.ConfigJSON)); err != nil {
		h.audit(r, "rollback", "release", record.ID, "failure", err)
		h.writeServerError(w, err)
		return
	}
	rollback, err := h.app.Store.CreatePublishRecord(r.Context(), model.PublishRecord{
		Version:    fmt.Sprintf("%s-rollback-%d", record.Version, time.Now().UTC().Unix()),
		Operator:   currentActor(r).Username,
		Status:     "success",
		ConfigPath: h.app.Config.GatewayConfigPath,
		Checksum:   record.Checksum,
		Note:       "rollback to " + record.Version,
		ConfigJSON: record.ConfigJSON,
	})
	h.audit(r, "rollback", "release", rollback.ID, resultFromErr(err), err)
	h.writeCreated(w, rollback, err)
}

func (h handlers) listAuditLogs(w http.ResponseWriter, r *http.Request) {
	filter, ok := parseAuditFilter(w, r)
	if !ok {
		return
	}
	items, err := h.app.Store.ListAuditLogs(r.Context(), filter)
	h.writeList(w, items, err)
}

func (h handlers) listAccessLists(w http.ResponseWriter, r *http.Request) {
	items, err := h.app.Store.ListAccessListEntries(r.Context())
	h.writeList(w, items, err)
}

func (h handlers) getAccessList(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	item, err := h.app.Store.GetAccessListEntry(r.Context(), id)
	h.writeItem(w, item, err)
}

func (h handlers) createAccessList(w http.ResponseWriter, r *http.Request) {
	var req accessListRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item := req.toModel()
	item.Enabled = boolValue(req.Enabled, true)
	normalizeAccessList(&item)
	if err := validateAccessList(item); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	created, err := h.app.Store.CreateAccessListEntry(r.Context(), item)
	h.audit(r, "create", "access_list", created.ID, resultFromErr(err), err)
	h.writeCreated(w, created, err)
}

func (h handlers) updateAccessList(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var req accessListRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item := req.toModel()
	item.Enabled = boolValue(req.Enabled, true)
	normalizeAccessList(&item)
	if err := validateAccessList(item); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	updated, err := h.app.Store.UpdateAccessListEntry(r.Context(), id, item)
	h.audit(r, "update", "access_list", id, resultFromErr(err), err)
	h.writeItem(w, updated, err)
}

func (h handlers) deleteAccessList(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	err := h.app.Store.DeleteAccessListEntry(r.Context(), id)
	h.audit(r, "delete", "access_list", id, resultFromErr(err), err)
	h.writeNoContent(w, err)
}

func (h handlers) listRateLimits(w http.ResponseWriter, r *http.Request) {
	items, err := h.app.Store.ListRateLimitRules(r.Context())
	h.writeList(w, items, err)
}

func (h handlers) getRateLimit(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	item, err := h.app.Store.GetRateLimitRule(r.Context(), id)
	h.writeItem(w, item, err)
}

func (h handlers) createRateLimit(w http.ResponseWriter, r *http.Request) {
	var req rateLimitRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item := req.toModel()
	item.Enabled = boolValue(req.Enabled, true)
	normalizeRateLimit(&item)
	if err := validateRateLimit(item); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	created, err := h.app.Store.CreateRateLimitRule(r.Context(), item)
	h.audit(r, "create", "rate_limit", created.ID, resultFromErr(err), err)
	h.writeCreated(w, created, err)
}

func (h handlers) updateRateLimit(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var req rateLimitRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item := req.toModel()
	item.Enabled = boolValue(req.Enabled, true)
	normalizeRateLimit(&item)
	if err := validateRateLimit(item); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	updated, err := h.app.Store.UpdateRateLimitRule(r.Context(), id, item)
	h.audit(r, "update", "rate_limit", id, resultFromErr(err), err)
	h.writeItem(w, updated, err)
}

func (h handlers) deleteRateLimit(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	err := h.app.Store.DeleteRateLimitRule(r.Context(), id)
	h.audit(r, "delete", "rate_limit", id, resultFromErr(err), err)
	h.writeNoContent(w, err)
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
	Name                    string   `json:"name"`
	Type                    string   `json:"type"`
	Target                  string   `json:"target"`
	Action                  string   `json:"action"`
	Expression              string   `json:"expression"`
	Score                   int      `json:"score"`
	Enabled                 *bool    `json:"enabled"`
	Module                  string   `json:"module"`
	Category                string   `json:"category"`
	AttackType              string   `json:"attack_type"`
	Group                   string   `json:"group"`
	Priority                int      `json:"priority"`
	PackageID               string   `json:"package_id"`
	PackageVersion          string   `json:"package_version"`
	PackageRuleID           string   `json:"package_rule_id"`
	SourceChecksum          string   `json:"source_checksum"`
	SignatureStatus         string   `json:"signature_status"`
	ReviewStatus            string   `json:"review_status"`
	LastTestStatus          string   `json:"last_test_status"`
	RemoteCatalogID         string   `json:"remote_catalog_id"`
	LastSyncedVersion       string   `json:"last_synced_version"`
	PendingUpdateState      string   `json:"pending_update_state"`
	LocalOverrideState      string   `json:"local_override_state"`
	ExportEligible          bool     `json:"export_eligible"`
	ExportIneligibleReasons []string `json:"export_ineligible_reasons"`
}

func (r ruleRequest) toModel() model.Rule {
	return model.Rule{
		Name:                    r.Name,
		Type:                    r.Type,
		Target:                  r.Target,
		Action:                  r.Action,
		Expression:              r.Expression,
		Score:                   r.Score,
		Module:                  r.Module,
		Category:                r.Category,
		AttackType:              r.AttackType,
		Group:                   r.Group,
		Priority:                r.Priority,
		PackageID:               r.PackageID,
		PackageVersion:          r.PackageVersion,
		PackageRuleID:           r.PackageRuleID,
		SourceChecksum:          r.SourceChecksum,
		SignatureStatus:         r.SignatureStatus,
		ReviewStatus:            r.ReviewStatus,
		LastTestStatus:          r.LastTestStatus,
		RemoteCatalogID:         r.RemoteCatalogID,
		LastSyncedVersion:       r.LastSyncedVersion,
		PendingUpdateState:      r.PendingUpdateState,
		LocalOverrideState:      r.LocalOverrideState,
		ExportEligible:          r.ExportEligible,
		ExportIneligibleReasons: cloneStrings(r.ExportIneligibleReasons),
	}
}

type policyRequest struct {
	Name                       string   `json:"name"`
	RiskThreshold              int      `json:"risk_threshold"`
	DefaultAction              string   `json:"default_action"`
	NormalizationEnabled       *bool    `json:"normalization_enabled"`
	NormalizationDecodePasses  int      `json:"normalization_decode_passes"`
	NormalizationMaxValueBytes int      `json:"normalization_max_value_bytes"`
	BodyInspectionEnabled      *bool    `json:"body_inspection_enabled"`
	BodyInspectionContentTypes []string `json:"body_inspection_content_types"`
	BodyInspectionPathPrefixes []string `json:"body_inspection_path_prefixes"`
	BodyInspectionMaxBytes     int      `json:"body_inspection_max_bytes"`
	OversizedBodyAction        string   `json:"oversized_body_action"`
	UploadInspectionEnabled    *bool    `json:"upload_inspection_enabled"`
	UploadMaxBytes             int      `json:"upload_max_bytes"`
	UploadSizeAction           string   `json:"upload_size_action"`
	DynamicBanEnabled          *bool    `json:"dynamic_ban_enabled"`
	DynamicBanDurationSec      int      `json:"dynamic_ban_duration_sec"`
	DynamicBanScoreThreshold   int      `json:"dynamic_ban_score_threshold"`
	DynamicBanTriggerCount     int      `json:"dynamic_ban_trigger_count"`
	DynamicBanWindowSec        int      `json:"dynamic_ban_window_sec"`
	Enabled                    *bool    `json:"enabled"`
	SiteIDs                    []int64  `json:"site_ids"`
	RuleIDs                    []int64  `json:"rule_ids"`
}

func (r policyRequest) toModel() model.Policy {
	return model.Policy{
		Name:                       r.Name,
		RiskThreshold:              r.RiskThreshold,
		DefaultAction:              r.DefaultAction,
		NormalizationEnabled:       boolValue(r.NormalizationEnabled, true),
		NormalizationDecodePasses:  r.NormalizationDecodePasses,
		NormalizationMaxValueBytes: r.NormalizationMaxValueBytes,
		BodyInspectionEnabled:      boolValue(r.BodyInspectionEnabled, false),
		BodyInspectionContentTypes: cloneStrings(r.BodyInspectionContentTypes),
		BodyInspectionPathPrefixes: cloneStrings(r.BodyInspectionPathPrefixes),
		BodyInspectionMaxBytes:     r.BodyInspectionMaxBytes,
		OversizedBodyAction:        r.OversizedBodyAction,
		UploadInspectionEnabled:    boolValue(r.UploadInspectionEnabled, false),
		UploadMaxBytes:             r.UploadMaxBytes,
		UploadSizeAction:           r.UploadSizeAction,
		DynamicBanEnabled:          boolValue(r.DynamicBanEnabled, false),
		DynamicBanDurationSec:      r.DynamicBanDurationSec,
		DynamicBanScoreThreshold:   r.DynamicBanScoreThreshold,
		DynamicBanTriggerCount:     r.DynamicBanTriggerCount,
		DynamicBanWindowSec:        r.DynamicBanWindowSec,
		SiteIDs:                    cloneIDs(r.SiteIDs),
		RuleIDs:                    cloneIDs(r.RuleIDs),
	}
}

type accessListRequest struct {
	Name          string `json:"name"`
	Kind          string `json:"kind"`
	Target        string `json:"target"`
	Value         string `json:"value"`
	MatchOperator string `json:"match_operator"`
	HeaderName    string `json:"header_name"`
	Action        string `json:"action"`
	SiteID        int64  `json:"site_id"`
	Enabled       *bool  `json:"enabled"`
	Priority      int    `json:"priority"`
}

func (r accessListRequest) toModel() model.AccessListEntry {
	return model.AccessListEntry{
		Name:          r.Name,
		Kind:          r.Kind,
		Target:        r.Target,
		Value:         r.Value,
		MatchOperator: r.MatchOperator,
		HeaderName:    r.HeaderName,
		Action:        r.Action,
		SiteID:        r.SiteID,
		Priority:      r.Priority,
	}
}

type rateLimitRequest struct {
	Name               string   `json:"name"`
	Scope              string   `json:"scope"`
	MatchValue         string   `json:"match_value"`
	PathMatch          string   `json:"path_match"`
	Methods            []string `json:"methods"`
	Threshold          int      `json:"threshold"`
	WindowSec          int      `json:"window_sec"`
	Action             string   `json:"action"`
	CCAction           string   `json:"cc_action"`
	BanDuration        int      `json:"ban_duration_sec"`
	ViolationThreshold int      `json:"violation_threshold"`
	ViolationWindowSec int      `json:"violation_window_sec"`
	SiteID             int64    `json:"site_id"`
	Enabled            *bool    `json:"enabled"`
}

func (r rateLimitRequest) toModel() model.RateLimitRule {
	return model.RateLimitRule{
		Name:               r.Name,
		Scope:              r.Scope,
		MatchValue:         r.MatchValue,
		PathMatch:          r.PathMatch,
		Methods:            cloneStrings(r.Methods),
		Threshold:          r.Threshold,
		WindowSec:          r.WindowSec,
		Action:             r.Action,
		CCAction:           r.CCAction,
		BanDuration:        r.BanDuration,
		ViolationThreshold: r.ViolationThreshold,
		ViolationWindowSec: r.ViolationWindowSec,
		SiteID:             r.SiteID,
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

func cloneStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	out := make([]string, len(values))
	copy(out, values)
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
	if !oneOf(rule.Type, "sqli", "xss", "rce", "path-traversal", "cc", "bot", "custom") {
		return errors.New("rule type is unsupported")
	}
	if !oneOf(rule.Target, "args", "uri", "headers", "normalized_uri", "normalized_path", "normalized_args", "normalized_headers", "body", "body_json", "body_form", "upload_filename", "upload_extension", "upload_mime", "upload_size") {
		return errors.New("rule target is unsupported")
	}
	if !oneOf(rule.Action, "pass", "block", "log-only") {
		return errors.New("rule action must be pass, block, or log-only")
	}
	if rule.Expression == "" {
		return errors.New("rule expression is required")
	}
	if rule.Target == "upload_size" {
		value, err := strconv.Atoi(rule.Expression)
		if err != nil || value < 0 {
			return errors.New("upload_size rule expression must be a non-negative integer")
		}
	} else if err := validateRegex(rule.Expression); err != nil {
		return errors.New("rule expression is invalid")
	}
	if rule.Score < 0 || rule.Score > 1000 {
		return errors.New("rule score must be between 0 and 1000")
	}
	if rule.Module != "" && rule.Module != attackmeta.Module {
		return errors.New("rule module is unsupported")
	}
	if rule.Category != "" && rule.Category != attackmeta.Category {
		return errors.New("rule category is unsupported")
	}
	if rule.AttackType != "" && !attackmeta.ValidAttackType(rule.AttackType) {
		return errors.New("rule attack_type is unsupported")
	}
	if rule.Priority < 0 {
		return errors.New("rule priority cannot be negative")
	}
	if err := rulepkg.ValidateRule(rule); err != nil {
		return err
	}
	return nil
}

func normalizePolicy(policy *model.Policy) {
	policy.Name = strings.TrimSpace(policy.Name)
	policy.DefaultAction = strings.ToLower(strings.TrimSpace(policy.DefaultAction))
	policy.OversizedBodyAction = strings.ToLower(strings.TrimSpace(policy.OversizedBodyAction))
	policy.UploadSizeAction = strings.ToLower(strings.TrimSpace(policy.UploadSizeAction))
	if policy.DefaultAction == "" {
		policy.DefaultAction = "block"
	}
	if policy.RiskThreshold == 0 {
		policy.RiskThreshold = 100
	}
	if policy.NormalizationDecodePasses == 0 {
		policy.NormalizationDecodePasses = 2
	}
	if policy.NormalizationMaxValueBytes == 0 {
		policy.NormalizationMaxValueBytes = 4096
	}
	if policy.BodyInspectionMaxBytes == 0 {
		policy.BodyInspectionMaxBytes = 65536
	}
	if policy.OversizedBodyAction == "" {
		policy.OversizedBodyAction = "log-only"
	}
	if policy.UploadMaxBytes == 0 {
		policy.UploadMaxBytes = 10485760
	}
	if policy.UploadSizeAction == "" {
		policy.UploadSizeAction = "block"
	}
	if policy.DynamicBanDurationSec == 0 {
		policy.DynamicBanDurationSec = 300
	}
	if policy.DynamicBanScoreThreshold == 0 {
		policy.DynamicBanScoreThreshold = 200
	}
	if policy.DynamicBanTriggerCount == 0 {
		policy.DynamicBanTriggerCount = 3
	}
	if policy.DynamicBanWindowSec == 0 {
		policy.DynamicBanWindowSec = 60
	}
	policy.BodyInspectionContentTypes = normalizeStringList(policy.BodyInspectionContentTypes, true)
	policy.BodyInspectionPathPrefixes = normalizeStringList(policy.BodyInspectionPathPrefixes, false)
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
	if policy.NormalizationDecodePasses < 1 || policy.NormalizationDecodePasses > 5 {
		return errors.New("policy normalization_decode_passes must be between 1 and 5")
	}
	if policy.NormalizationMaxValueBytes < 128 || policy.NormalizationMaxValueBytes > 65536 {
		return errors.New("policy normalization_max_value_bytes must be between 128 and 65536")
	}
	if policy.BodyInspectionMaxBytes < 1 || policy.BodyInspectionMaxBytes > 1048576 {
		return errors.New("policy body_inspection_max_bytes must be between 1 and 1048576")
	}
	if !oneOf(policy.OversizedBodyAction, "pass", "block", "log-only") {
		return errors.New("policy oversized_body_action must be pass, block, or log-only")
	}
	if policy.UploadMaxBytes < 1 || policy.UploadMaxBytes > 1073741824 {
		return errors.New("policy upload_max_bytes must be between 1 and 1073741824")
	}
	if !oneOf(policy.UploadSizeAction, "pass", "block", "log-only") {
		return errors.New("policy upload_size_action must be pass, block, or log-only")
	}
	if policy.DynamicBanDurationSec < 1 || policy.DynamicBanDurationSec > 86400 {
		return errors.New("policy dynamic_ban_duration_sec must be between 1 and 86400")
	}
	if policy.DynamicBanScoreThreshold < 1 || policy.DynamicBanScoreThreshold > 10000 {
		return errors.New("policy dynamic_ban_score_threshold must be between 1 and 10000")
	}
	if policy.DynamicBanTriggerCount < 1 || policy.DynamicBanTriggerCount > 1000 {
		return errors.New("policy dynamic_ban_trigger_count must be between 1 and 1000")
	}
	if policy.DynamicBanWindowSec < 1 || policy.DynamicBanWindowSec > 86400 {
		return errors.New("policy dynamic_ban_window_sec must be between 1 and 86400")
	}
	if len(policy.SiteIDs) == 0 {
		return errors.New("policy site_ids is required")
	}
	if len(policy.RuleIDs) == 0 {
		return errors.New("policy rule_ids is required")
	}
	return nil
}

func normalizeAccessList(item *model.AccessListEntry) {
	item.Name = strings.TrimSpace(item.Name)
	item.Kind = strings.ToLower(strings.TrimSpace(item.Kind))
	item.Target = strings.ToLower(strings.TrimSpace(item.Target))
	item.Value = strings.TrimSpace(item.Value)
	item.MatchOperator = strings.ToLower(strings.TrimSpace(item.MatchOperator))
	item.HeaderName = strings.TrimSpace(item.HeaderName)
	item.Action = strings.ToLower(strings.TrimSpace(item.Action))
	if item.Kind == "" {
		item.Kind = "blacklist"
	}
	if item.Action == "" {
		item.Action = "block"
	}
	if item.Priority == 0 {
		item.Priority = 100
	}
}

func validateAccessList(item model.AccessListEntry) error {
	if item.Name == "" {
		return errors.New("access list name is required")
	}
	if !oneOf(item.Kind, "blacklist", "whitelist") {
		return errors.New("access list kind must be blacklist or whitelist")
	}
	if !oneOf(item.Target, "ip", "cidr", "uri", "ua", "header", "host") {
		return errors.New("access list target must be ip, cidr, uri, ua, header, or host")
	}
	if item.Value == "" {
		return errors.New("access list value is required")
	}
	if !oneOf(item.Action, "allow", "block", "log-only") {
		return errors.New("access list action must be allow, block, or log-only")
	}
	switch item.Target {
	case "ip":
		if net.ParseIP(item.Value) == nil {
			return errors.New("access list ip value is invalid")
		}
	case "cidr":
		if _, _, err := net.ParseCIDR(item.Value); err != nil {
			return errors.New("access list cidr value is invalid")
		}
	case "uri":
		if !strings.HasPrefix(item.Value, "/") {
			return errors.New("access list uri value must start with /")
		}
	case "header":
		if item.HeaderName == "" {
			return errors.New("access list header_name is required")
		}
	}
	if item.Priority < 0 {
		return errors.New("access list priority cannot be negative")
	}
	return nil
}

func normalizeRateLimit(item *model.RateLimitRule) {
	item.Name = strings.TrimSpace(item.Name)
	item.Scope = strings.ToLower(strings.TrimSpace(item.Scope))
	item.MatchValue = strings.TrimSpace(item.MatchValue)
	item.PathMatch = strings.ToLower(strings.TrimSpace(item.PathMatch))
	item.Methods = normalizeHTTPMethods(item.Methods)
	item.Action = strings.ToLower(strings.TrimSpace(item.Action))
	item.CCAction = strings.ToLower(strings.TrimSpace(item.CCAction))
	if item.PathMatch == "" {
		item.PathMatch = "exact"
	}
	if item.Action == "" {
		item.Action = "block"
	}
	if item.CCAction == "" {
		item.CCAction = item.Action
	}
	if item.ViolationThreshold == 0 && item.BanDuration > 0 {
		item.ViolationThreshold = 3
	}
	if item.ViolationWindowSec == 0 && item.ViolationThreshold > 0 {
		item.ViolationWindowSec = item.WindowSec
	}
}

func validateRateLimit(item model.RateLimitRule) error {
	if item.Name == "" {
		return errors.New("rate limit name is required")
	}
	if !oneOf(item.Scope, "ip", "uri", "site") {
		return errors.New("rate limit scope must be ip, uri, or site")
	}
	if item.Threshold <= 0 {
		return errors.New("rate limit threshold must be positive")
	}
	if item.WindowSec <= 0 {
		return errors.New("rate limit window_sec must be positive")
	}
	if item.BanDuration < 0 {
		return errors.New("rate limit ban_duration_sec cannot be negative")
	}
	if item.ViolationThreshold < 0 {
		return errors.New("rate limit violation_threshold cannot be negative")
	}
	if item.ViolationWindowSec < 0 {
		return errors.New("rate limit violation_window_sec cannot be negative")
	}
	if item.ViolationThreshold > 0 && (item.ViolationWindowSec <= 0 || item.BanDuration <= 0) {
		return errors.New("rate limit repeated violation settings require positive violation_window_sec and ban_duration_sec")
	}
	if item.ViolationWindowSec > 0 && item.ViolationThreshold <= 0 {
		return errors.New("rate limit violation_threshold must be positive when violation_window_sec is set")
	}
	if !oneOf(item.Action, "block", "log-only") {
		return errors.New("rate limit action must be block or log-only")
	}
	return nil
}

func countAdvancedProtection(policies []model.Policy, rules []model.Rule, rateLimits []model.RateLimitRule) int {
	count := 0
	for _, policy := range policies {
		if policy.NormalizationEnabled || policy.BodyInspectionEnabled || policy.UploadInspectionEnabled || policy.DynamicBanEnabled {
			count++
		}
	}
	for _, rule := range rules {
		if oneOf(rule.Target, "normalized_uri", "normalized_path", "normalized_args", "normalized_headers", "body", "body_json", "body_form", "upload_filename", "upload_extension", "upload_mime", "upload_size") {
			count++
		}
	}
	for _, rule := range rateLimits {
		if rule.ViolationThreshold > 0 || rule.ViolationWindowSec > 0 {
			count++
		}
	}
	return count
}

func parseAuditFilter(w http.ResponseWriter, r *http.Request) (model.AuditLogFilter, bool) {
	query := r.URL.Query()
	filter := model.AuditLogFilter{
		Actor:        strings.TrimSpace(query.Get("actor")),
		Action:       strings.TrimSpace(query.Get("action")),
		ResourceType: strings.TrimSpace(query.Get("resource_type")),
		Result:       strings.TrimSpace(query.Get("result")),
	}
	if since := strings.TrimSpace(query.Get("since")); since != "" {
		parsed, err := time.Parse(time.RFC3339, since)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid since timestamp")
			return model.AuditLogFilter{}, false
		}
		filter.Since = parsed
	}
	if until := strings.TrimSpace(query.Get("until")); until != "" {
		parsed, err := time.Parse(time.RFC3339, until)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid until timestamp")
			return model.AuditLogFilter{}, false
		}
		filter.Until = parsed
	}
	return filter, true
}

func resultFromErr(err error) string {
	if err != nil {
		return "failure"
	}
	return "success"
}

func (h handlers) audit(r *http.Request, action string, resourceType string, resourceID int64, result string, operationErr error) {
	current := currentActor(r)
	message := ""
	if operationErr != nil {
		message = operationErr.Error()
	}
	_, err := h.app.Store.CreateAuditLog(r.Context(), model.AuditLog{
		Actor:        current.Username,
		Role:         current.Role,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   idString(resourceID),
		Result:       result,
		RemoteAddr:   r.RemoteAddr,
		UserAgent:    r.UserAgent(),
		Message:      message,
	})
	if err != nil {
		h.logger.Error("audit log failed", "error", err)
	}
}

func idString(id int64) string {
	if id <= 0 {
		return ""
	}
	return strconv.FormatInt(id, 10)
}

func validateRegex(value string) error {
	_, err := regexp.Compile(value)
	return err
}

func oneOf(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}

func normalizeStringList(values []string, lower bool) []string {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		item := strings.TrimSpace(value)
		if lower {
			item = strings.ToLower(item)
		}
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}
