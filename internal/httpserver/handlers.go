package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os/exec"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"litewaf-api/internal/app"
	"litewaf-api/internal/attackmeta"
	"litewaf-api/internal/auth"
	"litewaf-api/internal/defaults"
	"litewaf-api/internal/ipaccess"
	"litewaf-api/internal/model"
	"litewaf-api/internal/protectionrules"
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
		"name":                         h.app.Config.AppName,
		"version":                      app.Version,
		"env":                          h.app.Config.Env,
		"gateway_client_max_body_size": h.app.Config.NormalizedGatewayClientMaxBodySize(),
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

func publishActivationSummary(applications []model.Application, artifacts publish.RuntimeArtifacts, validationErrors []string, rollbackTarget string) model.PublishActivationSummary {
	return model.PublishActivationSummary{
		Applications:       countEnabledApplications(applications),
		ListenerCount:      artifacts.ListenerCount,
		HTTPSListenerCount: artifacts.HTTPSListenerCount,
		ClientMaxBodySize:  artifacts.ClientMaxBodySize,
		CertificateIDs:     append([]int64(nil), artifacts.CertificateIDs...),
		ReloadStatus:       "not-configured",
		ReloadMessage:      "gateway reload coordination is pending",
		ValidationErrors:   append([]string(nil), validationErrors...),
		RollbackTarget:     rollbackTarget,
	}
}

func applyReloadResult(activation *model.PublishActivationSummary, result gatewayReloadResult) {
	activation.ReloadStatus = result.Status
	activation.ReloadMessage = result.Message
}

func activationAuditSummary(activation model.PublishActivationSummary) string {
	return boundedSummary(fmt.Sprintf("applications=%d listeners=%d https_listeners=%d client_max_body_size=%s certificates=%v reload_status=%s reload_message=%s rollback_target=%s validation_errors=%d",
		activation.Applications, activation.ListenerCount, activation.HTTPSListenerCount, activation.ClientMaxBodySize, activation.CertificateIDs,
		activation.ReloadStatus, activation.ReloadMessage, activation.RollbackTarget, len(activation.ValidationErrors)), 512)
}

type gatewayReloadResult struct {
	Status  string
	Message string
}

func runGatewayReload(ctx context.Context, command string) gatewayReloadResult {
	command = strings.TrimSpace(command)
	if command == "" {
		return gatewayReloadResult{
			Status:  "not-configured",
			Message: "gateway reload coordination is pending",
		}
	}
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/C", command)
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", command)
	}
	output, err := cmd.CombinedOutput()
	message := boundedReloadMessage(string(output))
	if err != nil {
		if message == "" {
			message = err.Error()
		}
		return gatewayReloadResult{Status: "failed", Message: boundedReloadMessage(message)}
	}
	if message == "" {
		message = "gateway reload completed"
	}
	return gatewayReloadResult{Status: "reloaded", Message: message}
}

func boundedReloadMessage(message string) string {
	message = strings.Join(strings.Fields(message), " ")
	const maxLen = 480
	if len(message) > maxLen {
		return message[:maxLen]
	}
	return message
}

func countEnabledApplications(applications []model.Application) int {
	count := 0
	for _, application := range applications {
		if application.Enabled {
			count++
		}
	}
	return count
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
	applications, applicationIssues, err := h.applicationPreviewContext(r.Context())
	if err != nil {
		h.audit(r, "publish", "release", 0, "failure", err)
		h.writeServerError(w, err)
		return
	}
	if validationErrors := blockingApplicationMessages(applicationIssues); len(validationErrors) > 0 {
		err := fmt.Errorf("%s", strings.Join(validationErrors, "; "))
		h.audit(r, "publish", "release", 0, "failure", err)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
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
	artifacts, err := publish.WriteRuntimeArtifactsWithClientMaxBodySize(r.Context(), h.app.Store, h.app.Config.GatewayConfigPath, h.app.Config.GatewayClientMaxBodySize)
	if err != nil {
		h.audit(r, "publish", "release", 0, "failure", err)
		h.writeServerError(w, err)
		return
	}
	activation := publishActivationSummary(applications, artifacts, []string{}, "")
	applyReloadResult(&activation, runGatewayReload(r.Context(), h.app.Config.GatewayReloadCommand))
	record, err := h.app.Store.CreatePublishRecord(r.Context(), model.PublishRecord{
		Version:    version,
		Operator:   operator,
		Status:     "success",
		ConfigPath: h.app.Config.GatewayConfigPath,
		Checksum:   checksum,
		Note:       model.FormatPublishNote(input.Note, activation),
		ConfigJSON: string(payload),
		Activation: &activation,
	})
	h.auditMessage(r, "publish", "release", record.ID, resultFromErr(err), activationAuditSummary(activation), err)
	h.writeCreated(w, record, err)
}

func (h handlers) previewRelease(w http.ResponseWriter, r *http.Request) {
	publishValidationErrors := []string{}
	if err := publish.Validate(r.Context(), h.app.Store); err != nil {
		publishValidationErrors = append(publishValidationErrors, err.Error())
	}
	applications, applicationIssues, err := h.applicationPreviewContext(r.Context())
	if err != nil {
		h.writeServerError(w, err)
		return
	}
	certificates, err := h.app.Store.ListCertificates(r.Context())
	if err != nil {
		h.writeServerError(w, err)
		return
	}
	rules, _ := h.app.Store.ListRules(r.Context())
	policies, _ := h.app.Store.ListPolicies(r.Context())
	ipAccessLists, _ := h.app.Store.ListIPAccessListEntries(r.Context())
	rateLimits, _ := h.app.Store.ListRateLimitRules(r.Context())
	uploadRules, _ := h.app.Store.ListUploadProtectionRules(r.Context())
	botRules, _ := h.app.Store.ListBotProtectionRules(r.Context())
	dynamicRules, _ := h.app.Store.ListDynamicProtectionRules(r.Context())
	protectionRules, _ := h.app.Store.ListProtectionRules(r.Context())
	catalogs, _ := h.app.Store.ListRuleCatalogSources(r.Context())
	catalogPackages, _ := h.app.Store.ListRuleCatalogPackages(r.Context(), 0)
	trustKeys, _ := h.app.Store.ListRuleTrustKeys(r.Context())
	providers, _ := h.app.Store.ListRuleProviderAdapters(r.Context())
	providerPackages, _ := h.app.Store.ListRuleProviderPackages(r.Context(), 0)
	ccSummary := ccProtectionSummary(mergedCCProtectionRules(protectionRules, rateLimits))
	accessRules, _ := filterProtectionRules(protectionRules, "access-control")
	accessControlSummary := accessControlSummary(accessRules)
	ipAccessSummary := ipAccessListSummary(ipAccessLists)
	attackSummary := attackProtectionSummary(rules)
	uploadSummary := uploadProtectionSummary(mergedUploadProtectionRules(protectionRules, uploadRules))
	botSummary := botProtectionSummary(mergedBotProtectionRules(protectionRules, botRules))
	dynamicSummary := dynamicProtectionSummary(mergedDynamicProtectionRules(protectionRules, dynamicRules))
	ecosystemSummary := ruleEcosystemSummary(rules, catalogs, catalogPackages, trustKeys, providers, providerPackages)
	compatibilityDiagnostics := buildPublishCompatibilityDiagnostics(protectionRules, rateLimits, uploadRules, botRules, dynamicRules)
	modules := protectionModuleMatrix(
		ccSummary,
		attackSummary,
		ipAccessSummary,
		accessControlSummary,
		uploadSummary,
		botSummary,
		dynamicSummary,
		ecosystemSummary,
		model.ObservabilitySummary{},
	)
	writeJSON(w, http.StatusOK, envelope{
		"summary": envelope{
			"applications":              len(applications),
			"application_hosts":         countApplicationHosts(applications),
			"application_listeners":     countApplicationListeners(applications),
			"listener_ports":            applicationListenerPorts(applications),
			"listener_protocols":        applicationListenerProtocols(applications),
			"http_listeners":            countApplicationListenersByProtocol(applications, model.ListenerProtocolHTTP),
			"https_listeners":           countApplicationListenersByProtocol(applications, model.ListenerProtocolHTTPS),
			"certificates":              len(certificates),
			"upstreams":                 countApplicationUpstreams(applications),
			"enabled_upstreams":         countEnabledApplicationUpstreams(applications),
			"application_validation":    applicationValidationSummary(applicationIssues, publishValidationErrors),
			"listener_deployment_mode":  listenerDeploymentModeSummary(h.app.Config.GatewayListenerMode, h.app.Config.GatewayBridgePortRange),
			"gateway":                   gatewayRuntimeSummary(h.app.Config.NormalizedGatewayClientMaxBodySize()),
			"rules":                     len(rules),
			"policies":                  len(policies),
			"ip_access_list":            ipAccessSummary,
			"access_control":            accessControlSummary,
			"rate_limits":               len(rateLimits),
			"cc_protection":             ccSummary,
			"attack_protection":         attackSummary,
			"upload_protection":         uploadSummary,
			"bot_protection":            botSummary,
			"dynamic_protection":        dynamicSummary,
			"rule_ecosystem":            ecosystemSummary,
			"advanced_protection":       countAdvancedProtection(policies, rules, rateLimits),
			"module_matrix":             modules,
			"risk_warnings":             protectionRisks(modules),
			"compatibility_diagnostics": compatibilityDiagnostics,
		},
	})
}

func (h handlers) buildProtectionOverview(ctx context.Context, filter model.ObservabilitySummaryFilter) (model.ProtectionOverview, error) {
	rules, err := h.app.Store.ListRules(ctx)
	if err != nil {
		return model.ProtectionOverview{}, err
	}
	ipAccessLists, err := h.app.Store.ListIPAccessListEntries(ctx)
	if err != nil {
		return model.ProtectionOverview{}, err
	}
	rateLimits, err := h.app.Store.ListRateLimitRules(ctx)
	if err != nil {
		return model.ProtectionOverview{}, err
	}
	uploadRules, err := h.app.Store.ListUploadProtectionRules(ctx)
	if err != nil {
		return model.ProtectionOverview{}, err
	}
	botRules, err := h.app.Store.ListBotProtectionRules(ctx)
	if err != nil {
		return model.ProtectionOverview{}, err
	}
	dynamicRules, err := h.app.Store.ListDynamicProtectionRules(ctx)
	if err != nil {
		return model.ProtectionOverview{}, err
	}
	protectionRules, err := h.app.Store.ListProtectionRules(ctx)
	if err != nil {
		return model.ProtectionOverview{}, err
	}
	catalogs, err := h.app.Store.ListRuleCatalogSources(ctx)
	if err != nil {
		return model.ProtectionOverview{}, err
	}
	catalogPackages, err := h.app.Store.ListRuleCatalogPackages(ctx, 0)
	if err != nil {
		return model.ProtectionOverview{}, err
	}
	trustKeys, err := h.app.Store.ListRuleTrustKeys(ctx)
	if err != nil {
		return model.ProtectionOverview{}, err
	}
	providers, err := h.app.Store.ListRuleProviderAdapters(ctx)
	if err != nil {
		return model.ProtectionOverview{}, err
	}
	providerPackages, err := h.app.Store.ListRuleProviderPackages(ctx, 0)
	if err != nil {
		return model.ProtectionOverview{}, err
	}
	summary, err := h.app.Store.GetObservabilitySummary(ctx, filter)
	if err != nil {
		return model.ProtectionOverview{}, err
	}
	modules := protectionModuleMatrix(
		ccProtectionSummary(mergedCCProtectionRules(protectionRules, rateLimits)),
		attackProtectionSummary(rules),
		ipAccessListSummary(ipAccessLists),
		accessControlSummary(mustFilterProtectionRules(protectionRules, "access-control")),
		uploadProtectionSummary(mergedUploadProtectionRules(protectionRules, uploadRules)),
		botProtectionSummary(mergedBotProtectionRules(protectionRules, botRules)),
		dynamicProtectionSummary(mergedDynamicProtectionRules(protectionRules, dynamicRules)),
		ruleEcosystemSummary(rules, catalogs, catalogPackages, trustKeys, providers, providerPackages),
		summary,
	)
	return model.ProtectionOverview{
		Modules: modules,
		Risks:   protectionRisks(modules),
	}, nil
}

func (h handlers) applicationPreviewContext(ctx context.Context) ([]model.Application, []publish.ApplicationValidationIssue, error) {
	applications, err := h.app.Store.ListApplications(ctx)
	if err != nil {
		return nil, nil, err
	}
	if len(applications) == 0 {
		sites, err := h.app.Store.ListSites(ctx)
		if err != nil {
			return nil, nil, err
		}
		applications = publish.ApplicationsFromSites(sites)
	}
	issues, err := publish.ValidateApplicationReadinessWithDeployment(ctx, h.app.Store, publish.GatewayListenerDeployment{
		Mode:            h.app.Config.GatewayListenerMode,
		BridgePortRange: h.app.Config.GatewayBridgePortRange,
	})
	if err != nil {
		return nil, nil, err
	}
	return applications, issues, nil
}

func countApplicationHosts(applications []model.Application) int {
	total := 0
	for _, application := range applications {
		total += len(application.Hosts)
	}
	return total
}

func countApplicationListeners(applications []model.Application) int {
	total := 0
	for _, application := range applications {
		total += len(application.Listeners)
	}
	return total
}

func countApplicationListenersByProtocol(applications []model.Application, protocol string) int {
	total := 0
	for _, application := range applications {
		for _, listener := range application.Listeners {
			if listener.Enabled && listener.Protocol == protocol {
				total++
			}
		}
	}
	return total
}

func applicationListenerPorts(applications []model.Application) []int {
	seen := map[int]bool{}
	for _, application := range applications {
		for _, listener := range application.Listeners {
			if listener.Enabled {
				seen[listener.Port] = true
			}
		}
	}
	ports := make([]int, 0, len(seen))
	for port := range seen {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports
}

func applicationListenerProtocols(applications []model.Application) envelope {
	counts := map[string]int{}
	for _, application := range applications {
		for _, listener := range application.Listeners {
			if listener.Enabled {
				counts[listener.Protocol]++
			}
		}
	}
	out := envelope{}
	for protocol, count := range counts {
		out[protocol] = count
	}
	return out
}

func countApplicationUpstreams(applications []model.Application) int {
	total := 0
	for _, application := range applications {
		total += len(application.Upstreams)
	}
	return total
}

func countEnabledApplicationUpstreams(applications []model.Application) int {
	total := 0
	for _, application := range applications {
		for _, upstream := range application.Upstreams {
			if upstream.Enabled {
				total++
			}
		}
	}
	return total
}

func applicationValidationSummary(issues []publish.ApplicationValidationIssue, validationErrors []string) envelope {
	errorCount := 0
	warningCount := 0
	for _, issue := range issues {
		if issue.Severity == "error" {
			errorCount++
		}
		if issue.Severity == "warning" {
			warningCount++
		}
	}
	return envelope{
		"errors":            errorCount,
		"warnings":          warningCount,
		"issues":            issues,
		"blocking_messages": validationErrors,
	}
}

func blockingApplicationMessages(issues []publish.ApplicationValidationIssue) []string {
	var messages []string
	for _, issue := range issues {
		if issue.Severity == "error" {
			messages = append(messages, issue.Message)
		}
	}
	return messages
}

func listenerDeploymentModeSummary(mode string, rangeValue string) envelope {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "bridge-range" {
		mode = "host-network"
	}
	ports := listenerDeploymentPorts(rangeValue)
	warnings := []string{}
	if mode == "bridge-range" && len(ports) == 0 {
		warnings = append(warnings, "bridge-range mode is selected but GATEWAY_BRIDGE_PORT_RANGE is empty or invalid")
	}
	return envelope{
		"mode":                mode,
		"bridge_range_config": mode == "bridge-range",
		"port_range":          ports,
		"raw_port_range":      strings.TrimSpace(rangeValue),
		"warnings":            warnings,
	}
}

func gatewayRuntimeSummary(clientMaxBodySize string) envelope {
	return envelope{
		"client_max_body_size": clientMaxBodySize,
	}
}

func listenerDeploymentPorts(value string) []int {
	seen := map[int]bool{}
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.Contains(item, "-") {
			parts := strings.SplitN(item, "-", 2)
			start, errStart := strconv.Atoi(strings.TrimSpace(parts[0]))
			end, errEnd := strconv.Atoi(strings.TrimSpace(parts[1]))
			if errStart != nil || errEnd != nil || start <= 0 || end > 65535 || start > end {
				continue
			}
			for port := start; port <= end; port++ {
				seen[port] = true
			}
			continue
		}
		port, err := strconv.Atoi(item)
		if err != nil || port <= 0 || port > 65535 {
			continue
		}
		seen[port] = true
	}
	ports := make([]int, 0, len(seen))
	for port := range seen {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports
}

func protectionModuleMatrix(cc, attack, ipList, access, upload, bot, dynamic, ecosystem envelope, summary model.ObservabilitySummary) []model.ProtectionModuleOverview {
	return []model.ProtectionModuleOverview{
		moduleOverview("cc-protection", "CC 防护", "rate-limit", "/cc-protection", "cc-protection", cc, summaryCountTotal(summary.TopRules, "cc-protection")),
		moduleOverview("attack-protection", "攻击防护", "managed", "/attack-protection", "attack-protection", attack, summary.AttackProtection),
		moduleOverview("ip-access-list", "IP 黑白名单", "ip-access-list", "/ip-access-lists", "ip-access-list", ipList, summary.IPAccessList),
		moduleOverview("access-control", "访问控制", "access-control", "/access-control", "access-control", access, summary.AccessControl),
		moduleOverview("upload-protection", "上传防护", "upload", "/upload-protection", "upload-protection", upload, summary.UploadProtection),
		moduleOverview("bot-protection", "Bot / 人机验证", "challenge", "/bot-protection", "bot-protection", bot, summary.BotProtection),
		moduleOverview("dynamic-protection", "动态防护 / 等候室", "dynamic", "/dynamic-protection", "dynamic-protection", dynamic, summary.DynamicProtection),
		moduleOverview("advanced-rule-ecosystem", "高级规则生态", "advanced", "/rule-ecosystem", "attack-protection", ecosystem, []model.SummaryCount{}),
	}
}

func moduleOverview(key, label, category, route, logModule string, data envelope, evidence []model.SummaryCount) model.ProtectionModuleOverview {
	return model.ProtectionModuleOverview{
		Key:                 key,
		Label:               label,
		Category:            category,
		Route:               route,
		LogModule:           logModule,
		Rules:               envelopeInt(data, "rules", "groups", "packages"),
		Enabled:             envelopeInt(data, "enabled"),
		Observe:             envelopeInt(data, "observe", "log_only"),
		Block:               envelopeInt(data, "block", "untested_blocking"),
		Allow:               envelopeInt(data, "allow"),
		CompatibilitySource: compatibilitySource(key),
		Warnings:            envelopeStrings(data, "warnings"),
		RiskDetails:         envelopeRiskDetails(data),
		Evidence:            evidence,
	}
}

type protectionMigrationSummary struct {
	Migrated       int
	LegacyFallback int
	Disabled       int
}

func migrationSummary(rules []model.ProtectionRule) protectionMigrationSummary {
	summary := protectionMigrationSummary{}
	for _, rule := range rules {
		if !rule.Enabled {
			summary.Disabled++
		}
		switch rule.MigrationStatus {
		case "migrated", "native":
			summary.Migrated++
		case "legacy-only":
			summary.LegacyFallback++
		default:
			if rule.Source == "legacy" {
				summary.LegacyFallback++
			} else {
				summary.Migrated++
			}
		}
	}
	return summary
}

func mergedCCProtectionRules(protectionRules []model.ProtectionRule, rateLimits []model.RateLimitRule) []model.ProtectionRule {
	items, seen := filterProtectionRules(protectionRules, "cc-protection")
	for _, item := range rateLimits {
		ref := protectionrules.LegacyRef("rate_limits", item.ID)
		if seen[ref] {
			continue
		}
		items = append(items, publish.CCProtectionFromRateLimit(item))
	}
	return items
}

func mergedUploadProtectionRules(protectionRules []model.ProtectionRule, uploadRules []model.UploadProtectionRule) []model.ProtectionRule {
	items, seen := filterProtectionRules(protectionRules, "upload-protection")
	for _, item := range uploadRules {
		ref := protectionrules.LegacyRef("upload_protection_rules", item.ID)
		if seen[ref] {
			continue
		}
		items = append(items, publish.UploadProtectionFromRule(item))
	}
	return items
}

func mergedBotProtectionRules(protectionRules []model.ProtectionRule, botRules []model.BotProtectionRule) []model.ProtectionRule {
	items, seen := filterProtectionRules(protectionRules, "bot-protection")
	for _, item := range botRules {
		ref := protectionrules.LegacyRef("bot_protection_rules", item.ID)
		if seen[ref] {
			continue
		}
		items = append(items, publish.BotProtectionFromRule(item))
	}
	return items
}

func mergedDynamicProtectionRules(protectionRules []model.ProtectionRule, dynamicRules []model.DynamicProtectionRule) []model.ProtectionRule {
	items, seen := filterProtectionRules(protectionRules, "dynamic-protection")
	for _, item := range dynamicRules {
		ref := protectionrules.LegacyRef("dynamic_protection_rules", item.ID)
		if seen[ref] {
			continue
		}
		items = append(items, publish.DynamicProtectionFromRule(item))
	}
	return items
}

func filterProtectionRules(rules []model.ProtectionRule, module string) ([]model.ProtectionRule, map[string]bool) {
	items := []model.ProtectionRule{}
	seen := map[string]bool{}
	for _, rule := range rules {
		if rule.Module != module {
			continue
		}
		if rule.LegacyRef != "" {
			seen[rule.LegacyRef] = true
		}
		items = append(items, rule)
	}
	return items, seen
}

func mustFilterProtectionRules(rules []model.ProtectionRule, module string) []model.ProtectionRule {
	items, _ := filterProtectionRules(rules, module)
	return items
}

func summaryCountTotal(items []model.SummaryCount, prefix string) []model.SummaryCount {
	if prefix == "" {
		return items
	}
	out := []model.SummaryCount{}
	for _, item := range items {
		if strings.Contains(item.Key, prefix) {
			out = append(out, item)
		}
	}
	return out
}

func protectionRisks(modules []model.ProtectionModuleOverview) []model.ProtectionModuleRisk {
	risks := []model.ProtectionModuleRisk{}
	for _, module := range modules {
		if len(module.RiskDetails) > 0 {
			for _, risk := range module.RiskDetails {
				if risk.Module == "" {
					risk.Module = module.Key
				}
				if risk.Label == "" {
					risk.Label = module.Label
				}
				risks = append(risks, risk)
			}
			continue
		}
		for _, warning := range module.Warnings {
			risks = append(risks, model.ProtectionModuleRisk{
				Module:  module.Key,
				Label:   module.Label,
				Message: warning,
			})
		}
	}
	return risks
}

func envelopeRiskDetails(data envelope) []model.ProtectionModuleRisk {
	values, ok := data["risk_details"].([]model.ProtectionModuleRisk)
	if !ok || values == nil {
		return []model.ProtectionModuleRisk{}
	}
	out := make([]model.ProtectionModuleRisk, len(values))
	copy(out, values)
	return out
}

func compatibilitySource(key string) string {
	switch key {
	case "cc-protection":
		return "rate_limits"
	default:
		return ""
	}
}

func envelopeInt(data envelope, keys ...string) int {
	for _, key := range keys {
		switch value := data[key].(type) {
		case int:
			return value
		case int64:
			return int(value)
		case float64:
			return int(value)
		}
	}
	return 0
}

func envelopeStrings(data envelope, key string) []string {
	values, ok := data[key].([]string)
	if !ok || values == nil {
		return []string{}
	}
	out := make([]string, len(values))
	copy(out, values)
	return out
}

func protectionRiskDetail(module, label, ruleName, scope, action, impact, recommendation, message string) model.ProtectionModuleRisk {
	return model.ProtectionModuleRisk{
		Module:         module,
		Label:          label,
		RuleName:       ruleName,
		Scope:          scope,
		Action:         action,
		Impact:         impact,
		Recommendation: recommendation,
		Message:        message,
	}
}

func riskMessages(risks []model.ProtectionModuleRisk) []string {
	messages := make([]string, 0, len(risks))
	for _, risk := range risks {
		messages = append(messages, risk.Message)
	}
	return messages
}

func methodScope(methods []string) string {
	if len(methods) == 0 {
		return "全部方法"
	}
	return strings.Join(methods, ",")
}

func broadProtectionPath(match model.ProtectionRuleMatch) bool {
	return match.Path == "/" && (match.PathMatch == "" || match.PathMatch == "prefix" || match.PathMatch == "glob")
}

func accessRuleScope(rule model.ProtectionRule) string {
	switch rule.Match.Target {
	case "ip", "cidr":
		return fmt.Sprintf("%s %s，方法 %s", rule.Match.Target, rule.Match.Value, methodScope(rule.Match.Methods))
	case "host":
		host := rule.Match.Host
		if host == "" {
			host = rule.Match.Value
		}
		return fmt.Sprintf("Host %s %s，方法 %s", rule.Match.Operator, host, methodScope(rule.Match.Methods))
	case "header":
		return fmt.Sprintf("Header %s %s %s，方法 %s", rule.Match.HeaderName, rule.Match.Operator, rule.Match.Value, methodScope(rule.Match.Methods))
	default:
		return fmt.Sprintf("%s %s，方法 %s", rule.Match.PathMatch, rule.Match.Path, methodScope(rule.Match.Methods))
	}
}

func uploadRuleScope(rule model.ProtectionRule) string {
	extensions := "全部扩展名"
	maxBytes := "未限制大小"
	if rule.Upload != nil {
		if len(rule.Upload.Extensions) > 0 {
			extensions = strings.Join(rule.Upload.Extensions, ",")
		}
		if rule.Upload.MaxBytes > 0 {
			maxBytes = fmt.Sprintf("%d bytes", rule.Upload.MaxBytes)
		}
	}
	return fmt.Sprintf("%s %s，方法 %s，扩展名 %s，大小 %s", rule.Match.PathMatch, rule.Match.Path, methodScope(rule.Match.Methods), extensions, maxBytes)
}

func botRuleScope(rule model.ProtectionRule) string {
	mode := "js-challenge"
	ttl := 0
	if rule.Challenge != nil {
		mode = rule.Challenge.Mode
		ttl = rule.Challenge.VerifyTTL
	}
	return fmt.Sprintf("%s %s，方法 %s，模式 %s，TTL %d 秒", rule.Match.PathMatch, rule.Match.Path, methodScope(rule.Match.Methods), mode, ttl)
}

func dynamicRuleScope(rule model.ProtectionRule) string {
	if rule.Dynamic == nil {
		return fmt.Sprintf("%s %s，方法 %s，类别 %s", rule.Match.PathMatch, rule.Match.Path, methodScope(rule.Match.Methods), rule.Category)
	}
	switch rule.Category {
	case "dynamic-token":
		return fmt.Sprintf("%s %s，方法 %s，令牌位置 %s，TTL %d 秒", rule.Match.PathMatch, rule.Match.Path, methodScope(rule.Match.Methods), rule.Dynamic.TokenPlacement, rule.Dynamic.TokenTTL)
	case "page-mutation":
		return fmt.Sprintf("%s %s，方法 %s，插入点 %s，响应上限 %d bytes", rule.Match.PathMatch, rule.Match.Path, methodScope(rule.Match.Methods), rule.Dynamic.MutationMarker, rule.Dynamic.MutationMaxBytes)
	case "waiting-room":
		return fmt.Sprintf("%s %s，方法 %s，容量 %d，重试 %d 秒", rule.Match.PathMatch, rule.Match.Path, methodScope(rule.Match.Methods), rule.Dynamic.QueueCapacity, rule.Dynamic.RetryInterval)
	default:
		return fmt.Sprintf("%s %s，方法 %s，类别 %s", rule.Match.PathMatch, rule.Match.Path, methodScope(rule.Match.Methods), rule.Category)
	}
}

func ruleEcosystemSummary(rules []model.Rule, catalogs []model.RuleCatalogSource, catalogPackages []model.RuleCatalogPackage, trustKeys []model.RuleTrustKey, providers []model.RuleProviderAdapter, providerPackages []model.RuleProviderPackage) envelope {
	packages := rulepkg.PackagesFromRules(rules)
	signatures := map[string]int{}
	disabledImported := 0
	untestedBlocking := 0
	pendingUpdates := 0
	remoteOriginPackages := map[string]bool{}
	providerOriginPackages := map[string]bool{}
	staleProviderPackages := 0
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
		if rule.ProviderID > 0 {
			providerOriginPackages[rule.PackageID] = true
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
	for _, provider := range providers {
		switch provider.HealthStatus {
		case rulepkg.ProviderHealthUnauthorized:
			warnings = append(warnings, fmt.Sprintf("Provider %s 授权失败，已导入规则不会被自动停用", provider.Name))
		case rulepkg.ProviderHealthFailed:
			warnings = append(warnings, fmt.Sprintf("Provider %s 同步失败：%s", provider.Name, provider.LastError))
		case rulepkg.ProviderHealthStale:
			warnings = append(warnings, fmt.Sprintf("Provider %s 元数据已过期", provider.Name))
		}
		if provider.RetryExhausted {
			warnings = append(warnings, fmt.Sprintf("Provider %s 重试次数已耗尽", provider.Name))
		}
	}
	for _, item := range providerPackages {
		status := item.SignatureStatus
		if status == "" {
			status = rulepkg.SignatureUnsigned
		}
		signatures[status] += 0
		if item.Stale {
			staleProviderPackages++
			warnings = append(warnings, fmt.Sprintf("Provider 包 %s@%s 使用过期同步元数据", item.PackageID, item.Version))
		}
		if item.EntitlementState == rulepkg.ProviderEntitlementUnauthorized || item.EntitlementState == rulepkg.ProviderEntitlementDenied {
			warnings = append(warnings, fmt.Sprintf("Provider 包 %s@%s 授权状态为 %s", item.PackageID, item.Version, item.EntitlementState))
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
		"packages":                 len(packages),
		"package_ids":              packageIDs,
		"signature_status":         signatures,
		"disabled_imported":        disabledImported,
		"untested_blocking":        untestedBlocking,
		"catalog_sources":          len(catalogs),
		"catalog_packages":         len(catalogPackages),
		"remote_origin_packages":   len(remoteOriginPackages),
		"provider_adapters":        len(providers),
		"provider_packages":        len(providerPackages),
		"provider_origin_packages": len(providerOriginPackages),
		"stale_provider_packages":  staleProviderPackages,
		"pending_updates":          pendingUpdates,
		"warnings":                 warnings,
		"gateway_hot_path":         "published-rules-only",
		"remote_sync_enabled":      len(catalogs) > 0 || len(providers) > 0,
	}
}

func ipAccessListSummary(items []model.IPAccessListEntry) envelope {
	enabled := 0
	allow := 0
	block := 0
	exact := 0
	cidr := 0
	global := 0
	siteScoped := 0
	for _, item := range items {
		normalized, err := ipaccess.Normalize(item)
		if err == nil {
			item = normalized
		}
		if item.SiteID > 0 {
			siteScoped++
		} else {
			global++
		}
		if item.Target == ipaccess.TargetCIDR {
			cidr++
		} else {
			exact++
		}
		if !item.Enabled {
			continue
		}
		enabled++
		switch item.Kind {
		case ipaccess.KindAllow:
			allow++
		case ipaccess.KindBlock:
			block++
		}
	}
	return envelope{
		"rules":       len(items),
		"total":       len(items),
		"enabled":     enabled,
		"allow":       allow,
		"block":       block,
		"exact_ip":    exact,
		"cidr":        cidr,
		"global":      global,
		"site_scoped": siteScoped,
		"warnings":    []string{},
	}
}

func accessControlSummary(rules []model.ProtectionRule) envelope {
	enabled := 0
	allow := 0
	block := 0
	logOnly := 0
	risks := []model.ProtectionModuleRisk{}
	migration := migrationSummary(rules)
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		enabled++
		switch rule.Action.Type {
		case "allow":
			allow++
			if rule.Match.Target == "ip" && (rule.Match.Value == "0.0.0.0" || rule.Match.Value == "::") {
				risks = append(risks, protectionRiskDetail("access-control", "访问控制", rule.Name, accessRuleScope(rule), rule.Action.Type, "宽泛来源放行可能绕过后续防护模块", "确认来源范围是否可信，必要时改为 CIDR 白名单并提高优先级可见性", fmt.Sprintf("规则 %s 使用较宽泛的来源放行", rule.Name)))
			}
			if rule.Match.Target == "path" && rule.Match.Path == "/" && rule.Match.PathMatch == "prefix" {
				risks = append(risks, protectionRiskDetail("access-control", "访问控制", rule.Name, accessRuleScope(rule), rule.Action.Type, "全站放行可能成为终止性允许决策", "确认该规则只用于可信来源，并优先使用更窄路径或 Host 条件", fmt.Sprintf("规则 %s 对全站路径使用放行动作", rule.Name)))
			}
		case "log-only":
			logOnly++
		case "block":
			block++
			if broadProtectionPath(rule.Match) && len(rule.Match.Methods) == 0 {
				risks = append(risks, protectionRiskDetail("access-control", "访问控制", rule.Name, accessRuleScope(rule), rule.Action.Type, "全站阻断可能导致站点不可用", "先使用观察模式验证命中，再收窄来源、Host 或路径范围", fmt.Sprintf("规则 %s 对宽泛范围使用阻断动作", rule.Name)))
			}
		}
	}
	return envelope{
		"rules":           len(rules),
		"enabled":         enabled,
		"allow":           allow,
		"block":           block,
		"log_only":        logOnly,
		"warnings":        riskMessages(risks),
		"risk_details":    risks,
		"migrated":        migration.Migrated,
		"legacy_fallback": migration.LegacyFallback,
		"disabled":        migration.Disabled,
	}
}

func ccProtectionSummary(rules []model.ProtectionRule) envelope {
	enabled := 0
	block := 0
	logOnly := 0
	advancedCounters := 0
	globRules := 0
	risks := []model.ProtectionModuleRisk{}
	migration := migrationSummary(rules)
	for _, rule := range rules {
		if rule.Enabled {
			enabled++
			switch rule.Action.Type {
			case "log-only":
				logOnly++
			case "block", "ban", "rate-limit":
				block++
			}
			if rule.Match.PathMatch == "glob" {
				globRules++
			}
			switch rule.Limit.Counter {
			case "not_found_frequency", "attack_frequency", "session", "device":
				advancedCounters++
			}
			risks = append(risks, ccRuleRiskDetails(rule)...)
			if rule.Match.Path == "/" && rule.Match.PathMatch == "prefix" && rule.Limit.Threshold > 0 && rule.Limit.Threshold < 60 && rule.Limit.WindowSec <= 60 {
				found := false
				message := fmt.Sprintf("规则 %s 对全站路径使用较低阈值", rule.Name)
				for _, existing := range risks {
					if existing.Message == message {
						found = true
						break
					}
				}
				if !found {
					risks = append(risks, protectionRiskDetail("cc-protection", "CC 防护", rule.Name, fmt.Sprintf("%s %s，方法 %s", rule.Match.PathMatch, rule.Match.Path, methodScope(rule.Match.Methods)), rule.Action.Type, "全站低阈值可能限制正常用户访问", "先使用观察模式或提高阈值，确认业务峰值后再发布", message))
				}
			}
		}
	}
	return envelope{
		"rules":             len(rules),
		"enabled":           enabled,
		"block":             block,
		"log_only":          logOnly,
		"advanced_counters": advancedCounters,
		"glob_rules":        globRules,
		"warnings":          riskMessages(risks),
		"risk_details":      risks,
		"migrated":          migration.Migrated,
		"legacy_fallback":   migration.LegacyFallback,
		"disabled":          migration.Disabled,
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

func uploadProtectionSummary(rules []model.ProtectionRule) envelope {
	enabled := 0
	extensionRules := 0
	sizeRules := 0
	block := 0
	logOnly := 0
	risks := []model.ProtectionModuleRisk{}
	migration := migrationSummary(rules)
	for _, item := range rules {
		if !item.Enabled {
			continue
		}
		enabled++
		if item.Upload != nil && len(item.Upload.Extensions) > 0 {
			extensionRules++
		}
		if item.Upload != nil && item.Upload.MaxBytes > 0 {
			sizeRules++
			if item.Action.Type == "block" && item.Upload.MaxBytes < 1024*1024 {
				risks = append(risks, protectionRiskDetail("upload-protection", "上传防护", item.Name, uploadRuleScope(item), item.Action.Type, "较小上传大小限制可能影响头像、附件或业务文件上传", "确认业务文件大小基线，必要时先使用观察模式或收窄路径", fmt.Sprintf("规则 %s 使用较小上传大小限制", item.Name)))
			}
		}
		switch item.Action.Type {
		case "log-only":
			logOnly++
		case "block":
			block++
			if broadProtectionPath(item.Match) || (item.Upload != nil && len(item.Upload.Extensions) == 0 && item.Upload.MaxBytes == 0) {
				risks = append(risks, protectionRiskDetail("upload-protection", "上传防护", item.Name, uploadRuleScope(item), item.Action.Type, "宽泛上传阻断可能影响所有上传入口", "限定上传路径、方法或扩展名，并先验证真实业务上传流量", fmt.Sprintf("规则 %s 对宽泛上传范围使用阻断动作", item.Name)))
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
		"warnings":        riskMessages(risks),
		"risk_details":    risks,
		"migrated":        migration.Migrated,
		"legacy_fallback": migration.LegacyFallback,
		"disabled":        migration.Disabled,
	}
}

func botProtectionSummary(rules []model.ProtectionRule) envelope {
	enabled := 0
	challenges := 0
	captcha := 0
	behaviorScoring := 0
	deviceBinding := 0
	searchEngineBypass := 0
	block := 0
	logOnly := 0
	risks := []model.ProtectionModuleRisk{}
	migration := migrationSummary(rules)
	for _, item := range rules {
		if !item.Enabled {
			continue
		}
		enabled++
		if item.Challenge != nil {
			switch item.Challenge.Mode {
			case "js-challenge":
				challenges++
			case "captcha":
				captcha++
			}
			if item.Challenge.BehaviorEnabled {
				behaviorScoring++
			}
			if item.Challenge.DeviceBinding {
				deviceBinding++
			}
			if item.Challenge.SearchEngineBypass {
				searchEngineBypass++
			}
		}
		failureAction := ""
		if item.Challenge != nil {
			failureAction = item.Challenge.FailureAction
		}
		switch failureAction {
		case "log-only":
			logOnly++
		case "block":
			block++
			if broadProtectionPath(item.Match) {
				risks = append(risks, protectionRiskDetail("bot-protection", "Bot / 人机验证", item.Name, botRuleScope(item), failureAction, "全站挑战阻断可能影响正常用户、爬虫和回调请求", "先限定高风险路径或使用观察模式，确认挑战通过率后再扩大范围", fmt.Sprintf("规则 %s 对全站路径启用 Bot Challenge 阻断", item.Name)))
			}
			if len(item.Match.Methods) == 0 {
				risks = append(risks, protectionRiskDetail("bot-protection", "Bot / 人机验证", item.Name, botRuleScope(item), failureAction, "全部方法挑战可能影响 POST、回调或 API 请求", "优先限制 GET/登录等目标方法，并为 API 保留绕过策略", fmt.Sprintf("规则 %s 对全部方法启用 Bot Challenge 阻断", item.Name)))
			}
			if item.Challenge != nil && (item.Challenge.BehaviorEnabled || item.Challenge.DeviceBinding || item.Challenge.Mode == "captcha") && (broadProtectionPath(item.Match) || len(item.Match.Methods) == 0) {
				risks = append(risks, protectionRiskDetail("bot-protection", "Bot / 人机验证", item.Name, botRuleScope(item), failureAction, "严格挑战增强可能造成兼容性或误拦截问题", "确认 captcha、行为评分或设备信号对目标客户端兼容，再发布到宽泛范围", fmt.Sprintf("规则 %s 使用严格 Bot 增强并覆盖宽泛范围", item.Name)))
			}
		}
	}
	return envelope{
		"rules":                len(rules),
		"enabled":              enabled,
		"challenges":           challenges,
		"captcha":              captcha,
		"behavior_scoring":     behaviorScoring,
		"device_binding":       deviceBinding,
		"search_engine_bypass": searchEngineBypass,
		"block":                block,
		"log_only":             logOnly,
		"warnings":             riskMessages(risks),
		"risk_details":         risks,
		"migrated":             migration.Migrated,
		"legacy_fallback":      migration.LegacyFallback,
		"disabled":             migration.Disabled,
	}
}

func dynamicProtectionSummary(rules []model.ProtectionRule) envelope {
	enabled := 0
	dynamicTokens := 0
	pageMutations := 0
	waitingRooms := 0
	block := 0
	logOnly := 0
	waitingRoomAction := 0
	risks := []model.ProtectionModuleRisk{}
	migration := migrationSummary(rules)
	for _, item := range rules {
		if !item.Enabled {
			continue
		}
		enabled++
		switch item.Category {
		case "dynamic-token":
			dynamicTokens++
			failureAction := ""
			if item.Dynamic != nil {
				failureAction = item.Dynamic.FailureAction
			}
			switch failureAction {
			case "block":
				block++
				if broadProtectionPath(item.Match) {
					risks = append(risks, protectionRiskDetail("dynamic-protection", "动态防护 / 等候室", item.Name, dynamicRuleScope(item), failureAction, "全站动态令牌阻断可能影响无状态客户端或未注入令牌的入口", "确认 token 发放路径覆盖目标页面，并先从关键路径小范围发布", fmt.Sprintf("规则 %s 对全站路径启用动态令牌阻断", item.Name)))
				}
				if len(item.Match.Methods) == 0 {
					risks = append(risks, protectionRiskDetail("dynamic-protection", "动态防护 / 等候室", item.Name, dynamicRuleScope(item), failureAction, "全部方法动态令牌可能影响 API、回调或静态资源请求", "限定需要浏览器令牌的路径和方法，保留 API 兼容入口", fmt.Sprintf("规则 %s 对全部方法启用动态令牌阻断", item.Name)))
				}
			case "log-only":
				logOnly++
			}
		case "page-mutation":
			pageMutations++
			logOnly++
			mutationMaxBytes := 0
			if item.Dynamic != nil {
				mutationMaxBytes = item.Dynamic.MutationMaxBytes
			}
			if broadProtectionPath(item.Match) || mutationMaxBytes > 1024*1024 {
				risks = append(risks, protectionRiskDetail("dynamic-protection", "动态防护 / 等候室", item.Name, dynamicRuleScope(item), "page-mutation", "宽泛页面动态化可能影响前端兼容或缓存命中", "先限制 HTML 页面路径并确认响应大小边界，再扩大覆盖", fmt.Sprintf("规则 %s 对宽泛 HTML 响应启用页面动态化", item.Name)))
			}
		case "waiting-room":
			waitingRooms++
			overflowAction := ""
			queueCapacity := 0
			if item.Dynamic != nil {
				overflowAction = item.Dynamic.OverflowAction
				queueCapacity = item.Dynamic.QueueCapacity
			}
			switch overflowAction {
			case "waiting-room":
				waitingRoomAction++
				if broadProtectionPath(item.Match) && queueCapacity < 50 {
					risks = append(risks, protectionRiskDetail("dynamic-protection", "动态防护 / 等候室", item.Name, dynamicRuleScope(item), overflowAction, "低容量全站等候室可能让正常用户排队或收到过载响应", "根据真实并发设置容量，先对活动入口小范围启用", fmt.Sprintf("规则 %s 对全站使用较低等候室容量", item.Name)))
				}
			case "block":
				block++
				if broadProtectionPath(item.Match) {
					risks = append(risks, protectionRiskDetail("dynamic-protection", "动态防护 / 等候室", item.Name, dynamicRuleScope(item), overflowAction, "等候室溢出阻断可能在流量峰值时直接拒绝正常用户", "优先使用 waiting-room 动作并设置合理容量，再考虑阻断溢出", fmt.Sprintf("规则 %s 对宽泛等候室范围使用阻断溢出动作", item.Name)))
				}
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
		"warnings":            riskMessages(risks),
		"risk_details":        risks,
		"migrated":            migration.Migrated,
		"legacy_fallback":     migration.LegacyFallback,
		"disabled":            migration.Disabled,
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
	artifacts, err := publish.WriteRuntimeArtifactsFromConfigWithClientMaxBodySize(r.Context(), h.app.Store, []byte(record.ConfigJSON), h.app.Config.GatewayConfigPath, h.app.Config.GatewayClientMaxBodySize)
	if err != nil {
		h.audit(r, "rollback", "release", record.ID, "failure", err)
		h.writeServerError(w, err)
		return
	}
	applications, err := publish.ApplicationsFromConfigJSON([]byte(record.ConfigJSON))
	if err != nil {
		h.audit(r, "rollback", "release", record.ID, "failure", err)
		h.writeServerError(w, err)
		return
	}
	activation := publishActivationSummary(applications, artifacts, []string{}, record.Version)
	applyReloadResult(&activation, runGatewayReload(r.Context(), h.app.Config.GatewayReloadCommand))
	rollback, err := h.app.Store.CreatePublishRecord(r.Context(), model.PublishRecord{
		Version:    fmt.Sprintf("%s-rollback-%d", record.Version, time.Now().UTC().Unix()),
		Operator:   currentActor(r).Username,
		Status:     "success",
		ConfigPath: h.app.Config.GatewayConfigPath,
		Checksum:   record.Checksum,
		Note:       model.FormatPublishNote("rollback to "+record.Version, activation),
		ConfigJSON: record.ConfigJSON,
		Activation: &activation,
	})
	h.auditMessage(r, "rollback", "release", rollback.ID, resultFromErr(err), activationAuditSummary(activation), err)
	h.writeCreated(w, rollback, err)
}

func (h handlers) listAuditLogs(w http.ResponseWriter, r *http.Request) {
	filter, ok := parseAuditFilter(w, r)
	if !ok {
		return
	}
	result, err := h.app.Store.ListAuditLogs(r.Context(), filter)
	h.writePagedList(w, result.Items, result.Total, result.Pagination, err)
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
	SiteIDs                    []int64  `json:"application_ids"`
	LegacySiteIDs              []int64  `json:"site_ids"`
	RuleIDs                    []int64  `json:"rule_ids"`
}

func (r policyRequest) toModel() model.Policy {
	siteIDs := r.SiteIDs
	if len(siteIDs) == 0 {
		siteIDs = r.LegacySiteIDs
	}
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
		SiteIDs:                    cloneIDs(siteIDs),
		RuleIDs:                    cloneIDs(r.RuleIDs),
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
	SiteID             int64    `json:"application_id"`
	LegacySiteID       int64    `json:"site_id"`
	Enabled            *bool    `json:"enabled"`
}

func (r rateLimitRequest) toModel() model.RateLimitRule {
	siteID := r.SiteID
	if siteID == 0 {
		siteID = r.LegacySiteID
	}
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
		SiteID:             siteID,
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
	writeJSON(w, http.StatusOK, envelope{"items": nonNilList(items)})
}

func (h handlers) writePagedList(w http.ResponseWriter, items any, total int, pagination model.Pagination, err error) {
	if err != nil {
		h.writeServerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envelope{
		"items":  nonNilList(items),
		"total":  total,
		"limit":  pagination.Limit,
		"offset": pagination.Offset,
	})
}

func nonNilList(items any) any {
	if items == nil {
		return []any{}
	}

	value := reflect.ValueOf(items)
	if value.Kind() == reflect.Slice && value.IsNil() {
		return reflect.MakeSlice(value.Type(), 0, 0).Interface()
	}

	return items
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
		return errors.New("policy application_ids is required")
	}
	if len(policy.RuleIDs) == 0 {
		return errors.New("policy rule_ids is required")
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
	var ok bool
	if filter.Pagination, ok = parsePagination(w, r); !ok {
		return model.AuditLogFilter{}, false
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
	h.auditMessage(r, action, resourceType, resourceID, result, "", operationErr)
}

func (h handlers) auditMessage(r *http.Request, action string, resourceType string, resourceID int64, result string, message string, operationErr error) {
	current := currentActor(r)
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
