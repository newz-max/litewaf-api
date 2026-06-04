package httpserver

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"litewaf-api/internal/model"
	"litewaf-api/internal/rulepkg"
)

type ruleCatalogRequest struct {
	Name       string `json:"name"`
	Source     string `json:"source"`
	Enabled    *bool  `json:"enabled"`
	TimeoutSec int    `json:"timeout_sec"`
}

func (r ruleCatalogRequest) toModel() model.RuleCatalogSource {
	return model.RuleCatalogSource{
		Name:       r.Name,
		Source:     r.Source,
		Enabled:    boolValue(r.Enabled, true),
		TimeoutSec: r.TimeoutSec,
	}
}

type ruleTrustKeyRequest struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Owner     string `json:"owner"`
	PublicKey string `json:"public_key"`
	Enabled   *bool  `json:"enabled"`
	Revoked   *bool  `json:"revoked"`
	ExpiresAt string `json:"expires_at"`
}

type ruleAccountSourceRequest struct {
	Name               string                      `json:"name"`
	ProviderType       string                      `json:"provider_type"`
	ProviderAdapterID  int64                       `json:"provider_adapter_id"`
	Endpoint           string                      `json:"endpoint"`
	Enabled            *bool                       `json:"enabled"`
	TimeoutSec         int                         `json:"timeout_sec"`
	Credential         model.RuleAccountCredential `json:"credential"`
	CredentialSecret   string                      `json:"credential_secret"`
	SubscriptionStatus string                      `json:"subscription_status"`
	EntitlementSummary string                      `json:"entitlement_summary"`
	PackageCount       int                         `json:"package_count"`
}

func (r ruleAccountSourceRequest) toModel() model.RuleCommunityAccountSource {
	return model.RuleCommunityAccountSource{
		Name:               r.Name,
		ProviderType:       r.ProviderType,
		ProviderAdapterID:  r.ProviderAdapterID,
		Endpoint:           r.Endpoint,
		Enabled:            boolValue(r.Enabled, true),
		TimeoutSec:         r.TimeoutSec,
		Credential:         r.Credential,
		SubscriptionStatus: r.SubscriptionStatus,
		EntitlementSummary: r.EntitlementSummary,
		PackageCount:       r.PackageCount,
	}
}

type ruleProviderRequest struct {
	Name             string                         `json:"name"`
	ProviderType     string                         `json:"provider_type"`
	Endpoint         string                         `json:"endpoint"`
	AuthMode         string                         `json:"auth_mode"`
	Enabled          *bool                          `json:"enabled"`
	TimeoutSec       int                            `json:"timeout_sec"`
	RetryPolicy      model.RuleProviderRetryPolicy  `json:"retry_policy"`
	Credential       model.RuleAccountCredential     `json:"credential"`
	CredentialSecret string                         `json:"credential_secret"`
}

func (r ruleProviderRequest) toModel() model.RuleProviderAdapter {
	return model.RuleProviderAdapter{
		Name:        r.Name,
		ProviderType: r.ProviderType,
		Endpoint:    r.Endpoint,
		AuthMode:    r.AuthMode,
		Enabled:     boolValue(r.Enabled, true),
		TimeoutSec:  r.TimeoutSec,
		RetryPolicy: r.RetryPolicy,
		Credential:  r.Credential,
	}
}

type ruleContributionTargetRequest struct {
	Name             string                      `json:"name"`
	Provider         string                      `json:"provider"`
	Endpoint         string                      `json:"endpoint"`
	Channel          string                      `json:"channel"`
	Enabled          *bool                       `json:"enabled"`
	Credential       model.RuleAccountCredential `json:"credential"`
	CredentialSecret string                      `json:"credential_secret"`
}

func (r ruleContributionTargetRequest) toModel() model.RuleContributionTarget {
	return model.RuleContributionTarget{
		Name:       r.Name,
		Provider:   r.Provider,
		Endpoint:   r.Endpoint,
		Channel:    r.Channel,
		Enabled:    boolValue(r.Enabled, true),
		Credential: r.Credential,
	}
}

type queueDecisionRequest struct {
	State  string `json:"state"`
	Reason string `json:"reason"`
}

type feedbackSuggestionDecisionRequest struct {
	State string `json:"state"`
}

func (r ruleTrustKeyRequest) toModel() (model.RuleTrustKey, error) {
	var expires time.Time
	if strings.TrimSpace(r.ExpiresAt) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(r.ExpiresAt))
		if err != nil {
			return model.RuleTrustKey{}, err
		}
		expires = parsed
	}
	return model.RuleTrustKey{
		KeyID:     strings.TrimSpace(r.KeyID),
		Algorithm: strings.ToLower(strings.TrimSpace(r.Algorithm)),
		Owner:     strings.TrimSpace(r.Owner),
		PublicKey: strings.TrimSpace(r.PublicKey),
		Enabled:   boolValue(r.Enabled, true),
		Revoked:   boolValue(r.Revoked, false),
		ExpiresAt: expires,
	}, nil
}

func (h handlers) listRuleCatalogs(w http.ResponseWriter, r *http.Request) {
	items, err := h.app.Store.ListRuleCatalogSources(r.Context())
	h.writeList(w, items, err)
}

func (h handlers) getRuleCatalog(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	item, err := h.app.Store.GetRuleCatalogSource(r.Context(), id)
	h.writeItem(w, item, err)
}

func (h handlers) createRuleCatalog(w http.ResponseWriter, r *http.Request) {
	var req ruleCatalogRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	input := rulepkg.NormalizeCatalogSource(req.toModel())
	if err := rulepkg.ValidateCatalogSource(input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	item, err := h.app.Store.CreateRuleCatalogSource(r.Context(), input)
	h.audit(r, "create", "rule_catalog", item.ID, resultFromErr(err), err)
	h.writeCreated(w, item, err)
}

func (h handlers) updateRuleCatalog(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var req ruleCatalogRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	existing, err := h.app.Store.GetRuleCatalogSource(r.Context(), id)
	if err != nil {
		h.writeKnownError(w, err)
		return
	}
	input := rulepkg.NormalizeCatalogSource(req.toModel())
	input.Status = existing.Status
	input.LastSyncAt = existing.LastSyncAt
	input.LastError = existing.LastError
	if err := rulepkg.ValidateCatalogSource(input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	item, err := h.app.Store.UpdateRuleCatalogSource(r.Context(), id, input)
	h.audit(r, "update", "rule_catalog", id, resultFromErr(err), err)
	h.writeItem(w, item, err)
}

func (h handlers) deleteRuleCatalog(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	err := h.app.Store.DeleteRuleCatalogSource(r.Context(), id)
	h.audit(r, "delete", "rule_catalog", id, resultFromErr(err), err)
	h.writeNoContent(w, err)
}

func (h handlers) syncRuleCatalog(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	source, err := h.app.Store.GetRuleCatalogSource(r.Context(), id)
	if err != nil {
		h.writeKnownError(w, err)
		return
	}
	trustKeys, _ := h.app.Store.ListRuleTrustKeys(r.Context())
	items, err := rulepkg.SyncCatalogWithTrustKeys(r.Context(), h.app.Store, source, trustKeys)
	h.audit(r, "sync", "rule_catalog", id, resultFromErr(err), err)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, envelope{"items": items})
}

func (h handlers) listRuleCatalogPackages(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	items, err := h.app.Store.ListRuleCatalogPackages(r.Context(), id)
	h.writeList(w, items, err)
}

func (h handlers) previewRemoteRulePackage(w http.ResponseWriter, r *http.Request) {
	catalogPackage, ok := h.catalogPackageFromPath(w, r)
	if !ok {
		return
	}
	trustKeys, _ := h.app.Store.ListRuleTrustKeys(r.Context())
	preview, err := rulepkg.RemotePreviewWithTrustKeys(r.Context(), h.app.Store, catalogPackage, trustKeys)
	h.audit(r, "preview", "rule_catalog_package", catalogPackage.ID, resultFromErr(err), err)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, envelope{"item": preview})
}

func (h handlers) previewRulePackageUpdate(w http.ResponseWriter, r *http.Request) {
	catalogPackage, ok := h.catalogPackageFromPath(w, r)
	if !ok {
		return
	}
	trustKeys, _ := h.app.Store.ListRuleTrustKeys(r.Context())
	preview, err := rulepkg.UpdatePreviewWithTrustKeys(r.Context(), h.app.Store, catalogPackage, trustKeys)
	h.audit(r, "preview_update", "rule_catalog_package", catalogPackage.ID, resultFromErr(err), err)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, envelope{"item": preview})
}

func (h handlers) applyRulePackageUpdate(w http.ResponseWriter, r *http.Request) {
	catalogPackage, ok := h.catalogPackageFromPath(w, r)
	if !ok {
		return
	}
	trustKeys, _ := h.app.Store.ListRuleTrustKeys(r.Context())
	result, err := rulepkg.ApplyUpdateWithTrustKeys(r.Context(), h.app.Store, catalogPackage, trustKeys)
	h.audit(r, "apply_update", "rule_catalog_package", catalogPackage.ID, resultFromErr(err), err)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, envelope{"item": result})
}

func (h handlers) listRuleTrustKeys(w http.ResponseWriter, r *http.Request) {
	items, err := h.app.Store.ListRuleTrustKeys(r.Context())
	h.writeList(w, items, err)
}

func (h handlers) createRuleTrustKey(w http.ResponseWriter, r *http.Request) {
	var req ruleTrustKeyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	input, err := req.toModel()
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid expires_at timestamp")
		return
	}
	if err := rulepkg.ValidateTrustKey(input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	item, err := h.app.Store.CreateRuleTrustKey(r.Context(), input)
	h.audit(r, "create", "rule_trust_key", item.ID, resultFromErr(err), err)
	h.writeCreated(w, item, err)
}

func (h handlers) updateRuleTrustKey(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var req ruleTrustKeyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	input, err := req.toModel()
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid expires_at timestamp")
		return
	}
	if err := rulepkg.ValidateTrustKey(input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	item, err := h.app.Store.UpdateRuleTrustKey(r.Context(), id, input)
	h.audit(r, "update", "rule_trust_key", id, resultFromErr(err), err)
	h.writeItem(w, item, err)
}

func (h handlers) listRuleProviders(w http.ResponseWriter, r *http.Request) {
	items, err := h.app.Store.ListRuleProviderAdapters(r.Context())
	h.writeList(w, items, err)
}

func (h handlers) getRuleProvider(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	item, err := h.app.Store.GetRuleProviderAdapter(r.Context(), id)
	h.writeItem(w, item, err)
}

func (h handlers) createRuleProvider(w http.ResponseWriter, r *http.Request) {
	var req ruleProviderRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	input := rulepkg.NormalizeProviderAdapter(req.toModel())
	secret := model.RuleCommunityAccountSecret{Secret: strings.TrimSpace(req.CredentialSecret)}
	if err := rulepkg.ValidateProviderAdapter(input, secret, input.AuthMode == rulepkg.ProviderAuthBearer); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	item, err := h.app.Store.CreateRuleProviderAdapter(r.Context(), input, secret)
	h.audit(r, "create", "rule_provider", item.ID, resultFromErr(err), err)
	h.writeCreated(w, item, err)
}

func (h handlers) updateRuleProvider(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var req ruleProviderRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	input := rulepkg.NormalizeProviderAdapter(req.toModel())
	secret := model.RuleCommunityAccountSecret{Secret: strings.TrimSpace(req.CredentialSecret)}
	if err := rulepkg.ValidateProviderAdapter(input, secret, false); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	item, err := h.app.Store.UpdateRuleProviderAdapter(r.Context(), id, input, secret)
	h.audit(r, "update", "rule_provider", id, resultFromErr(err), err)
	h.writeItem(w, item, err)
}

func (h handlers) deleteRuleProvider(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	err := h.app.Store.DeleteRuleProviderAdapter(r.Context(), id)
	h.audit(r, "delete", "rule_provider", id, resultFromErr(err), err)
	h.writeNoContent(w, err)
}

func (h handlers) validateRuleProvider(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	provider, err := h.app.Store.GetRuleProviderAdapter(r.Context(), id)
	if err != nil {
		h.writeKnownError(w, err)
		return
	}
	provider, validationErr := rulepkg.ValidateProviderCredentials(provider)
	item, err := h.app.Store.UpdateRuleProviderAdapter(r.Context(), id, provider, model.RuleCommunityAccountSecret{})
	if err == nil && validationErr != nil {
		err = validationErr
	}
	h.audit(r, "validate_credentials", "rule_provider", id, resultFromErr(err), err)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, envelope{"item": item})
}

func (h handlers) syncRuleProvider(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	provider, err := h.app.Store.GetRuleProviderAdapter(r.Context(), id)
	if err != nil {
		h.writeKnownError(w, err)
		return
	}
	item, packages, err := rulepkg.SyncProvider(r.Context(), h.app.Store, provider)
	h.audit(r, "sync", "rule_provider", id, resultFromErr(err), err)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, envelope{"item": item, "items": packages})
}

func (h handlers) retryRuleProvider(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	provider, err := h.app.Store.GetRuleProviderAdapter(r.Context(), id)
	if err != nil {
		h.writeKnownError(w, err)
		return
	}
	item, packages, err := rulepkg.RetryProvider(r.Context(), h.app.Store, provider)
	h.audit(r, "retry", "rule_provider", id, resultFromErr(err), err)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, envelope{"item": item, "items": packages})
}

func (h handlers) listRuleProviderPackages(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	items, err := h.app.Store.ListRuleProviderPackages(r.Context(), id)
	h.writeList(w, items, err)
}

func (h handlers) previewRuleProviderPackage(w http.ResponseWriter, r *http.Request) {
	provider, providerPackage, ok := h.providerPackageFromPath(w, r)
	if !ok {
		return
	}
	trustKeys, _ := h.app.Store.ListRuleTrustKeys(r.Context())
	preview, err := rulepkg.ProviderPackagePreview(r.Context(), h.app.Store, provider, providerPackage, trustKeys)
	h.audit(r, "preview", "rule_provider_package", providerPackage.ID, resultFromErr(err), err)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, envelope{"item": preview})
}

func (h handlers) importRuleProviderPackage(w http.ResponseWriter, r *http.Request) {
	provider, providerPackage, ok := h.providerPackageFromPath(w, r)
	if !ok {
		return
	}
	trustKeys, _ := h.app.Store.ListRuleTrustKeys(r.Context())
	catalogPackage := rulepkg.ProviderPackageCatalogPackage(provider, providerPackage)
	result, err := rulepkg.ApplyUpdateWithTrustKeys(r.Context(), h.app.Store, catalogPackage, trustKeys)
	if err == nil {
		for _, rule := range append(result.Imported, result.Changed...) {
			rule.ProviderID = provider.ID
			rule.ProviderName = provider.Name
			rule.ProviderPackageRef = providerPackage.ProviderPackageRef
			_, _ = h.app.Store.UpdateRule(r.Context(), rule.ID, rule)
		}
	}
	h.audit(r, "import", "rule_provider_package", providerPackage.ID, resultFromErr(err), err)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, envelope{"item": result})
}

func (h handlers) previewRulePackageExport(w http.ResponseWriter, r *http.Request) {
	var input model.RulePackageExportRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	preview, err := rulepkg.ExportPreview(r.Context(), h.app.Store, input)
	h.audit(r, "preview_export", "rule_package_export", 0, resultFromErr(err), err)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, envelope{"item": preview})
}

func (h handlers) exportRulePackage(w http.ResponseWriter, r *http.Request) {
	var input model.RulePackageExportRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	artifact, err := rulepkg.ExportArtifact(r.Context(), h.app.Store, input)
	h.audit(r, "export", "rule_package_export", 0, resultFromErr(err), err)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, envelope{"item": artifact})
}

func (h handlers) listRuleAccountSources(w http.ResponseWriter, r *http.Request) {
	items, err := h.app.Store.ListRuleCommunityAccountSources(r.Context())
	h.writeList(w, items, err)
}

func (h handlers) getRuleAccountSource(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	item, err := h.app.Store.GetRuleCommunityAccountSource(r.Context(), id)
	h.writeItem(w, item, err)
}

func (h handlers) createRuleAccountSource(w http.ResponseWriter, r *http.Request) {
	var req ruleAccountSourceRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	input := rulepkg.NormalizeAccountSource(req.toModel())
	secret := model.RuleCommunityAccountSecret{Secret: strings.TrimSpace(req.CredentialSecret)}
	if err := rulepkg.ValidateAccountSource(input, secret, true); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	item, err := h.app.Store.CreateRuleCommunityAccountSource(r.Context(), input, secret)
	h.audit(r, "create", "rule_account_source", item.ID, resultFromErr(err), err)
	h.writeCreated(w, item, err)
}

func (h handlers) updateRuleAccountSource(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var req ruleAccountSourceRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	input := rulepkg.NormalizeAccountSource(req.toModel())
	secret := model.RuleCommunityAccountSecret{Secret: strings.TrimSpace(req.CredentialSecret)}
	if err := rulepkg.ValidateAccountSource(input, secret, false); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	item, err := h.app.Store.UpdateRuleCommunityAccountSource(r.Context(), id, input, secret)
	h.audit(r, "update", "rule_account_source", id, resultFromErr(err), err)
	h.writeItem(w, item, err)
}

func (h handlers) deleteRuleAccountSource(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	err := h.app.Store.DeleteRuleCommunityAccountSource(r.Context(), id)
	h.audit(r, "delete", "rule_account_source", id, resultFromErr(err), err)
	h.writeNoContent(w, err)
}

func (h handlers) refreshRuleAccountSource(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	source, err := h.app.Store.GetRuleCommunityAccountSource(r.Context(), id)
	if err != nil {
		h.writeKnownError(w, err)
		return
	}
	item, err := rulepkg.RefreshAccountSource(r.Context(), h.app.Store, source)
	h.audit(r, "refresh", "rule_account_source", id, resultFromErr(err), err)
	h.writeItem(w, item, err)
}

func (h handlers) listRuleContributionTargets(w http.ResponseWriter, r *http.Request) {
	items, err := h.app.Store.ListRuleContributionTargets(r.Context())
	h.writeList(w, items, err)
}

func (h handlers) createRuleContributionTarget(w http.ResponseWriter, r *http.Request) {
	var req ruleContributionTargetRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	input := rulepkg.NormalizeContributionTarget(req.toModel())
	secret := model.RuleCommunityAccountSecret{Secret: strings.TrimSpace(req.CredentialSecret)}
	if err := rulepkg.ValidateContributionTarget(input, secret, true); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	item, err := h.app.Store.CreateRuleContributionTarget(r.Context(), input, secret)
	h.audit(r, "create", "rule_contribution_target", item.ID, resultFromErr(err), err)
	h.writeCreated(w, item, err)
}

func (h handlers) listRuleContributionPushes(w http.ResponseWriter, r *http.Request) {
	items, err := h.app.Store.ListRuleContributionPushAttempts(r.Context())
	h.writeList(w, items, err)
}

func (h handlers) previewRuleContributionPush(w http.ResponseWriter, r *http.Request) {
	var input model.RuleContributionPushRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	target, err := h.app.Store.GetRuleContributionTarget(r.Context(), input.TargetID)
	if err != nil {
		h.writeKnownError(w, err)
		return
	}
	attempt, err := rulepkg.PreviewContributionPush(target, input.Artifact, currentActor(r).Username)
	h.audit(r, "preview_push", "rule_contribution_target", target.ID, resultFromErr(err), err)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, envelope{"item": attempt})
}

func (h handlers) executeRuleContributionPush(w http.ResponseWriter, r *http.Request) {
	var input model.RuleContributionPushRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	target, err := h.app.Store.GetRuleContributionTarget(r.Context(), input.TargetID)
	if err != nil {
		h.writeKnownError(w, err)
		return
	}
	attempt, err := rulepkg.ExecuteContributionPush(target, input.Artifact, currentActor(r).Username)
	if err == nil {
		attempt, err = h.app.Store.CreateRuleContributionPushAttempt(r.Context(), attempt)
	}
	h.audit(r, "push", "rule_contribution_target", target.ID, resultFromErr(err), err)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, envelope{"item": attempt})
}

func (h handlers) listRuleReviewQueue(w http.ResponseWriter, r *http.Request) {
	items, err := h.app.Store.ListRuleReviewQueueItems(r.Context())
	h.writeList(w, items, err)
}

func (h handlers) decideRuleReviewQueueItem(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var req queueDecisionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := h.app.Store.GetRuleReviewQueueItem(r.Context(), id)
	if err != nil {
		h.writeKnownError(w, err)
		return
	}
	item, err = rulepkg.ApplyQueueDecision(item, req.State, req.Reason, currentActor(r).Username)
	if err == nil {
		item, err = h.app.Store.UpdateRuleReviewQueueItem(r.Context(), id, item)
	}
	h.audit(r, "decide", "rule_review_queue", id, resultFromErr(err), err)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, envelope{"item": item})
}

func (h handlers) listRuleFeedback(w http.ResponseWriter, r *http.Request) {
	items, err := h.app.Store.ListRuleFeedback(r.Context())
	h.writeList(w, items, err)
}

func (h handlers) createRuleFeedback(w http.ResponseWriter, r *http.Request) {
	var input model.RuleFeedback
	if !decodeJSON(w, r, &input) {
		return
	}
	input = rulepkg.NormalizeFeedback(input)
	input.Actor = currentActor(r).Username
	if err := rulepkg.ValidateFeedback(input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	item, err := h.app.Store.CreateRuleFeedback(r.Context(), input)
	if err == nil {
		suggestion := rulepkg.SuggestionFromFeedback(item, currentActor(r).Username)
		_, err = h.app.Store.CreateRuleFeedbackSuggestion(r.Context(), suggestion)
	}
	h.audit(r, "create", "rule_feedback", item.ID, resultFromErr(err), err)
	h.writeCreated(w, item, err)
}

func (h handlers) listRuleFeedbackSuggestions(w http.ResponseWriter, r *http.Request) {
	items, err := h.app.Store.ListRuleFeedbackSuggestions(r.Context())
	h.writeList(w, items, err)
}

func (h handlers) testRuleFeedbackSuggestion(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	item, err := h.app.Store.GetRuleFeedbackSuggestion(r.Context(), id)
	if err != nil {
		h.writeKnownError(w, err)
		return
	}
	if item.RuleID <= 0 {
		err := errors.New("feedback suggestion has no rule to test")
		h.audit(r, "test", "rule_feedback_suggestion", id, "failure", err)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	rule, err := h.app.Store.GetRule(r.Context(), item.RuleID)
	if err == nil {
		item.TestResult, err = rulepkg.TestRule(rule, model.RuleTestSample{Method: "GET", Path: "/", Query: map[string]string{}, Headers: map[string]string{}})
		item.State = rulepkg.FeedbackSuggestionTested
		item.Actor = currentActor(r).Username
		item, err = h.app.Store.UpdateRuleFeedbackSuggestion(r.Context(), id, item)
	}
	h.audit(r, "test", "rule_feedback_suggestion", id, resultFromErr(err), err)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, envelope{"item": item})
}

func (h handlers) decideRuleFeedbackSuggestion(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var req feedbackSuggestionDecisionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := h.app.Store.GetRuleFeedbackSuggestion(r.Context(), id)
	if err != nil {
		h.writeKnownError(w, err)
		return
	}
	item, err = rulepkg.ApplySuggestionDecision(item, req.State, currentActor(r).Username)
	if err == nil {
		item, err = h.app.Store.UpdateRuleFeedbackSuggestion(r.Context(), id, item)
	}
	h.audit(r, "decide", "rule_feedback_suggestion", id, resultFromErr(err), err)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, envelope{"item": item})
}

func (h handlers) catalogPackageFromPath(w http.ResponseWriter, r *http.Request) (model.RuleCatalogPackage, bool) {
	catalogID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || catalogID <= 0 {
		writeError(w, http.StatusBadRequest, "invalid catalog id")
		return model.RuleCatalogPackage{}, false
	}
	packageID := strings.TrimSpace(r.PathValue("package_id"))
	item, err := h.app.Store.GetRuleCatalogPackage(r.Context(), catalogID, packageID)
	if err != nil {
		h.writeKnownError(w, err)
		return model.RuleCatalogPackage{}, false
	}
	return item, true
}

func (h handlers) providerPackageFromPath(w http.ResponseWriter, r *http.Request) (model.RuleProviderAdapter, model.RuleProviderPackage, bool) {
	providerID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || providerID <= 0 {
		writeError(w, http.StatusBadRequest, "invalid provider id")
		return model.RuleProviderAdapter{}, model.RuleProviderPackage{}, false
	}
	packageID := strings.TrimSpace(r.PathValue("package_id"))
	provider, err := h.app.Store.GetRuleProviderAdapter(r.Context(), providerID)
	if err != nil {
		h.writeKnownError(w, err)
		return model.RuleProviderAdapter{}, model.RuleProviderPackage{}, false
	}
	item, err := h.app.Store.GetRuleProviderPackage(r.Context(), providerID, packageID)
	if err != nil {
		h.writeKnownError(w, err)
		return model.RuleProviderAdapter{}, model.RuleProviderPackage{}, false
	}
	return provider, item, true
}
