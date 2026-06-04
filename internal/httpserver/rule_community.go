package httpserver

import (
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
