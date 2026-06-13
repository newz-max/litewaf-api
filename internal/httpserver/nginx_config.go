package httpserver

import (
	"net/http"

	"litewaf-api/internal/model"
	"litewaf-api/internal/publish"
)

func (h handlers) getNginxConfigDraft(w http.ResponseWriter, r *http.Request) {
	item, err := h.app.Store.GetNginxConfigDraft(r.Context())
	h.writeItem(w, item, err)
}

func (h handlers) updateNginxConfigDraft(w http.ResponseWriter, r *http.Request) {
	var input model.NginxConfigDraft
	if !decodeJSON(w, r, &input) {
		return
	}
	input.UpdatedBy = currentActor(r).Username
	if input.Validation.Status == "" {
		input.Validation = model.NginxValidationResult{Status: model.NginxValidationStatusUnchecked}
	}
	item, err := h.app.Store.SaveNginxConfigDraft(r.Context(), input)
	h.auditMessage(r, "update", "nginx-config", 1, resultFromErr(err), nginxConfigAuditSummary(item), err)
	h.writeItem(w, item, err)
}

func (h handlers) validateNginxConfigDraft(w http.ResponseWriter, r *http.Request) {
	review, err := publish.BuildAdvancedNginxReview(
		r.Context(),
		h.app.Store,
		h.app.Config.GatewayConfigPath,
		h.app.Config.GatewayClientMaxBodySize,
		h.app.Config.NginxValidationCommand,
	)
	if err != nil {
		h.writeServerError(w, err)
		return
	}
	draft, err := h.app.Store.GetNginxConfigDraft(r.Context())
	if err != nil {
		h.writeServerError(w, err)
		return
	}
	draft.Validation = review.Validation
	draft.UpdatedBy = currentActor(r).Username
	if saved, saveErr := h.app.Store.SaveNginxConfigDraft(r.Context(), draft); saveErr == nil {
		draft = saved
	}
	writeJSON(w, http.StatusOK, envelope{
		"item":   draft,
		"review": review,
	})
}

func nginxConfigAuditSummary(item model.NginxConfigDraft) string {
	return boundedSummary("mode="+item.Mode, 256)
}
