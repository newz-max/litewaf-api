package httpserver

import (
	"fmt"
	"net/http"
	"strings"

	"litewaf-api/internal/model"
)

type applicationRequest struct {
	Name        string                      `json:"name"`
	Mode        string                      `json:"mode"`
	Enabled     *bool                       `json:"enabled"`
	Description string                      `json:"description"`
	Hosts       []model.ApplicationHost     `json:"hosts"`
	Listeners   []model.ApplicationListener `json:"listeners"`
	Upstreams   []model.ApplicationUpstream `json:"upstreams"`
}

func (r applicationRequest) toModel() model.Application {
	item := model.Application{
		Name:        r.Name,
		Mode:        r.Mode,
		Enabled:     boolValue(r.Enabled, true),
		Description: r.Description,
		Hosts:       append([]model.ApplicationHost(nil), r.Hosts...),
		Listeners:   append([]model.ApplicationListener(nil), r.Listeners...),
		Upstreams:   append([]model.ApplicationUpstream(nil), r.Upstreams...),
	}
	model.NormalizeApplication(&item)
	return item
}

func (h handlers) listApplications(w http.ResponseWriter, r *http.Request) {
	items, err := h.app.Store.ListApplications(r.Context())
	h.writeList(w, items, err)
}

func (h handlers) getApplication(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	item, err := h.app.Store.GetApplication(r.Context(), id)
	h.writeItem(w, item, err)
}

func (h handlers) createApplication(w http.ResponseWriter, r *http.Request) {
	var req applicationRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	input := req.toModel()
	if err := model.ValidateApplication(input, h.certificateExists(r)); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	item, err := h.app.Store.CreateApplication(r.Context(), input)
	h.auditMessage(r, "create", "application", item.ID, resultFromErr(err), applicationAuditSummary(item), err)
	h.writeCreated(w, item, err)
}

func (h handlers) updateApplication(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var req applicationRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	input := req.toModel()
	if err := model.ValidateApplication(input, h.certificateExists(r)); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	item, err := h.app.Store.UpdateApplication(r.Context(), id, input)
	h.auditMessage(r, "update", "application", id, resultFromErr(err), applicationAuditSummary(input), err)
	h.writeItem(w, item, err)
}

func (h handlers) deleteApplication(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	err := h.app.Store.DeleteApplication(r.Context(), id)
	h.audit(r, "delete", "application", id, resultFromErr(err), err)
	h.writeNoContent(w, err)
}

func (h handlers) certificateExists(r *http.Request) func(int64) bool {
	return func(id int64) bool {
		_, err := h.app.Store.GetCertificate(r.Context(), id)
		return err == nil
	}
}

func applicationAuditSummary(item model.Application) string {
	listeners := make([]string, 0, len(item.Listeners))
	certificateIDs := map[int64]struct{}{}
	for _, listener := range item.Listeners {
		state := "disabled"
		if listener.Enabled {
			state = "enabled"
		}
		listeners = append(listeners, fmt.Sprintf("%d/%s/%s/cert:%d", listener.Port, listener.Protocol, state, listener.CertificateID))
		if listener.CertificateID > 0 {
			certificateIDs[listener.CertificateID] = struct{}{}
		}
	}
	upstreams := make([]string, 0, len(item.Upstreams))
	for _, upstream := range item.Upstreams {
		state := "disabled"
		if upstream.Enabled {
			state = "enabled"
		}
		upstreams = append(upstreams, fmt.Sprintf("%s/%s", upstream.URL, state))
	}
	return boundedSummary(fmt.Sprintf("mode=%s enabled=%t hosts=%d listeners=[%s] upstreams=[%s] certificate_refs=%d",
		item.Mode, item.Enabled, len(item.Hosts), strings.Join(listeners, ","), strings.Join(upstreams, ","), len(certificateIDs)), 512)
}
