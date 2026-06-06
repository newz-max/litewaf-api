package httpserver

import (
	"fmt"
	"net/http"
	"strings"

	"litewaf-api/internal/model"
)

type certificateRequest struct {
	Name    string `json:"name"`
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

func (h handlers) listCertificates(w http.ResponseWriter, r *http.Request) {
	items, err := h.app.Store.ListCertificates(r.Context())
	h.writeList(w, items, err)
}

func (h handlers) getCertificate(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	item, err := h.app.Store.GetCertificate(r.Context(), id)
	h.writeItem(w, item, err)
}

func (h handlers) createCertificate(w http.ResponseWriter, r *http.Request) {
	var req certificateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := model.ParseCertificate(req.Name, req.CertPEM, req.KeyPEM)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	created, err := h.app.Store.CreateCertificate(r.Context(), item)
	h.auditMessage(r, "create", "certificate", created.ID, resultFromErr(err), certificateAuditSummary(created), err)
	h.writeCreated(w, created, err)
}

func (h handlers) validateCertificate(w http.ResponseWriter, r *http.Request) {
	var req certificateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := model.ParseCertificate(req.Name, req.CertPEM, req.KeyPEM)
	if err != nil {
		h.auditMessage(r, "validate", "certificate", 0, "failure", "certificate validation failed", err)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.auditMessage(r, "validate", "certificate", 0, "success", certificateAuditSummary(item), nil)
	writeJSON(w, http.StatusOK, envelope{"item": item})
}

func (h handlers) deleteCertificate(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	err := h.app.Store.DeleteCertificate(r.Context(), id)
	h.audit(r, "delete", "certificate", id, resultFromErr(err), err)
	h.writeNoContent(w, err)
}

func certificateAuditSummary(item model.Certificate) string {
	return boundedSummary(fmt.Sprintf("name=%s domains=%s fingerprint=%s not_after=%s",
		item.Name, strings.Join(item.Domains, ","), item.Fingerprint, item.NotAfter.Format("2006-01-02T15:04:05Z07:00")), 512)
}
