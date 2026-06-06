package httpserver

import (
	"net/http"

	"litewaf-api/internal/ipaccess"
	"litewaf-api/internal/model"
)

type ipAccessListRequest struct {
	Name         string `json:"name"`
	Kind         string `json:"kind"`
	Target       string `json:"target"`
	Value        string `json:"value"`
	SiteID       int64  `json:"application_id"`
	LegacySiteID int64  `json:"site_id"`
	Enabled      *bool  `json:"enabled"`
	Priority     int    `json:"priority"`
	Description  string `json:"description"`
}

func (r ipAccessListRequest) toModel() model.IPAccessListEntry {
	siteID := r.SiteID
	if siteID == 0 {
		siteID = r.LegacySiteID
	}
	return model.IPAccessListEntry{
		Name:        r.Name,
		Kind:        r.Kind,
		Target:      r.Target,
		Value:       r.Value,
		SiteID:      siteID,
		Enabled:     boolValue(r.Enabled, true),
		Priority:    r.Priority,
		Description: r.Description,
	}
}

func (h handlers) listIPAccessLists(w http.ResponseWriter, r *http.Request) {
	items, err := h.app.Store.ListIPAccessListEntries(r.Context())
	h.writeList(w, items, err)
}

func (h handlers) getIPAccessList(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	item, err := h.app.Store.GetIPAccessListEntry(r.Context(), id)
	h.writeItem(w, item, err)
}

func (h handlers) createIPAccessList(w http.ResponseWriter, r *http.Request) {
	var req ipAccessListRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := ipaccess.Normalize(req.toModel())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := ipaccess.Validate(item); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	created, err := h.app.Store.CreateIPAccessListEntry(r.Context(), item)
	h.audit(r, "create", "ip_access_list", created.ID, resultFromErr(err), err)
	h.writeCreated(w, created, err)
}

func (h handlers) updateIPAccessList(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	existing, existingErr := h.app.Store.GetIPAccessListEntry(r.Context(), id)
	if existingErr != nil {
		h.writeKnownError(w, existingErr)
		return
	}
	var req ipAccessListRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, err := ipaccess.Normalize(req.toModel())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := ipaccess.Validate(item); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	updated, err := h.app.Store.UpdateIPAccessListEntry(r.Context(), id, item)
	action := "update"
	if err == nil && existing.Enabled != updated.Enabled {
		if updated.Enabled {
			action = "enable"
		} else {
			action = "disable"
		}
	}
	h.audit(r, action, "ip_access_list", id, resultFromErr(err), err)
	h.writeItem(w, updated, err)
}

func (h handlers) deleteIPAccessList(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	err := h.app.Store.DeleteIPAccessListEntry(r.Context(), id)
	h.audit(r, "delete", "ip_access_list", id, resultFromErr(err), err)
	h.writeNoContent(w, err)
}
