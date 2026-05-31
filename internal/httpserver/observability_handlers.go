package httpserver

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"litewaf-api/internal/model"
)

func (h handlers) ingestAccessLog(w http.ResponseWriter, r *http.Request) {
	var input model.AccessLog
	if !decodeJSON(w, r, &input) {
		return
	}
	normalizeAccessLog(&input)
	if err := validateAccessLog(input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	item, err := h.app.Store.CreateAccessLog(r.Context(), input)
	h.writeCreated(w, item, err)
}

func (h handlers) ingestWAFEvent(w http.ResponseWriter, r *http.Request) {
	var input model.WAFEvent
	if !decodeJSON(w, r, &input) {
		return
	}
	normalizeWAFEvent(&input)
	if err := validateWAFEvent(input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	item, err := h.app.Store.CreateWAFEvent(r.Context(), input)
	h.writeCreated(w, item, err)
}

func (h handlers) listAccessLogs(w http.ResponseWriter, r *http.Request) {
	filter, ok := parseAccessLogFilter(w, r)
	if !ok {
		return
	}
	items, err := h.app.Store.ListAccessLogs(r.Context(), filter)
	h.writeList(w, items, err)
}

func (h handlers) listAttackLogs(w http.ResponseWriter, r *http.Request) {
	filter, ok := parseWAFEventFilter(w, r)
	if !ok {
		return
	}
	items, err := h.app.Store.ListWAFEvents(r.Context(), filter)
	h.writeList(w, items, err)
}

func (h handlers) observabilitySummary(w http.ResponseWriter, r *http.Request) {
	filter, ok := parseSummaryFilter(w, r)
	if !ok {
		return
	}
	item, err := h.app.Store.GetObservabilitySummary(r.Context(), filter)
	h.writeItem(w, item, err)
}

func normalizeAccessLog(item *model.AccessLog) {
	item.RequestID = strings.TrimSpace(item.RequestID)
	item.Host = strings.ToLower(strings.TrimSpace(item.Host))
	item.Method = strings.ToUpper(strings.TrimSpace(item.Method))
	item.URI = strings.TrimSpace(item.URI)
	item.ClientIP = strings.TrimSpace(item.ClientIP)
	item.UserAgent = strings.TrimSpace(item.UserAgent)
	item.Disposition = strings.ToLower(strings.TrimSpace(item.Disposition))
}

func validateAccessLog(item model.AccessLog) error {
	if item.RequestID == "" {
		return errors.New("request_id is required")
	}
	if item.Method == "" {
		return errors.New("method is required")
	}
	if item.URI == "" {
		return errors.New("uri is required")
	}
	if item.Status <= 0 {
		return errors.New("status is required")
	}
	if item.Disposition == "" {
		return errors.New("disposition is required")
	}
	return nil
}

func normalizeWAFEvent(item *model.WAFEvent) {
	item.RequestID = strings.TrimSpace(item.RequestID)
	item.EventType = strings.ToLower(strings.TrimSpace(item.EventType))
	item.RuleType = strings.ToLower(strings.TrimSpace(item.RuleType))
	item.Target = strings.ToLower(strings.TrimSpace(item.Target))
	item.AdvancedTarget = strings.ToLower(strings.TrimSpace(item.AdvancedTarget))
	item.Action = strings.ToLower(strings.TrimSpace(item.Action))
	item.Disposition = strings.ToLower(strings.TrimSpace(item.Disposition))
	item.ClientIP = strings.TrimSpace(item.ClientIP)
	item.Method = strings.ToUpper(strings.TrimSpace(item.Method))
	item.URI = strings.TrimSpace(item.URI)
	item.Summary = boundedSummary(strings.TrimSpace(item.Summary), 512)
	item.Module = strings.ToLower(strings.TrimSpace(item.Module))
	item.Category = strings.ToLower(strings.TrimSpace(item.Category))
	item.RuleName = strings.TrimSpace(item.RuleName)
	item.AttackType = strings.ToLower(strings.TrimSpace(item.AttackType))
	item.GroupName = strings.TrimSpace(item.GroupName)
	item.Counter = strings.TrimSpace(item.Counter)
	item.NormalizedValue = boundedSummary(strings.TrimSpace(item.NormalizedValue), 512)
	item.MatchedRuleIDs = strings.TrimSpace(item.MatchedRuleIDs)
	item.BodyMetadata = boundedSummary(strings.TrimSpace(item.BodyMetadata), 1024)
	item.UploadMetadata = boundedSummary(strings.TrimSpace(item.UploadMetadata), 1024)
	item.BanReason = strings.TrimSpace(item.BanReason)
	item.ChallengeMode = strings.ToLower(strings.TrimSpace(item.ChallengeMode))
	item.ChallengeResult = strings.ToLower(strings.TrimSpace(item.ChallengeResult))
}

func validateWAFEvent(item model.WAFEvent) error {
	if item.RequestID == "" {
		return errors.New("request_id is required")
	}
	if item.EventType == "" {
		return errors.New("event_type is required")
	}
	if item.Action == "" {
		return errors.New("action is required")
	}
	if item.Disposition == "" {
		return errors.New("disposition is required")
	}
	return nil
}

func parseAccessLogFilter(w http.ResponseWriter, r *http.Request) (model.AccessLogFilter, bool) {
	query := r.URL.Query()
	filter := model.AccessLogFilter{
		Host:        strings.ToLower(strings.TrimSpace(query.Get("host"))),
		ClientIP:    strings.TrimSpace(query.Get("client_ip")),
		Method:      strings.ToUpper(strings.TrimSpace(query.Get("method"))),
		URI:         strings.TrimSpace(query.Get("uri")),
		Disposition: strings.ToLower(strings.TrimSpace(query.Get("disposition"))),
	}
	var ok bool
	if filter.SiteID, ok = parseOptionalInt64(w, query.Get("site_id"), "site_id"); !ok {
		return model.AccessLogFilter{}, false
	}
	status, ok := parseOptionalInt64(w, query.Get("status"), "status")
	if !ok {
		return model.AccessLogFilter{}, false
	}
	filter.Status = int(status)
	if filter.Since, filter.Until, ok = parseTimeRange(w, r); !ok {
		return model.AccessLogFilter{}, false
	}
	if filter.Pagination, ok = parsePagination(w, r); !ok {
		return model.AccessLogFilter{}, false
	}
	return filter, true
}

func parseWAFEventFilter(w http.ResponseWriter, r *http.Request) (model.WAFEventFilter, bool) {
	query := r.URL.Query()
	filter := model.WAFEventFilter{
		ClientIP:        strings.TrimSpace(query.Get("client_ip")),
		Action:          strings.ToLower(strings.TrimSpace(query.Get("action"))),
		Disposition:     strings.ToLower(strings.TrimSpace(query.Get("disposition"))),
		EventType:       strings.ToLower(strings.TrimSpace(query.Get("event_type"))),
		Module:          strings.ToLower(strings.TrimSpace(query.Get("module"))),
		AttackType:      strings.ToLower(strings.TrimSpace(query.Get("attack_type"))),
		AdvancedTarget:  strings.ToLower(strings.TrimSpace(query.Get("advanced_target"))),
		ChallengeResult: strings.ToLower(strings.TrimSpace(query.Get("challenge_result"))),
	}
	var ok bool
	if filter.SiteID, ok = parseOptionalInt64(w, query.Get("site_id"), "site_id"); !ok {
		return model.WAFEventFilter{}, false
	}
	if filter.RuleID, ok = parseOptionalInt64(w, query.Get("rule_id"), "rule_id"); !ok {
		return model.WAFEventFilter{}, false
	}
	minScore, ok := parseOptionalInt64(w, query.Get("min_score"), "min_score")
	if !ok {
		return model.WAFEventFilter{}, false
	}
	filter.MinScore = int(minScore)
	if filter.Since, filter.Until, ok = parseTimeRange(w, r); !ok {
		return model.WAFEventFilter{}, false
	}
	if filter.Pagination, ok = parsePagination(w, r); !ok {
		return model.WAFEventFilter{}, false
	}
	return filter, true
}

func boundedSummary(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit]
}

func parseSummaryFilter(w http.ResponseWriter, r *http.Request) (model.ObservabilitySummaryFilter, bool) {
	since, until, ok := parseTimeRange(w, r)
	if !ok {
		return model.ObservabilitySummaryFilter{}, false
	}
	limit, ok := parseOptionalInt64(w, r.URL.Query().Get("limit"), "limit")
	if !ok {
		return model.ObservabilitySummaryFilter{}, false
	}
	return model.ObservabilitySummaryFilter{Since: since, Until: until, Limit: int(limit)}, true
}

func parseTimeRange(w http.ResponseWriter, r *http.Request) (time.Time, time.Time, bool) {
	query := r.URL.Query()
	var since time.Time
	var until time.Time
	if value := strings.TrimSpace(query.Get("since")); value != "" {
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid since timestamp")
			return time.Time{}, time.Time{}, false
		}
		since = parsed
	}
	if value := strings.TrimSpace(query.Get("until")); value != "" {
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid until timestamp")
			return time.Time{}, time.Time{}, false
		}
		until = parsed
	}
	return since, until, true
}

func parsePagination(w http.ResponseWriter, r *http.Request) (model.Pagination, bool) {
	query := r.URL.Query()
	limit, ok := parseOptionalInt64(w, query.Get("limit"), "limit")
	if !ok {
		return model.Pagination{}, false
	}
	offset, ok := parseOptionalInt64(w, query.Get("offset"), "offset")
	if !ok {
		return model.Pagination{}, false
	}
	if limit < 0 || offset < 0 {
		writeError(w, http.StatusBadRequest, "pagination values cannot be negative")
		return model.Pagination{}, false
	}
	return model.Pagination{Limit: int(limit), Offset: int(offset)}, true
}

func parseOptionalInt64(w http.ResponseWriter, value string, field string) (int64, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, true
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed < 0 {
		writeError(w, http.StatusBadRequest, "invalid "+field)
		return 0, false
	}
	return parsed, true
}
