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
	h.resolveAccessLogGeo(&input)
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

func (h handlers) listDeniedRecords(w http.ResponseWriter, r *http.Request) {
	filter, ok := parseDeniedRecordFilter(w, r)
	if !ok {
		return
	}
	items, err := h.app.Store.ListDeniedRecords(r.Context(), filter)
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

func (h handlers) statisticsReport(w http.ResponseWriter, r *http.Request) {
	filter, ok := parseStatisticsReportFilter(w, r)
	if !ok {
		return
	}
	item, err := h.app.Store.GetStatisticsReport(r.Context(), filter)
	h.writeItem(w, item, err)
}

func (h handlers) listDynamicBans(w http.ResponseWriter, r *http.Request) {
	filter, ok := parseDynamicBanFilter(w, r)
	if !ok {
		return
	}
	items, err := h.app.Store.ListDynamicBans(r.Context(), filter)
	h.writeList(w, items, err)
}

func (h handlers) clearDynamicBan(w http.ResponseWriter, r *http.Request) {
	var input model.DynamicBanClearRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	input.ClientIP = strings.TrimSpace(input.ClientIP)
	if input.SiteID <= 0 {
		writeError(w, http.StatusBadRequest, "application_id is required")
		return
	}
	if input.ClientIP == "" {
		writeError(w, http.StatusBadRequest, "client_ip is required")
		return
	}
	input.Actor = currentActor(r).Username
	result, err := h.app.Store.ClearDynamicBan(r.Context(), input)
	h.auditDynamicBanClear(r, input, result, err)
	h.writeItem(w, result, err)
}

func (h handlers) listDynamicBanClears(w http.ResponseWriter, r *http.Request) {
	filter, ok := parseDynamicBanFilter(w, r)
	if !ok {
		return
	}
	items, err := h.app.Store.ListDynamicBanClears(r.Context(), filter)
	h.writeList(w, items, err)
}

func (h handlers) protectionOverview(w http.ResponseWriter, r *http.Request) {
	filter, ok := parseSummaryFilter(w, r)
	if !ok {
		return
	}
	item, err := h.buildProtectionOverview(r.Context(), filter)
	h.writeItem(w, item, err)
}

func normalizeAccessLog(item *model.AccessLog) {
	item.RequestID = strings.TrimSpace(item.RequestID)
	item.Host = strings.ToLower(strings.TrimSpace(item.Host))
	item.Method = strings.ToUpper(strings.TrimSpace(item.Method))
	item.URI = strings.TrimSpace(item.URI)
	item.Scheme = strings.ToLower(strings.TrimSpace(item.Scheme))
	item.ClientIP = strings.TrimSpace(item.ClientIP)
	item.UserAgent = strings.TrimSpace(item.UserAgent)
	item.Referer = strings.TrimSpace(item.Referer)
	item.GeoCountry = strings.TrimSpace(item.GeoCountry)
	item.GeoRegion = strings.TrimSpace(item.GeoRegion)
	item.GeoCity = strings.TrimSpace(item.GeoCity)
	item.GeoDistrict = strings.TrimSpace(item.GeoDistrict)
	item.GeoSource = strings.TrimSpace(item.GeoSource)
	item.GeoSourceVersion = strings.TrimSpace(item.GeoSourceVersion)
	item.GeoUnresolvedReason = strings.TrimSpace(item.GeoUnresolvedReason)
	item.Disposition = strings.ToLower(strings.TrimSpace(item.Disposition))
	item.ReasonCode = strings.ToLower(strings.TrimSpace(item.ReasonCode))
	item.Reason = boundedSummary(strings.TrimSpace(item.Reason), 512)
}

func (h handlers) resolveAccessLogGeo(item *model.AccessLog) {
	item.GeoCountry = ""
	item.GeoRegion = ""
	item.GeoCity = ""
	item.GeoDistrict = ""
	item.GeoLongitude = 0
	item.GeoLatitude = 0
	item.GeoResolved = false
	item.GeoSource = ""
	item.GeoSourceVersion = ""
	item.GeoUnresolvedReason = ""
	if h.app.GeoIPResolver == nil {
		item.GeoUnresolvedReason = "geoip-database-not-configured"
		return
	}
	result := h.app.GeoIPResolver.Resolve(item.ClientIP)
	item.GeoResolved = result.Resolved
	item.GeoCountry = firstNonEmptyString(result.Country, result.CountryCode)
	item.GeoRegion = firstNonEmptyString(result.Region, result.RegionCode)
	item.GeoCity = result.City
	item.GeoDistrict = result.District
	item.GeoLongitude = result.Longitude
	item.GeoLatitude = result.Latitude
	item.GeoSource = result.Source
	item.GeoSourceVersion = result.SourceVersion
	item.GeoUnresolvedReason = result.UnresolvedReason
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
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
	item.Host = strings.ToLower(strings.TrimSpace(item.Host))
	item.Scheme = strings.ToLower(strings.TrimSpace(item.Scheme))
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
	item.IPListKind = strings.ToLower(strings.TrimSpace(item.IPListKind))
	item.IPListTarget = strings.ToLower(strings.TrimSpace(item.IPListTarget))
	item.BanReason = strings.TrimSpace(item.BanReason)
	item.ChallengeMode = strings.ToLower(strings.TrimSpace(item.ChallengeMode))
	item.ChallengeResult = strings.ToLower(strings.TrimSpace(item.ChallengeResult))
	item.BotResult = strings.ToLower(strings.TrimSpace(item.BotResult))
	item.BotReason = boundedSummary(strings.TrimSpace(item.BotReason), 240)
	item.DeviceSignal = strings.ToLower(strings.TrimSpace(item.DeviceSignal))
	if item.Module == "dynamic-protection" && item.AdvancedTarget == "" {
		item.AdvancedTarget = strings.ToLower(strings.TrimSpace(item.ChallengeResult))
	}
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
	if item.Module == "ip-access-list" {
		if item.IPAccessListID <= 0 {
			return errors.New("ip_access_list_id is required for ip-access-list events")
		}
		if item.IPListKind != "" && item.IPListKind != "allow" && item.IPListKind != "block" {
			return errors.New("ip_list_kind is unsupported")
		}
		if item.IPListTarget != "" && item.IPListTarget != "ip" && item.IPListTarget != "cidr" {
			return errors.New("ip_list_target is unsupported")
		}
	}
	return nil
}

func parseAccessLogFilter(w http.ResponseWriter, r *http.Request) (model.AccessLogFilter, bool) {
	query := r.URL.Query()
	filter := model.AccessLogFilter{
		Host:        strings.ToLower(strings.TrimSpace(query.Get("host"))),
		Scheme:      strings.ToLower(strings.TrimSpace(query.Get("scheme"))),
		ClientIP:    strings.TrimSpace(query.Get("client_ip")),
		Method:      strings.ToUpper(strings.TrimSpace(query.Get("method"))),
		URI:         strings.TrimSpace(query.Get("uri")),
		Disposition: strings.ToLower(strings.TrimSpace(query.Get("disposition"))),
		ReasonCode:  strings.ToLower(strings.TrimSpace(query.Get("reason_code"))),
	}
	var ok bool
	if filter.SiteID, ok = parseApplicationIDQuery(w, query); !ok {
		return model.AccessLogFilter{}, false
	}
	listenerPort, ok := parseOptionalInt64(w, query.Get("listener_port"), "listener_port")
	if !ok {
		return model.AccessLogFilter{}, false
	}
	filter.ListenerPort = int(listenerPort)
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

func parseDeniedRecordFilter(w http.ResponseWriter, r *http.Request) (model.DeniedRecordFilter, bool) {
	query := r.URL.Query()
	filter := model.DeniedRecordFilter{
		Host:          strings.ToLower(strings.TrimSpace(query.Get("host"))),
		Scheme:        strings.ToLower(strings.TrimSpace(query.Get("scheme"))),
		ClientIP:      strings.TrimSpace(query.Get("client_ip")),
		Method:        strings.ToUpper(strings.TrimSpace(query.Get("method"))),
		URI:           strings.TrimSpace(query.Get("uri")),
		Disposition:   strings.ToLower(strings.TrimSpace(query.Get("disposition"))),
		Module:        strings.ToLower(strings.TrimSpace(query.Get("module"))),
		Action:        strings.ToLower(strings.TrimSpace(query.Get("action"))),
		TriggerSource: strings.ToLower(strings.TrimSpace(query.Get("trigger_source"))),
	}
	var ok bool
	if filter.SiteID, ok = parseApplicationIDQuery(w, query); !ok {
		return model.DeniedRecordFilter{}, false
	}
	listenerPort, ok := parseOptionalInt64(w, query.Get("listener_port"), "listener_port")
	if !ok {
		return model.DeniedRecordFilter{}, false
	}
	filter.ListenerPort = int(listenerPort)
	status, ok := parseOptionalInt64(w, query.Get("status"), "status")
	if !ok {
		return model.DeniedRecordFilter{}, false
	}
	filter.Status = int(status)
	if filter.Since, filter.Until, ok = parseTimeRange(w, r); !ok {
		return model.DeniedRecordFilter{}, false
	}
	if filter.Pagination, ok = parsePagination(w, r); !ok {
		return model.DeniedRecordFilter{}, false
	}
	return filter, true
}

func parseApplicationIDQuery(w http.ResponseWriter, query map[string][]string) (int64, bool) {
	value := ""
	field := "application_id"
	if values := query["application_id"]; len(values) > 0 {
		value = values[0]
	} else if values := query["site_id"]; len(values) > 0 {
		value = values[0]
		field = "site_id"
	}
	return parseOptionalInt64(w, value, field)
}

func parseWAFEventFilter(w http.ResponseWriter, r *http.Request) (model.WAFEventFilter, bool) {
	query := r.URL.Query()
	filter := model.WAFEventFilter{
		Host:            strings.ToLower(strings.TrimSpace(query.Get("host"))),
		Scheme:          strings.ToLower(strings.TrimSpace(query.Get("scheme"))),
		ClientIP:        strings.TrimSpace(query.Get("client_ip")),
		Action:          strings.ToLower(strings.TrimSpace(query.Get("action"))),
		Disposition:     strings.ToLower(strings.TrimSpace(query.Get("disposition"))),
		EventType:       strings.ToLower(strings.TrimSpace(query.Get("event_type"))),
		Module:          strings.ToLower(strings.TrimSpace(query.Get("module"))),
		AttackType:      strings.ToLower(strings.TrimSpace(query.Get("attack_type"))),
		AdvancedTarget:  strings.ToLower(strings.TrimSpace(query.Get("advanced_target"))),
		ChallengeResult: strings.ToLower(strings.TrimSpace(query.Get("challenge_result"))),
		BotResult:       strings.ToLower(strings.TrimSpace(query.Get("bot_result"))),
		DynamicResult:   strings.ToLower(strings.TrimSpace(query.Get("dynamic_result"))),
	}
	var ok bool
	if filter.SiteID, ok = parseApplicationIDQuery(w, query); !ok {
		return model.WAFEventFilter{}, false
	}
	listenerPort, ok := parseOptionalInt64(w, query.Get("listener_port"), "listener_port")
	if !ok {
		return model.WAFEventFilter{}, false
	}
	filter.ListenerPort = int(listenerPort)
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

func parseDynamicBanFilter(w http.ResponseWriter, r *http.Request) (model.DynamicBanFilter, bool) {
	query := r.URL.Query()
	filter := model.DynamicBanFilter{
		Scheme:   strings.ToLower(strings.TrimSpace(query.Get("scheme"))),
		ClientIP: strings.TrimSpace(query.Get("client_ip")),
		Status:   strings.ToLower(strings.TrimSpace(query.Get("status"))),
	}
	var ok bool
	if filter.SiteID, ok = parseApplicationIDQuery(w, query); !ok {
		return model.DynamicBanFilter{}, false
	}
	listenerPort, ok := parseOptionalInt64(w, query.Get("listener_port"), "listener_port")
	if !ok {
		return model.DynamicBanFilter{}, false
	}
	filter.ListenerPort = int(listenerPort)
	if filter.MinRevision, ok = parseOptionalInt64(w, query.Get("since_revision"), "since_revision"); !ok {
		return model.DynamicBanFilter{}, false
	}
	if filter.Pagination, ok = parsePagination(w, r); !ok {
		return model.DynamicBanFilter{}, false
	}
	return filter, true
}

func (h handlers) auditDynamicBanClear(r *http.Request, request model.DynamicBanClearRequest, result model.DynamicBanClearResult, operationErr error) {
	current := currentActor(r)
	auditResult := resultFromErr(operationErr)
	message := ""
	if operationErr != nil {
		message = operationErr.Error()
	} else {
		auditResult = result.Status
		message = result.Message
	}
	_, err := h.app.Store.CreateAuditLog(r.Context(), model.AuditLog{
		Actor:        current.Username,
		Role:         current.Role,
		Action:       "unban",
		ResourceType: "dynamic_ban",
		ResourceID:   strconv.FormatInt(request.SiteID, 10) + ":" + request.ClientIP,
		Result:       auditResult,
		RemoteAddr:   r.RemoteAddr,
		UserAgent:    r.UserAgent(),
		Message:      message,
	})
	if err != nil {
		h.logger.Error("audit log failed", "error", err)
	}
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

func parseStatisticsReportFilter(w http.ResponseWriter, r *http.Request) (model.StatisticsReportFilter, bool) {
	query := r.URL.Query()
	siteID, ok := parseApplicationIDQuery(w, query)
	if !ok {
		return model.StatisticsReportFilter{}, false
	}
	since, until, ok := parseTimeRange(w, r)
	if !ok {
		return model.StatisticsReportFilter{}, false
	}
	rangeValue := strings.ToLower(strings.TrimSpace(query.Get("range")))
	if since.IsZero() && until.IsZero() {
		until = time.Now().UTC()
		duration, valid := statisticsRangeDuration(rangeValue)
		if !valid {
			writeError(w, http.StatusBadRequest, "invalid range")
			return model.StatisticsReportFilter{}, false
		}
		since = until.Add(-duration)
	}
	limit, ok := parseOptionalInt64(w, query.Get("limit"), "limit")
	if !ok {
		return model.StatisticsReportFilter{}, false
	}
	scope := strings.ToLower(strings.TrimSpace(query.Get("scope")))
	if scope == "" {
		scope = "world"
	}
	if scope != "world" && scope != "china" {
		writeError(w, http.StatusBadRequest, "invalid scope")
		return model.StatisticsReportFilter{}, false
	}
	mapView := strings.ToLower(strings.TrimSpace(query.Get("map_view")))
	if mapView == "" {
		mapView = "3d"
	}
	if mapView != "3d" && mapView != "2d" {
		writeError(w, http.StatusBadRequest, "invalid map_view")
		return model.StatisticsReportFilter{}, false
	}
	if scope == "china" {
		mapView = "2d"
	}
	metric := strings.ToLower(strings.TrimSpace(query.Get("metric")))
	if metric == "" {
		metric = "requests"
	}
	if metric != "requests" && metric != "blocked" {
		writeError(w, http.StatusBadRequest, "invalid metric")
		return model.StatisticsReportFilter{}, false
	}
	return model.StatisticsReportFilter{
		SiteID:  siteID,
		Since:   since,
		Until:   until,
		Range:   rangeValue,
		Scope:   scope,
		MapView: mapView,
		Metric:  metric,
		Limit:   int(limit),
	}, true
}

func statisticsRangeDuration(value string) (time.Duration, bool) {
	switch value {
	case "", "24h":
		return 24 * time.Hour, true
	case "1h":
		return time.Hour, true
	case "7d":
		return 7 * 24 * time.Hour, true
	case "30d":
		return 30 * 24 * time.Hour, true
	default:
		return 0, false
	}
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
