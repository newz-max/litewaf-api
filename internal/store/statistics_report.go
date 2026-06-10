package store

import (
	"context"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"litewaf-api/internal/model"
)

const (
	realtimeQPSWindow = 3 * time.Minute
	realtimeQPSBucket = 5 * time.Second
)

type geoAccumulator struct {
	code      string
	name      string
	count     int64
	blocked   int64
	longitude float64
	latitude  float64
	hasPoint  bool
}

func (s *MemoryStore) GetStatisticsReport(_ context.Context, filter model.StatisticsReportFilter) (model.StatisticsReport, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	accessLogs := make([]model.AccessLog, 0, len(s.accessLogs))
	for _, item := range s.accessLogs {
		if statisticsAccessLogMatches(item, filter) {
			accessLogs = append(accessLogs, item)
		}
	}
	wafEvents := make([]model.WAFEvent, 0, len(s.wafEvents))
	for _, item := range s.wafEvents {
		if statisticsWAFEventMatches(item, filter) {
			wafEvents = append(wafEvents, item)
		}
	}
	return buildStatisticsReport(accessLogs, wafEvents, filter), nil
}

func (s *PostgresStore) GetStatisticsReport(ctx context.Context, filter model.StatisticsReportFilter) (model.StatisticsReport, error) {
	accessLogs, err := s.statisticsAccessLogs(ctx, filter)
	if err != nil {
		return model.StatisticsReport{}, err
	}
	wafEvents, err := s.statisticsWAFEvents(ctx, filter)
	if err != nil {
		return model.StatisticsReport{}, err
	}
	return buildStatisticsReport(accessLogs, wafEvents, filter), nil
}

func (s *PostgresStore) statisticsAccessLogs(ctx context.Context, filter model.StatisticsReportFilter) ([]model.AccessLog, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, request_id, site_id, listener_port, scheme, host, method, uri, status, upstream_status,
			duration_ms, client_ip, user_agent, referer, geo_country, geo_region, geo_city,
			geo_district, geo_longitude, geo_latitude, geo_resolved, geo_source, geo_source_version,
			geo_unresolved_reason, disposition, created_at
		FROM access_logs
		WHERE ($1::bigint = 0 OR site_id = $1)
			AND ($2::timestamptz IS NULL OR created_at >= $2)
			AND ($3::timestamptz IS NULL OR created_at <= $3)
		ORDER BY created_at ASC, id ASC`,
		filter.SiteID, nullableTime(filter.Since), nullableTime(filter.Until))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []model.AccessLog{}
	for rows.Next() {
		var item model.AccessLog
		if err := rows.Scan(
			&item.ID, &item.RequestID, &item.SiteID, &item.ListenerPort, &item.Scheme, &item.Host, &item.Method, &item.URI, &item.Status, &item.UpstreamStatus,
			&item.DurationMS, &item.ClientIP, &item.UserAgent, &item.Referer, &item.GeoCountry, &item.GeoRegion, &item.GeoCity,
			&item.GeoDistrict, &item.GeoLongitude, &item.GeoLatitude, &item.GeoResolved, &item.GeoSource, &item.GeoSourceVersion,
			&item.GeoUnresolvedReason, &item.Disposition, &item.CreatedAt,
		); err != nil {
			return nil, err
		}
		item.Time = item.CreatedAt.Format(time.RFC3339)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) statisticsWAFEvents(ctx context.Context, filter model.StatisticsReportFilter) ([]model.WAFEvent, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, request_id, site_id, listener_port, scheme, host, event_type, rule_id, rule_type, target, action, disposition,
			client_ip, method, uri, summary, rate_limit_id,
			module, category, rule_name, attack_type, group_name, counter, window_sec,
			advanced_target, normalized_value, score, threshold, matched_rule_ids,
			body_metadata, upload_metadata, ip_access_list_id, ip_list_kind, ip_list_target,
			ban_reason, ban_duration_sec, ban_remaining_sec,
			challenge_mode, challenge_result, bot_result, bot_reason, device_signal,
			created_at
		FROM waf_events
		WHERE ($1::bigint = 0 OR site_id = $1)
			AND ($2::timestamptz IS NULL OR created_at >= $2)
			AND ($3::timestamptz IS NULL OR created_at <= $3)
		ORDER BY created_at ASC, id ASC`,
		filter.SiteID, nullableTime(filter.Since), nullableTime(filter.Until))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []model.WAFEvent{}
	for rows.Next() {
		var item model.WAFEvent
		if err := rows.Scan(
			&item.ID, &item.RequestID, &item.SiteID, &item.ListenerPort, &item.Scheme, &item.Host, &item.EventType, &item.RuleID, &item.RuleType, &item.Target, &item.Action, &item.Disposition,
			&item.ClientIP, &item.Method, &item.URI, &item.Summary, &item.RateLimitID,
			&item.Module, &item.Category, &item.RuleName, &item.AttackType, &item.GroupName, &item.Counter, &item.WindowSec,
			&item.AdvancedTarget, &item.NormalizedValue, &item.Score, &item.Threshold, &item.MatchedRuleIDs,
			&item.BodyMetadata, &item.UploadMetadata, &item.IPAccessListID, &item.IPListKind, &item.IPListTarget,
			&item.BanReason, &item.BanDurationSec, &item.BanRemainingSec,
			&item.ChallengeMode, &item.ChallengeResult, &item.BotResult, &item.BotReason, &item.DeviceSignal,
			&item.CreatedAt,
		); err != nil {
			return nil, err
		}
		item.Time = item.CreatedAt.Format(time.RFC3339)
		items = append(items, item)
	}
	return items, rows.Err()
}

func buildStatisticsReport(accessLogs []model.AccessLog, wafEvents []model.WAFEvent, filter model.StatisticsReportFilter) model.StatisticsReport {
	scope := normalizeStatisticsScope(filter.Scope)
	mapView := normalizeStatisticsMapView(scope, filter.MapView)
	metric := normalizeStatisticsMetric(filter.Metric)
	limit := normalizeSummaryLimit(filter.Limit)
	report := model.StatisticsReport{
		QPS:      []model.TimeSeriesPoint{},
		Visits:   []model.TimeSeriesPoint{},
		Blocks:   []model.TimeSeriesPoint{},
		Statuses: []model.SummaryCount{},
		Geo: model.StatisticsGeoReport{
			Scope:   scope,
			MapView: mapView,
			Metric:  metric,
			Ranking: []model.GeoRank{},
			Points:  []model.GeoPoint{},
		},
		Clients: model.StatisticsClientReport{
			OS:         []model.SummaryCount{},
			Browsers:   []model.SummaryCount{},
			UserAgents: []model.SummaryCount{},
		},
		Referers: model.StatisticsRefererReport{
			Domains: []model.SummaryCount{},
			Pages:   []model.SummaryCount{},
		},
	}

	uniqueVisitors := map[string]struct{}{}
	uniqueIPs := map[string]struct{}{}
	attackIPs := map[string]struct{}{}
	statusCounts := map[string]int64{}
	osCounts := map[string]int64{}
	browserCounts := map[string]int64{}
	uaCounts := map[string]int64{}
	refererDomainCounts := map[string]int64{}
	refererPageCounts := map[string]int64{}
	qpsBuckets := map[time.Time]int64{}
	visitBuckets := map[time.Time]int64{}
	blockBuckets := map[time.Time]int64{}
	geoCounts := map[string]*geoAccumulator{}
	geoDiagnostics := map[string]int64{}
	qpsStart, qpsEnd := realtimeQPSRange(filter.Until)
	trendBucket := statisticsBucketDuration(filter.Since, filter.Until)

	for _, item := range accessLogs {
		report.Cards.Requests++
		increment(statusCounts, strconv.Itoa(item.Status))
		if item.ClientIP != "" {
			uniqueIPs[item.ClientIP] = struct{}{}
			uniqueVisitors[item.ClientIP+"|"+normalizeUserAgent(item.UserAgent)] = struct{}{}
		}
		if isPageView(item) {
			report.Cards.PV++
		}
		if item.Status >= 400 && item.Status <= 499 {
			report.Cards.Errors4xx++
			if isBlockedDisposition(item.Disposition) {
				report.Cards.Blocked4xx++
			}
		}
		if item.Status >= 500 && item.Status <= 599 {
			report.Cards.Errors5xx++
		}
		if isBlockedDisposition(item.Disposition) {
			report.Cards.Blocked++
		}
		addBucket(qpsBuckets, item.CreatedAt, realtimeQPSBucket, 1)
		if isPageView(item) {
			addBucket(visitBuckets, item.CreatedAt, trendBucket, 1)
		}
		if item.UserAgent != "" {
			increment(osCounts, detectOS(item.UserAgent))
			increment(browserCounts, detectBrowser(item.UserAgent))
			increment(uaCounts, normalizeUserAgent(item.UserAgent))
		}
		if domain, page := externalReferer(item.Referer, item.Host); domain != "" {
			increment(refererDomainCounts, domain)
			increment(refererPageCounts, page)
		}
		addGeo(geoCounts, item, scope, metric)
		if !item.GeoResolved && item.GeoUnresolvedReason != "" {
			increment(geoDiagnostics, item.GeoUnresolvedReason)
		}
	}

	for _, item := range wafEvents {
		if isBlockedDisposition(item.Disposition) || item.Action == "block" {
			report.Cards.Blocked++
			addBucket(blockBuckets, item.CreatedAt, trendBucket, 1)
			if item.ClientIP != "" {
				attackIPs[item.ClientIP] = struct{}{}
			}
		}
	}

	report.Cards.UV = int64(len(uniqueVisitors))
	report.Cards.UniqueIPs = int64(len(uniqueIPs))
	report.Cards.AttackIPs = int64(len(attackIPs))
	report.Cards.ErrorRate4xx = percent(report.Cards.Errors4xx, report.Cards.Requests)
	report.Cards.BlockRate4xx = percent(report.Cards.Blocked4xx, report.Cards.Errors4xx)
	report.Cards.ErrorRate5xx = percent(report.Cards.Errors5xx, report.Cards.Requests)
	report.QPS = realtimeQPSPoints(qpsBuckets, qpsStart, qpsEnd)
	report.Visits = bucketPoints(visitBuckets)
	report.Blocks = bucketPoints(blockBuckets)
	report.Statuses = topCounts(statusCounts, limit)
	report.Clients.OS = topCounts(osCounts, limit)
	report.Clients.Browsers = topCounts(browserCounts, limit)
	report.Clients.UserAgents = topCounts(uaCounts, limit)
	report.Referers.Domains = topCounts(refererDomainCounts, limit)
	report.Referers.Pages = topCounts(refererPageCounts, limit)
	report.Geo.Ranking, report.Geo.Points = geoResults(geoCounts, limit)
	for _, diagnostic := range topCounts(geoDiagnostics, limit) {
		message := "GeoIP unresolved " + diagnostic.Key + ": " + strconv.FormatInt(diagnostic.Count, 10)
		report.Geo.Diagnostics = append(report.Geo.Diagnostics, message)
		report.Diagnostics = append(report.Diagnostics, message)
	}
	if len(accessLogs) > 0 && len(report.Geo.Ranking) == 0 {
		message := "GeoIP data is unavailable for matched logs"
		report.Geo.Diagnostics = append(report.Geo.Diagnostics, message)
		report.Diagnostics = append(report.Diagnostics, message)
	}
	return report
}

func statisticsAccessLogMatches(item model.AccessLog, filter model.StatisticsReportFilter) bool {
	return (filter.SiteID == 0 || item.SiteID == filter.SiteID) && summaryTimeMatches(item.CreatedAt, filter.Since, filter.Until)
}

func statisticsWAFEventMatches(item model.WAFEvent, filter model.StatisticsReportFilter) bool {
	return (filter.SiteID == 0 || item.SiteID == filter.SiteID) && summaryTimeMatches(item.CreatedAt, filter.Since, filter.Until)
}

func normalizeStatisticsScope(value string) string {
	if strings.ToLower(strings.TrimSpace(value)) == "china" {
		return "china"
	}
	return "world"
}

func normalizeStatisticsMapView(scope string, value string) string {
	if scope == "china" {
		return "2d"
	}
	if strings.ToLower(strings.TrimSpace(value)) == "2d" {
		return "2d"
	}
	return "3d"
}

func normalizeStatisticsMetric(value string) string {
	if strings.ToLower(strings.TrimSpace(value)) == "blocked" {
		return "blocked"
	}
	return "requests"
}

func statisticsBucketDuration(since time.Time, until time.Time) time.Duration {
	if since.IsZero() || until.IsZero() {
		return time.Hour
	}
	duration := until.Sub(since)
	if duration <= time.Hour {
		return 5 * time.Minute
	}
	if duration <= 24*time.Hour {
		return time.Hour
	}
	return 24 * time.Hour
}

func realtimeQPSRange(until time.Time) (time.Time, time.Time) {
	if until.IsZero() {
		until = time.Now().UTC()
	}
	end := until.UTC().Truncate(realtimeQPSBucket)
	return end.Add(-realtimeQPSWindow), end
}

func addBucket(buckets map[time.Time]int64, value time.Time, bucket time.Duration, count int64) {
	if value.IsZero() {
		return
	}
	buckets[value.UTC().Truncate(bucket)] += count
}

func realtimeQPSPoints(buckets map[time.Time]int64, start time.Time, end time.Time) []model.TimeSeriesPoint {
	points := []model.TimeSeriesPoint{}
	if end.Before(start) {
		return points
	}
	for key := start; !key.After(end); key = key.Add(realtimeQPSBucket) {
		points = append(points, model.TimeSeriesPoint{
			Time:  key.Format(time.RFC3339),
			Value: float64(buckets[key]),
		})
	}
	return points
}

func bucketPoints(buckets map[time.Time]int64) []model.TimeSeriesPoint {
	times := make([]time.Time, 0, len(buckets))
	for key := range buckets {
		times = append(times, key)
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
	points := make([]model.TimeSeriesPoint, 0, len(times))
	for _, key := range times {
		points = append(points, model.TimeSeriesPoint{Time: key.Format(time.RFC3339), Value: float64(buckets[key])})
	}
	return points
}

func isPageView(item model.AccessLog) bool {
	method := strings.ToUpper(item.Method)
	if method != "GET" && method != "HEAD" {
		return false
	}
	uriPath := item.URI
	if parsed, err := url.Parse(item.URI); err == nil && parsed.Path != "" {
		uriPath = parsed.Path
	}
	extension := strings.ToLower(path.Ext(uriPath))
	if extension == "" {
		return true
	}
	staticExtensions := map[string]struct{}{
		".css": {}, ".js": {}, ".mjs": {}, ".png": {}, ".jpg": {}, ".jpeg": {}, ".gif": {}, ".svg": {},
		".ico": {}, ".webp": {}, ".woff": {}, ".woff2": {}, ".ttf": {}, ".map": {}, ".txt": {}, ".xml": {},
	}
	_, isStatic := staticExtensions[extension]
	return !isStatic
}

func isBlockedDisposition(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "blocked", "rejected", "denied":
		return true
	default:
		return false
	}
}

func percent(part int64, total int64) float64 {
	if total <= 0 {
		return 0
	}
	return float64(part) / float64(total) * 100
}

func normalizeUserAgent(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "Unknown"
	}
	if len(value) > 80 {
		return value[:80]
	}
	return value
}

func detectOS(userAgent string) string {
	lower := strings.ToLower(userAgent)
	switch {
	case strings.Contains(lower, "windows"):
		return "Windows"
	case strings.Contains(lower, "mac os") || strings.Contains(lower, "macintosh"):
		return "MacOS"
	case strings.Contains(lower, "android"):
		return "Android"
	case strings.Contains(lower, "iphone") || strings.Contains(lower, "ipad") || strings.Contains(lower, "ios"):
		return "iOS"
	case strings.Contains(lower, "linux"):
		return "Linux"
	default:
		return "Unknown"
	}
}

func detectBrowser(userAgent string) string {
	lower := strings.ToLower(userAgent)
	switch {
	case strings.Contains(lower, "edg/"):
		return "Edge"
	case strings.Contains(lower, "chrome/") || strings.Contains(lower, "crios/"):
		return "Chrome"
	case strings.Contains(lower, "firefox/"):
		return "Firefox"
	case strings.Contains(lower, "safari/"):
		return "Safari"
	case strings.Contains(lower, "curl/"):
		return "curl"
	case strings.Contains(lower, "go-http-client"):
		return "Go-http-client"
	default:
		return "Unknown"
	}
}

func externalReferer(raw string, currentHost string) (string, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", ""
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" || host == strings.ToLower(strings.TrimSpace(currentHost)) {
		return "", ""
	}
	page := raw
	if len(page) > 160 {
		page = page[:160]
	}
	return host, page
}

func addGeo(counts map[string]*geoAccumulator, item model.AccessLog, scope string, metric string) {
	if !item.GeoResolved {
		return
	}
	key := ""
	name := ""
	if scope == "china" {
		if !isChinaGeo(item.GeoCountry) || strings.TrimSpace(item.GeoRegion) == "" {
			return
		}
		key = strings.ToLower(strings.TrimSpace(item.GeoRegion))
		name = strings.TrimSpace(item.GeoRegion)
	} else {
		if strings.TrimSpace(item.GeoCountry) == "" {
			return
		}
		key = strings.ToLower(strings.TrimSpace(item.GeoCountry))
		name = strings.TrimSpace(item.GeoCountry)
	}
	count := int64(1)
	blocked := int64(0)
	if isBlockedDisposition(item.Disposition) {
		blocked = 1
	}
	if metric == "blocked" && blocked == 0 {
		return
	}
	if metric == "blocked" {
		count = blocked
	}
	current := counts[key]
	if current == nil {
		current = &geoAccumulator{code: key, name: name}
		counts[key] = current
	}
	current.count += count
	current.blocked += blocked
	if item.GeoLongitude != 0 || item.GeoLatitude != 0 {
		current.longitude = item.GeoLongitude
		current.latitude = item.GeoLatitude
		current.hasPoint = true
	}
}

func isChinaGeo(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "cn" || value == "china" || value == "中国" || value == "中华人民共和国"
}

func geoResults(counts map[string]*geoAccumulator, limit int) ([]model.GeoRank, []model.GeoPoint) {
	items := make([]*geoAccumulator, 0, len(counts))
	for _, item := range counts {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count == items[j].count {
			return items[i].name < items[j].name
		}
		return items[i].count > items[j].count
	})
	if len(items) > limit {
		items = items[:limit]
	}
	ranking := make([]model.GeoRank, 0, len(items))
	points := []model.GeoPoint{}
	for _, item := range items {
		ranking = append(ranking, model.GeoRank{
			Code:    item.code,
			Name:    item.name,
			Count:   item.count,
			Blocked: item.blocked,
		})
		if item.hasPoint {
			points = append(points, model.GeoPoint{
				Name:      item.name,
				Value:     item.count,
				Longitude: item.longitude,
				Latitude:  item.latitude,
			})
		}
	}
	return ranking, points
}
